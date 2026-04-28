#include "architecture.h"

#include <stdexcept>
#include <algorithm>
#include <iostream>

#include "../../runtime/common.h"
#include "../../runtime/crypto.h"
#include "../objects.h"
#include "../osutils.h"
#include "../streams.h"


#include "utils.h"
#include "references.h"
#include "mapping.h"
#include "sections.h"
#include "imports.h"
#include "exports.h"
#include "fixups.h"
#include "relocations.h"
#include "seh.h"
#include "resources.h"
#include "runtime_func.h"
#include "compiler_func.h"
#include "memory.h"
#include "markers.h"

#include "../processors/proc_interfaces.h"
#include "../processors/proc_crypto.h"

#include "../inifile.h"
#include "../lang.h"
#include "../core_internal/core.h"
#include "../script.h"

#include "../core_internal/watermark.h"
#include "../core_internal/license.h"
#include "../core_internal/file_manager.h"


/**
 * FunctionArch
 */

FunctionArch::FunctionArch(FunctionBundle *owner, IArchitecture *arch, IFunction *func)
	: IObject(), owner_(owner), arch_(arch), func_(func)
{

}

FunctionArch::~FunctionArch()
{
	if (owner_)
		owner_->RemoveObject(this);
}

/**
 * FunctionBundle
 */

FunctionBundle::FunctionBundle(FunctionBundleList *owner, const FunctionName &name, bool is_unknown)
	: ObjectList<FunctionArch>(), owner_(owner), name_(name), is_unknown_(is_unknown)
{

}

FunctionBundle::~FunctionBundle()
{
	if (owner_)
		owner_->RemoveObject(this);
}

FunctionArch *FunctionBundle::Add(IArchitecture *arch, IFunction *func)
{
	FunctionArch *func_arch = new FunctionArch(this, arch, func);
	AddObject(func_arch);
	return func_arch;
}

bool FunctionBundle::need_compile() const 
{ 
	return (count() == 0) ? false : item(0)->func()->need_compile(); 
}

CompilationType FunctionBundle::compilation_type() const
{ 
	return (count() == 0) ? ctNone : item(0)->func()->compilation_type(); 
}

CompilationType FunctionBundle::default_compilation_type() const
{ 
	return (count() == 0) ? ctNone : item(0)->func()->default_compilation_type(); 
}

uint32_t FunctionBundle::compilation_options() const
{ 
	return (count() == 0) ? 0 : item(0)->func()->compilation_options(); 
}

Folder *FunctionBundle::folder() const
{ 
	return (count() == 0) ? NULL : item(0)->func()->folder(); 
}

void FunctionBundle::set_need_compile(bool need_compile)
{ 
	for (size_t i = 0; i < count(); i++) {
		item(i)->func()->set_need_compile(need_compile);
	}
}

void FunctionBundle::set_compilation_type(CompilationType compilation_type)
{ 
	for (size_t i = 0; i < count(); i++) {
		item(i)->func()->set_compilation_type(compilation_type);
	}
}

void FunctionBundle::set_compilation_options(uint32_t compilation_options)
{ 
	for (size_t i = 0; i < count(); i++) {
		item(i)->func()->set_compilation_options(compilation_options);
	}
}

void FunctionBundle::set_folder(Folder *folder)
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->func()->set_folder(folder);
	}
}

FunctionArch *FunctionBundle::GetArchByFunction(IFunction *func) const
{
	for (size_t i = 0; i < count(); i++) {
		FunctionArch *func_arch = item(i);
		if (func_arch->func() == func)
			return func_arch;
	}
	return NULL;
}

ICommand *FunctionBundle::GetCommandByAddress(IArchitecture *file, uint64_t address) const
{
	for (size_t i = 0; i < count(); i++) {
		FunctionArch *func_arch = item(i);
		if (func_arch->arch() == file) {
			ICommand *command = func_arch->func()->GetCommandByAddress(address);
			if (command)
				return command;
		}
	}
	return NULL;
}

ObjectType FunctionBundle::type() const
{ 
	for (size_t i = 0; i < count(); i++) {
		ObjectType type = item(i)->func()->type();
		if (type != otUnknown)
			return type;
	}
	return otUnknown; 
}

std::string FunctionBundle::display_address() const
{
	bool show_arch_name = (owner_ && owner_->show_arch_name());
	std::string res;
	for (size_t i = 0; i < count(); i++) {
		IFunction *func = item(i)->func();
		if (func->type() != otUnknown) {
			if (!res.empty())
				res.append(", ");
			res.append(func->display_address(show_arch_name ? item(i)->arch()->name().append(".") : std::string()));
		}
	}
	return res;
}

std::string FunctionBundle::display_protection() const
{
	std::string res;
	if (need_compile()) {
		switch (compilation_type()) {
		case ctVirtualization:
			res = language[lsVirtualization];
			break;
		case ctMutation:
			res = language[lsMutation];
			break;
		case ctUltra:
			res = string_format("%s (%s + %s)", language[lsUltra].c_str(), language[lsMutation].c_str(), language[lsVirtualization].c_str());
			break;
		default:
			res = "?";
			break;
		}
		if (compilation_type() != ctMutation && (compilation_options() & coLockToKey)) {
			res += ", ";
			res += language[lsLockToSerialNumber];
		}
	} else {
		res = language[lsNone];
	}
	return res;
}

bool FunctionBundle::show_arch_name() const 
{ 
	return owner_ && owner_->show_arch_name(); 
}

/**
 * FunctionBundleList
 */

FunctionBundleList::FunctionBundleList()
	: ObjectList<FunctionBundle>(), show_arch_name_(false)
{

}

FunctionBundle *FunctionBundleList::Add(IArchitecture *arch, IFunction *func)
{
	FunctionName name = func->full_name();
	bool is_unknown = (func->type() == otUnknown);
	FunctionBundle *bundle = name.name().empty() ? NULL : GetFunctionByName(name.name(), is_unknown);
	if (!bundle) {
		bundle = new FunctionBundle(this, name, is_unknown);
		AddObject(bundle);
	}
	bundle->Add(arch, func);
	return bundle;
}

void FunctionBundleList::RemoveObject(FunctionBundle *bundle)
{
	std::map<FunctionBundleHash, FunctionBundle *>::const_iterator it; // C++11
	for (it = map_.begin(); it != map_.end(); it++) {
		if (it->second == bundle) {
			map_.erase(it);
			break;
		}
	}
	ObjectList<FunctionBundle>::RemoveObject(bundle);
}

FunctionBundle *FunctionBundleList::GetFunctionByName(const std::string &name, bool need_unknown) const
{
	std::map<FunctionBundleHash, FunctionBundle *>::const_iterator it = map_.find(FunctionBundleHash(name, need_unknown));
	if (it != map_.end())
		return it->second;

	return NULL;
}

FunctionBundle *FunctionBundleList::GetFunctionById(const std::string &id) const
{
	for (size_t i = 0; i < count(); i++) {
		FunctionBundle *func = item(i);
		if (func->id() == id)
			return func;
	}
	return NULL;
}

FunctionBundle *FunctionBundleList::GetFunctionByFunc(IFunction *func) const
{
	for (size_t i = 0; i < count(); i++) {
		FunctionBundle *bundle = item(i);
		for (size_t j = 0; j < bundle->count(); j++) {
			FunctionArch *func_arch = bundle->item(j);
			if (func_arch->func() == func)
				return bundle;
		}
	}
	return NULL;
}

FunctionBundle *FunctionBundleList::GetFunctionByAddress(IArchitecture *arch, uint64_t address) const
{
	for (size_t i = 0; i < count(); i++) {
		FunctionBundle *bundle = item(i);
		for (size_t j = 0; j < bundle->count(); j++) {
			FunctionArch *func_arch = bundle->item(j);
			if (func_arch->arch() == arch && func_arch->func()->address() == address)
				return bundle;
		}
	}
	return NULL;
}

void FunctionBundleList::AddObject(FunctionBundle *bundle)
{
	ObjectList<FunctionBundle>::AddObject(bundle);

	if (!bundle->name().empty()) {
		FunctionBundleHash hash(bundle->name(), bundle->is_unknown());
		if (map_.find(hash) == map_.end())
			map_[hash] = bundle;
	}
}

/**
 * BaseArchitecture
 */

BaseArchitecture::BaseArchitecture(IFile *owner, uint64_t offset, uint64_t size)
	: IArchitecture(), owner_(owner), source_(NULL), offset_(offset), size_(size), selected_segment_(NULL),
	 append_mode_(false)
{
	map_function_list_ = new MapFunctionList(this);
	compiler_function_list_ = new CompilerFunctionList();
	end_marker_list_ = new MarkerCommandList();
	memory_manager_ = new MemoryManager(this);
}

BaseArchitecture::BaseArchitecture(IFile *owner, const BaseArchitecture &src)
	: IArchitecture(src), owner_(owner), selected_segment_(NULL)
{
	offset_ = src.offset_;
	size_ = src.size_;
	source_ = &src;
	append_mode_ = src.append_mode_;
	map_function_list_ = src.map_function_list_->Clone(this);
	compiler_function_list_ = src.compiler_function_list_->Clone();
	end_marker_list_ = src.end_marker_list_->Clone();
	memory_manager_ = new MemoryManager(this);
}

BaseArchitecture::~BaseArchitecture()
{
	if (owner_)
		owner_->RemoveObject(this);

	delete end_marker_list_;
	delete compiler_function_list_;
	delete map_function_list_;
	delete memory_manager_;
}

std::string BaseArchitecture::map_file_name() const
{
	if (!owner_)
		return std::string();
	return os::ChangeFileExt(owner_->file_name().c_str(), ".map");
}

bool BaseArchitecture::AddressSeek(uint64_t address)
{
	ISection *segment = segment_list()->GetSectionByAddress(address);

	if (!segment || segment->physical_size() <= address - segment->address()) {
		selected_segment_ = NULL;
		return false;
	}
		
	selected_segment_ = segment;
	Seek(segment->physical_offset() + address - segment->address());
	return true;
}

uint64_t BaseArchitecture::Seek(uint64_t position) const
{
	position += offset_;
	// don't need to check size for append mode
	if (position < offset_ || (!append_mode_ && position >= offset_ + size_))
		throw std::runtime_error("Runtime error at Seek");
	return owner_->Seek(position) - offset_;
}

uint64_t BaseArchitecture::Tell() const
{
	uint64_t position = owner_->Tell();
	// don't need to check size for append mode
	if (position < offset_ || (!append_mode_ && position >= offset_ + size_))
		throw std::runtime_error("Runtime error at Tell");
	return position - offset_;
}

uint64_t BaseArchitecture::AddressTell()
{
	uint64_t position = Tell();
	ISection *segment = segment_list()->GetSectionByOffset(position);
	if (!segment)
		return 0;

	return segment->address() + position - segment->physical_offset();
}

uint64_t BaseArchitecture::Resize(uint64_t size)
{
	owner_->Resize(offset_ + size);
	size_ = size;
	return size_;
}

bool BaseArchitecture::Prepare(CompileContext &ctx)
{
	size_t i;

	uint32_t runtime_options = import_list()->GetRuntimeOptions();
	if (!runtime_options)
		runtime_options = compiler_function_list()->GetRuntimeOptions();

	if (ctx.options.flags & cpResourceProtection)
		runtime_options |= roResources;

	if (ctx.options.flags & cpInternalMemoryProtection)
		runtime_options |= roMemoryProtection;

	if (ctx.options.file_manager)
		runtime_options |= ctx.options.file_manager->GetRuntimeOptions();

	if ((runtime_options & roKey) == 0) {
		for (i = 0; i < function_list()->count(); i++) {
			IFunction *func = function_list()->item(i);
			if (func->need_compile() && func->type() != otUnknown && func->compilation_type() != ctMutation && (func->compilation_options() & coLockToKey)) {
				runtime_options |= roKey;
				break;
			}
		}
	}
	if ((runtime_options & roStrings) == 0) {
		for (i = 0; i < function_list()->count(); i++) {
			IFunction *func =  function_list()->item(i);
			if (func->need_compile() && func->type() == otString) {
				runtime_options |= roStrings;
				break;
			}
		}
	}

	if (runtime_options & (roKey | roActivation)) {
		if  (!ctx.options.licensing_manager || ctx.options.licensing_manager->empty()) {
			Notify(mtError, ctx.options.licensing_manager, language[lsLicensingParametersNotInitialized]);
			return false;
		}
		if ((runtime_options & roActivation) && ctx.options.licensing_manager->activation_server().empty()) {
			Notify(mtError, NULL, language[lsActivationServerNotSpecified]);
			return false;
		}
	} else {
		ctx.options.licensing_manager = NULL;
	}


	if (!ctx.options.hwid.empty())
		runtime_options |= roHWID;

	if (runtime_options || ctx.options.sdk_flags) {
		if (!ctx.runtime)
			throw std::runtime_error("Runtime error at Prepare");
	} else if (ctx.options.flags & (cpPack | cpImportProtection | cpCheckDebugger | cpCheckVirtualMachine | cpMemoryProtection | cpLoader)) {
		if (!ctx.runtime)
			throw std::runtime_error("Runtime error at Prepare");
		if ((ctx.options.flags & (cpCheckDebugger | cpCheckVirtualMachine)) == 0 || !ctx.runtime->function_list()->GetRuntimeOptions())
			ctx.runtime->segment_list()->clear();
	} else {
		ctx.runtime = NULL;
	}

	if (ctx.runtime) {
		IFunctionList *function_list = ctx.runtime->function_list();
		for (i = 0; i < function_list->count(); i++) {
			IFunction *func =  function_list->item(i);
			switch (func->tag()) {
			case ftLicensing:
				func->set_need_compile((runtime_options & (roHWID | roKey | roActivation)) != 0);
				break;
			case ftBundler:
				func->set_need_compile((runtime_options & roBundler) != 0);
				break;
			case ftResources:
				func->set_need_compile((runtime_options & roResources) != 0);
				break;
			case ftRegistry:
				func->set_need_compile((runtime_options & roRegistry) != 0);
				break;
			case ftLoader: 
			case ftProcessor:
				func->set_need_compile(false);
				break;
			}
		}
	}

	return true;
}

bool BaseArchitecture::Compile(CompileOptions &options, IArchitecture *runtime)
{
	if (source_) {
		// copy image data to file
		offset_ = owner()->size();
		source_->Seek(0);
		Seek(0);
		CopyFrom(*source_, size_);
	}

	IFunctionList *list = function_list();
	if (!list)
		return true;

#ifdef CHECKED
	if (runtime && !runtime->check_hash()) {
		std::cout << "------------------- BaseArchitecture::Compile " << __LINE__ << " -------------------" << std::endl;
		std::cout << "runtime->check_hash(): false" << std::endl;
		std::cout << "---------------------------------------------------------" << std::endl;
		return false;
	}
#endif

	if (options.script)
		options.script->DoBeforeCompilation();

	CompileContext ctx;

	ctx.options = options;
	ctx.options.sdk_flags = import_list()->GetSDKOptions() | compiler_function_list()->GetSDKOptions();
	ctx.file = this;
	ctx.runtime = runtime;
	ctx.manager = memory_manager_;

#ifdef CHECKED
	if (runtime && !runtime->check_hash()) {
		std::cout << "------------------- BaseArchitecture::Compile " << __LINE__ << " -------------------" << std::endl;
		std::cout << "runtime->check_hash(): false" << std::endl;
		std::cout << "---------------------------------------------------------" << std::endl;
		return false;
	}
#endif

	if (!Prepare(ctx))
		return false;

#ifdef CHECKED
	if (runtime && !runtime->check_hash()) {
		std::cout << "------------------- BaseArchitecture::Compile " << __LINE__ << " -------------------" << std::endl;
		std::cout << "runtime->check_hash(): false" << std::endl;
		std::cout << "---------------------------------------------------------" << std::endl;
		return false;
	}
#endif

	if (!list->Prepare(ctx))
		return false;

#ifdef CHECKED
	if (runtime && !runtime->check_hash()) {
		std::cout << "------------------- BaseArchitecture::Compile " << __LINE__ << " -------------------" << std::endl;
		std::cout << "runtime->check_hash(): false" << std::endl;
		std::cout << "---------------------------------------------------------" << std::endl;
		return false;
	}
#endif
	if (ctx.file->runtime_function_list() && ctx.file->runtime_function_list()->count()) {
		size_t k, i, j;
		std::map<uint64_t, IRuntimeFunction *> runtime_function_map;
		
		k = ctx.runtime && ctx.runtime->segment_list()->count() ? 2 : 1;
		for (j = 0; j < k; j++) {
			IArchitecture *file = (j == 0) ? ctx.file : ctx.runtime;
			for (size_t i = 0; i < file->runtime_function_list()->count(); i++) {
				IRuntimeFunction *runtime_function = file->runtime_function_list()->item(i);
				if (!runtime_function->begin())
					continue;

				runtime_function_map[runtime_function->begin()] = runtime_function;
			}
		}

		for (i = 0; i < memory_manager_->count() - 1; i++) {
			MemoryRegion *region = memory_manager_->item(i);
			if ((region->type() & mtExecutable) == 0)
				continue;

			region->exclude_type(mtExecutable);

			std::map<uint64_t, IRuntimeFunction *>::const_iterator it = runtime_function_map.upper_bound(region->address());
			if (it != runtime_function_map.begin())
				it--;

			while (it != runtime_function_map.end()) {
				IRuntimeFunction *runtime_function = it->second;
				if (runtime_function->begin() >= region->end_address())
					break;

				if (std::max<uint64_t>(runtime_function->begin(), region->address()) < std::min<uint64_t>(runtime_function->end(), region->end_address())) {
					region->exclude_type(mtReadable);
					break;
				}
				it++;
			}
		}
	}
	if (ctx.options.flags & cpDebugMode) {
		for (size_t i = 0; i < memory_manager_->count(); i++) {
			MemoryRegion *region = memory_manager_->item(i);
			if (region->parent_function()) {
				region->exclude_type(mtExecutable);
				region->exclude_type(mtReadable);
			}
		}
	}

	ctx.manager->Pack();

	if (!list->Compile(ctx))
		return false;

	if (options.script)
		options.script->DoBeforeSaveFile();

	append_mode_ = true;
	Save(ctx);
	size_ = size();
	append_mode_ = false;

	return true;
}

void BaseArchitecture::Notify(MessageType type, IObject *sender, const std::string &message) const
{
	if (owner_)
		owner_->Notify(type, sender, message);
}

void BaseArchitecture::StartProgress(const std::string &caption, unsigned long long max) const
{
	if (owner_)
		owner_->StartProgress(caption, max);
}

void BaseArchitecture::StepProgress(unsigned long long value) const
{
	if (owner_)
		owner_->StepProgress(value);
}

void BaseArchitecture::EndProgress() const
{
	if (owner_)
		owner_->EndProgress();
}

std::string BaseArchitecture::ReadANSIString(uint64_t address)
{
	if (!AddressSeek(address))
		return std::string();

	std::string res;
	for (;;) {
		if (fixup_list()->GetFixupByNearAddress(address))
			return std::string();
		unsigned char c = ReadByte();
		address += sizeof(c);
		if (c == '\n' || c == '\r' || c == '\t' || c >= ' ') {
			res.push_back(c);
		} else {
			if (c)
				return std::string();
			break;
		}
	}

	return res;
}

std::string BaseArchitecture::ReadUnicodeString(uint64_t address)
{
	if (!AddressSeek(address))
		return std::string();

	os::unicode_string res;
	for (;;) {
		if (fixup_list()->GetFixupByNearAddress(address))
			return std::string();
		os::unicode_char w = ReadWord();
		address += sizeof(w);
		if ((w >> 8) == 0 && (w == '\n' || w == '\r' || w == '\t' || w >= ' ')) {
			res.push_back(w);
		} else {
			if (w)
				return std::string();
			break;
		}
	}

	return os::ToUTF8(res);
}

std::string BaseArchitecture::ReadANSIStringWithLength(uint64_t address)
{
	if (!AddressSeek(address))
		return std::string();

	std::string res;
	size_t l = ReadByte();
	for (size_t i = 0; i < l; i++) {
		if (fixup_list()->GetFixupByNearAddress(address))
			return std::string();
		unsigned char c = ReadByte();
		address += sizeof(c);
		if (c == '\n' || c == '\r' || c == '\t' || c >= ' ') {
			res.push_back(c);
		} else {
			if (c)
				return std::string();
			break;
		}
	}

	return res;
}

std::string BaseArchitecture::ReadString(uint64_t address)
{
	if ((segment_list()->GetMemoryTypeByAddress(address) & mtReadable) == 0)
		return std::string();

	std::string res = ReadANSIString(address);
	std::string unicode_str = ReadUnicodeString(address);
	std::string pascal_str = ReadANSIStringWithLength(address);
	if (unicode_str.size() > res.size())
		res = unicode_str;
	if (pascal_str.size() > res.size())
		res = pascal_str;
	return res;
}

void BaseArchitecture::ReadFromBuffer(Buffer &buffer)
{
	export_list()->ReadFromBuffer(buffer, *this);
	import_list()->ReadFromBuffer(buffer, *this);
	map_function_list()->ReadFromBuffer(buffer, *this);
	function_list()->ReadFromBuffer(buffer, *this);
}

uint64_t BaseArchitecture::CopyFrom(const IArchitecture &src, uint64_t count)
{
	return owner()->CopyFrom(*src.owner(), count);
}

bool BaseArchitecture::ReadMapFile(IMapFile &map_file)
{
	if (time_stamp() && map_file.time_stamp()) {
		if (time_stamp() != map_file.time_stamp()) {
			Notify(mtWarning, NULL, string_format(language[lsMAPFileHasIncorrectTimeStamp].c_str(), os::ExtractFileName(map_file.file_name().c_str()).c_str()));
			return false;
		}
	} else {
		uint64_t file_time_stamp = os::GetLastWriteTime(owner_->file_name().c_str());
		uint64_t map_time_stamp = os::GetLastWriteTime(map_file.file_name().c_str());
		if (abs(static_cast<int64_t>(file_time_stamp - map_time_stamp)) > 30) {
			Notify(mtWarning, NULL, string_format(language[lsMAPFileHasIncorrectTimeStamp].c_str(), os::ExtractFileName(map_file.file_name().c_str()).c_str()));
			return false;
		}
	}

	MapSection *functions = map_file.GetSectionByType(msFunctions);
	if (functions) {
		MapSection *sections = map_file.GetSectionByType(msSections);

		for (size_t i = 0; i < functions->count(); i++) {
			MapObject *func = functions->item(i);

			uint64_t address = func->address();
			if (func->segment() != NOT_ID) {
				if (!sections)
					continue;

				MapObject *section = NULL;
				for (size_t j = 0; j < sections->count(); j++) {
					if (sections->item(j)->segment() == func->segment()) {
						section = sections->item(j);
						break;
					}
				}
				if (!section)
					continue;

				address += section->address();
			}

			uint32_t memory_type = segment_list()->GetMemoryTypeByAddress(address);
			if (memory_type != mtNone)
				map_function_list()->Add(address, 0, (memory_type & mtExecutable) ? otCode : otData, DemangleName(func->name()));
		}
	}

	return true;
}

void BaseArchitecture::Rebase(uint64_t delta_base)
{
	map_function_list_->Rebase(delta_base);
	compiler_function_list_->Rebase(delta_base);
}

#ifdef CHECKED
bool BaseArchitecture::check_hash() const
{
	if (function_list() && !function_list()->check_hash())
		return false;
	return true;
}
#endif

/**
 * Folder
 */

Folder::Folder(Folder *owner, const std::string &name)
	: ObjectList<Folder>(), owner_(owner), name_(name), read_only_(false)
{

}

Folder::~Folder()
{
	clear();
	if (owner_)
		owner_->RemoveObject(this);
	Notify(mtDeleted, this);
}

Folder::Folder(Folder *owner, const Folder &src)
	: ObjectList<Folder>(src), owner_(owner)
{
	name_ = src.name_;
	read_only_ = src.read_only_;

	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

Folder *Folder::Clone(Folder *owner) const
{
	Folder *folder = new Folder(owner, *this);
	return folder;
}

Folder *Folder::Add(const std::string &name)
{
	Folder *folder = new Folder(this, name);
	AddObject(folder);
	Notify(mtAdded, folder);
	return folder;
}

void Folder::changed()
{
	Notify(mtChanged, this);
}

void Folder::set_name(const std::string &name)
{
	if (name_ != name) {
		name_ = name;
		changed();
	}
}

std::string Folder::id() const
{
	std::string res;
	const Folder *folder = this;
	while (folder->owner_) {
		res = res + string_format("\\%d", folder->owner_->IndexOf(folder));
		folder = folder->owner_;
	}
	return res;
}

void Folder::set_owner(Folder *owner)
{
	if (owner == owner_)
		return;
	if (owner_)
		owner_->RemoveObject(this);
	owner_ = owner;
	if (owner_)
		owner_->AddObject(this);
	changed();
}

void Folder::Notify(MessageType type, IObject *sender, const std::string &message) const
{
	if (owner_)
		owner_->Notify(type, sender, message);
}

Folder *Folder::GetFolderById(const std::string &id) const
{
	if (this->id() == id)
		return (Folder *)this;
	for (size_t i = 0; i < count(); i++) {
		Folder *res = item(i)->GetFolderById(id);
		if (res)
			return res;
	}
	return NULL;
}

/**
 * FolderList
 */

FolderList::FolderList(IFile *owner)
	: Folder(NULL, ""), owner_(owner)
{

}

FolderList::FolderList(IFile *owner, const FolderList & /*src*/)
	: Folder(NULL, ""), owner_(owner)
{

}

FolderList *FolderList::Clone(IFile *owner) const
{
	FolderList *list = new FolderList(owner, *this);
	return list;
}

std::vector<Folder*> FolderList::GetFolderList(bool skip_read_only) const
{
	std::vector<Folder*> res;
	Folder *folder;
	size_t i, j;

	for (i = 0; i < count(); i++) {
		folder = item(i);
		if (skip_read_only && folder->read_only())
			continue;
		res.push_back(folder);
	}
	for (i = 0; i < res.size(); i++) {
		folder = res[i];
		for (j = 0; j < folder->count(); j++) {
			res.push_back(folder->item(j));
		}
	}
	return res;
}

void FolderList::Notify(MessageType type, IObject *sender, const std::string &message) const
{
	if (owner_) {
		if (type == mtDeleted) {
			for (size_t i = 0; i < owner_->count(); i++) {
				IArchitecture *arch = owner_->item(i);
				if (!arch->visible())
					continue;

				IFunctionList *function_list = arch->function_list();
				for (size_t i = function_list->count(); i > 0; i--) {
					IFunction *func = function_list->item(i - 1);
					if (func->folder() == sender)
						delete func;
				}
			}
		}
		owner_->Notify(type, sender, message);
	}
}

/**
 * IFile
 */

IFile::IFile(ILog *log)
	: ObjectList<IArchitecture>(), stream_(NULL), log_(log), skip_change_notifications_(false)
{
	folder_list_ = new FolderList(this);
	map_function_list_ = new MapFunctionBundleList(this);
	function_list_ = new FunctionBundleList();
}

IFile::IFile(const IFile &src, const char *file_name)
	: ObjectList<IArchitecture>(src), stream_(NULL), log_(NULL), skip_change_notifications_(true)
{
	std::auto_ptr<FileStream> stream(new FileStream());
	if (src.file_name().compare(file_name) == 0)
	{
		if  (!stream->Open(file_name, fmOpenRead | fmShareDenyWrite))
			throw std::runtime_error(string_format(language[os::FileExists(file_name) ? lsOpenFileError : lsFileNotFound].c_str(), file_name));
	} else 
	{
		if (!stream->Open(file_name, fmCreate | fmOpenReadWrite | fmShareDenyWrite))
			throw std::runtime_error(string_format(language[lsCreateFileError].c_str(), file_name));
	}
	folder_list_ = src.folder_list()->Clone(this);
	map_function_list_ = new MapFunctionBundleList(this);
	function_list_ = new FunctionBundleList();
	file_name_ = file_name;
	stream_ = stream.release();
	log_ = src.log_;
	skip_change_notifications_ = true;
}

IFile::~IFile()
{
	log_ = NULL;
	CloseStream();
	delete folder_list_;
	delete map_function_list_;
	delete function_list_;
}

IFile *IFile::Clone(const char *file_name) const
{
	IFile *file = new IFile(*this, file_name);
	return file;
}

bool IFile::OpenResource(const void *resource, size_t size, bool is_enc)
{
	Close();

	if (is_enc) {
		uint32_t key = 0;
		if (size >= sizeof(key)) {
			key = *reinterpret_cast<const uint32_t *>(resource);
			resource = reinterpret_cast<const uint8_t *>(resource) + sizeof(key);
			size -= sizeof(key);
		}

		stream_ = new MemoryStreamEnc(resource, size, key);
	}
	else {
		stream_ = new MemoryStream();
		stream_->Write(resource, size);
	}

	try {
		return (ReadHeader(foRead) == osSuccess);
	} catch(std::runtime_error &) {
		return false;
	}
}

bool IFile::OpenModule(uint32_t process_id, HMODULE module)
{
	Close();

	auto stream = new ModuleStream();
	stream_ = stream;
	if (!stream->Open(process_id, module))
		return false;

	return true;
}

OpenStatus IFile::Open(const char *file_name, uint32_t open_mode, std::string *error)
{
	Close();

	int mode = fmShareDenyWrite;
	if ((open_mode & (foRead | foWrite)) == (foRead | foWrite)) {
		mode |= fmOpenReadWrite;
	} else if (open_mode & foWrite) {
		mode |= fmOpenWrite;
	}

	if (open_mode & foCopyToTemp) {
		file_name_tmp_ = os::GetTempFilePathName();
		if (!os::FileCopy(file_name, file_name_tmp_.c_str())) {
			os::FileDelete(file_name_tmp_.c_str());
			file_name_tmp_.clear();
			return osOpenError;
		}
	}

	auto stream = new FileStream();
	stream_ = stream; 
	if (!stream->Open(file_name_tmp_.empty() ? file_name : file_name_tmp_.c_str(), mode))
	{
		return osOpenError;
	}

	file_name_ = file_name;
	try {
		OpenStatus res = ReadHeader(open_mode);
		if (res == osSuccess) {
			std::set<ISectionList *> mixed_map;
			for (size_t i = 0; i < count(); i++) {
				IArchitecture *arch = item(i);
				if (arch->function_list())
					mixed_map.insert(arch->segment_list());
			}
			bool show_arch_name = mixed_map.size() > 1;
			function_list()->set_show_arch_name(show_arch_name);
			map_function_list()->set_show_arch_name(show_arch_name);
		}

		return res;
	} catch(canceled_error &) {
		throw;
	} catch(std::runtime_error & e) {
		if (error)
			*error = e.what();
		return osInvalidFormat;
	}
}

void IFile::Close()
{
	CloseStream();
	file_name_.clear();
	clear();
	map_function_list_->clear();
	function_list_->clear();
	folder_list_->clear();
}

void IFile::CloseStream()
{
	if (stream_) {
		delete stream_;
		stream_ = NULL;
	}
	if(!file_name_tmp_.empty())
	{
		os::FileDelete(file_name_tmp_.c_str());
		file_name_tmp_.clear();
	}
}

uint8_t IFile::ReadByte()
{
	uint8_t b;

	Read(&b, sizeof(b));
	return b;
}

uint16_t IFile::ReadWord()
{
	uint16_t w;

	Read(&w, sizeof(w));
	return w;
}

uint32_t IFile::ReadDWord()
{
	uint32_t dw;

	Read(&dw, sizeof(dw));
	return dw;
}

uint64_t IFile::ReadQWord()
{
	uint64_t qw;

	Read(&qw, sizeof(qw));
	return qw;
}

size_t IFile::Read(void *buffer, size_t count)
{
	size_t res = stream_->Read(buffer, count);
	if (res != count)
		throw std::runtime_error("Runtime error at Read");
	return res;
}

size_t IFile::Write(const void *buffer, size_t count)
{
	size_t res = stream_->Write(buffer, count);
	if (res != count)
		throw std::runtime_error("Runtime error at Write");
	return res;
}

void IFile::Flush()
{
	if (stream_)
		stream_->Flush();
}

std::string IFile::ReadString()
{
	std::string res;

	while (true) {
		char c = ReadByte();
		if (c == '\0')
			break;
		res.push_back(c);
	}

	return res;
}

uint64_t IFile::Seek(uint64_t position)
{
	uint64_t res = stream_->Seek(position, soBeginning);
	if (res != position)
		throw std::runtime_error("Runtime error at Seek");
	return res;
}

uint64_t IFile::Tell()
{
	uint64_t res = stream_->Tell();
	if (res == (uint64_t)-1)
		throw std::runtime_error("Runtime error at Tell");
	return res;
}

uint64_t IFile::size() const 
{ 
	uint64_t res = stream_->Size();
	if (res == (uint64_t)-1)
		throw std::runtime_error("Runtime error at Size");
	return res;
}

uint64_t IFile::Resize(uint64_t size)
{
	uint64_t res = stream_->Resize(size);
	if (res != size)
		throw std::runtime_error("Runtime error at Resize");
	return res;
}

bool IFile::Compile(CompileOptions &options)
{
	bool need_show_arch = (visible_count() > 1);
	IFile *runtime = this->runtime();
	for (size_t i = 0; i < count(); i++) {
		IArchitecture *arch = item(i);

		if (options.architecture)
			*options.architecture = arch;

		if (need_show_arch && log_)
			log_->set_arch_name(arch->name());

		if (!arch->Compile(options, runtime ? runtime->GetArchitectureByType(arch->type()) : NULL))
			return false;
	}

	if (options.architecture)
		*options.architecture = NULL;

	if (options.watermark)
		options.watermark->inc_use_count();

	return true;
}

uint64_t IFile::CopyFrom(IFile &source, uint64_t count)
{
	uint64_t total = 0; 
	while (count) {
		size_t copy_count = static_cast<size_t>(count);
		if (copy_count != count) 
			copy_count = -1;
		size_t res = stream_->CopyFrom(*source.stream_, copy_count);
		if (!res)
			break;
		count -= res;
		total += res;
	}
	return total;
}

void IFile::Notify(MessageType type, IObject *sender, const std::string &message) const
{
	if (log_) {
		if (skip_change_notifications_ && (type == mtAdded || type == mtChanged || type == mtDeleted))
			return;
		log_->Notify(type, sender, message);
	}
}

void IFile::StartProgress(const std::string &caption, unsigned long long max) const
{
	if (log_)
		log_->StartProgress(caption, max);
}

void IFile::StepProgress(unsigned long long value) const
{
	if (log_)
		log_->StepProgress(value);
}

void IFile::EndProgress() const
{
	if (log_)
		log_->EndProgress();
}

std::map<Watermark *, size_t> IFile::SearchWatermarks(const WatermarkManager &watermark_list)
{
	std::map<Watermark *, size_t> res;

	uint64_t read_size;
	size_t i, j, n, k, r;
	uint8_t buf[4096];

	if (count() == 0) {
		uint64_t file_size = size();
		StartProgress(string_format("%s...", language[lsSearching].c_str()), static_cast<size_t>(file_size));

		watermark_list.InitSearch();
		Seek(0);
		for (read_size = 0; read_size < file_size; read_size += n) {
			n = Read(buf, std::min(static_cast<size_t>(file_size - read_size), sizeof(buf)));
			StepProgress(n);
			for (k = 0; k < n; k++) {
				uint8_t b = buf[k];
				for (r = 0; r < watermark_list.count(); r++) {
					Watermark *watermark = watermark_list.item(r);
					if (watermark->SearchByte(b)) {
						res[watermark]++;
					}
				}
			}
		}
		EndProgress();
	} else {
		for (i = 0; i < count(); i++) {
			IArchitecture *file = item(i);

			n = 0;
			for (j = 0; j < file->segment_list()->count(); j++) {
				ISection *segment = file->segment_list()->item(j);
				n += static_cast<size_t>(segment->physical_size());
			}

			StartProgress(string_format("%s...", language[lsSearching].c_str()), n);
			for (j = 0; j < file->segment_list()->count(); j++) {
				ISection *segment = file->segment_list()->item(j);
				if (!segment->physical_size())
					continue;

				watermark_list.InitSearch();
				file->Seek(segment->physical_offset());
				for (read_size = 0; read_size < segment->physical_size(); read_size += n) {
					n = file->Read(buf, std::min(static_cast<size_t>(segment->physical_size() - read_size), sizeof(buf)));
					StepProgress(n);
					for (k = 0; k < n; k++) {
						uint8_t b = buf[k];
						for (r = 0; r < watermark_list.count(); r++) {
							Watermark *watermark = watermark_list.item(r);
							if (watermark->SearchByte(b)) {
								res[watermark]++;
							}
						}
					}
				}
			}
			EndProgress();
		}
	}

	return res;
}

size_t IFile::visible_count() const
{
	size_t res = 0;
	for (size_t i = 0; i < count(); i++) {
		if (item(i)->visible())
			res++;
	}
	return res;
}

IArchitecture *IFile::GetArchitectureByType(uint32_t type) const
{
	for (size_t i = 0; i < count(); i++) {
		IArchitecture *arch = item(i);
		if (arch->type() == type)
			return arch;
	}
	return NULL;
}

IArchitecture *IFile::GetArchitectureByName(const std::string &name) const
{
	for (size_t i = 0; i < count(); i++) {
		IArchitecture *arch = item(i);
		if (arch->name() == name)
			return arch;
	}
	return NULL;
}