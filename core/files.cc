/**
 * Operations with executable files.
 */

#include "../runtime/common.h"
#include "../runtime/crypto.h"
#include "objects.h"
#include "osutils.h"
#include "streams.h"
#include "files.h"
#include "files/utils.h"
#include "files/references.h"
#include "files/mapping.h"
#include "files/sections.h"
#include "files/imports.h"
#include "files/exports.h"
#include "files/fixups.h"
#include "files/relocations.h"
#include "files/seh.h"
#include "processors/proc_interfaces.h"
#include "processors/proc_crypto.h"

#include "inifile.h"
#include "lang.h"
#include "core_internal/core.h"
#include "script.h"
#include "../third-party/demangle/undname.h"
#include "../third-party/demangle/demangle.h"
#include "../third-party/demangle/unmangle.h"

#include "core_internal/watermark.h"
#include "core_internal/license.h"
#include "core_internal/file_manager.h"

// OperandSizeToValue, OperandSizeToStack, NameToString, DisplayString,
// DisplayValue, DemangleName, C_alloca -> files/utils.cc


// BaseLoadCommand, BaseCommandList, BaseSection, BaseSectionList -> files/sections.cc

// BaseImportFunction, BaseImport, BaseImportList -> files/imports.cc

// BaseExport, BaseExportList -> files/exports.cc

// BaseFixup, BaseFixupList -> files/fixups.cc

/**
 * // BaseRelocation, BaseRelocationList -> files/relocations.cc

/**
 * // BaseSEHandler, BaseSEHandlerList -> files/seh.cc

// Reference, ReferenceList -> files/references.cc

// MapObject, MapSection, BaseMapFile, MapFile,
// MapFunction, MapFunctionList, MapFunctionArch,
// MapFunctionBundle, MapFunctionBundleList -> files/mapping.cc


// Implementation moved to files/mapping.cc



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
 * BaseResource
 */

BaseResource::BaseResource(IResource *owner)
	: IResource(), owner_(owner), excluded_from_packing_(false)
{

}

BaseResource::BaseResource(IResource *owner, const BaseResource &src)
	: IResource(src), owner_(owner)
{
	excluded_from_packing_ = src.excluded_from_packing_;
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

BaseResource::~BaseResource()
{
	if (owner_)
		owner_->RemoveObject(this);
}

IResource *BaseResource::GetResourceByName(const std::string &name) const
{
	for (size_t i = 0; i < count(); i++) {
		IResource *resource = item(i);
		if (resource->name() == name)
			return resource;
	}
	return NULL;
}

IResource *BaseResource::GetResourceByType(uint32_t type) const
{
	for (size_t i = 0; i < count(); i++) {
		IResource *resource = item(i);
		if (resource->type() == type)
			return resource;
	}
	return NULL;
}

IResource *BaseResource::GetResourceById(const std::string &id) const
{
	if (this->id() == id)
		return (IResource *)this;
	for (size_t i = 0; i < count(); i++) {
		IResource *res = item(i)->GetResourceById(id);
		if (res)
			return res;
	}
	return NULL;
}

void BaseResource::set_excluded_from_packing(bool value)
{
	if (excluded_from_packing_ != value) {
		excluded_from_packing_ = value;
		Notify(mtChanged, this);
	}
}

void BaseResource::Notify(MessageType type, IObject *sender, const std::string &message) const
{
	if (owner_)
		owner_->Notify(type, sender, message);
}

OperandSize BaseResource::address_size() const
{
	return owner()->address_size();
}

Data BaseResource::hash() const
{
	Data res;
	res.PushBuff(name().c_str(), name().size() + 1);
	res.PushByte(excluded_from_packing());
	return res;
}

/**
 * BaseResourceList
 */

BaseResourceList::BaseResourceList(IArchitecture *owner)
	: IResourceList(), owner_(owner)
{

}

BaseResourceList::BaseResourceList(IArchitecture *owner, const BaseResourceList &src)
	: IResourceList(), owner_(owner)
{ 
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

IResource *BaseResourceList::GetResourceByName(const std::string &name) const
{
	for (size_t i = 0; i < count(); i++) {
		IResource *resource = item(i);
		if (resource->name() == name)
			return resource;
	}
	return NULL;
}

IResource *BaseResourceList::GetResourceByType(uint32_t type) const
{
	for (size_t i = 0; i < count(); i++) {
		IResource *resource = item(i);
		if (resource->type() == type)
			return resource;
	}
	return NULL;
}

IResource *BaseResourceList::GetResourceById(const std::string &id) const
{
	for (size_t i = 0; i < count(); i++) {
		IResource *res = item(i)->GetResourceById(id);
		if (res)
			return res;
	}
	return NULL;
}

std::vector<IResource*> BaseResourceList::GetResourceList() const
{
	std::vector<IResource*> res;
	size_t i, j;

	for (i = 0; i < count(); i++) {
		res.push_back(item(i));
	}
	for (i = 0; i < res.size(); i++) {
		IResource *resource = res[i];
		for (j = 0; j < resource->count(); j++) {
			res.push_back(resource->item(j));
		}
	}
	return res;
}

OperandSize BaseResourceList::address_size() const
{
	return owner_->cpu_address_size();
}

void BaseResourceList::Notify(MessageType type, IObject *sender, const std::string &message) const
{
	if (owner_)
		owner_->Notify(type, sender, message);
}

/**
 * BaseRuntimeFunction
 */

BaseRuntimeFunction::BaseRuntimeFunction(IRuntimeFunctionList *owner) 
	: IRuntimeFunction(), owner_(owner)
{

}

BaseRuntimeFunction::BaseRuntimeFunction(IRuntimeFunctionList *owner, const BaseRuntimeFunction &src) 
	: IRuntimeFunction(), owner_(owner)
{

}

BaseRuntimeFunction::~BaseRuntimeFunction()
{
	if (owner_)
		owner_->RemoveObject(this);
}

/**
 * BaseRuntimeFunctionList
 */

BaseRuntimeFunctionList::BaseRuntimeFunctionList()
	: IRuntimeFunctionList()
{

}

BaseRuntimeFunctionList::BaseRuntimeFunctionList(const BaseRuntimeFunctionList &src)
	: IRuntimeFunctionList(src)
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

void BaseRuntimeFunctionList::clear()
{
	map_.clear();
	IRuntimeFunctionList::clear();
}

IRuntimeFunction *BaseRuntimeFunctionList::GetFunctionByAddress(uint64_t address) const
{
	if (map_.empty())
		return NULL;

	std::map<uint64_t, IRuntimeFunction *>::const_iterator it = map_.upper_bound(address);
	if (it != map_.begin())
		it--;

	IRuntimeFunction *func = it->second;
	if (func->begin() <= address && func->end() > address)
		return func;

	return NULL;
}

IRuntimeFunction *BaseRuntimeFunctionList::GetFunctionByUnwindAddress(uint64_t address) const
{
	std::map<uint64_t, IRuntimeFunction *>::const_iterator it = unwind_map_.find(address);
	return (it != unwind_map_.end()) ? it->second : NULL;
}

void BaseRuntimeFunctionList::AddObject(IRuntimeFunction *func)
{
	IRuntimeFunctionList::AddObject(func);
	if (func->begin())
		map_[func->begin()] = func;
	if (func->unwind_address())
		unwind_map_[func->unwind_address()] = func;
}

void BaseRuntimeFunctionList::Rebase(uint64_t delta_base)
{
	map_.clear();
	unwind_map_.clear();
	for (size_t i = 0; i < count(); i++) {
		IRuntimeFunction *func = item(i);
		func->Rebase(delta_base);
		if (func->begin())
			map_[func->begin()] = func;
		if (func->unwind_address())
			unwind_map_[func->unwind_address()] = func;
	}
}

/**
 * CompilerFunction
 */

CompilerFunction::CompilerFunction(CompilerFunctionList *owner, CompilerFunctionType type, uint64_t address)
	: IObject(), owner_(owner), address_(address), type_(type), options_(0)
{
}

CompilerFunction::CompilerFunction(CompilerFunctionList *owner, const CompilerFunction &src)
	: IObject(src), owner_(owner)
{
	address_ = src.address_;
	type_ = src.type_;
	value_list_ = src.value_list_;
	options_ = src.options_;
}

CompilerFunction::~CompilerFunction()
{
	if (owner_)
		owner_->RemoveObject(this);
}

CompilerFunction *CompilerFunction::Clone(CompilerFunctionList *owner) const
{
	CompilerFunction *func = new CompilerFunction(owner, *this);
	return func;
}

void CompilerFunction::Rebase(uint64_t delta_base)
{
	address_ += delta_base;
}

/**
 * CompilerFunctionList
 */

CompilerFunctionList::CompilerFunctionList()
	: ObjectList<CompilerFunction>()
{

}

CompilerFunctionList::CompilerFunctionList(const CompilerFunctionList &src)
	: ObjectList<CompilerFunction>(src)
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

CompilerFunctionList *CompilerFunctionList::Clone() const
{
	CompilerFunctionList *compiler_function_list = new CompilerFunctionList(*this);
	return compiler_function_list;
}

CompilerFunction *CompilerFunctionList::Add(CompilerFunctionType type, uint64_t address)
{
	CompilerFunction *func = new CompilerFunction(this, type, address);
	AddObject(func);
	return func;
}

void CompilerFunctionList::AddObject(CompilerFunction *func)
{
	ObjectList<CompilerFunction>::AddObject(func);
	map_[func->address()] = func;
}

CompilerFunction *CompilerFunctionList::GetFunctionByAddress(uint64_t address) const
{
	std::map<uint64_t, CompilerFunction *>::const_iterator it = map_.find(address);
	if (it != map_.end())
		return it->second;
	return NULL;
}

CompilerFunction *CompilerFunctionList::GetFunctionByLowerAddress(uint64_t address) const
{
	if (map_.empty())
		return NULL;

	std::map<uint64_t, CompilerFunction *>::const_iterator it = map_.upper_bound(address);
	if (it != map_.begin())
		it--;
	return it->first > address ? NULL : it->second;
}

uint64_t CompilerFunctionList::GetRegistrValue(uint64_t address, uint64_t value) const
{
	if (!map_.empty()) {
		std::map<uint64_t, CompilerFunction *>::const_iterator it = map_.upper_bound(address);
		if (it != map_.begin())
			it--;

		while (true) {
			CompilerFunction *func = it->second;
			if (func->type() == cfBaseRegistr) {
				if (func->value(0) == value)
					return func->address() + func->value(1);
				break;
			}
			if (it == map_.begin())
				break;
			it--;
		}
	}
	return -1;
}

uint32_t CompilerFunctionList::GetSDKOptions() const
{
	uint32_t res = 0;
	for (size_t i = 0; i < count(); i++) {
		CompilerFunction *compiler_function = item(i);
		if (compiler_function->type() == cfDllFunctionCall && (compiler_function->options() & coUsed)) {
			switch (compiler_function->value(0) & 0xff) {
			case atIsValidImageCRC:
				res |= cpMemoryProtection;
				break;
			case atIsVirtualMachinePresent:
				res |= cpCheckVirtualMachine;
				break;
			case atIsDebuggerPresent:
				res |= cpCheckDebugger;
				break;
			}
		}
	}

	return res;
}

uint32_t CompilerFunctionList::GetRuntimeOptions() const
{
	uint32_t res = 0;
	for (size_t i = 0; i < count(); i++) {
		CompilerFunction *compiler_function = item(i);
		if (compiler_function->type() == cfDllFunctionCall && (compiler_function->options() & coUsed)) {
			switch (compiler_function->value(0) & 0xff) {
			case atSetSerialNumber:
			case atGetSerialNumberState:
			case atGetSerialNumberData:
			case atGetOfflineActivationString:
			case atGetOfflineDeactivationString:
				res |= roKey;
				break;
			case atGetCurrentHWID:
				res |= roHWID;
				break;
			case atActivateLicense:
			case atDeactivateLicense:
				res |= roKey | roActivation;
				break;
			}
		}
	}

	return res;
}

void CompilerFunctionList::Rebase(uint64_t delta_base)
{
	map_.clear();
	for (size_t i = 0; i < count(); i++) {
		CompilerFunction *func = item(i);
		func->Rebase(delta_base);
		map_[func->address()] = func;
	}
}

/**
 * MarkerCommand
 */

MarkerCommand::MarkerCommand(MarkerCommandList *owner, uint64_t address, uint64_t operand_address, 
	uint64_t name_reference, uint64_t name_address, ObjectType type)
	: IObject(), owner_(owner), address_(address), operand_address_(operand_address), name_address_(name_address), 
	name_reference_(name_reference), type_(type)
{

}

MarkerCommand::MarkerCommand(MarkerCommandList *owner, const MarkerCommand &src)
	: IObject(), owner_(owner) 
{
	address_ = src.address_;
	operand_address_ = src.operand_address_;
	name_address_ = src.name_address_;
	name_reference_ = src.name_reference_;
	type_ = src.type_;
}

MarkerCommand::~MarkerCommand()
{
	if (owner_)
		owner_->RemoveObject(this);
}

MarkerCommand *MarkerCommand::Clone(MarkerCommandList *owner) const
{
	MarkerCommand *command = new MarkerCommand(owner, *this);
	return command;
}

int MarkerCommand::CompareWith(const MarkerCommand &obj) const
{
	if (address() < obj.address())
		return -1;
	if (address() > obj.address())
		return 1;
	return 0;
}

/**
 * MarkerCommandList
 */

MarkerCommandList::MarkerCommandList()
	: ObjectList<MarkerCommand>()
{

}

MarkerCommandList::MarkerCommandList(const MarkerCommandList &src)
	: ObjectList<MarkerCommand>()
{
	for (size_t i = 0; i < src.count(); i++) {
		MarkerCommand *command = src.item(i);
		AddObject(command->Clone(this));
	}
}

MarkerCommand *MarkerCommandList::Add(uint64_t address, uint64_t operand_address, uint64_t name_reference, uint64_t name_address, ObjectType type)
{
	MarkerCommand *command = new MarkerCommand(this, address, operand_address, name_reference, name_address, type);
	AddObject(command);
	return command;
}

MarkerCommandList *MarkerCommandList::Clone() const 
{
	MarkerCommandList *list = new MarkerCommandList(*this);
	return list;
}

/**
 * MemoryRegion
 */

MemoryRegion::MemoryRegion(MemoryManager *owner, uint64_t address, size_t size,  uint32_t type, IFunction *parent_function)
	: IObject(), owner_(owner), address_(address), end_address_(address + size), type_(type), parent_function_(parent_function)
{

}

MemoryRegion::~MemoryRegion()
{
	if (owner_)
		owner_->RemoveObject(this);
}

uint64_t MemoryRegion::Alloc(uint64_t memory_size, uint32_t memory_type)
{
	if (size() < memory_size)
		return 0;

	if (memory_type != mtNone) {
		if (((memory_type & mtReadable) != 0 && (type_ & mtReadable) == 0)
			|| ((memory_type & mtWritable) != 0 && (type_ & mtWritable) == 0)
			|| ((memory_type & mtExecutable) != 0 && (type_ & mtExecutable) == 0)
			|| ((memory_type & mtNotPaged) != 0 && (type_ & mtNotPaged) == 0)
			|| ((memory_type & mtDiscardable) != (type_ & mtDiscardable)))
			return 0;
	}

	uint64_t res = address_;
	address_ += memory_size;
	return res;
}

int MemoryRegion::CompareWith(const MemoryRegion &obj) const
{
	if (address() < obj.address())
		return -1;
	if (address() > obj.address())
		return 1;
	return 0;
}

bool MemoryRegion::Merge(const MemoryRegion &src)
{
	if (type_ == src.type() && end_address_ == src.address()) {
		end_address_ = src.end_address();
		return true;
	}

	return false;
}

MemoryRegion *MemoryRegion::Subtract(uint64_t remove_address, size_t size)
{
	MemoryRegion *res = NULL;
	uint64_t remove_end_address = remove_address + size;
	if (address_ < remove_address)
	{
		if (end_address_ > remove_end_address)
		{
			// create overflow region
			res = new MemoryRegion(*this);
			res->address_ = remove_end_address;
		}
		if (end_address_ > remove_address)
		{
			end_address_ = remove_address;
		}
	} else
	{
		if (address_ < remove_end_address)
		{
			address_ = std::min(end_address_, remove_end_address);
		}
	}
	return res;
}

/**
 * MemoryManager
 */

MemoryManager::MemoryManager(IArchitecture *owner)
	: ObjectList<MemoryRegion>(), owner_(owner)
{

}

void MemoryManager::Add(uint64_t address, size_t size)
{
	Add(address, size, owner_->segment_list()->GetMemoryTypeByAddress(address), NULL);
}

void MemoryManager::Remove(uint64_t address, size_t size)
{
	if (size == 0 || count() == 0)
		return;

	const_iterator it = std::upper_bound(begin(), end(), address, CompareHelper());
	if (it != begin())
		it--;

	for (size_t i = it - begin(); i < count();) {
		MemoryRegion *region = item(i);
		if (region->address() >= address + size)
			break;

		MemoryRegion *sub_region = region->Subtract(address, size);
		if (sub_region) {
			InsertObject(i + 1, sub_region);
			break;
		}

		if (!region->size()) {
			erase(i);
			region->set_owner(NULL);
			delete region;
		} else {
			i++;
		}
	}
}

void MemoryManager::Add(uint64_t address, size_t size, uint32_t type, IFunction *parent_function)
{
	if (!size)
		return;

	const_iterator it = std::lower_bound(begin(), end(), address, CompareHelper());
	size_t index = (it == end()) ? NOT_ID : it - begin();
	if (index != NOT_ID) {
		if (index > 0) {
			MemoryRegion *prev_region = item(index - 1);
			if (prev_region->end_address() > address) {
				if (prev_region->end_address() >= address + size)
					return;
				size = static_cast<size_t>(address + size - prev_region->end_address());
				address = prev_region->end_address();
			}
		}
		MemoryRegion *next_region = item(index);
		if (next_region->end_address() < address + size)
			Add(next_region->end_address(), static_cast<size_t>(address + size - next_region->end_address()), type, parent_function);
		if (next_region->address() < address + size) {
			size = static_cast<size_t>(next_region->address() - address);
			if (!size)
				return;
		}
	}

	MemoryRegion *region = new MemoryRegion(this, address, size, type, parent_function);
	if (index == NOT_ID) {
		AddObject(region);
	} else {
		InsertObject(index, region);
	}
}

size_t MemoryManager::IndexOfAddress(uint64_t address) const
{
	if (count() == 0)
		return NOT_ID;

	const_iterator it = std::upper_bound(begin(), end(), address, CompareHelper());
	if (it != begin())
		it--;

	MemoryRegion *region = *it;
	if (region->address() <= address && region->end_address() > address)
		return (it - begin());

	return NOT_ID;
}

uint64_t MemoryManager::Alloc(size_t size, uint32_t memory_type, uint64_t address, size_t alignment)
{
	size_t i, delta, start, end;
	MemoryRegion *region;
	uint64_t res, tmp_address;

	if (address) {
		start = IndexOfAddress(address);
		if (start == NOT_ID)
			return 0;
		end = start + 1;
	} else {
		start = 0;
		end = count();
	}

	for (i = start; i < end; i++) {
		region = item(i);
		tmp_address = (address) ? address : region->address();
		if (alignment > 1)
			tmp_address = AlignValue(tmp_address, alignment);

		if (region->address() < tmp_address) {
			// need to separate the region
			delta = static_cast<size_t>(tmp_address - region->address());
			if (region->size() < delta + size)
				continue;
				
			// alloc memory for new region
			res = region->Alloc(delta, memory_type);
			if (res == 0)
				continue;

			// insert new region
			InsertObject(i, new MemoryRegion(this, res, delta, (region->type() & mtSolid) ? region->type() & ~mtExecutable : region->type(), region->parent_function()));
			i++;
		}

		res = region->Alloc(size, memory_type);
		if (res) {
			if (!region->size()) {
				erase(i);
				region->set_owner(NULL);
				delete region;
			}
			return res;
		}
	}

	if ((memory_type & mtDiscardable) && !address)
		return Alloc(size, memory_type & (~mtDiscardable), address, alignment);

	return 0;
}

MemoryRegion *MemoryManager::GetRegionByAddress(uint64_t address) const
{
	size_t i = IndexOfAddress(address);
	return (i == NOT_ID) ? NULL : item(i);
}

void MemoryManager::Pack()
{
	for (size_t i = count(); i > 1; i--) {
		MemoryRegion *dst = item(i - 2);
		MemoryRegion *src = item(i - 1);
		if (dst->Merge(*src)) {
			erase(i - 1);
			src->set_owner(NULL);
			delete src;
		}
	}
}

/**
 * CRCTable
 */

CRCTable::CRCTable(ValueCryptor *cryptor, size_t max_size)
	: cryptor_(NULL), max_size_(max_size)
{ 
	manager_ = new MemoryManager(NULL);
	if (cryptor)
		cryptor_ = new CRCValueCryptor(static_cast<uint32_t>(cryptor->item(0)->value()));
}

CRCTable::~CRCTable()
{ 
	delete manager_;
	delete cryptor_;
}

void CRCTable::Add(uint64_t address, size_t size)
{
	manager_->Add(address, size, mtReadable);
}

void CRCTable::Remove(uint64_t address, size_t size)
{
	manager_->Remove(address, size);
}

size_t CRCTable::WriteToFile(IArchitecture &file, bool is_positions, uint32_t *hash)
{
	size_t i;
	std::vector<uint8_t> dump;
	uint64_t address_base = is_positions ? 0 : file.image_base();

	manager_->Pack();

	uint64_t pos = file.Tell();
	crc_info_list_.reserve(manager_->count());
	for (i = 0; i < manager_->count(); i++) {
		MemoryRegion *region = manager_->item(i);

		if (is_positions) {
			file.Seek(region->address());
		} else {
			if (!file.AddressSeek(region->address()))
				continue;
		}

		dump.resize(region->size());
		file.Read(&dump[0], dump.size());
		CRCInfo crc_info(static_cast<uint32_t>(region->address() - address_base), dump);
		 
		crc_info_list_.push_back(crc_info);
	}
	file.Seek(pos);

	// need random order in the vector
	for (i = 0; i < crc_info_list_.size(); i++)
		std::swap(crc_info_list_[i], crc_info_list_[rand() % crc_info_list_.size()]);

	if (cryptor_) {
		for (i = 0; i < crc_info_list_.size(); i++) {
			CRCInfo crc_info = crc_info_list_[i];
			uint32_t address = crc_info.pod.address;
			uint32_t size = crc_info.pod.size;
			crc_info.pod.address = cryptor_->Encrypt(crc_info.pod.address);
			crc_info.pod.size = cryptor_->Encrypt(crc_info.pod.size);
			crc_info.pod.hash = cryptor_->Encrypt(crc_info.pod.hash);
			crc_info_list_[i] = crc_info;
		}
	}

	if (max_size_) {
		size_t max_count = max_size_ / sizeof(CRCInfo::POD);
		if (max_count < crc_info_list_.size())
			crc_info_list_.resize(max_count);
	}

	// write to file
	size_t res = 0;
	if (crc_info_list_.size())
		res = file.Write(&crc_info_list_[0].pod, crc_info_list_.size() * sizeof(CRCInfo::POD));
	if (max_size_) {
		for (size_t i = res; i < max_size_; i += sizeof(uint32_t)) {
			file.WriteDWord(rand32());
		}
	}
	if (hash)
		*hash = CalcCRC(crc_info_list_.size() ? &crc_info_list_[0].pod : NULL, res);
	return res;
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
		//read-only mode, not used yet (only tests)
		if  (!stream->Open(file_name, fmOpenRead | fmShareDenyWrite))
			throw std::runtime_error(string_format(language[os::FileExists(file_name) ? lsOpenFileError : lsFileNotFound].c_str(), file_name));
	} else 
	{
		//compile scenario, mainstream
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
#ifdef CHECKED
			std::cout << "------------------- IFile::Open " << __LINE__ << " -------------------" << std::endl;
			std::cout << "os::FileCopy: false" << std::endl;
			std::cout << "current path: " << os::GetCurrentPath().c_str() << std::endl;
			std::cout << "file_name: " << file_name << " (exists: " << (os::FileExists(file_name) ? "true" : "false") << ") " << std::endl;
			std::cout << "file_name_tmp: " << file_name_tmp_.c_str() << " (exists: " << (os::FileExists(file_name_tmp_.c_str()) ? "true" : "false") << ") " << std::endl;
			std::cout << "---------------------------------------------------------" << std::endl;
#endif
			os::FileDelete(file_name_tmp_.c_str());
			file_name_tmp_.clear();
			return osOpenError;
		}
	}

	auto stream = new FileStream();
	stream_ = stream; 
	if (!stream->Open(file_name_tmp_.empty() ? file_name : file_name_tmp_.c_str(), mode))
	{
#ifdef CHECKED
		std::cout << "------------------- IFile::Open " << __LINE__ << " -------------------" << std::endl;
		std::cout << "stream->Open: false" << std::endl;
		std::cout << "file_name: " << (file_name_tmp_.empty() ? file_name : file_name_tmp_.c_str()) << std::endl;
		std::cout << "---------------------------------------------------------" << std::endl;
#endif
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
#ifdef CHECKED
		std::cout << "------------------- IFile::Open " << __LINE__ << L" -------------------" << std::endl;
		std::cout << "exception: " << e.what() << std::endl;
		std::cout << "---------------------------------------------------------" << std::endl;
#endif
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

CRCInfo::CRCInfo(uint32_t address_, const std::vector<uint8_t> &dump)
{
	pod.address = address_;
	pod.size = static_cast<uint32_t>(dump.size());
	pod.hash = CalcCRC(dump.data(), dump.size());
}