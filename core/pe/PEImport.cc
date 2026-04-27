

#include "../../runtime/common.h"
#include "../../runtime/crypto.h"
#include "../objects.h"
#include "../osutils.h"
#include "../streams.h"
#include "../files.h"
#include "../processors.h"
#include "PEImport.h"
#include "PEDirectory.h"
#include "PEArchitecture.h"
#include "../core_internal/core.h"

// Intel module
#include "../intel/ir/IntelCommandType.h"
#include "../intel/ir/IntelOperand.h"
#include "../intel/ir/IntelCommand.h"
#include "../intel/ir/IntelFunction.h"
#include "../intel/ir/IntelFunctionList.h"
#include "../intel/ir/IntelSDK.h"
#include "../intel/ir/IntelLoader.h"
#include "../intel/vm/IntelVirtualMachineList.h"


PEImportFunction::PEImportFunction(PEImport* owner)
	: BaseImportFunction(owner), name_address_(0), address_(0), is_ordinal_(false), ordinal_(0)
{

}

PEImportFunction::PEImportFunction(PEImport* owner, const std::string& name)
	: BaseImportFunction(owner), name_(name), name_address_(0), address_(0), is_ordinal_(false), ordinal_(0)
{

}

PEImportFunction::PEImportFunction(PEImport* owner, uint64_t address, APIType type, MapFunction* map_function)
	: BaseImportFunction(owner), name_address_(0), address_(address), ordinal_(0), is_ordinal_(false)
{
	set_type(type);
	set_map_function(map_function);
}

PEImportFunction::PEImportFunction(PEImport* owner, const PEImportFunction& src)
	: BaseImportFunction(owner, src)
{
	name_ = src.name_;
	name_address_ = src.name_address_;
	address_ = src.address_;
	is_ordinal_ = src.is_ordinal_;
	ordinal_ = src.ordinal_;
}

PEImportFunction* PEImportFunction::Clone(IImport* owner) const
{
	PEImportFunction* func = new PEImportFunction(reinterpret_cast<PEImport*>(owner), *this);
	return func;
}

bool PEImportFunction::ReadFromFile(PEArchitecture& file, uint32_t& rva)
{
	address_ = rva + file.image_base();
	if (file.cpu_address_size() == osDWord) {
		IMAGE_THUNK_DATA32 thunk;

		file.Read(&thunk, sizeof(thunk));
		name_address_ = thunk.u1.AddressOfData;
		if (!name_address_)
			return false;
		is_ordinal_ = IMAGE_SNAP_BY_ORDINAL32(name_address_);
		rva += sizeof(uint32_t);
	}
	else {
		IMAGE_THUNK_DATA64 thunk;

		file.Read(&thunk, sizeof(thunk));
		name_address_ = thunk.u1.AddressOfData;
		if (!name_address_)
			return false;
		is_ordinal_ = IMAGE_SNAP_BY_ORDINAL64(name_address_);
		rva += sizeof(uint64_t);
	}

	if (is_ordinal_) {
		ordinal_ = IMAGE_ORDINAL32(name_address_);
		name_address_ = 0;
		name_ = string_format("Ordinal: %.4X", ordinal_);
	}
	else {
		name_address_ += file.image_base();
		uint64_t pos = file.Tell();
		if (!file.AddressSeek(name_address_ + sizeof(WORD)))
			throw std::runtime_error("Format error");
		name_ = file.ReadString();
		file.Seek(pos);
	}

	return true;
}

void PEImportFunction::FreeByManager(MemoryManager& manager, bool free_iat)
{
	if (name_address_)
		manager.Add(name_address_, sizeof(uint16_t) + name_.size() + 1);

	if (address_ && free_iat && (options() & (ioHasDataReference | ioNoReferences)) == 0)
		manager.Add(address_, OperandSizeToValue(manager.owner()->cpu_address_size()));
}

void PEImportFunction::Rebase(uint64_t delta_base)
{
	if (name_address_)
		name_address_ += delta_base;
	if (address_)
		address_ += delta_base;
}

bool PEImportFunction::IsInternal(const CompileContext& ctx) const
{
	if ((options() & ioFromRuntime) == 0) {
		if (ctx.options.flags & cpResourceProtection) {
			if (type() >= atLoadResource && type() <= atEnumResourceTypesW)
				return true;
		}
	}
	return false;
}

std::string PEImportFunction::display_name(bool show_ret) const
{
	return DemangleName(name_).display_name(show_ret);
}

/**
 * PEImport
 */

PEImport::PEImport(PEImportList* owner)
	: BaseImport(owner), name_address_(0), is_sdk_(false), original_first_thunk_address_(0), first_thunk_address_(0), time_stamp_(0), forwarder_chain_(0)
{

}

PEImport::PEImport(PEImportList* owner, bool is_sdk)
	: BaseImport(owner), name_address_(0), is_sdk_(is_sdk), original_first_thunk_address_(0), first_thunk_address_(0), time_stamp_(0), forwarder_chain_(0)
{

}

PEImport::PEImport(PEImportList* owner, const std::string& name)
	: BaseImport(owner), name_(name), name_address_(0), is_sdk_(false), original_first_thunk_address_(0), first_thunk_address_(0), time_stamp_(0), forwarder_chain_(0)
{

}

PEImport::PEImport(PEImportList* owner, const PEImport& src)
	: BaseImport(owner, src)
{
	name_ = src.name_;
	is_sdk_ = src.is_sdk_;
	name_address_ = src.name_address_;
	original_first_thunk_address_ = src.original_first_thunk_address_;
	first_thunk_address_ = src.first_thunk_address_;
	time_stamp_ = src.time_stamp_;
	forwarder_chain_ = src.forwarder_chain_;
}

PEImport* PEImport::Clone(IImportList* owner) const
{
	PEImport* import = new PEImport(reinterpret_cast<PEImportList*>(owner), *this);
	return import;
}

PEImportFunction* PEImport::item(size_t index) const
{
	return reinterpret_cast<PEImportFunction*>(IImport::item(index));
}

bool PEImport::ReadFromFile(PEArchitecture& file)
{
	static const ImportInfo kernel32_info[] = {
		{atLoadResource, "LoadResource", ioNone, ctNone},
		{atFindResourceA, "FindResourceA", ioNone, ctNone},
		{atFindResourceExA, "FindResourceExA", ioNone, ctNone},
		{atFindResourceW, "FindResourceW", ioNone, ctNone},
		{atFindResourceExW, "FindResourceExW", ioNone, ctNone},
		{atEnumResourceNamesA, "EnumResourceNamesA", ioNone, ctNone},
		{atEnumResourceNamesW, "EnumResourceNamesW", ioNone, ctNone},
		{atEnumResourceLanguagesA, "EnumResourceLanguagesA", ioNone, ctNone},
		{atEnumResourceLanguagesW, "EnumResourceLanguagesW", ioNone, ctNone},
		{atEnumResourceTypesA, "EnumResourceTypesA", ioNone, ctNone},
		{atEnumResourceTypesW, "EnumResourceTypesW", ioNone, ctNone},
		{atNone, "ExitProcess", ioNoReturn, ctNone},
		{atNone, "ExitThread", ioNoReturn, ctNone},
		{atNone, "FreeLibraryAndExitThread", ioNoReturn, ctNone},
		{atNone, "GetVersion", ioNative, ctNone},
		{atNone, "GetVersionExA", ioNative, ctNone},
		{atNone, "GetVersionExW", ioNative, ctNone}
	};

	static const ImportInfo user32_info[] = {
		{atLoadStringA, "LoadStringA", ioNone, ctNone},
		{atLoadStringW, "LoadStringW", ioNone, ctNone}
	};

	static const ImportInfo msvbvm_info[] = {
		{atNone, "__vbaError", ioNoReturn, ctNone},
		{atNone, "__vbaErrorOverflow", ioNoReturn, ctNone},
		{atNone, "__vbaStopExe", ioNoReturn, ctNone},
		{atNone, "__vbaFailedFriend", ioNoReturn, ctNone},
		{atNone, "__vbaEnd", ioNoReturn, ctNone},
		{atNone, "__vbaFPException", ioNoReturn, ctNone},
		{atNone, "__vbaGenerateBoundsError", ioNoReturn, ctNone},
		{atNone, "Ordinal: 0064", ioNoReturn, ctNone},
	};

	static const ImportInfo default_info[] = {
		{atNone, "@System@@Halt0$qqrv", ioNoReturn, ctNone},
		{atNone, "exit", ioNoReturn, ctNone},
		{atNone, "abort", ioNoReturn, ctNone},
		{atNone, "?terminate@@YAXXZ", ioNoReturn, ctNone},
		{atNone, "?unexpected@@YAXXZ", ioNoReturn, ctNone},
		{atNone, "__std_terminate", ioNoReturn, ctNone},
		{atNone, "?_Xout_of_range@std@@YAXPEBD@Z", ioNoReturn, ctNone},
		{atNone, "?_Xlength_error@std@@YAXPEBD@Z", ioNoReturn, ctNone},
		{atNone, "_CxxThrowException", ioNoReturn, ctNone},
	};

	IMAGE_IMPORT_DESCRIPTOR import_descriptor;
	uint64_t pos;
	PEImportFunction* func;
	size_t i, j;
	std::string dll_name;

	file.Read(&import_descriptor, sizeof(import_descriptor));
	if (!import_descriptor.FirstThunk)
		return false;

	pos = file.Tell();
	name_address_ = import_descriptor.Name + file.image_base();
	if (!file.AddressSeek(name_address_))
		throw std::runtime_error("Format error");

	name_ = file.ReadString();

	original_first_thunk_address_ = import_descriptor.u.OriginalFirstThunk;
	if (original_first_thunk_address_)
		original_first_thunk_address_ += file.image_base();

	first_thunk_address_ = import_descriptor.FirstThunk;
	if (first_thunk_address_)
		first_thunk_address_ += file.image_base();

	if (!file.AddressSeek((original_first_thunk_address_ != 0) ? original_first_thunk_address_ : first_thunk_address_))
		throw std::runtime_error("Format error");

	time_stamp_ = import_descriptor.TimeDateStamp;
	forwarder_chain_ = import_descriptor.ForwarderChain;
	uint32_t rva = import_descriptor.FirstThunk;
	while (true) {
		func = new PEImportFunction(this);
		if (!func->ReadFromFile(file, rva)) {
			delete func;
			break;
		}
		AddObject(func);
	}

	file.Seek(pos);

	dll_name = name_;
	std::transform(dll_name.begin(), dll_name.end(), dll_name.begin(), tolower);
	std::string sdk_name;
	if (file.image_type() == itDriver) {
		if (dll_name.find('.') == (size_t)-1)
			dll_name += ".sys";
		sdk_name = string_format("vmprotectddk%d.sys", (file.cpu_address_size() == osDWord) ? 32 : 64);
	}
	else {
		if (dll_name.find('.') == (size_t)-1)
			dll_name += ".dll";
		sdk_name = string_format("vmprotectsdk%d.dll", (file.cpu_address_size() == osDWord) ? 32 : 64);
	}

	if (dll_name.compare(sdk_name) == 0) {
		is_sdk_ = true;
		for (i = 0; i < count(); i++) {
			func = item(i);
			const ImportInfo* import_info = owner()->GetSDKInfo(func->name());
			if (import_info) {
				func->set_type(import_info->type);
				if (import_info->options & ioHasCompilationType) {
					func->include_option(ioHasCompilationType);
					func->set_compilation_type(import_info->compilation_type);
					if (import_info->options & ioLockToKey)
						func->include_option(ioLockToKey);
				}
			}
		}
	}
	else {
		size_t c;
		const ImportInfo* import_info;
		if (dll_name.compare("kernel32.dll") == 0) {
			import_info = kernel32_info;
			c = _countof(kernel32_info);
		}
		else if (dll_name.compare("user32.dll") == 0) {
			import_info = user32_info;
			c = _countof(user32_info);
		}
		else if (dll_name.compare("msvbvm50.dll") == 0 || dll_name.compare("msvbvm60.dll") == 0) {
			import_info = msvbvm_info;
			c = _countof(msvbvm_info);
		}
		else {
			import_info = default_info;
			c = _countof(default_info);
		}

		if (import_info) {
			for (i = 0; i < count(); i++) {
				func = item(i);
				for (j = 0; j < c; j++) {
					if (func->name().compare(import_info[j].name) == 0) {
						func->set_type(import_info[j].type);
						if (import_info[j].options & ioNative)
							func->include_option(ioNative);
						if (import_info[j].options & ioNoReturn)
							func->include_option(ioNoReturn);
						break;
					}
				}
			}
		}
	}

	return true;
}

bool PEImport::FreeByManager(MemoryManager& manager, bool free_iat)
{
	if (!name_address_)
		return false;

	manager.Add(name_address_, name_.size() + 1);

	for (size_t i = 0; i < count(); i++) {
		item(i)->FreeByManager(manager, free_iat);
	}

	if (original_first_thunk_address_ && original_first_thunk_address_ != first_thunk_address_)
		manager.Add(original_first_thunk_address_, count() * OperandSizeToValue(manager.owner()->cpu_address_size()));

	return true;
}

void PEImport::Rebase(uint64_t delta_base)
{
	BaseImport::Rebase(delta_base);

	if (name_address_)
		name_address_ += delta_base;
	if (original_first_thunk_address_)
		original_first_thunk_address_ += delta_base;
	if (first_thunk_address_)
		first_thunk_address_ += delta_base;
}

PEImportFunction* PEImport::Add(uint64_t address, APIType type, MapFunction* map_function)
{
	PEImportFunction* import_function = new PEImportFunction(this, address, type, map_function);
	AddObject(import_function);
	return import_function;
}

void PEImport::WriteToFile(PEArchitecture& file) const
{
	IMAGE_IMPORT_DESCRIPTOR import_descriptor;

	import_descriptor.u.OriginalFirstThunk = original_first_thunk_address_ ? static_cast<uint32_t>(original_first_thunk_address_ - file.image_base()) : 0;
	import_descriptor.TimeDateStamp = time_stamp_;
	import_descriptor.ForwarderChain = forwarder_chain_;
	import_descriptor.Name = static_cast<uint32_t>(name_address_ - file.image_base());
	import_descriptor.FirstThunk = first_thunk_address_ ? static_cast<uint32_t>(first_thunk_address_ - file.image_base()) : 0;
	file.Write(&import_descriptor, sizeof(import_descriptor));
}

/**
 * PEImportList
 */

PEImportList::PEImportList(PEArchitecture* owner)
	: BaseImportList(owner), address_(0)
{

}

PEImportList::PEImportList(PEArchitecture* owner, const PEImportList& src)
	: BaseImportList(owner, src)
{
	address_ = src.address_;
}

PEImportList* PEImportList::Clone(PEArchitecture* owner) const
{
	PEImportList* import_list = new PEImportList(owner, *this);
	return import_list;
}

PEImport* PEImportList::item(size_t index) const
{
	return reinterpret_cast<PEImport*>(BaseImportList::item(index));
}

PEImportFunction* PEImportList::GetFunctionByAddress(uint64_t address) const
{
	return reinterpret_cast<PEImportFunction*>(BaseImportList::GetFunctionByAddress(address));
}

void PEImportList::ReadFromFile(PEArchitecture& file, PEDirectory& dir)
{
	if (!dir.address())
		return;

	address_ = dir.address();
	if (!file.AddressSeek(address_))
		throw std::runtime_error("Format error");

	while (true) {
		PEImport* imp = new PEImport(this);
		if (!imp->ReadFromFile(file)) {
			delete imp;
			break;
		}
		AddObject(imp);
	}
}

void PEImportList::WriteToFile(PEArchitecture& file, bool skip_sdk) const
{
	PEDirectory* dir = file.command_list()->GetCommandByType(IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (!dir)
		return;

	if (!file.AddressSeek(dir->address()))
		return;

	for (size_t i = 0; i < count(); i++) {
		PEImport* import = item(i);
		if (skip_sdk && import->is_sdk())
			continue;

import->WriteToFile(file);
	}

	IMAGE_IMPORT_DESCRIPTOR import_descriptor = IMAGE_IMPORT_DESCRIPTOR();
	file.Write(&import_descriptor, sizeof(import_descriptor));
}

void PEImportList::FreeByManager(MemoryManager& manager, bool free_iat)
{
	if (!address_)
		return;

	size_t c = 0;
	for (size_t i = 0; i < count(); i++) {
		if (item(i)->FreeByManager(manager, free_iat))
			c++;
	}

	manager.Add(address_, c * sizeof(IMAGE_IMPORT_DESCRIPTOR));
}

void PEImportList::Rebase(uint64_t delta_base)
{
	if (!address_)
		return;

	BaseImportList::Rebase(delta_base);

	address_ += delta_base;
}

PEImport* PEImportList::AddSDK()
{
	PEImport* sdk = new PEImport(this, true);
	AddObject(sdk);
	return sdk;
}
