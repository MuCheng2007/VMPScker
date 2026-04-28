/**
 * Executable imports implementations.
 * Rust mapping target: mod imports
 */

#include "imports.h"
#include "../files.h"
#include "../objects.h"
#include "../osutils.h"
#include "../streams.h"
#include "../core_internal/core.h"

/**
 * BaseImportFunction
 */

BaseImportFunction::BaseImportFunction(IImport *owner)
	: IImportFunction(), owner_(owner), type_(atNone), map_function_(NULL), compilation_type_(ctNone), options_(ioNone)
{

}

BaseImportFunction::BaseImportFunction(IImport *owner, const BaseImportFunction &src) 
	: IImportFunction(src), owner_(owner)
{
	type_ = src.type_;
	compilation_type_ = src.compilation_type_;
	options_ = src.options_;
	map_function_ = src.map_function_;
}

BaseImportFunction::~BaseImportFunction()
{
	if (owner_)
		owner_->RemoveObject(this);
}

uint32_t BaseImportFunction::GetRuntimeOptions() const
{
	uint32_t res;

	switch (type()) {
	case atSetSerialNumber:
	case atGetSerialNumberState:
	case atGetSerialNumberData:
	case atGetOfflineActivationString:
	case atGetOfflineDeactivationString:
		res = roKey;
		break;
	case atGetCurrentHWID:
		res = roHWID;
		break;
	case atActivateLicense:
	case atDeactivateLicense:
		res = roKey | roActivation;
		break;
	default:
		res = 0;
		break;
	}
	return res;
}

uint32_t BaseImportFunction::GetSDKOptions() const
{
	uint32_t res;

	switch (type()) {
	case atIsValidImageCRC:
		res = cpMemoryProtection;
		break;
	case atIsVirtualMachinePresent:
		res = cpCheckVirtualMachine;
		break;
	case atIsDebuggerPresent:
		res = cpCheckDebugger;
		break;
	default:
		res = 0;
		break;
	}
	return res;
}

std::string BaseImportFunction::full_name() const
{
	std::string dll_name = owner_->name();
	if (!dll_name.empty())
		dll_name.append("!");
	return dll_name.append(display_name());
}

OperandSize BaseImportFunction::address_size() const
{
	return owner_->owner()->owner()->cpu_address_size();
}

void BaseImportFunction::set_owner(IImport *value)
{
	if (value == owner_)
		return;

	if (owner_)
		owner_->RemoveObject(this);
	owner_ = value;
	if (owner_)
		owner_->AddObject(this);
}

/**
 * BaseImport
 */

BaseImport::BaseImport(IImportList *owner)
	: IImport(), owner_(owner), excluded_from_import_protection_(false)
{

}

BaseImport::BaseImport(IImportList *owner, const BaseImport &src)
	: IImport(src), owner_(owner)
{
	excluded_from_import_protection_ = src.excluded_from_import_protection_;
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

BaseImport::~BaseImport()
{
	if (owner_)
		owner_->RemoveObject(this);
}

void BaseImport::clear()
{
	map_.clear();
	IImport::clear();
}

void BaseImport::AddObject(IImportFunction *import_function)
{
	IImport::AddObject(import_function);
	map_[import_function->address()] = import_function;
}

IImportFunction *BaseImport::GetFunctionByAddress(uint64_t address) const
{
	std::map<uint64_t, IImportFunction *>::const_iterator it = map_.find(address);
	if (it != map_.end())
		return it->second;

	return NULL;
}

uint32_t BaseImport::GetRuntimeOptions() const
{
	uint32_t res = 0;
	for (size_t i = 0; i < count(); i++) {
		res |= item(i)->GetRuntimeOptions();
	}

	return res;
}

uint32_t BaseImport::GetSDKOptions() const
{
	uint32_t res = 0;
	for (size_t i = 0; i < count(); i++) {
		res |= item(i)->GetSDKOptions();
	}

	return res;
}

void BaseImport::Rebase(uint64_t delta_base)
{
	map_.clear();
	for (size_t i = 0; i < count(); i++) {
		IImportFunction *import_function = item(i);
		import_function->Rebase(delta_base);
		map_[import_function->address()] = import_function;
	}
}

bool BaseImport::CompareName(const std::string &name) const
{
	return (_strcmpi(this->name().c_str(), name.c_str()) == 0);
}

void BaseImport::set_excluded_from_import_protection(bool value)
{
	if (excluded_from_import_protection_ != value) {
		excluded_from_import_protection_ = value;
		if (owner_ && owner_->owner())
			owner_->owner()->Notify(mtChanged, this);
	}
}

Data BaseImport::hash() const
{
	Data res;
	res.PushBuff(name().c_str(), name().size() + 1);
	res.PushByte(excluded_from_import_protection());
	return res;
}

/**
 * BaseImportList
 */

BaseImportList::BaseImportList(IArchitecture *owner)
	: IImportList(), owner_(owner)
{

}

BaseImportList::BaseImportList(IArchitecture *owner, const BaseImportList &src)
	: IImportList(), owner_(owner)
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

IImportFunction *BaseImportList::GetFunctionByAddress(uint64_t address) const
{
	for (size_t i = 0; i < count(); i++) {
		IImportFunction *func = item(i)->GetFunctionByAddress(address);
		if (func)
			return func;
	}

	return NULL;
}

uint32_t BaseImportList::GetRuntimeOptions() const
{
	uint32_t res = 0;
	for (size_t i = 0; i < count(); i++) {
		res |= item(i)->GetRuntimeOptions();
	}

	return res;
}

uint32_t BaseImportList::GetSDKOptions() const
{
	uint32_t res = 0;
	for (size_t i = 0; i < count(); i++) {
		res |= item(i)->GetSDKOptions();
	}

	return res;
}

const ImportInfo *BaseImportList::GetSDKInfo(const std::string &name) const
{
	static const ImportInfo sdk_info[] = {
		{atBegin, "VMProtectBegin", ioNone, ctNone},
		{atBegin, "VMProtectBeginVirtualization", ioHasCompilationType, ctVirtualization},
		{atBegin, "VMProtectBeginMutation", ioHasCompilationType, ctMutation},
		{atBegin, "VMProtectBeginUltra", ioHasCompilationType, ctUltra},
		{atBegin, "VMProtectBeginVirtualizationLockByKey", ioHasCompilationType | ioLockToKey, ctVirtualization},
		{atBegin, "VMProtectBeginUltraLockByKey", ioHasCompilationType | ioLockToKey, ctUltra},
		{atEnd, "VMProtectEnd", ioNone, ctNone},
		{atIsProtected, "VMProtectIsProtected", ioNone, ctNone},
		{atIsVirtualMachinePresent, "VMProtectIsVirtualMachinePresent", ioNone, ctNone},
		{atIsDebuggerPresent, "VMProtectIsDebuggerPresent", ioNone, ctNone},
		{atIsValidImageCRC, "VMProtectIsValidImageCRC", ioNone, ctNone},
		{atDecryptStringA, "VMProtectDecryptStringA", ioNone, ctNone},
		{atDecryptStringW, "VMProtectDecryptStringW", ioNone, ctNone},
		{atFreeString, "VMProtectFreeString", ioNone, ctNone},
		{atSetSerialNumber, "VMProtectSetSerialNumber", ioNone, ctNone},
		{atGetSerialNumberState, "VMProtectGetSerialNumberState", ioNone, ctNone},
		{atGetSerialNumberData, "VMProtectGetSerialNumberData", ioNone, ctNone},
		{atGetCurrentHWID, "VMProtectGetCurrentHWID", ioNone, ctNone},
		{atActivateLicense, "VMProtectActivateLicense", ioNone, ctNone},
		{atDeactivateLicense, "VMProtectDeactivateLicense", ioNone, ctNone},
		{atGetOfflineActivationString, "VMProtectGetOfflineActivationString", ioNone, ctNone},
		{atGetOfflineDeactivationString, "VMProtectGetOfflineDeactivationString", ioNone, ctNone}
	};

	for (size_t i = 0; i < _countof(sdk_info); i++) {
		const ImportInfo *import_info = &sdk_info[i];
		if (name.compare(import_info->name) == 0)
			return import_info;
	}

	return NULL;
}

void BaseImportList::ReadFromBuffer(Buffer &buffer, IArchitecture &file)
{
	size_t i, c, j, k;
	uint64_t address, operand_address;
	uint64_t add_address = file.image_base();

	c = buffer.ReadDWord();
	if (c) {
		IImport *sdk = AddSDK();
		for (i = 0; i < c; i++) {
			APIType type = static_cast<APIType>(buffer.ReadByte());
			address = buffer.ReadDWord() + add_address;
			MapFunction *map_function = file.map_function_list()->Add(address, 0, otImport, FunctionName(""));
			sdk->Add(address, type, map_function);

			k = buffer.ReadDWord();
			for (j = 0; j < k; j++) {
				address = buffer.ReadDWord() + add_address;
				operand_address = buffer.ReadDWord() + add_address;
				map_function->reference_list()->Add(address, operand_address);
			}
		}
	}

	c = buffer.ReadDWord();
	for (i = 0; i < c; i++) {
		j = buffer.ReadDWord();
		k = buffer.ReadDWord();
		address = buffer.ReadDWord() + add_address;
		operand_address = buffer.ReadDWord() + add_address;
		item(j - 1)->item(k - 1)->map_function()->reference_list()->Add(address, operand_address);
	}

	// check import functions without references
	for (i = 0; i < count(); i++) {
		IImport *import = item(i);
		for (j = 0; j < import->count(); j++) {
			IImportFunction *import_function = import->item(j);
			if (import_function->map_function()->reference_list()->count() != 0)
				import_function->exclude_option(ioNoReferences);
		}
	}
}

void BaseImportList::Rebase(uint64_t delta_base)
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->Rebase(delta_base);
	}
}

bool BaseImportList::has_sdk() const
{
	for (size_t i = 0; i < count(); i++) {
		if (item(i)->is_sdk())
			return true;
	}
	return false;
}

IImport *BaseImportList::GetImportByName(const std::string &name) const
{
	for (size_t i = 0; i < count(); i++) {
		IImport *import = item(i);
		if (import->CompareName(name))
			return import;
	}
	return NULL;
}
