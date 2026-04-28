/**
 * PE Delay Import support.
 */

#include "../../runtime/common.h"
#include "../objects.h"
#include "../osutils.h"
#include "../streams.h"
#include "../files/architecture.h"
#include "../files/imports.h"
#include "../files/utils.h"
#include "PEDelayImport.h"
#include "PEDirectory.h"
#include "PEArchitecture.h"

/**
 * PEDelayImportFunction
 */

PEDelayImportFunction::PEDelayImportFunction(PEDelayImport* owner)
	: IObject(), owner_(owner), is_ordinal_(false), ordinal_(0)
{

}

PEDelayImportFunction::PEDelayImportFunction(PEDelayImport* owner, const PEDelayImportFunction& src)
	: IObject(), owner_(owner)
{
	name_ = src.name_;
	is_ordinal_ = src.is_ordinal_;
	ordinal_ = src.ordinal_;
}

PEDelayImportFunction::~PEDelayImportFunction()
{
	if (owner_)
		owner_->RemoveObject(this);
}

PEDelayImportFunction* PEDelayImportFunction::Clone(PEDelayImport* owner) const
{
	PEDelayImportFunction* func = new PEDelayImportFunction(owner, *this);
	return func;
}

bool PEDelayImportFunction::ReadFromFile(PEArchitecture& file, uint64_t add_value)
{
	uint64_t name_address;
	if (file.cpu_address_size() == osDWord) {
		IMAGE_THUNK_DATA32 thunk;

		file.Read(&thunk, sizeof(thunk));
		name_address = thunk.u1.AddressOfData;
		if (!name_address)
			return false;
		is_ordinal_ = IMAGE_SNAP_BY_ORDINAL32(name_address);
	}
	else {
		IMAGE_THUNK_DATA64 thunk;

		file.Read(&thunk, sizeof(thunk));
		name_address = thunk.u1.AddressOfData;
		if (!name_address)
			return false;
		is_ordinal_ = IMAGE_SNAP_BY_ORDINAL64(name_address);
	}

	if (is_ordinal_) {
		ordinal_ = IMAGE_ORDINAL32(name_address);
		name_address = 0;
		name_ = string_format("Ordinal: %.4X", ordinal_);
	}
	else {
		name_address += add_value;
		uint64_t pos = file.Tell();
		if (!file.AddressSeek(name_address + sizeof(uint16_t)))
			throw std::runtime_error("Format error");
		name_ = file.ReadString();
		file.Seek(pos);
	}

	return true;
}

/**
 * PEDelayImport
 */

PEDelayImport::PEDelayImport(PEDelayImportList* owner)
	: ObjectList<PEDelayImportFunction>(), owner_(owner)
{

}

PEDelayImport::PEDelayImport(PEDelayImportList* owner, const PEDelayImport& src)
	: ObjectList<PEDelayImportFunction>(), owner_(owner)
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
	name_ = src.name_;
	flags_ = src.flags_;
	module_ = src.module_;
	iat_ = src.iat_;
	bound_iat_ = src.bound_iat_;
	unload_iat_ = src.unload_iat_;
	time_stamp_ = src.time_stamp_;
}

PEDelayImport::~PEDelayImport()
{
	if (owner_)
		owner_->RemoveObject(this);
}

PEDelayImport* PEDelayImport::Clone(PEDelayImportList* owner) const
{
	PEDelayImport* imp = new PEDelayImport(owner, *this);
	return imp;
}

bool PEDelayImport::ReadFromFile(PEArchitecture& file)
{
	IMAGE_DELAY_IMPORT_DESCRIPTOR import_descriptor;
	file.Read(&import_descriptor, sizeof(import_descriptor));

	if (!import_descriptor.DllName)
		return false;

	flags_ = import_descriptor.Attrs;
	uint64_t name_address = import_descriptor.DllName;
	module_ = import_descriptor.Hmod;
	iat_ = import_descriptor.IAT;
	uint64_t address = import_descriptor.INT;
	bound_iat_ = import_descriptor.BoundIAT;
	unload_iat_ = import_descriptor.UnloadIAT;
	time_stamp_ = import_descriptor.TimeStamp;

	uint64_t add_value;
	if (flags_ & 1) {
		add_value = file.image_base();
		if (name_address)
			name_address += add_value;
		if (module_)
			module_ += add_value;
		if (iat_)
			iat_ += add_value;
		if (address)
			address += add_value;
		if (bound_iat_)
			bound_iat_ += add_value;
		if (unload_iat_)
			unload_iat_ += add_value;
	}
	else {
		if (file.cpu_address_size() != osDWord)
			throw std::runtime_error("Format error");
		add_value = 0;
	}

	uint64_t pos = file.Tell();
	if (!file.AddressSeek(name_address))
		throw std::runtime_error("Format error");
	name_ = file.ReadString();

	if (!file.AddressSeek(address))
		throw std::runtime_error("Format error");
	while (true) {
		PEDelayImportFunction* func = new PEDelayImportFunction(this);
		if (!func->ReadFromFile(file, add_value)) {
			delete func;
			break;
		}
		AddObject(func);
	}

	file.Seek(pos);

	return true;
}

/**
 * PEDelayImportList
 */

PEDelayImportList::PEDelayImportList()
	: ObjectList<PEDelayImport>()
{

}

PEDelayImportList::PEDelayImportList(const PEDelayImportList& src)
	: ObjectList<PEDelayImport>()
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

PEDelayImportList* PEDelayImportList::Clone() const
{
	PEDelayImportList* import_list = new PEDelayImportList(*this);
	return import_list;
}

void PEDelayImportList::ReadFromFile(PEArchitecture& file, PEDirectory& dir)
{
	if (!dir.address())
		return;

	if (!file.AddressSeek(dir.address()))
		throw std::runtime_error("Format error");

	for (size_t i = 0; i < dir.size(); i += sizeof(IMAGE_DELAY_IMPORT_DESCRIPTOR)) {
		PEDelayImport* imp = new PEDelayImport(this);
		if (!imp->ReadFromFile(file)) {
			delete imp;
			break;
		}
		AddObject(imp);
	}
}
