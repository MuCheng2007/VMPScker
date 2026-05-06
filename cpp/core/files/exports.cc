/**
 * Executable exports implementations.
 * Rust mapping target: mod exports
 */

#include "exports.h"
#include "architecture.h"
#include "../osutils.h"
#include "../streams.h"

/**
 * BaseExport
 */

BaseExport::BaseExport(IExportList *owner)
	: IExport(), owner_(owner), type_(atNone)
{

}

BaseExport::BaseExport(IExportList *owner, const BaseExport &src)
	: IExport(), owner_(owner)
{
	type_ = src.type_;
}

BaseExport::~BaseExport()
{
	if (owner_)
		owner_->RemoveObject(this);
}

OperandSize BaseExport::address_size() const
{
	return owner_->owner()->cpu_address_size();
}

bool BaseExport::is_equal(const IExport &src) const
{
	return (address() == src.address() && name() == src.name() && forwarded_name() == src.forwarded_name());
}

/**
 * BaseExportList
 */

BaseExportList::BaseExportList(IArchitecture *owner)
	: IExportList(), owner_(owner)
{

}

BaseExportList::BaseExportList(IArchitecture *owner, const BaseExportList &src)
	: IExportList(src), owner_(owner)
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

uint64_t BaseExportList::GetAddressByType(APIType type) const
{
	for (size_t i = 0; i < count(); i++) {
		IExport *exp = item(i);
		if (exp->type() == type)
			return exp->address();
	}
	return 0;
}

IExport *BaseExportList::GetExportByAddress(uint64_t address) const
{
	for (size_t i = 0; i < count(); i++) {
		IExport *exp = item(i);
		if (exp->address() == address)
			return exp;
	}
	return NULL;
}

IExport *BaseExportList::GetExportByName(const std::string &name) const
{
	for (size_t i = 0; i < count(); i++) {
		IExport *exp = item(i);
		if (exp->name() == name)
			return exp;
	}
	return NULL;
}

void BaseExportList::ReadFromBuffer(Buffer &buffer, IArchitecture &file)
{
	uint64_t add_address = file.image_base();

	size_t c = buffer.ReadDWord();
	for (size_t i = 0; i < c; i++) {
		Add(buffer.ReadDWord() + add_address);
	}
}

void BaseExportList::Rebase(uint64_t delta_base)
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->Rebase(delta_base);
	}
}

bool BaseExportList::is_equal(const IExportList &src) const
{
	if (name() != src.name() || count() != src.count())
		return false;

	for (size_t i = 0; i < count(); i++) {
		if (!item(i)->is_equal(*src.item(i)))
			return false;
	}
	return true;
}
