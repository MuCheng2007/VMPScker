/**
 * Reference and ReferenceList implementations.
 * Rust mapping target: mod references
 */

#include "references.h"

/**
 * Reference
 */

Reference::Reference(ReferenceList *owner, uint64_t address, uint64_t operand_address, size_t tag)
	: IObject(), owner_(owner), address_(address), operand_address_(operand_address), tag_(tag)
{

}

Reference::Reference(ReferenceList *owner, const Reference &src)
	: IObject(src), owner_(owner)
{
	address_ = src.address_;
	operand_address_ = src.operand_address_;
	tag_ = src.tag_;
}

Reference::~Reference()
{
	if (owner_)
		owner_->RemoveObject(this);
}

Reference *Reference::Clone(ReferenceList *owner) const
{
	Reference *ref = new Reference(owner, *this);
	return ref;
}

void Reference::Rebase(uint64_t delta_base)
{
	address_ += delta_base;
	operand_address_ += delta_base;
}

/**
 * ReferenceList
 */

ReferenceList::ReferenceList()
	: ObjectList<Reference>()
{

}

ReferenceList::ReferenceList(const ReferenceList &src)
	: ObjectList<Reference>(src)
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

ReferenceList *ReferenceList::Clone() const
{
	ReferenceList *list = new ReferenceList(*this);
	return list;
}

Reference *ReferenceList::Add(uint64_t address, uint64_t operand_address, size_t tag)
{
	Reference *ref = new Reference(this, address, operand_address, tag);
	AddObject(ref);
	return ref;
}

Reference *ReferenceList::GetReferenceByAddress(uint64_t address) const
{
	for (size_t i = 0; i < count(); i++) {
		Reference *ref = item(i);
		if (ref->address() == address)
			return ref;
	}
	return NULL;
}

void ReferenceList::Rebase(uint64_t delta_base)
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->Rebase(delta_base);
	}
}
