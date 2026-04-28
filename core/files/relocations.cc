/**
 * Executable relocations implementations.
 * Rust mapping target: mod relocations
 */

#include "relocations.h"
#include "../files.h"

/**
 * BaseRelocation
 */

BaseRelocation::BaseRelocation(IRelocationList *owner, uint64_t address, OperandSize size)
	: IRelocation(), owner_(owner), address_(address), size_(size)
{

}

BaseRelocation::BaseRelocation(IRelocationList *owner, const BaseRelocation &src)
	: IRelocation(), owner_(owner)
{
	address_ = src.address_;
	size_ = src.size_;
}

BaseRelocation::~BaseRelocation()
{
	if (owner_)
		owner_->RemoveObject(this);
}

/**
 * BaseRelocationList
 */

BaseRelocationList::BaseRelocationList()
	: IRelocationList()
{

}

BaseRelocationList::BaseRelocationList(const BaseRelocationList &src)
	: IRelocationList(src)
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

void BaseRelocationList::clear()
{
	map_.clear();
	IRelocationList::clear();
}

IRelocation *BaseRelocationList::GetRelocationByAddress(uint64_t address) const
{
	std::map<uint64_t, IRelocation *>::const_iterator it = map_.find(address);
	if (it != map_.end())
		return it->second;

	return NULL;
}

void BaseRelocationList::AddObject(IRelocation *relocation)
{
	IRelocationList::AddObject(relocation);
	map_[relocation->address()] = relocation;
}

void BaseRelocationList::Rebase(IArchitecture &file, uint64_t delta_base)
{
	map_.clear();
	for (size_t i = 0; i < count(); i++) {
		IRelocation *relocation = item(i);
		relocation->Rebase(file, delta_base);
		map_[relocation->address()] = relocation;
	}
}
