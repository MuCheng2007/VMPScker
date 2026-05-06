/**
 * Executable fixups implementations.
 * Rust mapping target: mod fixups
 */

#include "fixups.h"
#include "architecture.h"

/**
 * BaseFixup
 */

BaseFixup::BaseFixup(IFixupList *owner) 
	: IFixup(), owner_(owner), deleted_(false) 
{

}

BaseFixup::BaseFixup(IFixupList *owner, const BaseFixup &src) 
	: IFixup(), owner_(owner)
{
	deleted_ = src.deleted_;
}

BaseFixup::~BaseFixup()
{
	if (owner_)
		owner_->RemoveObject(this);
}

/**
 * BaseFixupList
 */

BaseFixupList::BaseFixupList()
	: IFixupList()
{

}

BaseFixupList::BaseFixupList(const BaseFixupList &src)
	: IFixupList(src)
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

void BaseFixupList::clear()
{
	map_.clear();
	IFixupList::clear();
}

IFixup *BaseFixupList::GetFixupByAddress(uint64_t address) const
{
	std::map<uint64_t, IFixup *>::const_iterator it = map_.find(address);
	if (it != map_.end())
		return it->second;

	return NULL;
}

IFixup *BaseFixupList::GetFixupByNearAddress(uint64_t address) const
{
	if (map_.empty())
		return NULL;

	std::map<uint64_t, IFixup *>::const_iterator it = map_.upper_bound(address);
	if (it != map_.begin())
		it--;

	IFixup *fixup = it->second;
	if (fixup && fixup->address() <= address && fixup->next_address() > address)
		return fixup;

	return NULL;
}

void BaseFixupList::AddObject(IFixup *fixup)
{
	IFixupList::AddObject(fixup);
	if (fixup->address())
		map_[fixup->address()] = fixup;
}

size_t BaseFixupList::Pack()
{
	for (size_t i = count(); i > 0; i--) {
		IFixup *fixup = item(i - 1);
		if (fixup->is_deleted())
			delete fixup;
	}

	return count();
}

void BaseFixupList::Rebase(IArchitecture &file, uint64_t delta_base)
{
	map_.clear();
	for (size_t i = 0; i < count(); i++) {
		IFixup *fixup = item(i);
		fixup->Rebase(file, delta_base);
		if (fixup->address())
			map_[fixup->address()] = fixup;
	}
}
