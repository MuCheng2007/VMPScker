/**
 * Windows SEH handlers implementations.
 * Rust mapping target: mod seh
 */

#include "seh.h"
#include "architecture.h"

/**
 * BaseSEHandler
 */

BaseSEHandler::BaseSEHandler(ISEHandlerList *owner)
	: ISEHandler(), owner_(owner)
{

}

BaseSEHandler::BaseSEHandler(ISEHandlerList *owner, const BaseSEHandler &src)
	: ISEHandler(src), owner_(owner)
{

}

BaseSEHandler::~BaseSEHandler()
{
	if (owner_)
		owner_->RemoveObject(this);
}

/**
 * BaseSEHandlerList
 */

BaseSEHandlerList::BaseSEHandlerList()
	: ISEHandlerList()
{

}

BaseSEHandlerList::BaseSEHandlerList(const BaseSEHandlerList &src)
	: ISEHandlerList(src)
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

void BaseSEHandlerList::clear()
{
	map_.clear();
	ISEHandlerList::clear();
}

ISEHandler *BaseSEHandlerList::GetHandlerByAddress(uint64_t address) const
{
	std::map<uint64_t, ISEHandler *>::const_iterator it = map_.find(address);
	if (it != map_.end())
		return it->second;

	return NULL;
}

void BaseSEHandlerList::AddObject(ISEHandler *handler)
{
	ISEHandlerList::AddObject(handler);
	map_[handler->address()] = handler;
}
