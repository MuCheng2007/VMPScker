/**
 * Windows SEH handlers abstractions.
 * Rust mapping target: mod seh
 */

#ifndef FILES_SEH_H
#define FILES_SEH_H

#include "../../runtime/common.h"
#include "../objects.h"

class ISEHandlerList;

#define NEED_SEH_HANDLER reinterpret_cast<ISEHandler *>(-1)

class ISEHandler : public IObject
{
public:
	virtual uint64_t address() const = 0;
	virtual void set_address(uint64_t address) = 0;
	virtual bool is_deleted() const = 0;
	virtual void set_deleted(bool deleted) = 0;

	using IObject::CompareWith;
	int CompareWith(const ISEHandler &obj) const
	{
		if (address() < obj.address())
			return -1;
		if (address() > obj.address())
			return 1;
		return 0;
	}
	virtual ISEHandler *Clone(ISEHandlerList *owner) const = 0;
};

class BaseSEHandler : public ISEHandler
{
public:
	explicit BaseSEHandler(ISEHandlerList *owner);
	explicit BaseSEHandler(ISEHandlerList *owner, const BaseSEHandler &src);
	~BaseSEHandler();
private:
	ISEHandlerList *owner_;
};

class ISEHandlerList : public ObjectList<ISEHandler>
{
public:
	virtual ISEHandler *GetHandlerByAddress(uint64_t address) const = 0;
	virtual ISEHandler *Add(uint64_t address) = 0;
};

class BaseSEHandlerList : public ISEHandlerList
{
public:
	explicit BaseSEHandlerList();
	explicit BaseSEHandlerList(const BaseSEHandlerList &src);
	virtual void clear();
	ISEHandler *GetHandlerByAddress(uint64_t address) const;
	virtual void AddObject(ISEHandler *handler);
private:
	std::map<uint64_t, ISEHandler *> map_;

	// no assignment op
	BaseSEHandlerList &operator =(const BaseSEHandlerList &);
};

#endif // FILES_SEH_H
