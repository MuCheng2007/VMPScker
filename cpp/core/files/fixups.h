/**
 * Executable fixups abstractions.
 * Rust mapping target: mod fixups
 */

#ifndef FILES_FIXUPS_H
#define FILES_FIXUPS_H

#include "../../runtime/common.h"
#include "../objects.h"
#include "types.h"
#include "utils.h"

class IArchitecture;
class IFixupList;

class IFixup : public IObject
{
public:
	virtual uint64_t address() const = 0;
	virtual uint64_t next_address() const = 0;
	virtual FixupType type() const = 0;
	virtual OperandSize size() const = 0;
	virtual void set_address(uint64_t address) = 0;
	virtual bool is_deleted() const = 0;
	virtual void set_deleted(bool deleted) = 0;
	virtual void Rebase(IArchitecture &file, uint64_t delta_base) = 0;
	
	using IObject::CompareWith;
	int CompareWith(const IFixup &obj) const
	{
		if (address() < obj.address())
			return -1;
		if (address() > obj.address())
			return 1;
		return 0;
	}
	virtual IFixup *Clone(IFixupList *owner) const = 0;
};

class BaseFixup : public IFixup
{
public:
	explicit BaseFixup(IFixupList *owner);
	explicit BaseFixup(IFixupList *owner, const BaseFixup &src);
	~BaseFixup();
	virtual uint64_t next_address() const { return address() + OperandSizeToValue(size()); }
	virtual bool is_deleted() const { return deleted_; }
	virtual void set_deleted(bool deleted) { deleted_ = deleted; }
private:
	IFixupList *owner_;
	bool deleted_;
};

class IFixupList : public ObjectList<IFixup>
{
public:
	virtual IFixup *GetFixupByAddress(uint64_t address) const = 0;
	virtual IFixup *GetFixupByNearAddress(uint64_t address) const = 0;
	virtual IFixup *AddDefault(OperandSize cpu_address_size, bool is_code) = 0;
	virtual void Rebase(IArchitecture &file, uint64_t delta_base) = 0;
};

class BaseFixupList : public IFixupList
{
public:
	explicit BaseFixupList();
	explicit BaseFixupList(const BaseFixupList &src);
	virtual void clear();
	virtual IFixup *GetFixupByAddress(uint64_t address) const;
	virtual IFixup *GetFixupByNearAddress(uint64_t address) const;
	virtual size_t Pack();
	virtual void Rebase(IArchitecture &file, uint64_t delta_base);
	virtual void AddObject(IFixup *obj);
private:
	std::map<uint64_t, IFixup *> map_;

	// no assignment op
	BaseFixupList &operator =(const BaseFixupList &);
};

#endif // FILES_FIXUPS_H
