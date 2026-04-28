/**
 * Executable relocations abstractions.
 * Rust mapping target: mod relocations
 */

#ifndef FILES_RELOCATIONS_H
#define FILES_RELOCATIONS_H

#include "../../runtime/common.h"
#include "../objects.h"
#include "types.h"

class IArchitecture;
class IRelocationList;

class ISymbol : public IObject
{
public:
	virtual uint64_t address() const = 0;
	virtual std::string display_name(bool show_ret = true) const = 0;
};

class IRelocation : public IObject
{
public:
	virtual IRelocation *Clone(IRelocationList *owner) const = 0;
	virtual uint64_t address() const = 0;
	virtual void set_address(uint64_t address) = 0;
	virtual void Rebase(IArchitecture &file, uint64_t delta_base) = 0;
	virtual ISymbol *symbol() const = 0;
};

class IRelocationList : public ObjectList<IRelocation>
{
public:
	virtual IRelocation *GetRelocationByAddress(uint64_t address) const = 0;
};

class BaseRelocation : public IRelocation
{
public:
	explicit BaseRelocation(IRelocationList *owner, uint64_t address, OperandSize size);
	explicit BaseRelocation(IRelocationList *owner, const BaseRelocation &src);
	~BaseRelocation();
	uint64_t address() const { return address_; }
	OperandSize size() const { return size_; }
	void set_address(uint64_t address) { address_ = address; }
	virtual void Rebase(IArchitecture &file, uint64_t delta_base) { address_ += delta_base; }
private:
	IRelocationList *owner_;
	uint64_t address_;
	OperandSize size_;
};

class BaseRelocationList : public IRelocationList
{
public:
	explicit BaseRelocationList();
	explicit BaseRelocationList(const BaseRelocationList &src);
	virtual void clear();
	virtual IRelocation *GetRelocationByAddress(uint64_t address) const;
	virtual void AddObject(IRelocation *relocation);
	void Rebase(IArchitecture &file, uint64_t delta_base);
private:
	std::map<uint64_t, IRelocation *> map_;

	// no assignment op
	BaseRelocationList &operator =(const BaseRelocationList &);
};

#endif // FILES_RELOCATIONS_H
