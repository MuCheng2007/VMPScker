/**
 * Runtime functions abstractions (SEH/Unwind info).
 * Rust mapping target: mod runtime_func
 */

#ifndef FILES_RUNTIME_FUNC_H
#define FILES_RUNTIME_FUNC_H

#include "../../runtime/common.h"
#include "../objects.h"

class IArchitecture;
class IFunction;
class IRuntimeFunctionList;

class IRuntimeFunction : public IObject
{
public:
	virtual IRuntimeFunction *Clone(IRuntimeFunctionList *owner) const = 0;
	virtual uint64_t address() const = 0;
	virtual uint64_t begin() const = 0;
	virtual uint64_t end() const = 0;
	virtual uint64_t unwind_address() const = 0;
	virtual void set_begin(uint64_t begin) = 0;
	virtual void set_end(uint64_t end) = 0;
	virtual void set_unwind_address(uint64_t unwind_address) = 0;
	virtual void Parse(IArchitecture &file, IFunction &dest) = 0;
	virtual void Rebase(uint64_t delta_base) = 0;

	using IObject::CompareWith;
	int CompareWith(const IRuntimeFunction &obj) const
	{
		if (begin() < obj.begin())
			return -1;
		if (begin() > obj.begin())
			return 1;
		return 0;
	}
};

class IRuntimeFunctionList : public ObjectList<IRuntimeFunction>
{
public:
	virtual IRuntimeFunction *GetFunctionByAddress(uint64_t address) const = 0;
	virtual IRuntimeFunction *GetFunctionByUnwindAddress(uint64_t address) const = 0;
	virtual IRuntimeFunction *Add(uint64_t address, uint64_t begin, uint64_t end, uint64_t unwind_address, IRuntimeFunction *source, const std::vector<uint8_t> &call_frame_instructions) = 0;
};

class BaseRuntimeFunction : public IRuntimeFunction
{
public:
	explicit BaseRuntimeFunction(IRuntimeFunctionList *owner);
	explicit BaseRuntimeFunction(IRuntimeFunctionList *owner, const BaseRuntimeFunction &src);
	~BaseRuntimeFunction();
private:
	IRuntimeFunctionList *owner_;
};

class BaseRuntimeFunctionList : public IRuntimeFunctionList
{
public:
	explicit BaseRuntimeFunctionList();
	explicit BaseRuntimeFunctionList(const BaseRuntimeFunctionList &src);
	virtual void clear();
	virtual IRuntimeFunction *GetFunctionByAddress(uint64_t address) const;
	virtual IRuntimeFunction *GetFunctionByUnwindAddress(uint64_t address) const;
	virtual void AddObject(IRuntimeFunction *func);
	virtual void Rebase(uint64_t delta_base);
private:
	std::map<uint64_t, IRuntimeFunction *> map_;
	std::map<uint64_t, IRuntimeFunction *> unwind_map_;

	// no assignment op
	BaseRuntimeFunctionList &operator =(const BaseRuntimeFunctionList &);
};

#endif // FILES_RUNTIME_FUNC_H
