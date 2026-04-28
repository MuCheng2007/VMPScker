/**
 * Compiler internal helper functions.
 * Rust mapping target: mod compiler_func
 */

#ifndef FILES_COMPILER_FUNC_H
#define FILES_COMPILER_FUNC_H

#include "../../runtime/common.h"
#include "../objects.h"
#include "types.h"

class CompilerFunctionList;

class CompilerFunction : public IObject
{
public:
	explicit CompilerFunction(CompilerFunctionList *owner, CompilerFunctionType type, uint64_t address);
	explicit CompilerFunction(CompilerFunctionList *owner, const CompilerFunction &src);
	~CompilerFunction();
	CompilerFunctionType type() const { return type_; }
	uint64_t address() const { return address_; }
	uint64_t value(size_t index) const { return (index < value_list_.size()) ? value_list_[index] : 0; }
	void add_value(uint64_t value) { value_list_.push_back(value); } 
	virtual CompilerFunction *Clone(CompilerFunctionList *owner) const;
	uint32_t options() const { return options_; }
	void include_option(CompilerFunctionOption option) { options_ |= option; }
	size_t count() const { return value_list_.size(); }
	void Rebase(uint64_t delta_base);
private:
	CompilerFunctionList *owner_;
	uint64_t address_;
	CompilerFunctionType type_;
	uint32_t options_;
	std::vector<uint64_t> value_list_;

	// not implemented
	CompilerFunction(const CompilerFunction &);
	CompilerFunction &operator =(const CompilerFunction &);
};

class CompilerFunctionList : public ObjectList<CompilerFunction>
{
public:
	explicit CompilerFunctionList();
	explicit CompilerFunctionList(const CompilerFunctionList &src);
	CompilerFunction *Add(CompilerFunctionType type, uint64_t address);
	virtual void AddObject(CompilerFunction *func);
	CompilerFunction *GetFunctionByAddress(uint64_t address) const;
	CompilerFunction *GetFunctionByLowerAddress(uint64_t address) const;
	CompilerFunctionList *Clone() const;
	uint64_t GetRegistrValue(uint64_t address, uint64_t registr) const;
	uint32_t GetSDKOptions() const;
	uint32_t GetRuntimeOptions() const;
	void Rebase(uint64_t delta_base);
private:
	std::map<uint64_t, CompilerFunction*> map_;

	// no assignment op
	CompilerFunctionList &operator =(const CompilerFunctionList &);
};

#endif // FILES_COMPILER_FUNC_H
