/**
 * Runtime functions implementations (SEH/Unwind info).
 * Rust mapping target: mod runtime_func
 */

#include "runtime_func.h"
#include "architecture.h"

/**
 * BaseRuntimeFunction
 */

BaseRuntimeFunction::BaseRuntimeFunction(IRuntimeFunctionList *owner) 
	: IRuntimeFunction(), owner_(owner)
{

}

BaseRuntimeFunction::BaseRuntimeFunction(IRuntimeFunctionList *owner, const BaseRuntimeFunction &src) 
	: IRuntimeFunction(), owner_(owner)
{

}

BaseRuntimeFunction::~BaseRuntimeFunction()
{
	if (owner_)
		owner_->RemoveObject(this);
}

/**
 * BaseRuntimeFunctionList
 */

BaseRuntimeFunctionList::BaseRuntimeFunctionList()
	: IRuntimeFunctionList()
{

}

BaseRuntimeFunctionList::BaseRuntimeFunctionList(const BaseRuntimeFunctionList &src)
	: IRuntimeFunctionList(src)
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

void BaseRuntimeFunctionList::clear()
{
	map_.clear();
	unwind_map_.clear();
	IRuntimeFunctionList::clear();
}

IRuntimeFunction *BaseRuntimeFunctionList::GetFunctionByAddress(uint64_t address) const
{
	if (map_.empty())
		return NULL;

	std::map<uint64_t, IRuntimeFunction *>::const_iterator it = map_.upper_bound(address);
	if (it != map_.begin())
		it--;

	IRuntimeFunction *func = it->second;
	if (func->begin() <= address && func->end() > address)
		return func;

	return NULL;
}

IRuntimeFunction *BaseRuntimeFunctionList::GetFunctionByUnwindAddress(uint64_t address) const
{
	std::map<uint64_t, IRuntimeFunction *>::const_iterator it = unwind_map_.find(address);
	return (it != unwind_map_.end()) ? it->second : NULL;
}

void BaseRuntimeFunctionList::AddObject(IRuntimeFunction *func)
{
	IRuntimeFunctionList::AddObject(func);
	if (func->begin())
		map_[func->begin()] = func;
	if (func->unwind_address())
		unwind_map_[func->unwind_address()] = func;
}

void BaseRuntimeFunctionList::Rebase(uint64_t delta_base)
{
	map_.clear();
	unwind_map_.clear();
	for (size_t i = 0; i < count(); i++) {
		IRuntimeFunction *func = item(i);
		func->Rebase(delta_base);
		if (func->begin())
			map_[func->begin()] = func;
		if (func->unwind_address())
			unwind_map_[func->unwind_address()] = func;
	}
}
