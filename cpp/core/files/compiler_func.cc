/**
 * Compiler internal helper functions implementations.
 * Rust mapping target: mod compiler_func
 */

#include "compiler_func.h"
#include "architecture.h"
#include "../core_internal/core.h"

/**
 * CompilerFunction
 */

CompilerFunction::CompilerFunction(CompilerFunctionList *owner, CompilerFunctionType type, uint64_t address)
	: IObject(), owner_(owner), address_(address), type_(type), options_(0)
{
}

CompilerFunction::CompilerFunction(CompilerFunctionList *owner, const CompilerFunction &src)
	: IObject(src), owner_(owner)
{
	address_ = src.address_;
	type_ = src.type_;
	value_list_ = src.value_list_;
	options_ = src.options_;
}

CompilerFunction::~CompilerFunction()
{
	if (owner_)
		owner_->RemoveObject(this);
}

CompilerFunction *CompilerFunction::Clone(CompilerFunctionList *owner) const
{
	CompilerFunction *func = new CompilerFunction(owner, *this);
	return func;
}

void CompilerFunction::Rebase(uint64_t delta_base)
{
	address_ += delta_base;
}

/**
 * CompilerFunctionList
 */

CompilerFunctionList::CompilerFunctionList()
	: ObjectList<CompilerFunction>()
{

}

CompilerFunctionList::CompilerFunctionList(const CompilerFunctionList &src)
	: ObjectList<CompilerFunction>(src)
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

CompilerFunctionList *CompilerFunctionList::Clone() const
{
	CompilerFunctionList *compiler_function_list = new CompilerFunctionList(*this);
	return compiler_function_list;
}

CompilerFunction *CompilerFunctionList::Add(CompilerFunctionType type, uint64_t address)
{
	CompilerFunction *func = new CompilerFunction(this, type, address);
	AddObject(func);
	return func;
}

void CompilerFunctionList::AddObject(CompilerFunction *func)
{
	ObjectList<CompilerFunction>::AddObject(func);
	map_[func->address()] = func;
}

CompilerFunction *CompilerFunctionList::GetFunctionByAddress(uint64_t address) const
{
	std::map<uint64_t, CompilerFunction *>::const_iterator it = map_.find(address);
	if (it != map_.end())
		return it->second;
	return NULL;
}

CompilerFunction *CompilerFunctionList::GetFunctionByLowerAddress(uint64_t address) const
{
	if (map_.empty())
		return NULL;

	std::map<uint64_t, CompilerFunction *>::const_iterator it = map_.upper_bound(address);
	if (it != map_.begin())
		it--;
	return it->first > address ? NULL : it->second;
}

uint64_t CompilerFunctionList::GetRegistrValue(uint64_t address, uint64_t registr) const
{
	if (!map_.empty()) {
		std::map<uint64_t, CompilerFunction *>::const_iterator it = map_.upper_bound(address);
		if (it != map_.begin())
			it--;

		while (true) {
			CompilerFunction *func = it->second;
			if (func->type() == cfBaseRegistr) {
				if (func->value(0) == registr)
					return func->address() + func->value(1);
				break;
			}
			if (it == map_.begin())
				break;
			it--;
		}
	}
	return -1;
}

uint32_t CompilerFunctionList::GetSDKOptions() const
{
	uint32_t res = 0;
	for (size_t i = 0; i < count(); i++) {
		CompilerFunction *compiler_function = item(i);
		if (compiler_function->type() == cfDllFunctionCall && (compiler_function->options() & coUsed)) {
			switch (compiler_function->value(0) & 0xff) {
			case atIsValidImageCRC:
				res |= cpMemoryProtection;
				break;
			case atIsVirtualMachinePresent:
				res |= cpCheckVirtualMachine;
				break;
			case atIsDebuggerPresent:
				res |= cpCheckDebugger;
				break;
			}
		}
	}

	return res;
}

uint32_t CompilerFunctionList::GetRuntimeOptions() const
{
	uint32_t res = 0;
	for (size_t i = 0; i < count(); i++) {
		CompilerFunction *compiler_function = item(i);
		if (compiler_function->type() == cfDllFunctionCall && (compiler_function->options() & coUsed)) {
			switch (compiler_function->value(0) & 0xff) {
			case atSetSerialNumber:
			case atGetSerialNumberState:
			case atGetSerialNumberData:
			case atGetOfflineActivationString:
			case atGetOfflineDeactivationString:
				res |= roKey;
				break;
			case atGetCurrentHWID:
				res |= roHWID;
				break;
			case atActivateLicense:
			case atDeactivateLicense:
				res |= roKey | roActivation;
				break;
			}
		}
	}

	return res;
}

void CompilerFunctionList::Rebase(uint64_t delta_base)
{
	map_.clear();
	for (size_t i = 0; i < count(); i++) {
		CompilerFunction *func = item(i);
		func->Rebase(delta_base);
		map_[func->address()] = func;
	}
}
