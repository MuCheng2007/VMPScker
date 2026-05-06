#ifndef INTEL_OBFUSCATION_H
#define INTEL_OBFUSCATION_H

#include "../../processors.h"
#include "IntelCommandType.h"
#include "IntelOperand.h"
#include "IntelStack.h"

class IntelFunction;
class IntelCommand;
class AddressRange;

class IntelObfuscation : public IObject
{
public:
	explicit IntelObfuscation();
	void Compile(IntelFunction *func, size_t index);
private:
	IntelCommand *AddCommand(IntelCommandType type, IntelOperand operand1 = IntelOperand(), IntelOperand operand2 = IntelOperand(), IntelOperand operand3 = IntelOperand());
	void AddRandomCommands();
	void AddRestoreStack(size_t to_index);
	void AddRestoreRegistr(uint8_t reg);
	void AddRestoreStackItem(IntelStackValue *stack_item);
	void CompileOperand(IntelOperand *operand);

	IntelFunction *func_;
	AddressRange *address_range_;
	std::vector<IntelCommand *> command_list_;
	IntelStack stack_;
	IntelRegistrStorage registr_values_;
	IntelFlagsValue flags_;
	std::map<IntelCommand *, size_t> jmp_command_list_;
};

#endif // INTEL_OBFUSCATION_H