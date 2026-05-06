#ifndef INTEL_VIRTUAL_MACHINE_PROCESSOR_H
#define INTEL_VIRTUAL_MACHINE_PROCESSOR_H

#include "../ir/IntelCommandType.h"
#include "../ir/IntelFunction.h"
#include "../../processors.h"
#include <vector>
#include <memory>

class IntelFunctionList;
class IntelCommand;
struct IntelVirtualMachineObfuscation;
struct CompileContext;

class IntelVirtualMachineProcessor : public IntelFunction
{
public:
	IntelVirtualMachineProcessor(IntelFunctionList *parent, OperandSize cpu_address_size);
	virtual bool Prepare(const CompileContext &ctx);
	void AddExceptionHandler(const CompileContext &ctx);
	void AddObfuscation(size_t old_count);
	void AddObfuscationHandler(IntelCommand *begin);

	std::vector<std::unique_ptr<IntelVirtualMachineObfuscation>> obfuscation_list_;
};

#endif // INTEL_VIRTUAL_MACHINE_PROCESSOR_H
