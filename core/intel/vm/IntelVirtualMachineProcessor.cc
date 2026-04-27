#include "IntelVirtualMachineProcessor.h"
#include "../ir/IntelFunction.h"
#include "../ir/IntelFunctionList.h"
#include "../ir/IntelCommand.h"
#include "../ir/IntelObfuscation.h"
#include "../../processors.h"
#include "../../lang.h"

/*
 * IntelVirtualMachineProcessor
 */

IntelVirtualMachineProcessor::IntelVirtualMachineProcessor(IntelFunctionList* owner, OperandSize cpu_address_size)
	: IntelFunction(owner, cpu_address_size)
{
	set_compilation_type(ctMutation);
	set_tag(ftProcessor);
}

bool IntelVirtualMachineProcessor::Prepare(const CompileContext& ctx)
{
	if (cpu_address_size() == ctx.file->cpu_address_size() && ctx.file->runtime_function_list())
		AddExceptionHandler(ctx);

	for (size_t i = 0; i < count(); i++) {
		IntelCommand* command = item(i);
		command->CompileToNative();
	}

	return IntelFunction::Prepare(ctx);
}

void IntelVirtualMachineProcessor::AddExceptionHandler(const CompileContext& ctx)
{
	size_t c = count();
	if (c == 0)
		return;

	switch (ctx.file->calling_convention()) {
	case ccMSx64:
	{
		// RCX: ExceptionRecord
		// RDX: EstablisherFrame
		// R8: ContextRecord
		// R9: DispatcherContext

		IntelCommand* command;
		size_t i, k;
		size_t context_registr_count = ((cpu_address_size() == osQWord) ? 24 : 16) + 8;

		IntelCommand* empty_unwind_command = AddCommand(cmRet);
		empty_unwind_command->include_option(roCreateNewBlock);

		IntelCommand* handler_entry = AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regEAX), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEDX, (context_registr_count - 8 + 0) * OperandSizeToValue(cpu_address_size())));
		AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regECX), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEDX, (context_registr_count - 8 + 1) * OperandSizeToValue(cpu_address_size())));

		AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size(), regECX), IntelOperand(otValue, cpu_address_size(), 0, 8));
		AddCommand(cmMov, IntelOperand(otMemory | otRegistr, cpu_address_size(), regECX), IntelOperand(otRegistr, cpu_address_size(), regEAX));

		command = AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size(), regEDX), IntelOperand(otValue, cpu_address_size(), 0, (context_registr_count - 8 + 6) * OperandSizeToValue(cpu_address_size())));
		command = AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size(), regEAX), IntelOperand(otMemory | otValue, cpu_address_size(), 0, 0, LARGE_VALUE));
		command->AddLink(1, ltOffset, empty_unwind_command);
		IntelCommand* cmp_command = AddCommand(cmCmp, IntelOperand(otRegistr, cpu_address_size(), regECX), IntelOperand(otRegistr, cpu_address_size(), regEDX));
		IntelCommand* jmp_command = AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size()));
		jmp_command->set_flags(fl_C | fl_Z);
		jmp_command->AddLink(0, ltJmpWithFlag);
		AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size(), regECX), IntelOperand(otValue, cpu_address_size(), 0, 8));
		AddCommand(cmMov, IntelOperand(otMemory | otRegistr, cpu_address_size(), regECX), IntelOperand(otRegistr, cpu_address_size(), regEAX));
		command = AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size()));
		command->AddLink(0, ltJmp, cmp_command);

		command = AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regECX), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regR9, 0x28)); // DISPATCHER_CONTEXT.ContextRecord
		jmp_command->link()->set_to_command(command);
		AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regEAX), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regECX, offsetof(CONTEXT64, Rsp)));
		AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regEAX), IntelOperand(otMemory | otRegistr, cpu_address_size(), regEAX));
		AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regECX, offsetof(CONTEXT64, Rip)), IntelOperand(otRegistr, cpu_address_size(), regEAX));

		command = AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regEAX), IntelOperand(otValue, osDWord, 0, ExceptionContinueSearch));
		AddCommand(cmRet);

		k = count();

		UNWIND_CODE unwind_code;
		std::vector<UNWIND_CODE> unwind_code_list;

		unwind_code.CodeOffset = 5;
		unwind_code.UnwindOp = UWOP_ALLOC_LARGE;
		unwind_code.OpInfo = 0;
		unwind_code_list.push_back(unwind_code);

		unwind_code.FrameOffset = (USHORT)(context_registr_count - 8 + 2);
		unwind_code_list.push_back(unwind_code);

		unwind_code.CodeOffset = 4;
		unwind_code.UnwindOp = UWOP_PUSH_NONVOL;
		unwind_code.OpInfo = regEBP;
		unwind_code_list.push_back(unwind_code);

		unwind_code.CodeOffset = 3;
		unwind_code.UnwindOp = UWOP_PUSH_NONVOL;
		unwind_code.OpInfo = regESI;
		unwind_code_list.push_back(unwind_code);

		unwind_code.CodeOffset = 2;
		unwind_code.UnwindOp = UWOP_PUSH_NONVOL;
		unwind_code.OpInfo = regEDI;
		unwind_code_list.push_back(unwind_code);

		unwind_code.CodeOffset = 1;
		unwind_code.UnwindOp = UWOP_PUSH_NONVOL;
		unwind_code.OpInfo = regEBX;
		unwind_code_list.push_back(unwind_code);

		UNWIND_INFO unwind_info = UNWIND_INFO();
		unwind_info.Version = 1;
		unwind_info.Flags = UNW_FLAG_EHANDLER;
		unwind_info.CountOfCodes = static_cast<uint8_t>(unwind_code_list.size());

		union UNWIND_INFO_HELPER {
			UNWIND_INFO info;
			uint32_t value;
		};

		UNWIND_INFO_HELPER unwind_info_helper;
		unwind_info_helper.info = unwind_info;

		// unwind data
		IntelCommand* unwind_data_command = AddCommand(osDWord, unwind_info_helper.value);
		unwind_data_command->include_option(roCreateNewBlock);
		unwind_data_command->set_alignment(OperandSizeToValue(osDWord));
		for (i = 0; i < unwind_code_list.size(); i++) {
			AddCommand(osWord, unwind_code_list[i].FrameOffset);
		}
		if (unwind_code_list.size() & 1)
			AddCommand(osWord, 0);

		// handler
		command = AddCommand(osDWord, 0);
		CommandLink* link = command->AddLink(0, ltOffset, handler_entry);
		link->set_sub_value(ctx.file->image_base());
		// handler data
		AddCommand(osDWord, 0);

		uint64_t info_address = owner()->IndexOf(this) * 10;
		FunctionInfo* info = function_info_list()->Add(info_address, info_address, btImageBase, 0, 0, unwind_info.FrameRegister, 0, unwind_data_command);
		AddressRange* address_range = info->Add(0, 0, NULL, NULL, NULL);
		for (i = 0; i < c; i++) {
			item(i)->set_address_range(address_range);
		}

		unwind_info = UNWIND_INFO();
		unwind_info.Version = 1;
		unwind_info.Flags = UNW_FLAG_NHANDLER;

		unwind_info_helper.info = unwind_info;
		unwind_data_command = AddCommand(osDWord, unwind_info_helper.value);
		unwind_data_command->include_option(roCreateNewBlock);
		unwind_data_command->set_alignment(OperandSizeToValue(osDWord));

		info = function_info_list()->Add(info_address + 1, info_address + 1, btImageBase, 0, 0, 0, 0, unwind_data_command);
		address_range = info->Add(0, 0, NULL, NULL, NULL);
		empty_unwind_command->set_address_range(address_range);

		unwind_info = UNWIND_INFO();
		unwind_info.Version = 1;
		unwind_info.Flags = UNW_FLAG_NHANDLER;

		unwind_info_helper.info = unwind_info;
		unwind_data_command = AddCommand(osDWord, unwind_info_helper.value);
		unwind_data_command->include_option(roCreateNewBlock);
		unwind_data_command->set_alignment(OperandSizeToValue(osDWord));

		info = function_info_list()->Add(info_address + 2, info_address + 2, btImageBase, 0, 0, 0, 0, unwind_data_command);
		address_range = info->Add(0, 0, NULL, NULL, NULL);
		for (i = IndexOf(handler_entry); i < k; i++) {
			item(i)->set_address_range(address_range);
		}
	}
	break;
	}
}
