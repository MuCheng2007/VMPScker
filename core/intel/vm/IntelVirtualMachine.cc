#include "IntelVirtualMachine.h"
#include "../../files/utils.h"
#include "../../files/architecture.h"
#include "IntelVirtualMachineList.h"
#include "IntelVirtualMachineProcessor.h"
#include "../ir/IntelCommand.h"
#include "../ir/IntelVMCommand.h"
#include "../ir/IntelOpcodeInfo.h"
#include "../ir/IntelFunction.h"
#include "../ir/IntelFunctionList.h"
#include "../../processors.h"
#include "../../core_internal/core.h"
#include "../../files/architecture.h"
#include "../../files/types.h"
#include "../../lang.h"
#include "../../../runtime/crypto.h"

// Copied from intel.cc: IntelVirtualMachine implementation
// Search "IntelVirtualMachine::" in intel.cc for all methods

/**
 * IntelVirtualMachine
 */

IntelVirtualMachine::IntelVirtualMachine(IntelVirtualMachineList* owner, VirtualMachineType type, uint8_t id, IntelVirtualMachineProcessor* processor)
	: BaseVirtualMachine(owner, id), type_(type), processor_(processor), entry_command_(NULL), init_command_(NULL), ext_jmp_command_(NULL), command_cryptor_(NULL),
	stack_registr_(0), pcode_registr_(0), jmp_registr_(0), crypt_registr_(0)
{
	backward_direction_ = (rand() & 1) == 0;
}

IntelVirtualMachine::~IntelVirtualMachine()
{
	delete ext_jmp_command_;
	delete command_cryptor_;
	for (size_t i = 0; i < cryptor_list_.size(); i++) {
		delete cryptor_list_[i];
	}
}

IntelFunction *IntelVirtualMachine::processor() const
{
	return processor_;
}

void IntelVirtualMachine::Init(const CompileContext& ctx, const IntelOpcodeList& visible_opcode_list)
{
	InitCommands(ctx, visible_opcode_list);

	opcode_stack_.clear();
	for (size_t i = 0; i < opcode_list_.count(); i++) {
		IntelOpcodeInfo* item = opcode_list_.item(i);
		opcode_stack_[item->Key()].push_back(item);
	}
}

void IntelVirtualMachine::Prepare(const CompileContext& ctx)
{
	size_t i;
	std::vector<IntelVirtualMachine*> virtual_machine_list;
	OperandSize cpu_address_size = processor_->cpu_address_size();
	for (i = 0; i < ctx.file->virtual_machine_list()->count(); i++) {
		IntelVirtualMachine* virtual_machine = reinterpret_cast<IntelVirtualMachineList*>(ctx.file->virtual_machine_list())->item(i);
		if (virtual_machine->processor()->cpu_address_size() == cpu_address_size)
			virtual_machine_list.push_back(virtual_machine);
	}

	// setup VMs cross references
	for (i = 0; i < vm_links_.size(); i++) {
		IntelVirtualMachine* virtual_machine = virtual_machine_list[i];

		IntelCommand* command = vm_links_[i];
		command->link()->set_to_command(virtual_machine->init_command());

		size_t j = processor_->IndexOf(command);
		uint8_t stack_registr = stack_registr_;
		uint8_t pcode_registr = processor_->item(j - 2)->operand(0).registr;
		if (virtual_machine->pcode_registr_ != pcode_registr) {
			if (virtual_machine->pcode_registr_ == stack_registr_) {
				command = new IntelCommand(processor_, cpu_address_size, cmXchg, IntelOperand(otRegistr, cpu_address_size, virtual_machine->pcode_registr_), IntelOperand(otRegistr, cpu_address_size, pcode_registr));
				stack_registr = pcode_registr;
			}
			else
				command = new IntelCommand(processor_, cpu_address_size, cmMov, IntelOperand(otRegistr, cpu_address_size, virtual_machine->pcode_registr_), IntelOperand(otRegistr, cpu_address_size, pcode_registr));
			command->CompileToNative();
			processor_->InsertObject(j++, command);
		}
		if (virtual_machine->stack_registr_ != stack_registr) {
			command = new IntelCommand(processor_, cpu_address_size, cmMov, IntelOperand(otRegistr, cpu_address_size, virtual_machine->stack_registr_), IntelOperand(otRegistr, cpu_address_size, stack_registr));
			command->CompileToNative();
			processor_->InsertObject(j, command);
		}
	}
}

IntelCommand* IntelVirtualMachine::AddReadCommand(OperandSize size, OpcodeCryptor* command_cryptor, uint8_t registr)
{
	size_t c = processor_->count();
	OperandSize mov_size = (size < osDWord) ? osDWord : size;
	if (backward_direction_) {
		processor_->AddCommand(cmSub, IntelOperand(otRegistr, processor_->cpu_address_size(), pcode_registr_), IntelOperand(otValue, processor_->cpu_address_size(), 0, OperandSizeToValue(size)));
		processor_->AddCommand((mov_size == size) ? cmMov : cmMovzx, IntelOperand(otRegistr, mov_size, registr), IntelOperand(otMemory | otRegistr, size, pcode_registr_));
	}
	else {
		processor_->AddCommand((mov_size == size) ? cmMov : cmMovzx, IntelOperand(otRegistr, mov_size, registr), IntelOperand(otMemory | otRegistr, size, pcode_registr_));
		processor_->AddCommand(cmAdd, IntelOperand(otRegistr, processor_->cpu_address_size(), pcode_registr_), IntelOperand(otValue, processor_->cpu_address_size(), 0, OperandSizeToValue(size)));
	}

	if (command_cryptor) {
		IntelCommandType command_type = CryptorCommandToIntel(command_cryptor->type());
		OperandSize size = command_cryptor->size();

		processor_->AddCommand(command_type, IntelOperand(otRegistr, size, registr), IntelOperand(otRegistr, size, crypt_registr_));
		for (size_t i = 0; i < command_cryptor->count(); i++) {
			AddValueCommand(*command_cryptor->item(i), false, registr);
		}
		if (processor_->cpu_address_size() == osQWord && size == osDWord) {
			processor_->AddCommand(cmPush, IntelOperand(otRegistr, osQWord, crypt_registr_));
			processor_->AddCommand(command_type, IntelOperand(otMemory | otRegistr, size, regESP), IntelOperand(otRegistr, size, registr));
			processor_->AddCommand(cmPop, IntelOperand(otRegistr, osQWord, crypt_registr_));
		}
		else {
			processor_->AddCommand(command_type, IntelOperand(otRegistr, size, crypt_registr_), IntelOperand(otRegistr, size, registr));
		}
	}

	return processor_->item(c);
}

void IntelVirtualMachine::AddValueCommand(ValueCommand& value_command, bool is_decrypt, uint8_t registr)
{
	IntelCommandType command_type = CryptorCommandToIntel(value_command.type(is_decrypt));
	IntelOperand second_operand;
	if (command_type == cmAdd || command_type == cmSub || command_type == cmXor || command_type == cmRol || command_type == cmRor)
		second_operand = IntelOperand(otValue, (command_type == cmRol || command_type == cmRor) ? osByte : value_command.size(), 0, value_command.value());
	processor_->AddCommand(command_type, IntelOperand(otRegistr, value_command.size(), registr), second_operand);
}

void IntelVirtualMachine::AddEndHandlerCommands(IntelCommand* to_command, OpcodeCryptor* command_cryptor)
{
	IntelCommand* command;
	if (type_ == vtAdvanced) {
		IntelRegistrList registr_list = free_registr_list_;
		uint8_t reg1 = registr_list.GetRandom();
		AddReadCommand(osDWord, command_cryptor, reg1);
		if (processor_->cpu_address_size() == osQWord)
			processor_->AddCommand(cmMovsxd, IntelOperand(otRegistr, processor_->cpu_address_size(), reg1), IntelOperand(otRegistr, osDWord, reg1));
		processor_->AddCommand(cmAdd, IntelOperand(otRegistr, processor_->cpu_address_size(), jmp_registr_), IntelOperand(otRegistr, processor_->cpu_address_size(), reg1));
		if (to_command) {
			command = processor_->AddCommand(cmJmp, IntelOperand(otValue, processor_->cpu_address_size()));
			command->AddLink(0, ltJmp, to_command);
		}
		else {
			command = processor_->AddCommand(cmJmp, IntelOperand(otRegistr, processor_->cpu_address_size(), jmp_registr_));
			command->AddLink(-1, ltJmp);
		}
	}
	else {
		command = processor_->AddCommand(cmJmp, IntelOperand(otValue, processor_->cpu_address_size()));
		command->AddLink(0, ltJmp, to_command);
	}
}

IntelCommand* IntelVirtualMachine::CloneHandler(IntelCommand* handler)
{
	size_t i, c, j;
	std::map<ICommand*, ICommand*> command_map;

	c = processor_->count();
	j = processor_->IndexOf(handler);
	for (i = j; i < c; i++) {
		IntelCommand* src_command = processor_->item(i);
		IntelCommand* dst_command = src_command->Clone(processor_);
		processor_->AddObject(dst_command);

		command_map[src_command] = dst_command;

		CommandLink* src_link = src_command->link();
		if (src_link) {
			CommandLink* dst_link = src_link->Clone(processor_->link_list());
			dst_link->set_from_command(dst_command);
			dst_link->set_to_command(src_link->to_command());
			processor_->link_list()->AddObject(dst_link);
		}

		if (src_command->type() == cmJmp && src_link && src_link->to_command()) {
			if (j > processor_->IndexOf(src_link->to_command()))
				break;
		}
		else if (src_command->is_end())
			break;
	}

	for (i = c; i < processor_->count(); i++) {
		IntelCommand* command = processor_->item(i);
		CommandLink* link = command->link();
		if (!link || !link->to_command())
			continue;

		std::map<ICommand*, ICommand*>::const_iterator it = command_map.find(link->to_command());
		if (it != command_map.end())
			link->set_to_command(it->second);
	}

	return processor_->item(c);
}

void IntelVirtualMachine::AddCallCommands(CallingConvention calling_convention, IntelCommand* call_entry, uint8_t registr)
{
	std::vector<uint8_t> registr_list;
	IntelCommand* command;
	size_t i;

	OperandSize cpu_address_size = processor_->cpu_address_size();
	OperandSize arg_address_size = (calling_convention == ccStdcallToMSx64) ? osDWord : processor_->cpu_address_size();

	switch (calling_convention) { //-V719
	case ccMSx64:
	case ccStdcallToMSx64:
		registr_list.push_back(regECX);
		registr_list.push_back(regEDX);
		registr_list.push_back(regR8);
		registr_list.push_back(regR9);
		break;
	case ccABIx64:
		registr_list.push_back(regEDI);
		registr_list.push_back(regESI);
		registr_list.push_back(regEDX);
		registr_list.push_back(regECX);
		registr_list.push_back(regR8);
		registr_list.push_back(regR9);
		break;
	}

	// push common registers
	processor_->AddCommand(cmPush, IntelOperand(otRegistr, cpu_address_size, pcode_registr_));
	if (jmp_registr_)
		processor_->AddCommand(cmPush, IntelOperand(otRegistr, cpu_address_size, jmp_registr_));
	if (crypt_registr_)
		processor_->AddCommand(cmPush, IntelOperand(otRegistr, cpu_address_size, crypt_registr_));
	if (stack_registr_ != regEBP)
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, regEBP), IntelOperand(otRegistr, cpu_address_size, stack_registr_));

	if (registr != regEBX)
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regEBX), IntelOperand(otRegistr, osDWord, registr));
	processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regEDX), IntelOperand(otRegistr, osDWord, regEBX));
	if (!registr_list.empty()) {
		processor_->AddCommand(cmXor, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otRegistr, osDWord, regECX));
		processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osDWord, regEBX), IntelOperand(otValue, osDWord, 0, registr_list.size()));
		IntelCommand* jmp_no_stack_args = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_no_stack_args->set_flags(fl_C | fl_Z);
		jmp_no_stack_args->AddLink(0, ltJmpWithFlag);
		if (calling_convention != ccStdcallToMSx64)
			processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regEDX), IntelOperand(otValue, osDWord, 0, registr_list.size()));
		processor_->AddCommand(cmLea, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otMemory | otRegistr | otValue, osDWord, regEBX, 0 - registr_list.size()));
		command = processor_->AddCommand(cmShl, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otValue, osByte, 0, cpu_address_size == osDWord ? 2 : 3));
		jmp_no_stack_args->link()->set_to_command(command);
	}
	processor_->AddCommand(cmShl, IntelOperand(otRegistr, osDWord, regEDX), IntelOperand(otValue, osByte, 0, arg_address_size == osDWord ? 2 : 3));
	if (calling_convention != ccCdecl) {
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, regEAX), IntelOperand(otRegistr, cpu_address_size, regEBP));
		processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, regEAX), IntelOperand(otRegistr, cpu_address_size, regEDX));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otBaseRegistr | otValue, cpu_address_size, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size)), IntelOperand(otRegistr, cpu_address_size, regEAX));
	}
	if (calling_convention != ccStdcall) {
		// align stack
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otBaseRegistr | otValue, cpu_address_size, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 2), IntelOperand(otRegistr, cpu_address_size, regESP));
		processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, regESP), IntelOperand(otRegistr, cpu_address_size, registr_list.empty() ? regEDX : regECX));
		processor_->AddCommand(cmAnd, IntelOperand(otRegistr, cpu_address_size, regESP), IntelOperand(otValue, cpu_address_size, 0, -16));
		processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, regESP), IntelOperand(otRegistr, cpu_address_size, registr_list.empty() ? regEDX : regECX));
	}
	else if (call_entry)
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otBaseRegistr | otValue, cpu_address_size, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 2), IntelOperand(otRegistr, cpu_address_size, regESP));

	processor_->AddCommand(cmTest, IntelOperand(otRegistr, osDWord, regEBX), IntelOperand(otRegistr, osDWord, regEBX));
	IntelCommand* jmp_end_store = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
	jmp_end_store->set_flags(fl_Z);
	jmp_end_store->AddLink(0, ltJmpWithFlag);

	IntelCommand* load_arg = processor_->AddCommand(cmMov, IntelOperand(otRegistr, arg_address_size, regEAX), IntelOperand(otMemory | otBaseRegistr | otRegistr | otValue, arg_address_size, (regEBP << 4) | regEBX));
	load_arg->set_operand_scale(1, arg_address_size == osDWord ? 2 : 3);

	std::vector<IntelCommand*> jmp_loop_arg;
	IntelCommand* jmp_arg_command = NULL;
	if (!registr_list.empty()) {
		// store arg in register
		for (i = 0; i < registr_list.size(); i++) {
			command = processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osDWord, regEBX), IntelOperand(otValue, osDWord, 0, i + 1));
			if (jmp_arg_command)
				jmp_arg_command->link()->set_to_command(command);

			jmp_arg_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
			jmp_arg_command->set_flags(fl_Z);
			jmp_arg_command->include_option(roInverseFlag);
			jmp_arg_command->AddLink(0, ltJmpWithFlag);

			processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, registr_list[i]), IntelOperand(otRegistr, cpu_address_size, regEAX));
			command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
			command->AddLink(0, ltJmp);
			jmp_loop_arg.push_back(command);
		}
	}

	// store arg in stack
	if (calling_convention == ccMSx64) {
		command = processor_->AddCommand(cmPush, IntelOperand(otMemory | otBaseRegistr | otRegistr | otValue, cpu_address_size, (regEBP << 4) | regEBX, 0x20));
		command->set_operand_scale(0, 3);
	}
	else
		command = processor_->AddCommand(cmPush, IntelOperand(otRegistr, cpu_address_size, regEAX));
	if (jmp_arg_command)
		jmp_arg_command->link()->set_to_command(command);

	// loop arg
	command = processor_->AddCommand(cmSub, IntelOperand(otRegistr, osDWord, regEBX), IntelOperand(otValue, osDWord, 0, 1));
	for (i = 0; i < jmp_loop_arg.size(); i++) {
		jmp_loop_arg[i]->link()->set_to_command(command);
	}
	command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
	command->set_flags(fl_Z);
	command->include_option(roInverseFlag);
	command->AddLink(0, ltJmpWithFlag, load_arg);

	// end store
	command = processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, regEAX), IntelOperand(otMemory | otBaseRegistr | otValue, cpu_address_size, regEBP << 4, 0));
	jmp_end_store->link()->set_to_command(command);

	if (calling_convention == ccStdcallToMSx64) {
		// convert input args
		std::vector<IntelCommand*> jmp_end_convert;
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR10), IntelOperand(otRegistr, osDWord, regEAX));
		processor_->AddCommand(cmShr, IntelOperand(otRegistr, osDWord, regR10), IntelOperand(otValue, osByte, 0, 24));
		IntelCommand* jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->AddLink(0, ltJmpWithFlag);
		jmp_end_convert.push_back(jmp_command);

		// NtProtectVirtualMemory
		processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osByte, regR10), IntelOperand(otValue, osByte, 0, 1));
		IntelCommand* cmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		cmp_command->set_flags(fl_Z);
		cmp_command->include_option(roInverseFlag);
		cmp_command->AddLink(0, ltJmpWithFlag);

		processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otValue, osDWord, 0, (uint32_t)-1)); // NtCurrentProcess
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->include_option(roInverseFlag);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmMovsxd, IntelOperand(otRegistr, osQWord, regECX), IntelOperand(otRegistr, osDWord, regECX));

		command = processor_->AddCommand(cmTest, IntelOperand(otRegistr, osDWord, regEDX), IntelOperand(otRegistr, osDWord, regEDX));
		jmp_command->link()->set_to_command(command);
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, regR10), IntelOperand(otMemory | otBaseRegistr | otValue, cpu_address_size, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 3));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regEDX), IntelOperand(otMemory | otRegistr, osDWord, regEDX));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, cpu_address_size, regR10), IntelOperand(otRegistr, cpu_address_size, regEDX));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, regEDX), IntelOperand(otRegistr, cpu_address_size, regR10));

		command = processor_->AddCommand(cmTest, IntelOperand(otRegistr, osDWord, regR8), IntelOperand(otRegistr, osDWord, regR8));
		jmp_command->link()->set_to_command(command);
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, regR10), IntelOperand(otMemory | otBaseRegistr | otValue, cpu_address_size, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 4));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR8), IntelOperand(otMemory | otRegistr, osDWord, regR8));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, cpu_address_size, regR10), IntelOperand(otRegistr, cpu_address_size, regR8));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, regR8), IntelOperand(otRegistr, cpu_address_size, regR10));
		command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
		jmp_command->link()->set_to_command(command);
		command->AddLink(0, ltJmp);
		jmp_end_convert.push_back(command);

		// NtSetInformationThread
		command = processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osByte, regR10), IntelOperand(otValue, osByte, 0, 2));
		cmp_command->link()->set_to_command(command);
		cmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		cmp_command->set_flags(fl_Z);
		cmp_command->include_option(roInverseFlag);
		cmp_command->AddLink(0, ltJmpWithFlag);

		processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otValue, osDWord, 0, (uint32_t)-2)); // NtCurrentThread
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->include_option(roInverseFlag);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmMovsxd, IntelOperand(otRegistr, osQWord, regECX), IntelOperand(otRegistr, osDWord, regECX));
		command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
		jmp_command->link()->set_to_command(command);
		command->AddLink(0, ltJmp);
		jmp_end_convert.push_back(command);

		// NtQueryInformationProcess
		command = processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osByte, regR10), IntelOperand(otValue, osByte, 0, 3));
		cmp_command->link()->set_to_command(command);
		cmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		cmp_command->set_flags(fl_Z);
		cmp_command->include_option(roInverseFlag);
		cmp_command->AddLink(0, ltJmpWithFlag);

		processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otValue, osDWord, 0, (uint32_t)-1)); // NtCurrentProcess
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->include_option(roInverseFlag);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmMovsxd, IntelOperand(otRegistr, osQWord, regECX), IntelOperand(otRegistr, osDWord, regECX));

		command = processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osDWord, regEDX), IntelOperand(otValue, osDWord, 0, 0x7)); // ProcessDebugPort
		jmp_command->link()->set_to_command(command);
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->include_option(roInverseFlag);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, regR10), IntelOperand(otMemory | otBaseRegistr | otValue, cpu_address_size, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 3));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, regR8), IntelOperand(otRegistr, cpu_address_size, regR10));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR9), IntelOperand(otValue, osDWord, 0, OperandSizeToValue(cpu_address_size)));
		command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
		command->AddLink(0, ltJmp);
		jmp_end_convert.push_back(command);

		command = processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osDWord, regEDX), IntelOperand(otValue, osDWord, 0, 0x1e)); // ProcessDebugObjectHandle
		jmp_command->link()->set_to_command(command);
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->include_option(roInverseFlag);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, regR10), IntelOperand(otMemory | otBaseRegistr | otValue, cpu_address_size, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 3));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, regR8), IntelOperand(otRegistr, cpu_address_size, regR10));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR9), IntelOperand(otValue, osDWord, 0, OperandSizeToValue(cpu_address_size)));
		command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
		jmp_command->link()->set_to_command(command);
		command->AddLink(0, ltJmp);
		jmp_end_convert.push_back(command);

		// NtMapViewOfSection
		command = processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osByte, regR10), IntelOperand(otValue, osByte, 0, 4));
		cmp_command->link()->set_to_command(command);
		cmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		cmp_command->set_flags(fl_Z);
		cmp_command->include_option(roInverseFlag);
		cmp_command->AddLink(0, ltJmpWithFlag);

		processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osDWord, regEDX), IntelOperand(otValue, osDWord, 0, (uint32_t)-1)); // NtCurrentProcess
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->include_option(roInverseFlag);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmMovsxd, IntelOperand(otRegistr, osQWord, regEDX), IntelOperand(otRegistr, osDWord, regEDX));

		command = processor_->AddCommand(cmTest, IntelOperand(otRegistr, osDWord, regR8), IntelOperand(otRegistr, osDWord, regR8));
		jmp_command->link()->set_to_command(command);
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, regR10), IntelOperand(otMemory | otBaseRegistr | otValue, cpu_address_size, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 3));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR8), IntelOperand(otMemory | otRegistr, osDWord, regR8));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, cpu_address_size, regR10), IntelOperand(otRegistr, cpu_address_size, regR8));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, regR8), IntelOperand(otRegistr, cpu_address_size, regR10));

		command = processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR11), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size, regESP, OperandSizeToValue(cpu_address_size) * 2));
		processor_->AddCommand(cmTest, IntelOperand(otRegistr, osDWord, regR11), IntelOperand(otRegistr, osDWord, regR11));
		jmp_command->link()->set_to_command(command);
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, regR10), IntelOperand(otMemory | otBaseRegistr | otValue, cpu_address_size, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 4));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR11), IntelOperand(otMemory | otRegistr, osDWord, regR11));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, cpu_address_size, regR10), IntelOperand(otRegistr, cpu_address_size, regR11));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size, regESP, OperandSizeToValue(cpu_address_size) * 2), IntelOperand(otRegistr, cpu_address_size, regR10));
		command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
		jmp_command->link()->set_to_command(command);
		command->AddLink(0, ltJmp);
		jmp_end_convert.push_back(command);

		// NtUnmapViewOfSection
		command = processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osByte, regR10), IntelOperand(otValue, osByte, 0, 5));
		cmp_command->link()->set_to_command(command);
		cmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		cmp_command->set_flags(fl_Z);
		cmp_command->include_option(roInverseFlag);
		cmp_command->AddLink(0, ltJmpWithFlag);

		processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otValue, osDWord, 0, (uint32_t)-1)); // NtCurrentProcess
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->include_option(roInverseFlag);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmMovsxd, IntelOperand(otRegistr, osQWord, regECX), IntelOperand(otRegistr, osDWord, regECX));
		command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
		jmp_command->link()->set_to_command(command);
		command->AddLink(0, ltJmp);
		jmp_end_convert.push_back(command);

		// NtOpenFile
		command = processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osByte, regR10), IntelOperand(otValue, osByte, 0, 6));
		cmp_command->link()->set_to_command(command);
		cmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		cmp_command->set_flags(fl_Z);
		cmp_command->include_option(roInverseFlag);
		cmp_command->AddLink(0, ltJmpWithFlag);

		command = processor_->AddCommand(cmTest, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otRegistr, osDWord, regECX));
		jmp_command->link()->set_to_command(command);
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, regECX), IntelOperand(otMemory | otBaseRegistr | otValue, cpu_address_size, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 3));

		command = processor_->AddCommand(cmTest, IntelOperand(otRegistr, osDWord, regR9), IntelOperand(otRegistr, osDWord, regR9));
		jmp_command->link()->set_to_command(command);
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, regR9), IntelOperand(otMemory | otBaseRegistr | otValue, cpu_address_size, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 5));

		command = processor_->AddCommand(cmTest, IntelOperand(otRegistr, osDWord, regR8), IntelOperand(otRegistr, osDWord, regR8));
		jmp_command->link()->set_to_command(command);
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, regR10), IntelOperand(otMemory | otBaseRegistr | otValue, cpu_address_size, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 10));
		processor_->AddCommand(cmAnd, IntelOperand(otRegistr, cpu_address_size, regR10), IntelOperand(otValue, cpu_address_size, 0, (uint64_t)-16));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR11), IntelOperand(otValue, osDWord, 0, 0x30));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, osQWord, regR10), IntelOperand(otRegistr, osQWord, regR11));
		processor_->AddCommand(cmXor, IntelOperand(otRegistr, osDWord, regR11), IntelOperand(otRegistr, osDWord, regR11));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osQWord, regR10, 0x08), IntelOperand(otRegistr, osQWord, regR11));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osQWord, regR10, 0x10), IntelOperand(otRegistr, osQWord, regR11));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osQWord, regR10, 0x20), IntelOperand(otRegistr, osQWord, regR11));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osQWord, regR10, 0x28), IntelOperand(otRegistr, osQWord, regR11));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR11), IntelOperand(otMemory | otRegistr | otValue, osDWord, regR8, 0x0c));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osQWord, regR10, 0x18), IntelOperand(otRegistr, osQWord, regR11));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR11), IntelOperand(otMemory | otRegistr | otValue, osDWord, regR8, 0x08));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, regR8), IntelOperand(otRegistr, cpu_address_size, regR10));

		processor_->AddCommand(cmTest, IntelOperand(otRegistr, osDWord, regR11), IntelOperand(otRegistr, osDWord, regR11));
		IntelCommand* jmp_command2 = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command2->set_flags(fl_Z);
		jmp_command2->AddLink(0, ltJmpWithFlag);

		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR10), IntelOperand(otMemory | otRegistr, osDWord, regR11));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osQWord, regR8, 0 - OperandSizeToValue(cpu_address_size) * 2), IntelOperand(otRegistr, osQWord, regR10));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR10), IntelOperand(otMemory | otRegistr | otValue, osDWord, regR11, 4));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osQWord, regR8, 0 - OperandSizeToValue(cpu_address_size)), IntelOperand(otRegistr, osQWord, regR10));
		processor_->AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, regR10), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size, regR8, 0 - OperandSizeToValue(cpu_address_size) * 2));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osQWord, regR8, 0x10), IntelOperand(otRegistr, osQWord, regR10));

		command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
		jmp_command->link()->set_to_command(command);
		jmp_command2->link()->set_to_command(command);
		command->AddLink(0, ltJmp);
		jmp_end_convert.push_back(command);

		// NtCreateSection
		command = processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osByte, regR10), IntelOperand(otValue, osByte, 0, 7));
		cmp_command->link()->set_to_command(command);
		cmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		cmp_command->set_flags(fl_Z);
		cmp_command->include_option(roInverseFlag);
		cmp_command->AddLink(0, ltJmpWithFlag);

		command = processor_->AddCommand(cmTest, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otRegistr, osDWord, regECX));
		jmp_command->link()->set_to_command(command);
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, regECX), IntelOperand(otMemory | otBaseRegistr | otValue, cpu_address_size, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 3));

		command = processor_->AddCommand(cmTest, IntelOperand(otRegistr, osDWord, regR8), IntelOperand(otRegistr, osDWord, regR8));
		jmp_command->link()->set_to_command(command);
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, regR10), IntelOperand(otMemory | otBaseRegistr | otValue, cpu_address_size, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 8));
		processor_->AddCommand(cmAnd, IntelOperand(otRegistr, cpu_address_size, regR10), IntelOperand(otValue, cpu_address_size, 0, (uint64_t)-16));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR11), IntelOperand(otValue, osDWord, 0, 0x30));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, osQWord, regR10), IntelOperand(otRegistr, osQWord, regR11));
		processor_->AddCommand(cmXor, IntelOperand(otRegistr, osDWord, regR11), IntelOperand(otRegistr, osDWord, regR11));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osQWord, regR10, 0x08), IntelOperand(otRegistr, osQWord, regR11));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osQWord, regR10, 0x10), IntelOperand(otRegistr, osQWord, regR11));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osQWord, regR10, 0x20), IntelOperand(otRegistr, osQWord, regR11));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osQWord, regR10, 0x28), IntelOperand(otRegistr, osQWord, regR11));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR11), IntelOperand(otMemory | otRegistr | otValue, osDWord, regR8, 0x0c));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osQWord, regR10, 0x18), IntelOperand(otRegistr, osQWord, regR11));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR11), IntelOperand(otMemory | otRegistr | otValue, osDWord, regR8, 0x08));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, regR8), IntelOperand(otRegistr, cpu_address_size, regR10));

		processor_->AddCommand(cmTest, IntelOperand(otRegistr, osDWord, regR11), IntelOperand(otRegistr, osDWord, regR11));
		jmp_command2 = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command2->set_flags(fl_Z);
		jmp_command2->AddLink(0, ltJmpWithFlag);

		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR10), IntelOperand(otMemory | otRegistr, osDWord, regR11));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osQWord, regR8, 0 - OperandSizeToValue(cpu_address_size) * 2), IntelOperand(otRegistr, osQWord, regR10));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR10), IntelOperand(otMemory | otRegistr | otValue, osDWord, regR11, 4));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osQWord, regR8, 0 - OperandSizeToValue(cpu_address_size)), IntelOperand(otRegistr, osQWord, regR10));
		processor_->AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, regR10), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size, regR8, 0 - OperandSizeToValue(cpu_address_size) * 2));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osQWord, regR8, 0x10), IntelOperand(otRegistr, osQWord, regR10));

		command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
		jmp_command->link()->set_to_command(command);
		jmp_command2->link()->set_to_command(command);
		command->AddLink(0, ltJmp);
		jmp_end_convert.push_back(command);

		// NtQueryVirtualMemory
		command = processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osByte, regR10), IntelOperand(otValue, osByte, 0, 8));
		cmp_command->link()->set_to_command(command);
		cmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		cmp_command->set_flags(fl_Z);
		cmp_command->include_option(roInverseFlag);
		cmp_command->AddLink(0, ltJmpWithFlag);

		processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otValue, osDWord, 0, (uint32_t)-1)); // NtCurrentProcess
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->include_option(roInverseFlag);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmMovsxd, IntelOperand(otRegistr, osQWord, regECX), IntelOperand(otRegistr, osDWord, regECX));

		command = processor_->AddCommand(cmTest, IntelOperand(otRegistr, osDWord, regR9), IntelOperand(otRegistr, osDWord, regR9));
		jmp_command->link()->set_to_command(command);
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, regR10), IntelOperand(otMemory | otBaseRegistr | otValue, cpu_address_size, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 8));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, regR9), IntelOperand(otRegistr, cpu_address_size, regR10));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osDWord, regESP), IntelOperand(otValue, osDWord, 0, 0x30));
		command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
		jmp_command->link()->set_to_command(command);
		command->AddLink(0, ltJmp);
		jmp_end_convert.push_back(command);

		command = processor_->AddCommand(cmAnd, IntelOperand(otRegistr, osDWord, regEAX), IntelOperand(otValue, osDWord, 0, WOW64_FLAG - 1));
		cmp_command->link()->set_to_command(command);
		for (i = 0; i < jmp_end_convert.size(); i++) {
			jmp_end_convert[i]->link()->set_to_command(command);
		}
	}

	if (calling_convention == ccMSx64 || calling_convention == ccStdcallToMSx64)
		processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, regESP), IntelOperand(otValue, cpu_address_size, 0, 0x20));
	if (call_entry) {
		command = processor_->AddCommand(cmCall, IntelOperand(otValue, cpu_address_size));
		command->AddLink(0, ltCall, call_entry);
	}
	else
		processor_->AddCommand(cmCall, IntelOperand(otRegistr, cpu_address_size, regEAX));

	if (calling_convention == ccStdcallToMSx64) {
		// convert output args
		std::vector<IntelCommand*> jmp_end_convert;
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR10), IntelOperand(otMemory | otBaseRegistr | otValue, osDWord, regEBP << 4, 0));
		processor_->AddCommand(cmShr, IntelOperand(otRegistr, osDWord, regR10), IntelOperand(otValue, osByte, 0, 24));
		IntelCommand* jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->AddLink(0, ltJmpWithFlag);
		jmp_end_convert.push_back(jmp_command);

		// NtProtectVirtualMemory
		processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osByte, regR10), IntelOperand(otValue, osByte, 0, 1));
		IntelCommand* cmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		cmp_command->set_flags(fl_Z);
		cmp_command->include_option(roInverseFlag);
		cmp_command->AddLink(0, ltJmpWithFlag);

		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otMemory | otBaseRegistr | otValue, arg_address_size, regEBP << 4, OperandSizeToValue(arg_address_size) * 2));
		processor_->AddCommand(cmTest, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otRegistr, osDWord, regECX));
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR10), IntelOperand(otMemory | otBaseRegistr | otValue, osDWord, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 3));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, osDWord, regECX), IntelOperand(otRegistr, osDWord, regR10));

		command = processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otMemory | otBaseRegistr | otValue, arg_address_size, regEBP << 4, OperandSizeToValue(arg_address_size) * 3));
		jmp_command->link()->set_to_command(command);
		processor_->AddCommand(cmTest, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otRegistr, osDWord, regECX));
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->AddLink(0, ltJmpWithFlag);

		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR10), IntelOperand(otMemory | otBaseRegistr | otValue, osDWord, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 4));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, osDWord, regECX), IntelOperand(otRegistr, osDWord, regR10));
		command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
		jmp_command->link()->set_to_command(command);
		command->AddLink(0, ltJmp);
		jmp_end_convert.push_back(command);

		// NtQueryInformationProcess
		command = processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osByte, regR10), IntelOperand(otValue, osByte, 0, 3));
		cmp_command->link()->set_to_command(command);
		cmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		cmp_command->set_flags(fl_Z);
		cmp_command->include_option(roInverseFlag);
		cmp_command->AddLink(0, ltJmpWithFlag);

		command = processor_->AddCommand(cmCmp, IntelOperand(otMemory | otBaseRegistr | otValue, arg_address_size, regEBP << 4, OperandSizeToValue(arg_address_size) * 2), IntelOperand(otValue, osDWord, 0, 0x7));  // ProcessDebugPort
		jmp_command->link()->set_to_command(command);
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->include_option(roInverseFlag);
		jmp_command->AddLink(0, ltJmpWithFlag);

		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otMemory | otBaseRegistr | otValue, arg_address_size, regEBP << 4, OperandSizeToValue(arg_address_size) * 3));
		processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otMemory | otBaseRegistr | otValue, arg_address_size, regEBP << 4, OperandSizeToValue(arg_address_size) * 5));
		IntelCommand* jmp_command2 = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command2->set_flags(fl_Z);
		jmp_command2->AddLink(0, ltJmpWithFlag);

		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR10), IntelOperand(otMemory | otBaseRegistr | otValue, osDWord, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 3));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, osDWord, regECX), IntelOperand(otRegistr, osDWord, regR10));
		command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
		jmp_command2->link()->set_to_command(command);
		command->AddLink(0, ltJmp);
		jmp_end_convert.push_back(command);

		command = processor_->AddCommand(cmCmp, IntelOperand(otMemory | otBaseRegistr | otValue, arg_address_size, regEBP << 4, OperandSizeToValue(arg_address_size) * 2), IntelOperand(otValue, osDWord, 0, 0x1e));  // ProcessDebugObjectHandle
		jmp_command->link()->set_to_command(command);
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->include_option(roInverseFlag);
		jmp_command->AddLink(0, ltJmpWithFlag);

		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otMemory | otBaseRegistr | otValue, arg_address_size, regEBP << 4, OperandSizeToValue(arg_address_size) * 3));
		processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otMemory | otBaseRegistr | otValue, arg_address_size, regEBP << 4, OperandSizeToValue(arg_address_size) * 5));
		jmp_command2 = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command2->set_flags(fl_Z);
		jmp_command2->AddLink(0, ltJmpWithFlag);

		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR10), IntelOperand(otMemory | otBaseRegistr | otValue, osDWord, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 3));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, osDWord, regECX), IntelOperand(otRegistr, osDWord, regR10));
		command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
		jmp_command->link()->set_to_command(command);
		jmp_command2->link()->set_to_command(command);
		command->AddLink(0, ltJmp);
		jmp_end_convert.push_back(command);

		// NtMapViewOfSection
		command = processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osByte, regR10), IntelOperand(otValue, osByte, 0, 4));
		cmp_command->link()->set_to_command(command);
		cmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		cmp_command->set_flags(fl_Z);
		cmp_command->include_option(roInverseFlag);
		cmp_command->AddLink(0, ltJmpWithFlag);

		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otMemory | otBaseRegistr | otValue, arg_address_size, regEBP << 4, OperandSizeToValue(arg_address_size) * 3));
		processor_->AddCommand(cmTest, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otRegistr, osDWord, regECX));
		jmp_command->link()->set_to_command(command);
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR10), IntelOperand(otMemory | otBaseRegistr | otValue, osDWord, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 3));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, osDWord, regECX), IntelOperand(otRegistr, osDWord, regR10));

		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otMemory | otBaseRegistr | otValue, arg_address_size, regEBP << 4, OperandSizeToValue(arg_address_size) * 7));
		jmp_command->link()->set_to_command(command);
		processor_->AddCommand(cmTest, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otRegistr, osDWord, regECX));
		jmp_command->link()->set_to_command(command);
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->AddLink(0, ltJmpWithFlag);

		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR10), IntelOperand(otMemory | otBaseRegistr | otValue, osDWord, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 4));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, osDWord, regECX), IntelOperand(otRegistr, osDWord, regR10));
		command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
		jmp_command->link()->set_to_command(command);
		command->AddLink(0, ltJmp);
		jmp_end_convert.push_back(command);

		// NtOpenFile
		command = processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osByte, regR10), IntelOperand(otValue, osByte, 0, 6));
		cmp_command->link()->set_to_command(command);
		cmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		cmp_command->set_flags(fl_Z);
		cmp_command->include_option(roInverseFlag);
		cmp_command->AddLink(0, ltJmpWithFlag);

		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otMemory | otBaseRegistr | otValue, arg_address_size, regEBP << 4, OperandSizeToValue(arg_address_size)));
		processor_->AddCommand(cmTest, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otRegistr, osDWord, regECX));
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR10), IntelOperand(otMemory | otBaseRegistr | otValue, osDWord, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 3));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, osDWord, regECX), IntelOperand(otRegistr, osDWord, regR10));
		command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
		jmp_command->link()->set_to_command(command);
		command->AddLink(0, ltJmp);
		jmp_end_convert.push_back(command);

		// NtCreateSection
		command = processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osByte, regR10), IntelOperand(otValue, osByte, 0, 7));
		cmp_command->link()->set_to_command(command);
		cmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		cmp_command->set_flags(fl_Z);
		cmp_command->include_option(roInverseFlag);
		cmp_command->AddLink(0, ltJmpWithFlag);

		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otMemory | otBaseRegistr | otValue, arg_address_size, regEBP << 4, OperandSizeToValue(arg_address_size)));
		processor_->AddCommand(cmTest, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otRegistr, osDWord, regECX));
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR10), IntelOperand(otMemory | otBaseRegistr | otValue, osDWord, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 3));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, osDWord, regECX), IntelOperand(otRegistr, osDWord, regR10));
		command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
		jmp_command->link()->set_to_command(command);
		command->AddLink(0, ltJmp);
		jmp_end_convert.push_back(command);

		// NtQueryVirtualMemory
		command = processor_->AddCommand(cmCmp, IntelOperand(otRegistr, osByte, regR10), IntelOperand(otValue, osByte, 0, 8));
		cmp_command->link()->set_to_command(command);
		cmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		cmp_command->set_flags(fl_Z);
		cmp_command->include_option(roInverseFlag);
		cmp_command->AddLink(0, ltJmpWithFlag);

		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otMemory | otBaseRegistr | otValue, arg_address_size, regEBP << 4, OperandSizeToValue(arg_address_size) * 4));
		processor_->AddCommand(cmTest, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otRegistr, osDWord, regECX));
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_Z);
		jmp_command->AddLink(0, ltJmpWithFlag);
		processor_->AddCommand(cmLea, IntelOperand(otRegistr, osDWord, regR10), IntelOperand(otMemory | otBaseRegistr | otValue, osDWord, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 8));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR11), IntelOperand(otMemory | otRegistr, osDWord, regR10));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, osDWord, regECX), IntelOperand(otRegistr, osDWord, regR11));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR11), IntelOperand(otMemory | otRegistr | otValue, osDWord, regR10, OperandSizeToValue(cpu_address_size)));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osDWord, regECX, OperandSizeToValue(arg_address_size)), IntelOperand(otRegistr, osDWord, regR11));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR11), IntelOperand(otMemory | otRegistr | otValue, osDWord, regR10, OperandSizeToValue(cpu_address_size) * 2));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osDWord, regECX, OperandSizeToValue(arg_address_size) * 2), IntelOperand(otRegistr, osDWord, regR11));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR11), IntelOperand(otMemory | otRegistr | otValue, osDWord, regR10, OperandSizeToValue(cpu_address_size) * 3));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osDWord, regECX, OperandSizeToValue(arg_address_size) * 3), IntelOperand(otRegistr, osDWord, regR11));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osQWord, regR11), IntelOperand(otMemory | otRegistr | otValue, osQWord, regR10, OperandSizeToValue(cpu_address_size) * 4));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osQWord, regECX, OperandSizeToValue(arg_address_size) * 4), IntelOperand(otRegistr, osQWord, regR11));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regR11), IntelOperand(otMemory | otRegistr | otValue, osDWord, regR10, OperandSizeToValue(cpu_address_size) * 5));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osDWord, regECX, OperandSizeToValue(arg_address_size) * 6), IntelOperand(otRegistr, osDWord, regR11));

		command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
		jmp_command->link()->set_to_command(command);
		command->AddLink(0, ltJmp);
		jmp_end_convert.push_back(command);

		command = processor_->AddCommand(cmNop);
		cmp_command->link()->set_to_command(command);
		for (i = 0; i < jmp_end_convert.size(); i++) {
			jmp_end_convert[i]->link()->set_to_command(command);
		}
	}

	// correct stack
	if (calling_convention != ccStdcall)
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, regESP), IntelOperand(otMemory | otBaseRegistr | otValue, cpu_address_size, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 2));
	else if (call_entry)
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, regESP), IntelOperand(otMemory | otBaseRegistr | otValue, cpu_address_size, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size) * 2));
	if (calling_convention != ccCdecl)
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, regEBP), IntelOperand(otMemory | otBaseRegistr | otValue, cpu_address_size, regEBP << 4, 0 - OperandSizeToValue(cpu_address_size)));

	// save result
	processor_->AddCommand(cmMov, IntelOperand(otMemory | otBaseRegistr | otValue, arg_address_size, regEBP << 4, 0), IntelOperand(otRegistr, arg_address_size, regEAX));

	// pop common registers
	if (stack_registr_ != regEBP)
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otRegistr, cpu_address_size, regEBP));
	if (crypt_registr_)
		processor_->AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size, crypt_registr_));
	if (jmp_registr_)
		processor_->AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size, jmp_registr_));
	processor_->AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size, pcode_registr_));
}

bool IntelVirtualMachine::IsRegistrUsed(uint8_t registr)
{
	return (registr == stack_registr_ || registr == pcode_registr_ || (jmp_registr_ && registr == jmp_registr_) || (crypt_registr_ && registr == crypt_registr_));
}

void IntelVirtualMachine::InitCommands(const CompileContext& ctx, const IntelOpcodeList& visible_opcode_list)
{
	IntelCommand* command, * read_opcode, * check_stack, * opcode_entry, * switch_entry, * jmp_command;
	uint8_t seg, s, reg1, reg2, reg3, reg4;
	OperandSize size, mov_size;
	size_t i, operand_size, result_size, j, c;
	IntelCommandType command_type;
	OpcodeCryptor* value_cryptor, * registr_cryptor, * end_cryptor;
	IntelOpcodeInfo* opcode;
	OperandSize cpu_address_size = processor_->cpu_address_size();
	IntelFunctionList* function_list = reinterpret_cast<IntelFunctionList*>(processor_->owner());

	IntelRegistrList wrong_registr_list;
	switch (ctx.file->calling_convention()) {
	case ccMSx64:
	case ccABIx64:
		wrong_registr_list.push_back(regR12);
		wrong_registr_list.push_back(regR13);
		wrong_registr_list.push_back(regR14);
		wrong_registr_list.push_back(regR15);
		break;
	}

	// init registers

	IntelRegistrList work_registr_list;
	work_registr_list.push_back(regEBX);
	work_registr_list.push_back(regEBP);
	work_registr_list.push_back(regESI);
	work_registr_list.push_back(regEDI);
	if (cpu_address_size == osQWord) {
		for (i = 8; i < 16; i++) {
			work_registr_list.push_back((uint8_t)i);
		}
	}
	work_registr_list.remove(wrong_registr_list);

	crypt_registr_ = 0;
	if (ctx.options.flags & cpEncryptBytecode) {
		if (cpu_address_size == osDWord) {
			crypt_registr_ = regEBX;
			work_registr_list.remove(crypt_registr_);
		}
		else
			crypt_registr_ = work_registr_list.GetRandom();
	}
	pcode_registr_ = work_registr_list.GetRandom();
	stack_registr_ = work_registr_list.GetRandom();
	jmp_registr_ = (type_ == vtAdvanced || cpu_address_size == osQWord) ? work_registr_list.GetRandom() : 0;


	free_registr_list_.push_back(regEAX);
	free_registr_list_.push_back(regECX);
	free_registr_list_.push_back(regEDX);
	free_registr_list_.push_back(regEBX);
	free_registr_list_.push_back(regEBP);
	free_registr_list_.push_back(regESI);
	free_registr_list_.push_back(regEDI);
	if (cpu_address_size == osQWord) {
		for (i = 8; i < 16; i++) {
			free_registr_list_.push_back((uint8_t)i);
		}
	}
	free_registr_list_.remove(wrong_registr_list);
	free_registr_list_.remove(pcode_registr_);
	free_registr_list_.remove(stack_registr_);
	if (jmp_registr_)
		free_registr_list_.remove(jmp_registr_);
	if (crypt_registr_)
		free_registr_list_.remove(crypt_registr_);

	// init cryptors
	entry_cryptor_.Init(osDWord);
	if (ctx.options.flags & cpEncryptBytecode) {
		command_cryptor_ = new OpcodeCryptor();
		command_cryptor_->Init((type_ == vtAdvanced) ? osDWord : osByte);
	}
	value_cryptor = NULL;
	registr_cryptor = NULL;
	end_cryptor = NULL;

	// init registr list
	registr_order_.clear();
	registr_order_.push_back(regEFX);
	registr_order_.push_back(regEAX);
	registr_order_.push_back(regECX);
	registr_order_.push_back(regEDX);
	registr_order_.push_back(regEBX);
	registr_order_.push_back(regEBP);
	registr_order_.push_back(regESI);
	registr_order_.push_back(regEDI);
	if (cpu_address_size == osQWord) {
		for (i = 8; i < 16; i++) {
			registr_order_.push_back((uint8_t)i);
		}
	}
	for (i = 0; i < registr_order_.size(); i++) {
		std::swap(registr_order_[i], registr_order_[rand() % registr_order_.size()]);
	}

	// create commands
	c = processor_->count();
	for (i = 0; i < registr_order_.size(); i++) {
		uint8_t reg = registr_order_[i];
		if (reg == regEFX) {
			processor_->AddCommand(cmPushf);
		}
		else {
			processor_->AddCommand(cmPush, IntelOperand(otRegistr, cpu_address_size, reg));
		}
	}
	entry_command_ = processor_->item(c);
	entry_command_->include_section_option(rtLinkedToInt);

	size_t context_registr_count = (cpu_address_size == osQWord) ? 24 : 16;
	if (ctx.file->runtime_function_list() && ctx.file->runtime_function_list()->count())
		context_registr_count += 8;
	{
		IntelRegistrList registr_list = free_registr_list_;
		reg1 = registr_list.GetRandom();
	}
	if (ctx.file->cpu_address_size() != cpu_address_size && cpu_address_size == osQWord)
		processor_->AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otMemory | otValue, cpu_address_size, 0, 0, LARGE_VALUE));
	else
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otValue, cpu_address_size, 0, 0, NEED_FIXUP));
	processor_->AddCommand(cmPush, IntelOperand(otRegistr, cpu_address_size, reg1));
	processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, pcode_registr_), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size, regESP, (registr_order_.size() + 2) * OperandSizeToValue(cpu_address_size)));
	for (i = entry_cryptor_.count(); i > 0; i--) {
		AddValueCommand(*entry_cryptor_.item(i - 1), true, pcode_registr_);
	}
	processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, pcode_registr_), IntelOperand(otRegistr, cpu_address_size, reg1));
	if (cpu_address_size == osQWord) {
		if (ctx.file->image_base() >> 32) {
			IntelRegistrList registr_list = free_registr_list_;
			reg1 = registr_list.GetRandom();
			processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otValue, cpu_address_size, 0, ctx.file->image_base() & 0xffffffff00000000ull));
			processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, pcode_registr_), IntelOperand(otRegistr, cpu_address_size, reg1));
		}
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otRegistr, cpu_address_size, regESP));
		processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, regESP), IntelOperand(otValue, cpu_address_size, 0, 128 + context_registr_count * OperandSizeToValue(cpu_address_size)));
		processor_->AddCommand(cmAnd, IntelOperand(otRegistr, cpu_address_size, regESP), IntelOperand(otValue, cpu_address_size, 0, -16));
	}
	else {
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otRegistr, cpu_address_size, regESP));
		processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, regESP), IntelOperand(otValue, cpu_address_size, 0, 128 + context_registr_count * OperandSizeToValue(cpu_address_size)));
	}

	c = processor_->count();
	if (crypt_registr_) {
		IntelRegistrList registr_list = free_registr_list_;
		reg1 = registr_list.GetRandom();
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, crypt_registr_), IntelOperand(otRegistr, cpu_address_size, pcode_registr_));
		if (ctx.file->cpu_address_size() != cpu_address_size && cpu_address_size == osQWord)
			processor_->AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otMemory | otValue, cpu_address_size, 0, 0, LARGE_VALUE));
		else
			processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otValue, cpu_address_size, 0, 0, NEED_FIXUP));
		processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, crypt_registr_), IntelOperand(otRegistr, cpu_address_size, reg1));
	}
	if (type_ == vtAdvanced) {
		opcode_entry = processor_->AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, jmp_registr_), IntelOperand(otMemory | otValue, cpu_address_size, 0, 0, (cpu_address_size == osDWord) ? NEED_FIXUP : LARGE_VALUE));
		opcode_entry->AddLink(1, ltOffset, opcode_entry);
		AddEndHandlerCommands(NULL, command_cryptor_);
		opcode_list_.Add(cmNop, otNone, cpu_address_size, 0, opcode_entry, NULL, command_cryptor_);
	}
	else if (cpu_address_size == osQWord) {
		command = processor_->AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, jmp_registr_), IntelOperand(otMemory | otValue, cpu_address_size, 0, 0, LARGE_VALUE));
		command->AddLink(1, ltOffset);
		switch_entry = command;
	}
	else if (c == processor_->count())
		processor_->AddCommand(cmNop);
	init_command_ = processor_->item(c);

	read_opcode = NULL;
	if (type_ == vtAdvanced) {
		command = processor_->AddCommand(cmJmp, IntelOperand(otRegistr, cpu_address_size, jmp_registr_));
		command->AddLink(-1, ltJmp);
	}
	else {
		IntelRegistrList registr_list = free_registr_list_;
		reg1 = registr_list.GetRandom(cpu_address_size == osDWord);
		read_opcode = AddReadCommand(osByte, command_cryptor_, reg1);
		if (cpu_address_size == osQWord) {
			command = processor_->AddCommand(cmJmp, IntelOperand(otMemory | otBaseRegistr | otRegistr, cpu_address_size, (jmp_registr_ << 4) | reg1, 0));
			command->set_operand_scale(0, 3);
			command->AddLink(-1, ltJmp);
		}
		else {
			command = processor_->AddCommand(cmJmp, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size, reg1, 0, NEED_FIXUP));
			command->set_operand_scale(0, 2);
			command->AddLink(0, ltSwitch);
			switch_entry = command;
		}
	}

	// check stack
	{
		IntelRegistrList registr_list = free_registr_list_;
		reg1 = registr_list.GetRandom();
		check_stack = processor_->AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size, regESP, (context_registr_count + 8) * OperandSizeToValue(cpu_address_size)));
		processor_->AddCommand(cmCmp, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otRegistr, cpu_address_size, reg1));
		jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
		jmp_command->set_flags(fl_C | fl_Z);
		jmp_command->include_option(roInverseFlag);
		jmp_command->AddLink(0, ltJmpWithFlag);

		registr_list = free_registr_list_;
		registr_list.remove(regESI);
		registr_list.remove(regEDI);
		registr_list.remove(regECX);
		reg1 = registr_list.GetRandom();
		reg2 = registr_list.GetRandom();
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, reg2), IntelOperand(otRegistr, cpu_address_size, regESP));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, regECX), IntelOperand(otValue, cpu_address_size, 0, context_registr_count * OperandSizeToValue(cpu_address_size)));
		processor_->AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otMemory | otBaseRegistr | otValue, cpu_address_size, stack_registr_ << 4, -128));
		processor_->AddCommand(cmAnd, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otValue, cpu_address_size, 0, (cpu_address_size == osQWord) ? -16 : -4));
		processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otRegistr, cpu_address_size, regECX));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, regESP), IntelOperand(otRegistr, cpu_address_size, reg1));
		if (IsRegistrUsed(regEDI))
			processor_->AddCommand(cmPush, IntelOperand(otRegistr, cpu_address_size, regEDI));
		if (IsRegistrUsed(regESI))
			processor_->AddCommand(cmPush, IntelOperand(otRegistr, cpu_address_size, regESI));
		processor_->AddCommand(cmPushf);
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, regESI), IntelOperand(otRegistr, cpu_address_size, reg2));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, regEDI), IntelOperand(otRegistr, cpu_address_size, reg1));
		processor_->AddCommand(cmCld);
		command = processor_->AddCommand(cmMovs, IntelOperand(otRegistr, osByte));
		command->set_preffix_command(cmRep);
		processor_->AddCommand(cmPopf);
		if (IsRegistrUsed(regESI))
			processor_->AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size, regESI));
		if (IsRegistrUsed(regEDI))
			processor_->AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size, regEDI));
		if (type_ == vtAdvanced) {
			command = processor_->AddCommand(cmJmp, IntelOperand(otRegistr, cpu_address_size, jmp_registr_));
			command->AddLink(-1, ltJmp);
			jmp_command->link()->set_to_command(command);
		}
		else {
			command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
			command->AddLink(0, ltJmp, read_opcode);
			jmp_command->link()->set_to_command(read_opcode);
		}
	}

	// push registr
	for (s = osByte; s <= cpu_address_size; s++) {
		size = static_cast<OperandSize>(s);
		IntelRegistrList registr_list = free_registr_list_;
		reg1 = registr_list.GetRandom(cpu_address_size == osDWord);
		reg2 = registr_list.GetRandom();
		mov_size = (size == osByte) ? osWord : size;
		if (ctx.options.flags & cpEncryptBytecode) {
			registr_cryptor = new OpcodeCryptor();
			cryptor_list_.push_back(registr_cryptor);
			registr_cryptor->Init(osByte);
			if (type_ == vtAdvanced) {
				end_cryptor = new OpcodeCryptor();
				cryptor_list_.push_back(end_cryptor);
				end_cryptor->Init(osDWord);
			}
		}
		opcode_entry = AddReadCommand(osByte, registr_cryptor, reg1);
		processor_->AddCommand((mov_size == size) ? cmMov : cmMovzx, IntelOperand(otRegistr, mov_size, reg2), IntelOperand(otMemory | otBaseRegistr | otRegistr, size, (regESP << 4) | reg1));
		operand_size = 0;
		result_size = OperandSizeToValue(mov_size);
		if (result_size > operand_size)
			processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
		else if (result_size < operand_size) //-V547
			processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, mov_size, stack_registr_), IntelOperand(otRegistr, mov_size, reg2));
		AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor);
		opcode_list_.Add(cmPush, otRegistr, size, 0, opcode_entry, registr_cryptor, end_cryptor);
	}

	// pop registr
	for (s = osByte; s <= cpu_address_size; s++) {
		size = static_cast<OperandSize>(s);
		IntelRegistrList registr_list = free_registr_list_;
		reg1 = registr_list.GetRandom(size == osByte && cpu_address_size == osDWord);
		reg2 = registr_list.GetRandom(cpu_address_size == osDWord);
		mov_size = (size == osByte) ? osWord : size;
		if (ctx.options.flags & cpEncryptBytecode) {
			registr_cryptor = new OpcodeCryptor();
			cryptor_list_.push_back(registr_cryptor);
			registr_cryptor->Init(osByte);
			if (type_ == vtAdvanced) {
				end_cryptor = new OpcodeCryptor();
				cryptor_list_.push_back(end_cryptor);
				end_cryptor->Init(osDWord);
			}
		}
		opcode_entry = processor_->AddCommand(cmMov, IntelOperand(otRegistr, mov_size, reg1), IntelOperand(otMemory | otRegistr, mov_size, stack_registr_));
		operand_size = OperandSizeToValue(mov_size);
		result_size = 0;
		if (result_size > operand_size) //-V547
			processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
		else if (result_size < operand_size)
			processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
		AddReadCommand(osByte, registr_cryptor, reg2);
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otBaseRegistr | otRegistr, size, (regESP << 4) | reg2), IntelOperand(otRegistr, size, reg1));
		AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor); //-V547
		opcode_list_.Add(cmPop, otRegistr, size, 0, opcode_entry, registr_cryptor, end_cryptor);
	}

	// push value
	for (s = osByte; s <= cpu_address_size; s++) {
		size = static_cast<OperandSize>(s);
		IntelRegistrList registr_list = free_registr_list_;
		reg1 = registr_list.GetRandom(size == osByte && cpu_address_size == osDWord);
		if (ctx.options.flags & cpEncryptBytecode) {
			value_cryptor = new OpcodeCryptor();
			cryptor_list_.push_back(value_cryptor);
			value_cryptor->Init(size);
			if (type_ == vtAdvanced) {
				end_cryptor = new OpcodeCryptor();
				cryptor_list_.push_back(end_cryptor);
				end_cryptor->Init(osDWord);
			}
		}
		opcode_entry = AddReadCommand(size, value_cryptor, reg1);
		mov_size = (size == osByte) ? osWord : size;
		operand_size = 0;
		result_size = OperandSizeToValue(mov_size);
		if (result_size > operand_size)
			processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
		else if (result_size < operand_size) //-V547
			processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, mov_size, stack_registr_), IntelOperand(otRegistr, mov_size, reg1));
		AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor);
		opcode_list_.Add(cmPush, otValue, size, 0, opcode_entry, value_cryptor, end_cryptor);
	}

	// push [address]
	for (s = osByte; s <= cpu_address_size; s++) {
		size = static_cast<OperandSize>(s);
		mov_size = (size == osByte) ? osWord : size;
		for (seg = segES; seg <= segGS; seg++) {
			if (seg != segDS && seg != segSS && !visible_opcode_list.GetOpcodeInfo(cmPush, otMemory, size, seg))
				continue;

			IntelRegistrList registr_list = free_registr_list_;
			reg1 = registr_list.GetRandom();
			reg2 = registr_list.GetRandom();
			if (ctx.options.flags & cpEncryptBytecode) {
				if (type_ == vtAdvanced) {
					end_cryptor = new OpcodeCryptor();
					cryptor_list_.push_back(end_cryptor);
					end_cryptor->Init(osDWord);
				}
			}
			opcode_entry = processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otMemory | otRegistr, cpu_address_size, stack_registr_));
			command = processor_->AddCommand((mov_size == size) ? cmMov : cmMovzx, IntelOperand(otRegistr, mov_size, reg2), IntelOperand(otMemory | otRegistr, size, reg1));
			if (seg != segDS)
				command->set_base_segment(static_cast<IntelSegment>(seg));
			operand_size = OperandSizeToValue(cpu_address_size);
			result_size = OperandSizeToValue(mov_size);
			if (result_size > operand_size)
				processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
			else if (result_size < operand_size)
				processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
			processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, mov_size, stack_registr_), IntelOperand(otRegistr, mov_size, reg2));
			AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor);
			opcode_list_.Add(cmPush, otMemory, size, seg, opcode_entry, NULL, end_cryptor);
		}
	}

	// pop [address]
	for (s = osByte; s <= cpu_address_size; s++) {
		size = static_cast<OperandSize>(s);
		mov_size = (size == osByte) ? osWord : size;
		for (seg = segES; seg <= segGS; seg++) {
			if (seg != segDS && seg != segSS && !visible_opcode_list.GetOpcodeInfo(cmPop, otMemory, size, seg))
				continue;

			IntelRegistrList registr_list = free_registr_list_;
			reg1 = registr_list.GetRandom();
			reg2 = registr_list.GetRandom(size == osByte && cpu_address_size == osDWord);
			if (ctx.options.flags & cpEncryptBytecode) {
				if (type_ == vtAdvanced) {
					end_cryptor = new OpcodeCryptor();
					cryptor_list_.push_back(end_cryptor);
					end_cryptor->Init(osDWord);
				}
			}
			opcode_entry = processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otMemory | otRegistr, cpu_address_size, stack_registr_));
			processor_->AddCommand(cmMov, IntelOperand(otRegistr, size, reg2), IntelOperand(otMemory | otRegistr | otValue, size, stack_registr_, OperandSizeToValue(cpu_address_size)));
			operand_size = OperandSizeToValue(cpu_address_size) + OperandSizeToValue(mov_size);
			result_size = 0;
			if (result_size > operand_size) //-V547
				processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
			else if (result_size < operand_size)
				processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
			command = processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, size, reg1), IntelOperand(otRegistr, size, reg2));
			if (seg != segDS)
				command->set_base_segment(static_cast<IntelSegment>(seg));
			AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor); //-V547
			opcode_list_.Add(cmPop, otMemory, size, seg, opcode_entry, NULL, end_cryptor);
		}
	}

	// push segment registr
	for (seg = segES; seg <= segGS; seg++) {
		if (!visible_opcode_list.GetOpcodeInfo(cmPush, otSegmentRegistr, osWord, seg))
			continue;

		IntelRegistrList registr_list = free_registr_list_;
		reg1 = registr_list.GetRandom();
		if (ctx.options.flags & cpEncryptBytecode) {
			if (type_ == vtAdvanced) {
				end_cryptor = new OpcodeCryptor();
				cryptor_list_.push_back(end_cryptor);
				end_cryptor->Init(osDWord);
			}
		}
		opcode_entry = processor_->AddCommand(cmMov, IntelOperand(otRegistr, osWord, reg1), IntelOperand(otSegmentRegistr, osWord, seg));
		operand_size = 0;
		result_size = OperandSizeToValue(osWord);
		if (result_size > operand_size)
			processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
		else if (result_size < operand_size) //-V547
			processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, osWord, stack_registr_), IntelOperand(otRegistr, osWord, reg1));
		AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor);
		opcode_list_.Add(cmPush, otSegmentRegistr, osWord, seg, opcode_entry, NULL, end_cryptor);
	}

	// pop segment registr
	for (seg = segES; seg <= segGS; seg++) {
		if (seg == segCS || !visible_opcode_list.GetOpcodeInfo(cmPop, otSegmentRegistr, osWord, seg))
			continue;

		IntelRegistrList registr_list = free_registr_list_;
		reg1 = registr_list.GetRandom();
		if (ctx.options.flags & cpEncryptBytecode) {
			if (type_ == vtAdvanced) {
				end_cryptor = new OpcodeCryptor();
				cryptor_list_.push_back(end_cryptor);
				end_cryptor->Init(osDWord);
			}
		}
		opcode_entry = processor_->AddCommand(cmMov, IntelOperand(otRegistr, osWord, reg1), IntelOperand(otMemory | otRegistr, osWord, stack_registr_));
		operand_size = OperandSizeToValue(osWord);
		result_size = 0;
		if (result_size > operand_size) //-V547
			processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
		else if (result_size < operand_size)
			processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
		processor_->AddCommand(cmMov, IntelOperand(otSegmentRegistr, osWord, seg), IntelOperand(otRegistr, osWord, reg1));
		AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor); //-V547
		opcode_list_.Add(cmPop, otSegmentRegistr, osWord, seg, opcode_entry, NULL, end_cryptor);
	}

	size_t debug_reg_count = 8;

	// push debug registr
	for (i = 0; i < debug_reg_count; i++) {
		if (!visible_opcode_list.GetOpcodeInfo(cmPush, otDebugRegistr, cpu_address_size, (uint8_t)i))
			continue;

		IntelRegistrList registr_list = free_registr_list_;
		reg1 = registr_list.GetRandom();
		if (ctx.options.flags & cpEncryptBytecode) {
			if (type_ == vtAdvanced) {
				end_cryptor = new OpcodeCryptor();
				cryptor_list_.push_back(end_cryptor);
				end_cryptor->Init(osDWord);
			}
		}
		opcode_entry = processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otDebugRegistr, cpu_address_size, (uint8_t)i));
		operand_size = 0;
		result_size = OperandSizeToValue(cpu_address_size);
		if (result_size > operand_size)
			processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
		else if (result_size < operand_size) //-V547
			processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, cpu_address_size, stack_registr_), IntelOperand(otRegistr, cpu_address_size, reg1));
		AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor);
		opcode_list_.Add(cmPush, otDebugRegistr, cpu_address_size, (uint8_t)i, opcode_entry, NULL, end_cryptor);
	}

	// pop debug registr
	for (i = 0; i < debug_reg_count; i++) {
		if (!visible_opcode_list.GetOpcodeInfo(cmPop, otDebugRegistr, cpu_address_size, (uint8_t)i))
			continue;

		IntelRegistrList registr_list = free_registr_list_;
		reg1 = registr_list.GetRandom();
		if (ctx.options.flags & cpEncryptBytecode) {
			if (type_ == vtAdvanced) {
				end_cryptor = new OpcodeCryptor();
				cryptor_list_.push_back(end_cryptor);
				end_cryptor->Init(osDWord);
			}
		}
		opcode_entry = processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otMemory | otRegistr, cpu_address_size, stack_registr_));
		operand_size = OperandSizeToValue(cpu_address_size);
		result_size = 0;
		if (result_size > operand_size) //-V547
			processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
		else if (result_size < operand_size)
			processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
		command = processor_->AddCommand(cmMov, IntelOperand(otDebugRegistr, cpu_address_size, (uint8_t)i), IntelOperand(otRegistr, cpu_address_size, reg1));
		AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor); //-V547
		opcode_list_.Add(cmPop, otDebugRegistr, cpu_address_size, (uint8_t)i, opcode_entry, NULL, end_cryptor);
	}

	size_t control_reg_count = cpu_address_size == osDWord ? 8 : 9;

	// push control registr
	for (i = 0; i < control_reg_count; i++) {
		if (!visible_opcode_list.GetOpcodeInfo(cmPush, otControlRegistr, cpu_address_size, (uint8_t)i))
			continue;

		IntelRegistrList registr_list = free_registr_list_;
		reg1 = registr_list.GetRandom();
		if (ctx.options.flags & cpEncryptBytecode) {
			if (type_ == vtAdvanced) {
				end_cryptor = new OpcodeCryptor();
				cryptor_list_.push_back(end_cryptor);
				end_cryptor->Init(osDWord);
			}
		}
		opcode_entry = processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otControlRegistr, cpu_address_size, (uint8_t)i));
		operand_size = 0;
		result_size = OperandSizeToValue(cpu_address_size);
		if (result_size > operand_size)
			processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
		else if (result_size < operand_size) //-V547
			processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, cpu_address_size, stack_registr_), IntelOperand(otRegistr, cpu_address_size, reg1));
		AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor);
		opcode_list_.Add(cmPush, otControlRegistr, cpu_address_size, (uint8_t)i, opcode_entry, NULL, end_cryptor);
	}

	// pop control registr
	for (i = 0; i < control_reg_count; i++) {
		if (!visible_opcode_list.GetOpcodeInfo(cmPop, otControlRegistr, cpu_address_size, (uint8_t)i))
			continue;

		IntelRegistrList registr_list = free_registr_list_;
		reg1 = registr_list.GetRandom();
		if (ctx.options.flags & cpEncryptBytecode) {
			if (type_ == vtAdvanced) {
				end_cryptor = new OpcodeCryptor();
				cryptor_list_.push_back(end_cryptor);
				end_cryptor->Init(osDWord);
			}
		}
		opcode_entry = processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otMemory | otRegistr, cpu_address_size, stack_registr_));
		operand_size = OperandSizeToValue(cpu_address_size);
		result_size = 0;
		if (result_size > operand_size) //-V547
			processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
		else if (result_size < operand_size)
			processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
		command = processor_->AddCommand(cmMov, IntelOperand(otControlRegistr, cpu_address_size, (uint8_t)i), IntelOperand(otRegistr, cpu_address_size, reg1));
		AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor); //-V547
		opcode_list_.Add(cmPop, otControlRegistr, cpu_address_size, (uint8_t)i, opcode_entry, NULL, end_cryptor);
	}

	// push ESP
	for (s = osWord; s <= cpu_address_size; s++) {
		size = static_cast<OperandSize>(s);
		IntelRegistrList registr_list = free_registr_list_;
		reg1 = registr_list.GetRandom();
		if (ctx.options.flags & cpEncryptBytecode) {
			if (type_ == vtAdvanced) {
				end_cryptor = new OpcodeCryptor();
				cryptor_list_.push_back(end_cryptor);
				end_cryptor->Init(osDWord);
			}
		}
		opcode_entry = processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otRegistr, cpu_address_size, stack_registr_));
		operand_size = 0;
		result_size = OperandSizeToValue(size);
		if (result_size > operand_size)
			processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
		else if (result_size < operand_size) //-V547
			processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, size, stack_registr_), IntelOperand(otRegistr, size, reg1));
		AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor);
		opcode_list_.Add(cmPush, otRegistr, size, 0xFF, opcode_entry, NULL, end_cryptor);
	}

	// pop ESP
	for (s = osWord; s <= cpu_address_size; s++) {
		if (ctx.options.flags & cpEncryptBytecode) {
			if (type_ == vtAdvanced) {
				end_cryptor = new OpcodeCryptor();
				cryptor_list_.push_back(end_cryptor);
				end_cryptor->Init(osDWord);
			}
		}
		size = static_cast<OperandSize>(s);
		opcode_entry = processor_->AddCommand(cmMov, IntelOperand(otRegistr, size, stack_registr_), IntelOperand(otMemory | otRegistr, size, stack_registr_));
		AddEndHandlerCommands(check_stack, end_cryptor);
		opcode_list_.Add(cmPop, otRegistr, size, 0xFF, opcode_entry, NULL, end_cryptor);
	}

	// add
	for (s = osByte; s <= cpu_address_size; s++) {
		size = static_cast<OperandSize>(s);
		IntelRegistrList registr_list = free_registr_list_;
		reg1 = registr_list.GetRandom(size == osByte && cpu_address_size == osDWord);
		reg2 = registr_list.GetRandom(size == osByte && cpu_address_size == osDWord);
		if (ctx.options.flags & cpEncryptBytecode) {
			if (type_ == vtAdvanced) {
				end_cryptor = new OpcodeCryptor();
				cryptor_list_.push_back(end_cryptor);
				end_cryptor->Init(osDWord);
			}
		}
		mov_size = (size == osByte) ? osWord : size;
		opcode_entry = processor_->AddCommand((mov_size == size) ? cmMov : cmMovzx, IntelOperand(otRegistr, mov_size, reg1), IntelOperand(otMemory | otRegistr, size, stack_registr_));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, size, reg2), IntelOperand(otMemory | otRegistr | otValue, size, stack_registr_, OperandSizeToValue(mov_size)));
		operand_size = OperandSizeToValue(mov_size);
		result_size = OperandSizeToValue(cpu_address_size);
		if (result_size > operand_size)
			processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
		else if (result_size < operand_size)
			processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
		processor_->AddCommand(cmAdd, IntelOperand(otRegistr, size, reg1), IntelOperand(otRegistr, size, reg2));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, mov_size, stack_registr_, OperandSizeToValue(cpu_address_size)), IntelOperand(otRegistr, mov_size, reg1));
		processor_->AddCommand(cmPushf, IntelOperand(otNone, cpu_address_size));
		processor_->AddCommand(cmPop, IntelOperand(otMemory | otRegistr, cpu_address_size, stack_registr_));
		AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor);
		opcode_list_.Add(cmAdd, otNone, size, true, opcode_entry, NULL, end_cryptor);
	}

	// nor
	for (s = osByte; s <= cpu_address_size; s++) {
		size = static_cast<OperandSize>(s);
		IntelRegistrList registr_list = free_registr_list_;
		reg1 = registr_list.GetRandom(size == osByte && cpu_address_size == osDWord);
		reg2 = registr_list.GetRandom(size == osByte && cpu_address_size == osDWord);
		if (ctx.options.flags & cpEncryptBytecode) {
			if (type_ == vtAdvanced) {
				end_cryptor = new OpcodeCryptor();
				cryptor_list_.push_back(end_cryptor);
				end_cryptor->Init(osDWord);
			}
		}
		mov_size = (size == osByte) ? osWord : size;
		opcode_entry = processor_->AddCommand((mov_size == size) ? cmMov : cmMovzx, IntelOperand(otRegistr, mov_size, reg1), IntelOperand(otMemory | otRegistr, size, stack_registr_));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, size, reg2), IntelOperand(otMemory | otRegistr | otValue, size, stack_registr_, OperandSizeToValue(mov_size)));
		operand_size = OperandSizeToValue(mov_size);
		result_size = OperandSizeToValue(cpu_address_size);
		if (result_size > operand_size)
			processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
		else if (result_size < operand_size)
			processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
		processor_->AddCommand(cmNot, IntelOperand(otRegistr, size, reg1));
		processor_->AddCommand(cmNot, IntelOperand(otRegistr, size, reg2));
		processor_->AddCommand(cmAnd, IntelOperand(otRegistr, size, reg1), IntelOperand(otRegistr, size, reg2));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, mov_size, stack_registr_, OperandSizeToValue(cpu_address_size)), IntelOperand(otRegistr, mov_size, reg1));
		processor_->AddCommand(cmPushf, IntelOperand(otNone, cpu_address_size));
		processor_->AddCommand(cmPop, IntelOperand(otMemory | otRegistr, cpu_address_size, stack_registr_));
		AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor);
		opcode_list_.Add(cmNor, otNone, size, true, opcode_entry, NULL, end_cryptor);
	}

	// nand
	for (s = osByte; s <= cpu_address_size; s++) {
		size = static_cast<OperandSize>(s);
		IntelRegistrList registr_list = free_registr_list_;
		reg1 = registr_list.GetRandom(size == osByte && cpu_address_size == osDWord);
		reg2 = registr_list.GetRandom(size == osByte && cpu_address_size == osDWord);
		if (ctx.options.flags & cpEncryptBytecode) {
			if (type_ == vtAdvanced) {
				end_cryptor = new OpcodeCryptor();
				cryptor_list_.push_back(end_cryptor);
				end_cryptor->Init(osDWord);
			}
		}
		mov_size = (size == osByte) ? osWord : size;
		opcode_entry = processor_->AddCommand((mov_size == size) ? cmMov : cmMovzx, IntelOperand(otRegistr, mov_size, reg1), IntelOperand(otMemory | otRegistr, size, stack_registr_));
		processor_->AddCommand(cmMov, IntelOperand(otRegistr, size, reg2), IntelOperand(otMemory | otRegistr | otValue, size, stack_registr_, OperandSizeToValue(mov_size)));
		operand_size = OperandSizeToValue(mov_size);
		result_size = OperandSizeToValue(cpu_address_size);
		if (result_size > operand_size)
			processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
		else if (result_size < operand_size)
			processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
		processor_->AddCommand(cmNot, IntelOperand(otRegistr, size, reg1));
		processor_->AddCommand(cmNot, IntelOperand(otRegistr, size, reg2));
		processor_->AddCommand(cmOr, IntelOperand(otRegistr, size, reg1), IntelOperand(otRegistr, size, reg2));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, mov_size, stack_registr_, OperandSizeToValue(cpu_address_size)), IntelOperand(otRegistr, mov_size, reg1));
		processor_->AddCommand(cmPushf, IntelOperand(otNone, cpu_address_size));
		processor_->AddCommand(cmPop, IntelOperand(otMemory | otRegistr, cpu_address_size, stack_registr_));
		AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor);
		opcode_list_.Add(cmNand, otNone, size, true, opcode_entry, NULL, end_cryptor);
	}

	// shl, shr
	for (i = 0; i < 2; i++) {
		command_type = (i == 0) ? cmShl : cmShr;
		for (s = osByte; s <= cpu_address_size; s++) {
			size = static_cast<OperandSize>(s);
			IntelRegistrList registr_list = free_registr_list_;
			registr_list.remove(regECX);
			reg1 = registr_list.GetRandom(size == osByte && cpu_address_size == osDWord);
			if (ctx.options.flags & cpEncryptBytecode) {
				if (type_ == vtAdvanced) {
					end_cryptor = new OpcodeCryptor();
					cryptor_list_.push_back(end_cryptor);
					end_cryptor->Init(osDWord);
				}
			}
			mov_size = (size == osByte) ? osWord : size;
			opcode_entry = processor_->AddCommand((mov_size == size) ? cmMov : cmMovzx, IntelOperand(otRegistr, mov_size, reg1), IntelOperand(otMemory | otRegistr, size, stack_registr_));
			processor_->AddCommand(cmMov, IntelOperand(otRegistr, osByte, regECX), IntelOperand(otMemory | otRegistr | otValue, osByte, stack_registr_, OperandSizeToValue(mov_size)));
			operand_size = OperandSizeToValue(osWord);
			result_size = OperandSizeToValue(cpu_address_size);
			if (result_size > operand_size)
				processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
			else if (result_size < operand_size)
				processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
			processor_->AddCommand(command_type, IntelOperand(otRegistr, size, reg1), IntelOperand(otRegistr, osByte, regECX));
			processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, mov_size, stack_registr_, OperandSizeToValue(cpu_address_size)), IntelOperand(otRegistr, mov_size, reg1));
			processor_->AddCommand(cmPushf, IntelOperand(otNone, cpu_address_size));
			processor_->AddCommand(cmPop, IntelOperand(otMemory | otRegistr, cpu_address_size, stack_registr_));
			AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor);
			opcode_list_.Add(command_type, otNone, size, true, opcode_entry, NULL, end_cryptor);
		}
	}

	// rcl, rcr
	for (i = 0; i < 2; i++) {
		command_type = (i == 0) ? cmRcl : cmRcr;
		for (s = osByte; s <= cpu_address_size; s++) {
			size = static_cast<OperandSize>(s);
			if (!visible_opcode_list.GetOpcodeInfo(command_type, otNone, size, true))
				continue;

			IntelRegistrList registr_list = free_registr_list_;
			registr_list.remove(regECX);
			reg1 = registr_list.GetRandom(size == osByte && cpu_address_size == osDWord);
			if (ctx.options.flags & cpEncryptBytecode) {
				if (type_ == vtAdvanced) {
					end_cryptor = new OpcodeCryptor();
					cryptor_list_.push_back(end_cryptor);
					end_cryptor->Init(osDWord);
				}
			}
			mov_size = (size == osByte) ? osWord : size;
			opcode_entry = processor_->AddCommand((mov_size == size) ? cmMov : cmMovzx, IntelOperand(otRegistr, mov_size, reg1), IntelOperand(otMemory | otRegistr, size, stack_registr_));
			processor_->AddCommand(cmMov, IntelOperand(otRegistr, osWord, regECX), IntelOperand(otMemory | otRegistr | otValue, osWord, stack_registr_, OperandSizeToValue(mov_size)));
			operand_size = OperandSizeToValue(osWord);
			result_size = OperandSizeToValue(cpu_address_size);
			if (result_size > operand_size)
				processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
			else if (result_size < operand_size)
				processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
			processor_->AddCommand(cmShr, IntelOperand(otHiPartRegistr, osByte, regECX), IntelOperand(otValue, osByte, 0, 1));
			processor_->AddCommand(command_type, IntelOperand(otRegistr, size, reg1), IntelOperand(otRegistr, osByte, regECX));
			processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, mov_size, stack_registr_, OperandSizeToValue(cpu_address_size)), IntelOperand(otRegistr, mov_size, reg1));
			processor_->AddCommand(cmPushf, IntelOperand(otNone, cpu_address_size));
			processor_->AddCommand(cmPop, IntelOperand(otMemory | otRegistr, cpu_address_size, stack_registr_));
			AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor);
			opcode_list_.Add(command_type, otNone, size, true, opcode_entry, NULL, end_cryptor);
		}
	}

	// shld, shrd
	for (i = 0; i < 2; i++) {
		command_type = (i == 0) ? cmShld : cmShrd;
		for (s = osDWord; s <= cpu_address_size; s++) {
			size = static_cast<OperandSize>(s);
			IntelRegistrList registr_list = free_registr_list_;
			registr_list.remove(regECX);
			reg1 = registr_list.GetRandom(size == osByte && cpu_address_size == osDWord);
			reg2 = registr_list.GetRandom(size == osByte && cpu_address_size == osDWord);
			if (ctx.options.flags & cpEncryptBytecode) {
				if (type_ == vtAdvanced) {
					end_cryptor = new OpcodeCryptor();
					cryptor_list_.push_back(end_cryptor);
					end_cryptor->Init(osDWord);
				}
			}
			opcode_entry = processor_->AddCommand(cmMov, IntelOperand(otRegistr, size, reg1), IntelOperand(otMemory | otRegistr, size, stack_registr_));
			processor_->AddCommand(cmMov, IntelOperand(otRegistr, size, reg2), IntelOperand(otMemory | otRegistr | otValue, size, stack_registr_, OperandSizeToValue(size)));
			processor_->AddCommand(cmMov, IntelOperand(otRegistr, osByte, regECX), IntelOperand(otMemory | otRegistr | otValue, osByte, stack_registr_, OperandSizeToValue(size) * 2));
			operand_size = OperandSizeToValue(size) + OperandSizeToValue(osWord);
			result_size = OperandSizeToValue(cpu_address_size);
			if (result_size > operand_size)
				processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
			else if (result_size < operand_size)
				processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
			processor_->AddCommand(command_type, IntelOperand(otRegistr, size, reg1), IntelOperand(otRegistr, size, reg2), IntelOperand(otRegistr, osByte, regECX));
			processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, size, stack_registr_, OperandSizeToValue(cpu_address_size)), IntelOperand(otRegistr, size, reg1));
			processor_->AddCommand(cmPushf, IntelOperand(otNone, cpu_address_size));
			processor_->AddCommand(cmPop, IntelOperand(otMemory | otRegistr, cpu_address_size, stack_registr_));
			AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor);
			opcode_list_.Add(command_type, otNone, size, true, opcode_entry, NULL, end_cryptor);
		}
	}

	// div, idiv
	for (i = 0; i < 2; i++) {
		command_type = (i == 0) ? cmDiv : cmIdiv;
		for (s = osByte; s <= cpu_address_size; s++) {
			size = static_cast<OperandSize>(s);
			if (!visible_opcode_list.GetOpcodeInfo(command_type, otNone, size, true))
				continue;

			if (ctx.options.flags & cpEncryptBytecode) {
				if (type_ == vtAdvanced) {
					end_cryptor = new OpcodeCryptor();
					cryptor_list_.push_back(end_cryptor);
					end_cryptor->Init(osDWord);
				}
			}
			mov_size = (size == osByte) ? osWord : size;
			if (size == osByte) {
				opcode_entry = processor_->AddCommand(cmMovzx, IntelOperand(otRegistr, mov_size, regEAX), IntelOperand(otMemory | otRegistr, size, stack_registr_));
				processor_->AddCommand(cmMov, IntelOperand(otRegistr, size, regECX), IntelOperand(otMemory | otRegistr | otValue, size, stack_registr_, OperandSizeToValue(mov_size)));
			}
			else {
				opcode_entry = processor_->AddCommand(cmMov, IntelOperand(otRegistr, size, regEAX), IntelOperand(otMemory | otRegistr | otValue, size, stack_registr_, OperandSizeToValue(size)));
				processor_->AddCommand(cmMov, IntelOperand(otRegistr, size, regEDX), IntelOperand(otMemory | otRegistr, size, stack_registr_));
				processor_->AddCommand(cmMov, IntelOperand(otRegistr, size, regECX), IntelOperand(otMemory | otRegistr | otValue, size, stack_registr_, OperandSizeToValue(size) * 2));
			}
			operand_size = OperandSizeToValue(mov_size);
			result_size = OperandSizeToValue(cpu_address_size);
			if (result_size > operand_size)
				processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
			else if (result_size < operand_size)
				processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
			processor_->AddCommand(command_type, IntelOperand(otRegistr, size, regECX));
			if (size == osByte) {
				processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, mov_size, stack_registr_, OperandSizeToValue(cpu_address_size)), IntelOperand(otRegistr, mov_size, regEAX));
			}
			else {
				processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, mov_size, stack_registr_, OperandSizeToValue(cpu_address_size)), IntelOperand(otRegistr, size, regEDX));
				processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, mov_size, stack_registr_, OperandSizeToValue(cpu_address_size) + OperandSizeToValue(mov_size)), IntelOperand(otRegistr, size, regEAX));
			}
			processor_->AddCommand(cmPushf, IntelOperand(otNone, cpu_address_size));
			processor_->AddCommand(cmPop, IntelOperand(otMemory | otRegistr, cpu_address_size, stack_registr_));
			AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor);
			opcode_list_.Add(command_type, otNone, size, true, opcode_entry, NULL, end_cryptor);
		}
	}

	// mul, imul
	for (i = 0; i < 2; i++) {
		command_type = (i == 0) ? cmMul : cmImul;
		for (s = osByte; s <= cpu_address_size; s++) {
			size = static_cast<OperandSize>(s);
			if (!visible_opcode_list.GetOpcodeInfo(command_type, otNone, size, true))
				continue;

			if (ctx.options.flags & cpEncryptBytecode) {
				if (type_ == vtAdvanced) {
					end_cryptor = new OpcodeCryptor();
					cryptor_list_.push_back(end_cryptor);
					end_cryptor->Init(osDWord);
				}
			}
			mov_size = (size == osByte) ? osWord : size;
			opcode_entry = processor_->AddCommand((mov_size == size) ? cmMov : cmMovzx, IntelOperand(otRegistr, mov_size, regEAX), IntelOperand(otMemory | otRegistr | otValue, size, stack_registr_, OperandSizeToValue(mov_size)));
			processor_->AddCommand(cmMov, IntelOperand(otRegistr, size, regEDX), IntelOperand(otMemory | otRegistr, size, stack_registr_));
			operand_size = (size == osByte) ? OperandSizeToValue(mov_size) : 0;
			result_size = OperandSizeToValue(cpu_address_size);
			if (result_size > operand_size)
				processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
			else if (result_size < operand_size)
				processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
			processor_->AddCommand(command_type, IntelOperand(otRegistr, size, regEDX));
			if (size == osByte) {
				processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, mov_size, stack_registr_, OperandSizeToValue(cpu_address_size)), IntelOperand(otRegistr, mov_size, regEAX));
			}
			else {
				processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, mov_size, stack_registr_, OperandSizeToValue(cpu_address_size)), IntelOperand(otRegistr, mov_size, regEDX));
				processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, mov_size, stack_registr_, OperandSizeToValue(cpu_address_size) + OperandSizeToValue(mov_size)), IntelOperand(otRegistr, mov_size, regEAX));
			}
			processor_->AddCommand(cmPushf, IntelOperand(otNone, cpu_address_size));
			processor_->AddCommand(cmPop, IntelOperand(otMemory | otRegistr, cpu_address_size, stack_registr_));
			AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor);
			opcode_list_.Add(command_type, otNone, size, true, opcode_entry, NULL, end_cryptor);
		}
	}

	// fild, fld, fadd, fsub, fsubr, fstp, fst, fist, fistp, fdiv, fmul, fcomp, fstcw, fldcw, fstsw
	for (i = 0; i < 33; i++) {
		switch (i) {
		case 0:
			command_type = cmFild;
			size = osWord;
			break;
		case 1:
			command_type = cmFild;
			size = osDWord;
			break;
		case 2:
			command_type = cmFild;
			size = osQWord;
			break;
		case 3:
			command_type = cmFld;
			size = osDWord;
			break;
		case 4:
			command_type = cmFld;
			size = osQWord;
			break;
		case 5:
			command_type = cmFld;
			size = osTByte;
			break;
		case 6:
			command_type = cmFadd;
			size = osDWord;
			break;
		case 7:
			command_type = cmFadd;
			size = osQWord;
			break;
		case 8:
			command_type = cmFsub;
			size = osDWord;
			break;
		case 9:
			command_type = cmFsub;
			size = osQWord;
			break;
		case 10:
			command_type = cmFsubr;
			size = osDWord;
			break;
		case 11:
			command_type = cmFsubr;
			size = osQWord;
			break;
		case 12:
			command_type = cmFstp;
			size = osDWord;
			break;
		case 13:
			command_type = cmFstp;
			size = osQWord;
			break;
		case 14:
			command_type = cmFstp;
			size = osTByte;
			break;
		case 15:
			command_type = cmFst;
			size = osDWord;
			break;
		case 16:
			command_type = cmFst;
			size = osQWord;
			break;
		case 17:
			command_type = cmFist;
			size = osWord;
			break;
		case 18:
			command_type = cmFist;
			size = osDWord;
			break;
		case 19:
			command_type = cmFistp;
			size = osWord;
			break;
		case 20:
			command_type = cmFistp;
			size = osDWord;
			break;
		case 21:
			command_type = cmFistp;
			size = osQWord;
			break;
		case 22:
			command_type = cmFisub;
			size = osWord;
			break;
		case 23:
			command_type = cmFisub;
			size = osDWord;
			break;
		case 24:
			command_type = cmFdiv;
			size = osDWord;
			break;
		case 25:
			command_type = cmFdiv;
			size = osQWord;
			break;
		case 26:
			command_type = cmFmul;
			size = osDWord;
			break;
		case 27:
			command_type = cmFmul;
			size = osQWord;
			break;
		case 28:
			command_type = cmFcomp;
			size = osDWord;
			break;
		case 29:
			command_type = cmFcomp;
			size = osQWord;
			break;
		case 30:
			command_type = cmFstcw;
			size = osWord;
			break;
		case 31:
			command_type = cmFldcw;
			size = osWord;
			break;
		case 32:
			command_type = cmFstsw;
			size = osWord;
			break;
		}
		if (!visible_opcode_list.GetOpcodeInfo(command_type, otNone, size, 0))
			continue;

		if (ctx.options.flags & cpEncryptBytecode) {
			if (type_ == vtAdvanced) {
				end_cryptor = new OpcodeCryptor();
				cryptor_list_.push_back(end_cryptor);
				end_cryptor->Init(osDWord);
			}
		}
		opcode_entry = processor_->AddCommand(command_type, IntelOperand(otMemory | otRegistr, size, stack_registr_));
		AddEndHandlerCommands(read_opcode, end_cryptor);
		opcode_list_.Add(command_type, otNone, size, 0, opcode_entry, NULL, end_cryptor);
	}

	// wait, fchs, fsqrt, f2xm1, fabs, fclex, fcos, fdecstp, fincstp, finit, fldln2, fldz, fld1, fldpi, fpatan, fprem, fprem1, fptan, frndint, fsin, ftst, fyl2x, fldlg2
	for (i = 0; i < 24; i++) {
		switch (i) {
		case 0:
			command_type = cmWait;
			break;
		case 1:
			command_type = cmFchs;
			break;
		case 2:
			command_type = cmFsqrt;
			break;
		case 3:
			command_type = cmF2xm1;
			break;
		case 4:
			command_type = cmFabs;
			break;
		case 5:
			command_type = cmFclex;
			break;
		case 6:
			command_type = cmFcos;
			break;
		case 7:
			command_type = cmFdecstp;
			break;
		case 8:
			command_type = cmFincstp;
			break;
		case 9:
			command_type = cmFinit;
			break;
		case 10:
			command_type = cmFldln2;
			break;
		case 12:
			command_type = cmFldz;
			break;
		case 13:
			command_type = cmFld1;
			break;
		case 14:
			command_type = cmFldpi;
			break;
		case 15:
			command_type = cmFpatan;
			break;
		case 16:
			command_type = cmFprem;
			break;
		case 17:
			command_type = cmFprem1;
			break;
		case 18:
			command_type = cmFptan;
			break;
		case 19:
			command_type = cmFrndint;
			break;
		case 20:
			command_type = cmFsin;
			break;
		case 21:
			command_type = cmFtst;
			break;
		case 22:
			command_type = cmFyl2x;
			break;
		case 23:
			command_type = cmFldlg2;
			break;
		}
		if (!visible_opcode_list.GetOpcodeInfo(command_type, otNone, cpu_address_size, 0))
			continue;

		if (ctx.options.flags & cpEncryptBytecode) {
			if (type_ == vtAdvanced) {
				end_cryptor = new OpcodeCryptor();
				cryptor_list_.push_back(end_cryptor);
				end_cryptor->Init(osDWord);
			}
		}
		opcode_entry = processor_->AddCommand(command_type);
		AddEndHandlerCommands(read_opcode, end_cryptor);
		opcode_list_.Add(command_type, otNone, cpu_address_size, 0, opcode_entry, NULL, end_cryptor);
	}

	// ret, iret
	for (j = 0; j < 3; j++) {
		command_type = (j == 1) ? cmIret : cmRet;
		if (j > 0 && !visible_opcode_list.GetOpcodeInfo(command_type, otNone, cpu_address_size, (j == 2) ? 1 : 0))
			continue;

		opcode_entry = processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, regESP), IntelOperand(otRegistr, cpu_address_size, stack_registr_));

		for (i = registr_order_.size(); i > 0; i--) {
			uint8_t reg = registr_order_[i - 1];
			if (reg == regEFX) {
				processor_->AddCommand(cmPopf);
			}
			else {
				processor_->AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size, reg));
			}
		}

		command = processor_->AddCommand(command_type);
		if (j == 2)
			command->include_option(roFar);
		opcode_list_.Add(command_type, otNone, cpu_address_size, (command->options() & roFar) ? 1 : 0, opcode_entry);
	}

	// popf
	{
		if (ctx.options.flags & cpEncryptBytecode) {
			if (type_ == vtAdvanced) {
				end_cryptor = new OpcodeCryptor();
				cryptor_list_.push_back(end_cryptor);
				end_cryptor->Init(osDWord);
			}
		}
		opcode_entry = processor_->AddCommand(cmPush, IntelOperand(otMemory | otRegistr, cpu_address_size, stack_registr_));
		operand_size = OperandSizeToValue(cpu_address_size);
		result_size = 0;
		if (result_size > operand_size) //-V547
			processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
		else if (result_size < operand_size)
			processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
		processor_->AddCommand(cmPopf, IntelOperand(otNone, cpu_address_size));
		AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor); //-V547
		opcode_list_.Add(cmPopf, otNone, cpu_address_size, 0, opcode_entry, NULL, end_cryptor);
	}

	// jmp
	for (i = 0; i < ctx.options.vm_count; i++) {
		IntelRegistrList registr_list = free_registr_list_;
		reg1 = registr_list.GetRandom();
		opcode_entry = processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otMemory | otRegistr, cpu_address_size, stack_registr_));
		processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, OperandSizeToStack(cpu_address_size)));
		command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
		command->AddLink(0, ltJmp);
		vm_links_.push_back(command);

		opcode_list_.Add(cmJmp, otNone, cpu_address_size, (uint8_t)i + 1, opcode_entry);
	}

	// rdtsc
	if (visible_opcode_list.GetOpcodeInfo(cmRdtsc, otNone, cpu_address_size, 0)) {
		if (ctx.options.flags & cpEncryptBytecode) {
			if (type_ == vtAdvanced) {
				end_cryptor = new OpcodeCryptor();
				cryptor_list_.push_back(end_cryptor);
				end_cryptor->Init(osDWord);
			}
		}
		opcode_entry = processor_->AddCommand(cmRdtsc);
		operand_size = 0;
		result_size = OperandSizeToValue(osDWord) * 2;
		if (result_size > operand_size)
			processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
		else if (result_size < operand_size) //-V547
			processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, osDWord, stack_registr_), IntelOperand(otRegistr, osDWord, regEDX));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osDWord, stack_registr_, OperandSizeToValue(osDWord)), IntelOperand(otRegistr, osDWord, regEAX));
		AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor);
		opcode_list_.Add(cmRdtsc, otNone, cpu_address_size, 0, opcode_entry, NULL, end_cryptor);
	}

	// cpuid
	if (visible_opcode_list.GetOpcodeInfo(cmCpuid, otNone, cpu_address_size, 0)) {
		if (stack_registr_ == regEBX) {
			IntelRegistrList registr_list = free_registr_list_;
			registr_list.remove(regEAX);
			registr_list.remove(regEBX);
			registr_list.remove(regECX);
			registr_list.remove(regEDX);
			reg1 = registr_list.GetRandom();
		}
		else
			reg1 = stack_registr_;
		if (ctx.options.flags & cpEncryptBytecode) {
			if (type_ == vtAdvanced) {
				end_cryptor = new OpcodeCryptor();
				cryptor_list_.push_back(end_cryptor);
				end_cryptor->Init(osDWord);
			}
		}
		opcode_entry = processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regEAX), IntelOperand(otMemory | otRegistr, osDWord, stack_registr_));
		if (reg1 != stack_registr_)
			processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otRegistr, cpu_address_size, stack_registr_));
		if (IsRegistrUsed(regEBX))
			processor_->AddCommand(cmPush, IntelOperand(otRegistr, cpu_address_size, regEBX));
		processor_->AddCommand(cmCpuid);
		operand_size = OperandSizeToValue(osDWord);
		result_size = OperandSizeToValue(osDWord) * 4;
		if (result_size > operand_size)
			processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
		else if (result_size < operand_size)
			processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osDWord, reg1, OperandSizeToValue(osDWord) * 3), IntelOperand(otRegistr, osDWord, regEAX));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osDWord, reg1, OperandSizeToValue(osDWord) * 2), IntelOperand(otRegistr, osDWord, regEBX));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, osDWord, reg1, OperandSizeToValue(osDWord)), IntelOperand(otRegistr, osDWord, regECX));
		processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, osDWord, reg1), IntelOperand(otRegistr, osDWord, regEDX));
		if (IsRegistrUsed(regEBX))
			processor_->AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size, regEBX));
		if (reg1 != stack_registr_)
			processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otRegistr, cpu_address_size, reg1));
		AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor);
		opcode_list_.Add(cmCpuid, otNone, cpu_address_size, 0, opcode_entry, NULL, end_cryptor);
	}

	// call
	if (visible_opcode_list.GetOpcodeInfo(cmCall, otNone, cpu_address_size, 0)) {
		IntelRegistrList registr_list = free_registr_list_;
		registr_list.remove(regEBP);
		reg1 = registr_list.GetRandom(cpu_address_size == osDWord);
		if (ctx.options.flags & cpEncryptBytecode) {
			value_cryptor = new OpcodeCryptor();
			cryptor_list_.push_back(value_cryptor);
			value_cryptor->Init(osByte);
			if (type_ == vtAdvanced) {
				end_cryptor = new OpcodeCryptor();
				cryptor_list_.push_back(end_cryptor);
				end_cryptor->Init(osDWord);
			}
		}
		opcode_entry = AddReadCommand(osByte, value_cryptor, reg1);
		AddCallCommands(ctx.file->calling_convention(), NULL, reg1);
		AddEndHandlerCommands(read_opcode, end_cryptor);
		opcode_list_.Add(cmCall, otNone, cpu_address_size, 0, opcode_entry, value_cryptor, end_cryptor);
	}

	// syscall
	if (visible_opcode_list.GetOpcodeInfo(cmSyscall, otNone, cpu_address_size, 0)) {
		IntelRegistrList registr_list = free_registr_list_;
		registr_list.remove(regEBP);
		reg1 = registr_list.GetRandom(cpu_address_size == osDWord);
		if (ctx.options.flags & cpEncryptBytecode) {
			value_cryptor = new OpcodeCryptor();
			cryptor_list_.push_back(value_cryptor);
			value_cryptor->Init(osByte);
			if (type_ == vtAdvanced) {
				end_cryptor = new OpcodeCryptor();
				cryptor_list_.push_back(end_cryptor);
				end_cryptor->Init(osDWord);
			}
		}
		c = processor_->count();
		if (cpu_address_size == osDWord) {
			// x32
			IntelVirtualMachineProcessor* new_processor = function_list->AddProcessor(osDWord);
			new_processor->set_compilation_type(ctVirtualization);

			command = new_processor->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, regEDX), IntelOperand(otRegistr, cpu_address_size, regESP));
			new_processor->AddCommand(cmSysenter);
			new_processor->AddCommand(cmRet);

			IntelCommand* sysenter_entry = new_processor->AddCommand(cmCall, IntelOperand(otValue, cpu_address_size));
			sysenter_entry->AddLink(0, ltCall, command);
			new_processor->AddCommand(cmRet);

			IntelVirtualMachineProcessor* old_processor = processor_;
			processor_ = new_processor;

			opcode_entry = AddReadCommand(osByte, value_cryptor, reg1);
			processor_->AddCommand(cmTest, IntelOperand(otMemory | otRegistr, osDWord, stack_registr_), IntelOperand(otValue, osDWord, 0, WOW64_FLAG));
			IntelCommand* cmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size));
			cmp_command->set_flags(fl_Z);
			cmp_command->include_option(roInverseFlag);
			cmp_command->AddLink(0, ltJmpWithFlag);
			AddCallCommands(ctx.file->calling_convention(), sysenter_entry, reg1);
			AddEndHandlerCommands(read_opcode, end_cryptor);

			jmp_command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
			jmp_command->AddLink(0, ltJmp);
			cmp_command->link()->set_to_command(jmp_command);

			size_t old_count = processor_->count();
			command = processor_->AddCommand(cmPush, IntelOperand(otSegmentRegistr, cpu_address_size, segCS, 0));
			jmp_command->link()->set_to_command(command);
			IntelCommand* ret_offset_command = processor_->AddCommand(cmPush, IntelOperand(otValue, cpu_address_size, 0, 0, NEED_FIXUP));
			ret_offset_command->AddLink(0, ltOffset);
			IntelCommand* far_call = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size, 0, 0, NEED_FIXUP), IntelOperand(otValue, osWord, 0, 0x33));
			far_call->AddLink(0, ltGateOffset);
			far_call->include_option(roFar);
			command = processor_->AddCommand(cmNop);
			ret_offset_command->link()->set_to_command(command);

			// AMD bug
			processor_->AddCommand(cmMov, IntelOperand(otRegistr, osWord, regECX), IntelOperand(otSegmentRegistr, osWord, segSS));
			processor_->AddCommand(cmMov, IntelOperand(otSegmentRegistr, osWord, segSS), IntelOperand(otRegistr, osWord, regECX));
			jmp_command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
			jmp_command->AddLink(0, ltGateOffset);

			CommandBlock* block = NULL;
			for (i = old_count; i < processor_->count(); i++) {
				if (!block)
					block = processor_->AddBlock(i, true);
				command = processor_->item(i);
				command->set_block(block);
				block->set_end_index(i);
				if (command->is_end())
					block = NULL;
			}

			old_count = processor_->count();
			AddEndHandlerCommands(read_opcode, end_cryptor);
			jmp_command->link()->set_to_command(processor_->item(old_count));

			// x64
			new_processor = function_list->AddProcessor(osQWord);
			new_processor->set_compilation_type(ctVirtualization);

			IntelCommand* syscall_entry = new_processor->AddCommand(cmMov, IntelOperand(otRegistr, osQWord, regR10), IntelOperand(otRegistr, osQWord, regECX));
			new_processor->AddCommand(cmSyscall);
			new_processor->AddCommand(cmRet);

			processor_ = new_processor;

			old_count = new_processor->count();
			AddCallCommands(ccStdcallToMSx64, syscall_entry, reg1);
			command = processor_->AddCommand(cmRet);
			command->include_option(roFar);
			far_call->link()->set_to_command(processor_->item(old_count));

			processor_ = old_processor;

			jmp_command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
			jmp_command->AddLink(0, ltJmp, opcode_entry);
			opcode_entry = jmp_command;
		}
		else {
			IntelVirtualMachineProcessor* new_processor = function_list->AddProcessor(osQWord);
			new_processor->set_compilation_type(ctVirtualization);
			IntelVirtualMachineProcessor* old_processor = processor_;
			processor_ = new_processor;

			IntelCommand* call_entry = processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, regR10), IntelOperand(otRegistr, cpu_address_size, regECX));
			processor_->AddCommand(cmSyscall);
			processor_->AddCommand(cmRet);

			opcode_entry = AddReadCommand(osByte, value_cryptor, reg1);
			AddCallCommands(ctx.file->calling_convention(), call_entry, reg1);
			AddEndHandlerCommands(read_opcode, end_cryptor);

			processor_ = old_processor;

			jmp_command = processor_->AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size));
			jmp_command->AddLink(0, ltJmp, opcode_entry);
			opcode_entry = jmp_command;
		}
		opcode_list_.Add(cmSyscall, otNone, cpu_address_size, 0, opcode_entry, value_cryptor, end_cryptor);
	}

	// crc
	if (visible_opcode_list.GetOpcodeInfo(cmCrc, otNone, cpu_address_size, 0)) {
		c = (type_ == vtAdvanced) ? 10 : 1;
		for (size_t k = 0; k < c; k++) {
			j = processor_->count();
			uint32_t crc_table_salt = rand32();
			for (i = 0; i < _countof(crc32_table); i++) {
				command = processor_->AddCommand(osDWord, crc32_table[i] ^ crc_table_salt);
				command->include_option(roNeedCRC);
			}
			IntelCommand* crc_table_entry = processor_->item(j);
			crc_table_entry->include_option(roCreateNewBlock);
			crc_table_entry->set_alignment(OperandSizeToValue(cpu_address_size));

			IntelRegistrList registr_list = free_registr_list_;
			registr_list.remove(regESI);
			reg1 = registr_list.GetRandom();
			reg2 = registr_list.GetRandom();
			reg3 = registr_list.GetRandom();
			reg4 = 0;
			if (ctx.options.flags & cpEncryptBytecode) {
				if (type_ == vtAdvanced) {
					end_cryptor = new OpcodeCryptor();
					cryptor_list_.push_back(end_cryptor);
					end_cryptor->Init(osDWord);
				}
			}

			opcode_entry = processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otMemory | otRegistr, cpu_address_size, stack_registr_));
			processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, reg2), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size, stack_registr_, OperandSizeToValue(cpu_address_size)));
			operand_size = OperandSizeToValue(cpu_address_size) * 2;
			result_size = OperandSizeToValue(osDWord);
			if (result_size > operand_size)
				processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
			else if (result_size < operand_size)
				processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));

			//processor_->AddCommand(cmInt, IntelOperand(otValue, osWord, 0, 3));

			processor_->AddCommand(cmXor, IntelOperand(otRegistr, osDWord, reg3), IntelOperand(otRegistr, osDWord, reg3));
			processor_->AddCommand(cmTest, IntelOperand(otRegistr, cpu_address_size, reg2), IntelOperand(otRegistr, cpu_address_size, reg2));
			IntelCommand* jmp_command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size, 0, 0));
			jmp_command->set_flags(fl_Z);
			jmp_command->AddLink(0, ltJmpWithFlag);

			if (cpu_address_size == osQWord) {
				reg4 = registr_list.GetRandom();
				command = processor_->AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, reg4), IntelOperand(otMemory | otValue, cpu_address_size, 0, 0, LARGE_VALUE));
				command->AddLink(1, ltOffset, crc_table_entry);
			}
			if (IsRegistrUsed(regESI))
				processor_->AddCommand(cmPush, IntelOperand(otRegistr, cpu_address_size, regESI));

			IntelCommand* loop_command = processor_->AddCommand(cmMovzx, IntelOperand(otRegistr, osDWord, regESI), IntelOperand(otMemory | otRegistr, osByte, reg1));
			processor_->AddCommand(cmXor, IntelOperand(otRegistr, osDWord, regESI), IntelOperand(otRegistr, osDWord, reg3));
			processor_->AddCommand(cmAnd, IntelOperand(otRegistr, osDWord, regESI), IntelOperand(otValue, osDWord, 0, 0xff));

			if (cpu_address_size == osQWord) {
				command = processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regESI), IntelOperand(otMemory | otBaseRegistr | otRegistr, osDWord, (reg4 << 4) | regESI, 0));
				command->set_operand_scale(1, 2);
			}
			else {
				command = processor_->AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regESI), IntelOperand(otMemory | otRegistr | otValue, osDWord, regESI, 0, NEED_FIXUP));
				command->set_operand_scale(1, 2);
				command->AddLink(1, ltOffset, crc_table_entry);
			}

			processor_->AddCommand(cmShr, IntelOperand(otRegistr, osDWord, reg3), IntelOperand(otValue, osByte, 0, 8));
			processor_->AddCommand(cmXor, IntelOperand(otRegistr, osDWord, reg3), IntelOperand(otRegistr, osDWord, regESI));
			processor_->AddCommand(cmInc, IntelOperand(otRegistr, cpu_address_size, reg1));
			processor_->AddCommand(cmXor, IntelOperand(otRegistr, osDWord, reg3), IntelOperand(otValue, osDWord, 0, crc_table_salt));
			processor_->AddCommand(cmDec, IntelOperand(otRegistr, cpu_address_size, reg2));

			command = processor_->AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size, 0, 0));
			command->set_flags(fl_Z);
			command->include_option(roInverseFlag);
			command->AddLink(0, ltJmpWithFlag, loop_command);

			if (IsRegistrUsed(regESI))
				processor_->AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size, regESI));

			command = processor_->AddCommand(cmNot, IntelOperand(otRegistr, osDWord, reg3));
			jmp_command->link()->set_to_command(command);

			processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, osDWord, stack_registr_), IntelOperand(otRegistr, osDWord, reg3));

			AddEndHandlerCommands(read_opcode, end_cryptor);
			opcode_list_.Add(cmCrc, otNone, cpu_address_size, 0, opcode_entry, NULL, end_cryptor);
		}
	}

	if (ctx.options.flags & cpMemoryProtection) {
		for (i = 0; i < opcode_list_.count(); i++) {
			IntelOpcodeInfo* opcode = opcode_list_.item(i);
			if (opcode->command_type() == cmCpuid || opcode->command_type() == cmRdtsc || opcode->command_type() == cmCrc || opcode->command_type() == cmSyscall) {
				for (j = processor_->IndexOf(opcode->entry()); j < processor_->count(); j++) {
					command = processor_->item(j);
					bool need_crc = true;
					if ((ctx.options.flags & cpStripFixups) == 0) {
						for (c = 0; c < 3; c++) {
							IntelOperand operand = command->operand(c);
							if (operand.type == otNone)
								break;

							if ((operand.type & otValue) && operand.fixup) {
								need_crc = false;
								break;
							}
						}
					}

					if (need_crc)
						command->include_option(roNeedCRC);
					if (command->type() == cmJmp || command->type() == cmRet || command->type() == cmIret)
						break;
				}
			}
		}
	}

	// lock
	for (i = 0; i < 7; i++) {
		switch (i) {
		case 0:
			command_type = cmAdd;
			break;
		case 1:
			command_type = cmSub;
			break;
		case 2:
			command_type = cmAnd;
			break;
		case 3:
			command_type = cmXor;
			break;
		case 4:
			command_type = cmOr;
			break;
		case 5:
			command_type = cmXchg;
			break;
		case 6:
			command_type = cmXadd;
			break;
		}
		for (s = osByte; s <= cpu_address_size; s++) {
			size = static_cast<OperandSize>(s);
			mov_size = (size == osByte) ? osWord : size;
			for (seg = segES; seg <= segGS; seg++) {
				if (!visible_opcode_list.GetOpcodeInfo(command_type, otMemory, size, seg))
					continue;

				IntelRegistrList registr_list = free_registr_list_;
				reg1 = registr_list.GetRandom(size == osByte && cpu_address_size == osDWord);
				reg2 = registr_list.GetRandom(size == osByte && cpu_address_size == osDWord);
				if (ctx.options.flags & cpEncryptBytecode) {
					if (type_ == vtAdvanced) {
						end_cryptor = new OpcodeCryptor();
						cryptor_list_.push_back(end_cryptor);
						end_cryptor->Init(osDWord);
					}
				}

				opcode_entry = processor_->AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, reg1), IntelOperand(otMemory | otRegistr, cpu_address_size, stack_registr_));
				processor_->AddCommand(cmMov, IntelOperand(otRegistr, size, reg2), IntelOperand(otMemory | otRegistr | otValue, size, stack_registr_, OperandSizeToValue(cpu_address_size)));
				operand_size = OperandSizeToValue(cpu_address_size) + OperandSizeToValue(mov_size);
				result_size = (command_type == cmXchg) ? 0 : OperandSizeToValue(cpu_address_size);
				if (command_type == cmXchg || command_type == cmXadd)
					result_size += OperandSizeToValue(mov_size);
				if (result_size > operand_size)
					processor_->AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, result_size - operand_size));
				else if (result_size < operand_size)
					processor_->AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size, stack_registr_), IntelOperand(otValue, cpu_address_size, 0, operand_size - result_size));
				command = processor_->AddCommand(command_type, IntelOperand(otMemory | otRegistr, size, reg1), IntelOperand(otRegistr, size, reg2));
				command->include_option(roLockPrefix);
				if (seg != segDS)
					command->set_base_segment(static_cast<IntelSegment>(seg));
				if (command_type == cmXchg)
					processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr, mov_size, stack_registr_), IntelOperand(otRegistr, mov_size, reg2));
				else {
					if (command_type == cmXadd)
						processor_->AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, mov_size, stack_registr_, OperandSizeToValue(cpu_address_size)), IntelOperand(otRegistr, mov_size, reg2));
					processor_->AddCommand(cmPushf, IntelOperand(otNone, cpu_address_size));
					processor_->AddCommand(cmPop, IntelOperand(otMemory | otRegistr, cpu_address_size, stack_registr_));
				}
				AddEndHandlerCommands((result_size > operand_size) ? check_stack : read_opcode, end_cryptor);
				opcode_list_.Add(command_type, otMemory, size, seg, opcode_entry, NULL, end_cryptor);
			}
		}
	}

	// randomize opcodes
	if (type_ == vtAdvanced) {
		c = opcode_list_.count();
		for (i = 0; i < c; i++) {
			opcode = opcode_list_.item(i);
			if (opcode->command_type() == cmNop || opcode->command_type() == cmJmp || opcode->command_type() == cmCrc)
				continue;

			for (j = 0; j < 10; j++) {
				opcode_list_.Add(opcode->command_type(), opcode->operand_type(), opcode->size(), opcode->value(), CloneHandler(opcode->entry()), opcode->value_cryptor(), opcode->end_cryptor());
			}
		}
	}
	else {
		c = opcode_list_.count();
		for (i = 0; i < opcode_list_.count(); i++) {
			opcode_list_.SwapObjects(i, rand() % c);
		}
		for (i = opcode_list_.count(); i < 0x100; i++) {
			opcode = opcode_list_.item(rand() % i);
			opcode_list_.Add(opcode->command_type(), opcode->operand_type(), opcode->size(), opcode->value(), (opcode->command_type() == cmJmp) ? opcode->entry() : CloneHandler(opcode->entry()), opcode->value_cryptor(), opcode->end_cryptor());
		}

		// CASEs
		c = processor_->count();
		command_type = (cpu_address_size == osDWord) ? cmDD : cmDQ;
		for (i = 0; i < opcode_list_.count(); i++) {
			IntelOpcodeInfo* opcode = opcode_list_.item(i);
			opcode->set_opcode(static_cast<uint8_t>(i));
			command = processor_->AddCommand(command_type, IntelOperand(otValue, cpu_address_size, 0, 0, NEED_FIXUP));
			CommandLink* link = command->AddLink(0, ltCase, opcode->entry());
			link->set_parent_command(switch_entry);
		}
		command = processor_->item(c);
		command->set_alignment(OperandSizeToValue(cpu_address_size));
		switch_entry->link()->set_to_command(command);
	}
}

IntelOpcodeInfo* IntelVirtualMachine::GetOpcode(IntelCommandType command_type, OperandType operand_type, OperandSize size, uint8_t value)
{
	IntelOpcodeInfo* res = NULL;
	uint64_t key = IntelOpcodeInfo::Key(command_type, operand_type, size, value);
	auto it = opcode_stack_.find(key);
	if (it != opcode_stack_.end())
		res = it->second.Next();
	return res;
}

static void EncryptBuffer(uint32_t* buffer, uint64_t key)
{
	uint32_t key0 = static_cast<uint32_t>(key >> 32);
	uint32_t key1 = static_cast<uint32_t>(key);
	buffer[0] = _rotr32(buffer[0] - key0, 7) ^ key1;
	buffer[1] = _rotr32(buffer[1] - key0, 11) ^ key1;
	buffer[2] = _rotr32(buffer[2] - key0, 17) ^ key1;
	buffer[3] = _rotr32(buffer[3] - key0, 23) ^ key1;
}

void IntelVirtualMachine::CompileCommand(IntelVMCommand& vm_command)
{
	IntelCommandType command_type = vm_command.command_type();
	OperandType operand_type = vm_command.operand_type();
	uint8_t registr = vm_command.registr();
	OperandSize size = vm_command.size();
	uint64_t value = vm_command.value();
	CommandBlock* block = vm_command.owner()->block();
	Data dump;
	bool backward_direction = (vm_command.owner()->section_options() & rtBackwardDirection) != 0;
	IntelOpcodeInfo* opcode = NULL;

	switch (command_type) {
	case cmPush:
		switch (operand_type) {
		case otRegistr:
			if (registr == regESP && (size == osWord || size == osDWord || size == osQWord)) {
				opcode = GetOpcode(cmPush, otRegistr, size, 0xFF);
			}
			else {
				opcode = GetOpcode(cmPush, otRegistr, size, 0);
				dump.PushByte(block->GetRegistr(size, registr, false));
			}
			break;
		case otHiPartRegistr:
			opcode = GetOpcode(cmPush, otRegistr, size, 0);
			dump.PushByte((uint8_t)(block->GetRegistr(size, registr, false) + OperandSizeToValue(size)));
			break;
		case otMemory:
			opcode = GetOpcode(cmPush, otMemory, size, vm_command.base_segment());
			break;
		case otSegmentRegistr:
			opcode = GetOpcode(cmPush, otSegmentRegistr, size, registr);
			break;
		case otDebugRegistr:
			opcode = GetOpcode(cmPush, otDebugRegistr, size, registr);
			break;
		case otControlRegistr:
			opcode = GetOpcode(cmPush, otControlRegistr, size, registr);
			break;
		case otValue:
			opcode = GetOpcode(cmPush, otValue, size, 0);

			uint64_t new_value;
			if (vm_command.crypt_command() == cmXadd) {
				uint32_t crypted_value[4];
				size_t i;
				for (i = 0; i < _countof(crypted_value); i++) {
					crypted_value[i] = rand32();
				}
				switch (vm_command.crypt_size()) {
				case osDWord:
					crypted_value[3] = static_cast<uint32_t>(value);
					break;
				case osQWord:
					*reinterpret_cast<uint64_t*>(&crypted_value[2]) = value;
					break;
				}
				uint32_t dw = 0;
				for (i = 1; i < 4; i++) {
					dw += crypted_value[i];
				}
				crypted_value[0] = 0 - dw;
				EncryptBuffer(crypted_value, vm_command.crypt_key());
				IntelVMCommand* link_command = vm_command.link_command();
				for (i = 3; i > 0; i--) {
					link_command->set_value(crypted_value[i - 1]);
					link_command->Compile();
					link_command = link_command->link_command();
				}
				new_value = crypted_value[3];
			}
			else {
				new_value = value;
			}

			new_value -= vm_command.sub_value();

			switch (size) {
			case osByte:
				dump.PushByte(static_cast<uint8_t>(new_value));
				break;
			case osWord:
				dump.PushWord(backward_direction ? __builtin_bswap16(static_cast<uint16_t>(new_value)) : static_cast<uint16_t>(new_value));
				break;
			case osDWord:
				dump.PushDWord(backward_direction ? __builtin_bswap32(static_cast<uint32_t>(new_value)) : static_cast<uint32_t>(new_value));
				break;
			case osQWord:
				dump.PushQWord(backward_direction ? __builtin_bswap64(new_value) : new_value);
				break;
			}
			break;
		}
		break;

	case cmPop:
		switch (operand_type) {
		case otRegistr:
			if (registr == regESP && (size == osWord || size == osDWord || size == osQWord)) {
				opcode = GetOpcode(cmPop, otRegistr, size, 0xFF);
			}
			else {
				opcode = GetOpcode(cmPop, otRegistr, size, 0);
				dump.PushByte(block->GetRegistr(size, registr, true));
			}
			break;
		case otHiPartRegistr:
			opcode = GetOpcode(cmPop, otRegistr, size, 0);
			dump.PushByte((uint8_t)(block->GetRegistr(size, registr, true) + OperandSizeToValue(size)));
			break;
		case otMemory:
			opcode = GetOpcode(cmPop, otMemory, size, vm_command.base_segment());
			break;
		case otSegmentRegistr:
			opcode = GetOpcode(cmPop, otSegmentRegistr, size, registr);
			break;
		case otDebugRegistr:
			opcode = GetOpcode(cmPop, otDebugRegistr, size, registr);
			break;
		case otControlRegistr:
			opcode = GetOpcode(cmPop, otControlRegistr, size, registr);
			break;
		}
		break;

	case cmCall:
		opcode = GetOpcode(cmCall, otNone, size, 0);
		dump.PushByte(vm_command.subtype());
		break;

	case cmSyscall:
		opcode = GetOpcode(cmSyscall, otNone, size, 0);
		dump.PushByte(vm_command.subtype());
		break;

	case cmJmp:
		if (vm_command.subtype())
			opcode = GetOpcode(command_type, otNone, size, vm_command.subtype());
		else
			opcode = GetOpcode(command_type, otNone, size, (vm_command.value() == 0) ? id() : static_cast<uint8_t>(vm_command.value()));
		break;

	case cmAdd: case cmSub: case cmXor: case cmOr: case cmXchg: case cmAnd: case cmXadd:
		if (vm_command.operand_type() == otMemory)
			opcode = GetOpcode(command_type, otMemory, size, vm_command.base_segment());
		else
			opcode = GetOpcode(command_type, otNone, size, vm_command.subtype());
		break;

	case cmNor: case cmNand: case cmCrc: case cmShld: case cmShrd: case cmShl: case cmShr: case cmDiv:
	case cmIdiv: case cmMul: case cmImul: case cmRcl: case cmRcr:
	case cmPopf: case cmIret: case cmRet:
	case cmFadd: case cmFsub: case cmFisub: case cmFsubr: case cmFdiv: case cmFmul: case cmFcomp:
	case cmFstp: case cmFst: case cmFild: case cmFld: case cmFstcw: case cmFldcw: case cmFistp: case cmFist:
	case cmWait: case cmFstsw: case cmFchs: case cmFsqrt: case cmRdtsc: case cmCpuid:
	case cmF2xm1: case cmFabs: case cmFclex: case cmFcos: case cmFdecstp: case cmFincstp:
	case cmFinit: case cmFldln2: case cmFldlg2: case cmFprem: case cmFprem1: case cmFptan:
	case cmFrndint: case cmFsin: case cmFtst: case cmFyl2x: case cmFpatan: case cmFldz: case cmFld1: case cmFldpi:
		opcode = GetOpcode(command_type, otNone, size, vm_command.subtype());
		break;

	case cmDD:
		dump.PushDWord(static_cast<uint32_t>(value));
		break;

	case cmDQ:
		dump.PushQWord(value);
		break;

	default:
		opcode = NULL;
		break;
	}

	if (opcode) {
		vm_command.set_opcode(opcode);
		if (type() == vtAdvanced) {
			size_t i = vm_command.owner()->IndexOf(&vm_command);
			bool need_begin_offset;
			if (i == 0) {
				need_begin_offset = (vm_command.owner()->section_options() & (rtLinkedToInt | rtLinkedToExt)) != 0;
			}
			else {
				IntelVMCommand* prev_command = reinterpret_cast<IntelVMCommand*>(vm_command.owner()->item(i - 1));
				need_begin_offset = prev_command->is_end() || (prev_command->options() & voInitOffset);
			}

			if (need_begin_offset) {
				vm_command.include_option(voBeginOffset);
				uint32_t value = 0;
				dump.InsertBuff(0, &value, sizeof(value));
			}

			if (!vm_command.is_end()) {
				vm_command.include_option(voEndOffset);
				dump.PushDWord(0);
			}
		}
		else {
			dump.InsertByte(0, opcode->opcode());
		}
	}
	else if (!vm_command.is_data()) {
		throw std::runtime_error("Runtime error at CompileToVM: " + std::string(intel_command_name[command_type]));
	}

	vm_command.set_dump(dump);
}

std::vector<OpcodeCryptor*> IntelVirtualMachine::GetOpcodeCryptorList(IntelVMCommand* command)
{
	std::vector<OpcodeCryptor*> res;
	if (type_ == vtAdvanced) {
		if (command->options() & voBeginOffset)
			res.push_back(command_cryptor_);
	}
	else {
		res.push_back(command_cryptor_);
	}
	if (command->opcode()->value_cryptor())
		res.push_back(command->opcode()->value_cryptor());
	if (command->opcode()->end_cryptor())
		res.push_back(command->opcode()->end_cryptor());
	return res;
}

void IntelVirtualMachine::CompileBlock(CommandBlock& block, bool need_encrypt)
{
	size_t i, j, k, d, c;
	IntelFunction* func = reinterpret_cast<IntelFunction*>(block.function());
	if (type() == vtAdvanced) {
		IntelVMCommand* prev_command = NULL;
		IntelOpcodeInfo* nop_opcode = GetOpcode(cmNop, otNone, processor_->cpu_address_size(), 0);
		if (nop_opcode == NULL)
			throw std::runtime_error("Runtime error at CompileBlock/nop_opcode");

		for (i = block.start_index(); i <= block.end_index(); i++) {
			IntelCommand* command = func->item(i);
			for (j = 0; j < command->count(); j++) {
				IntelVMCommand* vm_command = command->item(j);
				if (vm_command->is_data())
					continue;

				if (prev_command && (prev_command->options() & voEndOffset)) {
					IntelOpcodeInfo* opcode = (prev_command->options() & voInitOffset) ? nop_opcode : vm_command->opcode();
					prev_command->set_dump_value(osDWord, prev_command->dump_size() - 4, static_cast<uint32_t>(opcode->entry()->address() - prev_command->opcode()->entry()->address()));
				}
				if (vm_command->options() & voBeginOffset)
					vm_command->set_dump_value(osDWord, 0, static_cast<uint32_t>(vm_command->opcode()->entry()->address() - nop_opcode->entry()->address()));
				prev_command = vm_command;
			}
		}
	}

	if (!need_encrypt)
		return;

	struct CRC {
		uint64_t Value;
		CRC()
			: Value(0)
		{

		}
		uint64_t GetValue(OperandSize size) const
		{
			uint64_t res = 0;
			memcpy(&res, &Value, OperandSizeToValue(size));
			return res;
		}
		void SetValue(OperandSize size, uint64_t value)
		{
			memcpy(&Value, &value, OperandSizeToValue(size));
		}
	};

	CRC crc, crc2;
	OperandSize os;
	OpcodeCryptor* cryptor;
	std::vector<OpcodeCryptor*> cryptor_list;
	std::vector<IVMCommand*> correct_command_list = block.correct_command_list();
	for (i = 0; i < correct_command_list.size(); i++) {
		IntelVMCommand* vm_command = reinterpret_cast<IntelVMCommand*>(correct_command_list[i]);
		IntelCommand* command = reinterpret_cast<IntelCommand*>(vm_command->owner());
		IntelVMCommand* ext_vm_entry = command->ext_vm_entry();
		bool use_ext_entry = ext_vm_entry && command->IndexOf(vm_command) < command->IndexOf(ext_vm_entry);

		size_t n = func->IndexOf(command) + 1;
		for (size_t r = n; r > block.start_index(); r--) {
			IntelCommand* cur_command = func->item(r - 1);
			if ((cur_command->section_options() & rtBeginSection) == 0)
				continue;

			crc.Value = cur_command->vm_address();
			crc2.Value = use_ext_entry ? command->ext_vm_address() : func->item(n)->vm_address();

			for (j = r - 1; j < n; j++) {
				IntelCommand* tmp_command = func->item(j);
				for (k = 0; k < tmp_command->count(); k++) {
					IntelVMCommand* cur_vm_command = tmp_command->item(k);

					cryptor_list = GetOpcodeCryptorList(cur_vm_command);
					d = 0;
					for (c = 0; c < cryptor_list.size(); c++) {
						cryptor = cryptor_list[c];
						os = cryptor->size();
						crc.SetValue(os, cryptor->EncryptOpcode(crc.GetValue(os), cur_vm_command->dump_value(os, d)));
						d += OperandSizeToValue(os);
					}

					if (vm_command == cur_vm_command)
						break;
				}
			}

			size_t e = use_ext_entry ? command->IndexOf(ext_vm_entry) : command->count();

			for (k = e; k > 0; k--) {
				IntelVMCommand* cur_vm_command = command->item(k - 1);
				if (vm_command == cur_vm_command)
					break;

				cryptor_list = GetOpcodeCryptorList(cur_vm_command);
				d = cur_vm_command->dump_size();
				for (c = cryptor_list.size(); c > 0; c--) {
					cryptor = cryptor_list[c - 1];
					os = cryptor->size();
					crc2.SetValue(os, cryptor->DecryptOpcode(crc2.GetValue(os), cur_vm_command->dump_value(os, d - OperandSizeToValue(os))));
					d -= OperandSizeToValue(os);
				}
			}

			break;
		}

		if (type() == vtAdvanced) {
			j = (vm_command->options() & voBeginOffset) ? 4 : 0;
		}
		else {
			j = 1;
		}
		cryptor = vm_command->opcode()->value_cryptor();
		vm_command->set_dump_value(vm_command->size(), j, cryptor->EncryptOpcode(cryptor->DecryptOpcode(vm_command->dump_value(vm_command->size(), j), crc.Value), crc2.Value));
	}

	for (i = block.start_index(); i <= block.end_index(); i++) {
		IntelCommand* command = func->item(i);
		uint64_t address = command->vm_address();
		if (command->section_options() & rtBeginSection)
			crc.Value = command->vm_address();
		for (j = 0; j < command->count(); j++) {
			IntelVMCommand* vm_command = command->item(j);
			if (vm_command->is_data())
				continue;

			cryptor_list = GetOpcodeCryptorList(vm_command);
			d = 0;
			for (c = 0; c < cryptor_list.size(); c++) {
				cryptor = cryptor_list[c];
				os = cryptor->size();
				uint64_t old_value = vm_command->dump_value(os, d);
				vm_command->set_dump_value(os, d, cryptor->DecryptOpcode(cryptor->Decrypt(old_value), crc.Value));
				crc.SetValue(os, cryptor->EncryptOpcode(crc.Value, old_value));
				d += OperandSizeToValue(os);
			}

			if (vm_command->is_end()) {
				if (command->section_options() & rtBackwardDirection) {
					crc.Value = address - vm_command->dump_size();
				}
				else {
					crc.Value = address + vm_command->dump_size();
				}
			}

			if (command->section_options() & rtBackwardDirection) {
				address -= vm_command->dump_size();
			}
			else {
				address += vm_command->dump_size();
			}
		}
	}
}

void IntelVirtualMachine::AddExtJmpCommand(uint8_t id)
{
	IntelOpcodeInfo* opcode = GetOpcode(cmJmp, otNone, processor_->cpu_address_size(), id);
	if (!opcode)
		throw std::runtime_error("Runtime error at AddExtJmpCommand");
	if (type_ == vtAdvanced) {
		ext_jmp_command_ = new IntelCommand(NULL, processor_->cpu_address_size());
		ext_jmp_command_->set_address(opcode->entry()->address());
	}
	IntelOpcodeInfo* ext_jmp_opcode = opcode_list_.Add(cmJmp, otNone, processor_->cpu_address_size(), 0xff, (type() == vtAdvanced) ? ext_jmp_command_ : opcode->entry());
	ext_jmp_opcode->set_opcode(opcode->opcode());
	opcode_stack_[ext_jmp_opcode->Key()].push_back(ext_jmp_opcode);
}

