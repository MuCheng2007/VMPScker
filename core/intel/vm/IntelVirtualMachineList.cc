#include "IntelVirtualMachineList.h"
#include "IntelVirtualMachine.h"
#include "IntelVirtualMachineProcessor.h"
#include "../ir/IntelFunction.h"
#include "../ir/IntelFunctionList.h"
#include "../ir/IntelOpcodeInfo.h"
#include "../../processors.h"
#include "../../files.h"
#include "../../core_internal/core.h"

/*
 * IntelVirtualMachineList
 */

IntelVirtualMachineList::IntelVirtualMachineList()
	: IVirtualMachineList()
{
	crc_manager_ = new MemoryManager(NULL);
}

IntelVirtualMachineList::~IntelVirtualMachineList()
{
	delete crc_manager_;
}

IntelVirtualMachineList* IntelVirtualMachineList::Clone() const
{
	IntelVirtualMachineList* list = new IntelVirtualMachineList();
	return list;
}

void IntelVirtualMachineList::Prepare(const CompileContext& ctx)
{
	size_t i;
	IntelOpcodeList visible_opcode_list;
	OperandSize cpu_address_size = ctx.file->cpu_address_size();

	VirtualMachineType type =

		((ctx.options.flags & cpClassicVM) != 0) ? vtClassic : vtAdvanced;

	if (ctx.runtime) {
		visible_opcode_list.Add(cmCall, otNone, cpu_address_size, 0);
		visible_opcode_list.Add(cmCpuid, otNone, cpu_address_size, 0);
		visible_opcode_list.Add(cmCrc, otNone, cpu_address_size, 0);
	}

	if (ctx.options.flags & cpMemoryProtection) {
		visible_opcode_list.Add(cmRdtsc, otNone, cpu_address_size, 0);
		visible_opcode_list.Add(cmDiv, otNone, osDWord, true);
		visible_opcode_list.Add(cmMul, otNone, osDWord, true);
	}

	IntelCommandInfoList command_info_list(cpu_address_size);

	size_t n = ctx.runtime ? 2 : 1;
	for (size_t k = 0; k < n; k++) {
		IntelFunctionList* function_list = (k == 0) ? reinterpret_cast<IntelFunctionList*>(ctx.file->function_list()) : reinterpret_cast<IntelFunctionList*>(ctx.runtime->function_list());

		for (size_t i = 0; i < function_list->count(); i++) {
			IntelFunction* func = function_list->item(i);

			if (func->compilation_type() == ctMutation || (k == 1 && func->tag() != ftLoader))
				continue;

			if (func->compilation_options() & coLockToKey)
				visible_opcode_list.Add(cmCall, otNone, cpu_address_size, 0);

			for (size_t j = 0; j < func->count(); j++) {
				IntelCommand* command = func->item(j);
				if (command->link() && command->link()->type() == ltNative)
					continue;

				if ((command->options() & roLockPrefix) && command->type() != cmXchg) {
					if (type == vtAdvanced) { //-V547
						bool native_found = true;
						switch (command->type()) {
						case cmAdd: case cmSub: case cmAnd: case cmOr: case cmXor: case cmXadd:
							if (command->operand(0).type & otMemory)
								native_found = false;
							break;
						}
						if (!native_found) {
							command->include_option(roNoNative);
							size_t n = (command->operand(0).type & otMemory) ? 0 : 1;
							visible_opcode_list.Add(static_cast<IntelCommandType>(command->type()), otMemory, command->operand(0).size, command->operand(n).effective_base_segment(command->base_segment()));
						}
					}
					continue;
				}
				else
					switch (command->type()) {
					case cmWait: case cmFchs: case cmFsqrt: case cmF2xm1:
					case cmFabs: case cmFclex: case cmFcos: case cmFdecstp:
					case cmFincstp: case cmFinit: case cmFldln2: case cmFldz:
					case cmFld1: case cmFldpi: case cmFpatan: case cmFprem:
					case cmFprem1: case cmFptan: case cmFrndint: case cmFsin:
					case cmFtst: case cmFyl2x: case cmFldlg2:
					case cmRdtsc: case cmPopf: case cmIret:
						visible_opcode_list.Add(static_cast<IntelCommandType>(command->type()), otNone, cpu_address_size, 0);
						break;

					case cmFild: case cmFld: case cmFadd: case cmFsub: case cmFsubr:
					case cmFstp: case cmFst: case cmFdiv: case cmFmul: case cmFcomp:
					case cmFistp: case cmFist: case cmFisub:
					case cmFstsw: case cmFldcw: case cmFstcw:
						visible_opcode_list.Add(static_cast<IntelCommandType>(command->type()), otNone, command->operand(0).size, 0);
						break;

					case cmDiv: case cmIdiv: case cmMul: case cmImul: case cmRcl: case cmRcr:
						visible_opcode_list.Add(static_cast<IntelCommandType>(command->type()), otNone, command->operand(0).size, true);
						break;

					case cmRet:
						if (command->options() & roFar)
							visible_opcode_list.Add(static_cast<IntelCommandType>(command->type()), otNone, cpu_address_size, 1);
						break;

					case cmCpuid:
						if (k == 1)
							visible_opcode_list.Add(static_cast<IntelCommandType>(command->type()), otNone, cpu_address_size, 0);
						break;

					case cmSyscall:
						if (k == 1)
							visible_opcode_list.Add(static_cast<IntelCommandType>(command->type()), otNone, cpu_address_size, 0);
						break;

					case cmXchg:
						if (((command->operand(0).type | command->operand(1).type) & otMemory) && type == vtAdvanced) {
							command->include_option(roNoNative);
							size_t n = (command->operand(0).type & otMemory) ? 0 : 1;
							visible_opcode_list.Add(static_cast<IntelCommandType>(command->type()), otMemory, command->operand(0).size, command->operand(n).effective_base_segment(command->base_segment()));
						}
						break;
					}

				if (command->GetCommandInfo(command_info_list)) {
					for (size_t n = 0; n < command_info_list.count(); n++) {
						CommandInfo* command_info = command_info_list.item(n);
						IntelCommandType command_type = (command_info->type() == atRead) ? cmPush : cmPop;

						switch (command_info->operand_type()) {
						case otSegmentRegistr:
							visible_opcode_list.Add(command_type, command_info->operand_type(), osWord, command_info->value());
							break;
						case otControlRegistr:
						case otDebugRegistr:
							visible_opcode_list.Add(command_type, command_info->operand_type(), cpu_address_size, command_info->value());
							break;
						case otMemory:
							if (command_info->size() > cpu_address_size) {
								visible_opcode_list.Add(command_type, command_info->operand_type(), cpu_address_size, command_info->value());
								if (command_info->size() == osTByte)
									visible_opcode_list.Add(command_type, command_info->operand_type(), osWord, command_info->value());
							}
							else {
								visible_opcode_list.Add(command_type, command_info->operand_type(), command_info->size(), command_info->value());
							}
							break;
						}
					}
				}
			}
		}
	}

	IntelFunctionList* function_list = reinterpret_cast<IntelFunctionList*>(ctx.file->function_list());
	IntelVirtualMachineProcessor* processor = function_list->AddProcessor(cpu_address_size);
	for (i = 0; i < ctx.options.vm_count; i++) {
		IntelVirtualMachine* virtual_machine = new IntelVirtualMachine(this, type, (uint8_t)i + 1, processor);
		AddObject(virtual_machine);
		virtual_machine->Init(ctx, visible_opcode_list);
	}

	std::vector<IFunction*> processor_list = function_list->processor_list();
	for (i = 0; i < processor_list.size(); i++) {
		IFunction* func = processor_list[i];
		if (func->compilation_type() != ctMutation && func->cpu_address_size() != cpu_address_size) {
			IntelVirtualMachineProcessor* new_processor = function_list->AddProcessor(func->cpu_address_size());
			IntelVirtualMachine* virtual_machine = new IntelVirtualMachine(this, type, 1, new_processor);
			AddObject(virtual_machine);
			CompileContext new_ctx;
			new_ctx.options.vm_count = 1;
			new_ctx.options.flags = ctx.options.flags & (cpEncryptBytecode);

			new_ctx.file = ctx.file;
			visible_opcode_list.clear();
			visible_opcode_list.Add(cmRet, otNone, osQWord, 1);
			if (ctx.options.flags & cpMemoryProtection) {
				visible_opcode_list.Add(cmRdtsc, otNone, osQWord, 0);
				visible_opcode_list.Add(cmDiv, otNone, osDWord, true);
				visible_opcode_list.Add(cmMul, otNone, osDWord, true);
				visible_opcode_list.Add(cmCrc, otNone, osQWord, 0);
			}
			virtual_machine->Init(new_ctx, visible_opcode_list);
			break;
		}
	}

	for (i = 0; i < count(); i++) {
		item(i)->Prepare(ctx);
	}
}

uint64_t IntelVirtualMachineList::GetCRCValue(uint64_t& crc_address, size_t size)
{
	size_t i, j;

	if (map_.empty()) {
		std::set<IntelFunction*> processor_list;
		for (i = 0; i < count(); i++) {
			IntelFunction* processor = item(i)->processor();
			if (processor_list.find(processor) != processor_list.end())
				continue;

			processor_list.insert(processor);
			for (j = 0; j < processor->count(); j++) {
				IntelCommand* command = processor->item(j);
				if (command->options() & roNeedCRC)
					map_[command->address()] = command;
			}
		}
	}

	crc_address = crc_manager_->Alloc(size, mtReadable);
	if (!crc_address) {
		crc_manager_->clear();
		for (std::map<uint64_t, ICommand*>::const_iterator it = map_.begin(); it != map_.end(); it++) {
			ICommand* command = it->second;
			crc_manager_->Add(command->address(), command->dump_size(), mtReadable);
		}
		crc_manager_->Pack();
		crc_address = crc_manager_->Alloc(size, mtReadable);
	}

	if (crc_address) {
		std::map<uint64_t, ICommand*>::const_iterator it = map_.upper_bound(crc_address);
		if (it != map_.begin())
			it--;

		uint64_t address = crc_address;
		uint64_t value = 0;
		uint8_t* ptr = reinterpret_cast<uint8_t*>(&value);
		uint8_t* ptr_end = ptr + size;
		while (it != map_.end()) {
			ICommand* command = it->second;
			if (command->address() <= address && command->next_address() > address) {
				for (j = static_cast<size_t>(address - command->address()); j < command->dump_size(); j++) {
					*ptr = command->dump(j);
					ptr++;
					address++;
					if (ptr == ptr_end)
						return value;
				}
			}
			it++;
		}
	}

	throw std::runtime_error("Runtime error at GetCRCValue");
}

void IntelVirtualMachineList::ClearCRCMap()
{
	map_.clear();
	crc_manager_->clear();
}

