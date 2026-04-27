#include "IntelObfuscation.h"
#include "IntelFunction.h"
#include "IntelFunctionList.h"
#include "IntelCommand.h"
#include "IntelVMCommand.h"
#include "../../processors.h"
#include "../../core.h"
#include "../../lang.h"
#include "../../../runtime/crypto.h"
#include "../vm/IntelVirtualMachine.h"

// Copied from intel.cc: IntelObfuscation implementation
// Line range: ~17083 - 18992
/*
* IntelObfuscation
*/

IntelObfuscation::IntelObfuscation()
	: IObject(), func_(NULL)
{

}

IntelCommand* IntelObfuscation::AddCommand(IntelCommandType command_type, IntelOperand operand1, IntelOperand operand2, IntelOperand operand3)
{
	if (command_type != cmLea && registr_values_.count()) {
		for (size_t i = 0; i < 2; i++) {
			IntelOperand* operand = (i == 0) ? &operand1 : &operand2;
			uint16_t type = operand->type & (otMemory | otBaseRegistr | otRegistr);
			if (type == (otMemory | otBaseRegistr) || type == (otMemory | otRegistr)) {
				IntelRegistrValue* reg_value = registr_values_.item(rand() % registr_values_.count());
				if ((operand->type & otRegistr) && !operand->scale_registr) {
					operand->base_registr = operand->registr;
					operand->type -= otRegistr;
					operand->type |= otBaseRegistr;
				}
				if (operand->type & otBaseRegistr) {
					operand->scale_registr = rand() & 3;
					uint64_t tmp = operand->value - (reg_value->value() << operand->scale_registr);
					if (DWordToInt64(static_cast<uint32_t>(tmp)) == tmp) {
						operand->type |= (otRegistr | otValue);
						operand->registr = reg_value->registr();
						operand->value = tmp;
						operand->value_size = osDWord;
					}
				}
			}
		}
	}

	IntelCommand* command = new IntelCommand(func_, func_->cpu_address_size(), command_type, operand1, operand2, operand3);
	command_list_.push_back(command);
	return command;
}

void IntelObfuscation::AddRestoreStackItem(IntelStackValue* stack_item)
{
	if (stack_item && stack_item->type() == vtRegistr && stack_item->value() != regEmpty) {
		if (stack_item->is_modified()) {
			uint8_t reg = static_cast<uint8_t>(stack_item->value());
			OperandSize cpu_address_size = func_->cpu_address_size();
			uint64_t value = (stack_.count() - 1 - stack_.IndexOf(stack_item)) * OperandSizeToStack(cpu_address_size);

			if (reg == regEFX) {
				AddCommand(cmPush, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size, regESP, value));
				AddCommand(cmPopf, IntelOperand(otNone, cpu_address_size, 0));

				flags_.clear();
			}
			else {
				AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size, reg), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size, regESP, value));

				IntelRegistrValue* reg_value = registr_values_.GetRegistr(reg);
				if (reg_value)
					delete reg_value;
			}
		}
		stack_item->set_value(regEmpty);
		stack_item->set_is_modified(false);
	}
}

void IntelObfuscation::AddRestoreRegistr(uint8_t reg)
{
	if (IntelStackValue* stack_item = stack_.GetRegistr(reg))
		AddRestoreStackItem(stack_item);
}

void IntelObfuscation::AddRestoreStack(size_t to_index)
{
	size_t i;
	for (i = stack_.count(); i > to_index; i--) {
		IntelStackValue* stack_item = stack_.item(i - 1);
		AddRestoreStackItem(stack_item);
	}
	size_t value = 0;
	OperandSize cpu_address_size = func_->cpu_address_size();
	for (i = stack_.count(); i > to_index; i--) {
		delete stack_.item(i - 1);
		value += OperandSizeToStack(cpu_address_size);
	}
	if (value)
		AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, regESP), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size, regESP, value));
}

void IntelObfuscation::Compile(IntelFunction* func, size_t index)
{
	size_t end_index = -1; bool for_virtualization = false;

	func_ = func;
	flags_.clear();
	stack_.clear();
	registr_values_.clear();

	size_t i, j, old_count;
	IntelCommand* command;
	IntelStackValue* stack_item;
	IntelRegistrValue* reg_value;
	uint8_t reg;
	OperandSize cpu_address_size = func_->cpu_address_size();
	bool need_update;
	IntelOperand new_operand[3];

	while (index < func_->count()) {
		command = func_->item(index);
		func_->erase(index);

		if (command->section_options() & (rtLinkedToInt | rtLinkedToExt))
			AddRestoreStack(0);

		old_count = command_list_.size();

		AddRandomCommands();

		if (stack_.count()) {
			switch (command->type()) {
			case cmPop:
				reg = command->operand(0).registr;

				command->Init(cmMov, IntelOperand(otRegistr, cpu_address_size, reg), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size, regESP, stack_.count() * OperandSizeToStack(cpu_address_size)));

				stack_item = stack_.GetRegistr(reg);
				if (stack_item)
					stack_item->set_value(regEmpty);

				reg_value = registr_values_.GetRegistr(reg);
				if (reg_value)
					delete reg_value;

				stack_.Insert(0, vtRegistr, regEmpty);
				break;

			case cmPush:
			case cmPushf:
				stack_item = stack_.item(0);
				AddRestoreStackItem(stack_item);
				delete stack_item;

				if (command->type() == cmPushf) {
					AddCommand(cmPushf, IntelOperand(otNone, cpu_address_size, 0));
					command->Init(cmPop, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size, regESP, stack_.count() * OperandSizeToStack(cpu_address_size)));
				}
				else {
					IntelOperand first_operand = command->operand(0);
					if (first_operand.type == otValue) {
						if (first_operand.value_size == osQWord)
							first_operand.value_size = osDWord;
					}
					else if (first_operand.type == otRegistr)
						AddRestoreRegistr(first_operand.registr);

					command->Init(cmMov, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size, regESP, stack_.count() * OperandSizeToStack(cpu_address_size)), first_operand);
					if (command->link() && command->link()->operand_index() == 0)
						command->link()->set_operand_index(1);
				}
				break;

			case cmCall:
				if ((command->options() & roUseAsJmp) && command->link()) {
					size_t ret_pos = rand() % stack_.count();

					for (j = stack_.count(); j > 0; j--) {
						IntelStackValue* stack_item = stack_.item(j - 1);
						AddRestoreStackItem(stack_item);
					}
					uint64_t value = (stack_.count() - ret_pos - 1) * OperandSizeToStack(cpu_address_size);
					if (value)
						AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size, regESP), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size, regESP, value));

					stack_.clear();

					command_list_.push_back(command);

					j = command_list_.size();
					AddRandomCommands();

					stack_item = stack_.GetRegistr(regEFX);
					if (!stack_item) {
						AddCommand(cmPushf, IntelOperand(otNone, func_->cpu_address_size(), 0));
						stack_item = stack_.Add(vtRegistr, regEFX);
					}
					stack_item->set_is_modified(true);

					IntelCommand* add_command = AddCommand(cmAdd, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size, regESP, stack_.count() * OperandSizeToStack(cpu_address_size)),
						IntelOperand(otValue, cpu_address_size, 0, 0));

					flags_.clear();

					CommandLink* link = add_command->AddLink(1, ltDelta, command->link()->to_command());
					link->set_parent_command(command);
					link->set_sub_value(5);

					command->link()->set_to_command(command_list_[j]);

					AddRandomCommands();

					command = new IntelCommand(func_, cpu_address_size, cmRet, ret_pos ? IntelOperand(otValue, osWord, 0, ret_pos * OperandSizeToStack(cpu_address_size)) : IntelOperand());
				}
				AddRestoreStack(0);
				break;
			case cmRet:
			case cmJmp:
			case cmJmpWithFlag:
				AddRestoreStack(0);
				break;
			}
		}

		if (command_list_.size() > old_count && command->section_options() & (rtLinkedToInt | rtLinkedToExt)) {
			IntelCommand* dst_command = command_list_[old_count];
			IntelCommandType dst_type = (IntelCommandType)dst_command->type();
			IntelOperand dst_operand[3];
			for (i = 0; i < _countof(dst_operand); i++) {
				dst_operand[i] = dst_command->operand(i);
			}
			uint16_t dst_flags = dst_command->flags();
			uint32_t dst_options = dst_command->options();
			CommandLink* dst_link = dst_command->link();
			if (dst_link)
				dst_link->set_from_command(NULL);

			dst_command->Init(static_cast<IntelCommandType>(command->type()), command->operand(0), command->operand(1), command->operand(2));
			dst_command->set_flags(command->flags());
			dst_command->exclude_option((CommandOption)UINT32_MAX);
			dst_command->include_option((CommandOption)command->options());
			if (command->link())
				command->link()->set_from_command(dst_command);

			command->Init(dst_type, dst_operand[0], dst_operand[1], dst_operand[2]);
			command->set_flags(dst_flags);
			command->exclude_option((CommandOption)UINT32_MAX);
			command->include_option((CommandOption)dst_options);
			if (dst_link)
				dst_link->set_from_command(command);

			command_list_[old_count] = command;
			command = dst_command;
		}

		command_list_.push_back(command);
	}

	for (i = 0; i < command_list_.size(); i++) {
		command = command_list_[i];

		// optimize operands
		need_update = false;
		for (j = 0; j < _countof(new_operand); j++) {
			IntelOperand* operand = &new_operand[j];
			*operand = command->operand(j);

			if ((operand->type & (otMemory | otValue)) == (otMemory | otValue) && (operand->type & (otBaseRegistr | otRegistr))) {
				if (operand->fixup || operand->is_large_value)
					continue;

				if (command->link() && command->link()->operand_index() == (int)j)
					continue;

				if (operand->value_size != osByte && ByteToInt64(static_cast<uint8_t>(operand->value)) == operand->value) {
					operand->value_size = osByte;
					need_update = true;
				}
			}
		}
		if (need_update)
			command->Init(static_cast<IntelCommandType>(command->type()), new_operand[0], new_operand[1], new_operand[2]);

		command->CompileToNative();
		if (command->link() && !command->link()->to_command()) {
			std::map<IntelCommand*, size_t>::const_iterator it = jmp_command_list_.find(command);
			if (it != jmp_command_list_.end()) {
				IntelCommand* to_command;
				if (command->type() == cmJmpWithFlag && (command->options() & roUseAsJmp) == 0) {
					while (true) {
						j = rand() % command_list_.size();
						if (j == it->second || j == it->second + 1)
							continue;
						to_command = command_list_[j];
						break;
					}
				}
				else
					to_command = command_list_[it->second];
				command->link()->set_to_command(to_command);
			}
		}

		func_->AddObject(command);
	}
}

#define NEED_STORE_FLAGS reinterpret_cast<IntelStackValue *>(-1)

void IntelObfuscation::AddRandomCommands()
{
	size_t i, j, c;
	IntelCommand* new_command, * last_command;
	std::vector<IntelCommandType> template_command_list;
	IntelCommandType command_type;
	uint8_t reg;
	OperandSize cpu_address_size = func_->cpu_address_size();
	uint8_t registr_count = (cpu_address_size == osDWord) ? 8 : 16;
	IntelStackValue* stack_item;
	IntelRegistrValue* reg_value;
	uint16_t command_flags;
	uint64_t source_value;
	OperandSize size;

	c = 30 + (rand() % 10);
	for (i = 0; i < c; i++) {

		last_command = command_list_.empty() ? NULL : command_list_.back();

		template_command_list.clear();
		template_command_list.push_back(cmPush);
		if (stack_.count()) {
			template_command_list.push_back(cmPop);
			if (stack_.count() < 20) {
				template_command_list.push_back(cmPush);
				if (last_command && last_command->type() != cmCall) {
					template_command_list.push_back(cmCall);
					template_command_list.push_back(cmCall);
					template_command_list.push_back(cmCall);
					template_command_list.push_back(cmCall);

					template_command_list.push_back(cmRet);
					template_command_list.push_back(cmRet);
					template_command_list.push_back(cmRet);
					template_command_list.push_back(cmRet);
					template_command_list.push_back(cmRet);
				}
			}
			template_command_list.push_back(cmLea);
			template_command_list.push_back(cmMov);
			template_command_list.push_back(cmMovsx);
			template_command_list.push_back(cmMovzx);

			template_command_list.push_back(cmCbw);
			template_command_list.push_back(cmCwde);
			template_command_list.push_back(cmCwd);
			template_command_list.push_back(cmCdq);
			if (cpu_address_size == osQWord) {
				template_command_list.push_back(cmCdqe);
				template_command_list.push_back(cmCqo);
			}
			template_command_list.push_back(cmBswap);

			if (last_command && (last_command->type() != cmCmp || flags_.mask() == 0)) {
				template_command_list.push_back(cmAdd);
				template_command_list.push_back(cmSub);
				template_command_list.push_back(cmNeg);
				template_command_list.push_back(cmCmp);

				template_command_list.push_back(cmAnd);
				template_command_list.push_back(cmTest);
				template_command_list.push_back(cmXor);
				template_command_list.push_back(cmOr);
				template_command_list.push_back(cmNot);

				template_command_list.push_back(cmShr);
				template_command_list.push_back(cmShl);
				template_command_list.push_back(cmSal);
				template_command_list.push_back(cmSar);
				template_command_list.push_back(cmRol);
				template_command_list.push_back(cmRor);
			}

			template_command_list.push_back(cmBt);
			template_command_list.push_back(cmBtr);
			template_command_list.push_back(cmBtc);
			template_command_list.push_back(cmBts);

			if (flags_.mask()) {
				template_command_list.push_back(cmJmpWithFlag);
				template_command_list.push_back(cmJmpWithFlag);
				template_command_list.push_back(cmJmpWithFlag);
				template_command_list.push_back(cmJmpWithFlag);
				template_command_list.push_back(cmJmpWithFlag);

				template_command_list.push_back(cmSetXX);
				template_command_list.push_back(cmCmov);
				if (flags_.mask() & fl_C) {
					if (last_command && last_command->type() != cmCmc && last_command->type() != cmClc && last_command->type() != cmStc) {
						template_command_list.push_back((flags_.value() & fl_C) ? cmClc : cmStc);
						template_command_list.push_back(cmCmc);
					}
					template_command_list.push_back(cmAdc);
					template_command_list.push_back(cmSbb);
				}
			}
		}

		command_type = template_command_list[rand() % template_command_list.size()];
		switch (command_type) {
		case cmPush:
			if (rand() & 1) {
				reg = rand() % registr_count;
				if (reg == regESP)
					reg = regEFX;

				if (!registr_values_.GetRegistr(reg)) {
					if (stack_.GetRegistr(reg))
						break;
				}

				if (reg == regEFX)
					AddCommand(cmPushf, IntelOperand(otNone, func_->cpu_address_size(), 0));
				else
					AddCommand(cmPush, IntelOperand(otRegistr, func_->cpu_address_size(), reg));

				reg_value = registr_values_.GetRegistr(reg);
				if (reg_value)
					stack_.Add(reg_value->type(), reg_value->value());
				else
					stack_.Add(vtRegistr, reg);
			}
			else {
				uint64_t value = DWordToInt64(rand32());
				AddCommand(cmPush, IntelOperand(otValue, cpu_address_size, 0, value));
				stack_.Add(vtValue, value);
			}
			break;

		case cmPop:
			AddRestoreStack(stack_.count() - 1);
			break;

		case cmCall:
			stack_.Add(vtReturnAddress, command_list_.size());

			new_command = AddCommand(cmCall, IntelOperand(otValue, cpu_address_size, 0));
			new_command->AddLink(0, ltCall);
			new_command->include_option(roUseAsJmp);

			jmp_command_list_[new_command] = command_list_.size();
			break;

		case cmRet:
			if (IntelStackValue* ret_item = stack_.GetRandom(vtReturnAddress)) {
				size_t ret_pos = stack_.IndexOf(ret_item);
				IntelCommand* call_command = command_list_[static_cast<size_t>(ret_item->value())];
				j = static_cast<size_t>(call_command->operand(2).value);
				if (j == 0) {
					stack_item = stack_.GetRegistr(regEFX);
					if (!stack_item) {
						AddCommand(cmPushf, IntelOperand(otNone, func_->cpu_address_size(), 0));
						stack_item = stack_.Add(vtRegistr, regEFX);
					}
					stack_item->set_is_modified(true);

					call_command->set_operand_value(2, command_list_.size());

					AddCommand(cmAdd, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size, regESP, (stack_.count() - 1 - ret_pos) * OperandSizeToStack(cpu_address_size)),
						IntelOperand(otValue, cpu_address_size, 0, DWordToInt64(rand32())));

					flags_.clear();
				}
				else {
					IntelCommand* add_command = command_list_[j];
					CommandLink* link = add_command->AddLink(1, ltDelta);
					link->set_parent_command(call_command);
					link->set_sub_value(5);

					AddRestoreStack(ret_pos + 1);
					delete ret_item;

					source_value = 0;
					for (j = stack_.count(); j > 0; j--) {
						stack_item = stack_.item(j - 1);
						if (stack_item->type() == vtValue || stack_item->type() == vtReturnAddress || (stack_item->type() == vtRegistr && stack_item->value() == regEmpty)) {
							if (rand() & 1)
								break;

							delete stack_item;
							source_value += OperandSizeToStack(cpu_address_size);
						}
						else
							break;
					}
					if (source_value)
						AddCommand(cmRet, IntelOperand(otValue, osWord, 0, source_value));
					else
						AddCommand(cmRet);

					jmp_command_list_[add_command] = command_list_.size();
				}
			}
			break;

		case cmJmpWithFlag:
			command_flags = flags_.GetRandom();
			if (!command_flags)
				break;

			new_command = AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size, 0));
			new_command->AddLink(0, ltJmpWithFlag);
			new_command->set_flags(command_flags);
			if (rand() & 1)
				new_command->include_option(roInverseFlag);

			if (flags_.Check(new_command->flags()) == ((new_command->options() & roInverseFlag) == 0))
				new_command->include_option(roUseAsJmp);

			jmp_command_list_[new_command] = command_list_.size();
			break;

		case cmCbw:
		case cmCwde:
		case cmCdqe:
			reg_value = registr_values_.GetRegistr(regEAX);
			if (!reg_value)
				break;

			AddCommand(command_type);

			switch (command_type) {
			case cmCbw:
				size = osWord;
				break;
			case cmCwde:
				size = osDWord;
				break;
			default:
				size = osQWord;
				break;
			}

			reg_value->Calc(command_type, 0, false, size, reg_value->value(), &flags_);
			if (cpu_address_size == osQWord && size == osDWord)
				reg_value->set_value(static_cast<uint32_t>(reg_value->value()));
			break;

		case cmCwd:
		case cmCdq:
		case cmCqo:
			reg_value = registr_values_.GetRegistr(regEAX);
			if (!reg_value)
				break;

			source_value = reg_value->value();

			switch (command_type) {
			case cmCwd:
				size = osWord;
				break;
			case cmCdq:
				size = osDWord;
				break;
			default:
				size = osQWord;
				break;
			}

			reg_value = registr_values_.GetRegistr(regEDX);
			if (!reg_value) {
				if (size != cpu_address_size)
					break;

				stack_item = stack_.GetRegistr(regEDX);
				if (!stack_item) {
					AddCommand(cmPush, IntelOperand(otRegistr, cpu_address_size, regEDX));
					stack_item = stack_.Add(vtRegistr, regEDX);
				}
				stack_item->set_is_modified(true);

				reg_value = registr_values_.Add(regEDX, 0);
			}

			AddCommand(command_type);

			reg_value->Calc(command_type, 0, false, size, source_value, &flags_);
			if (cpu_address_size == osQWord && size == osDWord)
				reg_value->set_value(static_cast<uint32_t>(reg_value->value()));
			break;

		case cmStc:
		case cmCmc:
		case cmClc:
			if (flags_.mask() & fl_C) {
				stack_item = stack_.GetRegistr(regEFX);
				if (!stack_item)
					break;
				stack_item->set_is_modified(true);

				flags_.Calc(command_type, cpu_address_size, 0, 0, 0);
				AddCommand(command_type);
			}
			break;

		default:
			if (IntelStackValue* first_item = stack_.GetRandom(vtRegistr | vtValue)) {
				source_value = 0;

				command_flags = 0;
				bool inverse_flags = false;
				IntelStackValue* flags_item = NULL;

				if (command_type == cmSetXX || command_type == cmCmov) {
					command_flags = flags_.GetRandom();
					if (!command_flags)
						break;

					if (rand() & 1)
						inverse_flags = true;
				}
				else switch (command_type) {
				case cmXor:
				case cmAnd:
				case cmTest:
				case cmOr:
				case cmNeg:
				case cmAdd:
				case cmAdc:
				case cmSub:
				case cmSbb:
				case cmCmp:
				case cmRor:
				case cmRol:
				case cmShr:
				case cmShl:
				case cmSar:
				case cmSal:
				case cmDec:
				case cmInc:
				case cmBt:
				case cmBtr:
				case cmBtc:
				case cmBts:
					flags_item = stack_.GetRegistr(regEFX);
					if (!flags_item)
						flags_item = NEED_STORE_FLAGS;
					break;
				}

				IntelOperand first_operand, second_operand;

				switch (rand() % 4) {
				case 0:
					first_operand.size = osByte;
					break;
				case 1:
					first_operand.size = osWord;
					break;
				case 2:
					first_operand.size = osDWord;
					break;
				default:
					first_operand.size = cpu_address_size;
					break;
				}

				if (first_item->type() == vtRegistr) {
					first_operand.type = otRegistr;
					first_operand.registr = static_cast<uint8_t>(first_item->value());

					if (!registr_values_.GetRegistr(first_operand.registr)) {
						command_type = cmMov;
						first_operand.size = cpu_address_size;
					}
				}
				else {
					first_operand.type = otMemory | otBaseRegistr | otValue;
					first_operand.base_registr = regESP;
					first_operand.value = (stack_.count() - 1 - stack_.IndexOf(first_item)) * OperandSizeToStack(cpu_address_size);
					if (flags_item == NEED_STORE_FLAGS)
						first_operand.value += OperandSizeToStack(cpu_address_size);
				}

				if (command_type == cmLea) {
					if (first_operand.type != otRegistr || !registr_values_.count())
						break;

					first_operand.size = cpu_address_size;
					second_operand.size = first_operand.size;

					reg_value = registr_values_.item(rand() % registr_values_.count());

					second_operand.type = otMemory | otRegistr | otValue;
					second_operand.registr = reg_value->registr();
					second_operand.scale_registr = rand() & 3;

					source_value = reg_value->value();
					if (second_operand.scale_registr)
						source_value = source_value << second_operand.scale_registr;

					if (rand() & 1) {
						reg_value = registr_values_.item(rand() % registr_values_.count());
						second_operand.type |= otBaseRegistr;
						second_operand.base_registr = reg_value->registr();
						source_value = source_value + reg_value->value();
					}

					second_operand.value_size = second_operand.size;
					switch (second_operand.size) {
					case osByte:
						second_operand.value = ByteToInt64(rand32());
						break;
					case osWord:
						second_operand.value = WordToInt64(rand32());
						break;
					default:
						second_operand.value = DWordToInt64(rand32());
						second_operand.value_size = osDWord;
						break;
					}
					source_value = source_value + second_operand.value;
				}
				else if (command_type == cmSetXX) {
					first_operand.size = osByte;
				}
				else if (command_type == cmShr || command_type == cmShl || command_type == cmSal || command_type == cmSar || command_type == cmRol || command_type == cmRor) {
					second_operand.size = osByte;
					switch (rand() % 2) {
					case 0:
						reg_value = registr_values_.GetRegistr(regECX);
						if (reg_value) {
							second_operand.type = otRegistr;
							second_operand.registr = reg_value->registr();

							source_value = reg_value->value();
							break;
						}
					default:
						second_operand.type = otValue;
						second_operand.value = static_cast<uint8_t>(rand());
						if (!second_operand.value)
							second_operand.value = 1;
						second_operand.value_size = second_operand.size;

						source_value = second_operand.value;
						break;
					}
				}
				else if (command_type != cmNot && command_type != cmNeg && command_type != cmBswap) {
					second_operand.size = first_operand.size;
					switch (rand() % 3) {
					case 0:
						if (registr_values_.count()) {
							reg_value = registr_values_.item(rand() % registr_values_.count());
							source_value = reg_value->value();

							second_operand.type = otRegistr;
							second_operand.registr = reg_value->registr();
							break;
						}
					case 1:
						if (first_operand.type == otRegistr) {
							stack_item = stack_.GetRandom(otValue);
							if (stack_item) {
								source_value = stack_item->value();

								second_operand.type = otMemory | otBaseRegistr | otValue;
								second_operand.base_registr = regESP;
								second_operand.value = (stack_.count() - 1 - stack_.IndexOf(stack_item)) * OperandSizeToStack(cpu_address_size);
								if (flags_item == NEED_STORE_FLAGS)
									second_operand.value += OperandSizeToStack(cpu_address_size);
								break;
							}
						}
					default:
						second_operand.type = otValue;
						second_operand.value_size = second_operand.size;
						switch (second_operand.size) {
						case osByte:
							second_operand.value = ByteToInt64(rand32());
							break;
						case osWord:
							second_operand.value = WordToInt64(rand32());
							break;
						case osQWord:
							if (command_type == cmMov && first_operand.type == otRegistr) {
								second_operand.value = rand64();
								break;
							}
						default:
							second_operand.value = DWordToInt64(rand32());
							second_operand.value_size = osDWord;
							break;
						}

						source_value = second_operand.value;
					}
				}

				if (command_type == cmCmov) {
					if (first_operand.type != otRegistr || first_operand.size == osByte || second_operand.type == otValue)
						break;
				}
				else if (command_type == cmMovsx || command_type == cmMovzx) {
					if (first_operand.type != otRegistr || first_operand.size == osByte || second_operand.type == otValue)
						break;

					second_operand.size = rand() & 1 ? osByte : osWord;
					if (first_operand.size == osQWord && command_type == cmMovsx && (rand() & 1)) {
						command_type = cmMovsxd;
						second_operand.size = osDWord;
					}

					if (command_type == cmMovzx) {
						switch (second_operand.size) {
						case osByte:
							source_value = static_cast<uint8_t>(source_value);
							break;
						case osWord:
							source_value = static_cast<uint16_t>(source_value);
							break;
						case osDWord:
							source_value = static_cast<uint32_t>(source_value);
							break;
						}
					}
					else {
						switch (second_operand.size) {
						case osByte:
							source_value = ByteToInt64(static_cast<uint8_t>(source_value));
							break;
						case osWord:
							source_value = WordToInt64(static_cast<uint16_t>(source_value));
							break;
						case osDWord:
							source_value = DWordToInt64(static_cast<uint32_t>(source_value));
							break;
						}
					}
				}
				else if (command_type == cmBt || command_type == cmBtr || command_type == cmBtc || command_type == cmBts) {
					if (first_operand.size == osByte || first_operand.type != otRegistr || (second_operand.type & otMemory))
						break;

					if (second_operand.type == otValue) {
						second_operand.size = osByte;
						second_operand.value_size = osByte;
						second_operand.value = static_cast<uint8_t>(second_operand.value);
						source_value = second_operand.value;
					}
				}
				else if (command_type == cmBswap) {
					if (first_operand.size == osByte || first_operand.size == osWord || first_operand.type != otRegistr)
						break;
				}

				if (cpu_address_size == osDWord) {
					if (first_operand.type == otRegistr && first_operand.size == osByte && first_operand.registr >= 4)
						break;
					if (second_operand.type == otRegistr && second_operand.size == osByte && second_operand.registr >= 4)
						break;
				}

				if (flags_item == NEED_STORE_FLAGS) {
					AddCommand(cmPushf, IntelOperand(otNone, func_->cpu_address_size(), 0));
					flags_item = stack_.Add(vtRegistr, regEFX);
				}
				if (flags_item)
					flags_item->set_is_modified(true);

				new_command = AddCommand(command_type, first_operand, second_operand);
				if (command_flags) {
					new_command->set_flags(command_flags);
					if (inverse_flags)
						new_command->include_option(roInverseFlag);
				}

				if (first_operand.type == otRegistr) {
					bool is_modified = (command_type != cmCmp && command_type != cmTest && command_type != cmBt);
					if (is_modified)
						first_item->set_is_modified(true);
					reg_value = registr_values_.GetRegistr(first_operand.registr);
					if (reg_value) {
						reg_value->Calc(command_type, command_flags, inverse_flags, first_operand.size, source_value, &flags_);
						if (is_modified) {
							if (cpu_address_size == osQWord && first_operand.size == osDWord)
								reg_value->set_value(static_cast<uint32_t>(reg_value->value()));
						}
					}
					else
						registr_values_.Add(first_operand.registr, source_value);
				}
				else {
					first_item->Calc(command_type, command_flags, inverse_flags, first_operand.size, source_value, &flags_);
				}
			}
			break;
		}
	}
}

