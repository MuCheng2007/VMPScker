#include "IntelVMCommand.h"
#include "../../files/utils.h"
#include "../../files/architecture.h"
#include "IntelCommand.h"
#include "IntelOpcodeInfo.h"
#include "../../processors.h"
#include "../../files/architecture.h"
#include "../../files/sections.h"
#include "../../files/types.h"
#include "../../../runtime/crypto.h"
#include "../vm/IntelVirtualMachine.h"

// Copied from intel.cc: IntelVMCommand implementation
// Line range: ~12641 - 12748
/*
 * IntelVMCommand
 */

IntelVMCommand::IntelVMCommand(IntelCommand* owner, IntelCommandType command_type, OperandType operand_type, OperandSize size, uint64_t value, uint32_t options)
	: BaseVMCommand(owner), address_(0), command_type_(command_type), operand_type_(operand_type), size_(size), value_(0), registr_(0), subtype_(0), base_segment_(segDefault), options_(options),
	crypt_command_(cmUnknown), crypt_size_(osDefault), crypt_key_(0), link_command_(NULL), opcode_(NULL), sub_value_(0), fixup_(NULL)
{
	switch (operand_type_) { //-V719
	case otBaseRegistr:
	case otRegistr:
	case otHiPartRegistr:
	case otSegmentRegistr:
	case otDebugRegistr:
	case otControlRegistr:
		registr_ = static_cast<uint8_t>(value);
		break;
	case otValue:
		value_ = value;
		break;
	case otMemory:
		base_segment_ = static_cast<IntelSegment>(value);
		break;
	case otNone:
		subtype_ = static_cast<uint8_t>(value);
		break;
	}
};

IntelVMCommand::IntelVMCommand(IntelCommand* owner, const IntelVMCommand& src)
	: BaseVMCommand(owner), address_(0), link_command_(NULL)
{
	command_type_ = src.command_type_;
	operand_type_ = src.operand_type_;
	size_ = src.size_;
	value_ = src.value_;
	registr_ = src.registr_;
	subtype_ = src.subtype_;
	base_segment_ = src.base_segment_;
	options_ = src.options_;
	crypt_command_ = src.crypt_command_;
	crypt_size_ = src.crypt_size_;
	crypt_key_ = src.crypt_key_;
	dump_ = src.dump_;
	opcode_ = src.opcode_;
	sub_value_ = src.sub_value_;
	fixup_ = src.fixup_;
}

IntelVMCommand* IntelVMCommand::Clone(IntelCommand* owner)
{
	IntelVMCommand* vm_command = new IntelVMCommand(owner, *this);
	return vm_command;
}

void IntelVMCommand::WriteToFile(IArchitecture& file)
{
	if (!dump_.size())
		return;

	if (fixup_) {
		if (fixup_ == NEED_FIXUP) {
			ISection* segment = file.segment_list()->GetSectionByAddress(address_);
			fixup_ = file.fixup_list()->AddDefault(file.cpu_address_size(), segment && (segment->memory_type() & mtExecutable) != 0);
		}
		fixup_->set_address(address_);
	}

	if (owner()->section_options() & rtBackwardDirection) {
		for (size_t i = dump_.size(); i > 0; i--) {
			file.WriteByte(dump_[i - 1]);
		}
	}
	else {
		file.Write(dump_.data(), dump_.size());
	}
}

int IntelVMCommand::GetStackLevel() const
{
	int res = 0;
	OperandSize cpu_address_size = reinterpret_cast<IntelCommand*>(owner())->size();

	switch (command_type_) {
	case cmPush:
		if (operand_type_ == otMemory)
			res -= OperandSizeToStack(cpu_address_size);
		res += OperandSizeToStack(size_);
		break;
	case cmPop:
		if (operand_type_ == otMemory)
			res -= OperandSizeToStack(cpu_address_size);
		res -= OperandSizeToStack(size_);
		break;
	case cmJmp:
		res -= OperandSizeToStack(size_);
		break;
	case cmNor: case cmNand:
		res -= OperandSizeToStack(size_);
		res += OperandSizeToStack(cpu_address_size);
		break;
	case cmShl: case cmShr: case cmRcl: case cmRcr:
		res -= OperandSizeToStack(osWord);
		res += OperandSizeToStack(cpu_address_size);
		break;
	case cmPopf:
		res -= OperandSizeToStack(cpu_address_size);
		break;
	case cmShld: case cmShrd:
		res -= OperandSizeToStack(size_);
		res -= OperandSizeToStack(osWord);
		res += OperandSizeToStack(cpu_address_size);
		break;
	case cmDiv: case cmIdiv: case cmMul: case cmImul:
		if (size_ == osByte)
			res -= OperandSizeToStack(size_);
		res += OperandSizeToStack(cpu_address_size);
		break;
	case cmRdtsc:
		res -= OperandSizeToStack(osDWord) * 2;
		break;
	case cmCpuid:
		res -= OperandSizeToStack(osDWord);
		res += OperandSizeToStack(osDWord) * 4;
		break;
	case cmCall: case cmSyscall:
		res -= OperandSizeToStack(cpu_address_size) * subtype_;
		break;
	case cmCrc:
		res -= OperandSizeToStack(cpu_address_size) * 2;
		res += OperandSizeToStack(osDWord);
		break;
	case cmAnd: case cmSub: case cmAdd: case cmOr: case cmXor: case cmXchg: case cmXadd:
		if (operand_type_ == otMemory) {
			res -= OperandSizeToStack(size_);
			res -= OperandSizeToStack(cpu_address_size);
			if (command_type_ == cmXchg)
				res += OperandSizeToStack(size_);
			else {
				res += OperandSizeToStack(cpu_address_size);
				if (command_type_ == cmXadd)
					res += OperandSizeToStack(size_);
			}
		}
		else {
			res -= OperandSizeToStack(size_);
			res += OperandSizeToStack(cpu_address_size);
		}
		break;
	}

	return res;
}

void IntelVMCommand::Compile()
{
	reinterpret_cast<IntelVirtualMachine*>(owner()->block()->virtual_machine())->CompileCommand(*this);
}

uint64_t IntelVMCommand::CorrectDumpValue(OperandSize size, uint64_t value) const
{
	if (owner()->section_options() & rtBackwardDirection) {
		switch (size) {
		case osWord:
			value = __builtin_bswap16(static_cast<uint16_t>(value));
			break;
		case osDWord:
			value = __builtin_bswap32(static_cast<uint32_t>(value));
			break;
		case osQWord:
			value = __builtin_bswap64(value);
			break;
		}
	}

	return value;
}

uint64_t IntelVMCommand::dump_value(OperandSize size, size_t pos) const
{
	if (pos + OperandSizeToValue(size) > dump_.size())
		throw std::runtime_error("Index out of bounds");
	uint64_t res = 0;
	memcpy(&res, &dump_[pos], OperandSizeToValue(size));
	return CorrectDumpValue(size, res);
}

void IntelVMCommand::set_dump_value(OperandSize size, size_t pos, uint64_t value)
{
	if (pos + OperandSizeToValue(size) > dump_.size())
		throw std::runtime_error("Index out of bounds");
	value = CorrectDumpValue(size, value);
	memcpy(&dump_[pos], &value, OperandSizeToValue(size));
}

bool IntelVMCommand::can_merge(CommandInfoList& command_info_list) const
{
	CommandInfo* command_info;
	switch (command_type_) {
	case cmPush:
		switch (operand_type_) {
		case otRegistr:
			if (registr_ != regEmpty) {
				if (command_info_list.GetInfo(atWrite, otRegistr, registr_))
					return false;

				command_info = command_info_list.GetInfo(atWrite, otHiPartRegistr, registr_);
				if (command_info && size_ > command_info->size())
					return false;
			}
			break;

		case otHiPartRegistr:
			if (registr_ != regEmpty) {
				command_info = command_info_list.GetInfo(atWrite, otRegistr, registr_);
				if (command_info && size_ < command_info->size())
					return false;

				command_info = command_info_list.GetInfo(atWrite, otHiPartRegistr, registr_);
				if (command_info && size_ == command_info->size())
					return false;
			}
			break;

		case otSegmentRegistr: case otControlRegistr: case otDebugRegistr:
			if (command_info_list.GetInfo(atWrite, operand_type_, registr_))
				return false;
			break;

		case otMemory:
			if (base_segment_ == segFS || base_segment_ == segGS)
				return false;

			if (command_info_list.GetInfo(atWrite, otMemory))
				return false;

			break;
		}
		break;

	case cmPop:
		switch (operand_type_) {
		case otRegistr:
			if (registr_ == regESP || (registr_ & regExtended))
				return false;
			if (registr_ != regEmpty) {
				for (size_t i = 0; i < command_info_list.count(); i++) {
					command_info = command_info_list.item(i);
					if (command_info->operand_type() == otRegistr && command_info->value() == registr_) {
						return false;
					}
					else  if (command_info->operand_type() == otHiPartRegistr && command_info->value() == registr_) {
						if (size_ > command_info->size())
							return false;
					}
				}
			}
			break;

		case otHiPartRegistr:
			if (registr_ == regESP)
				return false;
			if (registr_ != regEmpty) {
				for (size_t i = 0; i < command_info_list.count(); i++) {
					command_info = command_info_list.item(i);
					if (command_info->operand_type() == otRegistr && command_info->value() == registr_) {
						if (size_ < command_info->size())
							return false;
					}
					else if (command_info->operand_type() == otHiPartRegistr && command_info->value() == registr_) {
						if (size_ == command_info->size())
							return false;
					}
				}
			}
			break;

		case otSegmentRegistr: case otControlRegistr: case otDebugRegistr:
			return false;
			break;

		case otMemory:
			if (base_segment_ == segFS || base_segment_ == segGS)
				return false;

			if (command_info_list.GetInfo(otMemory))
				return false;

			break;
		}

		break;

	case cmPopf:
		if (command_info_list.GetInfo(atWrite, otRegistr, regEFX))
			return false;
		break;

	case cmF2xm1: case cmFabs: case cmFclex: case cmFcos: case cmFdecstp: case cmFincstp:
	case cmFinit: case cmFldln2: case cmFldlg2: case cmFprem: case cmFprem1: case cmFptan:
	case cmFrndint: case cmFsin: case cmFtst: case cmFyl2x: case cmFpatan: case cmFldz: case cmFld1: case cmFldpi:
	case cmWait: case cmFchs: case cmFsqrt: case cmFstsw:
	case cmFistp: case cmFstp: case cmFst: case cmFist: case cmFadd: case cmFsub: case cmFisub: case cmFsubr: case cmFdiv: case cmFmul: case cmFcomp:
	case cmFild: case cmFld:
		if (command_info_list.GetInfo(otFPURegistr))
			return false;
		break;

	case cmAdd: case cmSub: case cmAnd: case cmXor: case cmOr: case cmXchg: case cmXadd:
		if (operand_type_ == otMemory) {
			if (base_segment_ == segFS || base_segment_ == segGS)
				return false;

			if (command_info_list.GetInfo(otMemory))
				return false;
		}
		break;
	}

	return true;
}

bool IntelVMCommand::is_end() const
{
	return (command_type_ == cmJmp || command_type_ == cmRet || command_type_ == cmIret);
}
