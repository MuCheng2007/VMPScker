#include "IntelOpcodeInfo.h"
#include "IntelCommand.h"
#include "../../processors.h"
#include "../../osutils.h"

// Copied from intel.cc:
// - IntelOpcodeInfo (lines: ~18993 - 19045)
// - IntelOpcodeList (lines: ~19046 - 19062)

/**
 * IntelOpcodeInfo
 */

IntelOpcodeInfo::IntelOpcodeInfo(IntelOpcodeList* owner, IntelCommandType command_type, OperandType operand_type, OperandSize size, uint8_t value,
	IntelCommand* entry, OpcodeCryptor* value_cryptor, OpcodeCryptor* end_cryptor)
	: IObject(), owner_(owner), command_type_(command_type), operand_type_(operand_type), size_(size), value_(value), entry_(entry),
	value_cryptor_(value_cryptor), end_cryptor_(end_cryptor), opcode_(0)
{

}

IntelOpcodeInfo::~IntelOpcodeInfo()
{
	if (owner_)
		owner_->RemoveObject(this);
}

uint64_t IntelOpcodeInfo::Key()
{
	return Key(command_type(), operand_type(), size(), value_);
}

uint64_t IntelOpcodeInfo::Key(IntelCommandType command_type, OperandType operand_type, OperandSize size, uint8_t value)
{
	union
	{
		uint64_t result;
		struct
		{
			uint32_t
				command_type : 10,
				operand_type : 14,
				value : 8;
			uint32_t
				size : 3,
				unused : 29;
		};
	} key;

	key.result = 0;

	assert(command_type < (1 << 10));
	key.command_type = command_type;
	assert(operand_type < (1 << 14));
	key.operand_type = operand_type;
	key.value = value;

	assert(size < (1 << 3));
	key.size = size;

	return key.result;
}

IntelOpcodeInfo* IntelOpcodeInfo::circular_queue::Next()
{
	IntelOpcodeInfo* res = NULL;
	if (size())
		res = this->operator[](position_++ % size());
	return res;
}
/**
 * IntelOpcodeInfoList
 */

IntelOpcodeList::IntelOpcodeList()
	: ObjectList<IntelOpcodeInfo>()
{

}

IntelOpcodeInfo* IntelOpcodeList::Add(IntelCommandType command_type, OperandType operand_type, OperandSize size, uint8_t value, IntelCommand* entry, OpcodeCryptor* value_cryptor, OpcodeCryptor* end_cryptor)
{
	if (!entry && GetOpcodeInfo(command_type, operand_type, size, value))
		return NULL;

	IntelOpcodeInfo* opcode = new IntelOpcodeInfo(this, command_type, operand_type, size, value, entry, value_cryptor, end_cryptor);
	AddObject(opcode);
	return opcode;
}

IntelOpcodeInfo* IntelOpcodeList::GetOpcodeInfo(IntelCommandType command_type, OperandType operand_type, OperandSize size, uint8_t value) const
{
	for (size_t i = 0; i < count(); i++) {
		IntelOpcodeInfo* opcode = item(i);
		if (opcode->command_type() == command_type && opcode->operand_type() == operand_type && opcode->size() == size && opcode->value() == value)
			return opcode;
	}
	return NULL;
}

