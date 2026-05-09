#ifndef INTEL_OPCODE_INFO_H
#define INTEL_OPCODE_INFO_H

#include "../../processors.h"
#include "IntelCommandType.h"

class IntelCommand;
class IntelOpcodeList;

class IntelOpcodeInfo : public IObject
{
public:
	IntelOpcodeInfo(IntelOpcodeList *owner, IntelCommandType command_type, OperandType operand_type, OperandSize size, uint8_t value, IntelCommand *entry, OpcodeCryptor *value_cryptor = NULL, OpcodeCryptor *end_cryptor = NULL);
	~IntelOpcodeInfo();
	IntelCommandType command_type() const { return command_type_; }
	OperandType operand_type() const { return operand_type_; }
	OperandSize size() const { return size_; }
	uint8_t value() const { return value_; }
	IntelCommand *entry() const { return entry_; }
	uint8_t opcode() const { return opcode_; }
	void set_opcode(uint8_t opcode) { opcode_ = opcode; }
	OpcodeCryptor *value_cryptor() const { return value_cryptor_; }
	OpcodeCryptor *end_cryptor() const { return end_cryptor_; }
	uint64_t Key();
	static uint64_t Key(IntelCommandType command_type, OperandType operand_type, OperandSize size, uint8_t value);
	class circular_queue : public std::vector<IntelOpcodeInfo *>
	{
		size_t position_;
	public:
		circular_queue() : std::vector<IntelOpcodeInfo *>(), position_(0) {}
		IntelOpcodeInfo *Next();
	};
private:
	IntelOpcodeList *owner_;
	IntelCommand *entry_;
	IntelCommandType command_type_;
	OperandType operand_type_;
	OperandSize size_;
	uint8_t value_;
	uint8_t opcode_;
	OpcodeCryptor *value_cryptor_;
	OpcodeCryptor *end_cryptor_;
};

class IntelOpcodeList : public ObjectList<IntelOpcodeInfo>
{
public:
	IntelOpcodeList();
	IntelOpcodeInfo *Add(IntelCommandType command_type, OperandType operand_type, OperandSize size, uint8_t value, IntelCommand *entry = NULL, OpcodeCryptor *value_cryptor = NULL, OpcodeCryptor *end_cryptor = NULL);
	IntelOpcodeInfo *GetOpcodeInfo(IntelCommandType command_type, OperandType operand_type, OperandSize size, uint8_t value) const;
};

#endif // INTEL_OPCODE_INFO_H