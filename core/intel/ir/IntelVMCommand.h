#ifndef INTEL_VM_COMMAND_H
#define INTEL_VM_COMMAND_H

#include "../../processors.h"
#include "IntelCommandType.h"

class IntelCommand;
class IntelOpcodeInfo;

class IntelVMCommand : public BaseVMCommand
{
public:
	explicit IntelVMCommand(IntelCommand *owner, IntelCommandType command_type, OperandType operand_type, OperandSize size, uint64_t value, uint32_t options);
	explicit IntelVMCommand(IntelCommand *owner, const IntelVMCommand &src);
	virtual void WriteToFile(IArchitecture &file);
	virtual void Compile();
	IntelVMCommand *Clone(IntelCommand *owner);
	virtual uint64_t address() const { return address_; }
	virtual size_t dump_size() const { return dump_.size(); }
	virtual void set_address(uint64_t address) { address_ = address; }
	virtual void set_value(uint64_t value) { value_ = value; }
	void set_sub_value(uint64_t sub_value) { sub_value_ = sub_value; }
	void set_dump(const Data &dump) { dump_ = dump; }
	uint32_t options() const { return options_; }
	void include_option(VMCommandOption option) { options_ |= option; }
	int GetStackLevel() const;
	IntelCommandType crypt_command() const { return crypt_command_; }
	OperandSize crypt_size() const { return crypt_size_; }
	uint64_t crypt_key() const { return crypt_key_; }
	IntelVMCommand *link_command() const { return link_command_; }
	void set_crypt_command(IntelCommandType crypt_command, OperandSize crypt_size, uint64_t crypt_key) { crypt_command_ = crypt_command; crypt_size_ = crypt_size; crypt_key_ = crypt_key; }
	void set_link_command(IntelVMCommand *command) { link_command_ = command; }
	IntelCommandType command_type() const { return command_type_; }
	OperandType operand_type() const { return operand_type_; }
	uint8_t registr() const { return registr_; }
	OperandSize size() const { return size_; }
	uint64_t value() const { return value_; }
	uint64_t sub_value() const { return sub_value_; }
	IntelSegment base_segment() const { return base_segment_; }
	uint8_t subtype() const { return subtype_; }
	uint8_t dump(size_t pos) const { return dump_[pos]; }
	uint64_t dump_value(OperandSize size, size_t pos) const;
	void set_dump_value(OperandSize size, size_t pos, uint64_t value);
	void set_dump(size_t pos, uint8_t value) { dump_[pos] = value; }
	bool can_merge(CommandInfoList &command_info_list) const;
	IntelOpcodeInfo *opcode() const { return opcode_; }
	void set_opcode(IntelOpcodeInfo *opcode) { opcode_ = opcode; }
	virtual bool is_end() const;
	bool is_data() const { return (command_type_ == cmDD || command_type_ == cmDQ); }
	IFixup *fixup() const { return fixup_; }
	void set_fixup(IFixup *fixup) { fixup_ = fixup; }
private:
	uint64_t CorrectDumpValue(OperandSize size, uint64_t value) const;
	uint64_t address_;
	uint64_t crypt_key_;
	uint64_t sub_value_;
	uint64_t value_;

	IntelVMCommand *link_command_;
	IntelOpcodeInfo *opcode_;

	uint32_t options_;
	IntelCommandType command_type_;
	IntelCommandType crypt_command_;

	Data dump_;

	OperandType operand_type_;
	uint8_t registr_;
	uint8_t subtype_;
	OperandSize size_;
	IntelSegment base_segment_;
	OperandSize crypt_size_;
	IFixup *fixup_;
};

#endif // INTEL_VM_COMMAND_H