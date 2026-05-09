#ifndef INTEL_COMMAND_H
#define INTEL_COMMAND_H

#include "../../processors.h"
#include "IntelCommandType.h"
#include "IntelOperand.h"
#include "IntelCommandInfo.h"
#include "IntelMisc.h"
#include "../crypto/SectionCryptor.h"
#include <vector>

class EncodedData;
class IArchitecture;
class ISEHandler;
class IntelFunction;
class IntelVMCommand;
class AddressRange;
struct CompileContext;

class IntelCommand: public BaseCommand
{
public:
	explicit IntelCommand(IFunction *owner, OperandSize size, uint64_t address = 0);
	explicit IntelCommand(IFunction *owner, OperandSize size, IntelCommandType type, IntelOperand operand1 = IntelOperand(), IntelOperand operand2 = IntelOperand(), IntelOperand operand3 = IntelOperand());
	explicit IntelCommand(IFunction *owner, OperandSize size, const std::string &value);
	explicit IntelCommand(IFunction *owner, OperandSize size, const os::unicode_string &value);
	explicit IntelCommand(IFunction *owner, OperandSize size, const Data &value);
	explicit IntelCommand(IFunction *owner, const IntelCommand &source);
	~IntelCommand();
	virtual void clear();
	virtual IntelCommand *Clone(IFunction *owner) const;
	virtual void CompileToNative();
	virtual void CompileLink(const CompileContext &ctx);
	virtual void PrepareLink(const CompileContext &ctx);
	void CompileToVM(const CompileContext &ctx);
	virtual uint64_t address() const { return address_; }
	virtual CommandType type() const { return type_; }
	IntelOperand operand(size_t index) const {
		if (index >= _countof(operand_))
			throw std::runtime_error("subscript out of range");
		return operand_[index];
	}
	const IntelOperand *operand_ptr(size_t index) const {
		if (index >= _countof(operand_))
			throw std::runtime_error("subscript out of range");
		return &operand_[index];
	}
	virtual std::string text() const;
	virtual CommentInfo comment();
	virtual uint32_t section_options() const { return section_options_; }
	virtual void set_address(uint64_t address);
	virtual size_t original_dump_size() const { return (original_dump_size_) ? original_dump_size_ : dump_size(); }
	IntelSegment base_segment() const { return base_segment_; }
	CommandType preffix_command() const { return preffix_command_; }
	OperandSize size() const { return size_; }
	uint32_t flags() const { return flags_; }
	void set_flags(uint32_t flags) { flags_ = flags; }
	virtual ISEHandler *seh_handler() const { return seh_handler_; }
	void set_seh_handler(ISEHandler *handler) { seh_handler_ = handler; }
	size_t command_pos() const { return command_pos_; }
	size_t ReadFromFile(IArchitecture &file);
	uint64_t ReadValueFromFile(IArchitecture &file, OperandSize size);
	void ReadArray(IArchitecture &file, size_t len);
	virtual void ReadFromBuffer(Buffer &buffer, IArchitecture &file);
	virtual void WriteToFile(IArchitecture &file);
	virtual void set_operand_value(size_t operand_index, uint64_t value);
	virtual void set_link_value(size_t link_index, uint64_t value);
	virtual void set_jmp_value(size_t link_index, uint64_t value);
	void set_operand_fixup(size_t operand_index, IFixup *fixup);
	void set_operand_relocation(size_t operand_index, IRelocation *relocation);
	void set_operand_scale(size_t operand_index, uint8_t value);
	void set_base_segment(IntelSegment base_segment) { base_segment_ = base_segment; }
	void set_preffix_command(IntelCommandType preffix_command) { preffix_command_ = preffix_command; }
	void Init(IntelCommandType type, IntelOperand operand1 = IntelOperand(), IntelOperand operand2 = IntelOperand(), IntelOperand operand3 = IntelOperand());
	void Init(const Data &data);
	void InitUnknown();
	virtual bool is_data() const;
	virtual bool is_end() const;
	virtual void Rebase(uint64_t delta_base);
	virtual void include_section_option(SectionOption option) { section_options_ |= option; }
	virtual void exclude_section_option(SectionOption option) { section_options_ &= ~option; }
	IntelVMCommand *AddVMCommand(const CompileContext &ctx, IntelCommandType command_type, OperandType operand_type, OperandSize size, uint64_t value, uint32_t options = 0, IFixup *fixup = NULL);
	void AddBeginSection(const CompileContext &ctx, uint32_t options = 0);
	void AddEndSection(const CompileContext &ctx, IntelCommandType end_command, uint8_t end_value = 0, uint32_t options = 0);
	void AddExtSection(const CompileContext &ctx, IntelCommand *command);
	uint64_t AddStoreEIPSection(const CompileContext &ctx, uint64_t prev_eip);
	void AddStoreExtRegistrSection(const CompileContext &ctx, uint8_t registr);
	void AddStoreExtRegistersSection(const CompileContext &ctx);
	void AddCryptorSection(const CompileContext &ctx, ValueCryptor *cryptor, bool is_decrypt);
	IntelVMCommand *item(size_t index) const;
	virtual uint64_t ext_vm_address() const;
	virtual std::string dump_str() const;
	virtual std::string display_address() const;
	bool is_equal(const IntelCommand &command) const;
	IntelVMCommand *ext_vm_entry() const { return ext_vm_entry_; }
	bool GetCommandInfo(IntelCommandInfoList &command_info_list) const;
	virtual bool Merge(ICommand *command);
	uint8_t ReadDataByte(EncodedData &data, size_t *pos);
	uint16_t ReadDataWord(EncodedData &data, size_t *pos);
	uint32_t ReadDataDWord(EncodedData &data, size_t *pos);
	uint64_t ReadDataQWord(EncodedData &data, size_t *pos);
	uint64_t ReadUleb128(EncodedData &data, size_t *pos);
	int64_t ReadSleb128(EncodedData &data, size_t *pos);
	uint64_t ReadEncoding(EncodedData &data, uint8_t encoding, size_t *pos);
	std::string ReadString(EncodedData &data, size_t *pos);
	void ReadData(EncodedData &data, size_t size, size_t *pos);
	int32_t ReadCompressedValue(IArchitecture &file);
#ifdef CHECKED
	virtual bool check_hash() const;
	void update_hash();
#endif
private:
	bool GetOperandText(std::string &str, size_t index) const;
	IntelOperand *GetFreeOperand();
	// disasm methods
	void ReadCommand(IntelCommandType type, uint32_t of_1, uint32_t of_2, uint32_t of_3, DisasmContext &ctx);
	void ReadRegFromRM(uint8_t code, OperandSize operand_size, OperandType operand_type, const DisasmContext &ctx);
	void ReadRM(uint8_t code, OperandSize operand_size, OperandType operand_type, bool show_size, const DisasmContext &ctx);
	void ReadReg(uint8_t code, OperandSize operand_size, OperandType operand_type, const DisasmContext &ctx);
	IntelOperand *ReadValue(OperandSize operand_size, OperandSize value_size, const DisasmContext &ctx);
	void ReadValueAddAddress(OperandSize operand_size, OperandSize value_size, const DisasmContext &ctx);
	void ReadFlags(uint8_t code);
	// asm methods
	void PushReg(size_t operand_index, uint8_t add_code, AsmContext &ctx);
	void PushRM(size_t operand_index, uint8_t add_code, AsmContext &ctx);
	void PushRegAndRM(size_t reg_operand_index, size_t rm_operand_index, AsmContext &ctx);
	void PushFlags(uint8_t add_code);
	void PushPrefix(AsmContext &ctx);
	void PushBytePrefix(uint8_t prefix);
	void PushWordPrefix();
	// virtualization methods
	void CompileOperand(const CompileContext &ctx, size_t operand_index, uint32_t options = 0);
	void AddCorrectOperandSizeSection(const CompileContext &ctx, OperandSize src, OperandSize dst);
	void AddCombineFlagsSection(const CompileContext &ctx, uint16_t mask);
	void AddRegistrAndValueSection(const CompileContext &ctx, uint8_t registr, OperandSize registr_size, uint64_t value, bool need_pushf = false);
	void AddRegistrOrValueSection(const CompileContext &ctx, uint8_t registr, OperandSize registr_size, uint64_t value, bool need_pushf = false);
	void AddCorrectFlagSection(const CompileContext &ctx, uint16_t flags);
	void AddExtractFlagSection(const CompileContext &ctx, uint16_t flags, bool is_inverse, uint8_t extract_to);
	void AddJmpWithFlagSection(const CompileContext &ctx, IntelCommandType command_type);
	void AddCorrectESPSection(const CompileContext &ctx, OperandSize operand_size, size_t value);
	void AddCheckBreakpointSection(const CompileContext &ctx, OperandSize address_size);
	void AddCheckCRCSection(const CompileContext &ctx, OperandSize address_size);
#ifdef CHECKED
	uint32_t calc_hash() const;
	uint32_t hash_;
#endif

	uint64_t address_;
	IntelOperand operand_[3];
	uint32_t vex_operand_;
	uint32_t flags_;

	std::vector<IntelVMCommand *> vm_links_;
	InternalLinkList internal_links_;
	std::vector<IntelVMCommand *> jmp_links_;

	IntelVMCommand *ext_vm_entry_;
	SectionCryptor *begin_section_cryptor_;
	SectionCryptor *end_section_cryptor_;
	IntelCommandInfoList *vm_command_info_list_;

	size_t command_pos_;
	size_t original_dump_size_;
	uint32_t section_options_;

	IntelCommandType type_;
	IntelCommandType preffix_command_;

	OperandSize size_;
	IntelSegment base_segment_;

	ISEHandler *seh_handler_;

	// no copy ctr or assignment op
	IntelCommand(const IntelCommand &);
	IntelCommand &operator =(const IntelCommand &);
};

IntelCommandType CryptorCommandToIntel(CryptCommandType crypt_command);

#endif // INTEL_COMMAND_H