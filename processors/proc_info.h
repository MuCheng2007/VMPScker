/**
 * Processors info classes.
 * CommandInfo, FunctionInfo, AddressRange, Signature
 */

#ifndef PROC_INFO_H
#define PROC_INFO_H

#include "proc_types.h"
#include "proc_interfaces.h"

class CommandInfoList;
class FunctionInfoList;
class ICommand;
class IFunction;
class IRuntimeFunction;
class SignatureList;

/**
 * Command operand information
 */
class CommandInfo : public IObject
{
public:
	explicit CommandInfo(CommandInfoList *owner, AccessType type, uint8_t value, OperandType operand_type, OperandSize size);
	~CommandInfo();
	AccessType type() const { return type_; }
	OperandType operand_type() const { return operand_type_; }
	uint8_t value() const { return value_; }
	OperandSize size() const { return size_; }
	void set_size(OperandSize size) { size_ = size; }
private:
	CommandInfoList *owner_;
	OperandType operand_type_;
	AccessType type_;
	uint8_t value_;
	OperandSize size_;
};

/**
 * List of command operand information
 */
class CommandInfoList : public ObjectList<CommandInfo>
{
public:
	explicit CommandInfoList();
	virtual void Add(AccessType access_type, uint8_t value, OperandType operand_type, OperandSize size);
	void set_need_flags(uint16_t flags) { need_flags_ = flags; }
	void set_change_flags(uint16_t flags) { change_flags_ = flags; }
	CommandInfo *GetInfo(AccessType type, OperandType operand_type, uint8_t value) const;
	CommandInfo *GetInfo(AccessType type, OperandType operand_type) const;
	CommandInfo *GetInfo(OperandType operand_type) const;
	uint16_t need_flags() const { return need_flags_; }
	uint16_t change_flags() const { return change_flags_; }
	virtual void clear();
private:
	uint16_t need_flags_;
	uint16_t change_flags_;
};

/**
 * Address range within a function
 */
class AddressRange : public IObject
{
public:
	explicit AddressRange(FunctionInfo *owner, uint64_t begin, uint64_t end, ICommand *begin_entry, ICommand *end_entry, ICommand *size_entry);
	explicit AddressRange(FunctionInfo *owner, const AddressRange &src);
	~AddressRange();
	uint64_t begin() const { return begin_; }
	uint64_t end() const { return end_; }
	uint64_t original_begin() const { return original_begin_ ? original_begin_ : begin_; }
	uint64_t original_end() const { return original_end_ ? original_end_ : end_; }
	ICommand *begin_entry() const { return begin_entry_; }
	ICommand *end_entry() const { return end_entry_; }
	ICommand *size_entry() const { return size_entry_; }
	void set_begin_entry(ICommand *begin_entry) { begin_entry_ = begin_entry; }
	void set_end_entry(ICommand *end_entry) { end_entry_ = end_entry; }
	void set_size_entry(ICommand *size_entry) { size_entry_ = size_entry; }
	AddressRange *Clone(FunctionInfo *owner) const;
	void Add(uint64_t address, size_t size);
	void Prepare();
	void Rebase(uint64_t delta_base);
	FunctionInfo *owner() const { return owner_; }
	void set_begin(uint64_t value) { begin_ = value; }
	void set_end(uint64_t value) { end_ = value; }
	FunctionInfo *link_info() const { return link_info_; }
	void set_link_info(FunctionInfo *info) { link_info_ = info; }
	void AddLink(AddressRange *link) { link_list_.push_back(link); }
private:
	FunctionInfo *owner_;
	uint64_t begin_;
	uint64_t end_;
	uint64_t original_begin_;
	uint64_t original_end_;
	ICommand *begin_entry_;
	ICommand *end_entry_;
	ICommand *size_entry_;
	FunctionInfo *link_info_;
	std::vector<AddressRange *> link_list_;
};

/**
 * Function metadata information
 */
class FunctionInfo : public ObjectList<AddressRange>
{
public:
	explicit FunctionInfo();
	explicit FunctionInfo(FunctionInfoList *owner, uint64_t begin, uint64_t end, AddressBaseType base_type, uint64_t base_value, size_t prolog_size,
		uint8_t frame_registr, IRuntimeFunction *source, ICommand *entry);
	explicit FunctionInfo(FunctionInfoList *owner, const FunctionInfo &src);
	~FunctionInfo();
	AddressRange *Add(uint64_t begin, uint64_t end, ICommand *begin_entry, ICommand *end_entry, ICommand *size_entry);
	AddressRange *GetRangeByAddress(uint64_t address) const;
	uint64_t begin() const { return begin_; }
	uint64_t end() const { return end_; }
	size_t prolog_size() const { return prolog_size_; }
	AddressBaseType base_type() const { return base_type_; }
	uint64_t base_value() const { return base_value_; }
	ICommand *entry() const { return entry_; }
	void set_entry(ICommand *entry) { entry_ = entry; }
	ICommand *data_entry() const { return data_entry_; }
	void set_data_entry(ICommand *data_entry) { data_entry_ = data_entry; }
	FunctionInfo *Clone(FunctionInfoList *owner) const;
	void Prepare();
	void Compile();
	void WriteToFile(IArchitecture &file);
	void Rebase(uint64_t delta_base);
	uint8_t frame_registr() const { return frame_registr_; }
	IRuntimeFunction *source() const { return source_; }
	void set_source(IRuntimeFunction *source) { source_ = source; }
	std::vector<ICommand *> *unwind_opcodes() { return &unwind_opcodes_; }
	void set_unwind_opcodes(const std::vector<ICommand *> &unwind_opcodes) { unwind_opcodes_ = unwind_opcodes; }
private:
	FunctionInfoList *owner_;
	uint64_t begin_;
	uint64_t end_;
	size_t prolog_size_;
	ICommand *entry_;
	ICommand *data_entry_;
	uint8_t frame_registr_;
	AddressBaseType base_type_;
	uint64_t base_value_;
	IRuntimeFunction *source_;
	std::vector<ICommand *> unwind_opcodes_;
};

/**
 * List of function information
 */
class FunctionInfoList : public ObjectList<FunctionInfo>
{
public:
	explicit FunctionInfoList();
	explicit FunctionInfoList(const FunctionInfoList &src);
	FunctionInfoList *Clone() const;
	FunctionInfo *GetItemByAddress(uint64_t address) const;
	AddressRange *GetRangeByAddress(uint64_t address) const;
	FunctionInfo *Add(uint64_t begin, uint64_t end, AddressBaseType base_type, uint64_t base_value, size_t prolog_size, uint8_t frame_registr,
		IRuntimeFunction *source, ICommand *entry);
	void Prepare();
	void Compile();
	void WriteToFile(IArchitecture &file);
	void Rebase(uint64_t delta_base);
private:
	// no assignment op
	FunctionInfoList &operator =(const FunctionInfoList &);
};

/**
 * Function signature for detection
 */
class Signature : public IObject
{
public:
	explicit Signature(SignatureList *owner, const std::string &value, uint32_t tag);
	~Signature();
	size_t size() const { return dump_.size(); }
	uint8_t dump(size_t index) const { return dump_[index]; }
	uint32_t tag() const { return tag_; }
	void InitSearch() { pos_.clear(); }
	bool SearchByte(uint8_t value);
private:
	void Init();

	SignatureList *owner_;
	std::string value_;
	std::vector<uint8_t> dump_;
	std::vector<uint8_t> mask_;
	std::vector<size_t> pos_;
	uint32_t tag_;
};

/**
 * List of signatures
 */
class SignatureList : public ObjectList<Signature>
{
public:
	explicit SignatureList();
	Signature *Add(const std::string &value, uint32_t tag = 0);
	void InitSearch();
};

#endif // PROC_INFO_H
