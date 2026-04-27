#include "proc_info.h"
#include "proc_interfaces.h"
#include "proc_command.h"
#include "proc_function.h"
#include <stdexcept>


/**
 * AddressRange
 */

AddressRange::AddressRange(FunctionInfo* owner, uint64_t begin, uint64_t end, ICommand* begin_entry, ICommand* end_entry, ICommand* size_entry)
	: IObject(), owner_(owner), begin_(begin), end_(end), original_begin_(0), original_end_(0), begin_entry_(begin_entry), end_entry_(end_entry),
	size_entry_(size_entry), link_info_(NULL)
{

}

AddressRange::AddressRange(FunctionInfo* owner, const AddressRange& src)
	: IObject(), owner_(owner)
{
	begin_ = src.begin_;
	end_ = src.end_;
	begin_entry_ = src.begin_entry_;
	end_entry_ = src.end_entry_;
	size_entry_ = src.size_entry_;
	original_begin_ = src.original_begin_;
	original_end_ = src.original_end_;
	link_info_ = src.link_info_;
}

AddressRange::~AddressRange()
{
	if (owner_)
		owner_->RemoveObject(this);
}

AddressRange* AddressRange::Clone(FunctionInfo* owner) const
{
	AddressRange* range = new AddressRange(owner, *this);
	return range;
}

void AddressRange::Add(uint64_t address, size_t size)
{
	if (!begin_ || begin_ > address)
		begin_ = address;

	if (!end_ || end_ < address + size)
		end_ = address + size;

	for (size_t i = 0; i < link_list_.size(); i++) {
		link_list_[i]->Add(address, size);
	}
}

void AddressRange::Prepare()
{
	original_begin_ = begin_;
	original_end_ = end_;
	begin_ = 0;
	end_ = 0;
}

void AddressRange::Rebase(uint64_t delta_base)
{
	if (begin_)
		begin_ += delta_base;
	if (end_)
		end_ += delta_base;
}

/**
 * FunctionInfo
 */

FunctionInfo::FunctionInfo()
	: ObjectList<AddressRange>(), owner_(NULL), begin_(0), end_(0), base_type_(btValue), base_value_(0), prolog_size_(0),
	entry_(NULL), frame_registr_(0), source_(NULL), data_entry_(NULL)
{}

FunctionInfo::FunctionInfo(FunctionInfoList* owner, uint64_t begin, uint64_t end, AddressBaseType base_type, uint64_t base_value, size_t prolog_size,
	uint8_t frame_registr, IRuntimeFunction* source, ICommand* entry)
	: ObjectList<AddressRange>(), owner_(owner), begin_(begin), end_(end), base_type_(base_type), base_value_(base_value), prolog_size_(prolog_size),
	entry_(entry), frame_registr_(frame_registr), source_(source), data_entry_(NULL)
{

}

FunctionInfo::FunctionInfo(FunctionInfoList* owner, const FunctionInfo& src)
	: ObjectList<AddressRange>(), owner_(owner)
{
	begin_ = src.begin_;
	end_ = src.end_;
	base_type_ = src.base_type_;
	base_value_ = src.base_value_;
	prolog_size_ = src.prolog_size_;
	source_ = src.source_;
	entry_ = src.entry_;
	data_entry_ = src.data_entry_;
	frame_registr_ = src.frame_registr_;
	unwind_opcodes_ = src.unwind_opcodes_;
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

FunctionInfo::~FunctionInfo()
{
	if (owner_)
		owner_->RemoveObject(this);
}

FunctionInfo* FunctionInfo::Clone(FunctionInfoList* owner) const
{
	FunctionInfo* info = new FunctionInfo(owner, *this);
	return info;
}

AddressRange* FunctionInfo::Add(uint64_t begin, uint64_t end, ICommand* begin_entry, ICommand* end_entry, ICommand* size_entry)
{
	AddressRange* range = new AddressRange(this, begin, end, begin_entry, end_entry, size_entry);
	AddObject(range);
	return range;
}

AddressRange* FunctionInfo::GetRangeByAddress(uint64_t address) const
{
	for (size_t i = 0; i < count(); i++) {
		AddressRange* range = item(i);
		if (range->begin() <= address && range->end() > address)
			return range;
	}
	return NULL;
}

void FunctionInfo::Prepare()
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->Prepare();
	}
}

void FunctionInfo::Compile()
{
	begin_ = 0;
	end_ = 0;
	for (size_t i = 0; i < count(); i++) {
		AddressRange* range = item(i);
		if (!range->begin())
			continue;
		if (!begin_ || begin_ > range->begin())
			begin_ = range->begin();
		if (!end_ || end_ < range->end())
			end_ = range->end();
	}
}

void FunctionInfo::WriteToFile(IArchitecture& file)
{
	if (begin_) {
		std::vector<uint8_t> call_frame_instructions;;
		for (size_t i = 0; i < unwind_opcodes_.size(); i++) {
			ICommand* command = unwind_opcodes_[i];
			for (size_t j = 0; j < command->dump_size(); j++) {
				call_frame_instructions.push_back(command->dump(j));
			}
		}
		file.runtime_function_list()->Add(0, begin_, end_, entry_ ? entry_->address() : 0, source_, call_frame_instructions);
	}
}

void FunctionInfo::Rebase(uint64_t delta_base)
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->Rebase(delta_base);
	}

	if (begin_)
		begin_ += delta_base;
	if (end_)
		end_ += delta_base;
}

/**
 * FunctionInfoList
 */

FunctionInfoList::FunctionInfoList()
	: ObjectList<FunctionInfo>()
{

}

FunctionInfoList::FunctionInfoList(const FunctionInfoList& src)
	: ObjectList<FunctionInfo>()
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

FunctionInfoList* FunctionInfoList::Clone() const
{
	FunctionInfoList* list = new FunctionInfoList(*this);
	return list;
}

FunctionInfo* FunctionInfoList::GetItemByAddress(uint64_t address) const
{
	for (size_t i = 0; i < count(); i++) {
		FunctionInfo* info = item(i);
		if (info->begin() <= address && info->end() > address)
			return info;
	}
	return NULL;
}

AddressRange* FunctionInfoList::GetRangeByAddress(uint64_t address) const
{
	FunctionInfo* info = GetItemByAddress(address);
	return info ? info->GetRangeByAddress(address) : NULL;
}

FunctionInfo* FunctionInfoList::Add(uint64_t begin, uint64_t end, AddressBaseType base_type, uint64_t base_value, size_t prolog_size, uint8_t frame_registr, IRuntimeFunction* source, ICommand* entry)
{
	FunctionInfo* info = new FunctionInfo(this, begin, end, base_type, base_value, prolog_size, frame_registr, source, entry);
	AddObject(info);
	return info;
};

void FunctionInfoList::Prepare()
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->Prepare();
	}
}

void FunctionInfoList::Compile()
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->Compile();
	}
}

void FunctionInfoList::WriteToFile(IArchitecture& file)
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->WriteToFile(file);
	}
}

void FunctionInfoList::Rebase(uint64_t delta_base)
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->Rebase(delta_base);
	}
}



/**
 * Signature
 */

Signature::Signature(SignatureList* owner, const std::string& value, uint32_t tag)
	: IObject(), owner_(owner), value_(value), tag_(tag)
{
	Init();
}

Signature::~Signature()
{
	if (owner_)
		owner_->RemoveObject(this);
}

void Signature::Init()
{
	size_t i, p;
	uint8_t m, b;
	char c;

	dump_.clear();
	mask_.clear();

	if (value_.size() == 0)
		return;

	for (i = 0; i < value_.size(); i++) {
		p = i / 2;
		if (p >= dump_.size()) {
			dump_.push_back(0);
			mask_.push_back(0);
		}

		m = 0xff;
		c = value_[i];
		if ((c >= '0') && (c <= '9')) {
			b = c - '0';
		}
		else if ((c >= 'A') && (c <= 'F')) {
			b = c - 'A' + 0x0a;
		}
		else if ((c >= 'a') && (c <= 'f')) {
			b = c - 'a' + 0x0a;
		}
		else {
			m = 0;
			b = 0;
		}

		if ((i & 1) == 0) {
			dump_[p] = (dump_[p] & 0x0f) | (b << 4);
			mask_[p] = (mask_[p] & 0x0f) | (m << 4);
		}
		else {
			dump_[p] = (dump_[p] & 0xf0) | (b & 0x0f);
			mask_[p] = (mask_[p] & 0xf0) | (m & 0x0f);
		}
	}
}

bool Signature::SearchByte(uint8_t value)
{
	int i;
	size_t p;
	bool res;

	if (dump_.size() == 0)
		return false;

	res = false;
	for (i = (int)pos_.size() - 1; i >= -1; i--) {
		p = (i == -1) ? 0 : pos_[i];
		if ((dump_[p] & mask_[p]) == (value & mask_[p])) {
			p++;
			if (p == dump_.size()) {
				res = true;
				if (i > -1)
					pos_.erase(pos_.begin() + i);
			}
			else if (i == -1) {
				pos_.push_back(p);
			}
			else {
				pos_[i] = p;
			}
		}
		else if (i > -1) {
			pos_.erase(pos_.begin() + i);
		}
	}

	return res;
}

/**
 * SignatureList
 */

SignatureList::SignatureList()
	: ObjectList<Signature>()
{

}

Signature* SignatureList::Add(const std::string& value, uint32_t tag)
{
	Signature* sign = new Signature(this, value, tag);
	AddObject(sign);
	return sign;
}

void SignatureList::InitSearch()
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->InitSearch();
	}
}


/**
 * CommandInfo
 */

CommandInfo::CommandInfo(CommandInfoList* owner, AccessType type, uint8_t value, OperandType operand_type, OperandSize size)
	: IObject(), owner_(owner), type_(type), value_(value), operand_type_(operand_type), size_(size)
{

}

CommandInfo::~CommandInfo()
{
	if (owner_)
		owner_->RemoveObject(this);
}

/**
 * CommandInfoList
 */

CommandInfoList::CommandInfoList()
	: ObjectList<CommandInfo>(), need_flags_(0), change_flags_(0)
{

}

void CommandInfoList::Add(AccessType type, uint8_t value, OperandType operand_type, OperandSize size)
{
	CommandInfo* command_info = GetInfo(type, operand_type, value);
	if (command_info) {
		if (operand_type == otHiPartRegistr) {
			if (size == command_info->size())
				return;
		}
		else {
			if (size > command_info->size())
				command_info->set_size(size);
			return;
		}
	}

	if (operand_type == otRegistr) {
		command_info = GetInfo(type, otHiPartRegistr, value);
		if (command_info) {
			if (size > command_info->size()) {
				delete command_info;
			}
			else if (size == command_info->size()) {
				delete command_info;
				size = static_cast<OperandSize>(size + 1);
			}
		}
	}
	else if (operand_type == otHiPartRegistr) {
		command_info = GetInfo(type, otRegistr, value);
		if (command_info) {
			if (size < command_info->size())
				return;
			if (size == command_info->size()) {
				command_info->set_size(static_cast<OperandSize>(size + 1));
				return;
			}
		}
	}

	command_info = new CommandInfo(this, type, value, operand_type, size);
	AddObject(command_info);
}

CommandInfo* CommandInfoList::GetInfo(AccessType type, OperandType operand_type, uint8_t value) const
{
	for (size_t i = 0; i < count(); i++) {
		CommandInfo* command_info = item(i);
		if (command_info->type() == type && command_info->value() == value && command_info->operand_type() == operand_type)
			return command_info;
	}
	return NULL;
}

CommandInfo* CommandInfoList::GetInfo(AccessType type, OperandType operand_type) const
{
	for (size_t i = 0; i < count(); i++) {
		CommandInfo* command_info = item(i);
		if (command_info->type() == type && command_info->operand_type() == operand_type)
			return command_info;
	}
	return NULL;
}

CommandInfo* CommandInfoList::GetInfo(OperandType operand_type) const
{
	for (size_t i = 0; i < count(); i++) {
		CommandInfo* command_info = item(i);
		if (command_info->operand_type() == operand_type)
			return command_info;
	}
	return NULL;
}

void CommandInfoList::clear()
{
	need_flags_ = 0;
	change_flags_ = 0;
	ObjectList<CommandInfo>::clear();
}

