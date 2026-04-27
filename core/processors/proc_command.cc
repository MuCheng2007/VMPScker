#include "proc_command.h"
#include "proc_interfaces.h"
#include "proc_info.h"
#include "proc_command_link.h"
#include "../streams.h"
#include <stdexcept>

/**
 * BaseVMCommand
 */

BaseVMCommand::BaseVMCommand(ICommand* owner)
	: IVMCommand(), owner_(owner)
{

}

BaseVMCommand::~BaseVMCommand()
{
	if (owner_)
		owner_->RemoveObject(this);
}

/**
* InternalLink
*/

InternalLink::InternalLink(InternalLinkList* owner, InternalLinkType type, IVMCommand* from_command, IObject* to_command)
	: owner_(owner), type_(type), from_command_(from_command), to_command_(to_command)
{

}

InternalLink::~InternalLink()
{
	if (owner_)
		owner_->RemoveObject(this);
}

/**
* InternalLinkList
*/

InternalLink* InternalLinkList::Add(InternalLinkType type, IVMCommand* from_command, IObject* to_command)
{
	InternalLink* link = new InternalLink(this, type, from_command, to_command);
	AddObject(link);
	return link;
}


/**
 * BaseCommand
 */

BaseCommand::BaseCommand(IFunction* owner)
	: ICommand(), owner_(owner), link_(NULL), block_(NULL), vm_address_(0), address_range_(NULL),
	alignment_(0), options_(roNeedCompile)
{

}

BaseCommand::BaseCommand(IFunction* owner, const std::string& value)
	: ICommand(), owner_(owner), link_(NULL), block_(NULL), vm_address_(0), address_range_(NULL),
	alignment_(0), options_(roNeedCompile)
{
	dump_.PushBuff(value.c_str(), value.size());
	dump_.PushByte(0);
}

BaseCommand::BaseCommand(IFunction* owner, const os::unicode_string& value)
	: ICommand(), owner_(owner), link_(NULL), block_(NULL), vm_address_(0), address_range_(NULL),
	alignment_(0), options_(roNeedCompile)
{
	dump_.PushBuff(value.c_str(), value.size() * sizeof(os::unicode_char));
	dump_.PushWord(0);
}

BaseCommand::BaseCommand(IFunction* owner, const Data& value)
	: ICommand(), owner_(owner), link_(NULL), block_(NULL), vm_address_(0), address_range_(NULL),
	alignment_(0), options_(roNeedCompile)
{
	dump_.PushBuff(value.data(), value.size());
}

BaseCommand::BaseCommand(IFunction* owner, const BaseCommand& src)
	: ICommand(), owner_(owner), link_(NULL), block_(NULL)
{
	dump_ = src.dump_;
	address_range_ = src.address_range_;
	comment_ = src.comment_;
	vm_address_ = src.vm_address_;
	alignment_ = src.alignment_;
	options_ = src.options_;
}

BaseCommand::~BaseCommand()
{
	if (owner_)
		owner_->RemoveObject(this);
}

void BaseCommand::clear()
{
	dump_.clear();
}

void BaseCommand::Read(IArchitecture& file, size_t len)
{
	uint8_t* p = new uint8_t[len];
	file.Read(p, len);
	dump_.PushBuff(p, len);
	delete[] p;
}

uint8_t BaseCommand::ReadByte(IArchitecture& file)
{
	uint8_t res = file.ReadByte();
	PushByte(res);
	return res;
}

uint16_t BaseCommand::ReadWord(IArchitecture& file)
{
	uint16_t res = file.ReadWord();
	PushWord(res);
	return res;
}

uint32_t BaseCommand::ReadDWord(IArchitecture& file)
{
	uint32_t res = file.ReadDWord();
	PushDWord(res);
	return res;
}

uint64_t BaseCommand::ReadQWord(IArchitecture& file)
{
	uint64_t res = file.ReadQWord();
	PushQWord(res);
	return res;
}

void BaseCommand::PushByte(uint8_t value)
{
	dump_.PushByte(value);
}

void BaseCommand::PushWord(uint16_t value)
{
	dump_.PushWord(value);
}

void BaseCommand::PushDWord(uint32_t value)
{
	dump_.PushDWord(value);
}

void BaseCommand::PushQWord(uint64_t value)
{
	dump_.PushQWord(value);
}

void BaseCommand::InsertByte(size_t position, uint8_t value)
{
	dump_.InsertByte(position, value);
}

void BaseCommand::WriteDWord(size_t position, uint32_t value)
{
	dump_.WriteDWord(position, value);
}

void BaseCommand::CompileInfo()
{
	if (address_range_)
		address_range_->Add(address(), dump_size());
}

void BaseCommand::ReadFromBuffer(Buffer& buffer, IArchitecture& file)
{
	options_ = buffer.ReadDWord() & (roNeedCompile | roInverseFlag | roClearOriginalCode | roCreateNewBlock | roLockPrefix | roExternal | roBreaked | roVexPrefix);
	alignment_ = buffer.ReadByte();
}

void BaseCommand::WriteToFile(IArchitecture& file)
{
	file.Write(dump_.data(), dump_.size());
}

CommandLink* BaseCommand::AddLink(int operand_index, LinkType type, uint64_t to_address)
{
	return owner_->link_list()->Add(this, operand_index, type, to_address);
}

CommandLink* BaseCommand::AddLink(int operand_index, LinkType type, ICommand* to_command)
{
	return owner_->link_list()->Add(this, operand_index, type, to_command);
}

size_t BaseCommand::vm_dump_size() const
{
	size_t res = 0;
	for (size_t i = 0; i < count(); i++) {
		res += item(i)->dump_size();
	}

	return res;
}

void BaseCommand::set_vm_address(uint64_t address)
{
	vm_address_ = address;
	bool backward_direction = (section_options() & rtBackwardDirection) != 0;
	for (size_t i = 0; i < count(); i++) {
		IVMCommand* vm_command = item(i);
		vm_command->set_address(address);
		if (backward_direction) {
			address -= vm_command->dump_size();
		}
		else {
			address += vm_command->dump_size();
		}
	}
}

void BaseCommand::set_dump(const void* buffer, size_t size)
{
	dump_.clear();
	dump_.PushBuff(buffer, size);
}

bool BaseCommand::CompareDump(const uint8_t* buffer, size_t size) const
{
	if (dump_.size() != size)
		return false;

	for (size_t i = 0; i < size; i++) {
		if (dump_[i] != buffer[i])
			return false;
	}
	return true;
}

std::string BaseCommand::dump_str() const
{
	std::string res;

	for (size_t i = 0; i < dump_size(); i++) {
		res += string_format("%.2X", dump(i));
	}

	return res;
}

uint64_t BaseCommand::dump_value(size_t pos, OperandSize size) const
{
	if (size > osQWord)
		throw std::runtime_error("Invalid value size");

	uint64_t res = 0;
	memcpy(&res, &dump_[pos], OperandSizeToValue(size));
	return res;
}