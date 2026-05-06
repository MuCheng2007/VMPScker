#include "proc_command_link.h"
#include "proc_command.h"
#include "proc_info.h"
#include "proc_function.h"
#include "proc_crypto.h"
#include <stdexcept>


/**
 * CommandLink
 */

CommandLink::CommandLink(CommandLinkList* owner, ICommand* from_command, int operand_index, LinkType type, uint64_t to_address)
	: IObject(), owner_(owner), parsed_(false), from_command_(from_command), parent_command_(NULL), to_command_(NULL), next_command_(NULL),
	type_(type), to_address_(to_address), operand_index_(operand_index), sub_value_(0), cryptor_(NULL), base_function_info_(NULL), is_inverse_(false)
{
	if (from_command_)
		from_command_->set_link(this);
}

CommandLink::CommandLink(CommandLinkList* owner, ICommand* from_command, int operand_index, LinkType type, ICommand* to_command)
	: IObject(), owner_(owner), parsed_(false), from_command_(from_command), parent_command_(NULL), to_command_(to_command), next_command_(NULL),
	type_(type), to_address_(0), operand_index_(operand_index), sub_value_(0), cryptor_(NULL), base_function_info_(NULL), is_inverse_(false)
{
	if (from_command_)
		from_command_->set_link(this);
}

CommandLink::CommandLink(CommandLinkList* owner, const CommandLink& src)
	: IObject(src), owner_(owner), from_command_(NULL), parent_command_(NULL), to_command_(NULL), next_command_(NULL)
{
	parsed_ = src.parsed_;
	type_ = src.type_;
	to_address_ = src.to_address_;
	operand_index_ = src.operand_index_;
	sub_value_ = src.sub_value_;
	cryptor_ = src.cryptor_;
	base_function_info_ = src.base_function_info_;
	is_inverse_ = src.is_inverse_;
}

CommandLink::~CommandLink()
{
	if (from_command_)
		from_command_->set_link(NULL);
	if (owner_)
		owner_->RemoveObject(this);
	delete cryptor_;
}

CommandLink* CommandLink::Clone(CommandLinkList* owner) const
{
	CommandLink* link = new CommandLink(owner, *this);
	return link;
}

void CommandLink::set_from_command(ICommand* command)
{
	if (from_command_ == command)
		return;
	if (from_command_)
		from_command_->set_link(NULL);
	from_command_ = command;
	if (from_command_)
		from_command_->set_link(this);
}

void CommandLink::Rebase(uint64_t delta_base)
{
	if (sub_value_)
		sub_value_ += delta_base;

	if (to_address_)
		to_address_ += delta_base;
}

void CommandLink::set_cryptor(ValueCryptor* cryptor)
{
	if (cryptor) {
		cryptor_ = cryptor->Clone();
	}
	else {
		delete cryptor_;
		cryptor_ = NULL;
	}
}

uint64_t CommandLink::Encrypt(uint64_t value) const
{
	uint64_t sub_value = base_function_info_ ? base_function_info_->begin() + base_function_info_->base_value() : sub_value_;
	if (is_inverse_)
		value = sub_value - value;
	else
		value = value - sub_value;
	if (cryptor_)
		value = cryptor_->Encrypt(value);
	return value;
}

/**
 * CommandLinkList
 */

CommandLinkList::CommandLinkList()
	: ObjectList<CommandLink>()
{

}

CommandLinkList::CommandLinkList(const CommandLinkList& src)
	: ObjectList<CommandLink>(src)
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

CommandLinkList* CommandLinkList::Clone() const
{
	CommandLinkList* list = new CommandLinkList(*this);
	return list;
}

CommandLink* CommandLinkList::Add(ICommand* from_command, int operand_index, LinkType type, uint64_t to_address)
{
	CommandLink* link = new CommandLink(this, from_command, operand_index, type, to_address);
	AddObject(link);
	return link;
};

CommandLink* CommandLinkList::Add(ICommand* from_command, int operand_index, LinkType type, ICommand* to_command)
{
	CommandLink* link = new CommandLink(this, from_command, operand_index, type, to_command);
	AddObject(link);
	return link;
};

CommandLink* CommandLinkList::GetLinkByToAddress(LinkType type, uint64_t to_address)
{
	for (size_t i = 0; i < count(); i++) {
		CommandLink* link = item(i);
		if (link->to_address() == to_address && (type == ltNone || link->type() == type))
			return link;
	}

	return NULL;
}

void CommandLinkList::Rebase(uint64_t delta_base)
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->Rebase(delta_base);
	}
}