/**
 * Processors command link classes.
 * CommandLink, CommandLinkList
 */

#ifndef PROC_COMMAND_LINK_H
#define PROC_COMMAND_LINK_H

#include "proc_types.h"
#include "proc_interfaces.h"

class CommandLinkList;
class FunctionInfo;
class ValueCryptor;

/**
 * Command link for linking commands
 */
class CommandLink : public IObject
{
public:
	explicit CommandLink(CommandLinkList *owner, ICommand *from_command, int operand_index, LinkType type, uint64_t to_address);
	explicit CommandLink(CommandLinkList *owner, ICommand *from_command, int operand_index, LinkType type, ICommand *to_command);
	explicit CommandLink(CommandLinkList *owner, const CommandLink &src);
	virtual ~CommandLink();
	CommandLink *Clone(CommandLinkList *owner) const;
	ICommand *from_command() const { return from_command_; }
	ICommand *parent_command() const { return parent_command_; }
	ICommand *to_command() const { return to_command_; }
	ICommand *next_command() const { return next_command_; }
	uint64_t to_address() const { return to_address_; }
	LinkType type() const { return type_; }
	bool parsed() const { return parsed_; }
	int operand_index() const { return operand_index_; }
	void set_operand_index(int value) { operand_index_ = value; }
	void set_parsed(bool parsed) { parsed_ = parsed; }
	void set_type(LinkType type) { type_ = type; }
	void set_parent_command(ICommand *parent_command) { parent_command_ = parent_command; }
	void set_from_command(ICommand *command);
	void set_to_command(ICommand *command) { to_command_ = command; }
	void set_next_command(ICommand *command) { next_command_ = command; }
	void set_sub_value(uint64_t value) { sub_value_ = value; }
	uint64_t sub_value() const { return sub_value_; }
	ICommand *gate_command(size_t index) const { return gate_commands_[index]; }
	void Rebase(uint64_t delta_base);
	void AddGateCommand(ICommand *command) { gate_commands_.push_back(command); }
	uint64_t Encrypt(uint64_t value) const;
	ValueCryptor *cryptor() const { return cryptor_; }
	void set_cryptor(ValueCryptor *cryptor);
	FunctionInfo *base_function_info() const { return base_function_info_; }
	void set_base_function_info(FunctionInfo *base_function_info) { base_function_info_ = base_function_info; }
	void set_is_inverse(bool is_inverse) { is_inverse_ = is_inverse; }
private:
	CommandLinkList *owner_;
	bool parsed_;
	ICommand *from_command_;
	ICommand *parent_command_;
	ICommand *to_command_;
	ICommand *next_command_;
	LinkType type_;
	uint64_t to_address_;
	int operand_index_;
	uint64_t sub_value_;
	std::vector<ICommand *> gate_commands_;
	ValueCryptor *cryptor_;
	FunctionInfo *base_function_info_;
	bool is_inverse_;

	// no copy ctr or assignment op
	CommandLink(const CommandLink &);
	CommandLink &operator =(const CommandLink &);
};

/**
 * List of command links
 */
class CommandLinkList : public ObjectList<CommandLink>
{
public:
	explicit CommandLinkList();
	explicit CommandLinkList(const CommandLinkList &src);
	virtual CommandLinkList *Clone() const;
	CommandLink *Add(ICommand *from_command, int operand_index, LinkType type, uint64_t to_address = 0);
	CommandLink *Add(ICommand *from_command, int operand_index, LinkType type, ICommand *to_command);
	CommandLink *GetLinkByToAddress(LinkType type, uint64_t to_address);
	void Rebase(uint64_t delta_base);
private:
	// no assignment op
	CommandLinkList &operator =(const CommandLinkList &);
};

#endif // PROC_COMMAND_LINK_H
