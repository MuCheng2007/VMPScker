/**
 * Processors command classes.
 * VMCommand, Command, InternalLink
 */

#ifndef PROC_COMMAND_H
#define PROC_COMMAND_H

#include "proc_types.h"
#include "proc_interfaces.h"

class IFunction;
class CommandBlock;
class CommandBlockList;
class InternalLinkList;
class ExtCommandList;
class CommandLinkList;

/**
 * Base implementation of VM command
 */
class BaseVMCommand : public IVMCommand
{
public:
	explicit BaseVMCommand(ICommand *owner);
	~BaseVMCommand();
	virtual ICommand *owner() const { return owner_; }
	void set_owner(ICommand *owner) { owner_ = owner; }
private:
	ICommand *owner_;
};

/**
 * Internal link for command references
 */
class InternalLink : public IObject
{
public:
	InternalLink(InternalLinkList *owner, InternalLinkType type, IVMCommand *from_command, IObject *to_command);
	~InternalLink();
	InternalLinkType type() const { return type_; }
	IVMCommand *from_command() const { return from_command_; }
	IObject *to_command() const { return to_command_; }
private:
	InternalLinkList *owner_;
	InternalLinkType type_;
	IVMCommand *from_command_;
	IObject *to_command_;
};

/**
 * List of internal links
 */
class InternalLinkList : public ObjectList<InternalLink>
{
public:
	InternalLink *Add(InternalLinkType type, IVMCommand *from_command, IObject *to_command);
};

/**
 * Base implementation of executable command
 */
class BaseCommand : public ICommand
{
public:
	explicit BaseCommand(IFunction *owner);
	explicit BaseCommand(IFunction *owner, const std::string &value);
	explicit BaseCommand(IFunction *owner, const os::unicode_string &value);
	explicit BaseCommand(IFunction *owner, const Data &value);
	explicit BaseCommand(IFunction *owner, const BaseCommand &src);
	~BaseCommand();
	virtual uint64_t next_address() const { return address() + dump_size(); }
	virtual uint8_t dump(size_t index) const { return dump_[index]; }
	uint64_t dump_value(size_t pos, OperandSize size) const;
	Data &raw_dump(void) { return dump_; };
	virtual size_t dump_size() const { return dump_.size(); }
	virtual std::string dump_str() const;
	virtual size_t vm_dump_size() const;
	virtual void clear();
	virtual void ReadFromBuffer(Buffer &buffer, IArchitecture &file);
	virtual void WriteToFile(IArchitecture &file);
	virtual CommandLink *link() const { return link_; }
	virtual void set_link(CommandLink *link) { link_ = link; }
	virtual CommandBlock *block() const { return block_; }
	virtual void set_block(CommandBlock *block) { block_ = block; }
	virtual IFunction *owner() const { return owner_; }
	virtual CommandLink *AddLink(int operand_index, LinkType type, ICommand *to_command);
	virtual CommandLink *AddLink(int operand_index, LinkType type, uint64_t to_address = 0);
	virtual uint64_t vm_address() const { return vm_address_; }
	virtual uint64_t ext_vm_address() const { return vm_address_; }
	virtual void set_vm_address(uint64_t address);
	bool CompareDump(const uint8_t *buffer, size_t size) const;
	void set_dump(const void *buffer, size_t size);
	virtual ISEHandler *seh_handler() const { return NULL; }
	virtual CommentInfo comment() { return comment_; }
	virtual void set_comment(const CommentInfo &comment) { comment_ = comment; }
	virtual AddressRange *address_range() const { return address_range_; }
	virtual void set_address_range(AddressRange *address_range) { address_range_ = address_range; }
	virtual void CompileInfo();
	virtual size_t alignment() const { return alignment_; }
	void set_alignment(size_t alignment) { alignment_ = alignment; }
	virtual uint32_t options() const { return options_; }
	virtual void include_option(CommandOption value) { options_ |= value; }
	virtual void exclude_option(CommandOption value) { options_ &= ~value; }
#ifdef CHECKED
	virtual bool check_hash() const { return true; }
#endif
	virtual void set_tag(uint8_t tag) { tag_ = tag; }
	virtual uint8_t tag() const { return tag_; }
protected:
	void Read(IArchitecture &file, size_t len);
	uint8_t ReadByte(IArchitecture &file);
	uint16_t ReadWord(IArchitecture &file);
	uint32_t ReadDWord(IArchitecture &file);
	uint64_t ReadQWord(IArchitecture &file);

	void PushByte(uint8_t value);
	void PushWord(uint16_t value);
	void PushDWord(uint32_t value);
	void PushQWord(uint64_t value);
	void InsertByte(size_t position, uint8_t value);
	void WriteDWord(size_t position, uint32_t value);
	std::string comment_text() const { return comment_.value; }
private:
	Data dump_;
	IFunction *owner_;
	CommandLink *link_;
	CommandBlock *block_;
	uint64_t vm_address_;
	AddressRange *address_range_;
	CommentInfo comment_;
	size_t alignment_;
	uint32_t options_;
	uint8_t tag_;
};

#endif // PROC_COMMAND_H
