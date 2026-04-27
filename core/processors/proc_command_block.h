/**
 * Processors command block classes.
 * ExtCommand, CommandBlock
 */

#ifndef PROC_COMMAND_BLOCK_H
#define PROC_COMMAND_BLOCK_H

#include "proc_types.h"
#include "proc_interfaces.h"

class IFunction;
class CommandBlockList;
class ExtCommandList;

/**
 * External command reference
 */
class ExtCommand : public IObject
{
public:
	explicit ExtCommand(ExtCommandList *owner, uint64_t address, ICommand *command, bool use_call);
	explicit ExtCommand(ExtCommandList *owner, const ExtCommand &src);
	virtual ~ExtCommand();
	virtual ExtCommand *Clone(ExtCommandList *owner) const;

	using IObject::CompareWith;
	int CompareWith(const ExtCommand &obj) const;
	uint64_t address() const { return address_; }
	ICommand *command() const { return command_; }
	bool use_call() const { return use_call_; }
	void set_command(ICommand *command) { command_ = command; }
	ExtCommandList *owner() const { return owner_; }
private:
	ExtCommandList *owner_;
	uint64_t address_;
	ICommand *command_;
	bool use_call_;
};

/**
 * List of external commands
 */
class ExtCommandList : public ObjectList<ExtCommand>
{
public:
	explicit ExtCommandList(IFunction *owner);
	explicit ExtCommandList(IFunction *owner, const ExtCommandList &src);
	virtual ExtCommandList *Clone(IFunction *owner) const;
	ExtCommand *Add(uint64_t address);
	ExtCommand *Add(uint64_t address, ICommand *command, bool use_call = false);
	ExtCommand *GetCommandByAddress(uint64_t address) const;
	virtual void AddObject(ExtCommand *ext_command);
	virtual void RemoveObject(ExtCommand *ext_command);
	IFunction *owner() const { return owner_; }
private:
	IFunction *owner_;
};

/**
 * Command block for basic block analysis
 */
class CommandBlock : public AddressableObject
{
public:
	explicit CommandBlock(CommandBlockList *owner, uint32_t type, size_t start_index);
	explicit CommandBlock(CommandBlockList *owner, const CommandBlock &src);
	~CommandBlock();
	CommandBlock *Clone(CommandBlockList *owner);
	size_t start_index() const { return start_index_; }
	size_t end_index() const { return end_index_; }
	uint32_t type() const { return type_; }
	void set_start_index(size_t start_index) { start_index_ = start_index; }
	void set_end_index(size_t end_index) { end_index_ = end_index; }
	void Compile(MemoryManager &manager);
	void CompileLinks(const CompileContext &ctx);
	void CompileInfo();
	size_t WriteToFile(IArchitecture &file);
	uint8_t GetRegistr(OperandSize size, uint8_t registr, bool is_write);
	void AddCorrectCommand(IVMCommand *command) { correct_command_list_.push_back(command); }
	std::vector<IVMCommand *> correct_command_list() const { return correct_command_list_; }
	IFunction *function() const;
	IVirtualMachine *virtual_machine() const { return virtual_machine_; }
	void set_virtual_machine(IVirtualMachine *value) { virtual_machine_ = value; }
	size_t sort_index() const { return sort_index_; }
	void set_sort_index(size_t sort_index) { sort_index_ = sort_index; }
	CommandBlockList *owner() { return owner_; };
private:
	CommandBlockList *owner_;
	uint32_t type_;
	size_t start_index_;
	size_t end_index_;
	uint8_t registr_indexes_[24];
	size_t registr_count_;
	std::vector<IVMCommand *> correct_command_list_;
	IVirtualMachine *virtual_machine_;
	size_t sort_index_;
};

/**
 * List of command blocks
 */
class CommandBlockList : public ObjectList<CommandBlock>
{
public:
	explicit CommandBlockList(IFunction *owner);
	explicit CommandBlockList(IFunction *owner, const CommandBlockList &src);
	CommandBlockList *Clone(IFunction *owner) const;
	CommandBlock *Add(uint32_t memory_type, size_t start_index);
	void CompileBlocks(MemoryManager &manager);
	void CompileLinks(const CompileContext &ctx);
	void CompileInfo();
	size_t WriteToFile(IArchitecture &file);
	IFunction *owner() const { return owner_; }
private:
	IFunction *owner_;
};

/**
 * Helper for sorting command blocks
 */
struct CommandBlockListCompareHelper {
	bool operator () (const CommandBlock *block1, const CommandBlock *block2) const;
};

#endif // PROC_COMMAND_BLOCK_H
