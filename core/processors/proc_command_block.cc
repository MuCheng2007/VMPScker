#include "proc_command_block.h"
#include "proc_command.h"
#include "proc_command_link.h"
#include "proc_info.h"
#include "proc_function.h"
#include "proc_vm.h"
#include <stdexcept>
#include <algorithm>

/**
 * ExtCommand
 */

ExtCommand::ExtCommand(ExtCommandList* owner, uint64_t address, ICommand* command, bool use_call)
	: IObject(), owner_(owner), address_(address), command_(command), use_call_(use_call)
{

}

ExtCommand::ExtCommand(ExtCommandList* owner, const ExtCommand& src)
	: IObject(src), owner_(owner)
{
	address_ = src.address_;
	command_ = src.command_;
	use_call_ = src.use_call_;
}

ExtCommand::~ExtCommand()
{
	if (owner_)
		owner_->RemoveObject(this);
}

ExtCommand* ExtCommand::Clone(ExtCommandList* owner) const
{
	ExtCommand* ext_command = new ExtCommand(owner, *this);
	return ext_command;
}

int ExtCommand::CompareWith(const ExtCommand& obj) const
{
	if (address() < obj.address())
		return -1;
	if (address() > obj.address())
		return 1;
	return 0;
}

/**
 * ExtCommandList
 */

ExtCommandList::ExtCommandList(IFunction* owner)
	: ObjectList<ExtCommand>(), owner_(owner)
{

}

ExtCommandList::ExtCommandList(IFunction* owner, const ExtCommandList& src)
	: ObjectList<ExtCommand>(src), owner_(owner)
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

ExtCommandList* ExtCommandList::Clone(IFunction* owner) const
{
	ExtCommandList* list = new ExtCommandList(owner, *this);
	return list;
}

ExtCommand* ExtCommandList::GetCommandByAddress(uint64_t address) const
{
	for (size_t i = 0; i < count(); i++) {
		ExtCommand* ext_command = item(i);
		if (ext_command->address() == address)
			return ext_command;
	}

	return NULL;
}

ExtCommand* ExtCommandList::Add(uint64_t address, ICommand* command, bool use_call)
{
	ExtCommand* ext_command = new ExtCommand(this, address, command, use_call);
	AddObject(ext_command);
	return ext_command;
}

ExtCommand* ExtCommandList::Add(uint64_t address)
{
	ExtCommand* ext_command = GetCommandByAddress(address);
	if (ext_command)
		return ext_command;

	if (owner_->address() == address || owner_->type() == otString)
		return NULL;

	ICommand* command = owner_->GetCommandByAddress(address);
	if (!command)
		return NULL;

	return Add(address, command);
}

void ExtCommandList::AddObject(ExtCommand* ext_command)
{
	ObjectList<ExtCommand>::AddObject(ext_command);
	if (owner_)
		owner_->Notify(mtAdded, ext_command);
}

void ExtCommandList::RemoveObject(ExtCommand* ext_command)
{
	ObjectList<ExtCommand>::RemoveObject(ext_command);
	if (owner_)
		owner_->Notify(mtDeleted, ext_command);
}


/**
 * CommandBlock
 */

CommandBlock::CommandBlock(CommandBlockList* owner, uint32_t type, size_t start_index)
	: AddressableObject(), owner_(owner), type_(type), start_index_(start_index), end_index_(start_index),
	virtual_machine_(NULL), sort_index_(0)
{
	registr_count_ = (function()->cpu_address_size() == osDWord) ? 16 : 24;
	memset(registr_indexes_, 0xff, sizeof(registr_indexes_));
}

CommandBlock::CommandBlock(CommandBlockList* owner, const CommandBlock& src)
	: AddressableObject(src), owner_(owner), virtual_machine_(NULL), sort_index_(0)
{
	type_ = src.type_;
	start_index_ = src.start_index_;
	end_index_ = src.end_index_;
	registr_count_ = src.registr_count_;
}

CommandBlock::~CommandBlock()
{
	if (owner_)
		owner_->RemoveObject(this);
}

CommandBlock* CommandBlock::Clone(CommandBlockList* owner)
{
	CommandBlock* block = new CommandBlock(owner, *this);
	return block;
}

IFunction* CommandBlock::function() const
{
	return owner_->owner();
}

void CommandBlock::Compile(MemoryManager& manager)
{
	size_t i, memory_size, alignment;
	ICommand* command;
	uint64_t address;
	IFunction* func = function();

	memory_size = 0;
	if (type_ & mtExecutable) {
		alignment = func->item(start_index_)->alignment();
		for (i = start_index_; i <= end_index_; i++) {
			command = func->item(i);
			memory_size += command->dump_size();
		}
	}
	else {
		alignment = 0;
		for (i = start_index_; i <= end_index_; i++) {
			command = func->item(i);
			for (size_t j = 0; j < command->count(); j++) {
				command->item(j)->Compile();
			}
			memory_size += command->vm_dump_size();
		}
	}

	if (memory_size) {
		address = (address_) ? address_ : manager.Alloc(memory_size, type_, 0, alignment);
		if (type_ & mtExecutable) {
			// native block
			for (i = start_index_; i <= end_index_; i++) {
				command = func->item(i);
				command->set_address(address);
				address += command->dump_size();
			}
		}
		else {
			// VM block
			bool backward_direction = (func->item(start_index_)->section_options() & rtBackwardDirection) != 0;
			if (backward_direction)
				address += memory_size;
			for (i = start_index_; i <= end_index_; i++) {
				command = func->item(i);
				command->set_vm_address(address);
				if (backward_direction) {
					address -= command->vm_dump_size();
				}
				else {
					address += command->vm_dump_size();
				}
			}
		}
	}
}

void CommandBlock::CompileInfo()
{
	IFunction* func = function();
	for (size_t i = start_index_; i <= end_index_; i++) {
		ICommand* command = func->item(i);
		command->CompileInfo();
	}
}

void CommandBlock::CompileLinks(const CompileContext& ctx)
{
	IFunction* func = function();
	for (size_t i = start_index_; i <= end_index_; i++) {
		ICommand* command = func->item(i);
		command->CompileLink(ctx);
	}
}

size_t CommandBlock::WriteToFile(IArchitecture& file)
{
	size_t i, j;
	ICommand* command;
	IVMCommand* vm_command;
	uint32_t update_type;

	IFunction* func = function();

	update_type = type_;
	if (func->memory_type() != mtNone && (update_type & mtDiscardable) == 0)
		update_type |= mtNotDiscardable;

	if (type_ & mtExecutable) {
		// native block
		for (i = start_index_; i <= end_index_; i++) {
			file.StepProgress();
			command = func->item(i);
			if (!file.AddressSeek(command->address()))
				throw std::runtime_error("Invalid command address");

			file.selected_segment()->include_write_type(update_type);
			command->WriteToFile(file);
		}
	}
	else {
		// VM block
		if (func->item(start_index_)->section_options() & rtBackwardDirection) {
			for (i = end_index_ + 1; i > start_index_; i--) {
				file.StepProgress();
				command = func->item(i - 1);
				if (!file.AddressSeek(command->vm_address() - command->vm_dump_size()))
					throw std::runtime_error("Invalid command address");

				for (j = command->count(); j > 0; j--) {
					vm_command = command->item(j - 1);
					file.selected_segment()->include_write_type(update_type);
					vm_command->WriteToFile(file);
				}
			}
		}
		else {
			for (i = start_index_; i <= end_index_; i++) {
				file.StepProgress();
				command = func->item(i);
				if (!file.AddressSeek(command->vm_address()))
					throw std::runtime_error("Invalid command address");

				for (j = 0; j < command->count(); j++) {
					vm_command = command->item(j);
					file.selected_segment()->include_write_type(update_type);
					vm_command->WriteToFile(file);
				}
			}
		}
	}

	return end_index_ - start_index_ + 1;
}

uint8_t CommandBlock::GetRegistr(OperandSize size, uint8_t registr, bool is_write)
{
	uint8_t res;
	OperandSize cpu_address_size = function()->cpu_address_size();
	if (registr & regExtended) {
		res = (uint8_t)(registr_count_ + (registr & 0xf));
	}
	else if (registr == regEmpty && !is_write) {
		res = (uint8_t)(rand() % registr_count_);
	}
	else {
		if (registr >= _countof(registr_indexes_))
			throw std::runtime_error("Runtime error at GetRegistr");

		res = registr_indexes_[registr];
		if (res == 0xff || (is_write && size == cpu_address_size)) {
			uint8_t empty_registr[_countof(registr_indexes_)];
			size_t empty_registr_count = 0;
			for (size_t i = 0; i < registr_count_; i++) {
				bool is_found = false;
				for (size_t j = 0; j < regEmpty; j++) {
					if (registr_indexes_[j] == i) {
						is_found = true;
						break;
					}
				}
				if (!is_found) {
					empty_registr[empty_registr_count] = (uint8_t)i;
					empty_registr_count++;
				}
			}

			if (empty_registr_count) {
				res = empty_registr[rand() % empty_registr_count];
				if (registr != regEmpty)
					registr_indexes_[registr] = res;
			}
			else if (res == 0xff)
				throw std::runtime_error("Runtime error at GetRegistr");
		}
	}

	return (uint8_t)(res * OperandSizeToValue(cpu_address_size));
}

/**
 * CommandBlockList
 */

CommandBlockList::CommandBlockList(IFunction* owner)
	: ObjectList<CommandBlock>(), owner_(owner)
{

}

CommandBlockList::CommandBlockList(IFunction* owner, const CommandBlockList& src)
	: ObjectList<CommandBlock>(src), owner_(owner)
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

CommandBlockList* CommandBlockList::Clone(IFunction* owner) const
{
	CommandBlockList* list = new CommandBlockList(owner, *this);
	return list;
}

CommandBlock* CommandBlockList::Add(uint32_t memory_type, size_t start_index)
{
	CommandBlock* block = new CommandBlock(this, memory_type, start_index);
	AddObject(block);
	return block;
}

void CommandBlockList::CompileBlocks(MemoryManager& manager)
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->Compile(manager);
	}
}

void CommandBlockList::CompileInfo()
{
	for (size_t i = 0; i < count(); i++) {
		CommandBlock* block = item(i);
		if (block->type() & mtExecutable)
			block->CompileInfo();
	}
}

void CommandBlockList::CompileLinks(const CompileContext& ctx)
{
	size_t i;
	CommandBlock* block;

	for (i = 0; i < count(); i++) {
		block = item(i);
		if ((block->type() & mtExecutable) == 0)
			continue;

		block->CompileLinks(ctx);
	}

	for (i = 0; i < count(); i++) {
		block = item(i);
		if ((block->type() & mtExecutable) != 0)
			continue;

		block->CompileLinks(ctx);
	}
}

size_t CommandBlockList::WriteToFile(IArchitecture& file)
{
	size_t res = 0;
	for (size_t i = 0; i < count(); i++) {
		CommandBlock* block = item(i);
		res += block->WriteToFile(file);
	}
	return res;
}

bool CommandBlockListCompareHelper::operator()(const CommandBlock* block1, const CommandBlock* block2) const
{
	AddressRange* range1 = (block1->type() & mtExecutable) ? block1->function()->item(block1->start_index())->address_range() : NULL;
	AddressRange* range2 = (block2->type() & mtExecutable) ? block2->function()->item(block2->start_index())->address_range() : NULL;

	FunctionInfo* info1 = range1 ? range1->owner() : NULL;
	FunctionInfo* info2 = range2 ? range2->owner() : NULL;

	bool res;
	if (info1 == info2 && range1 && range2) {
		if (range1->original_begin() == range2->original_begin())
			res = range1->original_begin() ? block1->start_index() < block2->start_index() : block1->sort_index() < block2->sort_index();
		else
			res = range1->original_begin() < range2->original_begin();
	}
	else {
		uint64_t value1 = info1 ? info1->begin() : 0;
		uint64_t value2 = info2 ? info2->begin() : 0;
		res = (value1 == value2) ? block1->sort_index() < block2->sort_index() : (value1 < value2);
	}

	return res;
}