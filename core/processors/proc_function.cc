#include "proc_function.h"
#include "proc_command.h"
#include "proc_command_link.h"
#include "proc_command_block.h"
#include "proc_info.h"
#include "proc_vm.h"
#include "../files/references.h"
#include "../files/mapping.h"
#include "../files/sections.h"
#include "../streams.h"
#include "../core_internal/core.h"
#include "../core_internal/watermark.h"
#include "../lang.h"
#include "../../runtime/crypto.h"
#include <intrin.h>
#include <stdexcept>
#include <set>



/**
 * BaseFunction
 */

BaseFunction::BaseFunction(IFunctionList* owner, const FunctionName& name, CompilationType compilation_type, uint32_t compilation_options, bool need_compile, Folder* folder)
	: IFunction(), owner_(owner), name_(name), address_(0), break_address_(0), type_(otUnknown), cpu_address_size_(osDefault), compilation_type_(compilation_type),
	compilation_options_(compilation_options), internal_lock_to_key_(false), default_compilation_type_(ctNone), need_compile_(need_compile), folder_(folder), memory_type_(mtNone),
	tag_(0), entry_(NULL), entry_type_(etDefault), from_runtime_(false), parent_(NULL)
{
	link_list_ = new CommandLinkList();
	ext_command_list_ = new ExtCommandList(this);
	block_list_ = new CommandBlockList(this);
	function_info_list_ = new FunctionInfoList();
	range_list_ = new FunctionInfo();
}

BaseFunction::BaseFunction(IFunctionList* owner, OperandSize cpu_address_size, IFunction* parent)
	: IFunction(), owner_(owner), address_(0), break_address_(0), type_(otCode), cpu_address_size_(cpu_address_size), compilation_type_(ctVirtualization),
	compilation_options_(0), internal_lock_to_key_(false), default_compilation_type_(ctNone), need_compile_(true), folder_(NULL), memory_type_(mtReadable), tag_(0), entry_(NULL),
	entry_type_(etDefault), from_runtime_(false), parent_(parent)
{
	link_list_ = new CommandLinkList();
	ext_command_list_ = new ExtCommandList(this);
	block_list_ = new CommandBlockList(this);
	function_info_list_ = new FunctionInfoList();
	range_list_ = new FunctionInfo();
}

BaseFunction::BaseFunction(IFunctionList* owner, const BaseFunction& src)
	: IFunction(src), owner_(owner), folder_(NULL), parent_(NULL)
{
	size_t i, j;

	address_ = src.address_;
	type_ = src.type_;
	entry_ = NULL;
	entry_type_ = src.entry_type_;
	break_address_ = src.break_address_;
	name_ = src.name_;
	cpu_address_size_ = src.cpu_address_size_;
	need_compile_ = src.need_compile_;

	compilation_type_ = src.compilation_type_;
	compilation_options_ = src.compilation_options_;
	internal_lock_to_key_ = src.internal_lock_to_key_;
	default_compilation_type_ = src.default_compilation_type_;
	memory_type_ = src.memory_type_;
	tag_ = src.tag_;
	from_runtime_ = src.from_runtime_;

	link_list_ = src.link_list_->Clone();
	ext_command_list_ = src.ext_command_list_->Clone(this);
	block_list_ = src.block_list_->Clone(this);
	function_info_list_ = src.function_info_list_->Clone();
	range_list_ = src.range_list_->Clone(NULL);

	for (i = 0; i < src.count(); i++) {
		ICommand* command = src.item(i)->Clone(this);
		AddObject(command);

		AddressRange* address_range = command->address_range();
		if (address_range) {
			FunctionInfo* info = function_info_list_->item(src.function_info_list()->IndexOf(address_range->owner()));
			command->set_address_range(info->item(address_range->owner()->IndexOf(address_range)));
		}
	}

	for (i = 0; i < range_list_->count(); i++) {
		AddressRange* range = range_list_->item(i);
		if (range->begin_entry())
			range->set_begin_entry(item(src.IndexOf(range->begin_entry())));
		if (range->end_entry())
			range->set_end_entry(item(src.IndexOf(range->end_entry())));
		if (range->size_entry())
			range->set_size_entry(item(src.IndexOf(range->size_entry())));
	}

	for (i = 0; i < function_info_list()->count(); i++) {
		FunctionInfo* info = function_info_list()->item(i);
		if (info->entry())
			info->set_entry(item(src.IndexOf(info->entry())));
		if (info->data_entry())
			info->set_data_entry(item(src.IndexOf(info->data_entry())));
		std::vector<ICommand*> unwind_opcodes = *info->unwind_opcodes();
		for (j = 0; j < unwind_opcodes.size(); j++) {
			unwind_opcodes[j] = item(src.IndexOf(unwind_opcodes[j]));
		}
		info->set_unwind_opcodes(unwind_opcodes);
	}

	if (src.entry_)
		entry_ = item(src.IndexOf(src.entry_));

	for (i = 0; i < src.count(); i++) {
		CommandLink* src_link = src.item(i)->link();
		if (!src_link)
			continue;

		CommandLink* link = link_list_->item(src.link_list()->IndexOf(src_link));
		link->set_from_command(item(i));
		if (src_link->parent_command())
			link->set_parent_command(item(src.IndexOf(src_link->parent_command())));
		if (src_link->base_function_info())
			link->set_base_function_info(function_info_list()->item(src.function_info_list()->IndexOf(src_link->base_function_info())));
	}

	for (i = 0; i < src.ext_command_list()->count(); i++) {
		ExtCommand* ext_command = src.ext_command_list()->item(i);
		if (!ext_command->command())
			continue;

		ext_command_list_->item(i)->set_command(item(src.IndexOf(ext_command->command())));
	}
}

BaseFunction::~BaseFunction()
{
	if (owner_)
		owner_->RemoveObject(this);

	delete link_list_;
	delete ext_command_list_;
	delete block_list_;
	delete function_info_list_;
	delete range_list_;
}

void BaseFunction::AddObject(ICommand* command)
{
	ObjectList<ICommand>::AddObject(command);
	if (command->address())
		map_[command->address()] = command;
}

void BaseFunction::RemoveObject(ICommand* command)
{
	for (map_command_list_t::iterator it = map_.begin(); it != map_.end(); it++) {
		if (it->second == command) {
			map_.erase(it);
			break;
		}
	}
	IFunction::RemoveObject(command);
}

ICommand* BaseFunction::GetCommandByLowerAddress(uint64_t address) const
{
	if (map_.empty())
		return NULL;

	map_command_list_t::const_iterator it = map_.upper_bound(address);
	if (it != map_.begin())
		it--;

	return it->first > address ? NULL : it->second;
}

ICommand* BaseFunction::GetCommandByUpperAddress(uint64_t address) const
{
	if (map_.empty())
		return NULL;

	map_command_list_t::const_iterator it = map_.upper_bound(address);
	if (it == map_.end())
		return NULL;

	return it->second;
}

ICommand* BaseFunction::GetCommandByNearAddress(uint64_t address) const
{
	ICommand* command = GetCommandByLowerAddress(address);
	if (command && command->address() <= address && command->address() + command->original_dump_size() > address)
		return command;

	return NULL;
}

ICommand* BaseFunction::GetCommandByAddress(uint64_t address) const
{
	ICommand* command = GetCommandByLowerAddress(address);
	if (command && command->address() == address)
		return command;

	return NULL;
}

uint64_t BaseFunction::GetNextAddress(IArchitecture& file)
{
	size_t i, j;
	uint64_t max_address;
	CommandLink* link;
	LinkType link_type;
	uint64_t to_address;

	for (i = 0; i < link_list_->count(); i++) {
		link = link_list_->item(i);
		link_type = link->type();
		if (link->parsed() || link_type == ltCall)
			continue;

		to_address = link->to_address();
		if (link_type == ltNone || link_type == ltOffset || link_type == ltDelta || GetCommandByNearAddress(to_address)) {
			link->set_parsed(true);
		}
		else if (to_address < address_) {
			link->set_parsed(true);
			if (parent() && (link_type == ltJmp || link_type == ltJmpWithFlag)) {
				IFunction* func = parent();
				while (func) {
					if (to_address > func->address()) {
						address_ = to_address;
						return to_address;
					}
					func = func->parent();
				}
			}
		}
		else if (link_type == ltJmp) {
			if (file.runtime_function_list()) {
				IRuntimeFunction* runtime_function = file.runtime_function_list()->GetFunctionByAddress(link->from_command()->address());
				if (runtime_function && to_address >= runtime_function->begin() && to_address < runtime_function->end()) {
					link->set_parsed(true);
					return to_address;
				}
			}
		}
		else {
			link->set_parsed(true);
			return to_address;
		}
	}

	max_address = address_;
	for (i = 0; i < link_list_->count(); i++) {
		link = link_list_->item(i);

		switch (link->type()) {
		case ltSEHBlock:
		case ltFinallyBlock:
		case ltDualSEHBlock:
		case ltFilterSEHBlock:
		case ltJmpWithFlag:
			if (link->to_address() > max_address)
				max_address = link->to_address();
			break;
		}
	}

	for (i = 0; i < link_list_->count(); i++) {
		link = link_list_->item(i);
		if (link->parsed())
			continue;

		to_address = link->to_address();
		if (link->type() == ltJmp && to_address < max_address) {
			link->set_parsed(true);
			return to_address;
		}
	}

	for (i = 0; i < link_list_->count(); i++) {
		link = link_list_->item(i);
		if (link->parsed() || link->type() != ltJmp)
			continue;

		// backward/forward jump
		bool res = false;
		to_address = link->to_address();
		if (parent()) {
			res = true;
		}
		else {
			bool is_forward_aligned = to_address > link->from_command()->address() && (to_address & 0x0f) == 0;
			IFunction* temp_func = CreateFunction(this);
			temp_func->ReadFromFile(file, to_address);
			for (j = 0; j < temp_func->count(); j++) {
				ICommand* command = temp_func->item(j);
				CommandLink* temp_link = command->link();
				if (temp_link && (temp_link->type() == ltJmp || temp_link->type() == ltJmpWithFlag)) {
					if (GetCommandByAddress(temp_link->to_address()) || (is_forward_aligned && temp_link->to_address() == to_address)
						|| (temp_link->type() == ltJmpWithFlag && temp_link->to_address() == link->from_command()->next_address())) {
						res = true;
						break;
					}
				}
				if (command->is_data() || command->is_end() || (command->options() & roBreaked))
					continue;

				if (command->next_address() == to_address) {
					res = true;
					break;
				}
			}
			delete temp_func;
		}

		if (res) {
			link->set_parsed(true);
			return to_address;
		}
	}

	return 0;
}

void BaseFunction::clear()
{
	address_ = 0;
	break_address_ = 0;
	type_ = otUnknown;
	entry_ = NULL;
	entry_type_ = etDefault;
	name_.clear();
	internal_lock_to_key_ = false;
	default_compilation_type_ = ctNone;

	ClearItems();
}

void BaseFunction::ClearItems()
{
	map_.clear();
	link_list_->clear();
	ext_command_list_->clear();
	block_list_->clear();
	function_info_list_->clear();
	range_list_->clear();
	IFunction::clear();
}

size_t BaseFunction::ReadFromFile(IArchitecture& file, uint64_t address)
{
	MapFunction* map_function;
	ICommand* command;
	ISectionList* segment_list;
	uint64_t def_parsed_address, parsed_address;
	size_t i;
	Reference* ref;
	ReferenceList* reference_list;

	clear();

	address_ = address;
	cpu_address_size_ = file.cpu_address_size();
	memory_type_ = file.segment_list()->GetMemoryTypeByAddress(address);

	map_function = file.map_function_list()->GetFunctionByAddress(address);
	if (map_function) {
		default_compilation_type_ = map_function->compilation_type();
		internal_lock_to_key_ = map_function->lock_to_key();
		name_ = map_function->full_name();
		type_ = map_function->type();
	}
	else {
		name_.clear();
		type_ = otCode;
	}

	ParseBeginCommands(file);

	if (type_ == otString) {
		if (map_function) {
			ParseString(file, address_, static_cast<size_t>(map_function->end_address() - address_));
			reference_list = map_function->equal_address_list();
			for (i = 0; i < reference_list->count(); i++) {
				ref = reference_list->item(i);
				ParseString(file, ref->address(), static_cast<size_t>(ref->operand_address() - ref->address()));
			}
		}
	}
	else {
		segment_list = file.segment_list();
		def_parsed_address = -1;
		parsed_address = def_parsed_address;
		IRuntimeFunctionList* runtime_function_list = file.runtime_function_list();
		IRuntimeFunction* runtime_function = NULL;

		for (;;) {
			command = NULL;
			if (address < parsed_address && (segment_list->GetMemoryTypeByAddress(address) & mtExecutable)) {
				if (runtime_function_list) {
					if (runtime_function && (address < runtime_function->begin() || address >= runtime_function->end()))
						runtime_function = NULL;
					if (!runtime_function)
						runtime_function = runtime_function_list->GetFunctionByAddress(address);
					if (runtime_function)
						runtime_function->Parse(file, *this);
				}
				command = ParseCommand(file, address);
			}

			if (!command || command->is_end() || (command->options() & roBreaked) != 0) {
				address = GetNextAddress(file);
				if (!address)
					break;
				command = GetCommandByUpperAddress(address);
				parsed_address = command ? command->address() : def_parsed_address;
			}
			else {
				address = command->next_address();
			}
		}
	}

	ParseEndCommands(file);

	Sort();

	if (type_ != otString)
		entry_ = GetCommandByAddress(address_);

	return count();
}

bool BaseFunction::FreeByManager(const CompileContext& ctx)
{
	MemoryManager* manager = ctx.manager;
	uint64_t block_address = 0;
	size_t block_size = 0;
	uint32_t block_memory_type = mtNone;
	ISectionList* segment_list = (from_runtime() ? ctx.runtime : ctx.file)->segment_list();

	for (size_t i = 0; i < count(); i++) {
		ICommand* command = item(i);
		if (command->address() && (command->options() & roClearOriginalCode) && !is_breaked_address(command->address())) {
			for (size_t j = 0; j < command->original_dump_size(); j++) {
				MemoryRegion* region = manager->GetRegionByAddress(command->address() + j);
				if (region) {
					IFunction* func = region->parent_function();
					uint64_t func_address;
					std::string func_name;
					if (func) {
						func_name = func->name();
						func_address = func->address();
					}
					else {
						func_name.clear();
						func_address = region->address();
					}
					if (func_name.empty())
						func_name = string_format("%.8llX", func_address);
					ctx.file->Notify(mtError, command, string_format(language[lsAddressUsedByFunction].c_str(), func_name.c_str()));
					return false;
				}
			}

			uint32_t command_memory_type = segment_list->GetMemoryTypeByAddress(command->address());
			if (block_address && ((block_address + block_size) != command->address() || block_memory_type != command_memory_type)) {
				if (block_size)
					manager->Add(block_address, block_size, block_memory_type, this);
				block_address = 0;
				block_size = 0;
				block_memory_type = mtNone;
			}
			if (!block_address) {
				block_address = command->address();
				block_memory_type = command_memory_type;
			}
			block_size += command->original_dump_size();
		}
	}

	if (block_size)
		manager->Add(block_address, block_size, block_memory_type, this);

	return true;
}

bool BaseFunction::PrepareExtCommands(const CompileContext& ctx)
{
	return true;
}

bool BaseFunction::PrepareLinks(const CompileContext& ctx)
{
	IFunctionList* function_list = ctx.file->function_list();
	for (size_t i = 0; i < link_list_->count(); i++) {
		CommandLink* link = link_list_->item(i);
		if (link->type() == ltNone)
			continue;

		if (link->to_address()) {
			ICommand* command = function_list->GetCommandByAddress(link->to_address(), true);
			if (is_breaked_address(link->from_command()->address())) {
				if (command && command->owner()->address() != link->to_address() && !command->owner()->ext_command_list()->GetCommandByAddress(link->to_address()))
					ctx.file->Notify(mtWarning, link->from_command(), string_format(language[lsJumpToInternalAddress].c_str(), link->to_address()));
				continue;
			}
			else {
				if (!command && function_list->GetCommandByNearAddress(link->to_address(), true)) {
					ctx.file->Notify(mtError, link->from_command(), language[lsJumpToCommandPart]);
					return false;
				}
				link->set_to_command(command && (command->options() & roNeedCompile) ? command : NULL);
			}
		}

		link->from_command()->PrepareLink(ctx);
	}

	return true;
}

bool BaseFunction::Init(const CompileContext&/*ctx*/)
{
	ICommand* command;
	size_t i;

	if (function_info_list()->count()) {
		std::set<uint64_t> address_list;
		FunctionInfo* info;
		AddressRange* range;
		for (i = 0; i < function_info_list_->count(); i++) {
			info = function_info_list_->item(i);
			address_list.insert(info->begin());
			address_list.insert(info->end());
		}
		for (i = 0; i < range_list_->count(); i++) {
			range = range_list_->item(i);
			info = function_info_list_->GetItemByAddress(range->begin());
			if (!info)
				continue;

			range->set_link_info(info);
			if (!range->end())
				range->set_end(info->end());
			address_list.insert(range->begin());
			address_list.insert(range->end());
		}

		uint64_t begin = 0;
		for (std::set<uint64_t>::const_iterator it = address_list.begin(); it != address_list.end(); it++) {
			if (begin) {
				uint64_t end = *it;
				info = function_info_list_->GetItemByAddress(begin);
				if (info) {
					AddressRange* dest = info->Add(begin, end, NULL, NULL, NULL);
					for (i = 0; i < range_list_->count(); i++) {
						range = range_list_->item(i);
						if (range->begin() <= begin && range->end() > begin)
							dest->AddLink(range);
					}
				}
			}
			begin = *it;
		}

		for (i = 0; i < count(); i++) {
			command = item(i);
			if (command->address_range())
				continue;

			command->set_address_range(function_info_list_->GetRangeByAddress(command->address()));
		}
	}

	return true;
}

bool BaseFunction::Prepare(const CompileContext& ctx)
{
	if (!FreeByManager(ctx))
		return false;

	range_list()->Prepare();
	function_info_list()->Prepare();

	return true;
}

bool BaseFunction::Compile(const CompileContext& ctx)
{
	return true;
}

void BaseFunction::AfterCompile(const CompileContext& ctx)
{

}

void BaseFunction::CompileInfo(const CompileContext& ctx)
{
	block_list()->CompileInfo();
	function_info_list()->Compile();
}

void BaseFunction::CompileLinks(const CompileContext& ctx)
{
	block_list()->CompileLinks(ctx);
}

size_t BaseFunction::WriteToFile(IArchitecture& file)
{
	size_t res = block_list_->WriteToFile(file);
	function_info_list_->WriteToFile(file);
	return res;
}

void BaseFunction::ReadFromBuffer(Buffer& buffer, IArchitecture& file)
{
	size_t i, j, c;
	ICommand* command;
	uint64_t add_address = file.image_base();

	tag_ = buffer.ReadByte();
	uint8_t b = buffer.ReadByte();

	switch (b & 0x30) {
	case 0x10:
		entry_type_ = etNone;
		break;
	case 0x20:
		entry_type_ = etRandomAddress;
		break;
	}

	compilation_type_ = static_cast<CompilationType>(b & 0xf);
	type_ = static_cast<ObjectType>(buffer.ReadByte());
	cpu_address_size_ = static_cast<OperandSize>(buffer.ReadByte());
	address_ = buffer.ReadDWord() + add_address;

	c = buffer.ReadDWord();
	for (i = 0; i < c; i++) {
		command = CreateCommand();
		command->ReadFromBuffer(buffer, file);
		AddObject(command);
	}

	c = buffer.ReadDWord();
	for (i = 0; i < c; i++) {
		uint32_t begin = buffer.ReadDWord();
		uint32_t end = buffer.ReadDWord();
		AddressBaseType base_type = static_cast<AddressBaseType>(buffer.ReadByte());
		uint32_t base_value = (base_type == btValue) ? buffer.ReadDWord() : 0;
		size_t prolog_size = buffer.ReadDWord();
		uint8_t frame_registr = buffer.ReadByte();
		uint32_t index = buffer.ReadDWord();
		uint32_t data_index = buffer.ReadDWord();
		std::vector<ICommand*> unwind_opcodes;
		unwind_opcodes.resize(buffer.ReadDWord());
		for (j = 0; j < unwind_opcodes.size(); j++) {
			unwind_opcodes[j] = item(buffer.ReadDWord() - 1);
		}
		FunctionInfo* info = function_info_list()->Add(begin + add_address, end + add_address, base_type, base_value, prolog_size, frame_registr,
			file.runtime_function_list()->GetFunctionByAddress(begin + add_address), (index != 0) ? item(index - 1) : NULL);
		if (data_index != 0)
			info->set_data_entry(item(data_index - 1));
		info->set_unwind_opcodes(unwind_opcodes);
	}

	c = buffer.ReadDWord();
	for (i = 0; i < c; i++) {
		uint32_t begin = buffer.ReadDWord();
		uint32_t end = buffer.ReadDWord();
		uint32_t begin_index = buffer.ReadDWord();
		uint32_t end_index = buffer.ReadDWord();
		uint32_t size_index = buffer.ReadDWord();
		range_list_->Add(begin + add_address, end + add_address,
			begin_index != 0 ? item(begin_index - 1) : NULL,
			end_index != 0 ? item(end_index - 1) : NULL,
			size_index != 0 ? item(size_index - 1) : NULL);
	}

	c = buffer.ReadDWord();
	for (i = 0; i < c; i++) {
		uint32_t dw = buffer.ReadDWord();
		LinkType link_type = static_cast<LinkType>(buffer.ReadByte());
		int operand_index = static_cast<int8_t>(buffer.ReadByte());
		uint8_t opt = buffer.ReadByte();
		uint64_t qw = (opt & 1) ? buffer.ReadDWord() + add_address : 0;
		CommandLink* link = item(dw - 1)->AddLink(operand_index, link_type, qw);
		if (opt & 2)
			link->set_sub_value(buffer.ReadDWord() + add_address);
		if (opt & 4) {
			dw = buffer.ReadDWord();
			if (dw != 0)
				link->set_parent_command(item(dw - 1));
		}
		if (opt & 8) {
			dw = buffer.ReadDWord();
			if (dw != 0)
				link->set_base_function_info(function_info_list()->item(dw - 1));
		}
	}

	memory_type_ = owner_->owner()->segment_list()->GetMemoryTypeByAddress(address_);
	if (type_ != otString)
		entry_ = GetCommandByAddress(address_);
}

CommandBlock* BaseFunction::AddBlock(size_t start_index, bool is_executable)
{
	return block_list_->Add((memory_type_ & (mtDiscardable | mtNotPaged)) | (is_executable ? mtExecutable : mtReadable), start_index);
}

uint8_t* version_watermark = NULL;
uint8_t* owner_watermark = NULL;

void BaseFunction::AddWatermark(Watermark* watermark, int copy_count)
{
	Watermark secure_watermark(NULL);
	std::string value;
	uint8_t* internal_watermarks[] = { version_watermark, owner_watermark };

	for (size_t k = 0; k < 1 + _countof(internal_watermarks); k++) {
		if (k == 0) {
			if (!watermark)
				continue;
		}
		else {
			uint8_t* ptr = internal_watermarks[k - 1];
			if (!ptr)
				continue;

			uint32_t key = *reinterpret_cast<uint32_t*>(ptr);
			uint16_t len = *reinterpret_cast<uint16_t*>(ptr + 4);
			value.resize(len);
			for (size_t i = 0; i < value.size(); i++) {
				value[i] = ptr[6 + i] ^ static_cast<uint8_t>(_rotl32(key, (int)i) + i);
			}
			secure_watermark.set_value(value);
			watermark = &secure_watermark;
		}

		for (int i = 0; i < copy_count; i++) {
			watermark->Compile();
			ICommand* command = AddCommand(Data(watermark->dump()));
			command->include_option(roCreateNewBlock);
		}
	}
}

void BaseFunction::Rebase(uint64_t delta_base)
{
	map_.clear();
	for (size_t i = 0; i < count(); i++) {
		ICommand* command = item(i);
		command->Rebase(delta_base);
		if (command->address())
			map_[command->address()] = command;
	}
	link_list_->Rebase(delta_base);
	range_list_->Rebase(delta_base);
	function_info_list_->Rebase(delta_base);

	if (address_)
		address_ += delta_base;
}

void BaseFunction::Notify(MessageType type, IObject* sender, const std::string& message) const
{
	if (owner_)
		owner_->Notify(type, sender, message);
}

void BaseFunction::set_compilation_type(CompilationType compilation_type)
{
	if (default_compilation_type_ != ctNone)
		return;

	if (compilation_type_ != compilation_type) {
		compilation_type_ = compilation_type;
		Notify(mtChanged, this);
	}
}

void BaseFunction::set_compilation_options(uint32_t compilation_options)
{
	if (compilation_options_ != compilation_options) {
		compilation_options_ = compilation_options;
		Notify(mtChanged, this);
	}
}

void BaseFunction::set_need_compile(bool need_compile)
{
	if (need_compile_ != need_compile) {
		need_compile_ = need_compile;
		Notify(mtChanged, this);
	}
}

void BaseFunction::set_folder(Folder* folder)
{
	if (folder_ != folder) {
		folder_ = folder;
		Notify(mtChanged, this);
	}
}

void BaseFunction::set_break_address(uint64_t break_address)
{
	if (type_ == otString)
		return;

	if (break_address_ != break_address) {
		break_address_ = break_address;
		Notify(mtChanged, this);
	}
}

std::string BaseFunction::display_address(const std::string& arch_name) const
{
	std::string res;
	if (type() != otUnknown)
		res.append(arch_name).append(DisplayValue(cpu_address_size(), address()));
	if (type() == otString) {
		for (size_t i = 1; i < count(); i++) {
			res.append(", ").append(arch_name).append(DisplayValue(cpu_address_size(), item(i)->address()));
		}
	}

	return res;
}

Data BaseFunction::hash() const
{
	Data res;
	bool is_unknown = (type() == otUnknown);
	res.PushBuff(name().c_str(), name().size() + 1);
	res.PushByte(need_compile());
	res.PushByte(is_unknown);
	res.PushDWord(is_unknown ? tag() : -1);
	res.PushByte(compilation_type());
	res.PushDWord(compilation_options());
	res.PushDWord(break_address() ? static_cast<uint32_t>(break_address() - address()) : 0);
	res.PushDWord(static_cast<uint32_t>(ext_command_list()->count()));
	for (size_t i = 0; i < ext_command_list()->count(); i++) {
		res.PushDWord(static_cast<uint32_t>(ext_command_list()->item(i)->address() - address()));
	}
	return res;
}

#ifdef CHECKED
bool BaseFunction::check_hash() const
{
	for (size_t i = 0; i < count(); i++) {
		if (!item(i)->check_hash())
			return false;
	}
	return true;
}
#endif

IVirtualMachine* BaseFunction::virtual_machine(IVirtualMachineList* virtual_machine_list, ICommand* command) const
{
	if (virtual_machine_list) {
		std::vector<IVirtualMachine*> list;
		for (size_t i = 0; i < virtual_machine_list->count(); i++) {
			IVirtualMachine* virtual_machine = virtual_machine_list->item(i);
			if (virtual_machine->processor()->cpu_address_size() == cpu_address_size())
				list.push_back(virtual_machine);
		}
		return list[rand() % list.size()];
	}

	return NULL;
}

/**
 * BaseFunctionList
 */

BaseFunctionList::BaseFunctionList(IArchitecture* owner)
	: IFunctionList(), owner_(owner)
{

}

BaseFunctionList::BaseFunctionList(IArchitecture* owner, const BaseFunctionList& src)
	: IFunctionList(src), owner_(owner)
{
	size_t i;
	std::vector<Folder*> src_folders, folders;
	Folder* folder;

	for (i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}

	src_folders = src.owner()->owner()->folder_list()->GetFolderList();
	FolderList* folder_list = NULL;
	if (owner && owner->owner()) folder_list = owner->owner()->folder_list();
	if (folder_list) folders = folder_list->GetFolderList();
	for (i = 0; i < src.count(); i++) {
		std::vector<Folder*>::const_iterator it = std::find(src_folders.begin(), src_folders.end(), src.item(i)->folder());
		folder = (it == src_folders.end()) ? folder_list : *it;
		if (folder) item(i)->set_folder(folder);
	}
}

IFunction* BaseFunctionList::AddUnknown(const std::string& name, CompilationType compilation_type, uint32_t compilation_options, bool need_compile, Folder* folder)
{
	IFunction* func = GetUnknownByName(name);
	if (!func) {
		func = Add(name, compilation_type, compilation_options, need_compile, folder);
		if (func)
			Notify(mtAdded, func);
	}
	else {
		func->set_compilation_type(compilation_type);
		func->set_compilation_options(compilation_options);
		func->set_need_compile(need_compile);
		func->set_folder(folder);
	}
	return func;
};

IFunction* BaseFunctionList::AddByAddress(uint64_t address, CompilationType compilation_type, uint32_t compilation_options, bool need_compile, Folder* folder)
{
	IFunction* func = GetFunctionByAddress(address);
	if (!func) {
		// check address
		uint32_t memory_type = owner_->segment_list()->GetMemoryTypeByAddress(address);
		if ((memory_type & mtExecutable) == 0) {
			MapFunction* map_function = owner_->map_function_list()->GetFunctionByAddress(address);
			if (!map_function || map_function->type() != otString)
				return NULL;
		}

		func = Add("", compilation_type, compilation_options, need_compile, folder);
		if (func) {
			func->ReadFromFile(*owner_, address);
			Notify(mtAdded, func);
		}
	}
	else {
		func->set_compilation_type(compilation_type);
		func->set_compilation_options(compilation_options);
		func->set_need_compile(need_compile);
		func->set_folder(folder);
	}
	return func;
};

IFunction* BaseFunctionList::GetFunctionByAddress(uint64_t address) const
{
	for (size_t i = 0; i < count(); i++) {
		IFunction* func = item(i);
		if (func->address() == address)
			return func;
	}

	return NULL;
}

IFunction* BaseFunctionList::GetFunctionByName(const std::string& name) const
{
	for (size_t i = 0; i < count(); i++) {
		IFunction* func = item(i);
		if (func->name().compare(name) == 0 && func->type() != otUnknown)
			return func;
	}

	return NULL;
}

IFunction* BaseFunctionList::GetUnknownByName(const std::string& name) const
{
	for (size_t i = 0; i < count(); i++) {
		IFunction* func = item(i);
		if (func->name().compare(name) == 0 && func->type() == otUnknown)
			return func;
	}

	return NULL;
}

ICommand* BaseFunctionList::GetCommandByAddress(uint64_t address, bool need_compile) const
{
	for (size_t i = 0; i < count(); i++) {
		IFunction* func = item(i);
		if (need_compile && !func->need_compile())
			continue;

		ICommand* command = func->GetCommandByAddress(address);
		if (command)
			return (need_compile && func->is_breaked_address(command->address())) ? NULL : command;
	}

	return NULL;
}

ICommand* BaseFunctionList::GetCommandByNearAddress(uint64_t address, bool need_compile) const
{
	for (size_t i = 0; i < count(); i++) {
		IFunction* func = item(i);
		if (need_compile && !func->need_compile())
			continue;

		ICommand* command = func->GetCommandByNearAddress(address);
		if (command)
			return (need_compile && func->is_breaked_address(command->address())) ? NULL : command;
	}

	return NULL;
}

bool BaseFunctionList::Prepare(const CompileContext& ctx)
{
	size_t i, j;

	bool need_machines = (ctx.runtime != NULL);
	uint32_t memory_type = mtReadable | mtDiscardable;
	for (i = count(); i > 0; i--) {
		IFunction* func = item(i - 1);
		if (!func->need_compile())
			delete func;
		else if (func->type() != otUnknown && func->compilation_type() != ctMutation) {
			if ((func->memory_type() & mtDiscardable) == 0)
				memory_type &= ~mtDiscardable;
			if (func->memory_type() & mtNotPaged)
				memory_type |= mtNotPaged;
			need_machines = true;
		}
	}

	if (need_machines) {
		IVirtualMachineList* virtual_machine_list = ctx.file->virtual_machine_list();
		virtual_machine_list->Prepare(ctx);
		std::vector<IFunction*> processor_list = ctx.file->function_list()->processor_list();
		for (i = 0; i < processor_list.size(); i++) {
			processor_list[i]->set_memory_type(memory_type);
		}
	}

	for (j = 0; j < 4; j++) {
		for (i = 0; i < count(); i++) {
			IFunction* func = item(i);
			switch (j) {
			case 0:
				if (func->type() == otUnknown) {
					ctx.file->Notify(mtWarning, func, string_format(language[lsFunctionNotFound].c_str(), func->name().c_str()));
					continue;
				}
				if (!func->Init(ctx))
					return false;
				break;
			case 1:
				if (!func->Prepare(ctx))
					return false;
				break;
			case 2:
				if (!func->PrepareExtCommands(ctx))
					return false;
				break;
			case 3:
				if (!func->PrepareLinks(ctx))
					return false;
				break;
			}
		}
	}

	return true;
}

bool BaseFunctionList::Compile(const CompileContext& ctx)
{
	size_t i, j, k;
	IFunction* func;
	CommandBlock* block;
	std::vector<CommandBlock*> block_list;

	j = 0;
	auto jjj = count();
	for (i = 0; i < count(); i++) {
		func = item(i);
		j += func->count();
		if (func->compilation_type() == ctUltra)
			j += func->count();
	}
	ctx.file->StartProgress(string_format("%s...", language[lsCompiling].c_str()), j);

	for (i = 0; i < count(); i++) {
		func = item(i);
		if (!func->Compile(ctx))
			return false;
	}
	for (i = 0; i < count(); i++) {
		func = item(i);
		func->AfterCompile(ctx);
		if (!func->need_compile())
			continue;

		for (j = 0; j < func->block_list()->count(); j++) {
			block_list.push_back(func->block_list()->item(j));
		}
	}

	for (i = 0; i < block_list.size(); i++) {
		std::swap(block_list[i], block_list[rand() % block_list.size()]);
	}

	if (ctx.file->runtime_function_list() && ctx.file->runtime_function_list()->count()) {
		// sort blocks by address range
		for (i = 0; i < block_list.size(); i++) {
			block_list[i]->set_sort_index(i);
		}
		std::sort(block_list.begin(), block_list.end(), CommandBlockListCompareHelper());
		// add prolog blocks
		std::set<FunctionInfo*> function_info_list;
		Data data;
		for (i = 0; i < block_list.size(); i++) {
			block = block_list[i];
			if ((block->type() & mtExecutable) == 0)
				continue;

			AddressRange* address_range = block->function()->item(block->start_index())->address_range();
			if (!address_range)
				continue;

			FunctionInfo* function_info = address_range->owner();
			if (!function_info->prolog_size() || function_info_list.find(function_info) != function_info_list.end())
				continue;

			func = block->function();
			size_t prolog_size = 0;
			for (j = block->start_index(); j <= block->end_index(); j++) {
				prolog_size += func->item(j)->dump_size();
			}

			if (prolog_size < function_info->prolog_size()) {
				size_t size = function_info->prolog_size() - prolog_size;
				data.resize(size);
				for (k = 0; k < data.size(); k++) {
					data[k] = rand();
				}
				CommandBlock* new_block = func->AddBlock(func->count(), true);
				ICommand* command = func->AddCommand(data);
				command->set_block(new_block);
				command->set_address_range(address_range);

				block_list.insert(block_list.begin() + i + 1, new_block);
			}

			function_info_list.insert(function_info);
		}
	}

	for (i = 0; i < block_list.size(); i++) {
		block_list[i]->Compile(*ctx.manager);
	}

	CompileInfo(ctx);
	CompileLinks(ctx);

	ctx.file->EndProgress();

	return true;
}

void BaseFunctionList::CompileInfo(const CompileContext& ctx)
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->CompileInfo(ctx);
	}
}

void BaseFunctionList::CompileLinks(const CompileContext& ctx)
{
	for (size_t i = 0; i < count(); i++) {
		IFunction* func = item(i);
		if (func->compilation_type() != ctMutation)
			continue;

		func->CompileLinks(ctx);
	}

	for (size_t i = 0; i < count(); i++) {
		IFunction* func = item(i);
		if (func->compilation_type() == ctMutation)
			continue;

		func->CompileLinks(ctx);
	}
}

void BaseFunctionList::ReadFromBuffer(Buffer& buffer, IArchitecture& file)
{
	size_t c = buffer.ReadDWord();
	for (size_t i = 0; i < c; i++) {
		IFunction* func = CreateFunction();
		AddObject(func);

		func->ReadFromBuffer(buffer, file);
	}
}

void BaseFunctionList::Rebase(uint64_t delta_base)
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->Rebase(delta_base);
	}
}

void BaseFunctionList::RemoveObject(IFunction* func)
{
	Notify(mtDeleted, func);
	IFunctionList::RemoveObject(func);
}

void BaseFunctionList::Notify(MessageType type, IObject* sender, const std::string& message) const
{
	if (owner_)
		owner_->Notify(type, sender, message);
}

std::vector<IFunction*> BaseFunctionList::processor_list() const
{
	std::vector<IFunction*> res;
	for (size_t i = 0; i < count(); i++) {
		IFunction* func = item(i);
		if (func->tag() == ftProcessor)
			res.push_back(func);
	}
	return res;
}

#ifdef CHECKED
bool BaseFunctionList::check_hash() const
{
	for (size_t i = 0; i < count(); i++) {
		if (!item(i)->check_hash())
			return false;
	}
	return true;
}
#endif