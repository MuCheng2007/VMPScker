#include "IntelFunction.h"
#include "IntelCommand.h"
#include "IntelObfuscation.h"
#include "IntelFunctionList.h"
#include "../../processors.h"
#include "../../core.h"
#include "../../files.h"
#include "../vm/IntelVirtualMachine.h"
#include "IntelVMCommand.h"
#include "../../pefile.h"
#include "../../packer.h"
#include "../../lang.h"
#include "../../osutils.h"
#include "../../../runtime/crypto.h"
#include "../../../runtime/loader.h"
#include "../../core_internal/watermark.h"

// Copied from intel.cc: IntelFunction implementation
// Line range: ~12749 - 16493 and ~20294 - 20419
// Note: IntelFunction implementation is split in two places, needs merging

/**
 * IntelFunction
 */

IntelFunction::IntelFunction(IFunctionList* owner, const std::string& name, CompilationType compilation_type, uint32_t compilation_options, bool need_compile, Folder* folder)
	: BaseFunction(owner, name, compilation_type, compilation_options, need_compile, folder)
{
	section_cryptor_list_ = new SectionCryptorList(this);
}

IntelFunction::IntelFunction(IFunctionList* owner)
	: BaseFunction(owner, FunctionName(""), ctVirtualization, 0, true, NULL)
{
	section_cryptor_list_ = new SectionCryptorList(this);
}

IntelFunction::IntelFunction(IFunctionList* owner, OperandSize cpu_address_size, IFunction* parent)
	: BaseFunction(owner, cpu_address_size, parent)
{
	section_cryptor_list_ = new SectionCryptorList(this);
}

IntelFunction::IntelFunction(IFunctionList* owner, const IntelFunction& src)
	: BaseFunction(owner, src)
{
	section_cryptor_list_ = new SectionCryptorList(this);
}

IntelFunction* IntelFunction::Clone(IFunctionList* owner) const
{
	IntelFunction* func = new IntelFunction(owner, *this);
	return func;
}

IntelFunction::~IntelFunction()
{
	delete section_cryptor_list_;
}

void IntelFunction::clear()
{
	break_case_list_.clear();
	BaseFunction::clear();
}

IntelCommand* IntelFunction::GetCommandByAddress(uint64_t address) const
{
	return reinterpret_cast<IntelCommand*>(BaseFunction::GetCommandByAddress(address));
}

IntelCommand* IntelFunction::GetCommandByNearAddress(uint64_t address) const
{
	return reinterpret_cast<IntelCommand*>(BaseFunction::GetCommandByNearAddress(address));
}

IntelCommand* IntelFunction::Add(uint64_t address)
{
	IntelCommand* command = new IntelCommand(this, cpu_address_size(), address);
	AddObject(command);
	return command;
}

IntelCommand* IntelFunction::AddCommand(IntelCommandType type, IntelOperand operand1, IntelOperand operand2, IntelOperand operand3)
{
	IntelCommand* command = new IntelCommand(this, cpu_address_size(), type, operand1, operand2, operand3);
	AddObject(command);
	return command;
}

IntelCommand* IntelFunction::AddCommand(const std::string& value)
{
	IntelCommand* command = new IntelCommand(this, cpu_address_size(), value);
	AddObject(command);
	return command;
}

IntelCommand* IntelFunction::AddCommand(const os::unicode_string& value)
{
	IntelCommand* command = new IntelCommand(this, cpu_address_size(), value);
	AddObject(command);
	return command;
}

IntelCommand* IntelFunction::AddCommand(const Data& value)
{
	IntelCommand* command = new IntelCommand(this, cpu_address_size(), value);
	AddObject(command);
	return command;
}

IntelCommand* IntelFunction::AddCommand(OperandSize value_size, uint64_t value)
{
	IntelCommandType command_type;
	switch (value_size) {
	case osWord:
		command_type = cmDW;
		break;
	case osDWord:
		command_type = cmDD;
		break;
	case osQWord:
		command_type = cmDQ;
		break;
	default:
		return NULL;
	}

	return AddCommand(command_type, IntelOperand(otValue, value_size, 0, value));
}

bool IntelFunction::ParseFilterSEH(IArchitecture& file, uint64_t address)
{
	uint32_t table_count;
	size_t i, j, c;
	uint64_t pos, value;
	IntelCommand* command;

	if (file.cpu_address_size() != osDWord || !file.AddressSeek(address))
		return false;

	pos = file.Tell();
	table_count = file.ReadDWord();
	for (i = 0; i < table_count; i++) {
		for (j = 0; j < 2; j++) {
			value = file.ReadDWord();
			if (value == 0) {
				if (j > 0)
					return false;
			}
			else {
				if (file.segment_list()->GetMemoryTypeByAddress(value) == mtNone ||
					(file.fixup_list()->count() != 0 && file.fixup_list()->GetFixupByAddress(address + (1 + i * 2 + j) * sizeof(uint32_t)) == NULL))
					return false;
			}
		}
	}

	file.Seek(pos);

	c = count();

	command = Add(address);
	command->ReadValueFromFile(file, osDWord);
	command->set_comment(CommentInfo(ttComment, "Count"));
	address = command->next_address();

	for (i = 0; i < table_count; i++) {
		command = Add(address);
		command->ReadValueFromFile(file, osDWord);
		command->set_comment(CommentInfo(ttComment, "Class"));
		address = command->next_address();

		command = Add(address);
		value = command->ReadValueFromFile(file, osDWord);
		command->set_comment(CommentInfo(ttComment, "Handler"));
		address = command->next_address();
		command->AddLink(0, ltMemSEHBlock, value);
	}

	for (i = c; i < count(); i++) {
		command = item(i);
		command->exclude_option(roClearOriginalCode);
	}

	return true;
}

bool IntelFunction::ParseSwitch(IArchitecture& file, uint64_t address, OperandSize value_size, uint64_t add_value, IntelCommand* parent_command, size_t mode, size_t max_table_count)
{
	if (value_size < osDWord || value_size > osQWord)
		return false;

	size_t i, table_count, c;
	IntelCommand* command;
	uint64_t pos, value;

	command = GetCommandByAddress(address);
	if (command) {
		// CASEs already parsed by previous switch
		for (table_count = 0; command && (command->type() == cmDD || command->type() == cmDQ) && command->link() && command->link()->type() == ltCase; table_count++) {
			if (command->link()->sub_value() != add_value) {
				if (break_case_list_.find(command->address()) != break_case_list_.end())
					break;
				break_case_list_.insert(command->address());
				ClearItems();
				return false;
			}
			command->link()->set_parent_command(parent_command);
			command = GetCommandByAddress(command->next_address());
		}
		return table_count != 0;
	}

	if (!file.AddressSeek(address))
		return false;

	pos = file.Tell();
	std::vector<uint64_t> value_list;
	for (table_count = 0; table_count <= max_table_count; table_count++) {
		uint64_t case_address = address + table_count * OperandSizeToValue(value_size);
		bool is_ok = true;
		for (i = 0; i < OperandSizeToValue(value_size); i++) {
			uint64_t tmp = case_address + i;
			if (GetCommandByNearAddress(tmp) || link_list()->GetLinkByToAddress(ltNone, tmp)) {
				is_ok = false;
				break;
			}
		}
		if (!is_ok)
			break;
		switch (value_size) {
		case osDWord:
		{
			uint32_t dw = file.ReadDWord();
			value = (mode == 1) ? DWordToInt64(dw) : dw;
		}
		break;
		case osQWord:
			value = file.ReadQWord();
			break;
		}
		if (mode == 2)
			value = add_value - value;
		else
			value = add_value + value;
		if (file.cpu_address_size() == osDWord)
			value = static_cast<uint32_t>(value);
		if ((file.segment_list()->GetMemoryTypeByAddress(value) & mtExecutable) == 0)
			break;
		if (value >= address)
			break;
		if (table_count > 0 && break_case_list_.find(case_address) != break_case_list_.end())
			break;
		value_list.push_back(value);
	}

	if (value_list.empty())
		return false;

	file.Seek(pos);
	c = count();
	for (i = 0; i < value_list.size(); i++) {
		command = Add(address);
		command->set_comment(CommentInfo(ttComment, "Case"));
		command->ReadValueFromFile(file, value_size);
		address = command->next_address();

		CommandLink* link = command->AddLink(0, ltCase, value_list[i]);
		link->set_parent_command(parent_command);
		if (add_value)
			link->set_sub_value(add_value);
		if (mode == 2)
			link->set_is_inverse(true);
	}

	command = item(c);
	command->set_alignment(OperandSizeToValue(value_size));
	command->include_option(roCreateNewBlock);

	return true;
}

bool IntelFunction::ParseSEH3(IArchitecture& file, uint64_t address)
{
	if (!file.AddressSeek(address))
		return false;

	uint32_t state;
	uint64_t pos, value;
	size_t i, c, table_count;
	IntelCommand* command;

	pos = file.Tell();
	for (table_count = 0;; table_count++) {
		state = file.ReadDWord();
		if (state != (uint32_t)-1 && state >= table_count)
			break;

		bool is_ok = true;
		for (i = 0; i < 2; i++) {
			value = file.ReadDWord();
			if (value) {
				if ((file.segment_list()->GetMemoryTypeByAddress(value) & mtExecutable) == 0) {
					is_ok = false;
					break;
				}
			}
			else if (i == 1) {
				is_ok = false;
				break;
			}
		}
		if (!is_ok)
			break;
	}

	if (!table_count)
		return false;

	file.Seek(pos);
	c = count();
	for (i = 0; i < table_count; i++) {
		command = Add(address);
		command->set_comment(CommentInfo(ttComment, "State"));
		command->ReadValueFromFile(file, osDWord);
		address = command->next_address();

		command = Add(address);
		command->set_comment(CommentInfo(ttComment, "Filter"));
		value = command->ReadValueFromFile(file, osDWord);
		if (value) {
			command->AddLink(0, ltMemSEHBlock, value);
			command->include_option(roExternal);
		}
		address = command->next_address();

		command = Add(address);
		command->set_comment(CommentInfo(ttComment, "Handler"));
		value = command->ReadValueFromFile(file, osDWord);
		if (value)
			command->AddLink(0, ltMemSEHBlock, value);
		address = command->next_address();
	}

	command = item(c);
	command->set_alignment(OperandSizeToValue(osDWord));
	command->include_option(roCreateNewBlock);

	for (i = c; i < count(); i++) {
		command = item(i);
		command->exclude_option(roClearOriginalCode);
	}
	return true;
}

bool IntelFunction::ParseSEH4(IArchitecture& file, uint64_t address)
{
	if (!file.AddressSeek(address))
		return false;

	uint32_t state;
	uint64_t pos, value;
	size_t i, c, table_count;
	IntelCommand* command;

	pos = file.Tell();
	file.ReadDWord();
	file.ReadDWord();
	file.ReadDWord();
	file.ReadDWord();
	for (table_count = 0;; table_count++) {
		state = file.ReadDWord();
		if (state != (uint32_t)-2 && (size_t)state >= table_count)
			break;

		bool is_ok = true;
		for (i = 0; i < 2; i++) {
			value = file.ReadDWord();
			if (value) {
				if ((file.segment_list()->GetMemoryTypeByAddress(value) & mtExecutable) == 0) {
					is_ok = false;
					break;
				}
			}
			else if (i == 1) {
				is_ok = false;
				break;
			}
		}
		if (!is_ok)
			break;
	}

	if (!table_count)
		return false;

	file.Seek(pos);
	c = count();

	command = Add(address);
	command->set_comment(CommentInfo(ttComment, "GSCookieOffset"));
	command->ReadValueFromFile(file, osDWord);
	address = command->next_address();

	command = Add(address);
	command->set_comment(CommentInfo(ttComment, "GSCookieXOROffset"));
	command->ReadValueFromFile(file, osDWord);
	address = command->next_address();

	command = Add(address);
	command->set_comment(CommentInfo(ttComment, "EHCookieOffset"));
	command->ReadValueFromFile(file, osDWord);
	address = command->next_address();

	command = Add(address);
	command->set_comment(CommentInfo(ttComment, "EHCookieXOROffset"));
	command->ReadValueFromFile(file, osDWord);
	address = command->next_address();

	for (i = 0; i < table_count; i++) {
		command = Add(address);
		command->set_comment(CommentInfo(ttComment, "State"));
		command->ReadValueFromFile(file, osDWord);
		address = command->next_address();

		command = Add(address);
		command->set_comment(CommentInfo(ttComment, "Filter"));
		value = command->ReadValueFromFile(file, osDWord);
		if (value) {
			command->AddLink(0, ltMemSEHBlock, value);
			command->include_option(roExternal);
		}
		address = command->next_address();

		command = Add(address);
		command->set_comment(CommentInfo(ttComment, "Handler"));
		value = command->ReadValueFromFile(file, osDWord);
		if (value)
			command->AddLink(0, ltMemSEHBlock, value);
		address = command->next_address();
	}

	command = item(c);
	command->set_alignment(OperandSizeToValue(osDWord));
	command->include_option(roCreateNewBlock);

	for (i = c; i < count(); i++) {
		command = item(i);
		command->exclude_option(roClearOriginalCode);
	}
	return true;
}

bool IntelFunction::ParseCxxSEH(IArchitecture& file, uint64_t address)
{
	if (!file.AddressSeek(address))
		return false;

	uint64_t pos, unwind_map_entry, try_block_entry, catches_entry, value, map_entry, action_entry;
	uint32_t magic, max_state, try_blocks, catches, map_count;
	IntelCommand* command;
	CommandLink* link;
	size_t i, j, c;

	uint64_t add_value = (cpu_address_size() == osDWord) ? 0 : file.image_base();
	pos = file.Tell();
	magic = file.ReadDWord();
	if (magic != 0x19930520 && magic != 0x19930521 && magic != 0x19930522)
		return false;

	if (GetCommandByAddress(address))
		return true;

	file.Seek(pos);

	c = count();

	command = Add(address);
	command->set_comment(CommentInfo(ttComment, "Magic"));
	command->ReadValueFromFile(file, osDWord);
	command->set_alignment(OperandSizeToValue(osDWord));
	command->include_option(roCreateNewBlock);
	address = command->next_address();

	command = Add(address);
	command->set_comment(CommentInfo(ttComment, "MaxState"));
	max_state = static_cast<uint32_t>(command->ReadValueFromFile(file, osDWord));
	address = command->next_address();

	command = Add(address);
	command->set_comment(CommentInfo(ttComment, "UnwindMapEntry"));
	unwind_map_entry = command->ReadValueFromFile(file, osDWord);
	if (unwind_map_entry) {
		unwind_map_entry += add_value;
		link = command->AddLink(0, ltOffset, unwind_map_entry);
		link->set_sub_value(add_value);
	}
	address = command->next_address();

	command = Add(address);
	command->set_comment(CommentInfo(ttComment, "TryBlocks"));
	try_blocks = static_cast<uint32_t>(command->ReadValueFromFile(file, osDWord));
	address = command->next_address();

	command = Add(address);
	command->set_comment(CommentInfo(ttComment, "TryBlockMapEntry"));
	try_block_entry = command->ReadValueFromFile(file, osDWord);
	if (try_block_entry) {
		try_block_entry += add_value;
		link = command->AddLink(0, ltOffset, try_block_entry);
		link->set_sub_value(add_value);
	}
	address = command->next_address();

	command = Add(address);
	command->set_comment(CommentInfo(ttComment, "IPMapEntries"));
	map_count = static_cast<uint32_t>(command->ReadValueFromFile(file, osDWord));
	address = command->next_address();

	command = Add(address);
	command->set_comment(CommentInfo(ttComment, "IPtoStateMap"));
	map_entry = command->ReadValueFromFile(file, osDWord);
	if (map_entry) {
		map_entry += add_value;
		link = command->AddLink(0, ltOffset, map_entry);
		link->set_sub_value(add_value);
	}
	address = command->next_address();

	if (file.cpu_address_size() == osQWord) {
		command = Add(address);
		command->set_comment(CommentInfo(ttComment, "UnwindHelp"));
		command->ReadValueFromFile(file, osDWord);
		address = command->next_address();
	}

	if (magic >= 0x19930521) {
		command = Add(address);
		command->ReadValueFromFile(file, osDWord);
		command->set_comment(CommentInfo(ttComment, "ESTypeList"));
		address = command->next_address();

		if (magic == 0x19930522) {
			command = Add(address);
			command->ReadValueFromFile(file, osDWord);
			command->set_comment(CommentInfo(ttComment, "Flags"));
			//address = command->next_address();
		}
	}

	if (max_state && file.AddressSeek(unwind_map_entry)) {
		for (i = 0; i < max_state; i++) {
			command = Add(unwind_map_entry);
			command->set_comment(CommentInfo(ttComment, "ToState"));
			command->ReadValueFromFile(file, osDWord);
			unwind_map_entry = command->next_address();

			command = Add(unwind_map_entry);
			command->set_comment(CommentInfo(ttComment, "Action"));
			action_entry = command->ReadValueFromFile(file, osDWord);
			if (action_entry) {
				action_entry += add_value;
				link = command->AddLink(0, ltMemSEHBlock, action_entry);
				link->set_parsed(true);
				link->set_sub_value(add_value);
			}
			unwind_map_entry = command->next_address();
		}
	}

	if (try_blocks && file.AddressSeek(try_block_entry)) {
		for (i = 0; i < try_blocks; i++) {
			command = Add(try_block_entry);
			command->set_comment(CommentInfo(ttComment, "TryLow"));
			command->ReadValueFromFile(file, osDWord);
			try_block_entry = command->next_address();

			command = Add(try_block_entry);
			command->set_comment(CommentInfo(ttComment, "TryHigh"));
			command->ReadValueFromFile(file, osDWord);
			try_block_entry = command->next_address();

			command = Add(try_block_entry);
			command->set_comment(CommentInfo(ttComment, "CatchHigh"));
			command->ReadValueFromFile(file, osDWord);
			try_block_entry = command->next_address();

			command = Add(try_block_entry);
			command->set_comment(CommentInfo(ttComment, "Catches"));
			catches = static_cast<uint32_t>(command->ReadValueFromFile(file, osDWord));
			try_block_entry = command->next_address();

			command = Add(try_block_entry);
			command->set_comment(CommentInfo(ttComment, "HandlerArray"));
			catches_entry = command->ReadValueFromFile(file, osDWord);
			if (catches_entry) {
				catches_entry += add_value;
				link = command->AddLink(0, ltOffset, catches_entry);
				link->set_sub_value(add_value);
			}
			try_block_entry = command->next_address();

			pos = file.Tell();
			if (catches && file.AddressSeek(catches_entry)) {
				for (j = 0; j < catches; j++) {
					command = Add(catches_entry);
					command->set_comment(CommentInfo(ttComment, "Adjectives"));
					command->ReadValueFromFile(file, osDWord);
					catches_entry = command->next_address();

					command = Add(catches_entry);
					command->set_comment(CommentInfo(ttComment, "Type"));
					command->ReadValueFromFile(file, osDWord);
					catches_entry = command->next_address();

					command = Add(catches_entry);
					command->set_comment(CommentInfo(ttComment, "CatchObj"));
					command->ReadValueFromFile(file, osDWord);
					catches_entry = command->next_address();

					command = Add(catches_entry);
					command->set_comment(CommentInfo(ttComment, "Handler"));
					value = command->ReadValueFromFile(file, osDWord);
					if (value) {
						value += add_value;
						link = command->AddLink(0, ltExtSEHHandler, value);
						link->set_sub_value(add_value);
					}
					catches_entry = command->next_address();

					if (cpu_address_size() == osQWord) {
						command = Add(catches_entry);
						command->set_comment(CommentInfo(ttComment, "Frame"));
						command->ReadValueFromFile(file, osDWord);
						catches_entry = command->next_address();
					}
				}
				file.Seek(pos);
			}
		}
	}

	if (map_count && file.AddressSeek(map_entry)) {
		AddressRange* last_range = NULL;
		for (i = 0; i < map_count; i++) {
			command = Add(map_entry);
			command->set_comment(CommentInfo(ttComment, "Ip"));
			value = command->ReadValueFromFile(file, osDWord) + add_value;
			map_entry = command->next_address();

			if (last_range && last_range->begin() < value)
				last_range->set_end(value);
			last_range = range_list()->Add(value, 0, command, NULL, NULL);

			command = Add(map_entry);
			command->set_comment(CommentInfo(ttComment, "State"));
			command->ReadValueFromFile(file, osDWord);
			map_entry = command->next_address();
		}
	}

	for (i = c; i < count(); i++) {
		command = item(i);
		command->exclude_option(roClearOriginalCode);
	}

	return true;
}

bool IntelFunction::ParseCompressedCxxSEH(IArchitecture& file, uint64_t address, uint64_t begin)
{
	// FIXME
	return false;

	if (file.cpu_address_size() != osQWord || !file.AddressSeek(address))
		return false;

	uint64_t pos, unwind_map_entry, try_block_entry, catches_entry, value, map_entry, action_entry;
	uint32_t max_state, try_blocks, catches, map_count;
	IntelCommand* command;
	CommandLink* link;
	size_t old_count, i, j, k, c;

	uint64_t add_value = (cpu_address_size() == osDWord) ? 0 : file.image_base();

	pos = file.Tell();
	uint8_t header_flags = file.ReadByte();
	if (header_flags & 4) {
		command = Add(address);
		command->ReadCompressedValue(file);
		delete command;
	}

	if (header_flags & 8) {
		value = file.ReadDWord();
		if (value && (file.segment_list()->GetMemoryTypeByAddress(value + add_value) & mtReadable) == 0)
			return false;
	}
	if (header_flags & 0x10) {
		value = file.ReadDWord();
		if (value && (file.segment_list()->GetMemoryTypeByAddress(value + add_value) & mtReadable) == 0)
			return false;
	}
	value = file.ReadDWord();
	if (file.AddressSeek(value + add_value)) {
		map_entry = value + add_value;
		command = Add(map_entry);
		map_count = command->ReadCompressedValue(file);

		value = begin;
		for (i = 0; i < map_count; i++) {
			uint32_t ip = command->ReadCompressedValue(file);
			command->ReadCompressedValue(file);
			value += ip;
			if ((file.segment_list()->GetMemoryTypeByAddress(value) & mtExecutable) == 0) {
				delete command;
				return false;
			}
		}
		delete command;
	}
	else
		return false;

	if (GetCommandByAddress(address))
		return true;

	file.Seek(pos);

	old_count = count();

	command = Add(address);
	command->set_comment(CommentInfo(ttComment, "Header"));
	command->ReadValueFromFile(file, osByte);
	command->include_option(roCreateNewBlock);
	address = command->next_address();

	if (header_flags & 4) {
		command = Add(address);
		command->set_comment(CommentInfo(ttComment, "Flags"));
		command->ReadCompressedValue(file);
		address = command->next_address();
	}

	unwind_map_entry = 0;
	if (header_flags & 8) {
		command = Add(address);
		command->set_comment(CommentInfo(ttComment, "UnwindMapEntry"));
		unwind_map_entry = command->ReadValueFromFile(file, osDWord);
		if (unwind_map_entry) {
			unwind_map_entry += add_value;
			link = command->AddLink(0, ltOffset, unwind_map_entry);
			link->set_sub_value(add_value);
		}
		address = command->next_address();
	}

	try_block_entry = 0;
	if (header_flags & 0x10) {
		command = Add(address);
		command->set_comment(CommentInfo(ttComment, "TryBlockMapEntry"));
		try_block_entry = command->ReadValueFromFile(file, osDWord);
		if (try_block_entry) {
			try_block_entry += add_value;
			link = command->AddLink(0, ltOffset, try_block_entry);
			link->set_sub_value(add_value);
		}
		address = command->next_address();
	}

	command = Add(address);
	command->set_comment(CommentInfo(ttComment, "IPtoStateMap"));
	map_entry = command->ReadValueFromFile(file, osDWord);
	if (map_entry) {
		map_entry += add_value;
		link = command->AddLink(0, ltOffset, map_entry);
		link->set_sub_value(add_value);
	}
	address = command->next_address();

	if (header_flags & 1) {
		command = Add(address);
		command->set_comment(CommentInfo(ttComment, "Frame"));
		command->ReadCompressedValue(file);
		address = command->next_address();
	}

	if (unwind_map_entry && file.AddressSeek(unwind_map_entry)) {
		command = Add(unwind_map_entry);
		command->set_comment(CommentInfo(ttComment, "MaxState"));
		max_state = command->ReadCompressedValue(file);
		unwind_map_entry = command->next_address();

		for (i = 0; i < max_state; i++) {
			command = Add(unwind_map_entry);
			command->set_comment(CommentInfo(ttComment, "NextOffset"));
			uint32_t offset = command->ReadCompressedValue(file);
			unwind_map_entry = command->next_address();

			uint8_t type = offset & 3;
			if (type) {
				command = Add(unwind_map_entry);
				command->set_comment(CommentInfo(ttComment, "Action"));
				action_entry = command->ReadValueFromFile(file, osDWord);
				if (action_entry) {
					action_entry += add_value;
					link = command->AddLink(0, ltMemSEHBlock, action_entry);
					link->set_parsed(true);
					link->set_sub_value(add_value);
				}
				unwind_map_entry = command->next_address();
			}

			if (type == 1 || type == 2) {
				command = Add(unwind_map_entry);
				command->set_comment(CommentInfo(ttComment, "Object"));
				command->ReadCompressedValue(file);
				unwind_map_entry = command->next_address();
			}
		}
	}

	if (try_block_entry && file.AddressSeek(try_block_entry)) {
		command = Add(try_block_entry);
		command->set_comment(CommentInfo(ttComment, "TryBlocks"));
		try_blocks = command->ReadCompressedValue(file);
		try_block_entry = command->next_address();

		for (i = 0; i < try_blocks; i++) {
			command = Add(try_block_entry);
			command->set_comment(CommentInfo(ttComment, "TryLow"));
			command->ReadCompressedValue(file);
			try_block_entry = command->next_address();

			command = Add(try_block_entry);
			command->set_comment(CommentInfo(ttComment, "TryHigh"));
			command->ReadCompressedValue(file);
			try_block_entry = command->next_address();

			command = Add(try_block_entry);
			command->set_comment(CommentInfo(ttComment, "CatchHigh"));
			command->ReadCompressedValue(file);
			try_block_entry = command->next_address();

			command = Add(try_block_entry);
			command->set_comment(CommentInfo(ttComment, "HandlerArray"));
			catches_entry = command->ReadValueFromFile(file, osDWord) + add_value;
			link = command->AddLink(0, ltOffset, catches_entry);
			link->set_sub_value(add_value);
			try_block_entry = command->next_address();

			pos = file.Tell();
			if (file.AddressSeek(catches_entry)) {
				command = Add(catches_entry);
				command->set_comment(CommentInfo(ttComment, "Catches"));
				catches = command->ReadCompressedValue(file);
				catches_entry = command->next_address();

				for (j = 0; j < catches; j++) {
					command = Add(catches_entry);
					command->set_comment(CommentInfo(ttComment, "Header"));
					uint8_t header = static_cast<uint8_t>(command->ReadValueFromFile(file, osByte));
					catches_entry = command->next_address();

					if (header & 1) {
						command = Add(catches_entry);
						command->set_comment(CommentInfo(ttComment, "Adjectives"));
						command->ReadCompressedValue(file);
						catches_entry = command->next_address();
					}

					if (header & 2) {
						command = Add(catches_entry);
						command->set_comment(CommentInfo(ttComment, "Type"));
						command->ReadValueFromFile(file, osDWord);
						catches_entry = command->next_address();
					}

					if (header & 4) {
						command = Add(catches_entry);
						command->set_comment(CommentInfo(ttComment, "CatchObj"));
						command->ReadCompressedValue(file);
						catches_entry = command->next_address();
					}

					command = Add(catches_entry);
					command->set_comment(CommentInfo(ttComment, "Handler"));
					value = command->ReadValueFromFile(file, osDWord);
					if (value) {
						value += add_value;
						link = command->AddLink(0, ltExtSEHHandler, value);
						link->set_sub_value(add_value);
					}
					catches_entry = command->next_address();

					switch ((header >> 4) & 3) {
					case 1:
						c = 1;
						break;
					case 2:
						c = 2;
						break;
					default:
						c = 0;
						break;
					}
					for (k = 0; k < c; k++) {
						command = Add(catches_entry);
						command->set_comment(CommentInfo(ttComment, "ContinuationAddress"));
						if (header & 8) {
							value = command->ReadValueFromFile(file, osDWord) + add_value;
							link = command->AddLink(0, ltMemSEHBlock, value);
							link->set_sub_value(add_value);
						}
						else {
							command->include_option(roFillNop);
							value = command->ReadCompressedValue(file) + begin;
							link = command->AddLink(0, ltMemSEHBlock, value);
							link->set_base_function_info(function_info_list()->GetItemByAddress(begin));
						}

						catches_entry = command->next_address();
					}
				}
				file.Seek(pos);
			}
		}
	}

	if (file.AddressSeek(map_entry)) {
		command = Add(map_entry);
		command->set_comment(CommentInfo(ttComment, "IPMapEntries"));
		map_count = command->ReadCompressedValue(file);
		map_entry = command->next_address();

		value = begin;
		AddressRange* last_range = NULL;
		for (i = 0; i < map_count; i++) {
			command = Add(map_entry);
			command->set_comment(CommentInfo(ttComment, "Ip"));
			value += command->ReadCompressedValue(file);
			command->include_option(roFillNop);
			map_entry = command->next_address();

			if (last_range)
				last_range->set_end(value);
			last_range = range_list()->Add(value, 0, command, NULL, NULL);

			command = Add(map_entry);
			command->set_comment(CommentInfo(ttComment, "State"));
			command->ReadCompressedValue(file);
			map_entry = command->next_address();
		}
	}

	for (i = old_count; i < count(); i++) {
		command = item(i);
		command->exclude_option(roClearOriginalCode);
	}

	return true;
}

bool IntelFunction::ParseScopeSEH(IArchitecture& file, uint64_t address, uint32_t table_count)
{
	if (!file.AddressSeek(address))
		return false;

	IntelCommand* command;
	CommandLink* link;
	size_t i;
	uint64_t value;
	uint64_t image_base = file.image_base();

	uint64_t pos = file.Tell();

	for (i = 0; i < table_count; i++) { //-V756
		for (size_t j = 0; j < 4; j++) {
			value = file.ReadDWord();
			if ((j == 0 || j == 1) && (file.segment_list()->GetMemoryTypeByAddress(value + image_base) & mtExecutable) == 0)
				return false;
		}
	}

	if (GetCommandByAddress(address))
		return true;

	file.Seek(pos);

	size_t c = count();

	for (i = 0; i < table_count; i++) {
		IntelCommand* begin_entry = command = Add(address);
		begin_entry->set_comment(CommentInfo(ttComment, "Begin"));
		uint64_t begin_address = begin_entry->ReadValueFromFile(file, osDWord) + image_base;
		address = begin_entry->next_address();

		IntelCommand* end_entry = Add(address);
		end_entry->set_comment(CommentInfo(ttComment, "End"));
		uint64_t end_address = end_entry->ReadValueFromFile(file, osDWord) + image_base;
		address = end_entry->next_address();

		range_list()->Add(begin_address, end_address, begin_entry, end_entry, NULL);

		command = Add(address);
		command->set_comment(CommentInfo(ttComment, "Filter"));
		value = command->ReadValueFromFile(file, osDWord);
		if (value > 1) {
			value += image_base;
			pos = file.Tell();
			if (ParseDelphiSEH(file, value)) {
				link = command->AddLink(0, ltOffset, value);
			}
			else {
				link = command->AddLink(0, ltMemSEHBlock, value);
				command->include_option(roExternal);
			}
			link->set_sub_value(image_base);
			file.Seek(pos);
		}
		address = command->next_address();

		command = Add(address);
		command->set_comment(CommentInfo(ttComment, "Handler"));
		value = command->ReadValueFromFile(file, osDWord);
		if (value) {
			value += image_base;
			link = command->AddLink(0, ltMemSEHBlock, value);
			link->set_sub_value(image_base);
		}
		address = command->next_address();
	};

	for (i = c; i < count(); i++) {
		command = item(i);
		command->exclude_option(roClearOriginalCode);
	}

	return true;
}

bool IntelFunction::ParseNewSEH(IArchitecture& file, uint64_t address)
{
	size_t i;
	IntelCommand* command;

	IntelFunction func(NULL, cpu_address_size(), this);
	func.ReadFromFile(file, address);
	command = func.GetCommandByAddress(address);
	if (command) {
		for (i = func.IndexOf(command) + 1; i < func.count(); i++) {
			command = func.item(i);
			if (command->type() == cmJmp
				&& command->operand(0).type == otValue
				&& (command->operand(0).value < address || func.GetCommandByAddress(command->operand(0).value) == NULL)) {
				command = func.item(i - 1);
				if (command->type() == cmMov
					&& command->operand(0).type == otRegistr
					&& command->operand(0).registr == regEAX
					&& command->operand(1).type == otValue) {
					return ParseCxxSEH(file, command->operand(1).value);
				}
			}
		}
	}

	return false;
}

bool IntelFunction::ParseVB6SEH(IArchitecture& file, uint64_t address)
{
	if (!file.AddressSeek(address))
		return false;

	uint64_t pos = file.Tell();

	size_t i, k, table_count;
	uint32_t flags;
	uint64_t value;
	IntelCommand* command;
	//CommandLink *link;

	flags = file.ReadDWord();
	switch (flags >> 16) {
	case 0x04:
	case 0x08:
	case 0x0c:
	case 0x10:
	case 0x14:
		break;
	default:
		return false;
	}

	k = (flags & 0xffff0007) == 0x80001 ? 1 : 3;
	for (table_count = 0;; table_count++) {
		bool is_ok = true;
		for (i = 0; i < k; i++) {
			value = file.ReadDWord();
			if (value != 0 && (file.segment_list()->GetMemoryTypeByAddress(value) & mtExecutable) == 0) {
				is_ok = false;
				break;
			}
		}
		if (!is_ok)
			break;
	}

	if (!table_count)
		return false;

	file.Seek(pos);

	size_t c = count();

	command = Add(address);
	command->ReadValueFromFile(file, osDWord);
	address = command->next_address();

	for (i = 0; i < k; i++) {
		command = Add(address);
		value = command->ReadValueFromFile(file, osDWord);
		if (value)
			command->AddLink(0, ltVBMemSEHBlock, value);
		address = command->next_address();
	}

	if (flags & 0x30) {
		command = Add(address);
		uint64_t ext_info = command->ReadValueFromFile(file, osDWord);
		address = command->next_address();

		command = Add(address);
		uint64_t address_info = command->ReadValueFromFile(file, osDWord);
		address = command->next_address();

		if (ext_info && file.AddressSeek(ext_info)) {
			address = ext_info;

			command = Add(address);
			command->ReadValueFromFile(file, osDWord);
			address = command->next_address();

			command = Add(address);
			command->ReadValueFromFile(file, osDWord);
			address = command->next_address();

			command = Add(address);
			value = command->ReadValueFromFile(file, osDWord);
			if (value)
				command->AddLink(0, ltVBMemSEHBlock, value);
			address = command->next_address();
		}

		if (address_info && file.AddressSeek(address_info)) {
			address = address_info;

			command = Add(address);
			size_t array_count = static_cast<size_t>(command->ReadValueFromFile(file, osDWord));
			address = command->next_address();

			for (i = 0; i < array_count; i++) {
				command = Add(address);
				value = command->ReadValueFromFile(file, osDWord);
				if (value)
					command->AddLink(0, ltVBMemSEHBlock, value);
				address = command->next_address();
			}
		}
	}

	for (i = c; i < count(); i++) {
		command = item(i);
		command->exclude_option(roClearOriginalCode);
	}

	return true;
}

bool IntelFunction::ParseDelphiSEH(IArchitecture& file, uint64_t address)
{
	if (!file.AddressSeek(address))
		return false;

	IntelCommand* command;
	size_t i, j;
	uint64_t value;

	size_t c = count();
	uint64_t image_base = file.image_base();
	uint64_t pos = file.Tell();

	uint32_t table_count = file.ReadDWord();
	for (i = 0; i < table_count; i++) {
		for (j = 0; j < 2; j++) {
			value = file.ReadDWord();
			if (!value)
				continue;

			value += image_base;
			if ((file.segment_list()->GetMemoryTypeByAddress(value) & (j == 1 ? mtExecutable : mtReadable)) == 0)
				return false;
		}
	}

	file.Seek(pos);

	command = Add(address);
	command->ReadValueFromFile(file, osDWord);
	command->set_comment(CommentInfo(ttComment, "Count"));
	address = command->next_address();

	for (size_t i = 0; i < table_count; i++) {
		command = Add(address);
		command->ReadValueFromFile(file, osDWord);
		command->set_comment(CommentInfo(ttComment, "Type"));
		address = command->next_address();

		command = Add(address);
		value = command->ReadValueFromFile(file, osDWord);
		if (value) {
			value += image_base;
			CommandLink* link = command->AddLink(0, ltMemSEHBlock, value);
			link->set_sub_value(image_base);
		}
		command->set_comment(CommentInfo(ttComment, "Handler"));
		address = command->next_address();
	}

	for (i = c; i < count(); i++) {
		command = item(i);
		command->exclude_option(roClearOriginalCode);
	}

	return true;
}

bool IntelFunction::ParseBCBSEH(IArchitecture& file, uint64_t address, uint64_t next_address, uint8_t version)
{
	if (!file.AddressSeek(address))
		return false;

	uint64_t base_address = address;
	IntelCommand* command;
	size_t c = count();

	if (version == 2) {
		command = Add(address);
		command->ReadValueFromFile(file, osDWord);
		command->set_comment(CommentInfo(ttComment, "ThrowLst"));
		address = command->next_address();
	}

	command = Add(address);
	command->ReadValueFromFile(file, osDWord);
	command->set_comment(CommentInfo(ttComment, "VirtCondOffs"));
	address = command->next_address();

	command = Add(address);
	uint64_t bp_offset = command->ReadValueFromFile(file, osDWord);
	command->set_comment(CommentInfo(ttComment, "BPoffs"));

	//std::vector<uint16_t> ctx_list;
	{
		uint64_t bcb_seh_operand = IntelOperand(otMemory | otRegistr | otValue, osWord, regEBP, bp_offset + 0x10).encode();
		IntelFunction tmp(NULL, file.cpu_address_size(), this);
		address = next_address;
		for (;;) {
			command = NULL;
			if (file.segment_list()->GetMemoryTypeByAddress(address) & mtExecutable) {
				if (file.AddressSeek(address)) {
					command = tmp.ParseCommand(file, address);
					if (command && command->type() == cmMov && command->operand(0).encode() == bcb_seh_operand && command->operand(1).type == otValue) {
						uint16_t bcb_ctx = static_cast<uint16_t>(command->operand(1).value);
						size_t old_count = link_list()->count();
						IntelCommand* orig = command;
						while (bcb_ctx) {
							address = base_address + bcb_ctx;

							if (GetCommandByAddress(address))
								break;

							if (!file.AddressSeek(address))
								break;

							command = Add(address);
							bcb_ctx = static_cast<uint16_t>(command->ReadValueFromFile(file, osWord));
							command->set_comment(CommentInfo(ttComment, "Outer"));
							address = command->next_address();

							command = Add(address);
							uint16_t kind = static_cast<uint16_t>(command->ReadValueFromFile(file, osWord));
							command->set_comment(CommentInfo(ttComment, "Kind"));
							address = command->next_address();

							uint64_t value;
							switch (kind) {
							case 0:
								command = Add(address);
								command->ReadValueFromFile(file, osDWord);
								command->set_comment(CommentInfo(ttComment, "Reserved"));
								address = command->next_address();

								command = Add(address);
								value = command->ReadValueFromFile(file, osDWord);
								if (value)
									command->AddLink(0, ltMemSEHBlock, value);
								command->set_comment(CommentInfo(ttComment, "Handler"));
								break;
							case 1:
							case 2:
								command = Add(address);
								value = command->ReadValueFromFile(file, osDWord);
								if (kind == 1 && value)
									command->AddLink(0, ltMemSEHBlock, value);
								command->set_comment(CommentInfo(ttComment, "Filter"));
								address = command->next_address();

								command = Add(address);
								value = command->ReadValueFromFile(file, osDWord);
								if (value)
									command->AddLink(0, ltMemSEHBlock, value);
								command->set_comment(CommentInfo(ttComment, "Handler"));
								break;
							case 3:
							{
								command = Add(address);
								address = command->ReadValueFromFile(file, osDWord);
								command->set_comment(CommentInfo(ttComment, "Table"));
								command->AddLink(0, ltOffset, address);

								if (file.AddressSeek(address)) {
									command = Add(address);
									command->ReadValueFromFile(file, osDWord);
									command->set_comment(CommentInfo(ttComment, "ArgAddr"));
									address = command->next_address();

									command = Add(address);
									command->ReadValueFromFile(file, osDWord);
									command->set_comment(CommentInfo(ttComment, "ArgSize"));
									address = command->next_address();

									while (true) {
										command = Add(address);
										value = command->ReadValueFromFile(file, osDWord);
										if (value) {
											command->AddLink(0, ltMemSEHBlock, value);
										}
										else {
											delete command;
											break;
										}
										command->set_comment(CommentInfo(ttComment, "Handler"));
										address = command->next_address();

										command = Add(address);
										command->ReadValueFromFile(file, osDWord);
										command->set_comment(CommentInfo(ttComment, "TypeID"));
										address = command->next_address();

										command = Add(address);
										command->ReadValueFromFile(file, osDWord);
										command->set_comment(CommentInfo(ttComment, "Flags"));
										address = command->next_address();

										command = Add(address);
										command->ReadValueFromFile(file, osDWord);
										command->set_comment(CommentInfo(ttComment, "CctrAddr"));
										address = command->next_address();

										command = Add(address);
										command->ReadValueFromFile(file, osDWord);
										command->set_comment(CommentInfo(ttComment, "CctrMask"));
										address = command->next_address();
									}
								}
							}
							break;
							case 4:
								break;
							case 5:
								command = Add(address);
								command->ReadValueFromFile(file, osDWord);
								command->set_comment(CommentInfo(ttComment, "MinCount"));
								address = command->next_address();

								command = Add(address);
								command->ReadValueFromFile(file, osDWord);
								command->set_comment(CommentInfo(ttComment, "Table"));
								break;
							}
						}
						for (size_t i = old_count; i < link_list()->count(); i++) {
							CommandLink* src_link = link_list()->item(i);
							CommandLink* dst_link = src_link->Clone(tmp.link_list());
							tmp.link_list()->AddObject(dst_link);
							dst_link->set_from_command(tmp.Add(src_link->from_command()->address()));
						}
						command = orig;
					}
				}
			}
			if (!command || command->is_end() || (command->options() & roBreaked) != 0) {
				address = tmp.GetNextAddress(file);
				if (!address)
					break;
			}
			else {
				address = command->next_address();
			}
		}
	}

	for (size_t i = c; i < count(); i++) {
		command = item(i);
		command->exclude_option(roClearOriginalCode);
	}

	return true;
}

IntelCommand* IntelFunction::ParseString(IArchitecture& file, uint64_t address, size_t len)
{
	if (!file.AddressSeek(address))
		return NULL;

	IntelCommand* command = Add(address);
	command->ReadArray(file, len);
	command->exclude_option(roNeedCompile);
	return command;
}

void IntelFunction::ParseBeginCommands(IArchitecture& file)
{
	if (type() == otMarker || type() == otAPIMarker) {
		CompilerFunction* func = file.compiler_function_list()->GetFunctionByLowerAddress(address());
		if (func && (func->type() == cfCxxSEH || func->type() == cfCxxSEH3 || func->type() == cfCxxSEH4 || func->type() == cfBCBSEH || func->type() == cfVB6SEH)) {
			IntelFunction tmp(NULL, cpu_address_size());
			tmp.ReadFromFile(file, func->address());
			if (tmp.GetCommandByAddress(address())) {
				switch (func->type()) {
				case cfCxxSEH:
					ParseNewSEH(file, func->value(0));
					break;
				case cfCxxSEH3:
					ParseSEH3(file, func->value(0));
					break;
				case cfCxxSEH4:
					ParseSEH4(file, func->value(0));
					break;
				case cfBCBSEH:
					ParseBCBSEH(file, func->value(0), address(), static_cast<uint8_t>(func->value(1)));
					break;
				case cfVB6SEH:
					ParseVB6SEH(file, func->value(0));
					break;
				}
			}
		}
	}
}

void IntelFunction::ParseEndCommands(IArchitecture& file)
{
	if (type() == otMarker) {
		uint64_t len_address = address() + 1;
		if (file.AddressSeek(len_address)) {
			uint8_t len = file.ReadByte();
			ParseString(file, len_address + 1, len);
		}
	}

	if (type() == otMarker || type() == otAPIMarker) {
		std::vector<ICommand*> entry_command_list;
		std::vector<ICommand*> exclude_command_list;
		size_t i, j, k;

		/*
		for (i = 0; i < link_list()->count(); i++) {
			CommandLink *link = link_list()->item(i);
			if (link->type() == ltMemSEHBlock || link->type() == ltExtSEHHandler) {
				IntelCommand *command = GetCommandByAddress(link->to_address());
				if (command && std::find(entry_command_list.begin(), entry_command_list.end(), command) == entry_command_list.end())
					entry_command_list.push_back(command);
			}
		}
		*/

		for (i = 0; i < file.end_marker_list()->count(); i++) {
			MarkerCommand* marker_command = file.end_marker_list()->item(i);
			IntelCommand* command = GetCommandByNearAddress(marker_command->address());
			if (command) {
				if (marker_command->type() == otMarker) {
					uint64_t len_address = command->address() + 1;
					if (file.AddressSeek(len_address)) {
						uint8_t len = file.ReadByte();
						command = ParseString(file, len_address + 1, len);
					}
				}
				else {
					if (!command->is_end())
						command->include_option(roBreaked);
				}
				command = GetCommandByAddress(command->next_address());
				if (command && std::find(entry_command_list.begin(), entry_command_list.end(), command) == entry_command_list.end())
					entry_command_list.push_back(command);
			}
			else {
				for (size_t j = 0; j < link_list()->count(); j++) {
					CommandLink* link = link_list()->item(j);
					if ((link->type() == ltJmp || link->type() == ltJmpWithFlag) && link->to_address() && link->to_address() > link->from_command()->address() && marker_command->address() > link->from_command()->next_address() && marker_command->address() < link->to_address()) {
						command = GetCommandByAddress(link->to_address());
						if (command && std::find(entry_command_list.begin(), entry_command_list.end(), command) == entry_command_list.end())
							entry_command_list.push_back(command);
					}
				}
			}
		}

		Sort();
		for (i = 0; i < entry_command_list.size(); i++) {
			ICommand* entry_command = entry_command_list[i];

			size_t n = IndexOf(entry_command);
			if (n > 0) {
				IntelCommand* command = item(n - 1);
				if (!command->is_end())
					command->include_option(roBreaked);
			}
			for (j = n; j < count(); j++) {
				IntelCommand* command = item(j);

				if (std::find(exclude_command_list.begin(), exclude_command_list.end(), command) != exclude_command_list.end())
					break;

				exclude_command_list.push_back(command);

				for (k = 0; k < link_list()->count(); k++) {
					CommandLink* link = link_list()->item(k);
					if (link->parent_command() == command && std::find(entry_command_list.begin(), entry_command_list.end(), link->from_command()) == entry_command_list.end())
						entry_command_list.push_back(link->from_command());
				}

				CommandLink* link = command->link();
				if (link && link->to_address()) {
					IntelCommand* link_command = GetCommandByAddress(link->to_address());
					if (link_command && std::find(entry_command_list.begin(), entry_command_list.end(), link_command) == entry_command_list.end())
						entry_command_list.push_back(link_command);
				}

				if (command->is_end())
					break;
			}
		}

		for (i = 0; i < exclude_command_list.size(); i++) {
			ICommand* command = exclude_command_list[i];

			for (j = 0; j < range_list()->count(); j++) {
				AddressRange* range = range_list()->item(j);
				if (range->begin_entry() == command)
					range->set_begin_entry(NULL);
				if (range->end_entry() == command)
					range->set_end_entry(NULL);
				if (range->size_entry() == command)
					range->set_size_entry(NULL);
			}
			for (j = 0; j < function_info_list()->count(); j++) {
				FunctionInfo* info = function_info_list()->item(j);
				if (info->entry() == command)
					info->set_entry(NULL);
				for (k = 0; k < info->count(); k++) {
					AddressRange* range = info->item(k);
					if (range->begin_entry() == command)
						range->set_begin_entry(NULL);
					if (range->end_entry() == command)
						range->set_end_entry(NULL);
					if (range->size_entry() == command)
						range->set_size_entry(NULL);
				}
			}

			if (command->link())
				delete command->link();
			delete command;
		}
	}
}

uint64_t IntelFunction::GetNextAddress(IArchitecture& file)
{
	uint64_t res = BaseFunction::GetNextAddress(file);
	if (res)
		return res;

	size_t c = link_list()->count();
	for (size_t i = 0; i < c; i++) {
		CommandLink* link = link_list()->item(i);
		switch (link->type()) {
		case ltJmp:
			if (type() == otMarker && !link->parsed() && link->to_address() == address() + 0x12) {
				link->set_parsed(true);
				return link->to_address();
			}
			break;
		case ltDualSEHBlock:
			if (!link->next_command()) {
				IntelCommand* command = GetCommandByAddress(link->to_address());
				if (command) {
					IntelCommand* next_command = GetCommandByAddress(command->next_address());
					if (next_command)
						link->set_next_command(next_command);
					else
						return command->next_address();
				}
			}
			break;
		case ltExtSEHHandler:
			if (!link->next_command()) {
				size_t k = IndexOf(GetCommandByAddress(link->to_address()));
				if (k == NOT_ID)
					continue;

				std::set<size_t> stack;
				stack.insert(k);
				while (!stack.empty()) {
					k = *stack.begin();

					for (size_t j = k; j < count(); j++) {
						std::set<size_t>::const_iterator it = stack.find(j);
						if (it != stack.end())
							stack.erase(it);

						IntelCommand* command = item(j);
						if (command->options() & roBreaked)
							break;

						if (command->type() == cmJmpWithFlag && command->operand(0).type == otValue) {
							IntelCommand* to_command = GetCommandByAddress(command->operand(0).value);
							if (to_command) {
								k = IndexOf(to_command);
								if (k != NOT_ID && k > j)
									stack.insert(k);
							}
						}

						if (command->type() != cmRet && command->type() != cmJmp)
							continue;

						if (command->type() == cmJmp && command->operand(0).type == otValue) {
							IntelCommand* tmp = GetCommandByAddress(command->operand(0).value - 8);
							if (tmp && tmp->type() == cmPush && tmp->operand(0).type == otValue) {
								IntelCommand* next = GetCommandByAddress(tmp->next_address());
								if (next && next->type() == cmAdd && next->operand(0).type == (otMemory | otBaseRegistr) && next->operand(0).base_registr == regESP && next->operand(1).type == otRegistr && next->operand(1).registr == regEBX) {
									link->set_next_command(tmp);
									if (!tmp->link())
										tmp->AddLink(0, ltSEHBlock, tmp->operand(0).value);
								}
							}

							IntelCommand* to_command = GetCommandByAddress(command->operand(0).value);
							if (to_command) {
								k = IndexOf(to_command);
								if (k != NOT_ID && k > j) {
									j = k - 1;
									continue;
								}
							}
						}

						for (size_t n = j; n > k; n--) {
							command = item(n - 1);
							if (command->operand(0).type == otRegistr && command->operand(0).registr == regEAX && command->operand(0).size == cpu_address_size() &&
								((command->type() == cmLea && command->operand(1).type == (otMemory | otValue)) || (command->type() == cmMov && command->operand(1).type == otValue))) {
								link->set_next_command(command);
								if (!command->link())
									command->AddLink(1, ltSEHBlock, command->operand(1).value);
								break;
							}
						}
						break;
					}
				}
			}
		}
	}
	if (link_list()->count() > c)
		return GetNextAddress(file);

	return 0;
}

uint64_t IntelFunction::GetRegistrValue(uint8_t reg, size_t end_index)
{
	std::map<uint64_t, IntelCommand*> address_list;
	IntelCommand* mov_command = NULL;
	IntelCommandInfoList command_info_list(cpu_address_size());
	for (size_t i = 0; i <= end_index; i++) {
		IntelCommand* command = item(i);
		if (command->is_data())
			continue;

		std::map<uint64_t, IntelCommand*>::iterator it = address_list.find(command->address());
		if (it != address_list.end()) {
			if (mov_command && it->second) {
				if (mov_command != it->second && !mov_command->is_equal(*it->second))
					mov_command = NULL;
			}
			else {
				mov_command = it->second;
			}
		}

		if (i == end_index)
			break;

		CommandLink* link = command->link();
		if (link && link->type() != ltOffset && link->to_address()) {
			std::map<uint64_t, IntelCommand*>::iterator it = address_list.find(link->to_address());
			if (it != address_list.end()) {
				if (it->second != mov_command)
					it->second = NULL;
			}
			else {
				address_list[link->to_address()] = mov_command;
			}
		}

		if (command->is_end() || (command->options() & roBreaked) != 0)
			mov_command = NULL;
		else if (command->GetCommandInfo(command_info_list) && command_info_list.GetInfo(atWrite, otRegistr, reg))
			mov_command = command;
	}

	return (mov_command && mov_command->type() == cmLea && mov_command->operand(1).type == (otValue | otMemory)) ? mov_command->operand(1).value : (uint64_t)-1;
}

uint64_t IntelFunction::GetRegistrMaxValue(uint8_t reg, size_t end_index, IArchitecture& file)
{
	IntelCommandInfoList command_info_list(cpu_address_size());
	IntelCommand* jmp_command = NULL;
	IntelOperand find_operand = IntelOperand(otRegistr, cpu_address_size(), reg);
	for (size_t i = end_index; i > 0; i--) {
		IntelCommand* command = item(i - 1);
		if ((command->options() & roBreaked) || command->is_end()) {
			CommandLink* link = link_list()->GetLinkByToAddress(ltJmpWithFlag, item(i)->address());
			if (!link)
				link = link_list()->GetLinkByToAddress(ltJmp, item(i)->address());
			if (link) {
				command = reinterpret_cast<IntelCommand*>(link->from_command());
				if (link->type() == ltJmpWithFlag && command->flags() == (fl_C | fl_Z) && (command->options() & roInverseFlag) == 0)
					jmp_command = command;
				size_t index = IndexOf(command);
				if (index != NOT_ID) {
					i = index + 1;
					continue;
				}
			}
			break;
		}
		switch (command->type()) {
		case cmJmpWithFlag:
			if (command->flags() == (fl_C | fl_Z) && (command->options() & roInverseFlag))
				jmp_command = command;
			break;
		case cmCmp:
			if (command->operand(0) == find_operand) {
				if (command->operand(1).type == otValue && jmp_command)
					return command->operand(1).value;
			}
			break;
		case cmMovsx: case cmMovsxd:
			if (command->operand(0) == find_operand)
				find_operand = command->operand(1);
			break;
		case cmMov:
		case cmMovzx:
			if (command->operand(0) == find_operand) {
				find_operand = command->operand(1);
				if ((command->operand(1).type & otMemory) && command->operand(1).size == osByte) {
					uint64_t max_count = GetRegistrMaxValue(command->operand(1).registr, i - 1, file);
					if (max_count != (uint64_t)-1) {
						uint64_t base_address = 0;
						if (command->operand(1).type & otBaseRegistr) {
							if (cpu_address_size() == osQWord) {
								base_address = GetRegistrValue(command->operand(1).base_registr, i);
							}
							else {
								base_address = file.compiler_function_list()->GetRegistrValue(command->address(), IntelOperand(otRegistr, cpu_address_size(), command->operand(1).base_registr).encode());
							}
							if (base_address == (uint64_t)-1)
								break;
						}
						if (!file.AddressSeek(base_address + command->operand(1).value))
							break;
						uint8_t res = 0;
						for (uint64_t j = 0; j <= max_count; j++) {
							uint8_t b = file.ReadByte();
							if (b > res)
								res = b;
						}
						return res;
					}
				}
			}
			break;
		case cmCall:
			if (command->operand(0).type != otValue || command->operand(0).value != command->next_address())
				command = NULL;
			break;
		case cmAnd:
			if (command->operand(0).type == otRegistr && command->operand(0).registr == find_operand.registr && static_cast<uint32_t>(command->operand(1).value) == 0xffffffff)
				break;
			// fall-through
		default:
			if (!command->GetCommandInfo(command_info_list))
				command = NULL;
			else if ((find_operand.type & otRegistr) && command_info_list.GetInfo(atWrite, otRegistr, find_operand.registr))
				command = NULL;
			else if ((find_operand.type & otBaseRegistr) && command_info_list.GetInfo(atWrite, otRegistr, find_operand.base_registr))
				command = NULL;
			break;
		}
		if (!command)
			break;
	}
	return (uint64_t)-1;
}

CompilerFunction* IntelFunction::ParseCompilerFunction(IArchitecture& file, uint64_t address)
{
	CompilerFunction* compiler_function = file.compiler_function_list()->GetFunctionByAddress(address);
	if (!compiler_function && (file.segment_list()->GetMemoryTypeByAddress(address) & mtExecutable)) {
		IFunction* tmp_parent = this;
		size_t stack_depth = 0;
		bool in_parent_list = false;
		while (tmp_parent) {
			if (tmp_parent->GetCommandByAddress(address)) {
				in_parent_list = true;
				break;
			}
			tmp_parent = tmp_parent->parent();
			if ((stack_depth++) > 1000)
				return NULL;
		}
		if (in_parent_list)
			return NULL;

		IntelFunction func(NULL, cpu_address_size(), this);
		func.ReadFromFile(file, address);
		IntelCommand* entry = func.GetCommandByAddress(address);
		if (entry) {
			std::set<size_t> entry_stack;
			std::set<IntelCommand*> end_command_list;
			std::set<IntelCommand*> parsed_command_list;

			entry_stack.insert(func.IndexOf(entry));
			while (!entry_stack.empty()) {
				for (size_t i = *entry_stack.begin(); i < func.count(); i++) {
					IntelCommand* command = func.item(i);
					std::set<size_t>::const_iterator it = entry_stack.find(i);
					if (it != entry_stack.end())
						entry_stack.erase(it);

					if (parsed_command_list.find(command) != parsed_command_list.end())
						break;
					parsed_command_list.insert(command);

					switch (command->type()) {
					case cmRet:
					case cmIret:
						if (cpu_address_size() == osQWord && i > 0) {
							IntelCommand* prev = func.item(i - 1);
							if (prev->type() == cmMov && prev->operand(0).type == otRegistr && prev->operand(0).registr == regESP) {
								// mov rsp, xxxx
								command->include_option(roBreaked);
							}
						}
						end_command_list.insert(command);
						break;
					case cmJmpWithFlag:
					{
						IntelCommand* link_command = func.GetCommandByAddress(command->operand(0).value);
						if (link_command)
							entry_stack.insert(func.IndexOf(link_command));
					}
					break;
					case cmJmp:
					{
						bool is_end = true;
						compiler_function = file.compiler_function_list()->GetFunctionByAddress(command->address());
						if (compiler_function && (compiler_function->options() & coNoReturn) != 0)
							command->include_option(roBreaked);

						if (command->operand(0).type == (otValue | otMemory)) {
							if (IRelocation* reloc = file.relocation_list() ? file.relocation_list()->GetRelocationByAddress(command->operand(0).value) : NULL) {
								if (reloc->symbol()) {
									compiler_function = func.ParseCompilerFunction(file, reloc->symbol()->address());
									if (compiler_function && (compiler_function->options() & coNoReturn) != 0)
										command->include_option(roBreaked);
								}
							}
						}
						else if (command->operand(0).type == otValue) {
							IntelCommand* link_command = func.GetCommandByAddress(command->operand(0).value);
							if (link_command) {
								entry_stack.insert(func.IndexOf(link_command));
								is_end = false;
							}
							else {
								compiler_function = func.ParseCompilerFunction(file, command->operand(0).value);
								if (compiler_function && (compiler_function->options() & coNoReturn) != 0)
									command->include_option(roBreaked);
							}
						}
						else if (command->link() && (command->link()->type() == ltSwitch || command->link()->type() == ltOffset)) {
							ICommand* parent_command;
							if (command->link()->type() == ltSwitch)
								parent_command = command;
							else {
								parent_command = func.GetCommandByAddress(command->link()->to_address());
								parent_command = (parent_command && parent_command->link()) ? parent_command->link()->parent_command() : NULL;
							}

							if (parent_command) {
								is_end = false;
								for (size_t j = 0; j < func.link_list()->count(); j++) {
									CommandLink* link = func.link_list()->item(j);
									if (link->parent_command() == parent_command) {
										IntelCommand* link_command = func.GetCommandByAddress(link->to_address());
										if (link_command)
											entry_stack.insert(func.IndexOf(link_command));
									}
								}
							}
						}

						if (is_end)
							end_command_list.insert(command);
					}
					break;
					}

					if (command->options() & roBreaked) {
						end_command_list.insert(command);
						break;
					}

					if (command->is_end())
						break;
				}
			}

			compiler_function = file.compiler_function_list()->Add(cfNone, address);
			if (!end_command_list.empty()) {
				size_t no_return_count = 0;
				for (std::set<IntelCommand*>::const_iterator it = end_command_list.begin(); it != end_command_list.end(); it++) {
					IntelCommand* tmp_command = *it;
					if (tmp_command->options() & roBreaked)
						no_return_count++;
				}

				if (no_return_count == end_command_list.size())
					compiler_function->include_option(coNoReturn);
			}
		}
	}

	return compiler_function;
}

IntelCommand* IntelFunction::ParseCommand(IArchitecture& file, uint64_t address, bool dump_mode)
{
	CommandLink* command_link;
	IntelCommand* command, * prev;
	size_t i, c;
	CommandLinkList* links;
	IImportFunction* import_function;
	CompilerFunction* compiler_function;
	uint64_t base_address;

	if (dump_mode) {
		command = Add(address);
		if (!file.AddressSeek(address))
			command->InitUnknown();
		else if ((file.selected_segment()->memory_type() & mtExecutable) == 0)
			command->ReadValueFromFile(file, osByte);
		else {
			command->ReadFromFile(file);
			switch (command->type()) {
			case cmJmp:
			case cmCall:
			case cmJmpWithFlag: case cmJCXZ: case cmLoop: case cmLoope: case cmLoopne:
				if ((command->options() & roFar) == 0 && command->operand(0).type == otValue)
					command->AddLink(0, ltNone, command->operand(0).value);
				break;
			}
		}
		return command;
	}
	else {
		if (!file.AddressSeek(address))
			return NULL;
	}

	command = Add(address);
	command->ReadFromFile(file);

	links = link_list();
	switch (command->type()) {
	case cmDB:
		command->include_option(roInvalidOpcode);
		break;

	case cmAdd:
		if (command->dump_size() == 2 && command->dump(0) == 0 && command->dump(1) == 0) {
			delete command;
			command = NULL;
		}
		break;

	case cmCall:
		if ((command->options() & roFar) == 0) {
			if (command->operand(0).type == otValue && !command->operand(0).relocation)
				command->AddLink(0, ltCall, command->operand(0).value);
			else
				command->AddLink(-1, ltCall);

			if (command->operand(0).type == (otValue | otMemory)) {
				// check import
				import_function = file.import_list()->GetFunctionByAddress(command->operand(0).value);
				if (import_function != NULL && (import_function->options() & ioNoReturn) != 0)
					command->include_option(roBreaked);
			}
			else if (command->operand(0).type == otValue) {
				// check compiler function
				compiler_function = ParseCompilerFunction(file, command->operand(0).value);
				if (compiler_function) {
					if (compiler_function->options() & coNoReturn)
						command->include_option(roBreaked);

					switch (compiler_function->type()) {
					case cfInitBCBSEH:
						if (compiler_function->value(0)) {
							CompilerFunction* func = file.compiler_function_list()->GetFunctionByLowerAddress(address);
							if (func && func->type() == cfBCBSEH)
								ParseBCBSEH(file, func->value(0), command->next_address(), static_cast<uint8_t>(func->value(1)));
						}
						break;
					case cfSEH4Prolog:
						if (count() > 1) {
							prev = item(count() - 2);
							if (prev->type() == cmPush && prev->operand(0).type == otValue) {
								if (ParseSEH4(file, prev->operand(0).value))
									prev->AddLink(0, ltOffset, prev->operand(0).value);
							}
						}
					}
				}
			}
		}
		break;

	case cmJmp:
		if ((command->options() & roFar) == 0) {
			if (command->operand(0).type == otValue) { // jmp xxxx
				if (!command->operand(0).relocation)
					command->AddLink(0, ltJmp, command->operand(0).value);

				if (cpu_address_size() == osDWord) {
					if (count() > 1) {
						i = count() - 2;
						prev = item(i);
						if (prev->type() == cmPush && prev->operand(0).type == otValue) {
							command_link = links->GetLinkByToAddress(ltVBMemSEHBlock, command->operand(0).value);
							if (command_link || (file.AddressSeek(command->operand(0).value) && file.ReadByte() == 0xc3))
								prev->AddLink(0, ltFinallyBlock, prev->operand(0).value);
						}
					}

					command_link = links->GetLinkByToAddress(ltSEHBlock, command->address());
					if (command_link) {
						i = count();
						if (ParseFilterSEH(file, command->next_address())) {
							command_link->set_type(ltFilterSEHBlock);
							command_link->set_parent_command(item(i));
						}
						else {
							command_link->set_type(ltDualSEHBlock);
						}
					}
				}
			}
			else if (command->operand(0).type == (otValue | otMemory | otRegistr) && command->operand(0).size == cpu_address_size() && command->operand(0).scale_registr == (cpu_address_size() == osDWord ? 2 : 3)) { // jmp dword ptr [reg*4 + xxxx]
				if (ParseSwitch(file, command->operand(0).value, command->operand(0).size, 0, command, 0, static_cast<size_t>(GetRegistrMaxValue(command->operand(0).registr, IndexOf(command), file))))
					command->AddLink(0, ltSwitch, command->operand(0).value);
				else if (count() == 0)
					return ParseCommand(file, this->address(), dump_mode);
			}
			else if (command->operand(0).type == otRegistr && count() > 1) { // jmp reg
				prev = NULL;
				IntelCommandInfoList command_info(cpu_address_size());
				if (count() > 2) {
					for (i = count() - 2; i > 0; i--) {
						IntelCommand* tmp = item(i);
						if (!tmp->GetCommandInfo(command_info) || command_info.GetInfo(atWrite, otBaseRegistr, regEIP))
							break;
						if (command_info.GetInfo(atWrite, otRegistr, command->operand(0).registr)) {
							prev = tmp;
							break;
						}
					}
				}
				if (prev) {
					if ((prev->type() == cmAdd || prev->type() == cmSub)
						&& prev->operand(0).type == otRegistr
						&& prev->operand(0).size == cpu_address_size()
						&& prev->operand(0).registr == command->operand(0).registr) {
						uint8_t base_registr;
						base_address = 0;
						if (prev->operand(1).type == otRegistr) {
							base_registr = prev->operand(1).registr;
							prev = NULL;
							for (c = i; c > 0; c--) {
								IntelCommand* tmp = item(c - 1);
								if (tmp->type() == cmMov && tmp->operand(0).type == otRegistr && tmp->operand(1).type == otRegistr && tmp->operand(0).registr == base_registr)
									base_registr = tmp->operand(1).registr;
								else if (tmp->type() == cmLea && tmp->operand(0).type == otRegistr && tmp->operand(1).type == (otMemory | otValue) && tmp->operand(0).registr == base_registr)
									base_address = tmp->operand(1).value;
								else if ((tmp->type() == cmMov || tmp->type() == cmMovsxd)
									&& tmp->operand(0).type == otRegistr
									&& tmp->operand(0).registr == command->operand(0).registr) {
									i = c - 1;
									prev = tmp;
									break;
								}
								else {
									if (!tmp->GetCommandInfo(command_info) || command_info.GetInfo(atWrite, otRegistr, command->operand(0).registr))
										break;
								}
							}
						}
						else {
							base_registr = prev->operand(0).registr;
						}
						if (prev) {
							if ((prev->operand(1).type & (otMemory | otBaseRegistr | otRegistr)) == (otMemory | otBaseRegistr | otRegistr)
								&& prev->operand(1).scale_registr == 2
								&& prev->operand(1).size == osDWord) { // add/mov/movsx reg, [reg1 + reg2*4 + xxxx]
								if (!base_address) {
									if (cpu_address_size() == osQWord) {
										base_address = GetRegistrValue(prev->operand(1).base_registr, i);
									}
									else {
										IntelOperand base_operand = IntelOperand(otRegistr, cpu_address_size(), base_registr);
										if (i > 0) {
											IntelCommand* tmp = item(i - 1);
											if (tmp->type() == cmMov
												&& tmp->operand(0).type == otRegistr
												&& tmp->operand(0).registr == base_registr) {
												base_operand = tmp->operand(1);
											}
										}
										base_address = file.compiler_function_list()->GetRegistrValue(command->address(), base_operand.encode());
									}
								}
								if (base_address != (uint64_t)-1) {
									size_t mode;
									switch (prev->type()) {
									case cmMovsxd:
										mode = 1;
										break;
									case cmSub:
										mode = 2;
										break;
									default:
										mode = 0;
										break;
									}
									if (ParseSwitch(file, base_address + prev->operand(1).value, osDWord, base_address, command, mode, static_cast<size_t>(GetRegistrMaxValue(prev->operand(1).registr, IndexOf(prev), file)))) {
										command_link = prev->AddLink(1, ltSwitch, base_address + prev->operand(1).value);
										command_link->set_sub_value(base_address);
										command->AddLink(-1, ltOffset, command_link->to_address());
									}
									else if (count() == 0)
										return ParseCommand(file, this->address(), dump_mode);
								}
							}
							else if (prev->type() == cmAdd
								&& prev->operand(1).type == (otMemory | otRegistr | otValue)
								&& prev->operand(1).scale_registr == 2
								&& prev->operand(1).size == osDWord
								&& prev->operand(0).registr == base_registr) { // add reg, [reg1*4 + xxxx]
								if (cpu_address_size() == osQWord) {
									base_address = GetRegistrValue(base_registr, i);
								}
								else {
									IntelOperand base_operand = IntelOperand(otRegistr, cpu_address_size(), base_registr);
									if (i > 0) {
										IntelCommand* tmp = item(i - 1);
										if (tmp->type() == cmMov
											&& tmp->operand(0).type == otRegistr
											&& tmp->operand(0).registr == base_registr) {
											base_operand = tmp->operand(1);
										}
									}
									base_address = file.compiler_function_list()->GetRegistrValue(command->address(), base_operand.encode());
								}
								if (base_address != (uint64_t)-1) {
									if (ParseSwitch(file, prev->operand(1).value, osDWord, base_address, command, 0, static_cast<size_t>(GetRegistrMaxValue(prev->operand(1).registr, IndexOf(prev), file)))) {
										command_link = prev->AddLink(1, ltSwitch, prev->operand(1).value);
										command->AddLink(-1, ltOffset, command_link->to_address());
									}
									else if (count() == 0)
										return ParseCommand(file, this->address(), dump_mode);
								}
							}
							else if (prev->type() == cmMov
								&& prev->operand(1).type == (otMemory | otRegistr | otValue)
								&& prev->operand(1).scale_registr == 2
								&& prev->operand(1).size == osDWord
								&& prev->operand(0).registr == command->operand(0).registr) { // mov reg, [reg1*4 + xxxx]
								if (cpu_address_size() == osQWord) {
									base_address = GetRegistrValue(base_registr, i + 1);
								}
								else {
									IntelOperand base_operand = IntelOperand(otRegistr, cpu_address_size(), base_registr);
									IntelCommand* tmp = item(i + 1);
									if (tmp->type() == cmMov
										&& tmp->operand(0).type == otRegistr
										&& tmp->operand(0).registr == base_registr) {
										base_operand = tmp->operand(1);
									}
									base_address = file.compiler_function_list()->GetRegistrValue(command->address(), base_operand.encode());
								}
								if (base_address != (uint64_t)-1) {
									if (ParseSwitch(file, prev->operand(1).value, osDWord, base_address, command, 0, static_cast<size_t>(GetRegistrMaxValue(prev->operand(1).registr, IndexOf(prev), file)))) {
										command_link = prev->AddLink(1, ltSwitch, prev->operand(1).value);
										command->AddLink(-1, ltOffset, command_link->to_address());
									}
									else if (count() == 0)
										return ParseCommand(file, this->address(), dump_mode);
								}
							}
						}
					}
					else if (prev->type() == cmMov && prev->operand(1).type == (otValue | otMemory | otRegistr) && prev->operand(1).size == cpu_address_size() && prev->operand(1).scale_registr == (cpu_address_size() == osDWord ? 2 : 3)) { // mov reg1, dword ptr [reg*4 + xxxx]
						if (ParseSwitch(file, prev->operand(1).value, prev->operand(1).size, 0, command, 0, static_cast<size_t>(GetRegistrMaxValue(prev->operand(1).registr, IndexOf(prev), file)))) {
							command_link = prev->AddLink(1, ltSwitch, prev->operand(1).value);
							command->AddLink(-1, ltOffset, command_link->to_address());
						}
						else if (count() == 0)
							return ParseCommand(file, this->address(), dump_mode);
					}
				}
			}
		}
		break;

	case cmPush:
		if (cpu_address_size() == osDWord) {
			if (command->operand(0).type == otValue) { // push xxxx
				if (count() > 1) {
					i = count() - 2;
					prev = item(i);
					if (prev->type() == cmMov
						&& prev->operand(0).type == (otMemory | otRegistr)
						&& prev->base_segment() == segFS
						&& prev->operand(1).type == otRegistr
						&& prev->operand(1).registr != regESP) // mov fs:[reg], reg1
						command->AddLink(0, ltFinallyBlock, command->operand(0).value);
				}
			}
			else if ((command->operand(0).type & otMemory) != 0 && command->base_segment() == segFS) { // push fs:[xxxx]
				if (count() >= 2) {
					i = count() - 2;
					prev = item(i);
					if (prev->type() == cmPush && prev->operand(0).type == otValue) // push xxxx
						prev->AddLink(0, ltSEHBlock, prev->operand(0).value);
				}
			}
		}
		break;

	case cmMov:
		if (cpu_address_size() == osDWord) {
			if (command->base_segment() == segFS) {
				if (command->operand(0).type == otRegistr
					&& command->operand(1).type == (otMemory | otValue)
					&& command->operand(1).value == 0) { // mov reg, fs:[00000000]

					uint64_t mem_offset = 0;
					uint8_t mem_registr = 0;
					{
						IntelCommand tmp(NULL, cpu_address_size());
						uint64_t pos = file.Tell();
						for (i = 0; i < 10; i++) {
							tmp.ReadFromFile(file);
							if (tmp.type() == cmPush
								|| tmp.type() == cmDB
								|| tmp.type() == cmJmp
								|| tmp.type() == cmJmpWithFlag
								|| tmp.type() == cmRet
								|| tmp.type() == cmIret
								|| tmp.type() == cmCall)
								break;
							if (tmp.type() == cmMov) {
								if (tmp.operand(1).type == otRegistr && tmp.operand(1).registr == command->operand(0).registr && tmp.operand(0).type == (otMemory | otRegistr | otValue)) {
									mem_offset = tmp.operand(0).value;
									mem_registr = tmp.operand(0).registr;
								}
								break;
							}
						}
						file.Seek(pos);
					}

					c = 0;
					for (i = count(); i > 0; i--) {
						prev = item(i - 1);
						if (prev->type() == cmJmp
							|| prev->type() == cmJmpWithFlag
							|| prev->type() == cmRet
							|| prev->type() == cmIret
							|| prev->type() == cmCall)
							break;

						if (prev->type() == cmPush ||
							(mem_offset && prev->type() == cmMov && prev->operand(0).type == (otMemory | otRegistr | otValue) && prev->operand(0).value == mem_offset + 4 && prev->operand(0).registr == mem_registr && prev->operand(1).type == otValue)) {
							c++;
							if (mem_offset)
								mem_offset += 4;
							size_t k = (prev->type() == cmPush) ? 0 : 1;
							if (c == 1) {
								if (ParseNewSEH(file, prev->operand(k).value)) {
									prev->AddLink((int)k, ltOffset, prev->operand(k).value);
									break;
								}
							}
							else if (c == 2) {
								uint64_t version = 0;
								if (i > 1) {
									IntelCommand* tmp = item(i - 2);
									if (tmp->type() == cmPush && tmp->operand(0).type == otValue)
										version = tmp->operand(0).value;
								}

								if (version == (uint64_t)-2 && ParseSEH4(file, prev->operand(k).value))
									prev->AddLink((int)k, ltOffset, prev->operand(k).value);
								else if (version == (uint64_t)-1 && ParseSEH3(file, prev->operand(k).value))
									prev->AddLink((int)k, ltOffset, prev->operand(k).value);
								break;
							}
						}
					}
				}
			}
			else if (command->operand(0).type == (otMemory | otRegistr | otValue)
				&& command->operand(0).registr == regEBP
				&& command->operand(0).size == osDWord
				&& command->operand(1).type == otValue) { // mov [ebp + xxxx], xxxx
				CompilerFunction* func = file.compiler_function_list()->GetFunctionByAddress(address);
				if (func && func->type() == cfVB6SEH) {
					if (ParseVB6SEH(file, func->value(0)))
						command->AddLink(1, ltOffset, func->value(0));
				}
			}
		}
		break;

	case cmInt:
		if (command->operand(0).value == 3)
			command->include_option(roBreaked);
		else if (file.owner()->format_name() == "PE") {
			if (command->operand(0).value == 0x29) // __failfast
				command->include_option(roBreaked);
		}
		break;

	case cmHlt:
	case cmUd2:
		command->include_option(roBreaked);
		break;

	case cmJmpWithFlag: case cmJCXZ: case cmLoop: case cmLoope: case cmLoopne:
		command->AddLink(0, ltJmpWithFlag, command->operand(0).value);
		break;
	}

	return command;
}

IntelCommand* IntelFunction::ReadValidCommand(IArchitecture& file, uint64_t address)
{
	size_t i, f, d;
	IntelCommand* command;
	IFixupList* fixup_list;
	ISectionList* segment_list;
	const IFixup* fixup;
	bool invalid_fixup;
	IntelOperand operand;

	command = ParseCommand(file, address, true);
	if (!command)
		return NULL;

	fixup_list = file.fixup_list();
	segment_list = file.segment_list();

	if (fixup_list->count() > 0) {
		// need to check fixups for all value operands
		d = 0;
		while (d < command->dump_size()) {
			fixup = fixup_list->GetFixupByNearAddress(address + d);
			if (fixup) {
				invalid_fixup = true;
				f = static_cast<size_t>(fixup->address() - address);
				for (i = 0; i < 3; i++) {
					operand = command->operand(i);
					if (operand.type & otValue) {
						if (command->type() == cmCall || command->type() == cmJmp || command->type() == cmJmpWithFlag) {
							if ((operand.type & otMemory) == 0)
								break;
						}
						if (f == operand.value_pos) {
							invalid_fixup = false;
							break;
						}
					}
				}
				if (invalid_fixup)
					return NULL;
				d += OperandSizeToValue(fixup->size());
			}
			else {
				d++;
			}
		}
	}

	/*
	for (i = 0; i < 3; i++) {
		operand = command->operand(i);
		if (operand.type == (otMemory | otValue)) {
			// check fixup
			if (fixup_list->count() > 0 && operand.fixup == NULL && !operand.is_large_value)
				return NULL;
			// check segment type
			if ((segment_list->GetMemoryTypeByAddress(operand.value) & mtReadable) == 0)
				return NULL;
		}
	}
	*/

	if (command->type() == cmCall || command->type() == cmJmp || command->type() == cmJmpWithFlag) {
		operand = command->operand(0);
		// check segment type for value operand
		if (operand.type == otValue && (segment_list->GetMemoryTypeByAddress(command->operand(0).value) & mtExecutable) == 0)
			return NULL;
	}

	if (cpu_address_size() == osQWord) {
		// calc REX preffixes count
		f = 0;
		for (i = 0; i < command->command_pos(); i++) {
			if ((command->dump(i) & 0xF0) == 0x40) {
				f++;
			}
			else {
				if (f)
					break;
			}
		}
		if (f > 1)
			return NULL;
	}

	return command;
}

uint64_t IntelFunction::ParseParam(IArchitecture& file, size_t index, uint64_t& param_reference)
{
	size_t i;
	IntelCommand* command;
	bool need_push_value;
	uint8_t registr;
	IntelOperand operand;
	IntelCommandInfoList command_info(cpu_address_size());

	CallingConvention calling_convention = file.calling_convention();
	bool use_stack = false;
	switch (calling_convention) {
	case ccMSx64:
		registr = regECX;
		break;
	case ccABIx64:
		registr = regEDI;
		break;
	default:
		registr = 0xFF;
		use_stack = true;
	}

	need_push_value = true;
	for (i = index; i > 0; i--) {
		command = item(i - 1);

		// unknown command
		if (!command->GetCommandInfo(command_info))
			return 0;

		// commands change EIP can no be found between API`s param and API`s call
		if (command_info.GetInfo(atWrite, otBaseRegistr, regEIP))
			return 0;

		param_reference = command->address();
		if (!use_stack) {
			if (command->type() == cmLea && command->operand(0).size == cpu_address_size() && command->operand(0).type == otRegistr && command->operand(0).registr == registr) {
				// lea reg, [xxxx]
				operand = command->operand(1);
				if (operand.type == (otMemory | otValue) && operand.is_large_value)
					return operand.value;
				return 0;
			}
			else if (command->type() == cmMov && (command->operand(0).size == cpu_address_size() || (command->operand(0).size == osDWord && cpu_address_size() == osQWord)) && command->operand(0).type == otRegistr && command->operand(0).registr == registr) {
				// mov reg, xxxx
				operand = command->operand(1);
				if (operand.type == otValue) {
					return operand.value;
				}
				else if (operand.type == otRegistr) {
					registr = operand.registr;
				}
				else {
					return 0;
				}
			}
			else if (command_info.GetInfo(atWrite, otRegistr, registr)) {
				return 0;
			}

		}
		else {
			if ((command->type() == cmPush && need_push_value) || // push xxxx
				(command->type() == cmMov && command->operand(0).size == cpu_address_size() &&
					// mov [esp], xxxx
					((command->operand(0).type == (otMemory | otBaseRegistr) && command->operand(0).base_registr == regESP && need_push_value) ||
						// mov reg, xxxx
						(command->operand(0).type == otRegistr && command->operand(0).registr == registr && !need_push_value))
					)) {
				operand = command->operand(command->type() == cmMov);
				if (operand.type == otValue) {
					return operand.value;
				}
				else if (operand.type == otRegistr) {
					need_push_value = false;
					registr = operand.registr;
				}
				else {
					return 0;
				}
			}
			else if (!need_push_value && command->type() == cmLea && command->operand(0).size == cpu_address_size() && command->operand(0).type == otRegistr && command->operand(0).registr == registr && command->operand(1).type == (otValue | otRegistr | otMemory)) {
				// lea reg, [reg + xxxx]
				IntelOperand base_operand = IntelOperand(otRegistr, cpu_address_size(), command->operand(1).registr);
				if (i > 1) {
					IntelCommand* tmp = item(i - 2);
					if (tmp->type() == cmMov
						&& tmp->operand(0).type == otRegistr
						&& tmp->operand(0).registr == base_operand.registr) {
						base_operand = tmp->operand(1);
					}
				}
				uint64_t base_address = file.compiler_function_list()->GetRegistrValue(command->address(), base_operand.encode());
				if (base_address != (uint64_t)-1)
					return base_address + command->operand(1).value;
			}
			else if (!need_push_value && command_info.GetInfo(atWrite, otRegistr, registr)) {
				return 0;
			}
		}
	}

	return 0;
}

void IntelFunction::ReadMarkerCommands(IArchitecture& file, MarkerCommandList& command_list, uint64_t address, uint32_t options)
{
	uint64_t param_address, param_reference, call_start, call_end, tmp_address;
	IntelCommand* command;
	ICommand* link_command;
	uint8_t api_reg;
	std::vector<size_t> stack;
	size_t i, j, cur_index;
	bool need_parse_backward, first_call;

	command_list.clear();
	call_start = address;
	call_end = address + 1;

	if (options & moForward) {
		// forward searching
		if (count() == 0)
			return;

		command = item(0);
		if (command->operand(0).type != otRegistr)
			return;

		api_reg = command->operand(0).registr;
		ReadFromFile(file, address);

		command = GetCommandByAddress(address);
		if (!command)
			return;

		cur_index = IndexOf(command) + 1;
		need_parse_backward = false;
		first_call = true;
		IntelCommandInfoList command_info_list(cpu_address_size());
		while (cur_index < count()) {
			command = item(cur_index);
			bool is_end = command->is_end();
			if ((command->options() & roBreaked) == 0) {
				if (command->type() == cmCall && command->operand(0).type == otRegistr && command->operand(0).registr == api_reg) {
					// call reg
					if (options & moNeedParam) {
						param_address = ParseParam(file, cur_index, param_reference);
						if (!param_address && first_call) {
							need_parse_backward = true;
							call_start = command->address();
							call_end = command->next_address();
						}
						else {
							command_list.Add(command->address(), command->next_address(), param_reference, param_address);
						}
						first_call = false;
					}
					else {
						command_list.Add(command->address(), command->next_address(), 0, 0);
					}
				}
				else if ((command->type() == cmJmp || command->type() == cmJmpWithFlag || command->type() == cmLoop) && command->link()) {
					// add link to stack
					link_command = GetCommandByAddress(command->link()->to_address());
					if (link_command) {
						i = IndexOf(link_command);
						if (i != NOT_ID)
							stack.push_back(i);
					}
				}
				else if (command->GetCommandInfo(command_info_list)) {
					if (command_info_list.GetInfo(atWrite, otRegistr, api_reg)) {
						std::vector<IntelCommand*> exclude_command_list;
						exclude_command_list.push_back(command);
						for (i = 0; i < exclude_command_list.size(); i++) {
							for (j = IndexOf(exclude_command_list[i]); j < count(); j++) {
								command = item(j);

								if (std::find(exclude_command_list.begin(), exclude_command_list.end(), command) == exclude_command_list.end())
									exclude_command_list.push_back(command);

								for (size_t k = 0; k < link_list()->count(); k++) {
									CommandLink* link = link_list()->item(k);
									if (link->parent_command() == command && std::find(exclude_command_list.begin(), exclude_command_list.end(), link->from_command()) == exclude_command_list.end())
										exclude_command_list.push_back(reinterpret_cast<IntelCommand*>(link->from_command()));
								}

								CommandLink* link = command->link();
								if (link && link->to_address()) {
									IntelCommand* link_command = GetCommandByAddress(link->to_address());
									if (link_command && std::find(exclude_command_list.begin(), exclude_command_list.end(), link_command) == exclude_command_list.end())
										exclude_command_list.push_back(link_command);
								}

								if (command->is_end())
									break;
							}
						}
						for (i = 0; i < exclude_command_list.size(); i++) {
							exclude_command_list[i]->include_option(roBreaked);
						}
						is_end = true;
					}
				}
				else {
					is_end = true;
				}
			}
			else {
				is_end = true;
			}

			// the end of branch
			if (is_end) {
				// delete processed indexes
				for (i = stack.size(); i > 0; i--) {
					if (stack[i - 1] <= cur_index)
						stack.erase(stack.begin() + i - 1);
				}
				if (stack.empty())
					break;

				// calc minimum index from stack
				cur_index = stack[0];
				for (i = 0; i < stack.size(); i++) {
					if (cur_index > stack[i])
						cur_index = stack[i];
				}
			}
			else {
				cur_index++;
			}
		}

		if (!need_parse_backward)
			return;
	}

	if ((options & moNeedParam) == 0)
		return;

	// backward searching
	SignatureList param_signatures;
	if (cpu_address_size() == osDWord) {
		for (i = 0; i < file.compiler_function_list()->count(); i++) {
			if (file.compiler_function_list()->item(i)->type() == cfBaseRegistr) {
				param_signatures.Add("8B");    // mov reg, [reg + xxxx]
				break;
			}
		}
		param_signatures.Add("68");    // push xxxx
		param_signatures.Add("B?");    // mov reg, xxxx
		param_signatures.Add("8D8?");    // lea reg, [xxxx]
		param_signatures.Add("C70424");    // mov [esp], xxxx
	}
	else {
		param_signatures.Add("4?8D");    // lea reg, [xxxx]
		param_signatures.Add("B?");    // mov reg, xxxx
	}

	for (i = 0; i < param_signatures.count(); i++) {
		Signature* sign = param_signatures.item(i);
		for (j = 0x100; j > 0; j--) {
			if (!file.AddressSeek(address - j))
				continue;
			uint8_t b;
			file.Read(&b, sizeof(b));
			if (!sign->SearchByte(b))
				continue;

			clear();
			tmp_address = address - j - sign->size() + 1;
			while (tmp_address < address) {
				command = ReadValidCommand(file, tmp_address);
				// these commands can no be found between API`s param and API`s call
				if (command == NULL
					|| command->type() == cmDB
					|| command->type() == cmRet
					|| command->type() == cmIret
					|| command->type() == cmJmp
					|| command->type() == cmEnter) {
					tmp_address = 0;
					break;
				}
				tmp_address = command->next_address();
			}

			if (tmp_address != address)
				continue;

			size_t index = count();
			if (options & moSkipLastCall) {
				if (count() > 1) {
					command = item(count() - 1);
					if (command->type() == cmPush && command->operand(0).type == otRegistr && command->operand(0).registr == regEAX) {
						command = item(count() - 2);
						if (command->type() == cmCall)
							index -= 2;
					}
				}
			}

			param_address = ParseParam(file, index, param_reference);
			if (param_address && (file.segment_list()->GetMemoryTypeByAddress(param_address) & mtReadable)) {
				command_list.Add(call_start, call_end, param_reference, param_address);
				return;
			}
		}
	}
}

IntelCommand* IntelFunction::CreateCommand()
{
	return new IntelCommand(this, cpu_address_size());
}

void IntelFunction::CreateBlocks()
{
	CommandBlock* cur_block = NULL;
	for (size_t i = 0; i < count(); i++) {
		IntelCommand* command = item(i);
		if (command->block() || (command->options() & roNeedCompile) == 0) {
			cur_block = NULL;
			continue;
		}

		if ((!cur_block || (command->options() & roCreateNewBlock) || item(cur_block->end_index())->is_data() != command->is_data()))
			cur_block = AddBlock(i, true);

		cur_block->set_end_index(i);

		command->set_block(cur_block);
		if (command->type() == cmJmp || command->type() == cmRet || command->type() == cmIret)
			cur_block = NULL;
	}
}

bool IntelFunction::Init(const CompileContext& ctx)
{
	if (need_compile()) {
		ICommand* command;
		CommandLink* link;
		size_t i, j, k;
		std::vector<ICommand*> entry_command_list;
		std::vector<ICommand*> exclude_command_list;

		// exclude duplicates of exception handlers
		for (i = 0; i < link_list()->count(); i++) {
			link = link_list()->item(i);
			if (link->type() == ltExtSEHHandler || link->type() == ltMemSEHBlock) {
				command = GetCommandByAddress(link->to_address());
				if (command && std::find(entry_command_list.begin(), entry_command_list.end(), command) == entry_command_list.end()) {
					ICommand* tmp = ctx.file->function_list()->GetCommandByAddress(command->address(), true);
					if (tmp && tmp != command)
						entry_command_list.push_back(command);
				}
			}
		}

		for (i = 0; i < entry_command_list.size(); i++) {
			ICommand* entry_command = entry_command_list[i];
			if (!entry_command)
				continue;

			for (j = IndexOf(entry_command); j < count(); j++) {
				command = item(j);

				if (std::find(exclude_command_list.begin(), exclude_command_list.end(), command) != exclude_command_list.end())
					break;

				std::vector<ICommand*>::iterator it = std::find(entry_command_list.begin(), entry_command_list.end(), command);
				if (it != entry_command_list.end())
					*it = NULL;

				exclude_command_list.push_back(command);

				for (k = 0; k < link_list()->count(); k++) {
					link = link_list()->item(k);
					if (link->parent_command() == command && std::find(entry_command_list.begin(), entry_command_list.end(), link->from_command()) == entry_command_list.end())
						entry_command_list.push_back(link->from_command());
				}

				link = command->link();
				if (link && link->to_address()) {
					ICommand* link_command = GetCommandByAddress(link->to_address());
					if (link_command && std::find(entry_command_list.begin(), entry_command_list.end(), link_command) == entry_command_list.end())
						entry_command_list.push_back(link_command);
				}

				if (command->is_data() || command->is_end() || (command->options() & roBreaked) != 0)
					break;
			}
		}

		for (i = 1; i < count(); i++) {
			command = item(i - 1);
			if (!command->is_end() && std::find(exclude_command_list.begin(), exclude_command_list.end(), item(i)) != exclude_command_list.end())
				command->include_option(roBreaked);
		}

		for (i = 0; i < exclude_command_list.size(); i++) {
			command = exclude_command_list[i];
			if (command->link())
				delete command->link();
			delete command;
			if (entry() == command)
				set_entry(NULL);
		}

		for (i = 0; i < function_info_list()->count(); i++) {
			FunctionInfo* info = function_info_list()->item(i);
			if (!info->entry())
				continue;

			if (info->entry()->comment().value == "LPStart Encoding") {
				size_t c = IndexOf(info->entry());
				for (j = c + 1; j < count(); j++) {
					IntelCommand* command = item(j);
					if (!command->is_data() || (command->options() & roCreateNewBlock))
						break;

					if (command->comment().value == "TTable Offset") {
						command->CompileToNative();
						if (command->link())
							command->link()->set_sub_value(command->link()->sub_value() + command->dump_size() - command->original_dump_size());
					}
				}
			}
		}
	}

	return BaseFunction::Init(ctx);
}

bool IntelFunction::Prepare(const CompileContext& ctx)
{
	IArchitecture* file = from_runtime() ? ctx.runtime : ctx.file;
	if (type() == otString) {
		MapFunction* map_function = file->map_function_list()->GetFunctionByAddress(address());
		if (map_function) {
			for (size_t i = 0; i < count(); i++) {
				IntelCommand* command = item(i);
				command->exclude_option(roClearOriginalCode);

				if (command->address()) {
					uint64_t end_address = command->address() + command->original_dump_size();
					for (size_t j = 0; j < map_function->reference_list()->count(); j++) {
						Reference* reference = map_function->reference_list()->item(j);
						if (reference->tag() != 1)
							continue;

						if (command->address() <= reference->operand_address() && end_address > reference->operand_address())
							end_address = reference->operand_address();
					}
					if (end_address > command->address())
						ctx.manager->Add(command->address(), static_cast<size_t>(end_address - command->address()), file->segment_list()->GetMemoryTypeByAddress(command->address()));
				}
			}
		}
	}
	else if (address() && count() > 0) {
		for (size_t i = 0; i < count(); i++) {
			IntelCommand* command = item(i);
			if (command->options() & roInvalidOpcode) {
				ctx.file->Notify(mtError, command, string_format(language[lsCommandNotSupported].c_str(), command->text().c_str()));
				return false;
			}

			uint64_t next_address = command->address() + command->original_dump_size();
			if (command->type() == cmCall && (command->options() & roFar) == 0 && command->operand(0).type == otValue && command->operand(0).value != next_address) {
				CompilerFunction* compiler_function = file->compiler_function_list()->GetFunctionByAddress(next_address);
				if (compiler_function && compiler_function->type() == cfBaseRegistr) {
					delete command->link();
					IntelOperand operand;
					operand.decode(compiler_function->value(0));
					command->Init(cmLea, operand, IntelOperand(otMemory | otValue, operand.size, 0, next_address, (cpu_address_size() == osDWord) ? NEED_FIXUP : LARGE_VALUE));
					command->CompileToNative();
				}
			}
			if (!command->is_data() && ((command->options() & roBreaked) || is_breaked_address(next_address))) {
				// need add JMP after breaked commands
				IntelCommand* jmp_command = new IntelCommand(this, cpu_address_size(), cmJmp, IntelOperand(otValue, cpu_address_size(), 0, next_address));
				jmp_command->AddLink(0, ltJmp, next_address);
				jmp_command->set_address_range(function_info_list()->GetRangeByAddress(next_address));
				jmp_command->CompileToNative();
				InsertObject(i + 1, jmp_command);
			}
			if (is_breaked_address(next_address))
				break;
		}

		if (ctx.runtime && compilation_type() != ctMutation && address() && entry_type() != etNone) {
			size_t i, c;
			IntelCommand* command, * jmp_command, * loop_command, * antitrace_command;
			ICommand* loader_data_command = NULL;
			uint64_t loader_data_address = 0;

			IntelLoaderData* loader_data = reinterpret_cast<IntelFunctionList*>(ctx.file->function_list())->loader_data();
			if (loader_data) {
				loader_data_command = loader_data->entry();
			}
			else {
				loader_data_address = ctx.runtime->export_list()->GetAddressByType(atLoaderData);
				if (!loader_data_address)
					return false;
			}

			c = count();
			AddCommand(cmPushf);
			AddCommand(cmPush, IntelOperand(otRegistr, cpu_address_size(), regEAX));
			AddCommand(cmPush, IntelOperand(otRegistr, cpu_address_size(), regECX));
			AddCommand(cmPush, IntelOperand(otRegistr, cpu_address_size(), regEBX));
			AddCommand(cmPush, IntelOperand(otRegistr, cpu_address_size(), regEDX));

			// anti trace
			antitrace_command = NULL;
			if (ctx.runtime && (ctx.options.flags & cpCheckDebugger)) {
				Data data;
				data.PushByte(0xf3); // rep
				data.PushByte(0xf3); // rep
				data.PushByte(0xf3); // rep
				data.PushByte(0xf3); // rep
				data.PushByte(0xf3); // rep
				data.PushByte(0x9c); // pushf
				command = AddCommand(data);
				command->AddLink(-1, ltNative);
				AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size(), regEAX));
				AddCommand(cmTest, IntelOperand(otRegistr, osDWord, regEAX), IntelOperand(otValue, osDWord, 0, fl_T));
				antitrace_command = AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size()));
				antitrace_command->set_flags(fl_Z);
				antitrace_command->include_option(roInverseFlag);
				antitrace_command->AddLink(0, ltJmpWithFlag);
			}

			// add CPU hash check
			AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regEAX), IntelOperand(otValue, osDWord, 0, 1));
			command = AddCommand(cmCpuid);
			command->include_option(roNoNative);

			// Athlon bug
			AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otRegistr, osDWord, regEAX));
			AddCommand(cmAnd, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otValue, osDWord, 0, 0xff0));
			AddCommand(cmCmp, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otValue, osDWord, 0, 0xfe0));
			jmp_command = AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size()));
			jmp_command->set_flags(fl_Z);
			jmp_command->include_option(roInverseFlag);
			jmp_command->AddLink(0, ltJmpWithFlag);
			AddCommand(cmXor, IntelOperand(otRegistr, osDWord, regEAX), IntelOperand(otValue, osDWord, 0, 0x20));
			command = AddCommand(cmNop);
			jmp_command->link()->set_to_command(command);

			AddCommand(cmAnd, IntelOperand(otRegistr, osDWord, regEBX), IntelOperand(otValue, osDWord, 0, 0x00ffffff));
			AddCommand(cmAdd, IntelOperand(otRegistr, osDWord, regEAX), IntelOperand(otRegistr, osDWord, regEBX));
			if (ctx.file->owner()->format_name() == "PE") {
				PEArchitecture* pe = reinterpret_cast<PEArchitecture*>(ctx.file);
				if (pe->image_type() != itDriver) {
					size_t osbuild_offset;
					if (cpu_address_size() == osDWord) {
						command = AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regEBX), IntelOperand(otMemory | otValue, cpu_address_size(), 0, 0x30));
						command->set_base_segment(segFS);
						osbuild_offset = offsetof(PEB32, OSBuildNumber);
					}
					else {
						command = AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regEBX), IntelOperand(otMemory | otValue, cpu_address_size(), 0, 0x60));
						command->set_base_segment(segGS);
						osbuild_offset = offsetof(PEB64, OSBuildNumber);
					}
					AddCommand(cmMovzx, IntelOperand(otRegistr, osDWord, regEBX), IntelOperand(otMemory | otRegistr | otValue, osWord, regEBX, osbuild_offset));
					AddCommand(cmShl, IntelOperand(otRegistr, osDWord, regEBX), IntelOperand(otValue, osWord, 0, 7));
					AddCommand(cmAdd, IntelOperand(otRegistr, osDWord, regEAX), IntelOperand(otRegistr, osDWord, regEBX));
				}
			}
			command = AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regEDX), IntelOperand(otMemory | otValue, cpu_address_size(), 0, loader_data_address, NEED_FIXUP));
			command->AddLink(1, ltOffset, loader_data_command);
			AddCommand(cmXor, IntelOperand(otRegistr, osDWord, regEAX), IntelOperand(otRegistr, osDWord, regEDX));
			AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otMemory | otRegistr | otValue, osDWord, regEDX, ctx.runtime_var_index[VAR_CPU_COUNT] * OperandSizeToValue(cpu_address_size())));
			AddCommand(cmXor, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otValue, osDWord, 0, ctx.runtime_var_salt[VAR_CPU_COUNT]));
			AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size(), regEDX), IntelOperand(otValue, cpu_address_size(), 0, ctx.runtime_var_index[VAR_CPU_HASH] * OperandSizeToValue(cpu_address_size())));

			command = AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regEBX), IntelOperand(otMemory | otRegistr, osDWord, regEDX, 0));
			AddCommand(cmXor, IntelOperand(otRegistr, osDWord, regEBX), IntelOperand(otValue, osDWord, 0, ctx.runtime_var_salt[VAR_CPU_HASH]));
			AddCommand(cmCmp, IntelOperand(otRegistr, osDWord, regEAX), IntelOperand(otRegistr, osDWord, regEBX));

			jmp_command = AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size()));
			jmp_command->set_flags(fl_Z);
			jmp_command->AddLink(0, ltJmpWithFlag);

			AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size(), regEDX), IntelOperand(otValue, cpu_address_size(), 0, OperandSizeToValue(cpu_address_size())));
			AddCommand(cmDec, IntelOperand(otRegistr, osDWord, regECX));
			loop_command = AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size()));
			loop_command->set_flags(fl_Z);
			loop_command->include_option(roInverseFlag);
			loop_command->AddLink(0, ltJmpWithFlag, command);

			command = AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size(), regEDX));
			if (antitrace_command)
				antitrace_command->link()->set_to_command(command);
			AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size(), regEBX));
			AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size(), regECX));
			AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size(), regEAX));
			AddCommand(cmPopf);
			AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regEAX), IntelOperand(otValue, osDWord, 0, 0xdeadc0de));
			AddCommand(cmPush, IntelOperand(otValue, cpu_address_size(), 0, 0));
			AddCommand(cmRet);

			command = AddCommand(cmNop);
			jmp_command->link()->set_to_command(command);
			AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size(), regEDX));
			AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size(), regEBX));
			AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size(), regECX));
			AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size(), regEAX));
			AddCommand(cmPopf);
			command = AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size(), 0, address()));
			command->AddLink(0, ltJmp, address());

			for (i = c; i < count(); i++) {
				command = item(i);
				command->CompileToNative();
			}

			set_entry(item(c));
		}
	}

	return BaseFunction::Prepare(ctx);
}

bool IntelFunction::PrepareExtCommands(const CompileContext& ctx)
{
	size_t i;
	MemoryManager& manager = *ctx.manager;

	ExtCommandList* ext_list = ext_command_list();
	if (type() != otString) {
		if (address() && !entry()) {
			ctx.file->Notify(mtError, (count()) ? item(0) : NULL, "There are no data for compilation");
			return false;
		}
		if (entry() && entry_type() != etNone)
			ext_list->Add((entry_type() == etDefault) ? address() : 0, entry());
	}

	ext_list->Sort();
	for (i = ext_list->count(); i > 0; i--) {
		ExtCommand* ext_command = ext_list->item(i - 1);
		if (!ext_command->command() || is_breaked_address(ext_command->address()))
			continue;

		if (ext_command->address()) {
			if (!manager.Alloc(5, mtNone, ext_command->address())) {
				ctx.file->Notify(mtError, ext_command->command(), ext_command->address() == address() ? language[lsMinimalFunctionSize] : language[lsNotEnoughPlace]);
				return false;
			}
		}
		ext_command->command()->include_section_option(rtLinkedToExt);
	}

	return true;
}

void IntelFunction::GetFreeRegisters(size_t index, CommandInfoList& free_registr_list) const
{
	CommandInfoList used_registr_list;
	IntelCommandInfoList command_info_list(cpu_address_size());

	uint16_t free_flags = 0;
	bool free_flags_extracted = false;
	free_registr_list.clear();
	for (size_t i = index; i < count(); i++) {
		IntelCommand* command = item(i);

		bool is_end;
		if (command->GetCommandInfo(command_info_list)) {
			if (!free_flags_extracted) {
				if (command_info_list.change_flags()) {
					free_flags = command_info_list.change_flags();
					free_flags_extracted = true;
				}
				if (command_info_list.need_flags()) {
					free_flags &= ~command_info_list.need_flags();
					free_flags_extracted = true;
				}
			}

			for (size_t j = 0; j < command_info_list.count(); j++) {
				CommandInfo* command_info = command_info_list.item(j);
				if ((command_info->operand_type() == otRegistr || command_info->operand_type() == otHiPartRegistr) && command_info->value() != regESP && command_info->value() != regEIP) {
					OperandSize reg_size = command_info->size();
					if (command_info->operand_type() == otHiPartRegistr)
						reg_size = (reg_size == osByte) ? osWord : osQWord;
					uint8_t reg = command_info->value();

					if (command_info->type() == atRead) {
						used_registr_list.Add(atRead, reg, otRegistr, reg_size);
					}
					else if (!used_registr_list.GetInfo(atRead, otRegistr, reg) && (command_info->operand_type() != otHiPartRegistr || free_registr_list.GetInfo(atWrite, otRegistr, reg))) {
						free_registr_list.Add(atWrite, reg, otRegistr, reg_size);
					}
				}
			}
			is_end = command_info_list.GetInfo(atWrite, otBaseRegistr, regEIP) != NULL;
		}
		else {
			is_end = true;
		}

		if (is_end)
			break;
	}
	free_registr_list.set_change_flags(free_flags);
}

void IntelFunction::Mutate(const CompileContext& ctx, bool for_virtualization)
{
#define osRandom (OperandSize)0x80
#define osRandomStartWord (OperandSize)0x81

	int index = 0;
	enum {
		regFree = 0xf,
		flRandom = 0xff
	};

	size_t i, j, insert_count;
	IntelCommand* command, * new_command;

	std::vector<IntelCommand*> template_command_list;
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmMov, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otRegistr, osRandom)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmMov, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otValue, osRandom)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmMovsx, IntelOperand(otRegistr, osWord, regFree), IntelOperand(otRegistr, osByte)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmMovsx, IntelOperand(otRegistr, osDWord, regFree), IntelOperand(otRegistr, osWord)));
	if (cpu_address_size() == osQWord) {
		template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmMovsx, IntelOperand(otRegistr, osQWord, regFree), IntelOperand(otRegistr, osWord)));
		template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmMovsxd, IntelOperand(otRegistr, osQWord, regFree), IntelOperand(otRegistr, osDWord)));
	}
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmMovzx, IntelOperand(otRegistr, osWord, regFree), IntelOperand(otRegistr, osByte)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmMovzx, IntelOperand(otRegistr, osDWord, regFree), IntelOperand(otRegistr, osWord)));
	if (cpu_address_size() == osQWord)
		template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmMovzx, IntelOperand(otRegistr, osQWord, regFree), IntelOperand(otRegistr, osWord)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmNot, IntelOperand(otRegistr, osRandom, regFree)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmNeg, IntelOperand(otRegistr, osRandom, regFree)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmInc, IntelOperand(otRegistr, osRandom, regFree)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmDec, IntelOperand(otRegistr, osRandom, regFree)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmCmp, IntelOperand(otRegistr, osRandom), IntelOperand(otRegistr, osRandom)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmCmp, IntelOperand(otRegistr, osRandom), IntelOperand(otValue, osRandom)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmTest, IntelOperand(otRegistr, osRandom), IntelOperand(otRegistr, osRandom)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmTest, IntelOperand(otRegistr, osRandom), IntelOperand(otValue, osRandom)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmAnd, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otRegistr, osRandom)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmAnd, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otValue, osRandom)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmOr, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otRegistr, osRandom)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmOr, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otValue, osRandom)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmXor, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otRegistr, osRandom)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmXor, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otValue, osRandom)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmAdd, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otRegistr, osRandom)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmAdd, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otValue, osRandom)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmAdc, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otRegistr, osRandom)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmAdc, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otValue, osRandom)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmSub, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otRegistr, osRandom)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmSub, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otValue, osRandom)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmShl, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otRegistr, osByte, regECX)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmShl, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otValue, osByte)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmShr, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otRegistr, osByte, regECX)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmShr, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otValue, osByte)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmSal, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otRegistr, osByte, regECX)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmSal, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otValue, osByte)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmSar, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otRegistr, osByte, regECX)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmSar, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otValue, osByte)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmRol, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otRegistr, osByte, regECX)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmRol, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otValue, osByte)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmRor, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otRegistr, osByte, regECX)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmRor, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otValue, osByte)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmShrd, IntelOperand(otRegistr, osRandomStartWord, regFree), IntelOperand(otRegistr, osRandomStartWord), IntelOperand(otRegistr, osByte, regECX)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmShrd, IntelOperand(otRegistr, osRandomStartWord, regFree), IntelOperand(otRegistr, osRandomStartWord), IntelOperand(otValue, osByte)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmShld, IntelOperand(otRegistr, osRandomStartWord, regFree), IntelOperand(otRegistr, osRandomStartWord), IntelOperand(otRegistr, osByte, regECX)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmShld, IntelOperand(otRegistr, osRandomStartWord, regFree), IntelOperand(otRegistr, osRandomStartWord), IntelOperand(otValue, osByte)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmBt, IntelOperand(otRegistr, osRandomStartWord, regFree), IntelOperand(otRegistr, osRandomStartWord)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmBt, IntelOperand(otRegistr, osRandomStartWord, regFree), IntelOperand(otValue, osByte)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmBtc, IntelOperand(otRegistr, osRandomStartWord, regFree), IntelOperand(otRegistr, osRandomStartWord)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmBtc, IntelOperand(otRegistr, osRandomStartWord, regFree), IntelOperand(otValue, osByte)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmBtr, IntelOperand(otRegistr, osRandomStartWord, regFree), IntelOperand(otRegistr, osRandomStartWord)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmBtr, IntelOperand(otRegistr, osRandomStartWord, regFree), IntelOperand(otValue, osByte)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmBts, IntelOperand(otRegistr, osRandomStartWord, regFree), IntelOperand(otRegistr, osRandomStartWord)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmBts, IntelOperand(otRegistr, osRandomStartWord, regFree), IntelOperand(otRegistr, osRandomStartWord)));

	command = new IntelCommand(this, cpu_address_size(), cmSetXX, IntelOperand(otRegistr, osByte, regFree));
	command->set_flags(flRandom);
	template_command_list.push_back(command);

	command = new IntelCommand(this, cpu_address_size(), cmCmov, IntelOperand(otRegistr, osRandomStartWord, regFree), IntelOperand(otRegistr, osRandomStartWord));
	command->set_flags(flRandom);
	template_command_list.push_back(command);

	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmClc));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmStc));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmCmc));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmCbw));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmCwde));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmCwd));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmCdq));
	if (cpu_address_size() == osQWord) {
		template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmCdqe));
		template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmCqo));
	}
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmLahf));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmBswap, IntelOperand(otRegistr, osRandomStartWord, regFree)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmXchg, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otRegistr, osRandom, regFree)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmXadd, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otRegistr, osRandom, regFree)));
	template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmJmp, IntelOperand(otValue, cpu_address_size())));

	// FIXME
	/*
	command = new IntelCommand(this, cpu_address_size(), cmJmpWithFlag, IntelOperand(otValue, cpu_address_size()));
	command->set_flags(flRandom);
	template_command_list.push_back(command);
	*/

	if (for_virtualization) {
		/*
		template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmJCXZ, IntelOperand(otValue, cpu_address_size())));
		template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmLoop, IntelOperand(otValue, cpu_address_size())));
		template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmLoope, IntelOperand(otValue, cpu_address_size())));
		template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmLoopne, IntelOperand(otValue, cpu_address_size())));
		*/
	}
	else {
		template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmSbb, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otRegistr, osRandom)));
		template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmSbb, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otValue, osRandom)));
		template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmRcl, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otRegistr, osByte, regECX)));
		template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmRcl, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otValue, osByte)));
		template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmRcr, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otRegistr, osByte, regECX)));
		template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmRcr, IntelOperand(otRegistr, osRandom, regFree), IntelOperand(otValue, osByte)));
		template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmBsr, IntelOperand(otRegistr, osRandomStartWord, regFree), IntelOperand(otRegistr, osRandomStartWord)));
		template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmBsf, IntelOperand(otRegistr, osRandomStartWord, regFree), IntelOperand(otRegistr, osRandomStartWord)));
		template_command_list.push_back(new IntelCommand(this, cpu_address_size(), cmRdtsc));
	}

	size_t link_count = link_list()->count();

	for (i = 0; i < count(); i++) {
		command = item(i);

		switch (command->type()) {
		case cmJmp:
		case cmJmpWithFlag:
			if (command->dump_size() < 5)
				command->CompileToNative();
			break;
		case cmJCXZ:
		case cmLoop:
		case cmLoope:
		case cmLoopne:
			if (!for_virtualization) {
				uint64_t next_address = command->next_address();
				uint64_t to_address = command->link()->to_address();
				AddressRange* address_range = command->address_range();

				new_command = new IntelCommand(this, cpu_address_size(), cmJmp, IntelOperand(otValue, cpu_address_size(), 0, 0));
				new_command->include_option(roNoProgress);
				new_command->AddLink(0, ltJmp, command);
				new_command->CompileToNative();
				new_command->set_address_range(address_range);
				InsertObject(i++, new_command);

				CommandBlock* block = AddBlock(i++, true);
				block->set_end_index(block->start_index() + 2);
				command->set_block(block);

				new_command = new IntelCommand(this, cpu_address_size(), cmJmp, IntelOperand(otValue, cpu_address_size(), 0, next_address));
				new_command->include_option(roNoProgress);
				new_command->AddLink(0, ltJmp, item(i));
				new_command->CompileToNative();
				new_command->set_address_range(address_range);
				new_command->set_block(block);
				InsertObject(i++, new_command);

				new_command = new IntelCommand(this, cpu_address_size(), cmJmp, IntelOperand(otValue, cpu_address_size(), 0, to_address));
				new_command->include_option(roNoProgress);
				new_command->AddLink(0, ltJmp, to_address);
				new_command->CompileToNative();
				new_command->set_address_range(address_range);
				new_command->set_block(block);
				InsertObject(i++, new_command);
				if (command->link()) {
					if (command->link()->to_command()) {
						new_command->link()->set_to_command(command->link()->to_command());
						command->link()->set_to_command(new_command);
					}
				}
			}
			break;
		case cmCall:
			if ((command->options() & roFar) == 0 && command->operand(0).type == otValue && command->operand(0).value == command->next_address()) {
				if (cpu_address_size() == osDWord) {
					command->Init(cmPush, IntelOperand(otValue, cpu_address_size(), 0, command->next_address(), NEED_FIXUP));
					command->CompileToNative();
					if (command->link()) {
						delete command->link();
						link_count--;
					}
				}
				else {
					uint64_t next_address = command->next_address();
					AddressRange* address_range = command->address_range();

					command->Init(cmPush, IntelOperand(otRegistr, cpu_address_size(), regEAX));
					command->CompileToNative();
					if (command->link()) {
						delete command->link();
						link_count--;
					}

					command = new IntelCommand(this, cpu_address_size(), cmLea, IntelOperand(otRegistr, cpu_address_size(), regEAX), IntelOperand(otMemory | otValue, cpu_address_size(), 0, next_address, LARGE_VALUE));
					command->include_option(roNoProgress);
					command->CompileToNative();
					command->set_address_range(address_range);
					InsertObject(i++, command);

					command = new IntelCommand(this, cpu_address_size(), cmXchg, IntelOperand(otMemory | otRegistr, cpu_address_size(), regESP), IntelOperand(otRegistr, cpu_address_size(), regEAX));
					command->include_option(roNoProgress);
					command->CompileToNative();
					command->set_address_range(address_range);
					InsertObject(i++, command);
				}
			}
			break;
		case cmDC:
			command->CompileToNative();
			break;
		}
	}

	IntelCommandInfoList command_info_list(cpu_address_size());
	CommandInfoList free_registr_list;
	std::vector<IntelCommand*> garbage_command_list;
	insert_count = 0;

	std::list<ICommand*> new_command_list;
	for (i = 0; i < count(); i++) {
		command = item(i);
		new_command_list.push_back(command);

		if ((command->options() & roNoProgress) == 0)
			ctx.file->StepProgress();

		if (is_breaked_address(command->address()))
			continue;

		AddressRange* address_range = command->address_range();
		uint32_t src_options = command->options();

		if (command->block()) {
			CommandBlock* block = command->block();
			for (j = block->start_index() + 1; j <= block->end_index(); j++) {
				new_command_list.push_back(item(j));
			}
			i = block->end_index();
			if (insert_count) {
				block->set_start_index(block->start_index() + insert_count);
				block->set_end_index(block->end_index() + insert_count);
			}
			ctx.file->StepProgress(block->end_index() - block->start_index());
			continue;
		}
		else if ((command->options() & roNeedCompile) == 0)
			continue;

		bool is_end;
		if (command->GetCommandInfo(command_info_list)) {
			GetFreeRegisters(i + 1, free_registr_list);
			// mutate command
			switch (command->type()) {
			case cmXor:
				if (command->operand(0).type == otRegistr && command->operand(1).type == otRegistr && command->operand(0).registr == command->operand(1).registr && (rand() & 1)) {
					// xor reg, reg -> sub reg, reg
					command->Init(cmSub, command->operand(0), command->operand(1));
					command->CompileToNative();
				}
				break;

			case cmCall:
				if ((command->options() & roFar) == 0 && (rand() & 1)) {
				}
				break;

			case cmAdd:
				if (command->operand(0).type == otRegistr && command->operand(0).size == cpu_address_size()
					&& ((command->operand(1).type == otRegistr && command->operand(1).registr != regESP) || (command->operand(1).type == otValue && cpu_address_size() != osQWord))
					&& (rand() & 1)) {
					if ((command_info_list.change_flags() & free_registr_list.change_flags()) == command_info_list.change_flags()) {
						// add reg, xxxx -> lea reg, [reg + xxxx]
						IntelOperand second_operand = command->operand(1);
						second_operand.type |= otMemory;
						if ((second_operand.type & otValue) && (command->operand(0).registr != regESP)) {
							second_operand.type |= otRegistr;
							second_operand.registr = command->operand(0).registr;
						}
						else {
							second_operand.type |= otBaseRegistr;
							second_operand.base_registr = command->operand(0).registr;
							if ((second_operand.base_registr & 7) == regEBP) {
								second_operand.type |= otValue;
								second_operand.value_size = osByte;
								second_operand.value = 0;
							}
						}

						command->Init(cmLea, command->operand(0), second_operand);
						command->CompileToNative();
					}
				}
				break;

			case cmSub:
				if (command->operand(0).type == otRegistr && command->operand(0).size == cpu_address_size()
					&& (command->operand(1).type == otValue && cpu_address_size() != osQWord)
					&& (rand() & 1)) {
					if ((command_info_list.change_flags() & free_registr_list.change_flags()) == command_info_list.change_flags()) {
						// sub reg, xxxx -> lea reg, [reg - xxxx]
						IntelOperand second_operand = command->operand(1);
						second_operand.type |= otMemory;
						if (command->operand(0).registr != regESP) {
							second_operand.type |= otRegistr;
							second_operand.registr = command->operand(0).registr;
						}
						else {
							second_operand.type |= otBaseRegistr;
							second_operand.base_registr = command->operand(0).registr;
						}
						second_operand.value = 0 - second_operand.value;

						command->Init(cmLea, command->operand(0), second_operand);
						command->CompileToNative();
					}
				}
				break;

			case cmJmp:
				if (!for_virtualization && (command->options() & roFar) == 0 && command->operand(0).type != otValue && (rand() & 1)) {
					// jmp xxxx -> push xxxx, ret
					command->Init(cmPush, command->operand(0));
					command->CompileToNative();

					command = new IntelCommand(this, cpu_address_size(), cmRet);
					command->include_option(roNoProgress);
					command->CompileToNative();
					command->set_address_range(address_range);

					new_command_list.push_back(command);
					insert_count++;
				}
				break;
			}
			is_end = command_info_list.GetInfo(atWrite, otBaseRegistr, regEIP) != NULL;
		}
		else {
			is_end = true;
		}

		if (!is_end) {
			// add garbage code
			garbage_command_list.clear();
			for (j = 0; j < template_command_list.size(); j++) {
				command = template_command_list[j];
				if (!command->GetCommandInfo(command_info_list))
					continue;

				bool is_ok = true;
				for (size_t k = 0; k < command_info_list.count() && is_ok; k++) {
					CommandInfo* command_info = command_info_list.item(k);
					if (command_info->type() == atWrite && (command_info->operand_type() == otRegistr || command_info->operand_type() == otHiPartRegistr)) {
						if (command_info->value() == regFree) {
							if (!free_registr_list.count())
								is_ok = false;
						}
						else if (command_info->value() == regEFX) {
							if ((command_info_list.change_flags() & free_registr_list.change_flags()) != command_info_list.change_flags())
								is_ok = false;
						}
						else {
							OperandSize registr_size;
							if (command_info->operand_type() == otHiPartRegistr) {
								switch (command_info->size()) {
								case osByte:
									registr_size = osWord;
									break;
								case osWord:
									registr_size = osDWord;
									break;
								default:
									registr_size = osQWord;
									break;
								}
							}
							else {
								registr_size = command_info->size();
							}

							CommandInfo* free_registr = free_registr_list.GetInfo(atWrite, otRegistr, command_info->value());
							if (!free_registr || free_registr->size() < registr_size)
								is_ok = false;
						}
					}
				}
				if (is_ok)
					garbage_command_list.push_back(command);
			}

			size_t c = rand() % 4;
			for (size_t m = 0; m < c && !garbage_command_list.empty(); m++) {
				j = rand() % garbage_command_list.size();
				command = garbage_command_list[j];
				garbage_command_list.erase(garbage_command_list.begin() + j);

				IntelOperand operand[3];
				uint8_t registr[3];
				OperandSize min_size = osByte;
				OperandSize max_size = cpu_address_size();
				bool is_ok = true;
				uint8_t max_registr = 0;
				for (size_t k = 0; k < _countof(operand) && is_ok; k++) {
					IntelOperand tmp = command->operand(k);
					if (tmp.type == otNone)
						continue;

					if (tmp.size == osRandomStartWord && min_size < osWord)
						min_size = osWord;

					if (tmp.type == otRegistr) {
						if (tmp.registr == regFree) {
							if (free_registr_list.count()) {
								CommandInfo* free_registr = free_registr_list.item(rand() % free_registr_list.count());
								registr[k] = free_registr->value();
								if (max_size > free_registr->size())
									max_size = free_registr->size();
							}
							else {
								is_ok = false;
								break;
							}
						}
						else if (tmp.registr == 0) {
							registr[k] = rand() % ((cpu_address_size() == osDWord) ? 8 : 16);
						}
						else {
							registr[k] = tmp.registr;
						}
						if (max_registr < registr[k])
							max_registr = registr[k];
						if (cpu_address_size() == osDWord && registr[k] > 3 && min_size < osWord)
							min_size = osWord;
						if (tmp.size & osRandom) {
							if (min_size > max_size)
								is_ok = false;
						}
						else if (tmp.size < min_size || tmp.size > max_size)
							is_ok = false;
					}
				}

				if (is_ok) {
					OperandSize random_size = min_size;
					for (int size = min_size; size <= max_size; size++) {
						random_size = static_cast<OperandSize>(size);
						if (rand() & 1)
							break;
					}

					for (size_t k = 0; k < _countof(operand) && is_ok; k++) {
						IntelOperand tmp = command->operand(k);
						if (tmp.size & osRandom)
							tmp.size = random_size;
						if (tmp.type == otRegistr) {
							if (tmp.size == osByte && (tmp.registr == regFree || tmp.registr == 0) && max_size > osByte && max_registr < 4 && (rand() & 1))
								tmp.type = otHiPartRegistr;
							tmp.registr = registr[k];
						}
						else if (tmp.type == otValue) {
							switch (tmp.size) {
							case osByte:
								tmp.value = ByteToInt64(rand32() & 0xff);
								tmp.value_size = osByte;
								break;
							case osWord:
								tmp.value = WordToInt64(rand32() & 0xffff);
								tmp.value_size = osWord;
								break;
							default:
								tmp.value = DWordToInt64(rand32());
								tmp.value_size = osDWord;
								break;
							}
						}
						operand[k] = tmp;
					}
					uint16_t flags = command->flags();
					uint32_t options = command->options();
					command = new IntelCommand(this, cpu_address_size(), static_cast<IntelCommandType>(command->type()), operand[0], operand[1], operand[2]);
					if (flags) {
						if (flags == flRandom) {
							switch (rand() % 8) {
							case 0: flags = fl_O; break;
							case 1: flags = fl_C; break;
							case 2: flags = fl_Z; break;
							case 3: flags = fl_C | fl_Z; break;
							case 4: flags = fl_S; break;
							case 5: flags = fl_P; break;
							case 6: flags = fl_S | fl_O; break;
							default: flags = fl_Z | fl_S | fl_O; break;
							}
							if (rand() & 1)
								options |= roInverseFlag;
						}
						command->set_flags(flags);
						if (options & roInverseFlag)
							command->include_option(roInverseFlag);
					}
					command->include_option(roNoProgress);
					if (src_options & roNeedCRC)
						command->include_option(roNeedCRC);
					command->CompileToNative();
					command->set_address_range(address_range);
					new_command_list.push_back(command);
					insert_count++;

					switch (command->type()) {
					case cmJmpWithFlag:
						// FIXME
						/*
						command->AddLink(0, ltJmpWithFlag, item(i + 1));
						*/
						break;
					case cmJmp:
						command->AddLink(0, ltJmp, item(i + 1));
						break;
					}
				}
			}
		}
	}

	for (i = link_count; i < link_list()->count(); i++) {
		link_list()->item(i)->from_command()->PrepareLink(ctx);
	}

	for (i = 0; i < template_command_list.size(); i++) {
		delete template_command_list[i];
	}

	assign(new_command_list);
}

void IntelFunction::CompileToNative(const CompileContext& ctx)
{
	size_t i, j;
	size_t c = link_list()->count();
	for (i = 0; i < c; i++) {
		CommandLink* link = link_list()->item(i);
		IntelCommand* to_command = reinterpret_cast<IntelCommand*>(link->to_command());
		if (!to_command)
			continue;

		switch (link->type()) {
		case ltDualSEHBlock:
		{
			CommandBlock* block = AddBlock(count(), true);
			size_t k = IndexOf(to_command);
			IntelCommand* next_command = item(k + 1);
			IntelCommand* src_command = to_command;
			IntelCommand* dst_command = src_command->Clone(this);
			AddObject(dst_command);
			CommandLink* src_link = src_command->link();
			if (src_link) {
				CommandLink* dst_link = src_link->Clone(link_list());
				dst_link->set_from_command(dst_command);
				dst_link->set_to_command(src_link->to_command());
				link_list()->AddObject(dst_link);
			}
			IntelCommand* command = new IntelCommand(this, cpu_address_size(), cmJmp, IntelOperand(otValue, cpu_address_size(), 0, to_command->next_address()));
			AddObject(command);
			command->AddLink(0, ltJmp, next_command);

			for (size_t j = block->start_index(); j < count(); j++) {
				IntelCommand* command = item(j);
				command->set_block(block);
				command->CompileToNative();
			}
			block->set_end_index(count() - 1);

			link->set_to_command(item(block->start_index()));
		}
		break;
		case ltFilterSEHBlock:
		{
			CommandBlock* block = AddBlock(count(), true);
			size_t k = IndexOf(to_command);
			IntelCommand* next_command = item(k + 1);
			size_t n = static_cast<size_t>(next_command->operand(0).value * 2 + 2);
			for (j = 0; j < n; j++) {
				IntelCommand* src_command = item(k + j);
				IntelCommand* dst_command = src_command->Clone(this);
				AddObject(dst_command);
				CommandLink* src_link = src_command->link();
				if (src_link) {
					CommandLink* dst_link = src_link->Clone(link_list());
					dst_link->set_from_command(dst_command);
					dst_link->set_to_command(src_link->to_command());
					link_list()->AddObject(dst_link);
				}
			}

			for (size_t j = block->start_index(); j < count(); j++) {
				IntelCommand* command = item(j);
				command->set_block(block);
				command->CompileToNative();
			}
			block->set_end_index(count() - 1);

			link->set_to_command(item(block->start_index()));
		}
		break;
		}
	}

	Mutate(ctx, false);

	CreateBlocks();
	for (i = 0; i < ext_command_list()->count(); i++) {
		ExtCommand* ext_command = ext_command_list()->item(i);
		if (!ext_command->command() || is_breaked_address(ext_command->address()))
			continue;

		CommandBlock* block = AddBlock(count(), true);
		block->set_address(ext_command->address());

		IntelCommand* command = AddCommand(ext_command->use_call() ? cmCall : cmJmp, IntelOperand(otValue, cpu_address_size()));
		command->AddLink(0, ltJmp, ext_command->command());
		command->CompileToNative();
		command->set_block(block);
	}
}

IntelCommand* IntelFunction::AddGate(ICommand* to_command, AddressRange* address_range)
{
	size_t i;

	IntelVirtualMachine* virtual_machine = reinterpret_cast<IntelVirtualMachine*>(to_command->block()->virtual_machine());
	size_t old_count = count();

	IntelCommand* command = AddCommand(cmPush, IntelOperand(otValue, cpu_address_size()));
	CommandLink* link = command->AddLink(0, ltJmp, to_command);
	link->set_cryptor(virtual_machine->entry_cryptor());
	if (to_command && to_command->seh_handler())
		command->set_seh_handler(NEED_SEH_HANDLER);

	command = AddCommand(cmCall, IntelOperand(otValue, cpu_address_size()));
	command->include_option(roUseAsJmp);
	command->AddLink(0, ltCall, virtual_machine->entry_command());
#ifndef DEMO
	if (false)
		if (virtual_machine->processor()->cpu_address_size() == cpu_address_size()) {
			IntelObfuscation engine;
			engine.Compile(this, old_count);
		}
#endif

	CommandBlock* cur_block = NULL;
	for (i = old_count; i < count(); i++) {
		if (!cur_block)
			cur_block = AddBlock(i, true);

		command = item(i);
		command->CompileToNative();
		command->set_block(cur_block);

		cur_block->set_end_index(i);
		if (command->is_end())
			cur_block = NULL;
	}

	IntelCommand* res = item(old_count);
	if (address_range) {
		cur_block = res->block();
		for (i = cur_block->start_index(); i <= cur_block->start_index(); i++) {
			command = item(i);
			command->set_address_range(address_range);
		}
	}

	return res;
}

IntelCommand* IntelFunction::AddShortGate(ICommand* to_command, AddressRange* address_range)
{
	CommandBlock* cur_block = AddBlock(count(), true);

	IntelCommand* res = AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size()));
	res->AddLink(0, ltJmp, to_command);
	if (to_command && to_command->seh_handler())
		res->set_seh_handler(NEED_SEH_HANDLER);

	cur_block->set_end_index(count() - 1);

	for (size_t i = cur_block->start_index(); i <= cur_block->end_index(); i++) {
		IntelCommand* command = item(i);
		command->CompileToNative();
		command->set_block(cur_block);
		if (address_range)
			command->set_address_range(address_range);
	}

	return res;
}

void IntelFunction::CompileToVM(const CompileContext& ctx)
{
	size_t i, j, c;
	IntelCommand* command;

	// create internal links
	c = link_list()->count();
	for (i = 0; i < count(); i++) {
		command = item(i);
		if (command->block() || (command->options() & roNeedCompile) == 0)
			continue;

		if (command->is_data()) {
			if (command->link() && command->link()->type() == ltCase) {
				// create blocks for CASEs
				CommandBlock* cur_block = NULL;
				for (j = i; j < count(); j++) {
					command = item(j);
					if (command->link() && command->link()->type() == ltCase) {
						if (command->block() || (command->options() & roNeedCompile) == 0 || is_breaked_address(command->address())) {
							cur_block = NULL;
							continue;
						}

						if (!cur_block || (command->options() & roCreateNewBlock)) {
							cur_block = AddBlock(j);
							cur_block->set_virtual_machine(virtual_machine(ctx.file->virtual_machine_list(), command));
						}
						cur_block->set_end_index(j);

						command->set_block(cur_block);

						command->CompileToVM(ctx);
					}
					else {
						break;
					}
				}
			}
			continue;
		}

		if ((command->options() & roLockPrefix) && (command->options() & roNoNative) == 0) {
			command->AddLink(-1, ltNative);
			continue;
		}
		else {
			bool relocation_found = false;
			for (j = 0; j < 3; j++) {
				IntelOperand operand = command->operand(j);
				if (operand.type == otNone)
					break;

				if (operand.relocation) {
					relocation_found = true;
					break;
				}
			}
			if (relocation_found) {
				command->AddLink(-1, ltNative);
				continue;
			}
		}

		switch (command->type()) {
		case cmJmp: case cmCall:
			if (command->options() & roFar)
				command->AddLink(-1, ltNative);
			break;
		case cmLods: case cmMovs: case cmScas: case cmCmps: case cmStos:
			if (command->preffix_command() == cmRep || command->preffix_command() == cmRepe || command->preffix_command() == cmRepne)
				command->AddLink(-1, ltNative);
			break;
		case cmCmov:
			command->AddLink(-1, ltJmpWithFlagNSNA);
			break;
		case cmXchg:
			if (((command->operand(0).type | command->operand(1).type) & otMemory) && (command->options() & roNoNative) == 0)
				command->AddLink(-1, ltNative);
			break;
		case cmFadd: case cmFsub: case cmFisub: case cmFsubr: case cmFdiv: case cmFmul:
		case cmFcomp: case cmFild: case cmFld: case cmFstp: case cmFst:
			if (command->operand(0).type == otFPURegistr)
				command->AddLink(-1, ltNative);
			break;
		case cmPush: case cmPop: case cmMov: case cmMovsx: case cmMovsxd: case cmMovzx:
		case cmJmpWithFlag: case cmJCXZ: case cmLoop: case cmLoope: case cmLoopne:
		case cmRet: case cmIret:
		case cmLea: case cmNop: case cmFnop:
		case cmNot: case cmNeg: case cmAdd: case cmAdc: case cmXadd:
		case cmSub: case cmCmp: case cmInc: case cmDec: case cmXlat: case cmSetXX:
		case cmAnd: case cmXor: case cmTest: case cmOr:
		case cmShld: case cmShrd:
		case cmRol: case cmRor: case cmRcl: case cmRcr:
		case cmShl: case cmSal: case cmShr: case cmSar:
		case cmCbw: case cmCwde: case cmCwd: case cmCdq: case cmCdqe: case cmCqo:
		case cmPushf: case cmPopf: case cmPusha: case cmPopa:
		case cmLahf: case cmSahf:
		case cmBt: case cmBtr: case cmBts: case cmBtc:
		case cmClc: case cmStc: case cmCmc: case cmCld: case cmStd:
		case cmBswap: case cmLeave:
		case cmImul: case cmMul: case cmDiv: case cmIdiv:
		case cmLes: case cmLds: case cmLfs: case cmLgs:
		case cmFstsw: case cmFldcw: case cmFstcw:
		case cmF2xm1: case cmFabs: case cmFclex: case cmFcos: case cmFdecstp: case cmFincstp:
		case cmFinit: case cmFldln2: case cmFldlg2: case cmFprem: case cmFprem1: case cmFptan:
		case cmFrndint: case cmFsin: case cmFtst: case cmFyl2x: case cmFpatan: case cmFldz: case cmFld1: case cmFldpi:
		case cmWait: case cmFchs: case cmFsqrt:
		case cmFistp: case cmFist: case cmRdtsc:
		case cmCrc:
			// do nothing
			break;

		default:
			if ((command->options() & roNoNative) == 0)
				command->AddLink(-1, ltNative);
			break;
		}
	}
	for (i = c; i < link_list()->count(); i++) {
		link_list()->item(i)->from_command()->PrepareLink(ctx);
	}

	// optimize flags 
	IntelCommand* flag_command = NULL;
	uint64_t flags = 0;
	IntelCommandInfoList command_info(cpu_address_size());
	for (i = 0; i < count(); i++) {
		command = item(i);

		if ((command->link() && command->link()->type() == ltNative) || !command->GetCommandInfo(command_info) || command_info.GetInfo(atWrite, otBaseRegistr, regEIP)) {
			flag_command = NULL;
			continue;
		}

		if (!flag_command) {
			if (command_info.change_flags()) {
				flag_command = command;
				flags = command_info.change_flags();
			}
		}
		else {
			if (command_info.need_flags()) {
				if ((command_info.need_flags() & flags) != 0) {
					flag_command = NULL;
					continue;
				}
			}
			if (command_info.change_flags()) {
				if ((command_info.change_flags() & flags) == flags) {
					flag_command->include_option(roNoSaveFlags);
					flag_command = command;
					flags = command_info.change_flags();
				}
			}
		}
	}

	// create VM blocks
	CommandBlock* cur_block = NULL;
	uint64_t cur_eip = (uint64_t)-1;
	for (i = 0; i < count(); i++) {
		command = item(i);
		if ((command->options() & roNoProgress) == 0)
			ctx.file->StepProgress();

		if (command->block() || (command->options() & roNeedCompile) == 0 || is_breaked_address(command->address())) {
			cur_block = NULL;
			continue;
		}

		bool is_data = command->is_data() && (!command->link() || command->link()->type() != ltNative);
		bool new_block = (!cur_block || (command->options() & roCreateNewBlock) || item(cur_block->end_index())->is_data() != is_data);
		if (new_block) {
			cur_block = AddBlock(i, is_data);
			if (!is_data)
				cur_block->set_virtual_machine(virtual_machine(ctx.file->virtual_machine_list(), command));
		}

		cur_block->set_end_index(i);

		command->set_block(cur_block);
		if (command->seh_handler())
			command->seh_handler()->set_deleted(true);
		if (is_data) {
			cur_eip = (uint64_t)-1;
		}
		else {
			if (command->block()->virtual_machine()->backward_direction())
				command->include_section_option(rtBackwardDirection);
			if (new_block || (command->section_options() & (rtLinkedToInt | rtLinkedToExt))) {
				command->AddExtSection(ctx, NULL);
				cur_eip = (uint64_t)-1;
			}
			cur_eip = command->AddStoreEIPSection(ctx, cur_eip);
			if (command->section_options() & rtLinkedToExt)
				command->AddStoreExtRegistersSection(ctx);
		}
		if (command->options() & roNeedCompile) {
			if (is_data) {
				command->CompileToNative();
			}
			else {
				command->CompileToVM(ctx);
			}
		}

		if (!is_data) {
			if ((command->section_options() & rtEndSection) == 0 && i < count() - 1 && (item(i + 1)->section_options() & (rtLinkedToInt | rtLinkedToExt)))
				command->AddExtSection(ctx, item(i + 1));
		}

		if (command->section_options() & rtCloseSection)
			cur_block = NULL;
	}

	// create gates for external commands
	ExtCommandList* ext_list = ext_command_list();
	for (i = 0; i < ext_list->count(); i++) {
		ExtCommand* ext_command = ext_list->item(i);
		if (!ext_command->command() || is_breaked_address(ext_command->address()))
			continue;

		command = AddGate(ext_command->command(), ext_command->command()->address_range());

		if (ext_command->address()) {
			command = AddShortGate(command, NULL);
			command->block()->set_address(ext_command->address());
		}

		if (entry() == ext_command->command())
			set_entry(command);
	}
}

bool IntelFunction::Compile(const CompileContext& ctx)
{
	switch (compilation_type()) {
	case ctMutation: //bian yi
		CompileToNative(ctx);
		break;
	case ctVirtualization: //xu ni hua
		CompileToVM(ctx);
		break;
	case ctUltra://xu ni hua + bian yi
		Mutate(ctx, true);
		CompileToVM(ctx);
		break;
	default:
		return false;
	}

	return BaseFunction::Compile(ctx);
}

void IntelFunction::AfterCompile(const CompileContext& ctx)
{
	size_t i, j, c;
	IntelCommand* command, * from_command, * gate_command, * native_command;
	CommandBlock* block;
	CommandLink* link;

	if (compilation_type() == ctMutation) {
		for (i = 0; i < link_list()->count(); i++) {
			link = link_list()->item(i);
			if (!link->to_command())
				continue;

			from_command = reinterpret_cast<IntelCommand*>(link->from_command());
			if ((from_command->section_options() & rtLinkedFromOtherType) && !link->to_command()->is_data())
				link->set_to_command(AddGate(link->to_command(), NULL));

			switch (link->type()) {
			case ltMemSEHBlock: case ltExtSEHHandler: case ltVBMemSEHBlock:
				if (from_command->address()) {
					block = AddBlock(count(), true);
					command = from_command->Clone(this);
					AddObject(command);
					command->set_block(block);
					block->set_address(command->address());

					CommandLink* dst_link = command->AddLink(0, ltOffset, link->to_command());
					dst_link->set_sub_value(link->sub_value());
				}
				break;
			}
		}
	}
	else {
		// create native gates for links
		c = count();
		for (i = 0; i < c; i++) {
			from_command = item(i);
			link = from_command->link();
			if (!link)
				continue;

			IntelCommand* to_command = reinterpret_cast<IntelCommand*>(link->to_command());
			ICommand* next_command = link->next_command();
			IntelCommand* parent_command = reinterpret_cast<IntelCommand*>(link->parent_command());

			if (to_command && to_command->block() && (to_command->block()->type() & mtExecutable) == 0) {
				// to VM block
				switch (link->type()) {
				case ltGateOffset:
					link->set_to_command(AddGate(to_command, to_command->address_range()));
					break;
				case ltMemSEHBlock: case ltExtSEHHandler: case ltVBMemSEHBlock:
					if (to_command) {
						if (from_command->address()) {
							block = AddBlock(count(), true);
							native_command = from_command->Clone(this);
							AddObject(native_command);
							native_command->set_block(block);
							block->set_address(native_command->address());
						}
						else {
							native_command = NULL;
						}

						gate_command = AddGate(to_command, to_command->address_range());

						if (native_command) {
							CommandLink* dst_link = native_command->AddLink(0, ltOffset, gate_command);
							dst_link->set_sub_value(link->sub_value());
						}

						link->set_to_command(gate_command);
					}
					break;
				}
			}

			if (from_command->block() && (from_command->block()->type() & mtExecutable) == 0) {
				// from VM block
				switch (link->type()) {
				case ltSEHBlock: case ltFinallyBlock: case ltExtSEHBlock:
					if (to_command)
						link->AddGateCommand(AddGate(to_command, to_command->address_range()));
					break;

				case ltCall:
					if (next_command && (from_command->options() & roInternal) == 0) {
						if (from_command->address_range()) {
							Data data;
							data.PushByte(rand());
							command = AddCommand(data);
							command->set_address_range(from_command->address_range());
							gate_command = AddGate(next_command, next_command->address_range());
							command->set_block(gate_command->block());
							command->block()->set_start_index(command->block()->start_index() - 1);
						}
						else {
							gate_command = AddGate(next_command, next_command->address_range());
						}
					}
					else {
						gate_command = NULL;
					}

					link->AddGateCommand(gate_command);
					break;

				case ltNative:
					native_command = from_command->Clone(this);
					AddObject(native_command);

					if (next_command) {
						gate_command = AddGate(next_command, native_command->address_range());
					}
					else {
						gate_command = AddShortGate(NULL, native_command->address_range());
						gate_command->set_operand_value(0, from_command->address() + from_command->original_dump_size());
						gate_command->CompileToNative();
					}
					block = gate_command->block();
					block->set_start_index(block->start_index() - 1);
					native_command->set_block(block);

					link->AddGateCommand(native_command);
					break;

				case ltDualSEHBlock:
					if (to_command) {
						block = AddBlock(count(), true);
						gate_command = reinterpret_cast<IntelCommand*>(to_command->Clone(this));
						AddObject(gate_command);
						CommandLink* src_link = to_command->link();
						if (src_link) {
							CommandLink* dst_link = src_link->Clone(link_list());
							dst_link->set_from_command(gate_command);
							dst_link->set_to_command(src_link->to_command());
							link_list()->AddObject(dst_link);
						}
						command = new IntelCommand(this, cpu_address_size(), cmJmp, IntelOperand(otValue, cpu_address_size(), 0, link->to_address() + 5));
						AddObject(command);
						command->AddLink(0, ltJmp, next_command);
						block->set_end_index(count() - 1);

						if (gate_command->link()->to_command())
							gate_command->link()->set_to_command(AddGate(gate_command->link()->to_command(), gate_command->address_range()));

						if (command->link()->to_command())
							command->link()->set_to_command(AddGate(command->link()->to_command(), command->address_range()));

						for (j = block->start_index(); j <= block->end_index(); j++) {
							command = item(j);
							command->set_block(block);
							command->CompileToNative();
						}

						link->AddGateCommand(gate_command);
					}
					break;

				case ltFilterSEHBlock:
					if (to_command) {
						block = AddBlock(count(), true);
						size_t index = IndexOf(to_command);
						size_t n = 2 + static_cast<uint32_t>(reinterpret_cast<IntelCommand*>(link->parent_command())->operand(0).value) * 2;
						for (j = 0; j < n; j++) {
							native_command = item(index + j);
							command = native_command->Clone(this);
							AddObject(command);
							CommandLink* src_link = native_command->link();
							if (src_link) {
								CommandLink* dst_link = src_link->Clone(link_list());
								dst_link->set_from_command(command);
								dst_link->set_to_command(src_link->to_command());
								link_list()->AddObject(dst_link);
							}
							command->set_block(block);
						}
						block->set_end_index(count() - 1);
						for (j = block->start_index(); j <= block->end_index(); j++) {
							CommandLink* src_link = item(j)->link();
							if (!src_link || !src_link->to_command())
								continue;

							src_link->set_to_command(AddGate(src_link->to_command(), src_link->from_command()->address_range()));
						}
						gate_command = item(block->start_index());
						link->AddGateCommand(gate_command);
					}
					break;

				case ltCase:
					if (to_command) {
						block = AddBlock(count());
						block->set_virtual_machine(parent_command->block()->virtual_machine());

						command = AddCommand(cmJmp);
						command->AddLink(-1, ltNone);
						command->include_section_option(rtLinkedToInt);
						command->set_block(block);
						if (command->block()->virtual_machine()->backward_direction())
							command->include_section_option(rtBackwardDirection);

						command->AddBeginSection(ctx);
						if (from_command->section_options() & rtLinkedFrom) {
							command->AddVMCommand(ctx, cmPush, otValue, cpu_address_size(), 0, voLinkCommand | voFixup);
							command->AddEndSection(ctx, cmJmp, 0);
						}
						else {
							command->AddVMCommand(ctx, cmPush, otValue, cpu_address_size(), 0, voLinkCommand | voFixup);
							command->AddEndSection(ctx, cmRet);
						}
						link->AddGateCommand(command);
					}
					break;
				}
			}
		}
	}

	for (i = 0; i < count(); i++) {
		command = item(i);
		if (!command->block())
			continue;

		for (j = 0; j < 3; j++) {
			IntelOperand operand = command->operand(j);
			if (operand.type == otNone)
				break;

			IFixup* fixup = operand.fixup;
			if (fixup && fixup != NEED_FIXUP) {
				if (command->options() & roClearOriginalCode)
					fixup->set_deleted(true);
				if (command->block()->type() & mtExecutable) {
					if (command->block()->address()) {
						fixup->set_deleted(false);
					}
					else {
						fixup = fixup->Clone(ctx.file->fixup_list());
						ctx.file->fixup_list()->AddObject(fixup);
						fixup->set_deleted(false);
						command->set_operand_fixup(j, fixup);
					}
				}
				else {
					for (size_t k = 0; k < command->count(); k++) {
						IntelVMCommand* vm_command = command->item(k);
						if (vm_command->fixup()) {
							fixup = fixup->Clone(ctx.file->fixup_list());
							ctx.file->fixup_list()->AddObject(fixup);
							fixup->set_deleted(false);
							vm_command->set_fixup(fixup);
						}
					}
				}
			}
		}
	}

	if (function_info_list()->count()) {
		std::set<AddressRange*> range_list;

		for (i = 0; i < block_list()->count(); i++) {
			CommandBlock* block = block_list()->item(i);
			if ((block->type() & mtExecutable) == 0)
				continue;

			AddressRange* block_range = item(block->start_index())->address_range();
			if (block_range)
				range_list.insert(block_range);

			for (j = block->start_index(); j <= block->end_index(); j++) {
				AddressRange* range = item(j)->address_range();
				if (range && range != block_range)
					range_list.insert(range);
			}
		}

		for (i = 0; i < function_info_list()->count(); i++) {
			FunctionInfo* info = function_info_list()->item(i);
			for (size_t j = 0; j < info->count(); j++) {
				AddressRange* range = info->item(j);
				if (range_list.find(range) == range_list.end()) {
					Data data;
					data.PushByte(rand());

					CommandBlock* block = AddBlock(count(), true);
					ICommand* command = AddCommand(data);
					command->set_block(block);
					command->set_address_range(range);
				}
			}
		}
	}
}

void IntelFunction::CompileInfo(const CompileContext& ctx)
{
	BaseFunction::CompileInfo(ctx);

	size_t i;
	FunctionInfo* info;
	AddressRange* range;
	uint64_t base_value;
	IntelCommand* command;

	for (i = 0; i < range_list()->count(); i++) {
		range = range_list()->item(i);
		info = range->link_info();
		if (!info)
			continue;

		switch (info->base_type()) {
		case btImageBase:
			base_value = ctx.file->image_base();
			break;
		case btFunctionBegin:
			base_value = info->begin();
			break;
		default:
			base_value = info->base_value();
			break;
		}

		if (range->begin_entry()) {
			command = reinterpret_cast<IntelCommand*>(range->begin_entry());
			if (command->type() == cmDC) {
				AddressRange* prev = NULL;
				for (size_t j = 0; j < i; j++) {
					AddressRange* tmp = range_list()->item(j);
					if (tmp->link_info() == info && tmp->original_end() == range->original_begin() && tmp->begin_entry()) {
						prev = tmp;
						break;
					}
				}
				base_value = prev ? prev->begin() : info->begin();
			}
			command->set_operand_value(0, range->begin() - base_value);
			command->CompileToNative();
		}
		if (range->end_entry()) {
			command = reinterpret_cast<IntelCommand*>(range->end_entry());
			command->set_operand_value(0, range->end() - base_value);
			command->CompileToNative();
		}
		if (range->size_entry()) {
			command = reinterpret_cast<IntelCommand*>(range->size_entry());
			command->set_operand_value(0, range->end() - range->begin());
			if (command->type() == cmDB) {
				uint32_t size = static_cast<uint32_t>(command->operand(0).value);
				Data data;
				if (command->comment().value == "UWOP_EPILOG") {
					uint32_t offset = static_cast<uint8_t>(info->end() - range->begin());
					UNWIND_CODE unwind_code;
					unwind_code.FrameOffset = static_cast<uint16_t>(command->dump_value(0, osWord));
					if (unwind_code.OpInfo & 1) {
						unwind_code.CodeOffset = static_cast<uint8_t>(offset);
						data.PushWord(unwind_code.FrameOffset);
					}
					else {
						unwind_code.CodeOffset = static_cast<uint8_t>(size);
						data.PushWord(unwind_code.FrameOffset);
						unwind_code.CodeOffset = static_cast<uint8_t>(offset);
						unwind_code.OpInfo = static_cast<uint8_t>(offset >> 8);
						data.PushWord(unwind_code.FrameOffset);
					}
					command->set_dump(data.data(), data.size());
				}
			}
			else
				command->CompileToNative();
		}
	}
}

void IntelFunction::CompileLinks(const CompileContext& ctx)
{
	BaseFunction::CompileLinks(ctx);

	bool need_encrypt = (ctx.options.flags & cpEncryptBytecode) != 0;
	for (size_t i = 0; i < block_list()->count(); i++) {
		CommandBlock* block = block_list()->item(i);

		// skip native blocks
		if (block->type() & mtExecutable)
			continue;

		IntelVirtualMachine* virtual_machine = reinterpret_cast<IntelVirtualMachine*>(block->virtual_machine());
		virtual_machine->CompileBlock(*block, need_encrypt);
	}
}

void IntelFunction::AddWatermarkReference(uint64_t address, const std::string& value)
{
	IntelCommand* ref_command = GetCommandByAddress(address);
	if (!ref_command || value.empty())
		return;

	uint32_t key = rand32();
	uint16_t len = static_cast<uint16_t>(value.size());
	Data data;
	data.PushDWord(key);
	data.PushWord(len);
	for (size_t i = 0; i < value.size(); i++) {
		data.PushByte(value[i] ^ static_cast<uint8_t>(_rotl32(key, (int)i) + i));
	}
	IntelCommand* data_command = AddCommand(data);

	switch (ref_command->type()) {
	case cmLea:
	{
		IntelCommand* mem_command = AddCommand(cpu_address_size() == osDWord ? cmDD : cmDQ, IntelOperand(otValue, cpu_address_size(), 0, 0, NEED_FIXUP));
		mem_command->AddLink(0, ltOffset, data_command);
		mem_command->CompileToNative();

		ref_command->AddLink(1, ltOffset, mem_command);
	}
	break;
	case cmMov:
		ref_command->Init(cmLea, ref_command->operand(0), ref_command->operand(1));
		ref_command->AddLink(1, ltOffset, data_command);
		break;
	default:
		throw std::runtime_error("Unknown reference command");
	}
}

void IntelFunction::ReadFromBuffer(Buffer& buffer, IArchitecture& file)
{
	BaseFunction::ReadFromBuffer(buffer, file);

	size_t i, j, k;
	IntelCommand* command;
	bool syscall_found = false;

	for (i = 0; i < count(); i++) {
		command = item(i);
		if (command->type() == cmCpuid || command->type() == cmSbb)
			command->include_option(roNoNative);
		else if (command->type() == cmPopf) {
			Data data;
			command->CompileToNative();
			for (k = 0; k < command->dump_size(); k++) {
				data.PushByte(command->dump(k));
			}
			command->Init(cmNop);

			for (j = i; j < count(); j++) {
				command = item(j);
				if (command->type() == cmCpuid || command->type() == cmRdtsc) {
					command->CompileToNative();
					for (k = 0; k < command->dump_size(); k++) {
						data.PushByte(command->dump(k));
					}
					data.PushByte(0x90);
					command->Init(data);
					command->AddLink(-1, ltNative);
					break;
				}
			}
		}
		else if (command->operand(1).type == otValue && static_cast<uint32_t>(command->operand(1).value) == FACE_SYSCALL) {
			command->set_operand_value(1, 0);
			command->CompileToNative();
			IntelOperand operand = command->operand(0);
			IntelCommandInfoList command_info_list(cpu_address_size());
			size_t cur_index = i + 1;
			std::vector<size_t> stack;

			while (cur_index < count()) {
				command = item(cur_index);
				bool is_end = command->is_end();
				if (command->type() == cmMov) {
					if (operand.type == otRegistr && command->operand(1) == operand) {
						operand = command->operand(0);
						cur_index++;
						continue;
					}
				}
				else if (command->type() == cmCall) {
					if (command->operand(0) == operand) {
						command->Init(cmSyscall, command->operand(0));
						command->CompileToNative();
						command->include_option(roNoNative);
						syscall_found = true;
					}
					if (operand.type != otRegistr || operand.registr == regEAX)
						is_end = true;
				}
				else if ((command->type() == cmJmp || command->type() == cmJmpWithFlag) && command->link()) {
					IntelCommand* link_command = GetCommandByAddress(command->link()->to_address());
					if (link_command) {
						k = IndexOf(link_command);
						if (k != NOT_ID)
							stack.push_back(k);
					}
				}
				if (command->GetCommandInfo(command_info_list)) {
					if (operand.type == otRegistr && command_info_list.GetInfo(atWrite, otRegistr, operand.registr))
						is_end = true;
				}
				else {
					is_end = true;
				}

				if (is_end) {
					for (k = stack.size(); k > 0; k--) {
						if (stack[k - 1] <= cur_index)
							stack.erase(stack.begin() + k - 1);
					}
					if (stack.empty())
						break;

					cur_index = stack[0];
					for (k = 0; k < stack.size(); k++) {
						if (cur_index > stack[k])
							cur_index = stack[k];
					}
				}
				else {
					cur_index++;
				}
			}
		}
	}

	if (syscall_found) {
		CallingConvention calling_convention = file.calling_convention();
		for (i = 0; i < count(); i++) {
			command = item(i);
			if (command->type() != cmSyscall)
				continue;

			IntelCommand* next_command = item(i + 1);
			if (next_command->type() == cmAdd && next_command->operand(0).type == otRegistr && next_command->operand(0).registr == regESP)
				continue;

			k = 0;
			for (j = i; j > 0; j--) {
				IntelCommand* param_command = item(j - 1);

				switch (param_command->type()) {
				case cmPush:
					if (calling_convention == ccStdcall) {
						k++;
					}
					else {
						param_command = NULL;
					}
					break;
				case cmMov: case cmLea: case cmXor: case cmMovsxd:
					if (calling_convention == ccMSx64) {
						if (param_command->operand(0).type == otRegistr) {
							switch (param_command->operand(0).registr) {
							case regECX:
								k = std::max<size_t>(k, 1);
								break;
							case regEDX:
								k = std::max<size_t>(k, 2);
								break;
							case regR8:
								k = std::max<size_t>(k, 3);
								break;
							case regR9:
								k = std::max<size_t>(k, 4);
								break;
							}
						}
						else if (param_command->operand(0).type == (otMemory | otBaseRegistr | otValue) && param_command->operand(0).base_registr == regESP) {
							switch (param_command->operand(0).value) {
							case 0x20:
								k = std::max<size_t>(k, 5);
								break;
							case 0x28:
								k = std::max<size_t>(k, 6);
								break;
							case 0x30:
								k = std::max<size_t>(k, 7);
								break;
							case 0x38:
								k = std::max<size_t>(k, 8);
								break;
							case 0x40:
								k = std::max<size_t>(k, 9);
								break;
							case 0x48:
								k = std::max<size_t>(k, 10);
								break;
							default:
								if (param_command->operand(0).value >= 0x50)
									k = NOT_ID;
								break;
							}
						}
					}
					break;
				case cmCall: case cmJmp: case cmJmpWithFlag: case cmRet:
					param_command = NULL;
					break;
				}
				if (!param_command || link_list()->GetLinkByToAddress(ltNone, param_command->address()))
					break;
			}
			if (k == NOT_ID)
				continue;

			command->include_option(roInternal);
			command->set_operand_value(2, k);
		}
	}

	if (file.owner()->format_name() != "PE" && compilation_type() != ctMutation && cpu_address_size() == osQWord) {
		// clang can use stack less than RSP
		bool is_use_rbp = false;
		uint64_t delta_rsp = 0;
		uint64_t sub_rsp_value = 0;
		for (j = 0; j < count(); j++) {
			command = item(j);
			switch (command->type()) {
			case cmMov:
				if (command->operand(0).type == otRegistr && command->operand(0).registr == regEBP && command->operand(1).type == otRegistr && command->operand(1).registr == regESP) {
					is_use_rbp = true;
				}
				else if (is_use_rbp && ((command->operand(0).type == (otMemory | otRegistr | otValue) && command->operand(0).registr == regEBP)
					|| ((command->operand(0).type & (otMemory | otBaseRegistr | otValue)) == (otMemory | otBaseRegistr | otValue) && command->operand(0).base_registr == regEBP))) {
					uint64_t value = command->operand(0).value;
					if (static_cast<int64_t>(value) < 0 && 0 - value > delta_rsp) {
						sub_rsp_value = std::max((0 - value) - delta_rsp, sub_rsp_value);
					}
				}
				else if (((command->operand(0).type == (otMemory | otRegistr | otValue) && command->operand(0).registr == regESP)
					|| ((command->operand(0).type & (otMemory | otBaseRegistr | otValue)) == (otMemory | otBaseRegistr | otValue) && command->operand(0).base_registr == regESP))) {
					uint64_t value = command->operand(0).value;
					if (static_cast<int64_t>(value) < 0)
						sub_rsp_value = std::max((0 - value), sub_rsp_value);
				}
				break;
			case cmPush:
				if (is_use_rbp)
					delta_rsp += OperandSizeToValue(cpu_address_size());
				break;
			case cmSub:
				if (is_use_rbp && command->operand(0).type == otRegistr && command->operand(0).registr == regESP && command->operand(1).type == otValue) {
					delta_rsp += command->operand(1).value;
				}
				break;
			}
		}
		if (sub_rsp_value) {
			size_t push_index = 0;
			size_t pop_index = 0;
			for (j = 0; j < count(); j++) {
				IntelCommand* command = item(j);

				for (i = 0; i < 3; i++) {
					IntelOperand operand = command->operand(i);
					if (operand.type == otNone)
						break;

					if (((operand.type & (otMemory | otRegistr)) == (otMemory | otRegistr) && operand.registr == regESP)
						|| ((operand.type & (otMemory | otBaseRegistr)) == (otMemory | otBaseRegistr) && operand.base_registr == regESP)) {
						command->set_operand_value(i, operand.value + sub_rsp_value);
						command->CompileToNative();
					}
				}

				switch (command->type()) {
				case cmPush:
					push_index = j;
					break;
				case cmMov:
					if (command->operand(0).type == otRegistr && command->operand(0).registr == regEBP && command->operand(1).type == otRegistr && command->operand(1).registr == regESP)
						push_index = j;
					break;
				case cmPop:
				case cmRet:
					if (!pop_index)
						pop_index = j;
					break;
				}
			}

			command = new IntelCommand(this, cpu_address_size(), cmSub, IntelOperand(otRegistr, cpu_address_size(), regESP), IntelOperand(otValue, cpu_address_size(), 0, sub_rsp_value));
			command->CompileToNative();
			InsertObject(push_index + 1, command);

			if (pop_index > push_index)
				pop_index++;

			IntelCommand* pop_command = item(pop_index);

			command = new IntelCommand(this, cpu_address_size(), static_cast<IntelCommandType>(pop_command->type()), pop_command->operand(0), pop_command->operand(1));
			command->CompileToNative();
			InsertObject(pop_index + 1, command);

			pop_command->Init(cmAdd, IntelOperand(otRegistr, cpu_address_size(), regESP), IntelOperand(otValue, cpu_address_size(), 0, sub_rsp_value));
			pop_command->CompileToNative();
		}
	}

#ifdef CHECKED
	for (i = 0; i < count(); i++) {
		item(i)->update_hash();
	}
#endif
}