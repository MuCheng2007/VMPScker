/**
 * PE Runtime Function support.
 */

#include "../../runtime/common.h"
#include "../objects.h"
#include "../osutils.h"
#include "../streams.h"
#include "../files.h"
#include "../processors.h"
#include "PERuntimeFunction.h"
#include "PEDirectory.h"
#include "PEArchitecture.h"

// Intel module
#include "../intel/ir/IntelCommandType.h"
#include "../intel/ir/IntelOperand.h"
#include "../intel/ir/IntelCommand.h"
#include "../intel/ir/IntelFunction.h"

/**
 * PERuntimeFunction
 */

PERuntimeFunction::PERuntimeFunction(PERuntimeFunctionList* owner, uint64_t address, uint64_t begin, uint64_t end, uint64_t unwind_address)
	: BaseRuntimeFunction(owner), address_(address), begin_(begin), end_(end), unwind_address_(unwind_address)
{

}

PERuntimeFunction::PERuntimeFunction(PERuntimeFunctionList* owner, const PERuntimeFunction& src)
	: BaseRuntimeFunction(owner)
{
	address_ = src.address_;
	begin_ = src.begin_;
	end_ = src.end_;
	unwind_address_ = src.unwind_address_;
}

PERuntimeFunction* PERuntimeFunction::Clone(IRuntimeFunctionList* owner) const
{
	PERuntimeFunction* func = new PERuntimeFunction(reinterpret_cast<PERuntimeFunctionList*>(owner), *this);
	return func;
}

void PERuntimeFunction::Rebase(uint64_t delta_base)
{
	address_ += delta_base;
	begin_ += delta_base;
	end_ += delta_base;
	unwind_address_ += delta_base;
}

void PERuntimeFunction::Parse(IArchitecture& file, IFunction& dest)
{
	union UNWIND_INFO_HELPER {
		UNWIND_INFO info;
		uint32_t value;
	};

	IntelFunction& func = reinterpret_cast<IntelFunction&>(dest);

	uint64_t address = address_;
	if (!file.AddressSeek(address) || func.GetCommandByAddress(address))
		return;

	size_t i;
	size_t c = func.count();
	IntelCommand* command;
	CommandLink* link;
	uint64_t image_base = file.image_base();

	command = func.Add(address);
	command->set_comment(CommentInfo(ttComment, "Begin"));
	command->ReadValueFromFile(file, osDWord);
	address = command->next_address();

	command = func.Add(address);
	command->set_comment(CommentInfo(ttComment, "End"));
	command->ReadValueFromFile(file, osDWord);
	address = command->next_address();

	command = func.Add(address);
	command->set_comment(CommentInfo(ttComment, "UnwindData"));
	address = command->ReadValueFromFile(file, osDWord);
	if (address) {
		address += image_base;
		link = command->AddLink(0, ltOffset, address);
		link->set_sub_value(image_base);
	}

	for (i = c; i < func.count(); i++) {
		command = func.item(i);
		command->exclude_option(roClearOriginalCode);
		command->exclude_option(roNeedCompile);
	}

	if (address) {
		command = func.GetCommandByAddress(address);
		if (command) {
			UNWIND_INFO_HELPER unwind_info_helper;
			unwind_info_helper.value = static_cast<uint32_t>(command->dump_value(0, osDWord));
			UNWIND_INFO unwind_info = unwind_info_helper.info;

			func.function_info_list()->Add(begin(), end(), btImageBase, 0, unwind_info.SizeOfProlog, unwind_info.FrameRegister ? unwind_info.FrameRegister : 0xff, this, command);
		}
		else if (file.AddressSeek(address)) {
			UNWIND_INFO_HELPER unwind_info_helper;
			command = func.Add(address);
			unwind_info_helper.value = static_cast<uint32_t>(command->ReadValueFromFile(file, osDWord));
			UNWIND_INFO unwind_info = unwind_info_helper.info;
			command->set_comment(CommentInfo(ttComment, string_format("Version: %.2X; Flags: %.2X; SizeOfProlog: %.2X; CountOfCodes: %.2X; FrameRegister: %.2X; FrameOffset: %.2X",
				unwind_info.Version, unwind_info.Flags, unwind_info.SizeOfProlog, unwind_info.CountOfCodes, unwind_info.FrameRegister, unwind_info.FrameOffset)));
			command->set_alignment(OperandSizeToValue(osDWord));
			command->include_option(roCreateNewBlock);
			address = command->next_address();

			func.function_info_list()->Add(begin(), end(), btImageBase, 0, unwind_info.SizeOfProlog, unwind_info.FrameRegister ? unwind_info.FrameRegister : 0xff, this, command);

			for (i = 0; i < unwind_info.CountOfCodes; i++) {
				command = func.Add(address);

				UNWIND_CODE unwind_code;
				bool is_epilog = false;
				file.Read(&unwind_code, sizeof(unwind_code));
				Data data;
				data.InsertBuff(0, &unwind_code, sizeof(unwind_code));
				switch (unwind_code.UnwindOp) {
				case UWOP_PUSH_NONVOL:
					command->set_comment(CommentInfo(ttComment, "UWOP_PUSH_NONVOL"));
					break;
				case UWOP_ALLOC_LARGE:
					data.PushWord(file.ReadWord());
					i++;
					if (unwind_code.OpInfo == 1) {
						data.PushWord(file.ReadWord());
						i++;
					}
					command->set_comment(CommentInfo(ttComment, "UWOP_ALLOC_LARGE"));
					break;
				case UWOP_ALLOC_SMALL:
					command->set_comment(CommentInfo(ttComment, "UWOP_ALLOC_SMALL"));
					break;
				case UWOP_SET_FPREG:
					command->set_comment(CommentInfo(ttComment, "UWOP_SET_FPREG"));
					break;
				case UWOP_SAVE_NONVOL:
					data.PushWord(file.ReadWord());
					i++;
					command->set_comment(CommentInfo(ttComment, "UWOP_SAVE_NONVOL"));
					break;
				case UWOP_SAVE_NONVOL_FAR:
					data.PushWord(file.ReadWord());
					data.PushWord(file.ReadWord());
					i += 2;
					command->set_comment(CommentInfo(ttComment, "UWOP_SAVE_NONVOL_FAR"));
					break;
				case UWOP_EPILOG:
					if (unwind_info.Version == 2) {
						is_epilog = true;
						if (unwind_code.CodeOffset) {
							uint64_t range_begin, range_end;
							if ((unwind_code.OpInfo & 1)) {
								range_begin = end() - unwind_code.CodeOffset;
								range_end = end();
							}
							else {
								UNWIND_CODE next_code;
								file.Read(&next_code, sizeof(next_code));
								data.PushWord(next_code.FrameOffset);
								i++;
								range_begin = end() - ((next_code.OpInfo << 8) + next_code.CodeOffset);
								range_end = range_begin + unwind_code.CodeOffset;
							}
							func.range_list()->Add(range_begin, range_end, NULL, NULL, command);
						}
						command->set_comment(CommentInfo(ttComment, "UWOP_EPILOG"));
					}
					else {
						data.PushWord(file.ReadWord());
						i++;
						command->set_comment(CommentInfo(ttComment, "UWOP_SAVE_XMM128"));
					}
					break;
				case UWOP_SAVE_XMM128:
					data.PushWord(file.ReadWord());
					i++;
					command->set_comment(CommentInfo(ttComment, "UWOP_SAVE_XMM128"));
					break;
				case UWOP_SAVE_XMM128_FAR:
					data.PushWord(file.ReadWord());
					data.PushWord(file.ReadWord());
					i += 2;
					command->set_comment(CommentInfo(ttComment, "UWOP_SAVE_XMM128_FAR"));
					break;
				case UWOP_PUSH_MACHFRAME:
					command->set_comment(CommentInfo(ttComment, "UWOP_PUSH_MACHFRAME"));
					break;
				}

				command->Init(data);
				address = command->next_address();

				if (!is_epilog)
					func.range_list()->Add(begin(), begin() + unwind_code.CodeOffset, NULL, NULL, NULL);
			}
			if (unwind_info.CountOfCodes & 1) {
				// align to DWORD
				command = func.Add(address);
				command->ReadArray(file, sizeof(UNWIND_CODE));
				address = command->next_address();
			}

			IntelCommand* handler_data_command = NULL;
			if (unwind_info.Flags & UNW_FLAG_CHAININFO) {
				command = func.Add(address);
				command->set_comment(CommentInfo(ttComment, "Begin"));
				command->ReadValueFromFile(file, osDWord);
				address = command->next_address();

				command = func.Add(address);
				command->set_comment(CommentInfo(ttComment, "End"));
				command->ReadValueFromFile(file, osDWord);
				address = command->next_address();

				command = func.Add(address);
				command->set_comment(CommentInfo(ttComment, "UnwindData"));
				address = command->ReadValueFromFile(file, osDWord);
				if (address) {
					address += image_base;
					link = command->AddLink(0, ltOffset, address);
					link->set_sub_value(image_base);
				}
			}
			else if (unwind_info.Flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) {
				command = func.Add(address);
				command->set_comment(CommentInfo(ttComment, "Handler"));
				address = command->ReadValueFromFile(file, osDWord);
				if (address) {
					address += image_base;
					CommentInfo res;
					res.type = ttNone;
					MapFunction* map_function = file.map_function_list()->GetFunctionByAddress(address);
					if (map_function) {
						res.value = string_format("%c %s", 3, map_function->name().c_str());
						switch (map_function->type()) {
						case otString:
							res.type = ttString;
							break;
						case otExport:
							res.type = ttExport;
							break;
						default:
							res.type = ttFunction;
							break;
						}

						command->set_comment(res);
					}
					link = command->AddLink(0, ltOffset, address);
					link->set_sub_value(image_base);
				}
				address = command->next_address();

				handler_data_command = func.Add(address);
				handler_data_command->ReadValueFromFile(file, osDWord);
				handler_data_command->set_comment(CommentInfo(ttComment, "HandlerData"));
			}

			for (i = c; i < func.count(); i++) {
				command = func.item(i);
				command->exclude_option(roClearOriginalCode);
			}

			if (handler_data_command) {
				uint32_t handler_data = static_cast<uint32_t>(handler_data_command->operand(0).value);
				if (func.ParseCxxSEH(file, handler_data + image_base)) {
					link = handler_data_command->AddLink(0, ltOffset, handler_data + image_base);
					link->set_sub_value(image_base);
					address = handler_data_command->next_address();
				}
				else if (func.ParseScopeSEH(file, handler_data_command->next_address(), handler_data)) {
					handler_data_command->set_comment(CommentInfo(ttComment, "Count"));
					address = handler_data_command->next_address() + handler_data * 0x10;
				}
				else if (func.ParseCompressedCxxSEH(file, handler_data + image_base, begin())) {
					link = handler_data_command->AddLink(0, ltOffset, handler_data + image_base);
					link->set_sub_value(image_base);
					address = handler_data_command->next_address();
				}
				else
					address = 0;

				if (address) {
					if (!func.GetCommandByAddress(address) && !file.runtime_function_list()->GetFunctionByUnwindAddress(address) && file.AddressSeek(address)) {
						command = func.Add(address);
						uint32_t value = static_cast<uint32_t>(command->ReadValueFromFile(file, osDWord));
						command->set_comment(CommentInfo(ttComment, string_format("EHandler: %.2X; UHandler: %.2X; HasAlignment: %.2X; CookieOffset: %.8X", value & 1, (value & 2) >> 1, (value & 4) >> 2, value & 0xFFFFFFF8)));
						command->exclude_option(roClearOriginalCode);

						if (value & 4) {
							command = func.Add(command->next_address());
							command->set_comment(CommentInfo(ttComment, "AlignedBaseOffset"));
							command->ReadValueFromFile(file, osDWord);
							command->exclude_option(roClearOriginalCode);

							command = func.Add(command->next_address());
							command->set_comment(CommentInfo(ttComment, "Alignment"));
							command->ReadValueFromFile(file, osDWord);
							command->exclude_option(roClearOriginalCode);
						}
					}
				}
			}
		}
	}
}

/**
 * PERuntimeFunctionList
 */

PERuntimeFunctionList::PERuntimeFunctionList()
	: BaseRuntimeFunctionList(), address_(0)
{

}

PERuntimeFunctionList::PERuntimeFunctionList(const PERuntimeFunctionList& src)
	: BaseRuntimeFunctionList(src), address_(0)
{
	address_ = src.address_;
}

PERuntimeFunctionList* PERuntimeFunctionList::Clone() const
{
	PERuntimeFunctionList* list = new PERuntimeFunctionList(*this);
	return list;
}

PERuntimeFunction* PERuntimeFunctionList::Add(uint64_t address, uint64_t begin, uint64_t end, uint64_t unwind_address, IRuntimeFunction* source, const std::vector<uint8_t>& call_frame_instructions)
{
	PERuntimeFunction* func = new PERuntimeFunction(this, address, begin, end, unwind_address);
	AddObject(func);
	return func;
}

void PERuntimeFunctionList::ReadFromFile(PEArchitecture& file, PEDirectory& directory)
{
	if (!directory.address())
		return;

	if (!file.AddressSeek(directory.address()))
		throw std::runtime_error("Format error");

	address_ = directory.address();
	uint64_t image_base = file.image_base();
	RUNTIME_FUNCTION data;
	std::vector<uint8_t> call_frame_instructions;
	for (size_t i = 0; i < directory.size(); i += sizeof(data)) {
		file.Read(&data, sizeof(data));
		Add(address_ + i, data.BeginAddress + image_base, data.EndAddress + image_base, data.u.UnwindInfoAddress + image_base, 0, call_frame_instructions);
	}
}

size_t PERuntimeFunctionList::WriteToFile(PEArchitecture& file)
{
	Sort();

	size_t res = 0;
	uint64_t image_base = file.image_base();
	RUNTIME_FUNCTION data;
	for (size_t i = 0; i < count(); i++) {
		PERuntimeFunction* runtime_function = item(i);
		data.BeginAddress = static_cast<uint32_t>(runtime_function->begin() - image_base);
		data.EndAddress = static_cast<uint32_t>(runtime_function->end() - image_base);
		data.u.UnwindInfoAddress = static_cast<uint32_t>(runtime_function->unwind_address() - image_base);
		res += file.Write(&data, sizeof(data));
	}

	return res;
}

PERuntimeFunction* PERuntimeFunctionList::GetFunctionByAddress(uint64_t address) const
{
	return reinterpret_cast<PERuntimeFunction*>(BaseRuntimeFunctionList::GetFunctionByAddress(address));
}

PERuntimeFunction* PERuntimeFunctionList::item(size_t index) const
{
	return reinterpret_cast<PERuntimeFunction*>(BaseRuntimeFunctionList::item(index));
}

uint64_t PERuntimeFunctionList::RebaseDWord(IArchitecture& file, uint32_t delta_rva)
{
	uint64_t pos = file.Tell();
	uint64_t value = file.ReadDWord();
	if (value > 1) {
		uint64_t address = file.AddressTell() - sizeof(uint32_t);
		IntelCommand* command = reinterpret_cast<IntelCommand*>(file.function_list()->GetCommandByAddress(address, false));
		if (command && command->type() == cmDD) {
			command->set_operand_value(0, command->operand(0).value + delta_rva);
			if (command->link())
				command->link()->set_sub_value(command->link()->sub_value() - delta_rva);
		}
		file.Seek(pos);
		file.WriteDWord(static_cast<uint32_t>(value) + delta_rva);
		value += file.image_base();
	}
	return value;
}

void PERuntimeFunctionList::RebaseByFile(IArchitecture& file, uint64_t target_image_base, uint64_t delta_base)
{
	if (!address_)
		return;

	uint32_t delta_rva = static_cast<uint32_t>(file.image_base() + delta_base - target_image_base);
	std::set<uint64_t> address_list;
	std::set<uint64_t> handler_list;
	size_t i, j, k;
	for (i = 0; i < count(); i++) {
		PERuntimeFunction* func = item(i);

		if (!file.AddressSeek(func->unwind_address()) || address_list.find(func->unwind_address()) != address_list.end())
			continue;

		address_list.insert(func->unwind_address());

		union UNWIND_INFO_HELPER {
			UNWIND_INFO info;
			uint32_t value;
		};
		UNWIND_INFO_HELPER unwind_info_helper;
		unwind_info_helper.value = file.ReadDWord();
		UNWIND_INFO unwind_info = unwind_info_helper.info;
		size_t count_of_codes = unwind_info.CountOfCodes;
		if (count_of_codes & 1) {
			// align to DWORD
			count_of_codes++;
		}

		for (j = 0; j < count_of_codes; j++) {
			file.ReadWord();
		}

		if (unwind_info.Flags & UNW_FLAG_CHAININFO) {
			RebaseDWord(file, delta_rva);
			RebaseDWord(file, delta_rva);
			RebaseDWord(file, delta_rva);
		}
		else if (unwind_info.Flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) {
			RebaseDWord(file, delta_rva);
			uint64_t handler_data_address = file.AddressTell();
			uint32_t handler_data = file.ReadDWord();
			bool is_cxx_handler = false;
			bool is_scope_table = false;
			if (file.AddressSeek(handler_data + file.image_base())) {
				uint32_t magic = file.ReadDWord();
				if (magic == 0x19930520 || magic == 0x19930521 || magic == 0x19930522)
					is_cxx_handler = true;
			}
			if (!is_cxx_handler && file.AddressSeek(handler_data_address + sizeof(handler_data))) {
				is_scope_table = true;
				for (j = 0; j < handler_data; j++) {
					for (size_t k = 0; k < 4; k++) {
						uint64_t value = file.ReadDWord();
						if (!value || (k == 2 && value == 1))
							continue;
						if ((file.segment_list()->GetMemoryTypeByAddress(value + file.image_base()) & mtExecutable) == 0) {
							is_scope_table = false;
							break;
						}
					}
					if (!is_scope_table)
						break;
				}
			}

			if (is_cxx_handler) {
				file.AddressSeek(handler_data_address);
				RebaseDWord(file, delta_rva);
				handler_data_address = handler_data + file.image_base();
				if (handler_list.find(handler_data_address) != handler_list.end())
					continue;

				handler_list.insert(handler_data_address);
				file.AddressSeek(handler_data_address);
				file.ReadDWord();
				uint32_t max_state = file.ReadDWord();
				uint64_t unwind_map_entry = RebaseDWord(file, delta_rva);
				uint32_t try_blocks = file.ReadDWord();
				uint64_t try_blocks_entry = RebaseDWord(file, delta_rva);
				uint32_t map_count = file.ReadDWord();
				uint64_t map_entry = RebaseDWord(file, delta_rva);

				if (max_state && file.AddressSeek(unwind_map_entry)) {
					for (j = 0; j < max_state; j++) {
						file.ReadDWord();
						RebaseDWord(file, delta_rva);
					}
				}

				if (try_blocks && file.AddressSeek(try_blocks_entry)) {
					for (j = 0; j < try_blocks; j++) {
						file.ReadDWord();
						file.ReadDWord();
						file.ReadDWord();
						uint32_t catches = file.ReadDWord();
						uint64_t catches_entry = RebaseDWord(file, delta_rva);
						uint64_t pos = file.Tell();
						if (catches && file.AddressSeek(catches_entry)) {
							for (k = 0; k < catches; k++) {
								file.ReadDWord();
								file.ReadDWord();
								file.ReadDWord();
								RebaseDWord(file, delta_rva);
								if (file.cpu_address_size() == osQWord)
									file.ReadDWord();
							}
							file.Seek(pos);
						}
					}
				}

				if (map_count && file.AddressSeek(map_entry)) {
					for (j = 0; j < map_count; j++) {
						RebaseDWord(file, delta_rva);
						file.ReadDWord();
					}
				}
			}
			else if (is_scope_table) {
				file.AddressSeek(handler_data_address + sizeof(handler_data));
				for (j = 0; j < handler_data; j++) {
					RebaseDWord(file, delta_rva);
					RebaseDWord(file, delta_rva);
					RebaseDWord(file, delta_rva);
					RebaseDWord(file, delta_rva);
				}
			}
		}
	}

	address_ += delta_base;

	BaseRuntimeFunctionList::Rebase(delta_base);
}

void PERuntimeFunctionList::FreeByManager(MemoryManager& manager)
{
	if (!address_)
		return;

	if (count())
		manager.Add(address_, sizeof(RUNTIME_FUNCTION) * count());
}
