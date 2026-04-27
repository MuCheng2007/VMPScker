#include "IntelLoader.h"
#include "IntelFunction.h"
#include "IntelFunctionList.h"
#include "IntelCommand.h"
#include "../../processors.h"
#include "../../core_internal/core.h"
#include "../../files.h"
#include "../../pe/pefile.h"
#include "../../core_internal/file_manager.h"
#include "../vm/IntelVirtualMachineList.h"
#include "../vm/IntelVirtualMachine.h"
#include "../../../runtime/crypto.h"
#include "../../lang.h"
#include "../../packer.h"

// Copied from intel.cc:
// - BaseIntelLoader (lines: ~24076 - 26950)
// - PEIntelLoader (lines: ~26951 - 27209)
// - MacIntelLoader (lines: ~27210 - 27271)
// - ELFIntelLoader (lines: ~27272 - 27301)

/**
 * BaseIntelLoader
 */

BaseIntelLoader::BaseIntelLoader(IntelFunctionList* owner, OperandSize cpu_address_size)
	: IntelFunction(owner, cpu_address_size), data_segment_address_(0), import_segment_address_(0)
{
	set_tag(ftLoader);
}

void BaseIntelLoader::AddAVBuffer(const CompileContext& ctx)
{
	IntelCommand* command;
	uint32_t sum = 0;
	CommandBlock* block = AddBlock(count(), true);
	for (size_t i = 0; i < 64; i++) {
		uint32_t value = (i == 0) ? 0 : rand32();
		sum += value;
		command = AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, value));
		command->CompileToNative();
		command->set_block(block);
	}
	block->set_end_index(count() - 1);
	command = item(block->start_index());
	command->set_operand_value(0, 0xB7896EB5 - sum);
	command->CompileToNative();
	uint64_t address = ctx.manager->Alloc((block->end_index() - block->start_index() + 1) * sizeof(uint32_t), mtReadable);
	block->set_address(address);
}

bool BaseIntelLoader::Prepare(const CompileContext& ctx)
{
	size_t i, j;

	if (ctx.file->virtual_machine_list()->count() > 1) {
		std::set<ICommand*> call_list;

		for (i = 0; i < count(); i++) {
			IntelCommand* command = item(i);
			if (command->type() == cmCall && (command->options() & roInternal)) {
				ICommand* to_command = command->link()->to_command();
				if (!to_command)
					continue;

				call_list.insert(to_command);
				command_group_.insert(item(i + 1));
			}
		}
		if (!call_list.empty()) {
			for (i = 0; i < count(); i++) {
				IntelCommand* command = item(i);
				if (command->type() == cmRet && (command->options() & roInternal)) {
					IntelCommand* block_command = NULL;
					for (j = i; j > 0; j--) {
						command = item(j - 1);
						if (!block_command) {
							if ((command->type() == cmCall && ((command->section_options() & rtLinkedFrom) || (command->options() & roInternal) == 0))
								|| command->type() == cmJmp || command->type() == cmJmpWithFlag || command->type() == cmCmov || command->type() == cmRet || command->is_data())
								block_command = item(j);
						}
						if (call_list.find(command) != call_list.end()) {
							command_group_.insert(block_command ? block_command : command);
							break;
						}
					}
				}
			}
		}
	}

	// prepare loader's VM
	std::vector<IFunction*> function_list = ctx.file->function_list()->processor_list();
	for (size_t k = 0; k < function_list.size(); k++) {
		IntelFunction* func = reinterpret_cast<IntelFunction*>(function_list[k]);
		for (i = 0; i < func->count(); i++) {
			IntelCommand* command = func->item(i);
			for (j = 0; j < 3; j++) {
				IntelOperand operand = command->operand(j);
				if (operand.type == otNone)
					break;

				if (operand.fixup)
					command->set_operand_fixup(j, NEED_FIXUP);
			}
		}
		for (i = 0; i < func->function_info_list()->count(); i++) {
			FunctionInfo* info = func->function_info_list()->item(i);
			for (size_t j = 0; j < info->count(); j++) {
				AddressRange* address_range = info->item(j);
				address_range->set_begin(0);
				address_range->set_end(0);
			}
		}
	}

	// prepare ranges
	function_list.push_back(this);
	for (i = 0; i < function_list.size(); i++) {
		IntelFunction* func = reinterpret_cast<IntelFunction*>(function_list[i]);
		func->range_list()->Prepare();
		func->function_info_list()->Prepare();
	}

	return PrepareExtCommands(ctx);
}

IVirtualMachine* BaseIntelLoader::virtual_machine(IVirtualMachineList* virtual_machine_list, ICommand* command) const
{
	if (command_group_.find(command) != command_group_.end()) {
		for (std::set<ICommand*>::const_iterator it = command_group_.begin(); it != command_group_.end(); it++) {
			command = *it;
			if (command->block())
				return command->block()->virtual_machine();
		}
	}

	return IntelFunction::virtual_machine(virtual_machine_list, command);
}

bool BaseIntelLoader::Compile(const CompileContext& ctx)
{
	size_t i, j;

	if (ctx.options.flags & cpMemoryProtection) {
		IntelVirtualMachineList* virtual_machine_list = reinterpret_cast<IntelVirtualMachineList*>(ctx.file->virtual_machine_list());
		virtual_machine_list->ClearCRCMap();
	}

	if (!IntelFunction::Compile(ctx))
		return false;
	IntelFunction::AfterCompile(ctx);

	std::vector<IFunction*> function_list = ctx.file->function_list()->processor_list();
	function_list.push_back(this);
	std::vector<CommandBlock*> data_block_list[2], block_list;
	for (i = 0; i < function_list.size(); i++) {
		IFunction* func = function_list[i];
		for (j = 0; j < func->block_list()->count(); j++) {
			CommandBlock* block = func->block_list()->item(j);
			uint32_t command_options = block->function()->item(block->start_index())->options();
			if (command_options & roImportSegment)
				data_block_list[0].push_back(block);
			else if (command_options & roDataSegment)
				data_block_list[1].push_back(block);
			else
				block_list.push_back(block);
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
	}

	for (i = 0; i < block_list.size(); i++) {
		block_list[i]->Compile(*ctx.manager);
	}

	for (j = 0; j < 2; j++) {
		std::vector<CommandBlock*>* list = &data_block_list[j];
		if (list->empty())
			continue;

		MemoryRegion* last_region = ctx.manager->item(ctx.manager->count() - 1);
		uint64_t address = last_region->address();
		uint64_t segment_address = AlignValue(address, ctx.file->segment_alignment());
		if (j == 0)
			import_segment_address_ = segment_address;
		else
			data_segment_address_ = segment_address;
		if (segment_address > address)
			last_region->Alloc(segment_address - address, mtNone);
		for (i = 0; i < ctx.manager->count(); i++) {
			MemoryRegion* region = ctx.manager->item(i);
			if (region->address() < segment_address)
				region->exclude_type(mtReadable);
		}
		for (i = 0; i < list->size(); i++) {
			list->at(i)->Compile(*ctx.manager);
		}
	}

	for (i = 0; i < function_list.size(); i++) {
		function_list[i]->CompileInfo(ctx);
	}

	if (ctx.options.flags & cpMemoryProtection) {
		IntelFunctionList* function_list = reinterpret_cast<IntelFunctionList*>(ctx.file->function_list());
		IntelRuntimeCRCTable* runtime_crc_table = function_list->runtime_crc_table();
		for (i = 0; i < function_list->count(); i++) {
			IntelFunction* func = function_list->item(i);
			if (func == runtime_crc_table || func->tag() == ftProcessor || func == this)
				continue;

			func->set_need_compile(false);
		}
		runtime_crc_table->clear();
		runtime_crc_table->Compile(ctx);
	}

	for (i = 0; i < function_list.size(); i++) {
		IFunction* func = function_list[i];
		if (func->compilation_type() != ctMutation)
			continue;

		func->CompileLinks(ctx);
	}

	for (i = 0; i < function_list.size(); i++) {
		IFunction* func = function_list[i];
		if (func->compilation_type() == ctMutation)
			continue;

		func->CompileLinks(ctx);
	}

	return true;
}

/**
 * PEIntelLoader
 */

PEIntelLoader::PEIntelLoader(IntelFunctionList* owner, OperandSize cpu_address_size)
	: BaseIntelLoader(owner, cpu_address_size), import_entry_(NULL), import_size_(0), iat_entry_(NULL), iat_size_(0),
	name_entry_(NULL), resource_section_info_(NULL), resource_packer_info_(NULL), export_entry_(NULL), export_size_(0),
	tls_entry_(NULL), tls_size_(0), file_crc_entry_(NULL), file_crc_size_(0), loader_crc_entry_(NULL), loader_crc_size_(0),
	delay_import_entry_(NULL), delay_import_size_(0), tls_call_back_entry_(NULL), iat_address_(0),
	loader_crc_size_entry_(NULL), loader_crc_hash_entry_(NULL), file_crc_size_entry_(NULL), security_cookie_(0), cfg_check_function_entry_(NULL)
{

}

Data EncryptString(const char* str, uint32_t key)
{
	Data data;
	for (size_t i = 0; ; i++) {
		data.PushByte(str[i] ^ static_cast<uint8_t>(_rotl32(key, (int)i) + i));
		if (!str[i])
			break;
	}
	return data;
}

Data EncryptString(const os::unicode_char* str, uint32_t key)
{
	Data data;
	for (size_t i = 0; ; i++) {
		data.PushWord(str[i] ^ static_cast<uint16_t>(_rotl32(key, (int)i) + i));
		if (!str[i])
			break;
	}
	return data;
}

bool PEIntelLoader::Prepare(const CompileContext& ctx)
{
	size_t i, j, k, index, old_count, import_index, orig_dll_count, file_dll_count, start_index;
	PEImportList new_import_list(NULL);
	PEImport* import;
	PEImportFunction* import_function;
	IntelCommandType value_command_type;
	IntelCommand* command, * iat_command, * src_command, * dst_command, * setup_image_entry, * free_image_entry;
	ImportInfo import_info;
	std::vector<ImportInfo> import_info_list;
	std::vector<ImportFunctionInfo> import_function_info_list;
	PEArchitecture* file, * runtime;
	CommandLink* link;
	IntelFunctionList* runtime_function_list;
	IntelFunction* func;
	std::map<uint64_t, PEImportFunction*> runtime_info_list;
	CommandLink* src_link, * dst_link;
	std::string dll_name;
	IntelImport* intel_import;
	IntelCRCTable* intel_crc;
	uint64_t loader_data_address, tls_index_address;

	file = reinterpret_cast<PEArchitecture*>(ctx.file);
	runtime = reinterpret_cast<PEArchitecture*>(ctx.runtime);
	intel_import = reinterpret_cast<IntelFunctionList*>(file->function_list())->import();
	intel_crc = reinterpret_cast<IntelFunctionList*>(file->function_list())->crc_table();
	IntelLoaderData* loader_data = reinterpret_cast<IntelFunctionList*>(file->function_list())->loader_data();
	loader_data_address = (loader_data) ? loader_data->entry()->address() : runtime->export_list()->GetAddressByType(atLoaderData);
	if (!loader_data_address)
		return false;

	// create AV signature buffer
	AddAVBuffer(ctx);
	start_index = count();

	ICommand* entry_point_command = NULL;
	if (file->entry_point()) {
		IFunction* entry_point_func = ctx.file->function_list()->GetFunctionByAddress(file->entry_point());
		if (entry_point_func)
			entry_point_command = entry_point_func->entry();
	}
	import_index = 0;
	file_dll_count = 0;
	k = (runtime->segment_list()->count() > 0) ? 2 : 1;
	for (j = 0; j < k; j++) {
		PEArchitecture* source_file = (j == 0) ? file : runtime;
		for (i = 0; i < source_file->import_list()->count(); i++) {
import = source_file->import_list()->item(i);
			if (import->is_sdk())
				continue;

			new_import_list.AddObject(import->Clone(&new_import_list));
			import_index += import->count();
		}

		if (j == 0)
			file_dll_count = new_import_list.count();
	}

	// need move native APIs to the top of vector
	if (ctx.options.flags & cpImportProtection) {
		for (i = 0; i < new_import_list.count(); i++) {
import = new_import_list.item(i);

			k = NOT_ID;
			for (j = 0; j < import->count(); j++) {
				import_function = import->item(j);
				if (import_function->options() & ioNative) {
					if (k == NOT_ID)
						continue;
import->SwapObjects(k, j);
					k++;
				}
				else {
					if (k == NOT_ID)
						k = j;
				}
			}
		}
	}

	// add loader import
	std::map<uint64_t, PEImportFunction*> import_map;
	orig_dll_count = new_import_list.count();
	runtime_function_list = reinterpret_cast<IntelFunctionList*>(runtime->function_list());
	for (i = 0; i < runtime_function_list->count(); i++) {
		func = runtime_function_list->item(i);
		if (func->tag() != ftLoader)
			continue;

		for (j = 0; j < func->count(); j++) {
			command = func->item(j);
			import_function = NULL;
			switch (command->type()) {
			case cmCall:
			case cmJmp:
			case cmMov:
				k = (command->type() == cmMov) ? 1 : 0;
				if (command->operand(k).type == (otMemory | otValue))
					import_function = runtime->import_list()->GetFunctionByAddress(command->operand(k).value);
				break;
			}
			if (!import_function)
				continue;

			std::map<uint64_t, PEImportFunction*>::const_iterator it = import_map.find(import_function->address());
			PEImportFunction* new_import_function = (it != import_map.end()) ? it->second : NULL;
			if (!new_import_function) {
				dll_name = import_function->owner()->name();
import = NULL;
				for (k = orig_dll_count; k < new_import_list.count(); k++) {
					if (new_import_list.item(k)->CompareName(dll_name)) {
import = new_import_list.item(k);
						break;
					}
				}
				if (!import) {
import = new PEImport(&new_import_list, dll_name);
					new_import_list.AddObject(import);
				}
				new_import_function = import_function->Clone(import);
import->AddObject(new_import_function);
				import_map[import_function->address()] = new_import_function;
			}
			runtime_info_list[command->address()] = new_import_function;
		}
	}

	// create import directory
	for (i = 0; i < new_import_list.count(); i++) {
import = new_import_list.item(i);

		if (ctx.options.file_manager && i < file_dll_count) {
			bool is_delay_import = false;
			for (j = 0; j < ctx.options.file_manager->count(); j++) {
				if (import->CompareName(ctx.options.file_manager->item(j)->name())) {
					is_delay_import = true;
					break;
				}
			}

			if (is_delay_import) {
				import_info.original_first_thunk = NULL;
				import_info.name = NULL;
				import_info.first_thunk = NULL;

				import_info_list.push_back(import_info);
				continue;
			}
		}

		// IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk
		command = AddCommand(cmDD, IntelOperand(otValue, osDWord));
		command->AddLink(0, ltOffset);
		import_info.original_first_thunk = command;

		// IMAGE_IMPORT_DESCRIPTOR.TimeDateStamp
		AddCommand(cmDD, IntelOperand(otValue, osDWord));

		// IMAGE_IMPORT_DESCRIPTOR.ForwarderChain
		AddCommand(cmDD, IntelOperand(otValue, osDWord));

		// IMAGE_IMPORT_DESCRIPTOR.Name
		command = AddCommand(cmDD, IntelOperand(otValue, osDWord));
		command->AddLink(0, ltOffset);
		import_info.name = command;

		// IMAGE_IMPORT_DESCRIPTOR.FirstThunk
		command = AddCommand(cmDD, IntelOperand(otValue, osDWord));
		command->AddLink(0, ltOffset);
		import_info.first_thunk = command;

		import_info_list.push_back(import_info);
	}

	// end of import directory
	for (j = 0; j < 5; j++) {
		AddCommand(cmDD, IntelOperand(otValue, osDWord));
	}

	import_size_ = static_cast<uint32_t>((count() - start_index) * sizeof(uint32_t));
	import_entry_ = item(start_index);
	import_entry_->set_alignment(OperandSizeToValue(cpu_address_size()));

	// create IAT
	value_command_type = (cpu_address_size() == osDWord) ? cmDD : cmDQ;
	uint64_t ordinal_mask = (cpu_address_size() == osDWord) ? IMAGE_ORDINAL_FLAG32 : IMAGE_ORDINAL_FLAG64;
	size_t name_index = count();
	for (i = 0; i < new_import_list.count(); i++) {
import = new_import_list.item(i);

		bool is_delay_import = (import_info_list[i].name == NULL);

		index = count();
		for (j = 0; j < import->count(); j++) {
			import_function = import->item(j);

			if (is_delay_import) {
				command = NULL;
			}
			else
				// for import protection need only one API for each DLL
				if ((ctx.options.flags & cpImportProtection) && i < orig_dll_count && (import_function->options() & ioNative) == 0 && j > 0) {
					command = NULL;
				}
				else if (import_function->is_ordinal()) {
					command = AddCommand(value_command_type, IntelOperand(otValue, cpu_address_size(), 0, ordinal_mask | import_function->ordinal()));
				}
				else {
					command = AddCommand(value_command_type, IntelOperand(otValue, cpu_address_size()));
					command->AddLink(0, ltOffset);
				}
			ImportFunctionInfo import_function_info(import_function);
			import_function_info.name = command;

			import_function_info_list.push_back(import_function_info);
		}

		if (is_delay_import)
			continue;

		AddCommand(value_command_type, IntelOperand(otValue, cpu_address_size()));

		import_info_list[i].original_first_thunk->link()->set_to_command(item(index));
	}
	name_entry_ = item(name_index);
	name_entry_->set_alignment(OperandSizeToValue(cpu_address_size()));

	size_t iat_index = count();
	for (i = 0, import_index = 0; i < new_import_list.count(); i++) {
import = new_import_list.item(i);

		bool is_delay_import = (import_info_list[i].name == NULL);

		index = count();
		for (j = 0; j < import->count(); j++, import_index++) {
			import_function = import->item(j);

			if (is_delay_import) {
				command = NULL;
			}
			else
				// for import protection need only one API for each DLL
				if ((ctx.options.flags & cpImportProtection) && i < orig_dll_count && (import_function->options() & ioNative) == 0 && j > 0) {
					command = NULL;
				}
				else if (import_function->is_ordinal()) {
					command = AddCommand(value_command_type, IntelOperand(otValue, cpu_address_size(), 0, ordinal_mask | import_function->ordinal()));
				}
				else {
					command = AddCommand(value_command_type, IntelOperand(otValue, cpu_address_size()));
					command->AddLink(0, ltOffset);
				}

			import_function_info_list[import_index].thunk = command;
		}

		if (is_delay_import)
			continue;

		AddCommand(value_command_type, IntelOperand(otValue, cpu_address_size()));

		import_info_list[i].first_thunk->link()->set_to_command(item(index));
	}

	iat_entry_ = item(iat_index);
	iat_size_ = static_cast<uint32_t>((count() - iat_index) * OperandSizeToValue(cpu_address_size()));
	iat_entry_->set_alignment(file->segment_alignment());
	iat_entry_->include_option(roCreateNewBlock);

	if (iat_address_) {
		CommandBlock* block = AddBlock(iat_index, true);
		block->set_address(iat_address_);
		for (i = iat_index; i < count(); i++) {
			block->set_end_index(i);
			item(i)->set_block(block);
		}
	}
	else {
		// IAT size must be aligned by page size
		j = AlignValue(iat_size_, file->segment_alignment());
		if (j > iat_size_) {
			std::string buffer;
			buffer.resize(j - iat_size_, 0);
			AddCommand(buffer);
		}
	}

	// create import DLL names
	uint32_t string_key = rand32();
	for (i = 0; i < new_import_list.count(); i++) {
import = new_import_list.item(i);

		bool is_delay_import = (import_info_list[i].name == NULL);

		if (is_delay_import) {
			command = AddCommand(EncryptString(import->name().c_str(), string_key));
			command->include_option(roCreateNewBlock);

			import_info_list[i].loader_name = command;
			continue;
		}

		if ((ctx.options.flags & cpImportProtection) && i < orig_dll_count) {
			command = AddCommand(EncryptString(import->name().c_str(), string_key));
			command->include_option(roCreateNewBlock);

			import_info_list[i].loader_name = command;
		}

		command = NULL;
		for (j = 0; j < i; j++) {
			if (new_import_list.item(j)->CompareName(import->name())) {
				command = reinterpret_cast<IntelCommand*>(import_info_list[j].name->link()->to_command());
				break;
			}
		}
		if (command == NULL) {
			command = AddCommand(import->name());
			command->include_option(roCreateNewBlock);
			command->set_alignment(sizeof(uint16_t));
		}

		import_info_list[i].name->link()->set_to_command(command);
	}

	// create import function names
	for (i = 0, import_index = 0; i < new_import_list.count(); i++) {
import = new_import_list.item(i);

		bool is_delay_import = (import_info_list[i].name == NULL);

		for (j = 0; j < import->count(); j++, import_index++) {
			import_function = import->item(j);
			if (import_function->is_ordinal())
				continue;

			if (is_delay_import) {
				command = AddCommand(EncryptString(import_function->name().c_str(), string_key));
				command->include_option(roCreateNewBlock);

				import_function_info_list[import_index].loader_name = command;
				continue;
			}

			// for import protection need only one API for each DLL
			if ((ctx.options.flags & cpImportProtection) && i < orig_dll_count && (import_function->options() & ioNative) == 0) {
				command = AddCommand(EncryptString(import_function->name().c_str(), string_key));
				command->include_option(roCreateNewBlock);

				import_function_info_list[import_index].loader_name = command;

				if (j > 0)
					continue;
			}

			command = AddCommand(cmDW, IntelOperand(otValue, osWord));
			command->include_option(roCreateNewBlock);
			command->set_alignment(sizeof(uint16_t));

			AddCommand(import_function->name());

			import_function_info_list[import_index].name->link()->set_to_command(command);
			import_function_info_list[import_index].thunk->link()->set_to_command(command);
		}
	}

	// update links for PE structures
	for (i = 0; i < count(); i++) {
		link = item(i)->link();
		if (!link)
			continue;

		link->set_sub_value(file->image_base());
	}

	// create export
	export_entry_ = NULL;
	export_size_ = 0;
	if (ctx.options.flags & cpPack) {
		index = count();
		export_size_ = file->export_list()->WriteToData(*this, file->image_base());
		export_entry_ = (count() == index) ? AddCommand(osDWord, 0) : item(index);
	}

	// create delay import
	delay_import_entry_ = NULL;
	delay_import_size_ = 0;
	if (file->delay_import_list()->count()) {
		std::vector<ImportInfo> delay_import_info;
		PEDelayImport* delay_import;
		PEDelayImportFunction* delay_import_function;

		size_t delay_index = count();
		for (i = 0; i < file->delay_import_list()->count(); i++) {
			delay_import = file->delay_import_list()->item(i);

			index = count();
			AddCommand(osDWord, delay_import->flags());

			import_info.name = AddCommand(osDWord, 0);
			import_info.name->AddLink(0, ltOffset);

			AddCommand(osDWord, delay_import->module());
			AddCommand(osDWord, delay_import->iat());

			import_info.first_thunk = AddCommand(osDWord, 0);
			import_info.first_thunk->AddLink(0, ltOffset);

			AddCommand(osDWord, delay_import->bound_iat());
			AddCommand(osDWord, delay_import->unload_iat());
			AddCommand(osDWord, delay_import->time_stamp());

			for (j = index + 1; j < count() - 1; j++) {
				command = item(j);
				if (delay_import->flags() & 1) {
					if (command->link())
						command->link()->set_sub_value(file->image_base());
					else if (command->operand(0).value)
						command->set_operand_value(0, command->operand(0).value - file->image_base());
				}
				else {
					if (command->link() || command->operand(0).value)
						command->set_operand_fixup(0, NEED_FIXUP);
				}
			}

			delay_import_info.push_back(import_info);
		}

		// end of delay import
		for (j = 0; j < 8; j++) {
			AddCommand(osDWord, 0);
		}

		delay_import_entry_ = item(delay_index);
		delay_import_entry_->include_option(roCreateNewBlock);
		delay_import_entry_->set_alignment(OperandSizeToValue(osDWord));
		delay_import_size_ = static_cast<uint32_t>((count() - delay_index) * sizeof(uint32_t));

		for (i = 0; i < file->delay_import_list()->count(); i++) {
			delay_import = file->delay_import_list()->item(i);

			index = count();
			for (j = 0; j < delay_import->count(); j++) {
				delay_import_function = delay_import->item(j);
				if (delay_import_function->is_ordinal()) {
					command = AddCommand(cpu_address_size(), ordinal_mask | delay_import_function->ordinal());
				}
				else {
					command = AddCommand(cpu_address_size(), 0);
					link = command->AddLink(0, ltOffset);
					if (delay_import->flags() & 1)
						link->set_sub_value(file->image_base());
					else
						command->set_operand_fixup(0, NEED_FIXUP);
				}
			}
			AddCommand(cpu_address_size(), 0);

			command = item(index);
			delay_import_info[i].first_thunk->link()->set_to_command(command);
			delay_import_info[i].original_first_thunk = command;
		}

		for (i = 0; i < file->delay_import_list()->count(); i++) {
			delay_import = file->delay_import_list()->item(i);
			import_info = delay_import_info[i];

			command = AddCommand(delay_import->name());
			command->include_option(roCreateNewBlock);
			import_info.name->link()->set_to_command(command);

			index = IndexOf(import_info.original_first_thunk);
			for (j = 0; j < delay_import->count(); j++) {
				delay_import_function = delay_import->item(j);
				if (delay_import_function->is_ordinal())
					continue;

				command = AddCommand(osWord, 0);
				command->include_option(roCreateNewBlock);
				command->set_alignment(sizeof(uint16_t));
				AddCommand(delay_import_function->name());

				item(index + j)->link()->set_to_command(command);
			}
		}
	}

	// create tls structure
	tls_entry_ = NULL;
	tls_size_ = 0;
	tls_call_back_entry_ = NULL;
	tls_index_address = 0;
	if (file->tls_directory()->address() && (file->tls_directory()->count() || (ctx.options.flags & cpPack))) {
		size_t tls_index = count();

		PETLSDirectory* tls_directory = file->tls_directory();
		if (ctx.options.flags & cpPack) {
			if (file->AddressSeek(tls_directory->address_of_index()) && !file->selected_segment()->excluded_from_packing())
				tls_index_address = tls_directory->address_of_index();
		}

		AddCommand(value_command_type, IntelOperand(otValue, cpu_address_size(), 0, tls_directory->start_address_of_raw_data(), NEED_FIXUP));
		AddCommand(value_command_type, IntelOperand(otValue, cpu_address_size(), 0, tls_directory->end_address_of_raw_data(), NEED_FIXUP));
		AddCommand(value_command_type, IntelOperand(otValue, cpu_address_size(), 0, tls_directory->address_of_index(), NEED_FIXUP));
		IntelCommand* call_back_entry = AddCommand(value_command_type, IntelOperand(otValue, cpu_address_size(), 0, 0));
		AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, tls_directory->size_of_zero_fill()));
		AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, tls_directory->characteristics()));

		tls_entry_ = item(tls_index);
		tls_entry_->include_option(roCreateNewBlock);
		tls_entry_->set_alignment(OperandSizeToValue(cpu_address_size()));
		for (i = tls_index; i < count(); i++) {
			command = item(i);
			tls_size_ += (command->type() == cmDB) ? (uint32_t)command->dump_size() : OperandSizeToValue(command->operand(0).size);
		}

		index = count();
		if (file->tls_directory()->count()) {
			tls_call_back_entry_ = AddCommand(value_command_type, IntelOperand(otValue, cpu_address_size(), 0, 0, NEED_FIXUP));
			tls_call_back_entry_->AddLink(0, ltGateOffset);
		}
		for (i = 0; i < tls_directory->count(); i++) {
			AddCommand(value_command_type, IntelOperand(otValue, cpu_address_size(), 0, tls_directory->item(i)->address(), NEED_FIXUP));
		}
		if (count() > index) {
			AddCommand(value_command_type, IntelOperand(otValue, cpu_address_size(), 0, 0));
			call_back_entry->AddLink(0, ltOffset, item(index));
			call_back_entry->set_operand_fixup(0, NEED_FIXUP);
		}
	}

	// create watermarks
	AddWatermark(ctx.options.watermark, 2);

	// create section list for setting WRITABLE flag
	PESegment* section;
	std::vector<PESegment*> writable_section_list;
	uint64_t address;
	section = file->segment_list()->GetSectionByAddress(loader_data_address);
	if (section)
		writable_section_list.push_back(section);
	for (i = 0; i < orig_dll_count; i++) {
import = new_import_list.item(i);
		for (j = 0; j < import->count(); j++) {
			import_function = import->item(j);
			address = import_function->address();
			if (ctx.options.flags & cpImportProtection) {
				iat_command = intel_import->GetIATCommand(import_function);
				if (iat_command)
					address = iat_command->address();
			}
			section = file->segment_list()->GetSectionByAddress(address);
			if (!section)
				continue;

			if (std::find(writable_section_list.begin(), writable_section_list.end(), section) == writable_section_list.end())
				writable_section_list.push_back(section);
		}
	}

	for (i = 0; i < file->relocation_list()->count(); i++) {
		PERelocation* relocation = file->relocation_list()->item(i);

		section = file->segment_list()->GetSectionByAddress(relocation->address());
		if (!section)
			continue;

		if (std::find(writable_section_list.begin(), writable_section_list.end(), section) == writable_section_list.end())
			writable_section_list.push_back(section);
	}

	std::vector<PackerInfo> packer_info_list;
	PEFixupList loader_fixup_list;
	bool pack_resources = false;
	IntelCommand* packer_props = NULL;
	if (ctx.options.flags & cpPack) {
		PackerInfo packer_info;
		for (i = 0; i < file->segment_list()->count(); i++) {
			section = file->segment_list()->item(i);
			if (section->excluded_from_packing())
				continue;

			bool can_be_packed = true;
			if ((section->memory_type() & (mtWritable | mtShared)) == (mtWritable | mtShared)) {
				can_be_packed = false;
			}

			if (!can_be_packed) {
				//file->Notify(mtWarning, NULL, string_format(language[lsSegmentCanNotBePacked].c_str(), section->name().c_str()));
				continue;
			}

			if (section->physical_size()) {
				packer_info.section = section;
				packer_info.address = section->address();
				packer_info.size = static_cast<size_t>(section->physical_size());
				packer_info.data = NULL;
				packer_info_list.push_back(packer_info);

				// need add packed section into WRITABLE section list
				if (std::find(writable_section_list.begin(), writable_section_list.end(), section) == writable_section_list.end())
					writable_section_list.push_back(section);
			}
		}

		if ((ctx.options.flags & cpStripFixups) == 0) {
			for (i = 0; i < file->fixup_list()->count(); i++) {
				PEFixup* fixup = file->fixup_list()->item(i);
				if (fixup->is_deleted())
					continue;

				section = file->segment_list()->GetSectionByAddress(fixup->address());
				if (!section || std::find(packer_info_list.begin(), packer_info_list.end(), section) == packer_info_list.end())
					continue;

				loader_fixup_list.AddObject(fixup->Clone(&loader_fixup_list));
				fixup->set_deleted(true);

				// need add section into WRITABLE section list
				if (std::find(writable_section_list.begin(), writable_section_list.end(), section) == writable_section_list.end())
					writable_section_list.push_back(section);
			}
		}

		// packing sections
		j = 0;
		for (i = 0; i < packer_info_list.size(); i++) {
			j += packer_info_list[i].size;
		}
		if (file->resource_list()->size() > file->resource_list()->store_size())
			j += file->resource_list()->size() - file->resource_list()->store_size();
		file->StartProgress(string_format("%s...", language[lsPacking].c_str()), j);

		Data data;
		Packer packer;

		if (!packer.WriteProps(&data))
			throw std::runtime_error("Packer error");
		packer_props = AddCommand(data);
		packer_props->include_option(roCreateNewBlock);

		for (i = 0; i < packer_info_list.size(); i++) {
			packer_info = packer_info_list[i];
			if (!file->AddressSeek(packer_info.address))
				return false;

			if (!packer.Code(file, packer_info.size, &data))
				throw std::runtime_error("Packer error");

			command = AddCommand(data);
			command->include_option(roCreateNewBlock);
			packer_info_list[i].data = command;
		}

		if (file->resource_list()->size() > file->resource_list()->store_size()) {
			Data res_data;
			file->resource_list()->WritePackData(res_data);

			if (!packer.Code(file, &res_data, &data))
				return false;

			command = AddCommand(data);
			command->include_option(roCreateNewBlock);

			packer_info.address = 0;
			packer_info.size = res_data.size();
			packer_info.data = command;
			packer_info.section = NULL;
			packer_info_list.push_back(packer_info);
			pack_resources = true;
		}

		// remove packed sections from file
		uint32_t physical_offset = 0;
		for (i = 0; i < file->segment_list()->count(); i++) {
			section = file->segment_list()->item(i);
			if (section->physical_offset() > 0 && section->physical_size() > 0) {
				physical_offset = static_cast<uint32_t>(section->physical_offset());
				break;
			}
		}

		for (i = 0; i < file->segment_list()->count(); i++) {
			section = file->segment_list()->item(i);
			uint32_t physical_size = section->physical_size();
			bool is_packed = false;
			std::vector<PackerInfo>::iterator it = std::find(packer_info_list.begin(), packer_info_list.end(), section);
			if (it != packer_info_list.end()) {
				physical_size = static_cast<uint32_t>(it->address - section->address());
				is_packed = true;
			}

			if (physical_size > 0 && section->physical_offset() != physical_offset) {
				uint8_t* buff = new uint8_t[physical_size];
				file->Seek(section->physical_offset());
				file->Read(buff, physical_size);
				file->Seek(physical_offset);
				file->Write(buff, physical_size);
				delete[] buff;
			}

			section->set_physical_offset(physical_offset);
			section->set_physical_size(physical_size);

			if (is_packed) {
				j = physical_offset + physical_size;
				file->Seek(j);
				physical_offset = (uint32_t)AlignValue(j, file->file_alignment());
				for (k = j; k < physical_offset; k++) {
					file->WriteByte(0);
				}
			}
			else {
				physical_offset += physical_size;
			}
		}
		file->Resize(physical_offset);
	}

	// create packer info for loader
	std::vector<LoaderInfo> loader_info_list;
	index = count();
	if (packer_props) {
		command = AddCommand(cmDD, IntelOperand(otValue, osDWord));
		link = command->AddLink(0, ltOffset, packer_props);
		link->set_sub_value(file->image_base());
		AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, packer_props->dump_size()));

		for (i = 0; i < packer_info_list.size(); i++) {
			command = AddCommand(cmDD, IntelOperand(otValue, osDWord));
			link = command->AddLink(0, ltOffset, packer_info_list[i].data);
			link->set_sub_value(file->image_base());

			AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, packer_info_list[i].address - file->image_base()));
		}
	}
	if (pack_resources) {
		resource_packer_info_ = item(count() - 1);
	}
	else {
		resource_packer_info_ = NULL;
	}
	command = (count() == index) ? NULL : item(index);
	if (command)
		command->include_option(roCreateNewBlock);
	loader_info_list.push_back(LoaderInfo(command, (count() - index) * OperandSizeToValue(osDWord)));

	// create file CRC info for loader
	index = count();
	if (((ctx.options.flags | ctx.options.sdk_flags) & cpMemoryProtection) && file->image_type() != itDriver) {
		AddCommand(cmDD, IntelOperand(otValue, osDWord));
		for (i = 0; i < 10; i++) {
			AddCommand(cmDD, IntelOperand(otValue, osDWord));
			AddCommand(cmDD, IntelOperand(otValue, osDWord));
			AddCommand(cmDD, IntelOperand(otValue, osDWord));
		}
	}
	file_crc_entry_ = (count() == index) ? NULL : item(index);
	if (file_crc_entry_)
		file_crc_entry_->include_option(roCreateNewBlock);
	file_crc_size_ = (uint32_t)((count() - index) * OperandSizeToValue(osDWord));
	loader_info_list.push_back(LoaderInfo(file_crc_entry_, file_crc_size_));

	file_crc_size_entry_ = file_crc_entry_ ? AddCommand(cmDD, IntelOperand(otValue, osDWord)) : NULL;
	if (file_crc_size_entry_)
		file_crc_size_entry_->include_option(roCreateNewBlock);

	// create header and loader CRC info for loader
	index = count();
	if (((ctx.options.flags | ctx.options.sdk_flags) & cpMemoryProtection) || (ctx.options.flags & cpLoaderCRC)) {
		// calc CRC blocks count
		k = 30 + new_import_list.count();
		if ((ctx.options.flags & cpStripFixups) == 0) {
			std::vector<IFunction*> function_list = ctx.file->function_list()->processor_list();
			function_list.push_back(this);
			for (i = 0; i < runtime_function_list->count(); i++) {
				func = runtime_function_list->item(i);
				if (func->tag() != ftLoader)
					continue;

				if (func->compilation_type() == ctMutation)
					function_list.push_back(func);
			}

			for (i = 0; i < function_list.size(); i++) {
				func = reinterpret_cast<IntelFunction*>(function_list[i]);
				for (j = 0; j < func->count(); j++) {
					command = func->item(j);
					for (size_t c = 0; c < 3; c++) {
						IntelOperand operand = command->operand(c);
						if (operand.type == otNone)
							break;
						if (operand.fixup)
							k++;
					}
				}
			}
		}
		for (i = 0; i < k; i++) {
			AddCommand(cmDD, IntelOperand(otValue, osDWord));
			AddCommand(cmDD, IntelOperand(otValue, osDWord));
			AddCommand(cmDD, IntelOperand(otValue, osDWord));
		}
	}
	loader_crc_entry_ = (count() == index) ? NULL : item(index);
	if (loader_crc_entry_)
		loader_crc_entry_->include_option(roCreateNewBlock);
	loader_crc_size_ = static_cast<uint32_t>((count() - index) * OperandSizeToValue(osDWord));
	loader_info_list.push_back(LoaderInfo(loader_crc_entry_, loader_crc_size_));

	loader_crc_size_entry_ = loader_crc_entry_ ? AddCommand(cmDD, IntelOperand(otValue, osDWord)) : NULL;
	if (loader_crc_size_entry_)
		loader_crc_size_entry_->include_option(roCreateNewBlock);
	loader_crc_hash_entry_ = loader_crc_entry_ ? AddCommand(cmDD, IntelOperand(otValue, osDWord)) : NULL;
	if (loader_crc_hash_entry_)
		loader_crc_hash_entry_->include_option(roCreateNewBlock);

	// create section info for loader
	bool skip_writable_sections = (file->image_type() != itDriver);
	index = count();
	for (i = 0; i < writable_section_list.size(); i++) {
		section = writable_section_list[i];
		if (skip_writable_sections && section->memory_type() & mtWritable)
			continue;

		AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, section->address() - file->image_base()));
		AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, section->size()));
		AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, section->flags()));
	}
	// add runtime's WRITABLE sections
	for (i = 0; i < runtime->segment_list()->count(); i++) {
		section = runtime->segment_list()->item(i);
		if (section->memory_type() & mtWritable) {
			AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, section->address() - file->image_base()));
			AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, section->size()));
			AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, section->flags()));
		}
	}
	if (pack_resources) {
		resource_section_info_ = AddCommand(cmDD, IntelOperand(otValue, osDWord));
		AddCommand(cmDD, IntelOperand(otValue, osDWord));
		AddCommand(cmDD, IntelOperand(otValue, osDWord));
	}
	else {
		resource_section_info_ = NULL;
	}
	command = (count() == index) ? NULL : item(index);
	if (command)
		command->include_option(roCreateNewBlock);
	loader_info_list.push_back(LoaderInfo(command, (count() - index) * OperandSizeToValue(osDWord)));

	// create fixup info for loader
	if (loader_fixup_list.count() > 0) {
		Data data;
		loader_fixup_list.WriteToData(data, file->image_base());
		command = AddCommand(data);
	}
	else {
		command = NULL;
	}
	if (command)
		command->include_option(roCreateNewBlock);
	loader_info_list.push_back(LoaderInfo(command, (command) ? command->dump_size() : 0));

	// create relocation info for loader
	if (file->relocation_list()->count() > 0) {
		Data data;
		file->relocation_list()->WriteToData(data, file->image_base());
		command = AddCommand(data);
	}
	else {
		command = NULL;
	}
	if (command)
		command->include_option(roCreateNewBlock);
	loader_info_list.push_back(LoaderInfo(command, (command) ? command->dump_size() : 0));

	// create IAT info for loader
	index = count();
	for (i = 0, import_index = 0; i < orig_dll_count; i++) {
import = new_import_list.item(i);
		if (import->count() == 0)
			continue;

		if (ctx.options.flags & cpImportProtection) {
			for (j = 0; j < import->count(); j++, import_index++) {
				import_function = import->item(j);
				if ((import_function->options() & ioNative) == 0)
					continue;

				iat_command = intel_import->GetIATCommand(import_function);

				command = AddCommand(cmDD, IntelOperand(otValue, osDWord));
				link = command->AddLink(0, ltOffset, import_function_info_list[import_index].thunk);
				link->set_sub_value(file->image_base());

				AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, ((iat_command) ? iat_command->address() : import_function->address()) - file->image_base()));
				AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, OperandSizeToValue(cpu_address_size())));
			}
		}
		else {
			import_function = import->item(0);
			command = AddCommand(cmDD, IntelOperand(otValue, osDWord));
			link = command->AddLink(0, ltOffset, import_function_info_list[import_index].thunk);
			link->set_sub_value(file->image_base());

			AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, import_function->address() - file->image_base()));
			AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, import->count() * OperandSizeToValue(cpu_address_size())));

			import_index += import->count();
		}
	}
	if (security_cookie_) {
		AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, security_cookie_ - file->image_base()));
		AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, file->load_config_directory()->security_cookie() - file->image_base()));
		AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, OperandSizeToValue(cpu_address_size())));
	}
	command = (count() == index) ? NULL : item(index);
	if (command)
		command->include_option(roCreateNewBlock);
	loader_info_list.push_back(LoaderInfo(command, (count() - index) * OperandSizeToValue(osDWord)));

	// create import info for loader
	index = count();
	if (ctx.options.flags & cpImportProtection) {
		for (i = 0, import_index = 0; i < orig_dll_count; i++) {
import = new_import_list.item(i);
			if (import->count() == 0)
				continue;

			if (import_info_list[i].name == NULL) {
				// delay import
				import_index += import->count();
				continue;
			}

			// DLL name
			command = AddCommand(cmDD, IntelOperand(otValue, osDWord));
			link = command->AddLink(0, ltOffset, import_info_list[i].loader_name);
			link->set_sub_value(file->image_base());

			for (j = 0; j < import->count(); j++, import_index++) {
				import_function = import->item(j);
				if (import_function->options() & ioNative)
					continue;

				if (import_function->IsInternal(ctx))
					continue;

				iat_command = intel_import->GetIATCommand(import_function);

				// API name
				if (import_function->is_ordinal()) {
					AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, IMAGE_ORDINAL_FLAG32 | import_function->ordinal()));
				}
				else {
					command = AddCommand(cmDD, IntelOperand(otValue, osDWord));
					link = command->AddLink(0, ltOffset, import_function_info_list[import_index].loader_name);
					link->set_sub_value(file->image_base());
				}

				// IAT
				AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, ((iat_command) ? iat_command->address() : import_function->address()) - file->image_base()));

				// decrypt value
				AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, (iat_command) ? iat_command->operand(1).value : 0));
			}

			// end of DLL
			AddCommand(cmDD, IntelOperand(otValue, osDWord));
		}
	}
	command = (count() == index) ? NULL : item(index);
	if (command)
		command->include_option(roCreateNewBlock);
	loader_info_list.push_back(LoaderInfo(command, (count() - index) * OperandSizeToValue(osDWord)));

	// create internal import info for loader
	index = count();
	for (i = 0; i < orig_dll_count; i++) {
import = new_import_list.item(i);
		for (j = 0; j < import->count(); j++) {
			import_function = import->item(j);

			if (!import_function->IsInternal(ctx))
				continue;

			iat_command = (intel_import) ? intel_import->GetIATCommand(import_function) : NULL;

			address = runtime->export_list()->GetAddressByType(import_function->type());
			func = reinterpret_cast<IntelFunction*>(file->function_list()->GetFunctionByAddress(address));
			if (func && func->entry())
				address = func->entry()->address();

			// address
			AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, address - file->image_base()));
			// IAT
			AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, ((iat_command) ? iat_command->address() : import_function->address()) - file->image_base()));
			// decrypt value
			AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, (iat_command) ? iat_command->operand(1).value : 0));
		}
	}
	command = (count() == index) ? NULL : item(index);
	if (command)
		command->include_option(roCreateNewBlock);
	loader_info_list.push_back(LoaderInfo(command, (count() - index) * OperandSizeToValue(osDWord)));

	// create memory CRC info for loader
	if (intel_crc) {
		command = intel_crc->table_entry();
		i = static_cast<size_t>(intel_crc->size_entry()->operand(0).value);
	}
	else {
		command = NULL;
		i = 0;
	}
	loader_info_list.push_back(LoaderInfo(command, i));

	// create delay import info for loader
	index = count();
	for (i = 0, import_index = 0; i < orig_dll_count; i++) {
import = new_import_list.item(i);
		if (import->count() == 0)
			continue;

		if (import_info_list[i].name) {
			import_index += import->count();
			continue;
		}

		// DLL name
		command = AddCommand(cmDD, IntelOperand(otValue, osDWord));
		link = command->AddLink(0, ltOffset, import_info_list[i].loader_name);
		link->set_sub_value(file->image_base());

		for (j = 0; j < import->count(); j++, import_index++) {
			import_function = import->item(j);
			if (import_function->options() & ioNative)
				continue;

			if (import_function->IsInternal(ctx))
				continue;

			iat_command = (intel_import) ? intel_import->GetIATCommand(import_function) : NULL;

			// API name
			if (import_function->is_ordinal()) {
				AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, IMAGE_ORDINAL_FLAG32 | import_function->ordinal()));
			}
			else {
				command = AddCommand(cmDD, IntelOperand(otValue, osDWord));
				link = command->AddLink(0, ltOffset, import_function_info_list[import_index].loader_name);
				link->set_sub_value(file->image_base());
			}

			// IAT
			AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, ((iat_command) ? iat_command->address() : import_function->address()) - file->image_base()));

			// decrypt value
			AddCommand(cmDD, IntelOperand(otValue, osDWord, 0, (iat_command) ? iat_command->operand(1).value : 0));
		}

		// end of DLL
		AddCommand(cmDD, IntelOperand(otValue, osDWord));
	}
	command = (count() == index) ? NULL : item(index);
	if (command)
		command->include_option(roCreateNewBlock);
	loader_info_list.push_back(LoaderInfo(command, (count() - index) * OperandSizeToValue(osDWord)));

	// create strings for loader
	std::map<uint32_t, IntelCommand*> loader_string_list;
	loader_string_list[FACE_FILE_CORRUPTED] = AddCommand(EncryptString((ctx.options.flags & cpMemoryProtection) ? os::FromUTF8(ctx.options.messages[MESSAGE_FILE_CORRUPTED]).c_str() : os::unicode_string().c_str(), string_key));
	loader_string_list[FACE_DEBUGGER_FOUND] = AddCommand(EncryptString(os::FromUTF8(ctx.options.messages[MESSAGE_DEBUGGER_FOUND]).c_str(), string_key));
	loader_string_list[FACE_VIRTUAL_MACHINE_FOUND] = AddCommand(EncryptString(os::FromUTF8(ctx.options.messages[MESSAGE_VIRTUAL_MACHINE_FOUND]).c_str(), string_key));
	loader_string_list[FACE_INITIALIZATION_ERROR] = AddCommand(EncryptString(os::FromUTF8("Initialization error %d").c_str(), string_key));
	VMProtectBeginVirtualization("Loader Strings");
	loader_string_list[FACE_UNREGISTERED_VERSION] = AddCommand(EncryptString(os::unicode_string().c_str(), string_key));
	VMProtectEnd();
	loader_string_list[FACE_SICE_NAME] = AddCommand(EncryptString("sice.sys", string_key));
	loader_string_list[FACE_SIWVID_NAME] = AddCommand(EncryptString("siwvid.sys", string_key));
	loader_string_list[FACE_NTICE_NAME] = AddCommand(EncryptString("ntice.sys", string_key));
	loader_string_list[FACE_ICEEXT_NAME] = AddCommand(EncryptString("iceext.sys", string_key));
	loader_string_list[FACE_SYSER_NAME] = AddCommand(EncryptString("syser.sys", string_key));
	if (file->image_type() == itDriver) {
		loader_string_list[FACE_PROC_NOT_FOUND] = AddCommand(EncryptString(os::FromUTF8("The procedure entry point %c could not be located in the module %c").c_str(), string_key));
		loader_string_list[FACE_ORDINAL_NOT_FOUND] = AddCommand(EncryptString(os::FromUTF8("The ordinal %d could not be located in the module %c").c_str(), string_key));
		loader_string_list[FACE_DRIVER_FORMAT_VALUE] = AddCommand("%ws\n");
		loader_string_list[FACE_NTOSKRNL_NAME] = AddCommand(EncryptString("ntoskrnl.exe", string_key));
		loader_string_list[FACE_HAL_NAME] = AddCommand(EncryptString("hal.dll", string_key));
	}
	else {
		loader_string_list[FACE_PROC_NOT_FOUND] = AddCommand(EncryptString(os::FromUTF8("The procedure entry point %c could not be located in the dynamic link library %c").c_str(), string_key));
		loader_string_list[FACE_ORDINAL_NOT_FOUND] = AddCommand(EncryptString(os::FromUTF8("The ordinal %d could not be located in the dynamic link library %c").c_str(), string_key));
		loader_string_list[FACE_USER32_NAME] = AddCommand(EncryptString("user32.dll", string_key));
		loader_string_list[FACE_MESSAGE_BOX_NAME] = AddCommand(EncryptString("MessageBoxW", string_key));
		loader_string_list[FACE_KERNEL32_NAME] = AddCommand(EncryptString("kernel32.dll", string_key));
		loader_string_list[FACE_CLOSE_HANDLE_NAME] = AddCommand(EncryptString("CloseHandle", string_key));
		loader_string_list[FACE_IS_WOW64_PROCESS_NAME] = AddCommand(EncryptString("IsWow64Process", string_key));
		loader_string_list[FACE_WINE_GET_VERSION_NAME] = AddCommand(EncryptString("wine_get_version", string_key));
		loader_string_list[FACE_WTSAPI32_NAME] = AddCommand(EncryptString("wtsapi32.dll", string_key));
		loader_string_list[FACE_WTS_SEND_MESSAGE_NAME] = AddCommand(EncryptString("WTSSendMessageW", string_key));
		loader_string_list[FACE_NTDLL_NAME] = AddCommand(EncryptString("ntdll.dll", string_key));
		loader_string_list[FACE_NT_QUERY_INFORMATION_NAME] = AddCommand(EncryptString("NtQuerySystemInformation", string_key));
		loader_string_list[FACE_NT_SET_INFORMATION_THREAD_NAME] = AddCommand(EncryptString("NtSetInformationThread", string_key));
		loader_string_list[FACE_NT_QUERY_INFORMATION_PROCESS_NAME] = AddCommand(EncryptString("NtQueryInformationProcess", string_key));
		loader_string_list[FACE_SBIEDLL_NAME] = AddCommand(EncryptString("sbiedll.dll", string_key));
		loader_string_list[FACE_QUERY_VIRTUAL_MEMORY_NAME] = AddCommand(EncryptString("NtQueryVirtualMemory", string_key));
		loader_string_list[FACE_ENUM_SYSTEM_FIRMWARE_NAME] = AddCommand(EncryptString("EnumSystemFirmwareTables", string_key));
		loader_string_list[FACE_GET_SYSTEM_FIRMWARE_NAME] = AddCommand(EncryptString("GetSystemFirmwareTable", string_key));
		loader_string_list[FACE_NT_VIRTUAL_PROTECT_NAME] = AddCommand(EncryptString("NtProtectVirtualMemory", string_key));
		loader_string_list[FACE_NT_OPEN_FILE_NAME] = AddCommand(EncryptString("NtOpenFile", string_key));
		loader_string_list[FACE_NT_CREATE_SECTION_NAME] = AddCommand(EncryptString("NtCreateSection", string_key));
		loader_string_list[FACE_NT_OPEN_SECTION_NAME] = AddCommand(EncryptString("NtOpenSection", string_key));
		loader_string_list[FACE_NT_MAP_VIEW_OF_SECTION] = AddCommand(EncryptString("NtMapViewOfSection", string_key));
		loader_string_list[FACE_NT_UNMAP_VIEW_OF_SECTION] = AddCommand(EncryptString("NtUnmapViewOfSection", string_key));
		loader_string_list[FACE_NT_CLOSE] = AddCommand(EncryptString("NtClose", string_key));
		loader_string_list[FACE_NT_SET_INFORMATION_PROCESS_NAME] = AddCommand(EncryptString("NtSetInformationProcess", string_key));
		loader_string_list[FACE_NT_RAISE_HARD_ERROR_NAME] = AddCommand(EncryptString("NtRaiseHardError", string_key));
	}
	for (std::map<uint32_t, IntelCommand*>::const_iterator it = loader_string_list.begin(); it != loader_string_list.end(); it++) {
		it->second->include_option(roCreateNewBlock);
	}

	cfg_check_function_entry_ = NULL;
	if (file->load_config_directory()->cfg_check_function()) {
		// work around check in LdrpCfgProcessLoadConfig
		PESegment* segment = file->segment_list()->GetSectionByAddress(file->load_config_directory()->cfg_check_function());
		if (segment && std::find(packer_info_list.begin(), packer_info_list.end(), segment) != packer_info_list.end()) {
			CommandBlock* block = AddBlock(count(), true);
			cfg_check_function_entry_ = AddCommand(value_command_type, IntelOperand(otValue, cpu_address_size(), 0, file->load_config_directory()->cfg_check_function(), NEED_FIXUP));
			cfg_check_function_entry_->set_block(block);
		}
	}

	// append loader
	old_count = count();
	std::vector<IntelCommand*> internal_entry_list;
	for (size_t n = 0; n < 2; n++) {
		for (i = 0; i < runtime_function_list->count(); i++) {
			func = runtime_function_list->item(i);
			if (func->tag() != ftLoader)
				continue;

			if (func->compilation_type() == ctMutation) {
				if (n != 0)
					continue;
			}
			else {
				if (n != 1)
					continue;
			}

			func->Init(ctx);

			size_t orig_function_info_count = function_info_list()->count();
			for (j = 0; j < func->function_info_list()->count(); j++) {
				FunctionInfo* info = func->function_info_list()->item(j);
				function_info_list()->AddObject(info->Clone(function_info_list()));
			}
			for (j = 0; j < func->range_list()->count(); j++) {
				AddressRange* range = func->range_list()->item(j);
				range_list()->AddObject(range->Clone(range_list()));
			}

			bool is_internal = (func->compilation_type() != ctMutation && func->entry_type() == etNone);
			for (j = 0; j < func->link_list()->count(); j++) {
				src_link = func->link_list()->item(j);
				if (src_link->type() != ltMemSEHBlock)
					continue;

				src_link->from_command()->set_address(0);
				if (!is_internal || (src_link->from_command()->options() & roExternal) == 0)
					continue;

				src_command = func->GetCommandByAddress(src_link->to_address());
				if (!src_command)
					continue;

				for (k = func->IndexOf(src_command); k < func->count(); k++) {
					src_command = func->item(k);
					if (src_command->type() == cmRet) {
						src_command->include_option(roExternal);
						break;
					}
				}
			}

			for (j = 0; j < func->count(); j++) {
				src_command = func->item(j);
				dst_command = src_command->Clone(this);
				AddressRange* address_range = src_command->address_range();
				if (address_range) {
					FunctionInfo* info = function_info_list()->item(orig_function_info_count + func->function_info_list()->IndexOf(address_range->owner()));
					dst_command->set_address_range(info->item(address_range->owner()->IndexOf(address_range)));
				}

				AddObject(dst_command);
				if (is_internal) {
					if (j == 0)
						internal_entry_list.push_back(dst_command);
					if (dst_command->type() == cmRet && (dst_command->options() & roExternal) == 0)
						dst_command->include_option(roInternal);
				}

				src_link = src_command->link();
				if (src_link) {
					dst_link = src_link->Clone(link_list());
					dst_link->set_from_command(dst_command);
					link_list()->AddObject(dst_link);

					if (src_link->parent_command())
						dst_link->set_parent_command(GetCommandByAddress(src_link->parent_command()->address()));
				}

				std::map<uint64_t, PEImportFunction*>::const_iterator it_import = runtime_info_list.find(dst_command->address());
				if (it_import != runtime_info_list.end()) {
					if (dst_command->type() == cmCall) {
						IntelOperand operand = dst_command->operand(0);
						dst_command->Init(cmMov, IntelOperand(otRegistr, operand.size, regEAX), operand);

						command = new IntelCommand(this, cpu_address_size(), cmCall, IntelOperand(otRegistr, operand.size, regEAX));
						if (dst_command->link())
							dst_command->link()->set_from_command(command);
						AddObject(command);
					}
					dst_link = dst_command->AddLink((dst_command->operand(1).type != otNone) ? 1 : 0, ltOffset);
					std::vector<ImportFunctionInfo>::iterator it = std::find(import_function_info_list.begin(), import_function_info_list.end(), it_import->second);
					if (it != import_function_info_list.end())
						dst_link->set_to_command(it->thunk);
				}

				command = dst_command;
				for (k = 0; k < 3; k++) {
					IntelOperand operand = command->operand(k);
					if (operand.type == otNone)
						break;

					if ((operand.type & otValue) == 0)
						continue;

					if ((operand.value & 0xFFFF0000) == 0xFACE0000) {
						switch (static_cast<uint32_t>(operand.value)) {
						case FACE_LOADER_OPTIONS:
							operand.value = 0;
							if (ctx.options.flags & cpMemoryProtection)
								operand.value |= LOADER_OPTION_CHECK_PATCH;
							if (ctx.options.flags & cpCheckDebugger)
								operand.value |= LOADER_OPTION_CHECK_DEBUGGER;
							if (ctx.options.flags & cpCheckKernelDebugger)
								operand.value |= LOADER_OPTION_CHECK_KERNEL_DEBUGGER;
							if (ctx.options.flags & cpCheckVirtualMachine)
								operand.value |= LOADER_OPTION_CHECK_VIRTUAL_MACHINE;
							if (file->image_type() == itExe)
								operand.value |= LOADER_OPTION_EXIT_PROCESS;
							command->set_operand_value(k, operand.value);
							command->CompileToNative();
							break;
						case FACE_LOADER_DATA:
							command->set_operand_value(k, loader_data_address - file->image_base());
							command->CompileToNative();
							break;
						case FACE_RUNTIME_ENTRY:
							command->set_operand_value(k, runtime->segment_list()->count() ? runtime->entry_point() - file->image_base() : 0);
							command->CompileToNative();
							break;
						case FACE_STRING_DECRYPT_KEY:
							command->set_operand_value(k, string_key);
							command->CompileToNative();
							break;
						case FACE_PACKER_INFO:
						case FACE_FILE_CRC_INFO:
						case FACE_LOADER_CRC_INFO:
						case FACE_SECTION_INFO:
						case FACE_FIXUP_INFO:
						case FACE_RELOCATION_INFO:
						case FACE_IAT_INFO:
						case FACE_IMPORT_INFO:
						case FACE_INTERNAL_IMPORT_INFO:
						case FACE_MEMORY_CRC_INFO:
						case FACE_DELAY_IMPORT_INFO:
							dst_command = loader_info_list[(operand.value & 0xff) >> 1].data;
							if (dst_command) {
								link = command->AddLink((int)k, ltOffset, dst_command);
								link->set_sub_value(file->image_base());
							}
							else {
								command->set_operand_value(k, 0);
								command->CompileToNative();
							}
							break;
						case FACE_PACKER_INFO_SIZE:
						case FACE_SECTION_INFO_SIZE:
						case FACE_FIXUP_INFO_SIZE:
						case FACE_RELOCATION_INFO_SIZE:
						case FACE_IAT_INFO_SIZE:
						case FACE_IMPORT_INFO_SIZE:
						case FACE_INTERNAL_IMPORT_INFO_SIZE:
						case FACE_MEMORY_CRC_INFO_SIZE:
						case FACE_DELAY_IMPORT_INFO_SIZE:
							command->set_operand_value(k, loader_info_list[(operand.value & 0xff) >> 1].size);
							command->CompileToNative();
							break;
						case FACE_LOADER_CRC_INFO_SIZE:
							if (loader_crc_size_entry_) {
								link = command->AddLink((int)k, ltOffset, loader_crc_size_entry_);
								link->set_sub_value(file->image_base());
							}
							else {
								command->set_operand_value(k, 0);
								command->CompileToNative();
							}
							break;
						case FACE_LOADER_CRC_INFO_HASH:
							if (loader_crc_hash_entry_) {
								link = command->AddLink((int)k, ltOffset, loader_crc_hash_entry_);
								link->set_sub_value(file->image_base());
							}
							else {
								command->set_operand_value(k, 0);
								command->CompileToNative();
							}
							break;
						case FACE_FILE_CRC_INFO_SIZE:
							if (file_crc_size_entry_) {
								link = command->AddLink((int)k, ltOffset, file_crc_size_entry_);
								link->set_sub_value(file->image_base());
							}
							else {
								command->set_operand_value(k, 0);
								command->CompileToNative();
							}
							break;
						case FACE_MEMORY_CRC_INFO_HASH:
							command->set_operand_value(k, intel_crc ? intel_crc->hash_entry()->operand(0).value : 0);
							command->CompileToNative();
							break;
						case FACE_CRC_INFO_SALT:
							command->set_operand_value(k, file->function_list()->crc_cryptor()->item(0)->value());
							command->CompileToNative();
							break;
						case FACE_IMAGE_BASE:
							if (command->operand(0).size != cpu_address_size()) {
								IntelOperand first = command->operand(0);
								IntelOperand second = command->operand(1);
								first.size = cpu_address_size();
								second.size = cpu_address_size();
								command->Init(static_cast<IntelCommandType>(command->type()), first, second);
							}
							command->set_operand_value(k, file->image_base());
							command->set_operand_fixup(k, NEED_FIXUP);
							command->CompileToNative();
							break;
						case FACE_FILE_BASE:
							if (command->operand(0).size != cpu_address_size()) {
								IntelOperand first = command->operand(0);
								IntelOperand second = command->operand(1);
								first.size = cpu_address_size();
								second.size = cpu_address_size();
								command->Init(static_cast<IntelCommandType>(command->type()), first, second);
							}
							command->set_operand_value(k, file->image_base());
							command->CompileToNative();
							break;
						case FACE_TLS_INDEX_INFO:
							command->set_operand_value(k, tls_index_address ? tls_index_address - file->image_base() : 0);
							command->CompileToNative();
							break;
						case FACE_VAR_IS_PATCH_DETECTED:
						case FACE_VAR_IS_DEBUGGER_DETECTED:
						case FACE_VAR_LOADER_CRC_INFO:
						case FACE_VAR_LOADER_CRC_INFO_SIZE:
						case FACE_VAR_LOADER_CRC_INFO_HASH:
						case FACE_VAR_CPU_HASH:
						case FACE_VAR_CPU_COUNT:
						case FACE_VAR_SESSION_KEY:
						case FACE_VAR_DRIVER_UNLOAD:
						case FACE_VAR_CRC_IMAGE_SIZE:
						case FACE_VAR_LOADER_STATUS:
						case FACE_VAR_SERVER_DATE:
						case FACE_VAR_OS_BUILD_NUMBER:
							command->set_operand_value(k, ctx.runtime_var_index[(operand.value & 0xff) >> 4] * OperandSizeToValue(cpu_address_size()));
							command->CompileToNative();
							break;
						case FACE_VAR_IS_PATCH_DETECTED_SALT:
						case FACE_VAR_IS_DEBUGGER_DETECTED_SALT:
						case FACE_VAR_LOADER_CRC_INFO_SALT:
						case FACE_VAR_LOADER_CRC_INFO_SIZE_SALT:
						case FACE_VAR_LOADER_CRC_INFO_HASH_SALT:
						case FACE_VAR_CPU_HASH_SALT:
						case FACE_VAR_CPU_COUNT_SALT:
						case FACE_VAR_DRIVER_UNLOAD_SALT:
						case FACE_VAR_CRC_IMAGE_SIZE_SALT:
						case FACE_VAR_SERVER_DATE_SALT:
						case FACE_VAR_OS_BUILD_NUMBER_SALT:
							command->set_operand_value(k, ctx.runtime_var_salt[operand.value & 0xff]);
							command->CompileToNative();
							break;
						default:
							std::map<uint32_t, IntelCommand*>::const_iterator it = loader_string_list.find(static_cast<uint32_t>(operand.value));
							if (it != loader_string_list.end()) {
								if (command->type() == cmMov) {
									operand = command->operand(0);
									operand.size = cpu_address_size();
									if (operand.type == otRegistr) {
										command->Init(cmLea, operand, IntelOperand(otMemory | otValue, cpu_address_size(), 0, 0, (cpu_address_size() == osDWord) ? NEED_FIXUP : LARGE_VALUE));
									}
									else {
										command->Init(cmMov, operand, IntelOperand(otValue, cpu_address_size(), 0, 0, NEED_FIXUP));
									}
								}
								else {
									command->Init(cmPush, IntelOperand(otValue, cpu_address_size(), 0, 0, NEED_FIXUP));
								}
								command->AddLink((int)k, ltOffset, it->second);
							}
							else {
								throw std::runtime_error(string_format("Unknown loader string: %X", static_cast<uint32_t>(operand.value)));
							}
						}
					}
				}
			}
		}
		if (n == 0) {
			// create native blocks
			for (j = 0; j < count(); j++) {
				item(j)->include_option(roNoProgress);
			}
			CompileToNative(ctx);
			for (j = 0; j < count(); j++) {
				item(j)->exclude_option(roNoProgress);
			}
		}
	}
	for (i = 0; i < function_info_list()->count(); i++) {
		FunctionInfo* info = function_info_list()->item(i);
		if (info->entry())
			info->set_entry(GetCommandByAddress(info->entry()->address()));
		for (j = 0; j < info->count(); j++) {
			AddressRange* dest = info->item(j);
			for (k = 0; k < range_list()->count(); k++) {
				AddressRange* range = range_list()->item(k);
				if (range->begin() <= dest->begin() && range->end() > dest->begin())
					dest->AddLink(range);
			}
		}
	}
	for (i = 0; i < range_list()->count(); i++) {
		AddressRange* range = range_list()->item(i);
		if (range->begin_entry())
			range->set_begin_entry(GetCommandByAddress(range->begin_entry()->address()));
		if (range->end_entry())
			range->set_end_entry(GetCommandByAddress(range->end_entry()->address()));
		if (range->size_entry())
			range->set_size_entry(GetCommandByAddress(range->size_entry()->address()));
	}
	for (i = old_count; i < count(); i++) {
		command = item(i);
		dst_link = command->link();
		if (!dst_link) {
			// search references to LoaderAlloc/LoaderFree/FreeImage
			for (k = 0; k < 2; k++) {
				IntelOperand operand = command->operand(k);
				if (operand.type == otNone)
					break;

				if (cpu_address_size() == osDWord) {
					if (!operand.fixup)
						continue;
				}
				else {
					if (!operand.is_large_value)
						continue;
				}

				dst_command = reinterpret_cast<IntelCommand*>(GetCommandByAddress(operand.value));
				if (dst_command) {
					dst_link = command->AddLink((int)k, dst_command->block() ? ltOffset : ltGateOffset, dst_command);
					break;
				}
			}
		}
		else {
			if (dst_link->to_address())
				dst_link->set_to_command(GetCommandByAddress(dst_link->to_address()));
		}
	}
	setup_image_entry = GetCommandByAddress(runtime->export_list()->GetAddressByType(atSetupImage));
	if (!setup_image_entry)
		return false;

	free_image_entry = GetCommandByAddress(runtime->export_list()->GetAddressByType(atFreeImage));
	if (!free_image_entry)
		return false;

	/*
	BOOL LoaderDllMain(HANDLE module, DWORD reason, LPVOID reserved)
	{
		BOOL status;
		if (reason == DLL_PROCESS_ATTACH) {
			status = SetupImage();
			if (status == TRUE) {
				status = DllMain(module, reason, reserved);
			} else {
				FreeImage();
			}
		} else {
			status = DllMain(module, reason, reserved);
			if (reason == DLL_PROCESS_DETACH)
				FreeImage();
		}
		return status;
	}

	NTSTATUS LoaderDriverEntry(driver_object, registry_path)
	{
		NTSTATUS status = SetupImage(true, driver_object);
		if (status == STATUS_SUCCESS) {
			status = DriverEntry(driver_object, registry_path);
			if (status == STATUS_SUCCESS) {
				SetupImage(false, driver_object);
			} else {
				FreeImage(driver_object);
			}
		} else {
			FreeImage(driver_object);
		}
		return status;
	}
	*/

	// create entry commands
	std::vector<IntelCommand*> end_command_list;
	old_count = count();
	size_t stack = 0x20;
	if (file->image_type() != itExe && cpu_address_size() == osQWord) {
		AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regESP, OperandSizeToValue(cpu_address_size()) * 1), IntelOperand(otRegistr, cpu_address_size(), regECX));
		AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regESP, OperandSizeToValue(cpu_address_size()) * 2), IntelOperand(otRegistr, cpu_address_size(), regEDX));
		AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regESP, OperandSizeToValue(cpu_address_size()) * 3), IntelOperand(otRegistr, cpu_address_size(), regR8));
	}
	AddCommand(cmPush, IntelOperand(otRegistr, cpu_address_size(), regEBP));
	if (cpu_address_size() == osDWord) {
		AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size(), regESP), IntelOperand(otValue, cpu_address_size(), 0, stack));
		AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regEBP), IntelOperand(otRegistr, cpu_address_size(), regESP));
	}
	else {
		AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size(), regEBP), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regESP, 0 - static_cast<uint64_t>(stack)));
		AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size(), regESP), IntelOperand(otValue, cpu_address_size(), 0, stack + 0x20));
	}

	IntelCommand* skip_loader_command = NULL;
	if (file->image_type() == itLibrary) {
		// check DLL_PROCESS_ATTACH
		AddCommand(cmCmp, IntelOperand(otMemory | otRegistr | otValue, osDWord, regEBP, stack + OperandSizeToValue(cpu_address_size()) * 3), IntelOperand(otValue, osDWord, 0, DLL_PROCESS_ATTACH));
		skip_loader_command = AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size()));
		skip_loader_command->set_flags(fl_Z);
		skip_loader_command->include_option(roInverseFlag);
		skip_loader_command->AddLink(0, ltJmpWithFlag);
	}

	// call SetupImage
	if (file->image_type() == itDriver) {
		if (cpu_address_size() == osQWord) {
			AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regEDX), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP, stack + OperandSizeToValue(cpu_address_size()) * 2));
			AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otValue, osDWord, 0, true));
		}
		else {
			AddCommand(cmPush, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP, stack + OperandSizeToValue(cpu_address_size()) * 2));
			AddCommand(cmPush, IntelOperand(otValue, cpu_address_size(), 0, true));
		}
	}
	command = AddCommand(cmCall, IntelOperand(otValue, cpu_address_size()));
	command->AddLink(0, ltCall, setup_image_entry);

	// check loader error code
	AddCommand(cmCmp, IntelOperand(otRegistr, osDWord, regEAX), IntelOperand(otValue, osDWord, 0, (file->image_type() == itDriver) ? 0 : TRUE));
	IntelCommand* check_loader_command = AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size()));
	check_loader_command->set_flags(fl_Z);
	check_loader_command->AddLink(0, ltJmpWithFlag);

	switch (file->image_type()) {
	case itExe:
		// call FreeImage
		command = AddCommand(cmCall, IntelOperand(otValue, cpu_address_size()));
		command->AddLink(0, ltCall, free_image_entry);

		// need convert FALSE into exit code
		AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regEAX), IntelOperand(otValue, osDWord, 0, 0xDEADC0DE));
		break;
	case itLibrary:
		// do nothing
		break;
	case itDriver:
		AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP), IntelOperand(otRegistr, cpu_address_size(), regEAX));

		// call FreeImage
		if (cpu_address_size() == osQWord) {
			AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regECX), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP, stack + OperandSizeToValue(cpu_address_size()) * 2));
		}
		else {
			AddCommand(cmPush, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP, stack + OperandSizeToValue(cpu_address_size()) * 2));
		}
		command = AddCommand(cmCall, IntelOperand(otValue, cpu_address_size()));
		command->AddLink(0, ltCall, free_image_entry);

		AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regEAX), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP));
		break;
	}

	command = AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size()));
	command->AddLink(0, ltJmp);
	end_command_list.push_back(command);

	command = AddCommand(cmNop);
	check_loader_command->link()->set_to_command(command);
	if (skip_loader_command)
		skip_loader_command->link()->set_to_command(command);

	// call file EntryPoint
	IntelCommand* jmp_entry_point_command = NULL;
	if (file->entry_point()) {
		switch (file->image_type()) {
		case itExe:
			AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size(), regESP), IntelOperand(otValue, cpu_address_size(), 0, stack + ((cpu_address_size() == osQWord) ? 0x20 : 0)));
			AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size(), regEBP));
			jmp_entry_point_command = AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size(), 0, file->entry_point()));
			jmp_entry_point_command->AddLink(0, ltJmp, file->entry_point());
			break;

		case itLibrary:
		{
			// check loader status
			AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regEAX), IntelOperand(otMemory | otValue, cpu_address_size(), 0, loader_data_address, (cpu_address_size() == osDWord) ? NEED_FIXUP : LARGE_VALUE));
			AddCommand(cmOr, IntelOperand(otRegistr, cpu_address_size(), regEAX), IntelOperand(otRegistr, cpu_address_size(), regEAX));
			IntelCommand* jmp_command = AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size()));
			jmp_command->set_flags(fl_Z);
			jmp_command->AddLink(0, ltJmpWithFlag);

			AddCommand(cmCmp, IntelOperand(otMemory | otRegistr | otValue, osDWord, regEAX, ctx.runtime_var_index[VAR_LOADER_STATUS] * OperandSizeToValue(cpu_address_size())), IntelOperand(otValue, osDWord, 0, TRUE));
			IntelCommand* jmp_status_command = AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size()));
			jmp_status_command->set_flags(fl_Z);
			jmp_status_command->include_option(roInverseFlag);
			jmp_status_command->AddLink(0, ltJmpWithFlag);

			// call EntryPoint
			if (cpu_address_size() == osQWord) {
				AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regR8), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP, stack + OperandSizeToValue(cpu_address_size()) * 4));
				AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regEDX), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP, stack + OperandSizeToValue(cpu_address_size()) * 3));
				AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regECX), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP, stack + OperandSizeToValue(cpu_address_size()) * 2));
			}
			else {
				AddCommand(cmPush, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP, stack + OperandSizeToValue(cpu_address_size()) * 4));
				AddCommand(cmPush, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP, stack + OperandSizeToValue(cpu_address_size()) * 3));
				AddCommand(cmPush, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP, stack + OperandSizeToValue(cpu_address_size()) * 2));
			}
			jmp_entry_point_command = AddCommand(cmCall, IntelOperand(otValue, cpu_address_size(), 0, file->entry_point()));
			jmp_entry_point_command->AddLink(0, ltCall, file->entry_point());

			command = AddCommand(cmNop);
			jmp_command->link()->set_to_command(command);
			jmp_status_command->link()->set_to_command(command);
		}
		break;

		case itDriver:
			if (cpu_address_size() == osQWord) {
				AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regEDX), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP, stack + OperandSizeToValue(cpu_address_size()) * 3));
				AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regECX), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP, stack + OperandSizeToValue(cpu_address_size()) * 2));
			}
			else {
				AddCommand(cmPush, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP, stack + OperandSizeToValue(cpu_address_size()) * 3));
				AddCommand(cmPush, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP, stack + OperandSizeToValue(cpu_address_size()) * 2));
			}
			jmp_entry_point_command = AddCommand(cmCall, IntelOperand(otValue, cpu_address_size(), 0, file->entry_point()));
			jmp_entry_point_command->AddLink(0, ltCall, file->entry_point());

			// store error code
			AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP), IntelOperand(otRegistr, cpu_address_size(), regEAX));

			{
				// check error code
				AddCommand(cmCmp, IntelOperand(otRegistr, osDWord, regEAX), IntelOperand(otValue, osDWord, 0, 0));
				command = AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size()));
				command->set_flags(fl_Z);
				command->include_option(roInverseFlag);
				command->AddLink(0, ltJmpWithFlag);
				IntelCommand* cmp_command = command;

				// call SetupImage
				if (cpu_address_size() == osQWord) {
					AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regEDX), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP, stack + OperandSizeToValue(cpu_address_size()) * 2));
					AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regECX), IntelOperand(otValue, osDWord, 0, false));
				}
				else {
					AddCommand(cmPush, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP, stack + OperandSizeToValue(cpu_address_size()) * 2));
					AddCommand(cmPush, IntelOperand(otValue, cpu_address_size(), 0, false));
				}
				command = AddCommand(cmCall, IntelOperand(otValue, cpu_address_size()));
				command->AddLink(0, ltCall, setup_image_entry);

				IntelCommand* jmp_command = AddCommand(cmJmp, IntelOperand(otValue, cpu_address_size(), 0, 0));
				jmp_command->AddLink(0, ltJmp);

				command = AddCommand(cmNop);
				cmp_command->link()->set_to_command(command);

				// call FreeImage
				if (cpu_address_size() == osQWord) {
					AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regECX), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP, stack + OperandSizeToValue(cpu_address_size()) * 2));
				}
				else {
					AddCommand(cmPush, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP, stack + OperandSizeToValue(cpu_address_size()) * 2));
				}
				command = AddCommand(cmCall, IntelOperand(otValue, cpu_address_size()));
				command->AddLink(0, ltCall, free_image_entry);

				// restore error code
				command = AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regEAX), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regEBP));
				jmp_command->link()->set_to_command(command);
			}
			break;
		}
	}

	if (file->image_type() == itLibrary) {
		// check DLL_PROCESS_DETACH
		AddCommand(cmCmp, IntelOperand(otMemory | otRegistr | otValue, osDWord, regEBP, stack + OperandSizeToValue(cpu_address_size()) * 3), IntelOperand(otValue, osDWord, 0, DLL_PROCESS_DETACH));
		command = AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size()));
		command->set_flags(fl_Z);
		command->include_option(roInverseFlag);
		command->AddLink(0, ltJmpWithFlag);
		end_command_list.push_back(command);

		// call FreeImage
		command = AddCommand(cmCall, IntelOperand(otValue, cpu_address_size()));
		command->AddLink(0, ltCall, free_image_entry);

		AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regEAX), IntelOperand(otValue, osDWord, 0, TRUE));
	}

	command = AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size(), regESP), IntelOperand(otValue, cpu_address_size(), 0, stack + ((cpu_address_size() == osQWord) ? 0x20 : 0)));
	for (i = 0; i < end_command_list.size(); i++) {
		end_command_list[i]->link()->set_to_command(command);
	}
	AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size(), regEBP));

	IntelOperand ret_operand;
	if (cpu_address_size() == osDWord) {
		switch (file->image_type()) {
		case itDriver:
			ret_operand = IntelOperand(otValue, osWord, 0, 2 * OperandSizeToValue(cpu_address_size()));
			break;
		case itLibrary:
			ret_operand = IntelOperand(otValue, osWord, 0, 3 * OperandSizeToValue(cpu_address_size()));
			break;
		}
	}
	AddCommand(cmRet, ret_operand);
	if (jmp_entry_point_command && entry_point_command)
		jmp_entry_point_command->link()->set_to_command(entry_point_command);

	command = item(old_count);
	set_entry(command);

	if (tls_call_back_entry_) {
		index = count();

		AddCommand(cmPush, IntelOperand(otRegistr, cpu_address_size(), regEBP));
		if (cpu_address_size() == osDWord) {
			AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size(), regESP), IntelOperand(otValue, cpu_address_size(), 0, stack));
			AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regEBP), IntelOperand(otRegistr, cpu_address_size(), regESP));
		}
		else {
			AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size(), regEBP), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regESP, 0 - stack));
			AddCommand(cmSub, IntelOperand(otRegistr, cpu_address_size(), regESP), IntelOperand(otValue, cpu_address_size(), 0, stack + 0x20));
		}

		// call loader
		command = AddCommand(cmCall, IntelOperand(otValue, cpu_address_size()));
		command->AddLink(0, ltCall, setup_image_entry);

		// check loader error code
		AddCommand(cmCmp, IntelOperand(otRegistr, osDWord, regEAX), IntelOperand(otValue, osDWord, 0, (file->image_type() == itDriver) ? 0 : TRUE));
		IntelCommand* check_loader_command = AddCommand(cmJmpWithFlag, IntelOperand(otValue, cpu_address_size()));
		check_loader_command->set_flags(fl_Z);
		check_loader_command->AddLink(0, ltJmpWithFlag);

		// call FreeImage
		command = AddCommand(cmCall, IntelOperand(otValue, cpu_address_size()));
		command->AddLink(0, ltCall, free_image_entry);

		command = AddCommand(cmNop);
		check_loader_command->link()->set_to_command(command);

		AddCommand(cmAdd, IntelOperand(otRegistr, cpu_address_size(), regESP), IntelOperand(otValue, cpu_address_size(), 0, stack + ((cpu_address_size() == osQWord) ? 0x20 : 0)));
		AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size(), regEBP));

		IntelOperand ret_operand;
		if (cpu_address_size() == osDWord)
			ret_operand = IntelOperand(otValue, osWord, 0, 3 * OperandSizeToValue(cpu_address_size()));
		AddCommand(cmRet, ret_operand);

		tls_call_back_entry_->link()->set_to_command(item(index));
	}

	for (i = 0; i < count(); i++) {
		command = item(i);
		command->CompileToNative();
	}

	// search API calls
	for (i = 0; i < count(); i++) {
		command = item(i);
		if (command->block())
			continue;

		if (command->type() == cmCall) {
			if (command->operand(0).type == otValue)
				continue;
		}
		else if (command->type() != cmSyscall)
			continue;

		IntelCommand* next_command = item(i + 1);
		if (next_command->type() == cmAdd && next_command->operand(0).type == otRegistr && next_command->operand(0).registr == regESP)
			continue;

		k = 0;
		for (j = i; j > 0; j--) {
			IntelCommand* param_command = item(j - 1);

			switch (param_command->type()) {
			case cmPush:
				if (cpu_address_size() == osDWord) {
					k++;
				}
				else {
					param_command = NULL;
				}
				break;
			case cmMov: case cmLea: case cmXor: case cmMovsxd:
				if (cpu_address_size() == osQWord) {
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

	if (entry_point_command && entry_point_command->block()->virtual_machine() && jmp_entry_point_command) {
		jmp_entry_point_command->include_option(roExternal);
		uint8_t id = entry_point_command->block()->virtual_machine()->id();
		IntelVirtualMachineList* virtual_machine_list = reinterpret_cast<IntelVirtualMachineList*>(ctx.file->virtual_machine_list());
		for (i = 0; i < virtual_machine_list->count(); i++) {
			IntelVirtualMachine* virtual_machine = virtual_machine_list->item(i);
			if (virtual_machine->processor()->cpu_address_size() == cpu_address_size())
				virtual_machine->AddExtJmpCommand(id);
		}
	}

	for (i = 0; i < link_list()->count(); i++) {
		CommandLink* link = link_list()->item(i);
		if (link->from_command()->type() == cmCall && std::find(internal_entry_list.begin(), internal_entry_list.end(), link->to_command()) != internal_entry_list.end())
			reinterpret_cast<IntelCommand*>(link->from_command())->include_option(roInternal);
		link->from_command()->PrepareLink(ctx);
	}

	return BaseIntelLoader::Prepare(ctx);
}

std::vector<uint64_t> PEIntelLoader::cfg_address_list() const
{
	std::vector<uint64_t> res;
	res.push_back(entry()->address());
	if (tls_call_back_entry_)
		res.push_back(tls_call_back_entry_->link()->to_command()->address());
	std::sort(res.begin(), res.end());
	return res;
}

