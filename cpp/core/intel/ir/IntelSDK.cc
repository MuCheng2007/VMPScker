#include "IntelSDK.h"
#include "IntelFunction.h"
#include "IntelFunctionList.h"
#include "IntelCommand.h"
#include "IntelVMCommand.h"
#include "../../processors.h"
#include "../../core_internal/core.h"
#include "../../files/architecture.h"
#include "../../files/mapping.h"
#include "../../files/compiler_func.h"
#include "../../files/memory.h"
#include "../../files/types.h"
#include "../../pe/pefile.h"
#include "../../packer.h"
#include "../../core_internal/license.h"
#include "../../../runtime/crypto.h"

// Copied from intel.cc:
// - IntelSDK (lines: ~20420 - 20744)
// - PEIntelSDK (lines: ~20745 - 20803)
// - MacIntelSDK (lines: ~20804 - 20831)
// - ELFIntelSDK (lines: ~20832 - ?)
// - PEIntelExport (lines: ?)
// - IntelImport (lines: ~21107 - 21158)
// - IntelCRCTable (lines: ~21159 - 21341)
// - IntelRuntimeData (lines: ~21342 - 21365)
// - IntelLoaderData (lines: ~21366 - 21919)
// - IntelRuntimeCRCTable (lines: ~22146 - 24075)


/**
 * IntelSDK
 */

IntelSDK::IntelSDK(IFunctionList* owner, OperandSize cpu_address_size)
	: IntelFunction(owner, cpu_address_size)
{
	set_compilation_type(ctMutation);
}

bool IntelSDK::Init(const CompileContext& ctx)
{
	MapFunctionList* map_function_list;
	MapFunction* map_function;
	IFunctionList* function_list;
	size_t i, c, j, k, /*old_count,*/ n, f;
	uint64_t address;
	IArchitecture* file;
	IImportList* import_list;
	IImport* import;
	IImportFunction* import_function;
	IntelCommand* command, * ret_command, * mem_command, * api_entry;
	CommandBlock* block;
	uint64_t api_address;
	std::map<APIType, IntelCommand*> map_api_entry;

	CallingConvention calling_convention = ctx.file->calling_convention();

	f = (ctx.runtime && ctx.runtime->segment_list()->count() > 0) ? 2 : 1;
	for (n = 0; n < f; n++) {
		file = (n == 0) ? ctx.file : ctx.runtime;
		map_function_list = file->map_function_list();
		function_list = file->function_list();
		for (i = 0; i < map_function_list->count(); i++) {
			map_function = map_function_list->item(i);
			switch (map_function->type()) {
			case otAPIMarker:
				// need clear marker name
				if (map_function->name_address())
					ctx.manager->Add(map_function->name_address(), map_function->name_length(), file->segment_list()->GetMemoryTypeByAddress(map_function->name_address()));
				break;
			case otMarker:
				// need clear "VMProtect begin" from asm markers
				ICommand* command = function_list->GetCommandByAddress(map_function->address() + 2, true);
				if (!command)
					ctx.manager->Add(map_function->address() + 2, 0x10, file->segment_list()->GetMemoryTypeByAddress(map_function->name_address()));
				break;
			}
		}

		// need clear "VMProtect end" from asm markers
		for (i = 0; i < file->end_marker_list()->count(); i++) {
			MarkerCommand* marker_command = file->end_marker_list()->item(i);
			if (marker_command->type() != otMarker)
				continue;

			ICommand* command = function_list->GetCommandByAddress(marker_command->address() + 2, true);
			if (!command)
				ctx.manager->Add(marker_command->address() + 2, 0x0e, file->segment_list()->GetMemoryTypeByAddress(map_function->name_address()));
		}

		for (i = 0; i < file->compiler_function_list()->count(); i++) {
			CompilerFunction* compiler_function = file->compiler_function_list()->item(i);
			if (compiler_function->type() == cfDllFunctionCall) {
				// clear names
				ctx.manager->Add(compiler_function->value(1), static_cast<size_t>(compiler_function->value(2)));
				ctx.manager->Add(compiler_function->value(3), static_cast<size_t>(compiler_function->value(4)));

				if ((compiler_function->options() & coUsed) == 0)
					continue;

				address = compiler_function->address();
				command = reinterpret_cast<IntelCommand*>(ctx.file->function_list()->GetCommandByNearAddress(address, true));
				if (command) {
					delete command->link();
				}
				else {
					if (!file->AddressSeek(address))
						return false;

					block = AddBlock(count(), true);
					block->set_address(address);

					command = Add(address);
					command->ReadFromFile(*file);
					command->set_block(block);
					command->include_option(roFillNop);
					command->exclude_option(roClearOriginalCode);
				}

				// need delete fixups
				for (k = 0; k < 3; k++) {
					IntelOperand operand = command->operand(k);
					if (operand.type == otNone)
						break;

					IFixup* fixup = operand.fixup;
					if (fixup && fixup != NEED_FIXUP)
						fixup->set_deleted(true);
				}
				// need clear operands
				command->Init(static_cast<IntelCommandType>(command->type()));

				APIType function_type = static_cast<APIType>(compiler_function->value(0) & 0xff);
				switch (function_type) {
				case atBegin:
					command->Init(cmRet, IntelOperand(otValue, osWord, 0, OperandSizeToValue(cpu_address_size())));
					break;
				case atEnd:
					command->Init(cmRet);
					break;
				default:
					if (!ctx.runtime)
						return false;
					api_address = ctx.runtime->export_list()->GetAddressByType(function_type);
					if (!api_address)
						return false;

					command->Init(cmJmp, IntelOperand(otValue, cpu_address_size(), 0, api_address));
					command->AddLink(0, ltJmp, api_address);
					break;
				}

				command->CompileToNative();
			}
		}

		import_list = file->import_list();
		for (i = 0; i < import_list->count(); i++) {
import = import_list->item(i);
			if (!import->is_sdk())
				continue;

			for (j = 0; j < import->count(); j++) {
				import_function = import->item(j);

				map_function = import_function->map_function();
				for (c = 0; c < map_function->reference_list()->count(); c++) {
					address = map_function->reference_list()->item(c)->address();

					command = reinterpret_cast<IntelCommand*>(ctx.file->function_list()->GetCommandByNearAddress(address, true));
					if (command) {
						delete command->link();
					}
					else {
						if (!file->AddressSeek(address))
							return false;

						block = AddBlock(count(), true);
						block->set_address(address);

						command = Add(address);
						command->ReadFromFile(*file);
						command->set_block(block);
						command->include_option(roFillNop);
						command->exclude_option(roClearOriginalCode);
					}

					if (command->type() != cmMov) {
						// need delete fixups
						for (k = 0; k < 3; k++) {
							IntelOperand operand = command->operand(k);
							if (operand.type == otNone)
								break;

							IFixup* fixup = operand.fixup;
							if (fixup && fixup != NEED_FIXUP)
								fixup->set_deleted(true);
						}
						// need clear operands
						command->Init(static_cast<IntelCommandType>(command->type()));
					}

					switch (import_function->type()) {
					case atBegin:
						switch (command->type()) {
						case cmCall:
							if (calling_convention == ccStdcall) {
								command->Init(cmLea, IntelOperand(otRegistr, cpu_address_size(), regESP),
									IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regESP, OperandSizeToValue(cpu_address_size())));
							}
							else {
								command->Init(cmNop);
							}
							break;
						case cmMov:
							if (calling_convention == ccStdcall) {
								ret_command = AddCommand(cmRet, IntelOperand(otValue, osWord, 0, OperandSizeToValue(cpu_address_size())));
							}
							else {
								ret_command = AddCommand(cmRet);
							}

							mem_command = AddCommand((cpu_address_size() == osDWord) ? cmDD : cmDQ, IntelOperand(otValue, cpu_address_size(), 0, 0, NEED_FIXUP));
							mem_command->AddLink(0, ltOffset, ret_command);

							command->AddLink(1, ltOffset, mem_command);
							break;
						default:
							if (calling_convention == ccStdcall) {
								command->Init(cmRet, IntelOperand(otValue, osWord, 0, OperandSizeToValue(cpu_address_size())));
							}
							else {
								command->Init(cmRet);
							}
							break;
						}
						break;

					case atEnd:
						switch (command->type()) {
						case cmCall:
							command->Init(cmNop);
							break;
						case cmMov:
							ret_command = AddCommand(cmRet);

							mem_command = AddCommand((cpu_address_size() == osDWord) ? cmDD : cmDQ, IntelOperand(otValue, cpu_address_size(), 0, 0, NEED_FIXUP));
							mem_command->AddLink(0, ltOffset, ret_command);

							command->AddLink(1, ltOffset, mem_command);
							break;
						default:
							command->Init(cmRet);
							break;
						}
						break;

					case atDecryptStringA:
					case atDecryptStringW:
					case atFreeString:
					case atIsDebuggerPresent:
					case atIsVirtualMachinePresent:
					case atIsValidImageCRC:
					case atActivateLicense:
					case atDeactivateLicense:
					case atGetOfflineActivationString:
					case atGetOfflineDeactivationString:
					case atSetSerialNumber:
					case atGetSerialNumberState:
					case atGetSerialNumberData:
					case atGetCurrentHWID:
					case atIsProtected:
						api_entry = NULL;
						api_address = 0;
						if (!ctx.runtime || ctx.runtime->segment_list()->count() == 0) {
							std::map<APIType, IntelCommand*>::const_iterator it = map_api_entry.find(import_function->type());
							if (it != map_api_entry.end())
								api_entry = it->second;
							else {
								switch (import_function->type()) {
								case atDecryptStringA:
								case atDecryptStringW:
									if (calling_convention == ccMSx64)
										api_entry = AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regEAX), IntelOperand(otRegistr, cpu_address_size(), regECX));
									else if (calling_convention == ccABIx64)
										api_entry = AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regEAX), IntelOperand(otRegistr, cpu_address_size(), regEDI));
									else
										api_entry = AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), regEAX), IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regESP, OperandSizeToValue(cpu_address_size())));
									if (calling_convention == ccStdcall)
										AddCommand(cmRet, IntelOperand(otValue, osWord, 0, OperandSizeToValue(cpu_address_size())));
									else
										AddCommand(cmRet);
									break;
								case atFreeString:
									api_entry = AddCommand(cmXor, IntelOperand(otRegistr, osDWord, regEAX), IntelOperand(otRegistr, osDWord, regEAX));
									if (calling_convention == ccStdcall)
										AddCommand(cmRet, IntelOperand(otValue, osWord, 0, OperandSizeToValue(cpu_address_size())));
									else
										AddCommand(cmRet);
									break;
								case atIsProtected:
									api_entry = AddCommand(cmMov, IntelOperand(otRegistr, osDWord, regEAX), IntelOperand(otValue, osDWord, 0, 1));
									AddCommand(cmRet);
									break;
								default:
									// other APIs can not work without runtime
									return false;
								}
								map_api_entry[import_function->type()] = api_entry;
							}
						}
						else {
							api_address = ctx.runtime->export_list()->GetAddressByType(import_function->type());
							if (!api_address)
								return false;
						}

						switch (command->type()) {
						case cmCall:
							command->Init(cmCall, IntelOperand(otValue, cpu_address_size(), 0, api_address));
							if (api_entry)
								command->AddLink(0, ltCall, api_entry);
							else
								command->AddLink(0, ltCall, api_address);
							break;
						case cmMov:
							mem_command = AddCommand((cpu_address_size() == osDWord) ? cmDD : cmDQ, IntelOperand(otValue, cpu_address_size(), 0, api_address, NEED_FIXUP));
							if (api_entry)
								mem_command->AddLink(0, ltOffset, api_entry);
							else
								mem_command->AddLink(0, ltOffset, api_address);
							command->AddLink(1, ltOffset, mem_command);
							break;
						default:
							command->Init(cmJmp, IntelOperand(otValue, cpu_address_size(), 0, api_address));
							if (api_entry)
								command->AddLink(0, ltJmp, api_entry);
							else
								command->AddLink(0, ltJmp, api_address);
							break;
						}
						break;

					default:
						throw std::runtime_error("Unknown API from SDK: " + import_function->name());
					}

					command->CompileToNative();
				}
			}
		}
	}

	for (i = 0; i < count(); i++) {
		item(i)->CompileToNative();
	}

	return IntelFunction::Init(ctx);
}

/**
 * PEIntelSDK
 */

PEIntelSDK::PEIntelSDK(IFunctionList* parent, OperandSize cpu_address_size)
	: IntelSDK(parent, cpu_address_size)
{

}

bool PEIntelSDK::Init(const CompileContext& ctx)
{
	if (!IntelSDK::Init(ctx))
		return false;

	PEArchitecture* file = reinterpret_cast<PEArchitecture*>(ctx.file);
	if (file->import_list()->has_sdk() && ctx.runtime == NULL) {
		// remove SDK from import
		PEDirectory* dir = file->command_list()->GetCommandByType(IMAGE_DIRECTORY_ENTRY_IMPORT);
		if (!dir)
			return false;

		size_t i, j;
		IntelCommand* command;
		uint64_t address = dir->address();

		CommandBlock* block = AddBlock(count(), true);
		block->set_address(address);

		for (i = 0; i < file->import_list()->count(); i++) {
			PEImport* import = file->import_list()->item(i);
			if (import->is_sdk()) {
import->FreeByManager(*ctx.manager, true);
			}
			else {
				if (!file->AddressSeek(address))
					return false;

				for (j = 0; j < 5; j++) {
					command = Add(0);
					command->ReadValueFromFile(*file, osDWord);
					command->include_option(roWritable);
				}
			}
			address += 5 * sizeof(uint32_t);
		}
		for (j = 0; j < 5; j++) {
			command = AddCommand(cmDD, IntelOperand(otValue, osDWord));
			command->CompileToNative();
		}
		block->set_end_index(count() - 1);

		for (i = block->start_index(); i <= block->end_index(); i++) {
			item(i)->set_block(block);
		}
	}

	return true;
}

/**
 * PEIntelExport
 */

PEIntelExport::PEIntelExport(IFunctionList* owner, OperandSize cpu_address_size)
	: IntelFunction(owner, cpu_address_size), size_(0)
{
	set_compilation_type(ctMutation);
}

bool PEIntelExport::Init(const CompileContext& ctx)
{
	PEArchitecture* file = reinterpret_cast<PEArchitecture*>(ctx.file);
	size_ = file->export_list()->WriteToData(*this, file->image_base());
	if (count())
		set_entry(item(0));

	return IntelFunction::Init(ctx);
}

bool PEIntelExport::Compile(const CompileContext& ctx)
{
	CreateBlocks();
	block_list()->CompileBlocks(*ctx.manager);
	CompileLinks(ctx);
	return true;
}

/**
 * IntelImport
 */

IntelImport::IntelImport(IFunctionList* owner, OperandSize cpu_address_size)
	: IntelFunction(owner, cpu_address_size)
{
	set_compilation_type(ctMutation);
}

IntelCommand* IntelImport::GetIATCommand(PEImportFunction* import_function) const
{
	size_t i;

	for (i = 0; i < iat_info_list_.size(); i++) {
		if (iat_info_list_[i].import_function->address() == import_function->address()) {
			return iat_info_list_[i].command;
		}
	}

	return NULL;
}

bool IntelImport::Init(const CompileContext& ctx)
{
	IntelCommandType value_type, rand_type, ref_type;
	size_t i, j, n, k, c, index, r;
	PEImportList* import_list;
	PEImport* import;
	PEImportFunction* import_function;
	IATInfo iat_info;
	IntelCommand* command, * src_command, * iat_command, * ref_command;
	ReferenceList call_references;
	MapFunction* map_function;
	uint64_t address, rand_value;
	PEArchitecture* file;
	uint8_t mov_registr, rand_registr;
	bool is_mov_command;
	CommandLink* link;

	value_type = (cpu_address_size() == osDWord) ? cmDD : cmDQ;
	k = (ctx.runtime && ctx.runtime->segment_list()->count() > 0) ? 2 : 1;
	for (n = 0; n < k; n++) {
		file = reinterpret_cast<PEArchitecture*>((n == 0) ? ctx.file : ctx.runtime);
		import_list = file->import_list();
		for (i = 0; i < import_list->count(); i++) {
import = import_list->item(i);

			// APIs processed by IntelSDK
			if (import->is_sdk())
				continue;

			if (import->excluded_from_import_protection())
				continue;

			for (j = 0; j < import->count(); j++) {
				import_function = import->item(j);

				if (import_function->options() & (ioHasDataReference | ioNoReferences))
					continue;

				iat_info.import_function = import_function;
				iat_info.command = NULL;
				iat_info.from_runtime = (n > 0);
				iat_info_list_.push_back(iat_info);
			}
		}
	}

	index = count();
	for (i = 0; i < iat_info_list_.size(); i++) {
		import_function = iat_info_list_[i].import_function;

		command = AddCommand(value_type, IntelOperand(otValue, cpu_address_size(), 0, (value_type == cmDD) ? rand32() : rand64()));
		// second operand is a key for decrypt IAT value
		command->set_operand_value(1, (import_function->options() & ioNative) ? 0 : DWordToInt64(rand32()));
		command->include_option(roCreateNewBlock);
		command->include_option(roWritable);

		iat_info_list_[i].command = command;

		map_function = import_function->map_function();

		call_references.clear();
		for (r = 0; r < 2; r++) {
			ReferenceList* reference_list = (r == 0) ? map_function->reference_list() : &call_references;

			for (n = 0; n < reference_list->count(); n++) {
				address = reference_list->item(n)->address();

				src_command = reinterpret_cast<IntelCommand*>(ctx.file->function_list()->GetCommandByNearAddress(address, true));
				iat_command = iat_info_list_[i].command;

				file = reinterpret_cast<PEArchitecture*>((iat_info_list_[i].from_runtime) ? ctx.runtime : ctx.file);

				if (file == NULL || !file->AddressSeek(address))
					return false;

				ref_command = Add(address);
				ref_command->ReadFromFile(*file);
				if (ref_command->type() == cmInt) {
					// reference command from runtime
					if (!src_command)
						throw std::runtime_error("Runtime error at Init");

					delete ref_command;
					ref_command = src_command->Clone(this);
					AddObject(ref_command);
				}

				// delete fixups
				for (k = 0; k < 3; k++) {
					IntelOperand operand = ref_command->operand(k);
					if (operand.type == otNone)
						break;

					IFixup* fixup = operand.fixup;
					if (fixup && fixup != NEED_FIXUP)
						fixup->set_deleted(true);
				}

				is_mov_command = (ref_command->type() == cmMov && ref_command->operand(0).type == otRegistr && ref_command->operand(0).size == cpu_address_size());
				ref_type = static_cast<IntelCommandType>(ref_command->type());
				mov_registr = ref_command->operand(0).registr;
				rand_registr = rand() % 8;
				if (rand_registr == regESP)
					rand_registr = regEAX;

				c = ref_command->original_dump_size();
				if (src_command == NULL && c > 5) {
					IntelCommand* push_command;
					switch (rand() % (is_mov_command ? 3 : 2)) {
					case 2:
						rand_type = cmPop;
						AddCommand(cmXchg, IntelOperand(otMemory | otRegistr, cpu_address_size(), regESP), IntelOperand(otRegistr, cpu_address_size(), mov_registr));
						push_command = AddCommand(cmPush, IntelOperand(otRegistr, cpu_address_size(), mov_registr));
						break;
					case 1:
						rand_type = cmPush;
						push_command = AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size(), rand_registr));
						AddCommand(cmXchg, IntelOperand(otMemory | otRegistr, cpu_address_size(), regESP), IntelOperand(otRegistr, cpu_address_size(), rand_registr));
						break;
					default:
						rand_type = cmNop;
						push_command = NULL;
						break;
					}
					if (push_command) {
						push_command->CompileToNative();
						c -= push_command->dump_size();
					}
				}
				else {
					rand_type = cmUnknown;
					c = 0;
				}

				if (is_mov_command && mov_registr == rand_registr) {
					if (c > 5) {
						AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size(), rand_registr));
						AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size(), rand_registr),
							IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), rand_registr, c - 5));
						AddCommand(cmPush, IntelOperand(otRegistr, cpu_address_size(), rand_registr));
					}
				}
				else {
					AddCommand(cmPush, IntelOperand(otRegistr, cpu_address_size(), rand_registr));
					if (c > 5 && ref_type != cmJmp) {
						AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), rand_registr),
							IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regESP, OperandSizeToValue(cpu_address_size())));
						AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size(), rand_registr),
							IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), rand_registr, c - 5));
						AddCommand(cmMov, IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), regESP, OperandSizeToValue(cpu_address_size())),
							IntelOperand(otRegistr, cpu_address_size(), rand_registr));
					}
				}

				rand_value = file->segment_list()->item(0)->address() + rand32() % file->segment_list()->item(0)->size();
				if (cpu_address_size() == osDWord) {
					AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), rand_registr),
						IntelOperand(otValue, cpu_address_size(), 0, rand_value, NEED_FIXUP));
				}
				else {
					AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size(), rand_registr),
						IntelOperand(otMemory | otValue, cpu_address_size(), 0, rand_value, LARGE_VALUE));
				}

				// read random registr from IAT
				command = AddCommand(cmMov, IntelOperand(otRegistr, cpu_address_size(), rand_registr),
					IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), rand_registr, 0x80000000));
				link = command->AddLink(1, ltOffset, iat_command);
				link->set_sub_value(rand_value);

				// decrypt API`s address in random registr
				AddCommand(cmLea, IntelOperand(otRegistr, cpu_address_size(), rand_registr),
					IntelOperand(otMemory | otRegistr | otValue, cpu_address_size(), rand_registr, iat_command->operand(1).value));

				// restore random registr
				if (ref_type == cmJmp || ref_type == cmCall) {
					AddCommand(cmXchg, IntelOperand(otMemory | otRegistr, cpu_address_size(), regESP), IntelOperand(otRegistr, cpu_address_size(), rand_registr));
				}
				else if (is_mov_command && mov_registr != rand_registr) {
					IntelOperand ref_operand = ref_command->operand(0);
					if ((ref_operand.type & otBaseRegistr) && ref_operand.base_registr == regESP) {
						ref_operand.type |= otValue;
						ref_operand.value += OperandSizeToValue(cpu_address_size());
					}

					AddCommand(cmMov, ref_operand, IntelOperand(otRegistr, ref_operand.size, rand_registr));
					AddCommand(cmPop, IntelOperand(otRegistr, cpu_address_size(), rand_registr));
				}

				if (ref_type == cmJmp) {
					AddCommand(cmRet, IntelOperand(otValue, osWord, 0, OperandSizeToValue(cpu_address_size())));
				}
				else {
					AddCommand(cmRet);
				}

				// clear operands
				ref_command->Init(cmNop);
				ref_command->set_address(0);
				ref_command->set_address_range(NULL);

				if (src_command) {
					delete src_command->link();
					src_command->Init(cmCall, IntelOperand(otValue, cpu_address_size()));
					if (ref_type == cmJmp)
						src_command->include_option(roUseAsJmp);
					src_command->AddLink(0, ltCall, ref_command);
				}
				else {
					c = ref_command->original_dump_size();
					if (rand_type == cmPush || rand_type == cmPop) {
						CommandBlock* block = AddBlock(index, true);
						block->set_address(address);

						command = new IntelCommand(this, cpu_address_size(), rand_type, IntelOperand(otRegistr, cpu_address_size(), (rand_type == cmPop) ? mov_registr : rand_registr));
						command->CompileToNative();
						command->set_block(block);
						InsertObject(index++, command);

						address += command->dump_size();
						c -= command->dump_size();
					}

					ctx.manager->Add(address, c, file->segment_list()->GetMemoryTypeByAddress(address), this);

					ext_command_list()->Add(address, ref_command, true);
				}

				if (ref_type == cmJmp) {
					address = reference_list->item(n)->address();

					for (j = 0; j < ctx.file->function_list()->count(); j++) {
						IntelFunction* func = reinterpret_cast<IntelFunction*>(ctx.file->function_list()->item(j));
						if (!func->need_compile())
							continue;

						for (k = 0; k < func->link_list()->count(); k++) {
							CommandLink* link = func->link_list()->item(k);
							if (link->type() != ltCall)
								continue;

							command = reinterpret_cast<IntelCommand*>(link->from_command());
							if (command->type() == cmCall && command->operand(0).type == otValue && command->operand(0).value == address)
								call_references.Add(command->address(), 0);
						}
					}
				}
			}
		}
	}

	for (i = 0; i < count(); i++) {
		item(i)->CompileToNative();
	}

	return IntelFunction::Init(ctx);
}

/**
 * IntelCRCTable
 */

IntelCRCTable::IntelCRCTable(IFunctionList* owner, OperandSize cpu_address_size)
	: IntelFunction(owner, cpu_address_size)
{
	set_compilation_type(ctMutation);
}

bool IntelCRCTable::Init(const CompileContext& ctx)
{
	size_t i, c, n, f;

	c = 10;
	f = (ctx.runtime && ctx.runtime->segment_list()->count() > 0) ? 2 : 1;
	for (n = 0; n < f; n++) {
		IArchitecture* file = (n == 0) ? ctx.file : ctx.runtime;
		c += ctx.file->segment_list()->count();
		if ((ctx.options.flags & cpStripFixups) == 0)
			c += file->fixup_list()->count();
		if (ctx.options.flags & cpImportProtection) {
			IImportList* import_list = file->import_list();
			for (i = 0; i < import_list->count(); i++) {
				c += import_list->item(i)->count();
			}
		}
		else {
			c += file->import_list()->count();
		}
	}

	for (i = 0; i < c; i++) {
		AddCommand(cmDD, IntelOperand(otValue, osDWord));
		AddCommand(cmDD, IntelOperand(otValue, osDWord));
		AddCommand(cmDD, IntelOperand(otValue, osDWord));
	}

	size_entry_ = AddCommand(cmDD, IntelOperand(otValue, osDWord));
	size_entry_->include_option(roCreateNewBlock);

	hash_entry_ = AddCommand(cmDD, IntelOperand(otValue, osDWord));
	hash_entry_->include_option(roCreateNewBlock);

	for (i = 0; i < count(); i++) {
		IntelCommand* command = item(i);
		command->CompileToNative();
		command->include_option(roWritable);
	}

	return IntelFunction::Init(ctx);
}

/**
 * IntelRuntimeCRCTable
 */

IntelRuntimeCRCTable::IntelRuntimeCRCTable(IFunctionList* owner, OperandSize cpu_address_size)
	: IntelFunction(owner, cpu_address_size), cryptor_(NULL)
{
	set_compilation_type(ctMutation);
}

void IntelRuntimeCRCTable::clear()
{
	region_info_list_.clear();
	IntelFunction::clear();
}

bool IntelRuntimeCRCTable::Compile(const CompileContext& ctx)
{
	IntelFunctionList* function_list = reinterpret_cast<IntelFunctionList*>(ctx.file->function_list());
	cryptor_ = function_list->crc_cryptor();

	size_t block_size, i, j, k, end_operand_index;
	uint64_t block_address;
	bool check_fixups = (ctx.options.flags & cpStripFixups) == 0;
	MemoryManager manager(ctx.file);

	for (i = 0; i < function_list->count(); i++) {
		IntelFunction* func = function_list->item(i);
		if (!func->need_compile())
			continue;

		for (j = 0; j < func->block_list()->count(); j++) {
			CommandBlock* block = func->block_list()->item(j);
			if (block->type() & mtExecutable) {
				// native block
				block_size = 0;
				block_address = 0;
				for (k = block->start_index(); k <= block->end_index(); k++) {
					IntelCommand* command = func->item(k);
					if (command->options() & roWritable)
						continue;

					if (block_address && (block_address + block_size) != command->address()) {
						if (block_size)
							manager.Add(block_address, block_size, mtReadable);
						block_address = 0;
						block_size = 0;
					}
					if (!block_address)
						block_address = command->address();

					end_operand_index = NOT_ID;
					for (size_t n = 0; n < 3; n++) {
						IntelOperand operand = command->operand(n);
						if (operand.type == otNone)
							break;

						if ((operand.type & otValue) && ((check_fixups && operand.fixup) || operand.relocation)) {
							end_operand_index = n;
							break;
						}
					}
					block_size += (end_operand_index == NOT_ID) ? command->dump_size() : command->operand(end_operand_index).value_pos;
				}
				if (block_size)
					manager.Add(block_address, block_size, mtReadable);
			}
			else {
				// VM block
				IntelCommand* command = func->item(block->end_index());
				block_size = 0;
				if (command->section_options() & rtBackwardDirection) {
					block_address = command->vm_address() - command->vm_dump_size();
					for (k = command->count(); k > 0; k--) {
						IntelVMCommand* vm_command = command->item(k - 1);
						if (check_fixups && vm_command->fixup())
							break;
						block_size += vm_command->dump_size();
					}
				}
				else {
					block_address = command->vm_address();
					for (k = 0; k < command->count(); k++) {
						IntelVMCommand* vm_command = command->item(k);
						if (check_fixups && vm_command->fixup())
							break;
						block_size += vm_command->dump_size();
					}
				}
				if (block_size)
					manager.Add(block_address, block_size, mtReadable);
			}
		}
	}
	if (manager.count() == 0)
		return true;

	manager.Pack();

	for (i = 0; i < manager.count(); i++) {
		MemoryRegion* region = manager.item(i);
		uint64_t block_address = region->address();

		size_t region_size, block_size;
		for (region_size = region->size(); region_size != 0; region_size -= block_size, block_address += block_size) {
			block_size = 0x1000 - (rand() & 0xff);
			if (block_size > region_size)
				block_size = region_size;

			region_info_list_.push_back(RegionInfo(block_address, static_cast<uint32_t>(block_size), false));
		}
	}

	for (i = 0; i < region_info_list_.size(); i++) {
		std::swap(region_info_list_[i], region_info_list_[rand() % region_info_list_.size()]);
	}

	size_t self_crc_offset = 0;
	size_t self_crc_size = 0;
	for (i = 0; i < region_info_list_.size(); i++) {
		self_crc_size += sizeof(CRCInfo::POD);
		if (self_crc_size > 0x1000 && (rand() & 1)) {
			region_info_list_.insert(region_info_list_.begin() + i + 1, RegionInfo(self_crc_offset, (uint32_t)self_crc_size, true));
			self_crc_offset += self_crc_size;
			self_crc_size = 0;
		}
	}
	if (self_crc_size)
		region_info_list_.push_back(RegionInfo(self_crc_offset, (uint32_t)self_crc_size, true));

	for (i = 0; i < region_info_list_.size(); i++) {
		AddCommand(cmDD, IntelOperand(otValue, osDWord));
		AddCommand(cmDD, IntelOperand(otValue, osDWord));
		AddCommand(cmDD, IntelOperand(otValue, osDWord));
	}
	set_entry(item(0));
	for (i = 0; i < count(); i++) {
		item(i)->CompileToNative();
	}

	CreateBlocks();

	for (i = 0; i < block_list()->count(); i++) {
		block_list()->item(i)->Compile(*ctx.manager);
	}

	return true;
}

size_t IntelRuntimeCRCTable::WriteToFile(IArchitecture& file)
{
	size_t res = IntelFunction::WriteToFile(file);

	if (entry()) {
		uint64_t address = entry()->address();
		std::vector<CRCInfo> crc_info_list;
		std::vector<uint8_t> dump;
		for (size_t i = 0; i < region_info_list_.size(); i++) {
			RegionInfo region_info = region_info_list_[i];

			dump.resize(region_info.size);
			if (region_info.is_self_crc) {
				memcpy(&dump[0], reinterpret_cast<uint8_t*>(&crc_info_list[0]) + region_info.address, dump.size());
				region_info.address += address;
			}
			else {
				file.AddressSeek(region_info.address);
				file.Read(&dump[0], dump.size());
			}

			CRCInfo crc_info(static_cast<uint32_t>(region_info.address - file.image_base()), dump);
			if (cryptor_) {
				crc_info.pod.address = static_cast<uint32_t>(cryptor_->Encrypt(crc_info.pod.address));
				crc_info.pod.size = static_cast<uint32_t>(cryptor_->Encrypt(crc_info.pod.size));
			}
			crc_info.pod.hash = 0 - crc_info.pod.hash;
			crc_info_list.push_back(crc_info);
		}

		file.AddressSeek(address);
		file.Write(&crc_info_list[0], crc_info_list.size() * sizeof(CRCInfo::POD));
	}

	return res;
}

/**
 * IntelLoaderData
 */

IntelLoaderData::IntelLoaderData(IFunctionList* owner, OperandSize cpu_address_size)
	: IntelFunction(owner, cpu_address_size)
{
	set_compilation_type(ctMutation);
}

bool IntelLoaderData::Init(const CompileContext& ctx)
{
	IntelCommand* command = AddCommand(cpu_address_size(), 0);
	if (!command)
		return false;

	command->CompileToNative();
	command->include_option(roWritable);
	set_entry(command);
	set_entry_type(etNone);

	return IntelFunction::Init(ctx);
}

/**
 * IntelRuntimeData
 */

IntelRuntimeData::IntelRuntimeData(IFunctionList* owner, OperandSize cpu_address_size)
	: IntelFunction(owner, cpu_address_size), strings_entry_(NULL), strings_size_(0), resources_entry_(NULL), resources_size_(0),
	trial_hwid_entry_(NULL), trial_hwid_size_(0), data_key_(0)
	, license_data_entry_(NULL), license_data_size_(0), files_entry_(NULL), files_size_(0),
	registry_entry_(NULL), registry_size_(0)
{
	set_compilation_type(ctMutation);
	rc5_key_.Create();
}

bool IntelRuntimeData::CommandCompareHelper::operator()(const IntelCommand* left, IntelCommand* right) const
{
	return (left->address() < right->address());
}

bool IntelRuntimeData::Init(const CompileContext& ctx)
{
	IntelFunctionList* function_list;
	size_t i, j, index, k;
	std::vector<IntelCommand*> string_command_list;
	IntelCommand* command, * string_command;
	CommandLink* link;
	IntelCommand* key_entry;
	Data key;
	uint64_t image_base = ctx.file->image_base();

	key.PushBuff(rc5_key_.Value, sizeof(rc5_key_.Value));
	data_key_ = key.ReadDWord(0);

	resources_entry_ = NULL;
	resources_size_ = 0;
	if ((ctx.options.flags & cpResourceProtection) && ctx.file->resource_list() && ctx.file->resource_list()->count()) {
		PEArchitecture* file = reinterpret_cast<PEArchitecture*>(ctx.file);
		PEResourceList resource_list(NULL);
		for (i = 0; i < file->resource_list()->count(); i++) {
			PEResource* resource = file->resource_list()->item(i);
			if (resource->need_store())
				continue;

			resource_list.AddObject(resource->Clone(&resource_list));
		}

		if (resource_list.count()) {
			index = count();

			std::vector<PEResource*> list;
			PEResource* resource;

			// create resource list
			for (i = 0; i < resource_list.count(); i++) {
				list.push_back(resource_list.item(i));
			}

			for (i = 0; i < list.size(); i++) {
				resource = list[i];
				for (j = 0; j < resource->count(); j++) {
					list.push_back(resource->item(j));
				}
			}

			// create root directory
			uint32_t number_of_id_entries = 0;
			uint32_t number_of_named_entries = 0;
			for (i = 0; i < resource_list.count(); i++) {
				if (resource_list.item(i)->has_name()) {
					number_of_named_entries++;
				}
				else {
					number_of_id_entries++;
				}
			}
			AddCommand(osDWord, number_of_named_entries);
			AddCommand(osDWord, number_of_id_entries);

			for (i = 0; i < resource_list.count(); i++) {
				resource_list.item(i)->WriteEntry(*this);
			}

			for (i = 0; i < list.size(); i++) {
				list[i]->WriteHeader(*this);
			}

			resources_entry_ = item(index);
			resources_entry_->include_option(roCreateNewBlock);
			resources_size_ = static_cast<uint32_t>((count() - index) * OperandSizeToValue(osDWord));

			for (i = 0; i < list.size(); i++) {
				list[i]->WriteName(*this, index, data_key_);
			}

			for (i = 0; i < list.size(); i++) {
				list[i]->WriteData(*this, *file, data_key_);
			}
		}
	}

	files_entry_ = NULL;
	files_size_ = 0;

	registry_entry_ = NULL;
	registry_size_ = 0;
	if (false) {
		index = count();

		// create root directory
		AddCommand(osDWord, 0);
		AddCommand(osDWord, 0);

		registry_entry_ = item(index);
		registry_entry_->include_option(roCreateNewBlock);
		for (i = index; i < count(); i++) {
			command = item(i);
			registry_size_ += (command->type() == cmDB) ? (uint32_t)command->dump_size() : OperandSizeToValue(command->operand(0).size);
		}

		i = AlignValue(registry_size_, 8);
		if (i > registry_size_) {
			Data tmp;
			tmp.resize(i - registry_size_, 0);
			AddCommand(tmp);
			registry_size_ = (uint32_t)i;
		}
	}

	function_list = reinterpret_cast<IntelFunctionList*>(ctx.file->function_list());
	for (i = 0; i < function_list->count(); i++) {
		IntelFunction* func = function_list->item(i);
		if (func->need_compile() && func->type() == otString) {
			for (j = 0; j < func->count(); j++) {
				string_command_list.push_back(func->item(j));
			}
		}
	}

	key_entry = AddCommand(key);
	key_entry->include_option(roCreateNewBlock);

	strings_entry_ = NULL;
	strings_size_ = 0;
	if (string_command_list.size()) {
		std::sort(string_command_list.begin(), string_command_list.end(), CommandCompareHelper());
		index = count();

		// create directory
		AddCommand(osDWord, string_command_list.size());

		for (i = 0; i < string_command_list.size(); i++) {
			string_command = string_command_list[i];

			// create string entry
			AddCommand(osDWord, string_command->address() - ctx.file->image_base());
			command = AddCommand(osDWord, 0);
			link = command->AddLink(0, ltOffset);
			link->set_sub_value(ctx.file->image_base());
			AddCommand(osDWord, string_command->dump_size());
		}
		strings_entry_ = item(index);
		strings_entry_->include_option(roCreateNewBlock);
		strings_size_ = static_cast<uint32_t>((count() - index) * OperandSizeToValue(osDWord));

		// create string values
		Data data;
		for (i = 0; i < string_command_list.size(); i++) {
			string_command = string_command_list[i];

			data.clear();
			for (j = 0; j < string_command->dump_size(); j++) {
				data.PushByte(string_command->dump(j) ^ static_cast<uint8_t>(_rotl32(data_key_, static_cast<int>(j)) + j));
			}

			command = AddCommand(data);
			command->include_option(roCreateNewBlock);

			item(index + 1 + i * 3 + 1)->link()->set_to_command(command);
		}
	}

	license_data_entry_ = NULL;
	license_data_size_ = 0;
	if (ctx.options.licensing_manager) {
		Data license_data;
		if (ctx.options.licensing_manager->GetLicenseData(license_data)) {
			license_data_entry_ = AddCommand(license_data);
			license_data_entry_->include_option(roCreateNewBlock);
			license_data_size_ = static_cast<uint32_t>(license_data.size());
		}
	}

	VMProtectBeginVirtualization("Trial HWID");
	trial_hwid_entry_ = NULL;
	trial_hwid_size_ = 0;

	if (!ctx.options.hwid.empty()) {
		std::string hwid = ctx.options.hwid;
		size_t size = hwid.size();

		std::vector<uint8_t> binary;
		binary.resize(size);
		Base64Decode(hwid.data(), hwid.size(), binary.data(), size);
		if (size & 3) {
			Notify(mtError, NULL, "Invalid HWID");
			return false;
		}

		Data data;
		data.PushBuff(binary.data(), binary.size());
		data.resize(64);

		trial_hwid_size_ = static_cast<uint32_t>(std::min(size, data.size()));
		trial_hwid_entry_ = AddCommand(data);
		trial_hwid_entry_->include_option(roCreateNewBlock);
	}
	VMProtectEnd();

	for (i = 0; i < count(); i++) {
		item(i)->CompileToNative();
	}

	// setup faces for common runtime functions
	IntelCRCTable* intel_crc = reinterpret_cast<IntelFunctionList*>(ctx.file->function_list())->crc_table();
	for (k = 0; k < function_list->count(); k++) {
		IntelFunction* func = function_list->item(k);
		if (!func->from_runtime() || func->tag() == ftLoader)
			continue;

		for (i = 0; i < func->count(); i++) {
			IntelCommand* command = func->item(i);
			for (j = 0; j < 3; j++) {
				IntelOperand operand = command->operand(j);
				if (operand.type == otNone)
					break;

				if ((operand.type & otValue) == 0)
					continue;

				if (operand.size == osQWord && ((operand.value >> 32) & 0xFFFF0000) == 0xFACE0000) {
					command->Init(static_cast<IntelCommandType>(command->type()), command->operand(0), IntelOperand(otValue, operand.size, 0, operand.value >> 32));
					func->InsertObject(i + 1, new IntelCommand(func, func->cpu_address_size(), cmShl, command->operand(0), IntelOperand(otValue, osWord, 0, 32)));
					func->InsertObject(i + 2, new IntelCommand(func, func->cpu_address_size(), cmAdd, command->operand(0), IntelOperand(otValue, operand.size, 0, static_cast<uint32_t>(operand.value))));
					operand = command->operand(1);
				}

				uint32_t value = static_cast<uint32_t>(operand.value);
				// clang optimization
				if (value == FACE_RC5_P + FACE_RC5_Q) {
					command->set_operand_value(j, rc5_key_.P + rc5_key_.Q);
					command->CompileToNative();
					continue;
				}
				if (value == FACE_RC5_P + FACE_RC5_Q + FACE_RC5_Q) {
					command->set_operand_value(j, rc5_key_.P + rc5_key_.Q + rc5_key_.Q);
					command->CompileToNative();
					continue;
				}

				bool is_neg = false;
				if ((value & 0xFFFF0000) != 0xFACE0000) {
					value = 0 - value;
					is_neg = true;
				}

				if ((value & 0xFFFF0000) == 0xFACE0000) {
					switch (value) {
					case FACE_STRING_INFO:
						if (strings_entry_) {
							link = command->AddLink((int)j, ltOffset, strings_entry_);
							link->set_sub_value(image_base);
						}
						else {
							command->set_operand_value(j, 0);
							command->CompileToNative();
						}
						break;
					case FACE_RESOURCE_INFO:
						if (resources_entry_) {
							link = command->AddLink((int)j, ltOffset, resources_entry_);
							link->set_sub_value(image_base);
						}
						else {
							command->set_operand_value(j, 0);
							command->CompileToNative();
						}
						break;
					case FACE_KEY_INFO:
						if (key_entry) {
							link = command->AddLink((int)j, ltOffset, key_entry);
							link->set_sub_value(image_base);
						}
						else {
							command->set_operand_value(j, 0);
							command->CompileToNative();
						}
						break;
					case FACE_STORAGE_INFO:
						if (files_entry_) {
							link = command->AddLink((int)j, ltOffset, files_entry_);
							link->set_sub_value(image_base);
						}
						else {
							command->set_operand_value(j, 0);
							command->CompileToNative();
						}
						break;
					case FACE_REGISTRY_INFO:
						if (registry_entry_) {
							link = command->AddLink((int)j, ltOffset, registry_entry_);
							link->set_sub_value(image_base);
						}
						else {
							command->set_operand_value(j, 0);
							command->CompileToNative();
						}
						break;
					case FACE_LICENSE_INFO:
						if (license_data_entry_) {
							link = command->AddLink((int)j, ltOffset, license_data_entry_);
							link->set_sub_value(image_base);
						}
						else {
							command->set_operand_value(j, 0);
							command->CompileToNative();
						}
						break;
					case FACE_LICENSE_INFO_SIZE:
						command->set_operand_value(j, license_data_size_);
						command->CompileToNative();
						break;
					case FACE_TRIAL_HWID:
						if (trial_hwid_entry_) {
							link = command->AddLink((int)j, ltOffset, trial_hwid_entry_);
							link->set_sub_value(image_base);
						}
						else {
							command->set_operand_value(j, 0);
							command->CompileToNative();
						}
						break;
					case FACE_TRIAL_HWID_SIZE:
						command->set_operand_value(j, trial_hwid_size_);
						command->CompileToNative();
						break;
					case FACE_RC5_P:
						command->set_operand_value(j, is_neg ? 0 - rc5_key_.P : rc5_key_.P);
						command->CompileToNative();
						break;
					case FACE_RC5_Q:
						command->set_operand_value(j, is_neg ? 0 - rc5_key_.Q : rc5_key_.Q);
						command->CompileToNative();
						break;
					case FACE_CRC_INFO_SALT:
						command->set_operand_value(j, function_list->crc_cryptor()->item(0)->value());
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
						command->set_operand_value(j, image_base);
						command->set_operand_fixup(j, NEED_FIXUP);
						command->CompileToNative();
						break;
					case FACE_CRC_TABLE_ENTRY:
						if (intel_crc) {
							link = command->AddLink((int)j, ltOffset, intel_crc->table_entry());
							link->set_sub_value(image_base);
						}
						else {
							command->set_operand_value(j, 0);
							command->CompileToNative();
						}
						break;
					case FACE_CRC_TABLE_SIZE:
						if (intel_crc) {
							link = command->AddLink((int)j, ltOffset, intel_crc->size_entry());
							link->set_sub_value(image_base);
						}
						else {
							command->set_operand_value(j, 0);
							command->CompileToNative();
						}
						break;
					case FACE_CRC_TABLE_HASH:
						if (intel_crc) {
							link = command->AddLink((int)j, ltOffset, intel_crc->hash_entry());
							link->set_sub_value(image_base);
						}
						else {
							command->set_operand_value(j, 0);
							command->CompileToNative();
						}
						break;
					case FACE_CORE_OPTIONS:
					{
						uint32_t options = 0;
						if (ctx.options.flags & cpInternalMemoryProtection)
							options |= CORE_OPTION_MEMORY_PROTECTION;
						if (ctx.options.flags & cpCheckDebugger)
							options |= CORE_OPTION_CHECK_DEBUGGER;
						command->set_operand_value(j, options);
					}
					command->CompileToNative();
					break;
					case FACE_VAR_IS_PATCH_DETECTED:
					case FACE_VAR_IS_DEBUGGER_DETECTED:
					case FACE_VAR_LOADER_CRC_INFO:
					case FACE_VAR_LOADER_CRC_INFO_SIZE:
					case FACE_VAR_LOADER_CRC_INFO_HASH:
					case FACE_VAR_CPU_HASH:
					case FACE_VAR_SESSION_KEY:
					case FACE_VAR_DRIVER_UNLOAD:
					case FACE_VAR_CRC_IMAGE_SIZE:
					case FACE_VAR_LOADER_STATUS:
					case FACE_VAR_SERVER_DATE:
					case FACE_VAR_OS_BUILD_NUMBER:
						command->set_operand_value(j, ctx.runtime_var_index[(value & 0xff) >> 4] * OperandSizeToValue(cpu_address_size()));
						command->CompileToNative();
						break;
					case FACE_VAR_IS_PATCH_DETECTED_SALT:
					case FACE_VAR_IS_DEBUGGER_DETECTED_SALT:
					case FACE_VAR_LOADER_CRC_INFO_SALT:
					case FACE_VAR_LOADER_CRC_INFO_SIZE_SALT:
					case FACE_VAR_LOADER_CRC_INFO_HASH_SALT:
					case FACE_VAR_CPU_HASH_SALT:
					case FACE_VAR_DRIVER_UNLOAD_SALT:
					case FACE_VAR_CRC_IMAGE_SIZE_SALT:
					case FACE_VAR_SERVER_DATE_SALT:
					case FACE_VAR_OS_BUILD_NUMBER_SALT:
						command->set_operand_value(j, ctx.runtime_var_salt[value & 0xff]);
						command->CompileToNative();
						break;
					}
				}
			}
		}
	}

	return IntelFunction::Init(ctx);
}

size_t IntelRuntimeData::WriteToFile(IArchitecture& file)
{
	size_t res = IntelFunction::WriteToFile(file);

	CipherRC5 cipher(rc5_key_);
	for (size_t i = 0; i < 6; i++) {
		IntelCommand* command;
		size_t size;

		switch (i) {
		case 0:
			command = resources_entry_;
			size = resources_size_;
			break;
		case 1:
			command = strings_entry_;
			size = strings_size_;
			break;
		case 2:
			command = trial_hwid_entry_;
			size = AlignValue(trial_hwid_size_, 8);
			break;
		case 3:
			command = license_data_entry_;
			size = license_data_size_;
			break;
		case 4:
			command = files_entry_;
			size = files_size_;
			break;
		case 5:
			command = registry_entry_;
			size = registry_size_;
			break;
		default:
			command = NULL;
			size = 0;
		}

		if (size) {
			std::vector<uint8_t> buff;
			buff.resize(size);
			file.AddressSeek(command->address());
			uint64_t pos = file.Tell();
			file.Read(&buff[0], buff.size());
			if (command == trial_hwid_entry_) {
				cipher.Encrypt(buff.data(), buff.size());
			}
			else if (command == license_data_entry_) {
				size_t crc_pos = buff.size() - 16;
				cipher.Encrypt(buff.data(), crc_pos);
				SHA1 sha1;
				sha1.Input(buff.data(), crc_pos);
				const uint8_t* p = sha1.Result();
				for (size_t j = crc_pos; j < buff.size(); j++) {
					buff[j] = p[j - crc_pos];
				}
				cipher.Encrypt(buff.data() + crc_pos, 16);
			}
			else
			{
				uint32_t* p = reinterpret_cast<uint32_t*>(buff.data());
				for (size_t j = 0; j < size / sizeof(uint32_t); j++) {
					p[j] ^= data_key_;
				}
			}
			file.Seek(pos);
			file.Write(buff.data(), buff.size());
		}
	}

	return res;
}


