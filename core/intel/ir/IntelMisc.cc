#include "IntelMisc.h"
#include "IntelCommand.h"
#include "IntelFunction.h"
#include "IntelFunctionList.h"
#include "../../processors.h"
#include "../../files.h"
#include "../../pe/pefile.h"
#include "../../lang.h"

// Copied from intel.cc: IntelFileHelper implementation
// Line range: ~92 - end of IntelFileHelper

/**
 * IntelFileHelper
 */

IntelFileHelper::IntelFileHelper()
	: IObject(), marker_index_(0)
{
	marker_name_list_ = new MapFunctionList(NULL);
}

IntelFileHelper::~IntelFileHelper()
{
	delete marker_name_list_;
}

void IntelFileHelper::AddMarker(IArchitecture& file, uint64_t address, uint64_t name_reference, uint64_t name_address, ObjectType type, uint8_t tag, bool is_unicode)
{
	if (type == otUnknown)
		return;

	std::string marker_name;
	MapFunction* map_function;
	size_t name_length = 0;
	if (name_address) {
		// read marker name
		if (file.AddressSeek(name_address)) {
			if (is_unicode) {
				os::unicode_string wname;
				for (;;) {
					os::unicode_char w = file.ReadWord();
					if (w == 0)
						break;
					wname.push_back(w);
				}
				name_length = (wname.size() + 1) * sizeof(os::unicode_char);
				marker_name = os::ToUTF8(wname);
			}
			else {
				for (;;) {
					char c = file.ReadByte();
					if (c == 0)
						break;
					marker_name.push_back(c);
				}
				name_length = marker_name.size() + 1;
				marker_name = file.ANSIToUTF8(marker_name);
			}
		}

		map_function = marker_name_list_->GetFunctionByAddress(name_address);
		if (!map_function) {
			map_function = marker_name_list_->Add(name_address, name_address + name_length, otString, marker_name);
			// need add marker name to string_list for string references searching
			string_list_.push_back(map_function);
		}
		map_function->reference_list()->Add(name_reference, 0);
	}

	std::string name = marker_name.empty() ? string_format("VMProtectMarker%d", ++marker_index_) : string_format("VMProtectMarker \"%s\"", marker_name.c_str());

	map_function = file.map_function_list()->GetFunctionByAddress(address);
	if (!map_function) {
		map_function = file.map_function_list()->Add(address, 0, type, name);
	}
	else {
		map_function->set_type(type);
		map_function->set_name(name);
	}
	map_function->set_name_address(name_address);
	map_function->set_name_length(name_length);
	switch (tag & 0x7f) {
	case 1:
		map_function->set_compilation_type(ctVirtualization);
		break;
	case 2:
		map_function->set_compilation_type(ctMutation);
		break;
	case 3:
		map_function->set_compilation_type(ctUltra);
		break;
	}
	if (tag & 0x80)
		map_function->set_lock_to_key(true);
}

void IntelFileHelper::AddString(IArchitecture& file, uint64_t address, uint64_t reference, bool is_unicode)
{
	uint64_t end_address;
	std::string name;
	os::unicode_string wname;
	char c;
	os::unicode_char w;
	MapFunction* map_function;

	if (!file.AddressSeek(address))
		return;

	// read string from file
	if (is_unicode) {
		for (;;) {
			w = file.ReadWord();
			if (w == 0)
				break;
			wname.push_back(w);
		}
		end_address = address + (wname.size() + 1) * sizeof(w);
		name = os::ToUTF8(wname);
	}
	else {
		for (;;) {
			c = file.ReadByte();
			if (c == 0)
				break;
			name.push_back(c);
		}
		end_address = address + name.size() + 1;
		name = file.ANSIToUTF8(name);
	}
	name = "string \"" + name + "\"";

	map_function = file.map_function_list()->Add(address, end_address, otString, name);
	map_function->reference_list()->Add(reference, address);

	if (std::find(string_list_.begin(), string_list_.end(), map_function) == string_list_.end())
		string_list_.push_back(map_function);
}

void IntelFileHelper::AddEndMarker(IArchitecture& file, uint64_t address, uint64_t next_address, ObjectType type)
{
	file.end_marker_list()->Add(address, next_address, 0, 0, type);
}

void IntelFileHelper::Parse(IArchitecture& file)
{
	SignatureList asm_signatures, import_signatures, string_signatures, compiler_function_signatures;
	ISectionList* segment_list;
	size_t i, k, j, r, n, pointer_size, c;
	ISection* segment;
	uint64_t read_size, address, buf_address, operand_address, tmp_address, pointer_value, last_operand_address;
	uint8_t buf[4096], b, registr;
	Signature* sign;
	IntelFunctionList function_list(NULL);
	IntelFunction command_list(NULL, file.cpu_address_size());
	IntelCommand* command, * tmp_command;
	IImportFunction* import_function;
	IntelOperand operand, tmp_operand;
	IFixupList* fixup_list;
	IImportList* import_list;
	std::map<uint64_t, IImportFunction*> jmp_references;
	MarkerCommandList marker_command_list;
	MarkerCommand* marker_command;
	MapFunction* map_function;
	MapFunctionList* map_function_list;
	CompilerFunctionList* compiler_function_list;
	bool is_data_reference;
	std::map<uint64_t, IImportFunction*> call_import_function_map;

	asm_signatures.Add("EB10564D50726F7465637420626567696E0?");	// "VMProtect begin"
	asm_signatures.Add("EB0E564D50726F7465637420656E6400");	// "VMProtect end"

	import_signatures.Add("FF15");  // call dword ptr [xxxx]
	import_signatures.Add("FF25");  // jmp dword ptr [xxxx]
	import_signatures.Add("FF2425");// jmp dword ptr [xxxx]
	import_signatures.Add("E8");    // call xxxx
	import_signatures.Add("A1");    // mov eax, [xxxx]
	import_signatures.Add((file.cpu_address_size() == osQWord) ? "4?8B" : "8B");  // mov reg, [xxxx]
	import_signatures.Add((file.cpu_address_size() == osQWord) ? "4?8D" : "8D");  // lea reg, [xxxx]
	uint64_t plt_got_address = 0;

	if (file.cpu_address_size() == osDWord) {
		// patch TlsAlloc in Delphi6
		compiler_function_signatures.Add("5352BA????????89C38B5203B8????????8B12B905000000", cfPatchImport);

		// base registr
		compiler_function_signatures.Add("E8000000005?", cfBaseRegistr);

		// get base registr
		compiler_function_signatures.Add("8B1C24C3", cfGetBaseRegistr);
		compiler_function_signatures.Add("8B3424C3", cfGetBaseRegistr);
		compiler_function_signatures.Add("8B0424C3", cfGetBaseRegistr);
		compiler_function_signatures.Add("8B0C24C3", cfGetBaseRegistr);
		compiler_function_signatures.Add("8B1424C3", cfGetBaseRegistr);

		// DllFunctionCall in VB6
		compiler_function_signatures.Add("A1????????0BC07402FFE068????????B8????????FFD0FFE0", cfDllFunctionCall);

		// CxxSEH
		compiler_function_signatures.Add("6AFF68????????64A100000000", cfCxxSEH);
		compiler_function_signatures.Add("6AFF68????????68????????64A100000000", cfCxxSEH3);
		compiler_function_signatures.Add("6AFE68????????68????????64A100000000", cfCxxSEH4);
		compiler_function_signatures.Add("68????????64FF3500000000", cfSEH4Prolog);

		// VB6SEH
		compiler_function_signatures.Add("83EC??68????????64A1000000005064892500000000", cfVB6SEH);
		compiler_function_signatures.Add("81EC??????68????????64A1000000005064892500000000", cfVB6SEH);

		// __InitExceptBlockLDTC in BCB
		compiler_function_signatures.Add("538BDD03580?8943088D44240889430CC74304????????66C74310000066C743120000C7431C000000006467A1000089036467891E00005BC3", cfInitBCBSEH);

		// _pei386_runtime_relocator in MinGW
		compiler_function_signatures.Add("C705????????01000000B8????????2D????????83F8077EDDBB????????83F80B7E618B3D????????85FF750B8B35????????85F6743D", cfRelocatorMinGW);
		compiler_function_signatures.Add("C705????????01000000E8????????8D04408D04851E00000083E0F0E8????????C705????????0000000029C48D44241F83E0F0A3????????B8????????2D????????83F8070F8E??00000083F80B0F8E??010000A1????????85C00F85??000000A1????????85C00F85??000000", cfRelocatorMinGW);
		compiler_function_signatures.Add("C705????????01000000E8????????8D04408D04851E000000C1E804C1E004E8????????C705????????0000000029C48D44241F83E0F0A3????????B8????????2D????????83F807", cfRelocatorMinGW);


	}
	else {
		compiler_function_signatures.Add("554889E55DE9????????", cfJmpFunction);
	}

	segment_list = file.segment_list();
	fixup_list = file.fixup_list();
	import_list = file.import_list();
	map_function_list = file.map_function_list();
	compiler_function_list = file.compiler_function_list();

	for (i = 0; i < import_list->count(); i++) {
		IImport* import = import_list->item(i);
		for (j = 0; j < import->count(); j++) {
			import_function = import->item(j);
			if (import_function->options() & ioIsRelative) {
				import_function->map_function()->reference_list()->Add(import_function->address(), import_function->address() + 1);
				jmp_references[import_function->address()] = import_function;
			}
		}
	}

	j = 0;
	for (i = 0; i < segment_list->count(); i++) {
		segment = segment_list->item(i);
		if (!segment->need_parse())
			continue;

		j += static_cast<size_t>(segment->physical_size());
		if (compiler_function_signatures.count() && (segment->memory_type() & mtExecutable))
			j += static_cast<size_t>(segment->physical_size());
	}
	std::string arch_name = (file.owner()->visible_count() > 1) ? string_format(" (%s)", file.name().c_str()) : "";
	file.StartProgress(string_format("%s %s%s...", language[lsLoading].c_str(), os::ExtractFileName(file.owner()->file_name().c_str()).c_str(), arch_name.c_str()), j);

	if (compiler_function_signatures.count()) {
		// search compiler functions
		for (i = 0; i < segment_list->count(); i++) {
			segment = segment_list->item(i);
			if (!segment->need_parse() || (segment->memory_type() & mtExecutable) == 0)
				continue;

			compiler_function_signatures.InitSearch();
			read_size = 0;
			while (read_size < segment->physical_size()) {
				file.Seek(segment->physical_offset() + read_size);
				n = file.Read(buf, std::min(static_cast<size_t>(segment->physical_size() - read_size), sizeof(buf)));
				file.StepProgress(n);
				for (k = 0; k < n; k++) {
					b = buf[k];
					buf_address = segment->address() + read_size + k + 1;

					for (j = 0; j < compiler_function_signatures.count(); j++) {
						sign = compiler_function_signatures.item(j);
						if (sign->SearchByte(b)) {
							address = buf_address - sign->size();
							CompilerFunctionType func_type = static_cast<CompilerFunctionType>(sign->tag());
							switch (func_type) {
							case cfBaseRegistr:
							{
								IntelOperand base_operand = IntelOperand(otRegistr, command_list.cpu_address_size(), b & 7);
								uint64_t value = 0;
								command = command_list.ReadValidCommand(file, address + sign->size());
								if (command) {
									if (command->type() == cmMov && command->operand(1).type == otRegistr && command->operand(1).registr == base_operand.registr && (command->operand(0).type & otMemory))
										base_operand = command->operand(0); // mov [xxxx], reg
									else {
										if (command->type() == cmAdd && command->operand(0).type == otRegistr && command->operand(0).registr == base_operand.registr && command->operand(1).type == otValue)
											value = command->operand(1).value; // add reg, xxxx

										IntelCommandInfoList command_info_list(file.cpu_address_size());
										std::set<uint64_t> address_list;
										address_list.insert(command->next_address());
										while (!address_list.empty()) {
											tmp_address = *address_list.begin();
											for (;;) {
												std::set<uint64_t>::const_iterator it = address_list.find(tmp_address);
												if (it != address_list.end())
													address_list.erase(it);

												command = command_list.ReadValidCommand(file, tmp_address);
												if (!command || (command->options() & roBreaked) || command->is_data())
													break;

												if ((command->type() == cmJmp && command->operand(0).type == otValue) || command->type() == cmJmpWithFlag) {
													if (command->operand(0).value > tmp_address)
														address_list.insert(command->operand(0).value);
												}

												if (command->type() == cmJmp || command->type() == cmRet || command->type() == cmIret || command->type() == cmCall)
													break;

												if (!command->GetCommandInfo(command_info_list) || command_info_list.GetInfo(atWrite, otRegistr, base_operand.registr))
													break;

												if (command->type() == cmMov && command->operand(1).type == otRegistr && command->operand(1).registr == base_operand.registr && (command->operand(0).type & otMemory)) {
													base_operand = command->operand(0); // mov [xxxx], reg
													address_list.clear();
													break;
												}

												tmp_address = command->next_address();
											}
										}
									}
								}
								address += 5;
								CompilerFunction* compiler_function = compiler_function_list->Add(func_type, address);
								compiler_function->add_value(base_operand.encode());
								if (value)
									compiler_function->add_value(value);
							}
							break;

							case cfDllFunctionCall:
								command_list.ReadFromFile(file, address);
								if (command_list.count() == 8) {
									if (file.AddressSeek(command_list.item(4)->operand(0).value)) {
										std::string dll_name;
										std::string func_name;
										uint32_t dll_name_address = file.ReadDWord();
										uint32_t func_name_address = file.ReadDWord();
										if (file.AddressSeek(dll_name_address))
											dll_name = file.ReadString();
										if (file.AddressSeek(func_name_address))
											func_name = file.ReadString();
										std::transform(dll_name.begin(), dll_name.end(), dll_name.begin(), tolower);
										if (dll_name.find('.') == NOT_ID)
											dll_name += ".dll";
										if (dll_name == "vmprotectsdk32.dll") {
											const ImportInfo* import_info = file.import_list()->GetSDKInfo(func_name);
											if (import_info) {
												CompilerFunction* compiler_function = compiler_function_list->Add(func_type, address);
												compiler_function->add_value(import_info->encode());
												compiler_function->add_value(dll_name_address);
												compiler_function->add_value(dll_name.size() + 1);
												compiler_function->add_value(func_name_address);
												compiler_function->add_value(func_name.size() + 1);
											}
										}
									}
								}
								break;

							case cfCxxSEH:
							case cfCxxSEH3:
							case cfCxxSEH4:
								command = command_list.ReadValidCommand(file, address + 2);
								if (command) {
									CompilerFunction* compiler_function = compiler_function_list->Add(func_type, address);
									compiler_function->add_value(command->operand(0).value);
								}
								break;

							case cfVB6SEH:
							{
								command = command_list.ReadValidCommand(file, address);
								uint64_t offset = 4 - command->operand(1).value;
								for (;;) {
									command = command_list.ReadValidCommand(file, address);
									if (!command || command->is_end())
										break;

									if (command->operand(0).type == (otMemory | otRegistr | otValue)
										&& command->operand(0).registr == regEBP
										&& command->operand(0).size == osDWord
										&& command->operand(0).value == offset
										&& command->operand(1).type == otValue) { // mov [ebp + xxxx], xxxx
										CompilerFunction* compiler_function = compiler_function_list->Add(cfVB6SEH, command->address());
										compiler_function->add_value(command->operand(1).value);
										break;
									}
									address = command->next_address();
								}
							}
							break;

							case cfInitBCBSEH:
							{
								CompilerFunction* compiler_function = compiler_function_list->Add(cfInitBCBSEH, address);
								if (file.AddressSeek(address + 5)) {
									b = file.ReadByte();
									if (b == 8)
										compiler_function->add_value(2);
									else if (b == 4)
										compiler_function->add_value(1);
								}
							}
							break;

							case cfRelocatorMinGW:
							{
								command_list.clear();
								size_t d;
								switch (sign->size()) {
								case 73:
									d = 11;
									break;
								case 111:
									d = 10;
									break;
								default:
									d = 0;
									break;
								}

								while (command_list.count() < 13 + d) {
									command = command_list.ReadValidCommand(file, address);
									if (!command)
										break;

									address = command->next_address();
								}

								if (command_list.count() == 13 + d) {
									CompilerFunction* compiler_function = compiler_function_list->Add(cfRelocatorMinGW, address);
									compiler_function->add_value(command_list.item(0)->operand(0).value);
									compiler_function->add_value(command_list.item(d + 2)->operand(1).value);
									compiler_function->add_value(command_list.item(d + 1)->operand(1).value);
								}
							}
							break;

							case cfPatchImport:
								command = command_list.ReadValidCommand(file, address + 2);
								if (command && file.AddressSeek(command->operand(1).value + 3)) {
									import_function = import_list->GetFunctionByAddress(file.ReadDWord());
									if (import_function)
										import_function->include_option(ioHasDataReference);
								}
								break;

							case cfJmpFunction:
								command = command_list.ReadValidCommand(file, address + 5);
								if (command && file.segment_list()->GetMemoryTypeByAddress(command->operand(0).value) & mtExecutable) {
									CompilerFunction* compiler_function = compiler_function_list->Add(cfJmpFunction, address);
									compiler_function->add_value(command->operand(0).value);
								}
								break;

							case cfGetBaseRegistr:
								command = command_list.ReadValidCommand(file, address);
								if (command) {
									CompilerFunction* compiler_function = compiler_function_list->Add(cfGetBaseRegistr, address);
									compiler_function->add_value(command->operand(0).registr);
								}
								break;

							default:
								compiler_function_list->Add(func_type, address);
								break;
							}
						}
					}
				}
				read_size += n;
			}
		}
	}

	pointer_size = OperandSizeToValue(file.cpu_address_size());
	for (i = 0; i < segment_list->count(); i++) {
		segment = segment_list->item(i);
		if (!segment->need_parse())
			continue;

		asm_signatures.InitSearch();
		import_signatures.InitSearch();
		read_size = 0;
		pointer_value = 0;
		last_operand_address = 0;
		while (read_size < segment->physical_size()) {
			file.Seek(segment->physical_offset() + read_size);
			n = file.Read(buf, std::min(static_cast<size_t>(segment->physical_size() - read_size), sizeof(buf)));
			file.StepProgress(n);
			for (k = 0; k < n; k++) {
				b = buf[k];
				buf_address = segment->address() + read_size + k + 1;

				if (segment->memory_type() & mtExecutable) {
					// search asm markers
					for (j = 0; j < asm_signatures.count(); j++) {
						sign = asm_signatures.item(j);
						if (sign->SearchByte(b)) {
							address = buf_address - sign->size();
							switch (j) {
							case 0:
								AddMarker(file, address, 0, 0, otMarker, b, false);
								break;
							case 1:
								AddEndMarker(file, address, address + sign->size(), otMarker);
								break;
							}
						}
					}

					// search references to import
					for (j = 0; j < import_signatures.count(); j++) {
						sign = import_signatures.item(j);
						if (sign->SearchByte(b)) {
							address = buf_address - sign->size();
							command_list.clear();
							command = command_list.ReadValidCommand(file, address);
							if (!command)
								continue;

							IntelCommandType ref_command = static_cast<IntelCommandType>(command->type());
							operand = command->operand((ref_command == cmJmp || ref_command == cmCall) ? 0 : 1);
							if ((operand.type & otValue) == 0)
								continue;

							operand_address = address + operand.value_pos;
							uint64_t next_address = command->next_address();

							import_function = NULL;
							if (j == 3 && !operand.relocation) {
								// check compiler function
								CompilerFunction* compiler_function = compiler_function_list->GetFunctionByAddress(operand.value);
								if (compiler_function) {
									switch (compiler_function->type()) {
									case cfGetBaseRegistr:
										registr = static_cast<uint8_t>(compiler_function->value(0));
										compiler_function = compiler_function_list->Add(cfBaseRegistr, next_address);
										compiler_function->add_value(IntelOperand(otRegistr, command_list.cpu_address_size(), registr).encode());
										tmp_address = command->next_address();
										for (;;) {
											tmp_command = command_list.ReadValidCommand(file, tmp_address);
											if (tmp_command && tmp_command->type() == cmAdd && tmp_command->operand(0).type == otRegistr) {
												if (tmp_command->operand(0).registr == registr) {
													compiler_function->add_value(tmp_command->operand(1).value);
													break;
												}
												tmp_address = tmp_command->next_address();
											}
											else {
												break;
											}
										}
										break;

									case cfDllFunctionCall:
										compiler_function->include_option(coUsed);
										ImportInfo sdk_info;
										sdk_info.decode(compiler_function->value(0));
										switch (sdk_info.type) {
										case atBegin:
										{
											b = 0;
											if (sdk_info.options & ioHasCompilationType)
												b = 1 + sdk_info.compilation_type;
											if (sdk_info.options & ioLockToKey)
												b |= 0x80;

											command_list.ReadMarkerCommands(file, marker_command_list, address, moNeedParam | moSkipLastCall);
											if (marker_command_list.count() == 0) {
												AddMarker(file, address, 0, 0, otAPIMarker, b, true);
											}
											else {
												marker_command_list.Sort();
												for (r = 0; r < marker_command_list.count(); r++) {
													marker_command = marker_command_list.item(r);
													AddMarker(file, marker_command->address(),
														marker_command->name_reference(),
														marker_command->name_address(),
														otAPIMarker, b, true);
												}
											}
										}
										break;

										case atEnd:
											AddEndMarker(file, address, next_address, otAPIMarker);
											break;
										case atDecryptStringW:
											command_list.ReadMarkerCommands(file, marker_command_list, address, moNeedParam | moSkipLastCall);
											for (r = 0; r < marker_command_list.count(); r++) {
												marker_command = marker_command_list.item(r);
												AddString(file, marker_command->name_address(), marker_command->name_reference(), true);
											}
											break;
										}
										break;

									case cfInitBCBSEH:
									{
										uint8_t version = static_cast<uint8_t>(compiler_function->value(0));
										if (version) {
											for (size_t d = 0x30; d > 0; d--) {
												if (!file.AddressSeek(address - d))
													continue;

												command_list.clear();
												tmp_address = address - d;
												while (tmp_address < address) {
													command = command_list.ReadValidCommand(file, tmp_address);
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
													if (command->type() == cmCall)
														command_list.clear();
												}

												if (tmp_address != address)
													continue;

												for (size_t c = command_list.count(); c > 0; c--) {
													command = command_list.item(i);
													if (command->type() == cmMov && command->operand(0).type == otRegistr && command->operand(0).registr == regEAX) {
														if (command->operand(1).type == otValue) {
															compiler_function = compiler_function_list->Add(cfBCBSEH, address);
															compiler_function->add_value(command->operand(1).value);
															compiler_function->add_value(version);
														}
														d = 1;
													}
												}
											}
										}
									}
									break;

									case cfJmpFunction:
										operand.value = compiler_function->value(0);
										break;
									}
								}

								// try to search import_function by jmp references
								std::map<uint64_t, IImportFunction*>::const_iterator it = jmp_references.find(operand.value);
								if (it != jmp_references.end())
									import_function = it->second;

								if (!import_function) {
									tmp_address = operand.value;
									for (;;) {
										// try parse jmp branches
										tmp_command = command_list.ReadValidCommand(file, tmp_address);
										if (tmp_command) {
											if (tmp_command->type() == cmJmp && (tmp_command->options() & roFar) == 0) {
												// jmp xxxx
												tmp_operand = tmp_command->operand(0);
												if (tmp_operand.type == otValue) {
													if (command_list.GetCommandByNearAddress(tmp_operand.value) == NULL) {
														tmp_address = tmp_operand.value;
														continue;
													}
												}
												else if (tmp_operand.type == (otMemory | otValue)) {
													import_function = import_list->GetFunctionByAddress(tmp_operand.value);
												}
											}
											else if (tmp_command->type() == cmNop) {
												// rep nop xxxx
												tmp_address = tmp_command->next_address();
												continue;
											}
										}
										break;
									}
								}
							}
							else if (j == 8)
								import_function = import_list->GetFunctionByAddress(plt_got_address + operand.value);
							else
								import_function = import_list->GetFunctionByAddress(operand.relocation ? operand_address : operand.value);

							if (import_function) {
								if ((ref_command == cmJmp || j == 3) && (import_function->options() & ioNoReturn)) {
									tmp_address = (j == 3) ? command->operand(0).value : address;
									CompilerFunction* compiler_function = compiler_function_list->GetFunctionByAddress(tmp_address);
									if (!compiler_function)
										compiler_function = compiler_function_list->Add(cfNone, tmp_address);
									compiler_function->include_option(coNoReturn);
								}

								// check data reference to import function
								if (ref_command == cmMov) {
									is_data_reference = true;
									registr = command->operand(0).registr;
									tmp_address = command->next_address();
									while (segment_list->GetMemoryTypeByAddress(tmp_address) & mtExecutable) {
										command = command_list.ReadValidCommand(file, tmp_address);
										if (!command)
											break;

										tmp_address = command->next_address();
										if (command->operand(0).type == otRegistr && command->operand(0).registr == registr) {
											if (command->type() == cmJmp || command->type() == cmCall)
												is_data_reference = false;
											break;
										}
										else if (command->type() == cmJmp && command->operand(0).type == otValue && command->operand(0).value >= tmp_address) {
											tmp_address = command->operand(0).value;
										}
										else if (command->type() == cmDB
											|| command->type() == cmJmp
											|| command->type() == cmCall
											|| command->type() == cmRet
											|| command->type() == cmIret)
											break;
									}
									if (is_data_reference)
										import_function->include_option(ioHasDataReference);
								}

								switch (import_function->type()) {
								case atBegin:
									if (ref_command != cmJmp) {
										command_list.ReadMarkerCommands(file, marker_command_list, address, moNeedParam | (ref_command == cmMov ? moForward : 0));

										b = 0;
										if ((import_function->options() & ioHasCompilationType) != 0)
											b = 1 + import_function->compilation_type();
										if ((import_function->options() & ioLockToKey) != 0)
											b |= 0x80;

										if (marker_command_list.count() == 0) {
											AddMarker(file, address, 0, 0, otAPIMarker, b, false);
										}
										else {
											marker_command_list.Sort();
											for (r = 0; r < marker_command_list.count(); r++) {
												marker_command = marker_command_list.item(r);
												AddMarker(file, marker_command->address(),
													marker_command->name_reference(),
													marker_command->name_address(),
													otAPIMarker, b, false);
											}
										}
									}
									break;

								case atEnd:
									if (ref_command == cmMov) {
										command_list.ReadMarkerCommands(file, marker_command_list, address, (ref_command == cmMov ? moForward : 0)); //-V547
										if (marker_command_list.count()) {
											marker_command_list.Sort();
											for (r = 0; r < marker_command_list.count(); r++) {
												marker_command = marker_command_list.item(r);
												AddEndMarker(file, marker_command->address(),
													marker_command->operand_address(),
													otAPIMarker);
											}
										}
									}
									else if (ref_command != cmJmp)
										AddEndMarker(file, address, next_address, otAPIMarker);
									break;

								case atDecryptStringA: case atDecryptStringW:
									command_list.ReadMarkerCommands(file, marker_command_list, address, moNeedParam | (ref_command == cmMov ? moForward : 0));
									for (r = 0; r < marker_command_list.count(); r++) {
										marker_command = marker_command_list.item(r);
										AddString(file, marker_command->name_address(), marker_command->name_reference(), import_function->type() == atDecryptStringW);
										call_import_function_map[marker_command->address()] = import_function;
									}
									break;
								}
								if (j == 3 || j == 7) {
									if (import_function->address() == operand_address)
										import_function->map_function()->reference_list()->Add(address, operand_address);
								}
								else {
									last_operand_address = operand_address;
									import_function->map_function()->reference_list()->Add(address, operand_address);
									// add jmp_reference for next searching
									if (ref_command == cmJmp)
										jmp_references[address] = import_function;
								}
							}
						}
					}
				}

				// check data reference
				pointer_value >>= 8;
				pointer_value |= static_cast<uint64_t>(b) << ((pointer_size - 1) * 8);
				if (buf_address >= segment->address() + pointer_size - 1) {
					tmp_address = buf_address - pointer_size;
					if ((segment_list->GetMemoryTypeByAddress(pointer_value) & mtReadable) && (fixup_list->count() == 0 || fixup_list->GetFixupByAddress(tmp_address))) {
						import_function = import_list->GetFunctionByAddress(pointer_value);
						if (import_function && last_operand_address != tmp_address)
							import_function->include_option(ioHasDataReference);
					}
				}
			}
			read_size += n;
		}
	}

	// search references to strings
	if (string_list_.size() > 0) {
		if (file.cpu_address_size() == osQWord) {
			string_signatures.Add("4?8D"); // lea reg, [xxxxxxxx]
			string_signatures.Add("48B?"); // mov reg, xxxxxxxx
		}
		else {
			string_signatures.Add("B?");  // mov reg, xxxxxxxx
			string_signatures.Add("C7");  // mov [xxxxxxxx], xxxxxxxx
			string_signatures.Add("8D");  // lea reg, [xxxxxxxx]
			string_signatures.Add("68");  // push xxxxxxxx
		}

		for (i = 0; i < segment_list->count(); i++) {
			segment = segment_list->item(i);
			if (!segment->need_parse() || (segment->memory_type() & mtExecutable) == 0)
				continue;

			string_signatures.InitSearch();
			read_size = 0;
			while (read_size < segment->physical_size()) {
				file.Seek(segment->physical_offset() + read_size);
				n = file.Read(buf, std::min(static_cast<size_t>(segment->physical_size() - read_size), sizeof(buf)));
				for (k = 0; k < n; k++) {
					b = buf[k];
					buf_address = segment->address() + read_size + k + 1;

					for (j = 0; j < string_signatures.count(); j++) {
						sign = string_signatures.item(j);
						if (sign->SearchByte(b)) {
							address = buf_address - sign->size();
							command_list.clear();
							command = command_list.ReadValidCommand(file, address);
							if (!command)
								continue;

							uint64_t delta_offset = (uint64_t)-1;
							if (command->operand(0).type == otRegistr) {
								tmp_command = command_list.ReadValidCommand(file, command->next_address());
								if (tmp_command && tmp_command->type() == cmLea && tmp_command->operand(1).type == (otMemory | otRegistr | otValue) && tmp_command->operand(1).registr == command->operand(0).registr)
									delta_offset = tmp_command->operand(1).value;
							}

							operand = command->operand(command->type() != cmPush);
							if ((operand.type & otValue) == 0)
								continue;

							tmp_command = command_list.ReadValidCommand(file, command->next_address());
							if (tmp_command && tmp_command->type() == cmJmp && tmp_command->operand(0).type == otValue) {
								tmp_command = command_list.ReadValidCommand(file, tmp_command->operand(0).value);
								if (tmp_command && tmp_command->type() == cmCall) {
									std::map<uint64_t, IImportFunction*>::const_iterator it = call_import_function_map.find(tmp_command->address());
									if (it != call_import_function_map.end()) {
										import_function = it->second;
										if (import_function->type() == atDecryptStringA || import_function->type() == atDecryptStringW) {
											uint64_t param_reference;
											if (command_list.ParseParam(file, 1, param_reference))
												AddString(file, operand.value, command->address(), import_function->type() == atDecryptStringW);
										}
									}
								}
							}

							for (r = 0; r < string_list_.size(); r++) {
								map_function = string_list_[r];
								bool is_match = false;
								if (map_function->address() <= operand.value && map_function->end_address() > operand.value)
									is_match = true;
								else for (c = 0; c < map_function->equal_address_list()->count(); c++) {
									Reference* reference = map_function->equal_address_list()->item(c);
									if (reference->address() <= operand.value && reference->operand_address() > operand.value) {
										is_match = true;
										break;
									}
								}

								if (is_match) {
									if (map_function->reference_list()->GetReferenceByAddress(address) == NULL && (delta_offset == (uint64_t)-1 || delta_offset < map_function->end_address() - map_function->address()))
										map_function->reference_list()->Add(address, operand.value, 1);
									break;
								}
							}
						}
					}
				}
				read_size += n;
			}
		}

		// check references to marker_names
		for (i = 0; i < map_function_list->count(); i++) {
			map_function = map_function_list->item(i);
			if (map_function->type() == otAPIMarker) {
				MapFunction* name_function = NULL;
				for (j = 0; j < string_list_.size(); j++) {
					if (string_list_[j]->address() == map_function->name_address() || string_list_[j]->equal_address_list()->GetReferenceByAddress(map_function->name_address())) {
						name_function = string_list_[j];
						break;
					}
				}
				if (name_function && name_function->reference_list()->count() > 1) {
					uint64_t end_name_address = map_function->name_address() + map_function->name_length();
					for (j = 0; j < name_function->reference_list()->count(); j++) {
						Reference* reference = name_function->reference_list()->item(j);
						if (reference->tag() != 1)
							continue;

						if (map_function->name_address() <= reference->operand_address() && end_name_address > reference->operand_address())
							end_name_address = reference->operand_address();
					}
					if (end_name_address > map_function->name_address())
						map_function->set_name_length(static_cast<size_t>(end_name_address - map_function->name_address()));
					else
						map_function->set_name_address(0);
				}
			}
		}
	}

	// check import functions without references
	for (i = 0; i < import_list->count(); i++) {
		IImport* import = import_list->item(i);
		for (j = 0; j < import->count(); j++) {
			import_function = import->item(j);
			if ((import_function->options() & ioHasDataReference) == 0 && import_function->map_function()->reference_list()->count() == 0)
				import_function->include_option(ioNoReferences);
		}
	}

	file.EndProgress();
};
