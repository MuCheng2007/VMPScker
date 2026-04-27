#include "IntelFunctionList.h"
#include "IntelFunction.h"
#include "IntelCommand.h"
#include "IntelSDK.h"
#include "IntelLoader.h"
#include "../../processors.h"
#include "../../core.h"
#include "../../files.h"
#include "../../pefile.h"
#include "../../lang.h"
#include "../../osutils.h"
#include "../../../runtime/crypto.h"
#include "../../core_internal/watermark.h"

// VM layer
#include "../vm/IntelVirtualMachineProcessor.h"

// Copied from intel.cc:
// - IntelFunctionList (lines: ~27302 - 27475)
// - PEIntelFunctionList (lines: ~27476 - ?)
// - MacIntelFunctionList (lines: ?)
// - ELFIntelFunctionList (lines: ?)
/**
 * IntelFunctionList
 */

IntelFunctionList::IntelFunctionList(IArchitecture* owner)
	: BaseFunctionList(owner), import_(NULL), crc_table_(NULL), loader_data_(NULL), runtime_crc_table_(NULL)
{
	crc_cryptor_ = new ValueCryptor();
}

IntelFunctionList::IntelFunctionList(IArchitecture* owner, const IntelFunctionList& src)
	: BaseFunctionList(owner, src), import_(NULL), crc_table_(NULL), loader_data_(NULL), runtime_crc_table_(NULL)
{
	crc_cryptor_ = new ValueCryptor();
}

IntelFunctionList::~IntelFunctionList()
{
	delete crc_cryptor_;
}

IntelFunctionList* IntelFunctionList::Clone(IArchitecture* owner) const
{
	IntelFunctionList* list = new IntelFunctionList(owner, *this);
	return list;
}

IntelFunction* IntelFunctionList::Add(const std::string& name, CompilationType compilation_type, uint32_t compilation_options, bool need_compile, Folder* folder)
{
	IntelFunction* func = new IntelFunction(this, name, compilation_type, compilation_options, need_compile, folder);
	AddObject(func);
	return func;
}

IntelFunction* IntelFunctionList::CreateFunction(OperandSize cpu_address_size)
{
	return new IntelFunction(this, cpu_address_size);
}

IntelFunction* IntelFunctionList::item(size_t index) const
{
	return reinterpret_cast<IntelFunction*>(BaseFunctionList::item(index));
}

IntelFunction* IntelFunctionList::GetFunctionByAddress(uint64_t address) const
{
	return reinterpret_cast<IntelFunction*>(BaseFunctionList::GetFunctionByAddress(address));
}

IntelSDK* IntelFunctionList::AddSDK(OperandSize cpu_address_size)
{
	IntelSDK* func = new IntelSDK(this, cpu_address_size);
	AddObject(func);
	return func;
}

IntelImport* IntelFunctionList::AddImport(OperandSize cpu_address_size)
{
	IntelImport* func = new IntelImport(this, cpu_address_size);
	AddObject(func);
	return func;
}

IntelRuntimeData* IntelFunctionList::AddRuntimeData(OperandSize cpu_address_size)
{
	IntelRuntimeData* func = new IntelRuntimeData(this, cpu_address_size);
	AddObject(func);
	return func;
}

IntelCRCTable* IntelFunctionList::AddCRCTable(OperandSize cpu_address_size)
{
	IntelCRCTable* func = new IntelCRCTable(this, cpu_address_size);
	AddObject(func);
	return func;
}

IntelLoaderData* IntelFunctionList::AddLoaderData(OperandSize cpu_address_size)
{
	IntelLoaderData* func = new IntelLoaderData(this, cpu_address_size);
	AddObject(func);
	return func;
}

IntelFunction* IntelFunctionList::AddWatermark(OperandSize cpu_address_size, Watermark* watermark, int copy_count)
{
	IntelFunction* func = new IntelFunction(this, cpu_address_size);
	func->set_compilation_type(ctMutation);
	func->set_memory_type(mtNone);
	func->AddWatermark(watermark, copy_count);
	AddObject(func);
	return func;
}

IntelRuntimeCRCTable* IntelFunctionList::AddRuntimeCRCTable(OperandSize cpu_address_size)
{
	IntelRuntimeCRCTable* func = new IntelRuntimeCRCTable(this, cpu_address_size);
	AddObject(func);
	return func;
}

IntelVirtualMachineProcessor* IntelFunctionList::AddProcessor(OperandSize cpu_address_size)
{
	IntelVirtualMachineProcessor* func = new IntelVirtualMachineProcessor(this, cpu_address_size);
	AddObject(func);
	return func;
}

void IntelFunctionList::ReadFromBuffer(Buffer& buffer, IArchitecture& file)
{
	BaseFunctionList::ReadFromBuffer(buffer, file);

	// add loader stubs
	size_t c = count();
	for (size_t i = 0; i < c; i++) {
		IntelFunction* func = item(i);
		if (func->tag() != ftLoader)
			continue;

		for (size_t j = 0; j < func->count(); j++) {
			IntelCommand* command = func->item(j);
			if (command->type() == cmCall && command->operand(0).type == otValue) {
				uint64_t address = command->operand(0).value;
				if (address == command->next_address() || GetFunctionByAddress(address))
					continue;

				IntelFunction* new_func = reinterpret_cast<IntelFunction*>(AddByAddress(address, ctMutation, 0, false, NULL));
				if (new_func) {
					new_func->set_tag(ftLoader);
					for (size_t k = 0; k < new_func->count(); k++) {
						IntelCommand* command = new_func->item(k);
						command->exclude_option(roClearOriginalCode);
#ifdef CHECKED
						command->update_hash();
#endif
					}
				}
			}
		}
	}
}

bool IntelFunctionList::Prepare(const CompileContext& ctx)
{
	IntelFunction* func;
	IntelCommand* command;
	size_t i, j;
	OperandSize cpu_address_size = ctx.file->cpu_address_size();

	crc_cryptor_->clear();
	crc_cryptor_->set_size(osDWord);
	crc_cryptor_->Add(ccXor, rand32());

	if ((ctx.options.flags | ctx.options.sdk_flags) & cpMemoryProtection) {
		crc_table_ = AddCRCTable(cpu_address_size);
	}
	else {
		crc_table_ = NULL;
	}

	if (ctx.runtime) {
		// remove CalcCRC function
		IntelFunctionList* function_list = reinterpret_cast<IntelFunctionList*>(ctx.runtime->function_list());
		uint64_t calc_crc_address = ctx.runtime->export_list()->GetAddressByType(atCalcCRC);
		if (!calc_crc_address)
			return false;
		func = function_list->GetFunctionByAddress(calc_crc_address);
		if (!func)
			return false;
		func->set_need_compile(false);
		for (i = 0; i < function_list->count(); i++) {
			func = function_list->item(i);
			for (j = 0; j < func->count(); j++) {
				command = func->item(j);
				if (command->type() == cmCall && command->operand(0).type == otValue && command->operand(0).value == calc_crc_address) {
					delete command->link();
					command->Init(cmCrc);
#ifdef CHECKED
					command->update_hash();
#endif
				}
			}
		}

		if (ctx.runtime->segment_list()->count() > 0) {
			// add runtime functions
			for (i = 0; i < function_list->count(); i++) {
				func = function_list->item(i);

				if (func->need_compile()) {
					func = func->Clone(this);
					AddObject(func);

					if (func->type() == otString) {
						for (j = 0; j < func->count(); j++) {
							command = func->item(j);
							for (size_t k = 0; k < MESSAGE_COUNT; k++) {
								os::unicode_string unicode_message =
#ifdef VMP_GNU
									os::FromUTF8(default_message[k]);
#else
									default_message[k];
#endif
								if (command->CompareDump(reinterpret_cast<const uint8_t*>(unicode_message.c_str()), (unicode_message.size() + 1) * sizeof(os::unicode_char))) {
									os::unicode_string str = os::FromUTF8(ctx.options.messages[k]);
									command->set_dump(reinterpret_cast<const uint8_t*>(str.c_str()), (str.size() + 1) * sizeof(os::unicode_char));
								}
								else {
									std::string message =
#ifdef VMP_GNU								
										default_message[k];
#else									
										os::ToUTF8(default_message[k]);
#endif
									if (command->CompareDump(reinterpret_cast<const uint8_t*>(message.c_str()), message.size() + 1)) {
										std::string str = ctx.options.messages[k];
										command->set_dump(reinterpret_cast<const uint8_t*>(str.c_str()), str.size() + 1);
									}
								}
							}
						}
					}

					for (j = 0; j < func->count(); j++) {
						func->item(j)->CompileToNative();
					}
				}
				else {
					// need delete import references
					for (j = 0; j < ctx.runtime->map_function_list()->count(); j++) {
						ReferenceList* reference_list = ctx.runtime->map_function_list()->item(j)->reference_list();
						for (size_t k = reference_list->count(); k > 0; k--) {
							Reference* reference = reference_list->item(k - 1);
							command = func->GetCommandByNearAddress(reference->address());
							if (command && (command->options() & roClearOriginalCode))
								delete reference;
						}
					}
					if (!func->FreeByManager(ctx))
						return false;
				}
			}

			AddRuntimeData(cpu_address_size);
		}
	}

	if (ctx.options.flags & cpImportProtection) {
		import_ = AddImport(cpu_address_size);
	}
	else {
		import_ = NULL;
	}

	AddSDK(cpu_address_size);

	if (ctx.runtime && ctx.runtime->segment_list()->count() == 0) {
		loader_data_ = AddLoaderData(cpu_address_size);
	}
	else {
		loader_data_ = NULL;
	}

	AddWatermark(cpu_address_size, ctx.options.watermark, ctx.runtime ? 8 : 10);

	return BaseFunctionList::Prepare(ctx);
}

void IntelFunctionList::CompileLinks(const CompileContext& ctx)
{
	if (ctx.options.flags & cpMemoryProtection) {
		runtime_crc_table_ = AddRuntimeCRCTable(ctx.file->cpu_address_size());
		runtime_crc_table_->Compile(ctx);
	}
	else {
		runtime_crc_table_ = NULL;
	}

	BaseFunctionList::CompileLinks(ctx);
}

bool IntelFunctionList::GetRuntimeOptions() const
{
	for (size_t i = 0; i < count(); i++) {
		IntelFunction* func = item(i);
		if (func->tag() != ftLoader)
			continue;

		for (size_t j = 0; j < func->count(); j++) {
			IntelCommand* command = func->item(j);

			if (command->link() && command->link()->to_address()) {
				if (!GetCommandByAddress(command->link()->to_address(), false))
					return true;
			}
			else {
				for (size_t k = 0; k < 3; k++) {
					IntelOperand operand = command->operand(k);
					if (operand.type == otNone)
						break;

					if ((operand.type & otValue) && (operand.fixup || operand.is_large_value)) {
						if (owner()->image_base() == operand.value || owner()->import_list()->GetFunctionByAddress(operand.value))
							continue;

						if (!GetCommandByAddress(operand.value, false))
							return true;
					}
				}
			}
		}
	}
	return false;
}

/**
 * PEIntelFunctionList
 */

PEIntelFunctionList::PEIntelFunctionList(IArchitecture* owner)
	: IntelFunctionList(owner)
{

}

PEIntelFunctionList::PEIntelFunctionList(IArchitecture* owner, const PEIntelFunctionList& src)
	: IntelFunctionList(owner, src)
{

}

PEIntelFunctionList* PEIntelFunctionList::Clone(IArchitecture* owner) const
{
	PEIntelFunctionList* list = new PEIntelFunctionList(owner, *this);
	return list;
}

IntelSDK* PEIntelFunctionList::AddSDK(OperandSize cpu_address_size)
{
	IntelSDK* func = new PEIntelSDK(this, cpu_address_size);
	AddObject(func);
	return func;
}

PEIntelExport* PEIntelFunctionList::AddExport(OperandSize cpu_address_size)
{
	PEIntelExport* func = new PEIntelExport(this, cpu_address_size);
	AddObject(func);
	return func;
}

void PEIntelFunctionList::ReadFromBuffer(Buffer& buffer, IArchitecture& file)
{
	IntelFunctionList::ReadFromBuffer(buffer, file);

	if (file.cpu_address_size() == osDWord && reinterpret_cast<PEArchitecture&>(file).image_type() == itDriver) {
		// add exception handler
		IntelFunction* except_handler = NULL;
		for (size_t i = 0; i < count(); i++) {
			IntelFunction* func = item(i);
			if (func->tag() != ftLoader)
				continue;

			for (size_t j = 0; j < func->count(); j++) {
				IntelCommand* command = func->item(j);
				if (command->base_segment() == segFS && command->operand(0).type == otRegistr && command->operand(1).type == (otMemory | otValue) && command->operand(1).value == 0) {
					// mov reg, fs:[00000000]
					command = func->item(j - 1);
					uint64_t address = command->operand(0).value;
					command->AddLink(0, ltOffset, address);
					if (!GetFunctionByAddress(address)) {
						IntelFunction* new_func = reinterpret_cast<IntelFunction*>(AddByAddress(address, ctMutation, 0, false, NULL));
						if (new_func) {
							new_func->set_tag(ftLoader);
							for (size_t k = 0; k < new_func->count(); k++) {
								IntelCommand* command = new_func->item(k);
								command->exclude_option(roClearOriginalCode);
								if (command->seh_handler())
									command->set_seh_handler(NEED_SEH_HANDLER);
#ifdef CHECKED
								command->update_hash();
#endif
							}
						}
					}
				}
			}
		}
	}
}

bool PEIntelFunctionList::Prepare(const CompileContext& ctx)
{
	if (ctx.runtime) {
		PEArchitecture* file = reinterpret_cast<PEArchitecture*>(ctx.file);
		if (file->image_type() == itDriver) {
			IntelFunctionList* function_list = reinterpret_cast<IntelFunctionList*>(ctx.runtime->function_list());
			for (size_t i = 0; i < function_list->count(); i++) {
				IntelFunction* func = function_list->item(i);
				for (size_t j = 0; j < func->count(); j++) {
					IntelCommand* command = func->item(j);
					for (size_t k = 0; k < 3; k++) {
						IntelOperand operand = command->operand(k);
						if (operand.type == otNone)
							break;

						if ((operand.type & otValue) == 0)
							continue;

						uint32_t value = static_cast<uint32_t>(operand.value);
						if ((value & 0xFFFF0000) == 0xFACE0000) {
							switch (value) {
							case FACE_NON_PAGED_POOL_NX:
								// NonPagedPoolNx
								command->set_operand_value(k, file->operating_system_version() >= 0x060002 ? 512 : 0);
								command->CompileToNative();
								break;
							case FACE_DEFAULT_MDL_PRIORITY:
								// MdlMappingNoExecute | HighPagePriority
								command->set_operand_value(k, file->operating_system_version() >= 0x060002 ? 0x40000020 : 0x20);
								command->CompileToNative();
								break;
							}
						}
					}
				}
			}
		}

		if (file->entry_point()) {
			IntelFunction* entry_point_func = GetFunctionByAddress(file->entry_point());
			if (entry_point_func) {
				entry_point_func->set_entry_type(etNone);
				entry_point_func->entry()->include_section_option(rtLinkedToInt);
			}
		}
	}

	return IntelFunctionList::Prepare(ctx);
}
