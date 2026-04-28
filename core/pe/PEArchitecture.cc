

#include "../../runtime/common.h"
#include "../../runtime/crypto.h"
#include "../objects.h"
#include "../osutils.h"
#include "../streams.h"
#include "../files/architecture.h"
#include "../files/mapping.h"
#include "../files/sections.h"
#include "../files/imports.h"
#include "../files/exports.h"
#include "../files/fixups.h"
#include "../files/relocations.h"
#include "../files/resources.h"
#include "../files/runtime_func.h"
#include "../files/seh.h"
#include "../files/utils.h"
#include "../processors.h"
#include "PEArchitecture.h"
#include "PEFile.h"
#include "PEDirectory.h"
#include "PESegment.h"
#include "PEImport.h"
#include "PEDelayImport.h"
#include "PEExport.h"
#include "PEFixup.h"
#include "PESEHandler.h"
#include "PEResource.h"
#include "PERuntimeFunction.h"
#include "PETLS.h"
#include "PEDebug.h"
#include "PEMapFile.h"
#include "../lang.h"
#include "../core_internal/core.h"
#include "../script.h"
#include "../pdb.h"

// Intel module
#include "../intel/ir/IntelCommandType.h"
#include "../intel/ir/IntelOperand.h"
#include "../intel/ir/IntelCommand.h"
#include "../intel/ir/IntelFunction.h"
#include "../intel/ir/IntelFunctionList.h"
#include "../intel/ir/IntelSDK.h"
#include "../intel/ir/IntelLoader.h"
#include "../intel/vm/IntelVirtualMachineList.h"

/**
 * PEArchitecture
 */



PEArchitecture::PEArchitecture(PEFile* owner, uint64_t offset, uint64_t size)
	: BaseArchitecture(owner, offset, size), function_list_(NULL), virtual_machine_list_(NULL),
	cpu_(0), cpu_address_size_(osDWord), time_stamp_(0), entry_point_(0),
	image_base_(0), header_offset_(0), header_size_(0), segment_alignment_(0),
	file_alignment_(0), resource_section_(NULL), fixup_section_(NULL),
	optimized_section_count_(0), image_type_(itExe), characterictics_(0), check_sum_(0),
	low_resize_header_(0), resize_header_(0), operating_system_version_(0), subsystem_version_(0),
	dll_characteristics_(0)
{
	directory_list_ = new PEDirectoryList(this);
	segment_list_ = new PESegmentList(this);
	section_list_ = new PESectionList(this);
	import_list_ = new PEImportList(this);
	export_list_ = new PEExportList(this);
	fixup_list_ = new PEFixupList();
	relocation_list_ = new PERelocationList();
	resource_list_ = new PEResourceList(this);
	load_config_directory_ = new PELoadConfigDirectory();
	runtime_function_list_ = new PERuntimeFunctionList();
	tls_directory_ = new PETLSDirectory();
	debug_directory_ = new PEDebugDirectory();
	delay_import_list_ = new PEDelayImportList();
}

PEArchitecture::PEArchitecture(PEFile* owner, const PEArchitecture& src)
	: BaseArchitecture(owner, src), function_list_(NULL), virtual_machine_list_(NULL),
	resource_section_(NULL), fixup_section_(NULL)
{
	size_t i, j, k;

	cpu_ = src.cpu_;
	cpu_address_size_ = src.cpu_address_size_;
	entry_point_ = src.entry_point_;
	image_base_ = src.image_base_;
	header_offset_ = src.header_offset_;
	header_size_ = src.header_size_;
	segment_alignment_ = src.segment_alignment_;
	file_alignment_ = src.file_alignment_;
	characterictics_ = src.characterictics_;
	image_type_ = src.image_type_;
	check_sum_ = src.check_sum_;
	low_resize_header_ = src.low_resize_header_;
	resize_header_ = src.resize_header_;
	operating_system_version_ = src.operating_system_version_;
	subsystem_version_ = src.subsystem_version_;
	dll_characteristics_ = src.dll_characteristics_;
	time_stamp_ = src.time_stamp_;

	directory_list_ = src.directory_list_->Clone(this);
	segment_list_ = src.segment_list_->Clone(this);
	section_list_ = src.section_list_->Clone(this);
	import_list_ = src.import_list_->Clone(this);
	export_list_ = src.export_list_->Clone(this);
	fixup_list_ = src.fixup_list_->Clone();
	relocation_list_ = src.relocation_list_->Clone();
	resource_list_ = src.resource_list_->Clone(this);
	load_config_directory_ = src.load_config_directory_->Clone();
	runtime_function_list_ = src.runtime_function_list_->Clone();
	tls_directory_ = src.tls_directory_->Clone();
	debug_directory_ = src.debug_directory_->Clone();
	delay_import_list_ = src.delay_import_list_->Clone();

	if (src.function_list_)
		function_list_ = src.function_list_->Clone(this);
	if (src.virtual_machine_list_)
		virtual_machine_list_ = src.virtual_machine_list_->Clone();
	if (src.resource_section_)
		resource_section_ = segment_list_->item(src.segment_list_->IndexOf(src.resource_section_));
	if (src.fixup_section_)
		fixup_section_ = segment_list_->item(src.segment_list_->IndexOf(src.fixup_section_));

	for (i = 0; i < src.section_list()->count(); i++) {
		PESegment* segment = src.section_list()->item(i)->parent();
		if (segment)
			section_list_->item(i)->set_parent(segment_list_->item(src.segment_list_->IndexOf(segment)));
	}

	for (i = 0; i < src.import_list_->count(); i++) {
		PEImport* import = src.import_list_->item(i);
		for (j = 0; j < import->count(); j++) {
			MapFunction* map_function = import->item(j)->map_function();
			if (map_function)
				import_list_->item(i)->item(j)->set_map_function(map_function_list()->item(src.map_function_list()->IndexOf(map_function)));
		}
	}

	if (function_list_) {
		for (i = 0; i < function_list_->count(); i++) {
			IntelFunction* func = reinterpret_cast<IntelFunction*>(function_list_->item(i));
			for (j = 0; j < func->count(); j++) {
				IntelCommand* command = func->item(j);

				if (command->seh_handler())
					command->set_seh_handler(seh_handler_list()->GetHandlerByAddress(command->address()));

				for (k = 0; k < 3; k++) {
					IntelOperand operand = command->operand(k);
					if (operand.type == otNone)
						break;

					if (operand.fixup)
						command->set_operand_fixup(k, fixup_list_->GetFixupByAddress(operand.fixup->address()));
					if (operand.relocation)
						command->set_operand_relocation(k, relocation_list_->GetRelocationByAddress(operand.relocation->address()));
				}
			}
			for (j = 0; j < func->function_info_list()->count(); j++) {
				FunctionInfo* info = func->function_info_list()->item(j);
				if (info->source())
					info->set_source(runtime_function_list_->GetFunctionByAddress(info->source()->begin()));
			}
		}
	}
}

PEArchitecture::~PEArchitecture()
{
	delete export_list_;
	delete import_list_;
	delete segment_list_;
	delete section_list_;
	delete directory_list_;
	delete fixup_list_;
	delete relocation_list_;
	delete resource_list_;
	delete load_config_directory_;
	delete runtime_function_list_;
	delete function_list_;
	delete virtual_machine_list_;
	delete tls_directory_;
	delete debug_directory_;
	delete delay_import_list_;
}

PEArchitecture* PEArchitecture::Clone(IFile* file) const
{
	PEArchitecture* arch = new PEArchitecture(dynamic_cast<PEFile*>(file), *this);
	return arch;
}

std::string PEArchitecture::name() const
{
	switch (cpu_) {
	case IMAGE_FILE_MACHINE_I386:
		return std::string("i386");
	case IMAGE_FILE_MACHINE_R3000:
	case IMAGE_FILE_MACHINE_R4000:
	case IMAGE_FILE_MACHINE_R10000:
	case IMAGE_FILE_MACHINE_MIPS16:
	case IMAGE_FILE_MACHINE_MIPSFPU:
	case IMAGE_FILE_MACHINE_MIPSFPU16:
		return std::string("mips");
	case IMAGE_FILE_MACHINE_WCEMIPSV2:
		return std::string("mips_wce_v2");
	case IMAGE_FILE_MACHINE_ALPHA:
		return std::string("alpha_axp");
	case IMAGE_FILE_MACHINE_SH3:
	case IMAGE_FILE_MACHINE_SH3DSP:
		return std::string("sh3");
	case IMAGE_FILE_MACHINE_SH3E:
		return std::string("sh3e");
	case IMAGE_FILE_MACHINE_SH4:
		return std::string("sh4");
	case IMAGE_FILE_MACHINE_SH5:
		return std::string("sh5");
	case IMAGE_FILE_MACHINE_ARM:
		return std::string("arm");
	case IMAGE_FILE_MACHINE_THUMB:
		return std::string("thumb");
	case IMAGE_FILE_MACHINE_AM33:
		return std::string("am33");
	case IMAGE_FILE_MACHINE_POWERPC:
	case IMAGE_FILE_MACHINE_POWERPCFP:
		return std::string("ppc");
	case IMAGE_FILE_MACHINE_IA64:
		return std::string("ia64");
	case IMAGE_FILE_MACHINE_ALPHA64:
		return std::string("alpha64");
	case IMAGE_FILE_MACHINE_TRICORE:
		return std::string("infineon");
	case IMAGE_FILE_MACHINE_CEF:
		return std::string("cef");
	case IMAGE_FILE_MACHINE_EBC:
		return std::string("ebc");
	case IMAGE_FILE_MACHINE_AMD64:
		return std::string("amd64");
	case IMAGE_FILE_MACHINE_M32R:
		return std::string("m32r");
	case IMAGE_FILE_MACHINE_CEE:
		return std::string("cee");
	default:
		return string_format("unknown 0x%X", cpu_);
	}
}

OpenStatus PEArchitecture::ReadFromFile(uint32_t mode)
{
	Seek(0);

	IMAGE_DOS_HEADER dos_header;
	if (size() < sizeof(dos_header))
		return osUnknownFormat;

	Read(&dos_header, sizeof(dos_header));
	if (dos_header.e_magic != IMAGE_DOS_SIGNATURE)
		return osUnknownFormat;

	Seek(dos_header.e_lfanew);
	uint32_t signature = ReadDWord();
	if (signature != IMAGE_NT_SIGNATURE)
		return osUnknownFormat;

	IMAGE_FILE_HEADER image_header;
	Read(&image_header, sizeof(image_header));
	cpu_ = image_header.Machine;
	if (cpu_ != IMAGE_FILE_MACHINE_I386 && cpu_ != IMAGE_FILE_MACHINE_AMD64)
		return osUnsupportedCPU;

	uint16_t magic = ReadWord();
	assert(sizeof(magic) == sizeof(IMAGE_OPTIONAL_HEADER32().Magic));
	assert(sizeof(magic) == sizeof(IMAGE_OPTIONAL_HEADER64().Magic));

	uint16_t subsystem;
	uint32_t dir_count;
	switch (magic) {
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
	{
		IMAGE_OPTIONAL_HEADER32 pe_header = IMAGE_OPTIONAL_HEADER32();
		Read(&pe_header.MajorLinkerVersion, sizeof(pe_header) - sizeof(magic) - sizeof(pe_header.DataDirectory));
		dir_count = pe_header.NumberOfRvaAndSizes;
		entry_point_ = pe_header.AddressOfEntryPoint;
		image_base_ = pe_header.ImageBase;
		segment_alignment_ = pe_header.SectionAlignment;
		file_alignment_ = pe_header.FileAlignment;
		cpu_address_size_ = osDWord;
		subsystem = pe_header.Subsystem;
		check_sum_ = pe_header.CheckSum;
		operating_system_version_ = (pe_header.MajorOperatingSystemVersion << 16) | pe_header.MinorOperatingSystemVersion;
		subsystem_version_ = (pe_header.MajorSubsystemVersion << 16) | pe_header.MinorSubsystemVersion;
		dll_characteristics_ = pe_header.DllCharacteristics;
	}
	break;

	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
	{
		IMAGE_OPTIONAL_HEADER64 pe_header = IMAGE_OPTIONAL_HEADER64();
		Read(&pe_header.MajorLinkerVersion, sizeof(pe_header) - sizeof(magic) - sizeof(pe_header.DataDirectory));
		dir_count = pe_header.NumberOfRvaAndSizes;
		entry_point_ = pe_header.AddressOfEntryPoint;
		image_base_ = pe_header.ImageBase;
		segment_alignment_ = pe_header.SectionAlignment;
		file_alignment_ = pe_header.FileAlignment;
		cpu_address_size_ = osQWord;
		subsystem = pe_header.Subsystem;
		check_sum_ = pe_header.CheckSum;
		operating_system_version_ = (pe_header.MajorOperatingSystemVersion << 16) | pe_header.MinorOperatingSystemVersion;
		subsystem_version_ = (pe_header.MajorSubsystemVersion << 16) | pe_header.MinorSubsystemVersion;
		dll_characteristics_ = pe_header.DllCharacteristics;
	}
	break;

	default:
		return osInvalidFormat;
	}

	time_stamp_ = image_header.TimeDateStamp;
	characterictics_ = image_header.Characteristics;
	switch (subsystem) {
	case IMAGE_SUBSYSTEM_NATIVE:
		image_type_ = itDriver;
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_GUI:
	case IMAGE_SUBSYSTEM_WINDOWS_CUI:
		image_type_ = (characterictics_ & IMAGE_FILE_DLL) ? itLibrary : itExe;
		break;
	default:
		return osUnsupportedSubsystem;
	}

	if (entry_point_)
		entry_point_ += image_base_;

	header_offset_ = dos_header.e_lfanew;
	header_size_ = image_header.SizeOfOptionalHeader;

	directory_list_->ReadFromFile(*this, dir_count);

	Seek(header_offset_ + offsetof(IMAGE_NT_HEADERS32, OptionalHeader) + header_size_);
	segment_list_->ReadFromFile(*this, image_header.NumberOfSections);

	// read long section names from the COFF string table 
	if (image_header.PointerToSymbolTable) {
		Seek(image_header.PointerToSymbolTable + image_header.NumberOfSymbols * sizeof(IMAGE_SYMBOL));

		COFFStringTable string_table;
		string_table.ReadFromFile(*this);
		for (size_t i = 0; i < segment_list_->count(); i++) {
			PESegment* segment = segment_list_->item(i);
			const std::string& segment_name = segment->name();
			if (segment_name.length() && segment_name[0] == '/') {
				char* endptr = NULL;
				uint32_t name_offset = strtoul(segment_name.c_str() + 1, &endptr, 10);
				if (endptr && *endptr == 0)
					segment->set_name(string_table.GetString(name_offset));
			}
		}
	}

	resource_section_ = NULL;
	fixup_section_ = NULL;
	for (size_t i = 0; i < directory_list_->count(); i++) {
		PEDirectory* dir = directory_list_->item(i);
		switch (dir->type()) {
		case IMAGE_DIRECTORY_ENTRY_EXPORT:
			export_list_->ReadFromFile(*this, *dir);
			break;
		case IMAGE_DIRECTORY_ENTRY_IMPORT:
			import_list_->ReadFromFile(*this, *dir);
			break;
		case IMAGE_DIRECTORY_ENTRY_RESOURCE:
			resource_list_->ReadFromFile(*this, *dir);
			if (dir->address()) {
				resource_section_ = segment_list_->GetSectionByAddress(dir->address());
				if (!resource_section_)
					return osInvalidFormat;

				if (resource_section_->address() != dir->address() || resource_section_ == segment_list_->header_segment())
					resource_section_ = NULL;
			}
			break;
		case IMAGE_DIRECTORY_ENTRY_BASERELOC:
			fixup_list_->ReadFromFile(*this, *dir);
			if (dir->address()) {
				fixup_section_ = segment_list_->GetSectionByAddress(dir->address());
				if (!fixup_section_)
					return osInvalidFormat;

				if (fixup_section_->address() != dir->address() || fixup_section_ == segment_list_->header_segment())
					fixup_section_ = NULL;
			}
			break;
		case IMAGE_DIRECTORY_ENTRY_DEBUG:
			debug_directory_->ReadFromFile(*this, *dir);
			break;
		case IMAGE_DIRECTORY_ENTRY_TLS:
			tls_directory_->ReadFromFile(*this, *dir);
			break;
		case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
			load_config_directory_->ReadFromFile(*this, *dir);
			break;
		case IMAGE_DIRECTORY_ENTRY_EXCEPTION:
			runtime_function_list_->ReadFromFile(*this, *dir);
			break;
		case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
			delay_import_list_->ReadFromFile(*this, *dir);
			break;
		case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
			if (dir->address()) {
				// This is a .NET assembly - not supported
				return osUnsupportedCPU;
			}
			break;
		}
	}
	if (fixup_section_)
		fixup_section_->set_need_parse(false);
	if (resource_section_)
		resource_section_->set_need_parse(false);

	if ((mode & foHeaderOnly) == 0) {
		if (!owner()->file_name().empty()) {
			std::vector<uint64_t> segments;
			for (size_t i = 0; i < segment_list()->count(); i++) {
				segments.push_back(segment_list()->item(i)->address());
			}
			if (std::find(segments.begin(), segments.end(), 0) == segments.end())
				segments.insert(segments.begin(), 0);

			for (size_t i = 0; i < 3; i++) {
				if (i == 0) {
					MapFile map_file;
					if (map_file.Parse(map_file_name().c_str(), segments)) {
						ReadMapFile(map_file);
						break;
					}
				}
				else if (i == 1) {
					PDBFile pdb_file;
					if (pdb_file.Parse(pdb_file_name().c_str(), segments)) {
						std::vector<uint8_t> guid;
						if (pdb_file.guid().size()) {
							for (size_t j = 0; j < debug_directory_->count(); j++) {
								PEDebugData* data = debug_directory_->item(j);
								if (data->type() == IMAGE_DEBUG_TYPE_CODEVIEW) {
									if (AddressSeek(data->address())) {
										struct PdbInfo
										{
											uint32_t     Signature;
											GUID         Guid;
											uint32_t     Age;
											// char      PdbFileName[1];
										} pi;
										Read(&pi, sizeof(pi));
										if (pi.Signature == 0x53445352) // RSDS
											guid.insert(guid.begin(), reinterpret_cast<const uint8_t*>(&pi.Guid), reinterpret_cast<const uint8_t*>(&pi.Guid) + sizeof(pi.Guid));
									}
									break;
								}
							}
						}
						if (guid == pdb_file.guid()) {
							pdb_file.set_time_stamp(time_stamp_);
							ReadMapFile(pdb_file);
						}
						else
							Notify(mtWarning, NULL, string_format(language[lsMAPFileHasIncorrectTimeStamp].c_str(), os::ExtractFileName(pdb_file.file_name().c_str()).c_str()));
						break;
					}
				}
				else if (image_header.PointerToSymbolTable) {
					COFFFile coff_file;
					if (coff_file.Parse(owner()->file_name().c_str(), segments)) {
						ReadMapFile(coff_file);
						break;
					}
				}
			}
		}

		map_function_list()->ReadFromFile(*this);
	}

	switch (cpu_) {
	case IMAGE_FILE_MACHINE_I386:
	case IMAGE_FILE_MACHINE_AMD64:
		function_list_ = new PEIntelFunctionList(this);
		virtual_machine_list_ = new IntelVirtualMachineList();
		if ((mode & foHeaderOnly) == 0) {
			IntelFileHelper helper;
			helper.Parse(*this);

			relocation_list_->ReadFromFile(*this);
		}
		break;
	default:
		return osUnsupportedCPU;
	}

	return osSuccess;
}

std::string PEArchitecture::pdb_file_name() const
{
	if (!owner())
		return std::string();
	return os::ChangeFileExt(owner()->file_name().c_str(), ".pdb");
}

bool PEArchitecture::ReadMapFile(IMapFile& map_file)
{
	if (!BaseArchitecture::ReadMapFile(map_file))
		return false;

	MapSection* sections = map_file.GetSectionByType(msSections);
	if (sections) {
		for (size_t i = 0; i < sections->count(); i++) {
			MapObject* section = sections->item(i);

			uint64_t address = section->address();
			PESegment* segment;
			if (section->segment() != (size_t)-1) {
				if (section->segment() == 0 || section->segment() > segment_list_->count())
					continue;

				segment = segment_list_->item(section->segment() - 1);
			}
			else {
				segment = segment_list_->GetSectionByAddress(address);
				if (!segment)
					continue;
			}

			section_list_->Add(segment, address, section->size(), section->name());
		}
	}
	return true;
}

void PEArchitecture::WriteCheckSum()
{
	if (check_sum_ && reinterpret_cast<PEFile*>(owner())->GetCheckSum(&check_sum_)) {
		Seek(header_offset_ + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) + ((cpu_address_size() == osDWord) ? offsetof(IMAGE_OPTIONAL_HEADER32, CheckSum) : offsetof(IMAGE_OPTIONAL_HEADER64, CheckSum)));
		WriteDWord(check_sum_);
	}
}

bool PEArchitecture::WriteToFile()
{
	IMAGE_FILE_HEADER image_header;
	IMAGE_OPTIONAL_HEADER32 pe_header32;
	IMAGE_OPTIONAL_HEADER64 pe_header64;
	uint32_t image_size, header_size;
	PESegment* last_section;

	// read header
	Seek(header_offset_ + sizeof(uint32_t));
	Read(&image_header, sizeof(image_header));
	image_header.PointerToSymbolTable = 0;
	image_header.NumberOfSymbols = 0;
	image_header.NumberOfSections = static_cast<uint16_t>(segment_list_->count());
	if (cpu_address_size_ == osDWord) {
		Read(&pe_header32, sizeof(pe_header32) - sizeof(pe_header32.DataDirectory));
	}
	else {
		Read(&pe_header64, sizeof(pe_header64) - sizeof(pe_header64.DataDirectory));
	}

	// write header
	directory_list_->WriteToFile(*this);
	segment_list_->WriteToFile(*this);
	header_size = AlignValue(static_cast<uint32_t>(Tell()), file_alignment_);

	last_section = segment_list_->last();
	image_size = (last_section) ? AlignValue(static_cast<uint32_t>(last_section->address() - image_base() + last_section->size()), segment_alignment_) : 0;

	Seek(header_offset_ + sizeof(uint32_t));
	image_header.Characteristics = characterictics_;
	Write(&image_header, sizeof(image_header));
	if (cpu_address_size_ == osDWord) {
		pe_header32.AddressOfEntryPoint = (entry_point_) ? static_cast<uint32_t>(entry_point_ - image_base_) : 0;
		pe_header32.SizeOfImage = image_size;
		if (header_size > pe_header32.SizeOfHeaders)
			pe_header32.SizeOfHeaders = header_size;
		pe_header32.MajorOperatingSystemVersion = operating_system_version_ >> 16;
		pe_header32.MinorOperatingSystemVersion = static_cast<uint16_t>(operating_system_version_);
		pe_header32.MajorSubsystemVersion = subsystem_version_ >> 16;
		pe_header32.MinorSubsystemVersion = static_cast<uint16_t>(subsystem_version_);
		pe_header32.DllCharacteristics = dll_characteristics_;
		Write(&pe_header32, sizeof(pe_header32) - sizeof(pe_header32.DataDirectory));
	}
	else {
		pe_header64.AddressOfEntryPoint = (entry_point_) ? static_cast<uint32_t>(entry_point_ - image_base_) : 0;
		pe_header64.SizeOfImage = image_size;
		if (header_size > pe_header64.SizeOfHeaders)
			pe_header64.SizeOfHeaders = header_size;
		pe_header64.MajorOperatingSystemVersion = operating_system_version_ >> 16;
		pe_header64.MinorOperatingSystemVersion = static_cast<uint16_t>(operating_system_version_);
		pe_header64.MajorSubsystemVersion = subsystem_version_ >> 16;
		pe_header64.MinorSubsystemVersion = static_cast<uint16_t>(subsystem_version_);
		pe_header64.DllCharacteristics = dll_characteristics_;
		Write(&pe_header64, sizeof(pe_header64) - sizeof(pe_header64.DataDirectory));
	}
	return true;
}

bool PEArchitecture::Prepare(CompileContext& ctx)
{
	if ((ctx.options.flags & cpPack) && segment_alignment_ < 0x1000) {
		ctx.options.flags &= ~cpPack;
		Notify(mtWarning, NULL, language[lsFileCanNotBePacked].c_str());
	}

	if (image_type() == itExe && (dll_characteristics_ & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0)
		ctx.options.flags |= cpStripFixups;

	if (image_type() != itDriver) {
		if (ctx.options.flags & cpMemoryProtection)
			ctx.options.flags |= cpInternalMemoryProtection;
		if (ctx.options.flags & cpResourceProtection) {
			std::vector<IResource*> resources = resource_list()->GetResourceList();
			bool need_resource_protection = false;
			for (size_t i = 0; i < resources.size(); i++) {
				IResource* resource = resources[i];
				if (!resource->excluded_from_packing() && !resource->need_store()) {
					need_resource_protection = true;
					break;
				}
			}
			if (!need_resource_protection)
				ctx.options.flags &= ~cpResourceProtection;
		}
	}
	else {
		if (ctx.options.flags & cpResourceProtection)
			ctx.options.flags &= ~cpResourceProtection;
		if (ctx.options.file_manager)
			ctx.options.file_manager = NULL;
	}

	if (!BaseArchitecture::Prepare(ctx))
		return false;

	size_t i;
	PESegment* section;
	std::vector<PESegment*> optimized_section_list;

	// optimize sections
	if (resource_section_)
		optimized_section_list.push_back(resource_section_);
	if (fixup_section_)
		optimized_section_list.push_back(fixup_section_);
	if (ctx.options.flags & cpStripDebugInfo) {
		for (i = 0; i < segment_list_->count(); i++) {
			section = segment_list_->item(i);
			if ((section->flags() & (IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_LNK_INFO)) == IMAGE_SCN_MEM_DISCARDABLE && section->name().substr(0, 6) == ".debug")
				optimized_section_list.push_back(section);
		}
	}

	optimized_section_count_ = segment_list_->count();
	for (i = segment_list_->count(); i > 0; i--) {
		section = segment_list_->item(i - 1);

		std::vector<PESegment*>::iterator it = std::find(optimized_section_list.begin(), optimized_section_list.end(), section);
		if (it != optimized_section_list.end()) {
			optimized_section_list.erase(it);
			optimized_section_count_--;
		}
		else {
			break;
		}
	}

	// calc new header size
	uint32_t new_section_count = static_cast<uint32_t>(optimized_section_count_ + 1);
	if ((ctx.options.flags & cpStripFixups) == 0)
		new_section_count++;
	if (resource_list_->count())
		new_section_count++;
	if (ctx.runtime)
		new_section_count += 2;

	// calc header resizes
	uint32_t new_header_size = header_offset_ + offsetof(IMAGE_NT_HEADERS32, OptionalHeader) + header_size_ + new_section_count * sizeof(IMAGE_SECTION_HEADER);
	low_resize_header_ = 0;
	if ((ctx.options.flags & cpStripDebugInfo) && header_offset_ > MIN_HEADER_OFFSET) {
		low_resize_header_ = header_offset_ - MIN_HEADER_OFFSET;
		new_header_size -= low_resize_header_;
	}
	for (i = 0; i < directory_list_->count(); i++) {
		PEDirectory* dir = directory_list_->item(i);
		if (!dir->visible() || dir->type() == IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT)
			continue;

		uint32_t rva = static_cast<uint32_t>(dir->address() - image_base_);
		if (low_resize_header_ == 0 && new_header_size > rva && header_offset_ > MIN_HEADER_OFFSET) {
			low_resize_header_ = header_offset_ - MIN_HEADER_OFFSET;
			new_header_size -= low_resize_header_;
		}
		if (new_header_size > rva) {
			Notify(mtError, NULL, language[lsCreateSegmentError]);
			return false;
		}
	}

	uint32_t aligned_header_size = AlignValue(new_header_size, file_alignment_);
	resize_header_ = 0;
	for (i = 0; i < segment_list_->count(); i++) {
		section = segment_list_->item(i);
		if (section->physical_size() == 0 || section->physical_offset() == 0 || aligned_header_size <= section->physical_offset())
			continue;

		uint32_t rva = static_cast<uint32_t>(section->address() - image_base_);
		if (low_resize_header_ == 0 && aligned_header_size > rva && header_offset_ > MIN_HEADER_OFFSET) {
			low_resize_header_ = header_offset_ - MIN_HEADER_OFFSET;
			new_header_size -= low_resize_header_;
			aligned_header_size = AlignValue(new_header_size, file_alignment_);
		}
		if (aligned_header_size > rva) {
			Notify(mtError, NULL, language[lsCreateSegmentError]);
			return false;
		}
		if (aligned_header_size > section->physical_offset())
			resize_header_ = std::max(resize_header_, aligned_header_size - section->physical_offset());
	}

	for (i = 0; i < optimized_section_list.size(); i++) {
		section = optimized_section_list[i];
		ctx.manager->Add(section->address(), std::min(static_cast<uint32_t>(section->size()), section->physical_size()), section->memory_type());
	}

	if (optimized_section_count_ > 0) {
		section = segment_list_->item(optimized_section_count_ - 1);
		if (ctx.runtime) {
			PEArchitecture* runtime = reinterpret_cast<PEArchitecture*>(ctx.runtime);
			if (runtime->segment_list()->count()) {
				runtime->Rebase(image_base(), AlignValue(section->address() + section->size(), segment_alignment()) - runtime->segment_list()->item(0)->address());

				MemoryManager runtime_manager(runtime);
				if (runtime->segment_list()->last() == runtime->fixup_section_) {
					delete runtime->fixup_section_;
					runtime->fixup_section_ = NULL;
				}
				if (runtime->load_config_directory()->seh_table_address()) {
					section = runtime->segment_list()->last();
					if (section->address() == runtime->load_config_directory()->seh_table_address())
						delete section;
				}
				if (runtime->runtime_function_list()->address()) {
					section = runtime->segment_list()->last();
					if (section->address() == runtime->runtime_function_list()->address())
						delete section;
					else
						runtime->runtime_function_list()->FreeByManager(runtime_manager);
				}
				runtime->import_list()->FreeByManager(runtime_manager, (ctx.options.flags & cpImportProtection) != 0);
				runtime_manager.Pack();
				for (i = 0; i < runtime_manager.count(); i++) {
					MemoryRegion* region = runtime_manager.item(i);
					ctx.manager->Add(region->address(), region->size(), region->type());
				}
				section = runtime->segment_list()->last();
			}
			else {
				runtime->Rebase(image_base(), image_base() - runtime->image_base());
			}
		}

		// add new section
		assert(section);
		ctx.manager->Add(AlignValue(section->address() + section->size(), segment_alignment()), UINT32_MAX, mtReadable | mtExecutable | mtWritable | mtNotPaged | (runtime_function_list()->count() ? mtSolid : mtNone));
	}

	if (ctx.runtime)
		import_list_->FreeByManager(*ctx.manager, (ctx.options.flags & cpImportProtection) != 0);
	if (ctx.options.flags & cpPack) {
		export_list_->FreeByManager(*ctx.manager);
		tls_directory_->FreeByManager(*ctx.manager);
		PEDirectory* dir = directory_list_->GetCommandByType(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
		if (dir)
			dir->FreeByManager(*ctx.manager);
		dir = directory_list_->GetCommandByType(IMAGE_DIRECTORY_ENTRY_ARCHITECTURE);
		if (dir)
			dir->FreeByManager(*ctx.manager);
	}
	if (ctx.options.flags & (cpPack | cpStripDebugInfo))
		debug_directory_->FreeByManager(*ctx.manager);
	load_config_directory_->FreeByManager(*ctx.manager);
	runtime_function_list_->FreeByManager(*ctx.manager);

	return true;
}

bool PEArchitecture::Compile(CompileOptions& options, IArchitecture* runtime)
{
	return visible() ? BaseArchitecture::Compile(options, runtime) : true;
}

void PEArchitecture::Save(CompileContext& ctx)
{
	PEDirectory* dir;
	PESegment* last_section, * section, * vmp_section;
	uint64_t pos, address, resource_section_info, resource_packer_info, file_crc_address, loader_crc_address, name_table,
		loader_crc_size_address, loader_crc_hash_address, file_crc_size_address;
	uint32_t size, file_crc_size, loader_crc_size, name_table_size;
	size_t i, j, c;
	MemoryRegion* region;
	uint32_t resource_section_flags, fixup_section_flags;
	std::string resource_section_name, fixup_section_name;
	int vmp_index;
	MemoryManager* manager = memory_manager();

	// erase sections area
	{
		IMAGE_SECTION_HEADER section_header = IMAGE_SECTION_HEADER();
		Seek(header_offset_ + offsetof(IMAGE_NT_HEADERS32, OptionalHeader) + header_size_);
		for (i = 0; i < segment_list_->count(); i++) {
			Write(&section_header, sizeof(section_header));
		}
	}

	// resize header
	if (low_resize_header_ || resize_header_) {
		uint32_t new_header_offset = header_offset_ - low_resize_header_;
		size_t total_header_size = offsetof(IMAGE_NT_HEADERS32, OptionalHeader) + header_size_ + segment_list_->count() * sizeof(IMAGE_SECTION_HEADER);
		const PEArchitecture* src = dynamic_cast<const PEArchitecture*>(source());
		if (low_resize_header_) {
			Seek(offsetof(IMAGE_DOS_HEADER, e_lfanew));
			WriteDWord(new_header_offset);
			src->Seek(header_offset_);
			Seek(new_header_offset);
			CopyFrom(*src, total_header_size);
			for (i = 0; i < low_resize_header_; i++) {
				WriteByte(0);
			}
		}
		if (resize_header_) {
			src->Seek(header_offset_ + total_header_size);
			Seek(header_offset_ + total_header_size);
			for (i = 0; i < resize_header_; i++) {
				WriteByte(0);
			}
			CopyFrom(*src, this->size() - src->Tell());
			section = segment_list_->header_segment();
			if (section)
				section->set_physical_size(section->physical_size() + resize_header_);
			for (i = 0; i < segment_list_->count(); i++) {
				section = segment_list_->item(i);
				if (section->physical_offset())
					section->set_physical_offset(section->physical_offset() + resize_header_);
			}

			if ((ctx.options.flags & (cpPack | cpStripDebugInfo)) == 0) {
				if (debug_directory_->address()) {
					for (i = 0; i < debug_directory_->count(); i++) {
						PEDebugData* data = debug_directory_->item(i);
						data->set_offset(data->offset() + resize_header_);
					}
					AddressSeek(debug_directory_->address());
					debug_directory_->WriteToFile(*this);
				}
			}
		}
		header_offset_ = new_header_offset;
	}

	// add antidebug export
	if ((ctx.options.flags & cpCheckDebugger) && image_type() != itDriver && !import_list()->GetImportByName("dbghelp.dll"))
		export_list_->AddAntidebug();

	// compile modified objects
	if ((ctx.options.flags & cpPack) == 0) {
		if (source() && !export_list()->is_equal(*source()->export_list())) {
			const PEArchitecture* src = dynamic_cast<const PEArchitecture*>(source());
			if (src == NULL)
				throw std::runtime_error("Runtime error at Save");

			src->export_list()->FreeByManager(*manager);

			PEIntelExport* pe_export = reinterpret_cast<PEIntelFunctionList*>(function_list())->AddExport(cpu_address_size());
			pe_export->Init(ctx);
			pe_export->Compile(ctx);

			PEDirectory* dir = directory_list_->GetCommandByType(IMAGE_DIRECTORY_ENTRY_EXPORT);
			if (dir) {
				if (pe_export->entry()) {
					dir->set_address(pe_export->entry()->address());
					dir->set_size(pe_export->size());
				}
				else {
					dir->clear();
				}
			}
		}
	}

	// calc progress maximum
	c = 0;
	if (ctx.runtime)
		c += ctx.runtime->segment_list()->count();
	for (i = 0; i < function_list_->count(); i++) {
		IFunction* func = function_list_->item(i);
		for (j = 0; j < func->block_list()->count(); j++) {
			CommandBlock* block = func->block_list()->item(j);
			c += block->end_index() - block->start_index() + 1;
		}
	}
	StartProgress(string_format("%s...", language[lsSaving].c_str()), c);

	if (resource_list_->count()) {
		if (ctx.options.flags & cpResourceProtection) {
			for (i = resource_list_->count(); i > 0; i--) {
				PEResource* resource = resource_list_->item(i - 1);
				if (!resource->need_store())
					delete resource;
			}
		}
		resource_list_->Compile(*this, (resource_section_ && resource_section_->excluded_from_packing()) ? false : (ctx.options.flags & cpPack) != 0);
	}

	resource_section_flags = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;
	resource_section_name = ".rsrc";

	fixup_section_flags = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_CNT_INITIALIZED_DATA;
	fixup_section_name = ".reloc";

	// need erase optimized sections
	for (i = segment_list_->count(); i > optimized_section_count_; i--) {
		section = segment_list_->item(i - 1);
		if (resource_section_ == section) {
			resource_section_flags = section->flags();
			resource_section_name = section->name();
			resource_section_ = NULL;
		}
		else if (fixup_section_ == section) {
			fixup_section_flags = section->flags();
			fixup_section_name = section->name();
			fixup_section_ = NULL;
		}
		delete section;
	}

	// need truncate optimized sections and overlay
	for (i = segment_list_->count(); i > 0; i--) {
		section = segment_list_->item(i - 1);
		if (section->physical_size() > 0) {
			Resize(section->physical_offset() + section->physical_size());
			break;
		}
	}

	last_section = segment_list_->last();
	address = AlignValue(last_section->address() + last_section->size(), segment_alignment_);
	pos = Resize(AlignValue(this->size(), file_alignment_));
	vmp_section = segment_list_->Add(address, UINT32_MAX, static_cast<uint32_t>(pos), UINT32_MAX, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE, "");

	// merge runtime objects
	PEArchitecture* runtime = reinterpret_cast<PEArchitecture*>(ctx.runtime);
	if (runtime && runtime->segment_list()->count()) {
		// merge sections
		SignatureList patch_signatures;
		if (image_type() != itDriver) {
			if (cpu_address_size() == osDWord)
				patch_signatures.Add("817DD800000001741B83C8FF8B4DF0", 0);
		}
		for (i = 0; i < runtime->segment_list()->count(); i++) {
			section = runtime->segment_list()->item(i);
			if (section->physical_offset() && section->physical_size()) {
				runtime->Seek(section->physical_offset());
				size = static_cast<uint32_t>(section->physical_size());
				uint8_t* buffer = new uint8_t[size];
				runtime->Read(buffer, size);
				if ((section->memory_type() & mtExecutable) && patch_signatures.count()) {
					patch_signatures.InitSearch();
					for (c = 0; c < size; c++) {
						uint8_t b = buffer[c];
						for (j = 0; j < patch_signatures.count(); j++) {
							Signature* sign = patch_signatures.item(j);
							if (sign->SearchByte(b)) {
								size_t p = c + 1 - sign->size();
								buffer[p + 7] = 0xeb;
							}
						}
					}
				}

				Write(buffer, size);
				delete[] buffer;
			}
			size = static_cast<uint32_t>(AlignValue(section->size(), runtime->segment_alignment()) - section->physical_size());
			for (j = 0; j < size; j++) {
				WriteByte(0);
			}
			uint32_t memory_type = section->memory_type();
			if (image_type_ != itDriver)
				memory_type &= ~mtWritable;
			vmp_section->include_write_type(memory_type);

			StepProgress();
		}
		// merge fixups
		for (i = 0; i < runtime->fixup_list()->count(); i++) {
			PEFixup* fixup = runtime->fixup_list()->item(i);
			fixup_list_->AddObject(fixup->Clone(fixup_list_));
		}
		// merge seh handlers
		for (i = 0; i < runtime->seh_handler_list()->count(); i++) {
			PESEHandler* handler = runtime->seh_handler_list()->item(i);
			load_config_directory_->seh_handler_list()->Add(handler->address());
		}
		// merge CFG addresses
		PECFGAddressTable* cfg_address_list = runtime->load_config_directory_->cfg_address_list();
		for (i = 0; i < cfg_address_list->count(); i++) {
			load_config_directory_->cfg_address_list()->Add(cfg_address_list->item(i)->address());
		}
		// merge runtime functions
		for (i = 0; i < runtime->runtime_function_list()->count(); i++) {
			PERuntimeFunction* runtime_function = runtime->runtime_function_list()->item(i);
			runtime_function_list_->AddObject(runtime_function->Clone(runtime_function_list_));
		}
	}

	// write functions
	for (i = 0; i < function_list_->count(); i++) {
		function_list_->item(i)->WriteToFile(*this);
	}

	// erase not used memory regions
	if (manager->count() > 1) {
		// need skip last big region
		for (i = 0; i < manager->count() - 1; i++) {
			region = manager->item(i);
			if (!AddressSeek(region->address()))
				continue;

			for (j = 0; j < region->size(); j++) {
				WriteByte((ctx.options.flags & cpDebugMode) ? 0xcc : rand());
			}
		}
	}

	vmp_index = 0;
	// need update fixup and resource sections if they are not optimized
	if (fixup_section_) {
		fixup_section_->set_name(string_format("%s%d", ctx.options.section_name.c_str(), vmp_index++));
		if (fixup_section_->write_type()) {
			fixup_section_->set_flags(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_CNT_INITIALIZED_DATA);
			fixup_section_->update_type(fixup_section_->write_type());
		}
		fixup_section_ = NULL;
	}
	if (resource_section_) {
		resource_section_->set_name(string_format("%s%d", ctx.options.section_name.c_str(), vmp_index++));
		if (resource_section_->write_type()) {
			resource_section_->set_flags(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_CNT_INITIALIZED_DATA);
			resource_section_->update_type(resource_section_->write_type());
		}
		resource_section_ = NULL;
	}

	if (!runtime) {
		last_section = segment_list_->last();
		if (import_list_->has_sdk())
			import_list_->WriteToFile(*this, true);
		if (load_config_directory_->WriteToFile(*this))
			last_section->include_write_type(mtReadable | mtNotDiscardable);

		dir = directory_list_->GetCommandByType(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
		if (dir) {
			pos = Resize(AlignValue(this->size(), 0x10));
			address = last_section->address() + pos - last_section->physical_offset();

			size = static_cast<uint32_t>(runtime_function_list_->WriteToFile(*this));
			if (size) {
				last_section->include_write_type(mtReadable | mtNotDiscardable | mtNotPaged);
				dir->set_address(address);
				dir->set_size(size);
			}
			else {
				dir->clear();
			}
		}
	}

	if (vmp_section->write_type() == mtNone) {
		delete vmp_section;
	}
	else {
		vmp_section->set_name(string_format("%s%d", ctx.options.section_name.c_str(), vmp_index++));

		size = static_cast<uint32_t>(this->size() - vmp_section->physical_offset());
		vmp_section->set_size(size);
		vmp_section->set_physical_size(AlignValue(size, file_alignment_));
		vmp_section->update_type(vmp_section->write_type());

		Resize(vmp_section->physical_offset() + vmp_section->physical_size());
	}

	if ((ctx.options.flags & cpPack) && ctx.options.script)
		ctx.options.script->DoBeforePackFile();

	// write memory CRC table
	if (function_list_->crc_table()) {
		IntelCRCTable* intel_crc = reinterpret_cast<IntelCRCTable*>(function_list_->crc_table());
		CRCTable crc_table(function_list_->crc_cryptor(), intel_crc->table_size());

		// add non writable sections
		for (i = 0; i < segment_list_->count(); i++) {
			section = segment_list_->item(i);
			if ((section->memory_type() & (mtReadable | mtWritable)) != mtReadable || section->excluded_from_memory_protection())
				continue;

			size = std::min(static_cast<uint32_t>(section->size()), section->physical_size());
			if (size) {
				crc_table.Add(section->address(), size);
				if (ctx.options.sdk_flags & cpMemoryProtection)
					section->update_type(mtNotPaged);
			}
		}

		// skip writable runtime's sections
		if (runtime) {
			for (i = 0; i < runtime->segment_list()->count(); i++) {
				section = runtime->segment_list()->item(i);
				if (section->memory_type() & mtWritable)
					crc_table.Remove(section->address(), static_cast<uint32_t>(section->size()));
			}
		}

		// skip IAT
		IntelImport* intel_import = reinterpret_cast<IntelFunctionList*>(function_list_)->import();
		size = OperandSizeToValue(cpu_address_size());
		size_t k = (runtime && runtime->segment_list()->count() > 0) ? 2 : 1;
		for (size_t n = 0; n < k; n++) {
			PEImportList* import_list = (n == 0) ? import_list_ : runtime->import_list();
			for (i = 0; i < import_list->count(); i++) {
				PEImport* import = import_list->item(i);
				if (ctx.options.flags & cpImportProtection) {
					for (j = 0; j < import->count(); j++) {
						PEImportFunction* import_function = import->item(j);
						address = import_function->address();
						IntelCommand* iat_command = intel_import->GetIATCommand(import_function);
						if (iat_command)
							address = iat_command->address();
						crc_table.Remove(address, size);
					}
				}
				else {
					if (import->count() > 0)
						crc_table.Remove(import->item(0)->address(), size * import->count());
				}
			}
		}

		// skip fixups
		if ((ctx.options.flags & cpStripFixups) == 0) {
			for (i = 0; i < fixup_list_->count(); i++) {
				PEFixup* fixup = fixup_list_->item(i);
				if (!fixup->is_deleted())
					crc_table.Remove(fixup->address(), OperandSizeToValue(fixup->size()));
			}
		}

		// skip relocations
		for (i = 0; i < relocation_list_->count(); i++) {
			PERelocation* relocation = relocation_list_->item(i);
			crc_table.Remove(relocation->address(), OperandSizeToValue(relocation->size()));
		}

		// skip loader_data
		IntelFunction* loader_data = reinterpret_cast<IntelFunctionList*>(function_list_)->loader_data();
		if (loader_data)
			crc_table.Remove(loader_data->entry()->address(), loader_data->entry()->dump_size());

		// skip memory CRC table
		crc_table.Remove(intel_crc->table_entry()->address(), intel_crc->table_size());
		crc_table.Remove(intel_crc->size_entry()->address(), sizeof(uint32_t));
		crc_table.Remove(intel_crc->hash_entry()->address(), sizeof(uint32_t));

		// write to file
		AddressSeek(intel_crc->table_entry()->address());
		uint32_t hash;
		size = static_cast<uint32_t>(crc_table.WriteToFile(*this, false, &hash));
		AddressSeek(intel_crc->size_entry()->address());
		WriteDWord(size);
		AddressSeek(intel_crc->hash_entry()->address());
		WriteDWord(hash);

		intel_crc->size_entry()->set_operand_value(0, size);
		intel_crc->hash_entry()->set_operand_value(0, hash);
	}
	EndProgress();

	resource_section_info = 0;
	resource_packer_info = 0;
	file_crc_address = 0;
	file_crc_size = 0;
	file_crc_size_address = 0;
	loader_crc_address = 0;
	loader_crc_size = 0;
	loader_crc_size_address = 0;
	loader_crc_hash_address = 0;
	name_table = 0;
	name_table_size = 0;
	if (runtime) {
		uint64_t iat_address = 0;
		uint64_t security_cookie_address = 0;

		last_section = segment_list_->last();
		address = AlignValue(last_section->address() + last_section->size(), segment_alignment_);
		pos = Resize(AlignValue(this->size(), file_alignment_));
		size = 0;

		// create segment for IAT
		{
			size_t iat_count = 0;
			for (j = 0; j < 2; j++) {
				PEArchitecture* source_file = (j == 0) ? this : runtime;
				for (i = 0; i < source_file->import_list()->count(); i++) {
					IImport* import = source_file->import_list()->item(i);
					if (import->is_sdk())
						continue;

					iat_count += import->count();
					if (j == 1 && runtime->segment_list()->count())
						iat_count += import->count();
				}
			}

			if (iat_count) {
				iat_count++;
				iat_address = address + size;
				size += static_cast<uint32_t>(iat_count) * OperandSizeToValue(cpu_address_size());
			}
		}

		// create segment for security_cookie
		if ((ctx.options.flags & cpPack) && image_type() == itDriver && load_config_directory_->security_cookie() && AddressSeek(load_config_directory_->security_cookie())) {
			section = segment_list_->GetSectionByAddress(load_config_directory_->security_cookie());
			if (!(section && section->excluded_from_packing())) {
				uint32_t value_size = OperandSizeToValue(cpu_address_size());
				uint64_t security_cookie_value = 0;
				Read(&security_cookie_value, value_size);

				Resize(pos + size);
				Write(&security_cookie_value, value_size);

				security_cookie_address = address + size;
				size += value_size;
			}
		}

		// create segment for tls data
		if ((ctx.options.flags & cpPack) && tls_directory_->end_address_of_raw_data() > tls_directory_->start_address_of_raw_data()) {
			uint32_t data_size = static_cast<uint32_t>(tls_directory_->end_address_of_raw_data() - tls_directory_->start_address_of_raw_data());

			Data data;
			data.resize(data_size);
			if (AddressSeek(tls_directory_->start_address_of_raw_data()))
				Read(&data[0], data.size());

			Resize(pos + size);
			Write(data.data(), data.size());

			uint64_t tls_data_address = address + size;
			for (i = 0; i < data_size; i++) {
				if (IFixup* fixup = fixup_list()->GetFixupByAddress(tls_directory_->start_address_of_raw_data() + i))
					fixup->set_address(tls_data_address + i);
			}
			tls_directory_->set_start_address_of_raw_data(tls_data_address);
			tls_directory_->set_end_address_of_raw_data(tls_data_address + data_size);

			size += data_size;
		}

		if (size) {
			section = segment_list_->Add(address, size, static_cast<uint32_t>(pos), AlignValue(size, file_alignment_),
				IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA,
				string_format("%s%d", ctx.options.section_name.c_str(), vmp_index++));
			section->set_excluded_from_packing(true);
			Resize(section->physical_offset() + section->physical_size());
		}

		std::vector<IFunction*> processor_list = function_list_->processor_list();
		IntelRuntimeCRCTable* runtime_crc_table = reinterpret_cast<IntelFunctionList*>(function_list_)->runtime_crc_table();
		PEIntelLoader* loader = new PEIntelLoader(NULL, cpu_address_size());
		if (security_cookie_address)
			loader->set_security_cookie(security_cookie_address);
		if (iat_address)
			loader->set_iat_address(iat_address);

		last_section = segment_list_->last();
		address = AlignValue(last_section->address() + last_section->size(), segment_alignment_);

		manager->clear();
		manager->Add(address, UINT32_MAX, mtReadable | mtExecutable | mtWritable | mtNotPaged | (runtime_function_list()->count() ? mtSolid : mtNone));

		if (!loader->Prepare(ctx)) {
			delete loader;
			throw std::runtime_error("Runtime error at Save");
		}
		size_t write_count = loader->count() + 10000;
		size_t processor_count = 0;
		for (i = 0; i < processor_list.size(); i++) {
			processor_count += processor_list[i]->count();
		}
		ctx.file->StartProgress(string_format("%s...", language[lsSavingStartupCode].c_str()), loader->count() + write_count + processor_count);
		loader->Compile(ctx);

		pos = Resize(AlignValue(this->size(), file_alignment_));
		section = segment_list_->Add(address, UINT32_MAX, static_cast<uint32_t>(pos), UINT32_MAX,
			IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE,
			string_format("%s%d", ctx.options.section_name.c_str(), vmp_index++));
		c = loader->WriteToFile(*this);
		section->update_type(section->write_type() | ((ctx.options.sdk_flags & cpMemoryProtection) ? mtNotPaged : mtNone));
		for (i = 0; i < processor_list.size(); i++) {
			processor_list[i]->WriteToFile(*this);
		}
		if (runtime_crc_table)
			c += runtime_crc_table->WriteToFile(*this);

		// correct progress position
		write_count -= c;
		if (write_count)
			StepProgress(write_count);

		// copy directories
		{
			IArchitecture* source = const_cast<IArchitecture*>(this->source());
			last_section = segment_list_->last();
			const uint32_t copy_dir_types[] = { IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, IMAGE_DIRECTORY_ENTRY_ARCHITECTURE };
			for (j = 0; j < _countof(copy_dir_types); j++) {
				if (copy_dir_types[j] != IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG && (ctx.options.flags & cpPack) == 0)
					continue;

				dir = directory_list_->GetCommandByType(copy_dir_types[j]);
				if (dir && dir->address() && dir->physical_size() && source->AddressSeek(dir->address())) {
					size = dir->physical_size();
					pos = Resize(AlignValue(this->size(), 0x10));
					CopyFrom(*source, size);
					address = last_section->address() + pos - last_section->physical_offset();
					for (i = 0; i < size; i++) {
						PEFixup* fixup = reinterpret_cast<PEFixup*>(source->fixup_list()->GetFixupByAddress(dir->address() + i));
						if (fixup) {
							fixup = fixup->Clone(fixup_list_);
							fixup->set_address(address + i);
							fixup_list_->AddObject(fixup);
						}
					}
					dir->set_address(address);
				}
			}

			if ((ctx.options.flags & (cpPack | cpStripDebugInfo)) == cpPack) {
				if (debug_directory_->address()) {
					for (i = 0; i < debug_directory_->count(); i++) {
						PEDebugData* data = debug_directory_->item(i);
						if (source->Seek(data->offset())) {
							size = data->size();
							pos = Resize(AlignValue(this->size(), 0x10));
							CopyFrom(*source, size);
							address = last_section->address() + pos - last_section->physical_offset();

							data->set_offset(static_cast<uint32_t>(pos));
							data->set_address(address);
						}
					}
					pos = Resize(AlignValue(this->size(), 0x10));
					address = last_section->address() + pos - last_section->physical_offset();
					debug_directory_->WriteToFile(*this);

					dir = directory_list_->GetCommandByType(IMAGE_DIRECTORY_ENTRY_DEBUG);
					if (dir)
						dir->set_address(address);
				}
			}
		}

		dir = directory_list_->GetCommandByType(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
		if (dir) {
			if (security_cookie_address)
				load_config_directory_->set_security_cookie(security_cookie_address);
			std::vector<uint64_t> cfg_address_list = loader->cfg_address_list();
			for (i = 0; i < cfg_address_list.size(); i++) {
				load_config_directory_->cfg_address_list()->Add(cfg_address_list[i]);
			}
			if (loader->cfg_check_function_entry())
				load_config_directory_->set_cfg_check_function(loader->cfg_check_function_entry()->address());
			load_config_directory_->WriteToFile(*this);
		}

		dir = directory_list_->GetCommandByType(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
		if (dir) {
			pos = Resize(AlignValue(this->size(), 0x10));
			address = section->address() + pos - section->physical_offset();

			size = static_cast<uint32_t>(runtime_function_list_->WriteToFile(*this));
			if (size) {
				section->update_type(mtReadable | mtNotDiscardable | mtNotPaged);
				dir->set_address(address);
				dir->set_size(size);
			}
			else {
				dir->clear();
			}
		}

		size = static_cast<uint32_t>(this->size() - section->physical_offset());
		section->set_size(size);
		section->set_physical_size(AlignValue(size, file_alignment_));

		Resize(section->physical_offset() + section->physical_size());

		dir = directory_list_->GetCommandByType(IMAGE_DIRECTORY_ENTRY_IMPORT);
		if (dir) {
			dir->set_address(loader->import_entry()->address());
			dir->set_size(loader->import_size());
		}

		dir = directory_list_->GetCommandByType(IMAGE_DIRECTORY_ENTRY_IAT);
		if (dir) {
			dir->set_address(loader->iat_entry()->address());
			dir->set_size(loader->iat_size());
		}

		if (loader->export_entry()) {
			dir = directory_list_->GetCommandByType(IMAGE_DIRECTORY_ENTRY_EXPORT);
			if (dir) {
				if (loader->export_size()) {
					dir->set_address(loader->export_entry()->address());
					dir->set_size(loader->export_size());
				}
				else {
					dir->clear();
				}
			}
		}

		if (loader->tls_entry()) {
			dir = directory_list_->GetCommandByType(IMAGE_DIRECTORY_ENTRY_TLS);
			if (dir) {
				if (loader->tls_size()) {
					dir->set_address(loader->tls_entry()->address());
					dir->set_size(loader->tls_size());
				}
				else {
					dir->clear();
				}
			}
		}

		if (loader->delay_import_entry()) {
			dir = directory_list_->GetCommandByType(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
			if (dir) {
				if (loader->delay_import_size()) {
					dir->set_address(loader->delay_import_entry()->address());
					dir->set_size(loader->delay_import_size());
				}
				else {
					dir->clear();
				}
			}
		}

		entry_point_ = loader->entry()->address();

		if (loader->resource_section_info()) {
			resource_section_info = loader->resource_section_info()->address();
			resource_packer_info = loader->resource_packer_info()->address();
		}

		if (loader->file_crc_entry()) {
			file_crc_address = loader->file_crc_entry()->address();
			file_crc_size = loader->file_crc_size();
			file_crc_size_address = loader->file_crc_size_entry()->address();
		}

		if (loader->loader_crc_entry()) {
			loader_crc_address = loader->loader_crc_entry()->address();
			loader_crc_size = loader->loader_crc_size();
			loader_crc_size_address = loader->loader_crc_size_entry()->address();
			loader_crc_hash_address = loader->loader_crc_hash_entry()->address();
		}

		if (loader->name_entry()) {
			name_table = loader->name_entry()->address();
			name_table_size = loader->name_size();
		}

		delete loader;

		// update versions
		if (operating_system_version_ < runtime->operating_system_version_)
			operating_system_version_ = runtime->operating_system_version_;
		if (subsystem_version_ < runtime->subsystem_version_)
			subsystem_version_ = runtime->subsystem_version_;

		ctx.file->EndProgress();
	}

	// save fixups
	dir = directory_list_->GetCommandByType(IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (dir) {
		if (fixup_list_->Pack() == 0 || (ctx.options.flags & cpStripFixups) != 0) {
			dir->clear();
			fixup_section_ = NULL;
		}
		else {
			last_section = segment_list_->last();
			address = AlignValue(last_section->address() + last_section->size(), segment_alignment_);

			pos = Resize(AlignValue(this->size(), file_alignment_));
			size = static_cast<uint32_t>(fixup_list_->WriteToFile(*this));
			section = segment_list_->Add(address, size, static_cast<uint32_t>(pos), AlignValue(size, file_alignment_),
				fixup_section_flags, fixup_section_name);
			fixup_section_ = section;

			Resize(section->physical_offset() + section->physical_size());

			dir->set_address(address);
			dir->set_size(size);
		}
	}

	// save resources
	dir = directory_list_->GetCommandByType(IMAGE_DIRECTORY_ENTRY_RESOURCE);
	if (dir) {
		if (resource_list_->count() == 0) {
			dir->clear();
			resource_section_ = NULL;
		}
		else {
			last_section = segment_list_->last();
			address = AlignValue(last_section->address() + last_section->size(), segment_alignment_);

			pos = Resize(AlignValue(this->size(), file_alignment_));
			address = AlignValue(last_section->address() + last_section->size(), segment_alignment_);
			size = static_cast<uint32_t>(resource_list_->WriteToFile(*this, address));
			section = segment_list_->Add(address, (uint32_t)resource_list_->size(), static_cast<uint32_t>(pos), AlignValue(size, file_alignment_),
				resource_section_flags, resource_section_name);
			resource_section_ = section;

			Resize(section->physical_offset() + section->physical_size());

			dir->set_address(address);
			dir->set_size((uint32_t)resource_list_->size());

			if (resource_section_info) {
				pos = Tell();

				AddressSeek(resource_section_info);
				WriteDWord(static_cast<uint32_t>(address - image_base_));
				WriteDWord(static_cast<uint32_t>(resource_list_->size()));
				WriteDWord(section->flags());

				AddressSeek(resource_packer_info);
				WriteDWord(static_cast<uint32_t>(address - image_base_ + resource_list_->store_size()));

				Seek(pos);
			}
		}
	}

	// clear directories
	{
		const uint32_t clear_dir_types[] = { IMAGE_DIRECTORY_ENTRY_SECURITY, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT };
		for (i = 0; i < _countof(clear_dir_types); i++) {
			dir = directory_list_->GetCommandByType(clear_dir_types[i]);
			if (dir)
				dir->clear();
		}
		if (ctx.options.flags & cpStripDebugInfo) {
			dir = directory_list_->GetCommandByType(IMAGE_DIRECTORY_ENTRY_DEBUG);
			if (dir)
				dir->clear();
		}
	}

	// check discardable sections
	for (i = segment_list_->count(); i > 1; i--) {
		section = segment_list_->item(i - 1);
		if ((section->flags() & IMAGE_SCN_MEM_DISCARDABLE) == 0) {
			for (j = i - 1; j > 0; j--) {
				section = segment_list_->item(j - 1);
				section->set_flags(section->flags() & ~IMAGE_SCN_MEM_DISCARDABLE);
			}
			break;
		}
	}

	if (ctx.options.script)
		ctx.options.script->DoAfterSaveFile();

	// write header
	if (ctx.options.flags & cpStripFixups) {
		characterictics_ |= IMAGE_FILE_RELOCS_STRIPPED;
		dll_characteristics_ &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	}
	if ((ctx.options.flags | ctx.options.sdk_flags) & (cpCheckDebugger | cpCheckVirtualMachine))
		dll_characteristics_ &= ~IMAGE_DLLCHARACTERISTICS_NO_SEH;
	WriteToFile();

	// write header and loader CRC table
	if (loader_crc_address) {
		CRCTable crc_table(function_list_->crc_cryptor(), loader_crc_size);

		uint64_t resources_address = 0;
		if (resource_list()->size() > resource_list()->store_size()) {
			dir = directory_list_->GetCommandByType(IMAGE_DIRECTORY_ENTRY_RESOURCE);
			if (dir)
				resources_address = dir->address();
		}

		// add header
		crc_table.Add(image_base_, header_offset_ + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) +
			((cpu_address_size() == osDWord) ? offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory) : offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory)) +
			directory_list_->count() * sizeof(IMAGE_DATA_DIRECTORY) +
			segment_list_->count() * sizeof(IMAGE_SECTION_HEADER));

		// add loader sections
		j = segment_list_->IndexOf(segment_list_->GetSectionByAddress(loader_crc_address));
		if (j != NOT_ID) {
			c = (ctx.options.flags & cpLoaderCRC) ? j + 1 : segment_list_->count();
			for (i = j; i < c; i++) {
				section = segment_list_->item(i);
				if (section->memory_type() & mtWritable)
					continue;

				if (resources_address && section->address() == resources_address) {
					size = (uint32_t)(resource_list()->store_size());
				}
				else {
					size = std::min(static_cast<uint32_t>(section->size()), section->physical_size());
				}
				if (size)
					crc_table.Add(section->address(), size);
			}
		}

		// skip IMAGE_DOS_HEADER.e_res
		crc_table.Remove(image_base_ + offsetof(IMAGE_DOS_HEADER, e_res), sizeof(uint16_t) * 4);
		// skip IMAGE_OPTIONAL_HEADER.CheckSum
		crc_table.Remove(image_base_ + header_offset_ + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) +
			((cpu_address_size() == osDWord) ? offsetof(IMAGE_OPTIONAL_HEADER32, CheckSum) : offsetof(IMAGE_OPTIONAL_HEADER64, CheckSum)),
			sizeof(uint32_t));
		// skip IMAGE_OPTIONAL_HEADER.ImageBase
		crc_table.Remove(image_base_ + header_offset_ + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) +
			((cpu_address_size() == osDWord) ? offsetof(IMAGE_OPTIONAL_HEADER32, ImageBase) : offsetof(IMAGE_OPTIONAL_HEADER64, ImageBase)),
			OperandSizeToValue(cpu_address_size()));
		// skip security directory
		crc_table.Remove(image_base_ + header_offset_ + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) +
			((cpu_address_size() == osDWord) ? offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory) : offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory)) +
			IMAGE_DIRECTORY_ENTRY_SECURITY * sizeof(IMAGE_DATA_DIRECTORY),
			sizeof(IMAGE_DATA_DIRECTORY));
		// skip IAT directory
		dir = directory_list_->GetCommandByType(IMAGE_DIRECTORY_ENTRY_IAT);
		if (dir)
			crc_table.Remove(dir->address(), dir->size());

		if (image_type_ == itDriver) {
			// skip part of import table
			if (name_table)
				crc_table.Remove(name_table, name_table_size);
		}
		else {
			// skip IMAGE_IMPORT_DESCRIPTOR.TimeDateStamp and IMAGE_IMPORT_DESCRIPTOR.ForwarderChain for each import DLL
			dir = directory_list_->GetCommandByType(IMAGE_DIRECTORY_ENTRY_IMPORT);
			if (dir) {
				address = dir->address();
				for (i = 0; i < dir->size() / sizeof(IMAGE_IMPORT_DESCRIPTOR); i++, address += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
					crc_table.Remove(address + offsetof(IMAGE_IMPORT_DESCRIPTOR, TimeDateStamp), sizeof(uint32_t) * 2);
				}
			}
		}
		if (load_config_directory_->cfg_check_function())
			crc_table.Remove(load_config_directory_->cfg_check_function(), OperandSizeToValue(cpu_address_size()));
		// skip fixups
		if ((ctx.options.flags & cpStripFixups) == 0) {
			for (i = 0; i < fixup_list_->count(); i++) {
				PEFixup* fixup = fixup_list_->item(i);
				crc_table.Remove(fixup->address(), OperandSizeToValue(fixup->size()));
			}
		}
		// skip loader CRC table
		crc_table.Remove(loader_crc_address, loader_crc_size);
		crc_table.Remove(loader_crc_size_address, sizeof(uint32_t));
		crc_table.Remove(loader_crc_hash_address, sizeof(uint32_t));
		// skip file CRC table
		if (file_crc_address)
			crc_table.Remove(file_crc_address, file_crc_size);
		if (file_crc_size_address)
			crc_table.Remove(file_crc_size_address, sizeof(uint32_t));

		// write to file
		AddressSeek(loader_crc_address);
		uint32_t hash;
		size = static_cast<uint32_t>(crc_table.WriteToFile(*this, false, &hash));
		AddressSeek(loader_crc_size_address);
		WriteDWord(size);
		AddressSeek(loader_crc_hash_address);
		WriteDWord(hash);
	}

	// write file CRC table
	if (file_crc_address) {
		CRCTable crc_table(function_list_->crc_cryptor(), file_crc_size - sizeof(uint32_t));

		// add file range
		crc_table.Add(1, static_cast<size_t>(this->size()) - 1);
		// skip IMAGE_OPTIONAL_HEADER.CheckSum
		crc_table.Remove(header_offset_ + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) +
			((cpu_address_size() == osDWord) ? offsetof(IMAGE_OPTIONAL_HEADER32, CheckSum) : offsetof(IMAGE_OPTIONAL_HEADER64, CheckSum)),
			sizeof(uint32_t));
		// skip position of security directory
		crc_table.Remove(header_offset_ + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) +
			((cpu_address_size() == osDWord) ? offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory) : offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory)) +
			IMAGE_DIRECTORY_ENTRY_SECURITY * sizeof(IMAGE_DATA_DIRECTORY),
			sizeof(IMAGE_DATA_DIRECTORY));
		// skip file CRC table
		if (AddressSeek(file_crc_address))
			crc_table.Remove(Tell(), file_crc_size);
		if (AddressSeek(file_crc_size_address))
			crc_table.Remove(Tell(), sizeof(uint32_t));

		// write to file
		AddressSeek(file_crc_address);
		size = static_cast<uint32_t>(this->size());
		WriteDWord(size);
		size = static_cast<uint32_t>(crc_table.WriteToFile(*this, true));
		AddressSeek(file_crc_size_address);
		WriteDWord(size);
	}

	WriteCheckSum();

	EndProgress();
}

void PEArchitecture::Rebase(uint64_t target_image_base, uint64_t delta_base)
{
	BaseArchitecture::Rebase(delta_base);

	fixup_list_->Rebase(*this, delta_base);
	import_list_->Rebase(delta_base);
	export_list_->Rebase(delta_base);
	directory_list_->Rebase(delta_base);
	load_config_directory_->Rebase(delta_base);
	runtime_function_list_->RebaseByFile(*this, target_image_base, delta_base);
	segment_list_->Rebase(delta_base);
	section_list_->Rebase(delta_base);
	function_list_->Rebase(delta_base);

	if (entry_point_)
		entry_point_ += delta_base;
	image_base_ += delta_base;
}

bool PEArchitecture::is_executable() const
{
	return image_type() == itExe;
}

std::string PEArchitecture::ANSIToUTF8(const std::string& str) const
{
#ifndef VMP_GNU
	if (!os::ValidateUTF8(str))
		return os::ToUTF8(os::FromACP(str));
#endif
	return str;
}

void PEArchitecture::ReadFromBuffer(Buffer& buffer)
{
	BaseArchitecture::ReadFromBuffer(buffer);

	PECFGAddressTable* cfg_address_list = load_config_directory_->cfg_address_list();
	size_t c = buffer.ReadDWord();
	for (size_t i = 0; i < c; i++) {
		cfg_address_list->Add(buffer.ReadDWord() + image_base());
	}
}
