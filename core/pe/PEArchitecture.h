/**
 * PE Architecture support.
 */

#ifndef PE_ARCHITECTURE_H
#define PE_ARCHITECTURE_H

#include "../files/architecture.h"
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

class PEFile;
class IFunctionList;
class IVirtualMachineList;

enum ImageType {
	itExe,
	itLibrary,
	itDriver
};

class PEArchitecture : public BaseArchitecture
{
public:
	explicit PEArchitecture(PEFile *owner, uint64_t offset, uint64_t size);
	explicit PEArchitecture(PEFile *owner, const PEArchitecture &src);
	virtual ~PEArchitecture();
	virtual PEArchitecture *Clone(IFile *file) const;
	OpenStatus ReadFromFile(uint32_t mode);
	virtual void ReadFromBuffer(Buffer &buffer);
	void WriteCheckSum();
	virtual bool WriteToFile();
	virtual bool is_executable() const;
	virtual std::string name() const;
	virtual uint32_t type() const { return cpu_; }
	virtual OperandSize cpu_address_size() const { return cpu_address_size_; }
	virtual uint64_t entry_point() const { return entry_point_; }
	void set_entry_point(uint64_t entry_point) { entry_point_ = entry_point; }
	virtual uint32_t segment_alignment() const { return segment_alignment_; }
	virtual uint32_t file_alignment() const { return file_alignment_; }
	virtual uint64_t image_base() const { return image_base_; }
	virtual PEDirectoryList *command_list() const { return directory_list_; }
	virtual PESegmentList *segment_list() const { return segment_list_; }
	virtual PESectionList *section_list() const { return section_list_; }
	virtual PEImportList *import_list() const { return import_list_; }
	virtual PEExportList *export_list() const { return export_list_; }
	virtual PEFixupList *fixup_list() const { return fixup_list_; }
	virtual PERelocationList *relocation_list() const { return relocation_list_; }
	virtual PEResourceList *resource_list() const { return resource_list_; }
	virtual PESEHandlerList *seh_handler_list() const { return load_config_directory_->seh_handler_list(); }
	PETLSDirectory *tls_directory() const { return tls_directory_; }
	PELoadConfigDirectory *load_config_directory() const { return load_config_directory_; }
	PEDelayImportList *delay_import_list() const { return delay_import_list_; }
	virtual IFunctionList *function_list() const { return function_list_; }
	virtual IVirtualMachineList *virtual_machine_list() const { return virtual_machine_list_; }
	virtual PERuntimeFunctionList *runtime_function_list() const { return runtime_function_list_; }
	virtual bool Compile(CompileOptions &options, IArchitecture *runtime);
	virtual void Save(CompileContext &ctx);
	ImageType image_type() const { return image_type_; }
	void Rebase(uint64_t target_image_base, uint64_t delta_base);
	virtual CallingConvention calling_convention() const { return (cpu_address_size() == osDWord) ? ccStdcall : ccMSx64; }
	virtual uint64_t time_stamp() const { return time_stamp_; }
	PESegment *resource_section() const { return resource_section_; }
	PESegment *fixup_section() const { return fixup_section_; }
	uint32_t header_offset() const { return header_offset_; }
	uint32_t header_size() const { return header_size_; }
	virtual std::string ANSIToUTF8(const std::string &str) const;
	uint16_t dll_characteristics() const { return dll_characteristics_; }
	std::string pdb_file_name() const;
	uint32_t operating_system_version() const { return operating_system_version_; }
protected:
	virtual bool Prepare(CompileContext &ctx);
	virtual bool ReadMapFile(IMapFile &map_file);
private:
	enum {
		MIN_HEADER_OFFSET = 0x80
	};
	PEDirectoryList *directory_list_;
	PESegmentList *segment_list_;
	PESectionList *section_list_;
	PEImportList *import_list_;
	PEExportList *export_list_;
	PEFixupList *fixup_list_;
	PERelocationList *relocation_list_;
	IFunctionList *function_list_;
	PEResourceList *resource_list_;
	PELoadConfigDirectory *load_config_directory_;
	IVirtualMachineList *virtual_machine_list_;
	PERuntimeFunctionList *runtime_function_list_;
	PETLSDirectory *tls_directory_;
	PEDebugDirectory *debug_directory_;
	PEDelayImportList *delay_import_list_;
	uint32_t cpu_;
	OperandSize cpu_address_size_;
	uint64_t time_stamp_;
	uint64_t entry_point_;
	uint64_t image_base_;
	uint32_t header_offset_;
	uint32_t header_size_;
	uint32_t segment_alignment_;
	uint32_t file_alignment_;
	PESegment *resource_section_;
	PESegment *fixup_section_;
	size_t optimized_section_count_;
	ImageType image_type_;
	uint16_t characterictics_;
	uint32_t check_sum_;
	uint32_t low_resize_header_;
	uint32_t resize_header_;
	uint32_t operating_system_version_;
	uint32_t subsystem_version_;
	uint16_t dll_characteristics_;
	
	// no copy ctr or assignment op
	PEArchitecture(const PEArchitecture &);
	PEArchitecture &operator =(const PEArchitecture &);
};

#endif // PE_ARCHITECTURE_H
