#ifndef INTEL_LOADER_H
#define INTEL_LOADER_H

#include "IntelFunction.h"
#include <set>

class PESegment;
class MacSegment;
class ELFSegment;
class MacImportFunction;
class MacFixup;
class MacSymbol;
class ELFImportFunction;
class ELFFixup;
class ELFArchitecture;
class IVirtualMachine;
class IVirtualMachineList;
class ICommand;
class AddressRange;
class IntelFunctionList;
class PEImportFunction;
struct CompileContext;

class BaseIntelLoader : public IntelFunction
{
public:
	BaseIntelLoader(IntelFunctionList *owner, OperandSize cpu_address_size);
	virtual bool Prepare(const CompileContext &ctx);
	virtual bool Compile(const CompileContext &ctx);
	virtual IVirtualMachine *virtual_machine(IVirtualMachineList *virtual_machine_list, ICommand *command) const;
	uint64_t import_segment_address() const { return import_segment_address_; }
	uint64_t data_segment_address() const { return data_segment_address_; }
protected:
	struct LoaderInfo {
		IntelCommand *data;
		size_t size;
		LoaderInfo(IntelCommand *data_, size_t size_) 
			: data(data_), size(size_) {}
	};
	void AddAVBuffer(const CompileContext &ctx);
private:
	std::set<ICommand *> command_group_;
	uint64_t import_segment_address_;
	uint64_t data_segment_address_;
};

class PEIntelLoader : public BaseIntelLoader
{
public:
	PEIntelLoader(IntelFunctionList *owner, OperandSize cpu_address_size);
	virtual bool Prepare(const CompileContext &ctx);
	IntelCommand *import_entry() const { return import_entry_; }
	uint32_t import_size() const { return import_size_; }
	IntelCommand *iat_entry() const { return iat_entry_; }
	uint32_t iat_size() const { return iat_size_; }
	IntelCommand *name_entry() const { return name_entry_; }
	uint32_t name_size() const { return iat_size_; }
	IntelCommand *export_entry() const { return export_entry_; }
	uint32_t export_size() const { return export_size_; }
	IntelCommand *tls_entry() const { return tls_entry_; }
	uint32_t tls_size() const { return tls_size_; }
	IntelCommand *delay_import_entry() const { return delay_import_entry_; }
	uint32_t delay_import_size() const { return delay_import_size_; }
	IntelCommand *resource_section_info() const { return resource_section_info_; }
	IntelCommand *resource_packer_info() const { return resource_packer_info_; }
	IntelCommand *file_crc_entry() const { return file_crc_entry_; }
	uint32_t file_crc_size() const { return file_crc_size_; }
	IntelCommand *file_crc_size_entry() const { return file_crc_size_entry_; }
	IntelCommand *loader_crc_entry() const { return loader_crc_entry_; }
	uint32_t loader_crc_size() const { return loader_crc_size_; }
	IntelCommand *loader_crc_size_entry() const { return loader_crc_size_entry_; }
	IntelCommand *loader_crc_hash_entry() const { return loader_crc_hash_entry_; }
	IntelCommand *cfg_check_function_entry() const { return cfg_check_function_entry_; }
	void set_security_cookie(uint64_t value) { security_cookie_ = value; }
	void set_iat_address(uint64_t value) { iat_address_ = value; }
	std::vector<uint64_t> cfg_address_list() const;
private:
	IntelCommand *import_entry_;
	uint32_t import_size_;
	IntelCommand *iat_entry_;
	uint32_t iat_size_;
	IntelCommand *name_entry_;
	IntelCommand *resource_section_info_;
	IntelCommand *resource_packer_info_;
	IntelCommand *export_entry_;
	uint32_t export_size_;
	IntelCommand *tls_entry_;
	IntelCommand *tls_call_back_entry_;
	uint32_t tls_size_;
	IntelCommand *file_crc_entry_;
	uint32_t file_crc_size_;
	IntelCommand *file_crc_size_entry_;
	IntelCommand *loader_crc_entry_;
	uint32_t loader_crc_size_;
	IntelCommand *loader_crc_size_entry_;
	IntelCommand *loader_crc_hash_entry_;
	IntelCommand *delay_import_entry_;
	uint32_t delay_import_size_;
	uint64_t security_cookie_;
	uint64_t iat_address_;
	IntelCommand *cfg_check_function_entry_;

	struct ImportInfo {
		IntelCommand *original_first_thunk;
		IntelCommand *name;
		IntelCommand *first_thunk;
		IntelCommand *loader_name;
	};

	struct ImportFunctionInfo {
		PEImportFunction *import_function;
		IntelCommand *name;
		IntelCommand *thunk;
		IntelCommand *loader_name;
		ImportFunctionInfo(PEImportFunction *import_function_)
			: import_function(import_function_), name(NULL), thunk(NULL), loader_name(NULL) {}
		bool operator == (PEImportFunction *import_function_) const
		{
			return (import_function == import_function_);
		}
	};

	struct PackerInfo {
		PESegment *section;
		uint64_t address;
		size_t size;
		IntelCommand *data;
		bool operator == (PESegment *section_) const
		{
			return (section == section_);
		}
	};
};

class MacIntelLoader : public BaseIntelLoader
{
public:
	MacIntelLoader(IntelFunctionList *owner, OperandSize cpu_address_size);
	virtual bool Prepare(const CompileContext &ctx);
	virtual bool Compile(const CompileContext &ctx);
	IntelCommand *import_entry() const { return import_entry_; }
	uint32_t import_size() const { return import_size_; }
	IntelCommand *jmp_table_entry() const { return jmp_table_entry_; }
	uint32_t jmp_table_size() const { return jmp_table_size_; }
	IntelCommand *lazy_import_entry() const { return lazy_import_entry_; }
	uint32_t lazy_import_size() const { return lazy_import_size_; }
	IntelCommand *init_entry() const { return init_entry_; }
	uint32_t init_size() const { return init_size_; }
	IntelCommand *term_entry() const { return term_entry_; }
	uint32_t term_size() const { return term_size_; }
	IntelCommand *thread_variables_entry() const { return thread_variables_entry_; }
	uint32_t thread_variables_size() const { return thread_variables_size_; }
	IntelCommand *thread_data_entry() const { return thread_data_entry_; }
	uint32_t thread_data_size() const { return thread_data_size_; }
	IntelCommand *file_crc_entry() const { return file_crc_entry_; }
	uint32_t file_crc_size() const { return file_crc_size_; }
	IntelCommand *file_crc_size_entry() const { return file_crc_size_entry_; }
	IntelCommand *loader_crc_entry() const { return loader_crc_entry_; }
	uint32_t loader_crc_size() const { return loader_crc_size_; }
	IntelCommand *loader_crc_size_entry() const { return loader_crc_size_entry_; }
	IntelCommand *loader_crc_hash_entry() const { return loader_crc_hash_entry_; }
	IntelCommand *file_entry() const { return file_entry_; }
	std::vector<MacSegment *> packed_segment_list() const { return packed_segment_list_; }
	IntelCommand *patch_section_entry() const { return patch_section_entry_; }
private:
	IntelCommand *import_entry_;
	uint32_t import_size_;
	IntelCommand *jmp_table_entry_;
	uint32_t jmp_table_size_;
	IntelCommand *lazy_import_entry_;
	uint32_t lazy_import_size_;
	IntelCommand *init_entry_;
	uint32_t init_size_;
	IntelCommand *term_entry_;
	uint32_t term_size_;
	IntelCommand *thread_variables_entry_;
	uint32_t thread_variables_size_;
	IntelCommand *thread_data_entry_;
	uint32_t thread_data_size_;
	std::map<MacImportFunction *, IntelCommand *> import_function_info_;
	std::map<MacFixup *, IntelCommand *> relocation_info_;
	IntelCommand *file_crc_entry_;
	uint32_t file_crc_size_;
	IntelCommand *file_crc_size_entry_;
	IntelCommand *loader_crc_entry_;
	uint32_t loader_crc_size_;
	IntelCommand *loader_crc_size_entry_;
	IntelCommand *loader_crc_hash_entry_;
	IntelCommand *file_entry_;
	IntelCommand *patch_section_entry_;
	std::vector<MacSegment *> packed_segment_list_;

	struct PackerInfo {
		uint64_t address;
		size_t size;
		MacSegment *segment;
		IntelCommand *data;
		PackerInfo()
			: address(0), size(0), segment(NULL), data(NULL)
		{
		}

		PackerInfo(MacSegment *segment_, uint64_t address_, size_t size_)
			: address(address_), size(size_), segment(segment_), data(NULL)
		{
		}

		bool operator == (MacSegment *segment_) const
		{
			return (segment == segment_);
		}
	};
};

class ELFIntelLoader : public BaseIntelLoader
{
public:
	ELFIntelLoader(IntelFunctionList *owner, OperandSize cpu_address_size);
	virtual bool Prepare(const CompileContext &ctx);
	virtual bool Compile(const CompileContext &ctx);
	IntelCommand *import_entry() const { return import_entry_; }
	uint32_t import_size() const { return import_size_; }
	IntelCommand *file_crc_entry() const { return file_crc_entry_; }
	uint32_t file_crc_size() const { return file_crc_size_; }
	IntelCommand *file_crc_size_entry() const { return file_crc_size_entry_; }
	IntelCommand *loader_crc_entry() const { return loader_crc_entry_; }
	uint32_t loader_crc_size() const { return loader_crc_size_; }
	IntelCommand *loader_crc_size_entry() const { return loader_crc_size_entry_; }
	IntelCommand *loader_crc_hash_entry() const { return loader_crc_hash_entry_; }
	IntelCommand *term_entry() const { return term_entry_ ? reinterpret_cast<IntelCommand *>(term_entry_->link()->to_command()) : NULL; }
	IntelCommand *preinit_entry() const { return preinit_entry_; }
	uint32_t preinit_size() const { return preinit_size_; }
	IntelCommand *init_entry() const { return init_entry_; }
	IntelCommand *tls_entry() const { return tls_entry_; }
	uint32_t GetPackedSize(ELFArchitecture *file) const;
private:
	IntelCommand *import_entry_;
	uint32_t import_size_;
	IntelCommand *file_crc_entry_;
	uint32_t file_crc_size_;
	IntelCommand *file_crc_size_entry_;
	IntelCommand *loader_crc_entry_;
	uint32_t loader_crc_size_;
	IntelCommand *loader_crc_size_entry_;
	IntelCommand *loader_crc_hash_entry_;
	IntelCommand *preinit_entry_;
	uint32_t preinit_size_;
	IntelCommand *term_entry_;
	IntelCommand *init_entry_;
	IntelCommand *tls_entry_;
	IntelCommand *relro_entry_;

	struct PackerInfo {
		uint64_t address;
		size_t size;
		ELFSegment *segment;
		IntelCommand *data;
		PackerInfo()
			: address(0), size(0), segment(NULL), data(NULL)
		{
		}

		PackerInfo(ELFSegment *segment_, uint64_t address_, size_t size_)
			: address(address_), size(size_), segment(segment_), data(NULL)
		{
		}

		bool operator == (ELFSegment *segment_) const
		{
			return (segment == segment_);
		}
	};
};

#endif // INTEL_LOADER_H