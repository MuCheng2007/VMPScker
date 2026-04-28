/**
 * Operations with executable files.
 */

#ifndef FILES_H
#define FILES_H

#include "../runtime/common.h"
#include "objects.h"


class LicensingManager;
class FileManager;

#include "files/utils.h"

class Core;
class Watermark;
class WatermarkManager;
class LicensingManager;
class FileManager;
class Script;
class IFile;
class IArchitecture;
class IFunctionList;
class IFunction;
class ICommand;
class CommandBlock;
class IVirtualMachineList;
class MemoryManager;
class ILoadCommandList;
class ISectionList;
class IImport;
class IImportList;
class IExportList;
class IFixupList;
class ISEHandlerList;
class MapFunction;
class MapFunctionList;
class ReferenceList;
class Buffer;
class IRuntimeFunctionList;
class ValueCryptor;
class CRCValueCryptor;
class ISymbol;

class ILog : public IObject
{
public:
	virtual void Notify(MessageType type, IObject *sender, const std::string &message = "") = 0;
	virtual void StartProgress(const std::string &message, unsigned long long max) = 0;
	virtual void StepProgress(unsigned long long value = 1, bool is_project = false) = 0;
	virtual void EndProgress() = 0;
	virtual void set_warnings_as_errors(bool value) = 0;
	virtual void set_arch_name(const std::string &arch_name) = 0;
};

#include "files/sections.h"

// APIType, ImportOption, RuntimeOptions, CompilationType -> files/types.h

#include "files/imports.h"

#include "files/exports.h"

// NEED_FIXUP, LARGE_VALUE, FixupType -> files/types.h

#include "files/fixups.h"

#include "files/relocations.h"

#include "files/seh.h"

#include "files/references.h"

#include "files/mapping.h"

// Map classes -> files/mapping.h

class IResource : public ObjectList<IResource>
{
public:
	virtual uint32_t type() const = 0;
	virtual uint64_t address() const = 0;
	virtual size_t size() const = 0;
	virtual std::string name() const = 0;
	virtual IResource *owner() const = 0;
	virtual bool is_directory() const = 0;
	virtual bool need_store() const = 0;
	virtual IResource *Clone(IResource *owner) const = 0;
	virtual IResource *GetResourceByName(const std::string &name) const = 0;
	virtual IResource *GetResourceByType(uint32_t type) const = 0;
	virtual IResource *GetResourceById(const std::string &id) const = 0;
	virtual bool excluded_from_packing() const = 0;
	virtual void set_excluded_from_packing(bool value) = 0;
	virtual OperandSize address_size() const = 0;
	virtual void Notify(MessageType type, IObject *sender, const std::string &message = "") const = 0;
	virtual std::string id() const = 0;
	virtual Data hash() const = 0;
};

class IResourceList : public IResource
{
public:
	virtual std::vector<IResource*> GetResourceList() const = 0;
};

class BaseResource : public IResource
{
public:
	explicit BaseResource(IResource *owner);
	explicit BaseResource(IResource *owner, const BaseResource &src);
	~BaseResource();
	virtual IResource *owner() const { return owner_; }
	virtual IResource *GetResourceByName(const std::string &name) const;
	virtual IResource *GetResourceByType(uint32_t type) const;
	virtual IResource *GetResourceById(const std::string &id) const;
	virtual bool excluded_from_packing() const { return excluded_from_packing_; }
	virtual void set_excluded_from_packing(bool value);
	virtual OperandSize address_size() const;
	virtual void Notify(MessageType type, IObject *sender, const std::string &message = "") const;
	virtual Data hash() const;
private:
	IResource *owner_;
	bool excluded_from_packing_;
};

class BaseResourceList : public IResourceList
{
public:
	explicit BaseResourceList(IArchitecture *owner);
	explicit BaseResourceList(IArchitecture *owner, const BaseResourceList &src);
	virtual uint32_t type() const { return (uint32_t)-1; }
	virtual uint64_t address() const { return 0; }
	virtual size_t size() const { return 0; }
	virtual std::string name() const { return std::string(); }
	virtual IResource *owner() const { return NULL; }
	virtual bool is_directory() const { return true; }
	virtual IResource *Clone(IResource * /*owner*/) const { return NULL; }
	virtual IResource *GetResourceByName(const std::string &name) const;
	virtual IResource *GetResourceByType(uint32_t type) const;
	virtual IResource *GetResourceById(const std::string &id) const;
	virtual bool excluded_from_packing() const { return false; }
	virtual void set_excluded_from_packing(bool /*value*/) { }
	virtual bool need_store() const { return true; }
	virtual std::vector<IResource*> GetResourceList() const;
	virtual std::string id() const { return std::string(); }
	virtual OperandSize address_size() const;
	virtual void Notify(MessageType type, IObject *sender, const std::string &message = "") const;
	virtual Data hash() const { return Data(); }
private:
	IArchitecture *owner_;
};

// CompilerFunctionType, CompilerFunctionOption -> files/types.h

class CompilerFunctionList;

class CompilerFunction : public IObject
{
public:
	explicit CompilerFunction(CompilerFunctionList *owner, CompilerFunctionType type, uint64_t address);
	explicit CompilerFunction(CompilerFunctionList *owner, const CompilerFunction &src);
	~CompilerFunction();
	CompilerFunctionType type() const { return type_; }
	uint64_t address() const { return address_; }
	uint64_t value(size_t index) const { return (index < value_list_.size()) ? value_list_[index] : 0; }
	void add_value(uint64_t value) { value_list_.push_back(value); } 
	virtual CompilerFunction *Clone(CompilerFunctionList *owner) const;
	uint32_t options() const { return options_; }
	void include_option(CompilerFunctionOption option) { options_ |= option; }
	size_t count() const { return value_list_.size(); }
	void Rebase(uint64_t delta_base);
private:
	CompilerFunctionList *owner_;
	uint64_t address_;
	CompilerFunctionType type_;
	uint32_t options_;
	std::vector<uint64_t> value_list_;

	// not implemented
	CompilerFunction(const CompilerFunction &);
	CompilerFunction &operator =(const CompilerFunction &);
};

class CompilerFunctionList : public ObjectList<CompilerFunction>
{
public:
	explicit CompilerFunctionList();
	explicit CompilerFunctionList(const CompilerFunctionList &src);
	CompilerFunction *Add(CompilerFunctionType type, uint64_t address);
	virtual void AddObject(CompilerFunction *func);
	CompilerFunction *GetFunctionByAddress(uint64_t address) const;
	CompilerFunction *GetFunctionByLowerAddress(uint64_t address) const;
	CompilerFunctionList *Clone() const;
	uint64_t GetRegistrValue(uint64_t address, uint64_t registr) const;
	uint32_t GetSDKOptions() const;
	uint32_t GetRuntimeOptions() const;
	void Rebase(uint64_t delta_base);
private:
	std::map<uint64_t, CompilerFunction*> map_;

	// no assignment op
	CompilerFunctionList &operator =(const CompilerFunctionList &);
};

class IRuntimeFunction : public IObject
{
public:
	virtual IRuntimeFunction *Clone(IRuntimeFunctionList *owner) const = 0;
	virtual uint64_t address() const = 0;
	virtual uint64_t begin() const = 0;
	virtual uint64_t end() const = 0;
	virtual uint64_t unwind_address() const = 0;
	virtual void set_begin(uint64_t begin) = 0;
	virtual void set_end(uint64_t end) = 0;
	virtual void set_unwind_address(uint64_t unwind_address) = 0;
	virtual void Parse(IArchitecture &file, IFunction &dest) = 0;
	virtual void Rebase(uint64_t delta_base) = 0;

	using IObject::CompareWith;
	int CompareWith(const IRuntimeFunction &obj) const
	{
		if (begin() < obj.begin())
			return -1;
		if (begin() > obj.begin())
			return 1;
		return 0;
	}
};

class IRuntimeFunctionList : public ObjectList<IRuntimeFunction>
{
public:
	virtual IRuntimeFunction *GetFunctionByAddress(uint64_t address) const = 0;
	virtual IRuntimeFunction *GetFunctionByUnwindAddress(uint64_t address) const = 0;
	virtual IRuntimeFunction *Add(uint64_t address, uint64_t begin, uint64_t end, uint64_t unwind_address, IRuntimeFunction *source, const std::vector<uint8_t> &call_frame_instructions) = 0;
};

class BaseRuntimeFunction : public IRuntimeFunction
{
public:
	explicit BaseRuntimeFunction(IRuntimeFunctionList *owner);
	explicit BaseRuntimeFunction(IRuntimeFunctionList *owner, const BaseRuntimeFunction &src);
	~BaseRuntimeFunction();
private:
	IRuntimeFunctionList *owner_;
};

class BaseRuntimeFunctionList : public IRuntimeFunctionList
{
public:
	explicit BaseRuntimeFunctionList();
	explicit BaseRuntimeFunctionList(const BaseRuntimeFunctionList &src);
	virtual void clear();
	virtual IRuntimeFunction *GetFunctionByAddress(uint64_t address) const;
	virtual IRuntimeFunction *GetFunctionByUnwindAddress(uint64_t address) const;
	virtual void Rebase(uint64_t delta_base);
	virtual void AddObject(IRuntimeFunction *obj);
private:
	std::map<uint64_t, IRuntimeFunction *> map_;
	std::map<uint64_t, IRuntimeFunction *> unwind_map_;

	// not impl
	BaseRuntimeFunctionList &operator =(const BaseRuntimeFunctionList &);
};

struct CompileOptions {
	uint32_t flags;
	uint32_t vm_flags;
	uint32_t sdk_flags;
	size_t vm_count;
	std::string section_name;
	std::string messages[MESSAGE_COUNT];
	Watermark *watermark;
	Script *script;
	IArchitecture **architecture;
	std::string hwid;
	LicensingManager *licensing_manager;
	FileManager *file_manager;
	CompileOptions() : flags(0), vm_flags(0), sdk_flags(0), vm_count(1), watermark(NULL), script(NULL), architecture(NULL)
		, licensing_manager(NULL), file_manager(NULL)
		{}
};

class Folder : public ObjectList<Folder>
{
public:
	explicit Folder(Folder *owner, const std::string &name);
	explicit Folder(Folder *owner, const Folder &src);
	virtual ~Folder();
	Folder *Clone(Folder *owner) const;
	Folder *Add(const std::string &name);
	std::string name() const { return name_; }
	Folder *owner() const { return owner_; }
	void set_name(const std::string &name);
	bool read_only() const { return read_only_; }
	void set_read_only(bool read_only) { read_only_ = read_only; }
	std::string id() const;
	void set_owner(Folder *owner);
	virtual void Notify(MessageType type, IObject *sender, const std::string &message = "") const;
	Folder *GetFolderById(const std::string &id) const;
private:
	void changed();
	Folder *owner_;
	std::string name_;
	bool read_only_;
};

class FunctionBundle;
class FunctionBundleList;

class FolderList : public Folder
{
public:
	explicit FolderList(IFile *owner);
	explicit FolderList(IFile *owner, const FolderList &src);
	FolderList *Clone(IFile *owner) const;
	std::vector<Folder*> GetFolderList(bool skip_read_only = false) const;
	virtual void Notify(MessageType type, IObject *sender, const std::string &message = "") const;
	IFile *owner() const { return owner_; }
private:
	IFile *owner_;
};

class FunctionArch : public IObject
{
public:
	explicit FunctionArch(FunctionBundle *owner, IArchitecture *arch, IFunction *func);
	~FunctionArch();
	IArchitecture *arch() const { return arch_; }
	IFunction *func() const { return func_; }
private:
	FunctionBundle *owner_;
	IArchitecture *arch_;
	IFunction *func_;
};

struct FunctionBundleHash {
	std::string name;
	bool is_unknown;
	FunctionBundleHash(const std::string &name_, bool is_unknown_) : name(name_), is_unknown(is_unknown_) {}
	bool operator < (const FunctionBundleHash &hash) const
	{
		int res = name.compare(hash.name);
		return (res != 0) ? (res < 0) : (is_unknown < hash.is_unknown);
	}
};

class FunctionBundle : public ObjectList<FunctionArch>
{
public:
	explicit FunctionBundle(FunctionBundleList *owner, const FunctionName &name, bool is_unknown);
	~FunctionBundle();
	FunctionArch *Add(IArchitecture *arch, IFunction *func);
	std::string name() const { return name_.name(); }
	bool is_unknown() const { return is_unknown_; }
	std::string display_name() const { return name_.display_name(); }
	bool need_compile() const;
	void set_need_compile(bool need_compile);
	CompilationType compilation_type() const;
	CompilationType default_compilation_type() const;
	void set_compilation_type(CompilationType compilation_type);
	uint32_t compilation_options() const;
	void set_compilation_options(uint32_t compilation_options);
	Folder *folder() const;
	void set_folder(Folder *folder);
	ObjectType type() const;
	std::string display_address() const;
	std::string display_protection() const;
	std::string id() const { return (type() == otUnknown) ? display_name() : display_address(); }
	bool show_arch_name() const;
	FunctionArch *GetArchByFunction(IFunction *func) const;
	ICommand *GetCommandByAddress(IArchitecture *file, uint64_t address) const;
private:
	FunctionBundleList *owner_;
	FunctionName name_;
	bool is_unknown_;
};

class FunctionBundleList : public ObjectList<FunctionBundle>
{
public:
	explicit FunctionBundleList();
	FunctionBundle *Add(IArchitecture *arch, IFunction *func);
	virtual void AddObject(FunctionBundle *bundle);
	virtual void RemoveObject(FunctionBundle *bundle);
	FunctionBundle *GetFunctionByFunc(IFunction *func) const;
	FunctionBundle *GetFunctionByAddress(IArchitecture *arch, uint64_t address) const;
	FunctionBundle *GetFunctionById(const std::string &id) const;
	FunctionBundle *GetFunctionByName(const std::string &name, bool need_unknown = false) const;
	bool show_arch_name() const { return show_arch_name_; }
	void set_show_arch_name(bool show_arch_name) { show_arch_name_ = show_arch_name; }
private:
	std::map<FunctionBundleHash, FunctionBundle *> map_;
	bool show_arch_name_;
};

// OpenMode, OpenStatus -> files/types.h

class AbstractStream;
class ILog;

// ResourceInfo -> files/types.h

class IFile : public ObjectList<IArchitecture>
{
public:
	explicit IFile(ILog *log);
	explicit IFile(const IFile &src, const char *file_name);
	virtual ~IFile();
	virtual std::string format_name() const { return std::string("Unknown"); }
	virtual bool OpenResource(const void *resource, size_t size, bool is_enc);
	virtual bool OpenModule(uint32_t process_id, HMODULE module);
	virtual OpenStatus Open(const char *file_name, uint32_t open_mode, std::string *error = NULL);
	virtual void Close();
	virtual IFile *Clone(const char *file_name) const;
	virtual std::string file_name(bool is_real = false) const { return (is_real && !file_name_tmp_.empty()) ? file_name_tmp_ : file_name_; };
	virtual std::string version() const { return std::string(); };
	virtual std::string exec_command() const { return std::string(); };
	uint8_t ReadByte();
	uint16_t ReadWord();
	uint32_t ReadDWord();
	uint64_t ReadQWord();
	size_t Read(void *buffer, size_t count);
	size_t Write(const void *buffer, size_t count);
	void Flush();
	std::string ReadString();
	uint64_t Seek(uint64_t position);
	uint64_t Tell();
	uint64_t size() const;
	uint64_t Resize(uint64_t size);
	virtual bool Compile(CompileOptions &options);
	virtual IFile *runtime() const { return NULL; }
	uint64_t CopyFrom(IFile &source, uint64_t count);
	void Notify(MessageType type, IObject *sender, const std::string &message = "") const;
	void StartProgress(const std::string &caption, unsigned long long max) const;
	void StepProgress(unsigned long long value = 1ull) const;
	void EndProgress() const;
	void set_log(ILog *log) { log_ = log; }
	std::map<Watermark *, size_t> SearchWatermarks(const WatermarkManager &watermark_list);
	virtual bool is_executable() const { return false; }
	size_t visible_count() const;
	IArchitecture *GetArchitectureByType(uint32_t type) const;
	IArchitecture *GetArchitectureByName(const std::string &name) const;
	FolderList *folder_list() const { return folder_list_; }
	MapFunctionBundleList *map_function_list() const { return map_function_list_; }
	FunctionBundleList *function_list() const { return function_list_; }
	virtual uint32_t disable_options() const { return 0; }
	AbstractStream *stream() const { return stream_; }
protected:
	AbstractStream *stream_;
	void CloseStream();
	virtual OpenStatus ReadHeader(uint32_t /*open_mode*/) { return osSuccess; }
private:
	std::string file_name_, file_name_tmp_;
	ILog *log_;
	bool skip_change_notifications_;
	FolderList *folder_list_;
	MapFunctionBundleList *map_function_list_;
	FunctionBundleList *function_list_;

	// no copy ctr or assignment op
	IFile(const IFile &);
	IFile &operator =(const IFile &);
};

class MemoryManager;

class MemoryRegion: public IObject
{
public:
	explicit MemoryRegion(MemoryManager *owner, uint64_t address, size_t size, 
		uint32_t type, IFunction *parent_function);
	~MemoryRegion();
	uint64_t address() const { return address_; }
	uint64_t end_address() const { return end_address_; }
	size_t size() const { return static_cast<size_t>(end_address_ - address_); }
	uint32_t type() const { return type_; }
	IFunction *parent_function() const { return parent_function_; }
	uint64_t Alloc(uint64_t memory_size, uint32_t memory_type);
	
	using IObject::CompareWith;
	int CompareWith(const MemoryRegion &obj) const;
	bool Merge(const MemoryRegion &src);
	MemoryRegion *Subtract(uint64_t remove_address, size_t size);
	void exclude_type(MemoryTypeFlags type) { type_ &= ~type; }
	void set_owner(MemoryManager *owner) { owner_ = owner; }
private:
	MemoryManager *owner_;
	uint64_t address_;
	uint64_t end_address_;
	uint32_t type_;
	IFunction *parent_function_;
};

class MemoryManager : public ObjectList<MemoryRegion>
{
public:
	explicit MemoryManager(IArchitecture *owner);
	uint64_t Alloc(size_t size, uint32_t memory_type, uint64_t address = 0, size_t alignment = 0);
	MemoryRegion *GetRegionByAddress(uint64_t address) const;
	void Add(uint64_t address, size_t size);
	void Add(uint64_t address, size_t size, uint32_t type, IFunction *parent_function = NULL);
	void Remove(uint64_t address, size_t size);
	void Pack();
	IArchitecture *owner() const { return owner_; }
private:
	size_t IndexOfAddress(uint64_t address) const;
	struct CompareHelper {
		bool operator () (const MemoryRegion *region, uint64_t address) const
		{
			return (region->address() < address);
		}

		bool operator () (uint64_t address, const MemoryRegion *region) const
		{
			return (address < region->address());
		}
	};

	IArchitecture *owner_;
};

struct CRCInfo {
	struct POD {
		uint32_t address;
		uint32_t size;
		uint32_t hash;
	} pod;

	CRCInfo() 
	{
		pod.address = 0;
		pod.size = 0;
		pod.hash = 0;
	}

	CRCInfo(uint32_t address_, const std::vector<uint8_t> &dump);
};

class CRCTable
{
public:
	CRCTable(ValueCryptor *cryptor, size_t max_size);
	~CRCTable();
	void Add(uint64_t address, size_t size);
	void Remove(uint64_t address, size_t size);
	size_t WriteToFile(IArchitecture &file, bool is_positions, uint32_t *hash = NULL);
private:
	std::vector<CRCInfo> crc_info_list_;
	MemoryManager *manager_;
	CRCValueCryptor *cryptor_;
	size_t max_size_;

	// no copy ctr or assignment op
	CRCTable(const CRCTable &);
	CRCTable &operator =(const CRCTable &);
};

struct CompileContext {
	CompileOptions options;
	IArchitecture *file;
	IArchitecture *runtime;
	IArchitecture *vm_runtime;
	MemoryManager *manager;
	size_t runtime_var_index[VAR_COUNT];
	size_t runtime_var_salt[VAR_COUNT];
	CompileContext() : file(NULL), runtime(NULL), vm_runtime(NULL), manager(NULL)
	{
		size_t i;
		for (i = 0; i <= VAR_CPU_HASH; i++) {
			runtime_var_index[i] = i;
			runtime_var_salt[i] = static_cast<uint32_t>(rand());
		}
		for (i = 0; i <= VAR_CPU_HASH; i++) {
			std::swap(runtime_var_index[i], runtime_var_index[rand() % (VAR_CPU_HASH + 1)]);
		}
		for (i = 0; i <= VAR_CPU_HASH; i++) {
			if (runtime_var_index[i] > runtime_var_index[VAR_CPU_HASH])
				runtime_var_index[i] += VAR_COUNT - VAR_CPU_HASH - 1;
		}
		for (i = VAR_CPU_HASH + 1; i < VAR_COUNT; i++) {
			runtime_var_index[i] = runtime_var_index[VAR_CPU_HASH] + i - VAR_CPU_HASH;
			runtime_var_salt[i] = runtime_var_salt[VAR_CPU_HASH];
		}
	}
};

class MarkerCommandList;

class MarkerCommand: public IObject
{
public:
	explicit MarkerCommand(MarkerCommandList *owner, uint64_t address, uint64_t operand_address, 
		uint64_t name_reference, uint64_t name_address, ObjectType type);
	explicit MarkerCommand(MarkerCommandList *owner, const MarkerCommand &src);
	~MarkerCommand();
	MarkerCommand *Clone(MarkerCommandList *owner) const;
	uint64_t address() const { return address_; }
	uint64_t operand_address() const { return operand_address_; }
	uint64_t name_address() const { return name_address_; }
	uint64_t name_reference() const { return name_reference_; }
	ObjectType type() const { return type_; }

	using IObject::CompareWith;
	int CompareWith(const MarkerCommand &obj) const;
private:
	MarkerCommandList *owner_;
	uint64_t address_;
	uint64_t operand_address_;
	uint64_t name_address_;
	uint64_t name_reference_;
	ObjectType type_;
};

class MarkerCommandList : public ObjectList<MarkerCommand>
{
public:
	explicit MarkerCommandList();
	explicit MarkerCommandList(const MarkerCommandList &src);
	MarkerCommandList *Clone() const;
	MarkerCommand *Add(uint64_t address, uint64_t operand_address, uint64_t name_reference, 
		uint64_t name_address, ObjectType type = otUnknown);
private:
	// no assignment op
	MarkerCommandList &operator =(const MarkerCommandList &);
};

// CallingConvention -> files/types.h

class IArchitecture : public IObject
{
public:
	virtual std::string name() const = 0;
	virtual uint32_t type() const = 0;
	virtual OperandSize cpu_address_size() const = 0;
	virtual uint64_t entry_point() const = 0;
	virtual uint32_t segment_alignment() const = 0;
	virtual ILoadCommandList *command_list() const = 0;
	virtual ISectionList *segment_list() const = 0;
	virtual ISectionList *section_list() const = 0;
	virtual IImportList *import_list() const = 0;
	virtual IExportList *export_list() const = 0;
	virtual IFixupList *fixup_list() const = 0;
	virtual IRelocationList *relocation_list() const = 0;
	virtual IFunctionList *function_list() const = 0;
	virtual IVirtualMachineList *virtual_machine_list() const = 0;
	virtual IResourceList *resource_list() const = 0;
	virtual ISEHandlerList *seh_handler_list() const = 0;
	virtual std::string map_file_name() const = 0;
	virtual MapFunctionList *map_function_list() const = 0;
	virtual CompilerFunctionList *compiler_function_list() const = 0;
	virtual IRuntimeFunctionList *runtime_function_list() const = 0;
	virtual MarkerCommandList *end_marker_list() const = 0;
	virtual bool visible() const = 0;
	virtual uint8_t ReadByte() = 0;
	virtual uint16_t ReadWord() = 0;
	virtual uint32_t ReadDWord() = 0;
	virtual uint64_t ReadQWord() = 0;
	virtual size_t Read(void *buffer, size_t count) const = 0;
	virtual size_t WriteByte(uint8_t value) = 0;
	virtual size_t WriteWord(uint16_t value) = 0;
	virtual size_t WriteDWord(uint32_t value) = 0;
	virtual size_t WriteQWord(uint64_t value) = 0;
	virtual size_t Write(const void *buffer, size_t count) = 0;
	virtual std::string ReadString() = 0;
	virtual std::string ReadString(uint64_t address) = 0;
	virtual uint64_t Seek(uint64_t position) const = 0;
	virtual uint64_t Tell() const = 0;
	virtual uint64_t AddressTell() = 0;
	virtual uint64_t Resize(uint64_t size) = 0;
	virtual bool AddressSeek(uint64_t address) = 0;
	virtual bool Compile(CompileOptions &options, IArchitecture *runtime) = 0;
	virtual void Save(CompileContext &ctx) = 0;
	virtual IFile *owner() const = 0;
	virtual ISection *selected_segment() const = 0;
	virtual void Notify(MessageType type, IObject *sender, const std::string &message = "") const = 0;
	virtual void StartProgress(const std::string &caption, unsigned long long max) const = 0;
	virtual void StepProgress(unsigned long long value = 1ull) const = 0;
	virtual void EndProgress() const = 0;
	virtual const IArchitecture *source() const = 0;
	virtual uint64_t offset() const = 0;
	virtual uint64_t size() const = 0;
	virtual uint64_t image_base() const = 0;
	virtual CallingConvention calling_convention() const = 0;
	virtual uint64_t CopyFrom(const IArchitecture &src, uint64_t count) = 0;
	virtual void ReadFromBuffer(Buffer &buffer) = 0;
	virtual bool WriteToFile() = 0;
	virtual bool is_executable() const = 0;
	virtual IArchitecture *Clone(IFile *owner) const = 0;
	virtual std::string ANSIToUTF8(const std::string &str) const = 0;
#ifdef CHECKED
	virtual bool check_hash() const = 0;
#endif
};

class BaseArchitecture : public IArchitecture
{
public:
	explicit BaseArchitecture(IFile *owner, uint64_t offset, uint64_t size);
	explicit BaseArchitecture(IFile *owner, const BaseArchitecture &src);
	virtual ~BaseArchitecture();
	virtual MapFunctionList *map_function_list() const { return map_function_list_; }
	virtual CompilerFunctionList *compiler_function_list() const { return compiler_function_list_; }
	virtual MarkerCommandList *end_marker_list() const { return end_marker_list_; }
	virtual std::string map_file_name() const;
	virtual uint8_t ReadByte() { return owner_->ReadByte(); }
	virtual uint16_t ReadWord() { return owner_->ReadWord(); }
	virtual uint32_t ReadDWord() { return owner_->ReadDWord(); }
	virtual uint64_t ReadQWord() { return owner_->ReadQWord(); }
	virtual size_t Read(void *buffer, size_t count) const { return owner_->Read(buffer, count); }
	virtual size_t WriteByte(uint8_t value) { return Write(&value, sizeof(value)); }
	virtual size_t WriteWord(uint16_t value) { return Write(&value, sizeof(value)); }
	virtual size_t WriteDWord(uint32_t value) { return Write(&value, sizeof(value)); }
	virtual size_t WriteQWord(uint64_t value) { return Write(&value, sizeof(value)); }
	virtual size_t Write(const void *buffer, size_t count) { return owner_->Write(buffer, count); }
	virtual std::string ReadString() { return owner_->ReadString(); }
	virtual std::string ReadString(uint64_t address);
	virtual uint64_t Seek(uint64_t position) const;
	virtual uint64_t Tell() const;
	virtual uint64_t Resize(uint64_t size);
	virtual bool AddressSeek(uint64_t address);
	virtual uint64_t AddressTell();
	virtual bool visible() const { return (function_list() != NULL); }
	virtual bool Compile(CompileOptions &options, IArchitecture *runtime);
	virtual IFile *owner() const { return owner_; }
	virtual ISection *selected_segment() const { return selected_segment_; }
	virtual void Notify(MessageType type, IObject *sender, const std::string &message = "") const;
	virtual void StartProgress(const std::string &caption, unsigned long long max) const;
	virtual void StepProgress(unsigned long long value = 1) const;
	virtual void EndProgress() const;
	virtual const IArchitecture *source() const { return source_; }
	virtual uint64_t offset() const { return offset_; }
	virtual uint64_t size() const { return append_mode_ ? owner_->size() - offset_ : size_; }
	virtual void ReadFromBuffer(Buffer &buffer);
	virtual uint64_t CopyFrom(const IArchitecture &src, uint64_t count);
	virtual uint64_t time_stamp() const { return 0; }
	virtual std::string ANSIToUTF8(const std::string &str) const { return str; }
#ifdef CHECKED
	virtual bool check_hash() const;
#endif
protected:
	MemoryManager *memory_manager() const { return memory_manager_; }
	virtual bool Prepare(CompileContext &ctx);
	virtual bool ReadMapFile(IMapFile &map_file);
	void Rebase(uint64_t delta_base);
	void set_append_mode(bool value) { append_mode_ = value; }
private:
	std::string ReadANSIString(uint64_t address);
	std::string ReadUnicodeString(uint64_t address);
	std::string ReadANSIStringWithLength(uint64_t address);
	IFile *owner_;
	const IArchitecture *source_;
	uint64_t offset_;
	uint64_t size_;
	MapFunctionList *map_function_list_;
	CompilerFunctionList *compiler_function_list_;
	MarkerCommandList *end_marker_list_;
	MemoryManager *memory_manager_;
	ISection *selected_segment_;
	bool append_mode_;

	// no copy ctr or assignment op
	BaseArchitecture(const BaseArchitecture &);
	BaseArchitecture &operator =(const BaseArchitecture &);
};

#endif