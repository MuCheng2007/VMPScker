/**
 * Operations with executable files and architecture management.
 */

#ifndef CORE_FILES_ARCHITECTURE_H
#define CORE_FILES_ARCHITECTURE_H

#include <string>
#include <vector>
#include <map>
#include <set>

#include "../../runtime/common.h"
#include "../objects.h"


#include "types.h"
#include "utils.h"


class Watermark;
class WatermarkManager;
class LicensingManager;
class FileManager;

class IArchitecture;
class IFunctionList;
class IFunction;
class ICommand;
class CommandBlock;
class IVirtualMachineList;
class MemoryManager;
class ILoadCommandList;
class ISectionList;
class ISection;
class IImportList;
class IExportList;
class IFixupList;
class IRelocationList;
class IResourceList;
class ISEHandlerList;
class MapFunctionList;
class MapFunctionBundleList;
class CompilerFunctionList;
class IRuntimeFunctionList;
class MarkerCommandList;
class Buffer;
class IMapFile;
class AbstractStream;

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

struct CompileOptions {
	uint32_t flags;
	uint32_t vm_flags;
	uint32_t sdk_flags;
	size_t vm_count;
	std::string section_name;
	std::string messages[MESSAGE_COUNT];
	
	Watermark *watermark;

	IArchitecture **architecture;
	std::string hwid;
	LicensingManager *licensing_manager;
	FileManager *file_manager;

	CompileOptions() : flags(0), vm_flags(0), sdk_flags(0), vm_count(1), watermark(NULL), architecture(NULL)
		, licensing_manager(NULL), file_manager(NULL)
		{}
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

class IFile;

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

class FunctionBundle;
class FunctionBundleList;

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

	BaseArchitecture(const BaseArchitecture &);
	BaseArchitecture &operator =(const BaseArchitecture &);
};

#endif