/**
 * Processors function classes.
 * BaseFunction, BaseFunctionList
 */

#ifndef PROC_FUNCTION_H
#define PROC_FUNCTION_H

#include "proc_types.h"
#include "proc_interfaces.h"
#include "../files/types.h"
#include "../files/architecture.h"

class IFunctionList;
class ICommandList;
class CommandBlockList;
class InternalLinkList;
class ExtCommandList;

/**
 * Base implementation of function
 */
class BaseFunction : public IFunction
{
public:
	explicit BaseFunction(IFunctionList *owner, const FunctionName &name, CompilationType compilation_type, uint32_t compilation_options, bool need_compile, Folder *folder);
	explicit BaseFunction(IFunctionList *owner, OperandSize cpu_address_size, IFunction *parent);
	explicit BaseFunction(IFunctionList *owner, const BaseFunction &source);
	virtual ~BaseFunction();
	virtual void RemoveObject(ICommand *obj);
	virtual void clear();
	virtual uint64_t address() const { return address_; }
	virtual ObjectType type() const { return type_; }
	virtual EntryType entry_type() const { return entry_type_; }
	virtual void set_entry_type(EntryType entry_type) { entry_type_ = entry_type; }
	virtual ICommand *entry() const { return entry_; }
	virtual std::string name() const { return name_.name(); }
	virtual std::string display_name() const { return name_.display_name(); }
	virtual FunctionName full_name() const { return name_; }
	virtual OperandSize cpu_address_size() const { return cpu_address_size_; }
	virtual CommandLinkList *link_list() const { return link_list_; }
	virtual ExtCommandList *ext_command_list() const { return ext_command_list_; }
	virtual CommandBlockList *block_list() const { return block_list_; }
	virtual bool need_compile() const { return need_compile_; }
	virtual CompilationType compilation_type() const { return (default_compilation_type_ == ctNone) ? compilation_type_ : default_compilation_type_; }
	virtual CompilationType default_compilation_type() const { return default_compilation_type_; }
	virtual uint32_t compilation_options() const { return compilation_options_ | (internal_lock_to_key_ ? coLockToKey : 0); }
	virtual Folder *folder() const { return folder_; }
	virtual uint32_t memory_type() const { return memory_type_; }
	virtual void set_memory_type(uint32_t memory_type) { memory_type_ = memory_type; }
	virtual uint8_t tag() const { return tag_; }
	virtual void set_compilation_type(CompilationType compilation_type);
	virtual void set_compilation_options(uint32_t compilation_options);
	virtual void set_need_compile(bool need_compile);
	virtual void set_folder(Folder *folder);
	virtual void set_tag(uint8_t tag) { tag_ = tag; }
	virtual bool from_runtime() const { return from_runtime_; }
	virtual void set_from_runtime(bool from_runtime) { from_runtime_ = from_runtime; }
	virtual size_t ReadFromFile(IArchitecture &file, uint64_t address);
	virtual size_t WriteToFile(IArchitecture &file);
	virtual ICommand *GetCommandByAddress(uint64_t address) const;
	virtual ICommand *GetCommandByNearAddress(uint64_t address) const;
	virtual bool Init(const CompileContext &ctx);
	virtual bool Prepare(const CompileContext &ctx);
	virtual bool PrepareExtCommands(const CompileContext &ctx);
	virtual bool PrepareLinks(const CompileContext &ctx);
	virtual bool Compile(const CompileContext &ctx);
	virtual void AfterCompile(const CompileContext &ctx);
	virtual void CompileLinks(const CompileContext &ctx);
	virtual void CompileInfo(const CompileContext &ctx);
	virtual void ReadFromBuffer(Buffer &buffer, IArchitecture &file);
	virtual void Rebase(uint64_t delta_base);
	bool FreeByManager(const CompileContext &ctx);
	virtual IFunctionList *owner() const { return owner_; }
	virtual uint64_t break_address() const { return break_address_; }
	virtual void set_break_address(uint64_t break_address);
	virtual bool is_breaked_address(uint64_t address) const { return break_address_ ? address >= break_address_ : false; }
	virtual IFunction *parent() const { return parent_; }
	virtual CommandBlock *AddBlock(size_t start_index, bool is_executable = false);
	virtual void Notify(MessageType type, IObject *sender, const std::string &message = "") const;
	virtual FunctionInfo *range_list() const { return range_list_; }
	virtual FunctionInfoList *function_info_list() const { return function_info_list_; }
	virtual std::string display_address(const std::string &arch_name) const;
	virtual Data hash() const;
	virtual IVirtualMachine *virtual_machine(IVirtualMachineList *virtual_machine_list, ICommand *command) const;
	virtual void AddObject(ICommand *command);
#ifdef CHECKED
	virtual bool check_hash() const;
#endif
protected:
	virtual ICommand *ParseString(IArchitecture & /*file*/, uint64_t /*address*/, size_t /*len*/) { return NULL; }
	virtual void ParseBeginCommands(IArchitecture & /*file*/) { return; }
	virtual void ParseEndCommands(IArchitecture & /*file*/) { return; }
	void set_entry(ICommand *entry) { entry_ = entry; }
	ICommand *GetCommandByLowerAddress(uint64_t address) const;
	ICommand *GetCommandByUpperAddress(uint64_t address) const;
	virtual uint64_t GetNextAddress(IArchitecture &file);
	virtual IFunction *CreateFunction(IFunction *parent = NULL) = 0;
	void ClearItems();
private:
	typedef std::map<uint64_t, ICommand *> map_command_list_t;

	map_command_list_t map_;
	FunctionName name_;
	IFunction *parent_;

	uint64_t address_;
	uint64_t break_address_;

	IFunctionList *owner_;
	CommandLinkList *link_list_;
	ExtCommandList *ext_command_list_;
	CommandBlockList *block_list_;
	Folder *folder_;
	ICommand *entry_;
	FunctionInfo *range_list_;
	FunctionInfoList *function_info_list_;

	uint32_t compilation_options_;
	uint32_t memory_type_;

	ObjectType type_;
	OperandSize cpu_address_size_;
	CompilationType compilation_type_;
	CompilationType default_compilation_type_;
	uint8_t tag_;
	EntryType entry_type_;
	bool from_runtime_;
	bool internal_lock_to_key_;
	bool need_compile_;

	// no copy ctr or assignment op
	BaseFunction(const BaseFunction &);
	BaseFunction &operator =(const BaseFunction &);
};

/**
 * Base implementation of function list
 */
class BaseFunctionList : public IFunctionList
{
public:
	explicit BaseFunctionList(IArchitecture *owner);
	explicit BaseFunctionList(IArchitecture *owner, const BaseFunctionList &src);
	virtual IFunction *GetFunctionByAddress(uint64_t address) const;
	virtual IFunction *GetFunctionByName(const std::string &name) const;
	virtual IFunction *GetUnknownByName(const std::string &name) const;
	virtual ICommand *GetCommandByAddress(uint64_t address, bool need_compile) const;
	virtual ICommand *GetCommandByNearAddress(uint64_t address, bool need_compile) const;
	virtual IFunction *AddUnknown(const std::string &name, CompilationType compilation_type, uint32_t compilation_options, bool need_compile, Folder *folder);
	virtual IFunction *AddByAddress(uint64_t address, CompilationType compilation_type, uint32_t compilation_options, bool need_compile, Folder *folder);
	virtual bool Prepare(const CompileContext &ctx);
	virtual bool Compile(const CompileContext &ctx);
	virtual void CompileLinks(const CompileContext &ctx);
	virtual void CompileInfo(const CompileContext &ctx);
	virtual void ReadFromBuffer(Buffer &buffer, IArchitecture &file);
	virtual void Rebase(uint64_t delta_base);
	virtual IArchitecture *owner() const { return owner_; }
	virtual void RemoveObject(IFunction *func);
	virtual void Notify(MessageType type, IObject *sender, const std::string &message = "") const;
	virtual std::vector<IFunction *> processor_list() const;
#ifdef CHECKED
	virtual bool check_hash() const;
#endif
private:
	IArchitecture *owner_;
};

#endif // PROC_FUNCTION_H
