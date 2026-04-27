/**
 * Processors interfaces.
 */

#ifndef PROC_INTERFACES_H
#define PROC_INTERFACES_H

#include "proc_types.h"

// Type definitions
typedef std::vector<uint8_t> ByteList;

// Forward declarations
class IVMCommand;
class ICommand;
class ICommandList;
class IFunction;
class IFunctionList;
class IVirtualMachine;
class IVirtualMachineList;
class CommandBlock;
class CommandBlockList;
class InternalLink;
class InternalLinkList;
class ExtCommand;
class ExtCommandList;
class CommandLink;
class CommandLinkList;
class CommandInfo;
class CommandInfoList;
class AddressRange;
class ISEHandler;
struct CompileContext;

/**
 * VM Command Interface
 */
class IVMCommand : public IObject
{
public:
	virtual void WriteToFile(IArchitecture &file) = 0;
	virtual void Compile() = 0;
	virtual size_t dump_size() const = 0;
	virtual void set_address(uint64_t address) = 0;
	virtual uint64_t address() const = 0;
	virtual ICommand *owner() const = 0;
	virtual bool is_end() const = 0;
};

/**
 * Command Interface
 */
class ICommand : public ObjectList<IVMCommand>
{
public:
	virtual uint64_t address() const = 0;
	virtual uint64_t next_address() const = 0;
	virtual CommandType type() const = 0;
	virtual std::string text() const = 0;
	virtual CommentInfo comment() = 0;
	virtual void set_comment(const CommentInfo &value) = 0;
	virtual uint32_t options() const = 0;
	virtual CommandLink *link() const = 0;
	virtual void set_link(CommandLink *link) = 0;
	virtual uint8_t dump(size_t index) const = 0;
	virtual size_t dump_size() const = 0;
	virtual std::string dump_str() const = 0;
	virtual size_t original_dump_size() const = 0;
	virtual size_t vm_dump_size() const = 0;
	virtual void clear() = 0;
	virtual void CompileToNative() = 0;
	virtual void CompileLink(const CompileContext &ctx) = 0;
	virtual void PrepareLink(const CompileContext &ctx) = 0;
	virtual void CompileInfo() = 0;
	virtual void set_operand_value(size_t operand_index, uint64_t value) = 0;
	virtual void set_link_value(size_t link_index, uint64_t value) = 0;
	virtual void set_jmp_value(size_t link_index, uint64_t value) = 0;
	virtual void set_address(uint64_t address) = 0;
	virtual uint64_t vm_address() const = 0;
	virtual uint64_t ext_vm_address() const = 0;
	virtual void set_vm_address(uint64_t address) = 0;
	virtual void WriteToFile(IArchitecture &file) = 0;
	virtual void ReadFromBuffer(Buffer &buffer, IArchitecture &file) = 0;
	virtual size_t alignment() const = 0;
	virtual CommandBlock *block() const = 0;
	virtual void set_block(CommandBlock *block) = 0;
	virtual void Rebase(uint64_t delta_base) = 0;
	virtual IFunction *owner() const = 0;
	virtual ICommand *Clone(IFunction *owner) const = 0;
	virtual CommandLink *AddLink(int operand_index, LinkType type, ICommand *to_command) = 0;
	virtual CommandLink *AddLink(int operand_index, LinkType type, uint64_t to_address = 0) = 0;
	virtual void include_section_option(SectionOption option) = 0;
	virtual uint32_t section_options() const = 0;
	virtual ISEHandler *seh_handler() const = 0;
	virtual AddressRange *address_range() const = 0;
	virtual void set_address_range(AddressRange *address_range) = 0;
	virtual bool Merge(ICommand *command) = 0;
	virtual bool is_data() const = 0;
	virtual bool is_end() const = 0;
	virtual void include_option(CommandOption value) = 0;
	virtual void exclude_option(CommandOption value) = 0;
	virtual std::string display_address() const = 0;
	virtual void set_tag(uint8_t tag) = 0;
	virtual uint8_t tag() const = 0;

	using IObject::CompareWith;
	int CompareWith(const ICommand &obj) const
	{
		if (address() < obj.address())
			return -1;
		if (address() > obj.address())
			return 1;
		return 0;
	}
#ifdef CHECKED
	virtual bool check_hash() const = 0;
#endif
};

/**
 * Function Interface
 */
class IFunction : public ObjectList<ICommand>
{
public:
	virtual uint64_t address() const = 0;
	virtual uint64_t break_address() const = 0;
	virtual ObjectType type() const = 0;
	virtual EntryType entry_type() const = 0;
	virtual ICommand *entry() const = 0;
	virtual std::string name() const = 0;
	virtual std::string display_name() const = 0;
	virtual FunctionName full_name() const = 0;
	virtual OperandSize cpu_address_size() const = 0;
	virtual CommandLinkList *link_list() const = 0;
	virtual ExtCommandList *ext_command_list() const = 0;
	virtual CommandBlockList *block_list() const = 0;
	virtual bool need_compile() const = 0;
	virtual CompilationType compilation_type() const = 0;
	virtual CompilationType default_compilation_type() const = 0;
	virtual uint32_t compilation_options() const = 0;
	virtual Folder *folder() const = 0;
	virtual void set_break_address(uint64_t break_address) = 0;
	virtual bool is_breaked_address(uint64_t address) const = 0;
	virtual void set_compilation_type(CompilationType compilation_type) = 0;
	virtual void set_compilation_options(uint32_t compilation_options) = 0;
	virtual void set_need_compile(bool need_compile) = 0;
	virtual void set_folder(Folder *folder) = 0;
	virtual void set_tag(uint8_t tag) = 0;
	virtual bool from_runtime() const = 0;
	virtual void set_from_runtime(bool from_runtime) = 0;
	virtual IFunction *Clone(IFunctionList *owner) const = 0;
	virtual size_t ReadFromFile(IArchitecture &file, uint64_t address) = 0;
	virtual size_t WriteToFile(IArchitecture &file) = 0;
	virtual bool Init(const CompileContext &ctx) = 0;
	virtual bool Prepare(const CompileContext &ctx) = 0;
	virtual bool PrepareExtCommands(const CompileContext &ctx) = 0;
	virtual bool PrepareLinks(const CompileContext &ctx) = 0;
	virtual bool Compile(const CompileContext &ctx) = 0;
	virtual void AfterCompile(const CompileContext &ctx) = 0;
	virtual void CompileLinks(const CompileContext &ctx) = 0;
	virtual void CompileInfo(const CompileContext &ctx) = 0;
	virtual ICommand *GetCommandByAddress(uint64_t address) const = 0;
	virtual ICommand *GetCommandByNearAddress(uint64_t address) const = 0;
	virtual void ReadFromBuffer(Buffer &buffer, IArchitecture &file) = 0;
	virtual uint8_t tag() const = 0;
	virtual void Rebase(uint64_t delta_base) = 0;
	virtual uint32_t memory_type() const = 0;
	virtual void set_memory_type(uint32_t memory_type) = 0;
	virtual ICommand *ParseCommand(IArchitecture &file, uint64_t address, bool dump_mode = false) = 0;
	virtual IFunctionList *owner() const = 0;
	virtual IFunction *parent() const = 0;
	virtual void Notify(MessageType type, IObject *sender, const std::string &message = "") const = 0;
	virtual CommandBlock *AddBlock(size_t start_index, bool is_executable = false) = 0;
	virtual ICommand *AddCommand(const Data &value) = 0;
	virtual ICommand *AddCommand(OperandSize value_size, uint64_t value) = 0;
	virtual std::string display_address(const std::string &arch_name) const = 0;
	virtual Data hash() const = 0;
	virtual FunctionInfoList *function_info_list() const = 0;
#ifdef CHECKED
	virtual bool check_hash() const = 0;
#endif
protected:
	virtual ICommand *CreateCommand() = 0;
};

/**
 * Function List Interface
 */
class IFunctionList : public ObjectList<IFunction>
{
public:
	virtual IFunction *Add(const std::string &name, CompilationType compilation_type, uint32_t compilation_options, bool need_compile, Folder *folder) = 0;
	virtual IFunction *GetFunctionByAddress(uint64_t address) const = 0;
	virtual IFunction *GetFunctionByName(const std::string &name) const = 0;
	virtual IFunction *GetUnknownByName(const std::string &name) const = 0;
	virtual ICommand *GetCommandByAddress(uint64_t address, bool need_compile) const = 0;
	virtual ICommand *GetCommandByNearAddress(uint64_t address, bool need_compile) const = 0;
	virtual IFunction *AddUnknown(const std::string &name, CompilationType compilation_type, uint32_t compilation_options, bool need_compile, Folder *folder) = 0;
	virtual IFunction *AddByAddress(uint64_t address, CompilationType compilation_type, uint32_t compilation_options, bool need_compile, Folder *folder) = 0;
	virtual IFunctionList *Clone(IArchitecture *owner) const = 0;
	virtual bool Prepare(const CompileContext &ctx) = 0;
	virtual bool Compile(const CompileContext &ctx) = 0;
	virtual void CompileLinks(const CompileContext &ctx) = 0;
	virtual void ReadFromBuffer(Buffer &buffer, IArchitecture &file) = 0;
	virtual IFunction *crc_table() const = 0;
	virtual ValueCryptor *crc_cryptor() const = 0;
	virtual void Rebase(uint64_t delta_base) = 0;
	virtual IFunction *CreateFunction(OperandSize cpu_address_size = osDefault) = 0;
	virtual IArchitecture *owner() const = 0;
	virtual void Notify(MessageType type, IObject *sender, const std::string &message = "") const = 0;
	virtual bool GetRuntimeOptions() const = 0;
	virtual std::vector<IFunction *> processor_list() const = 0;
#ifdef CHECKED
	virtual bool check_hash() const = 0;
#endif
};

/**
 * Virtual Machine Interface
 */
class IVirtualMachine : public IObject
{
public:
	virtual uint8_t id() const = 0;
	virtual ByteList *registr_order() = 0;
	virtual bool backward_direction() const = 0;
	virtual IFunction *processor() const = 0;
};

/**
 * Virtual Machine List Interface
 */
class IVirtualMachineList : public ObjectList<IVirtualMachine>
{
public:
	virtual IVirtualMachineList *Clone() const = 0;
	virtual void Prepare(const CompileContext &ctx) = 0;
};

#endif // PROC_INTERFACES_H
