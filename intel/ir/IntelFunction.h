#ifndef INTEL_FUNCTION_H
#define INTEL_FUNCTION_H

#include "../../processors.h"
#include "../../files/types.h"
#include "../../files/markers.h"
#include "IntelCommandType.h"
#include "IntelCommand.h"
#include <set>

class IArchitecture;
class IFunctionList;
class Folder;
class ISEHandler;
class Buffer;
class AddressRange;
class CompilerFunction;
struct CompileContext;

enum ReadMarkerOption {
	moNone,
	moNeedParam = 0x1,
	moForward = 0x2,
	moSkipLastCall = 0x4
};

class IntelFunction : public BaseFunction
{
public:
	explicit IntelFunction(IFunctionList *owner, const std::string &name, CompilationType compilation_type, uint32_t compilation_options, bool need_compile, Folder *folder);
	explicit IntelFunction(IFunctionList *owner = NULL);
	explicit IntelFunction(IFunctionList *owner, OperandSize cpu_address_size, IFunction *parent = NULL);
	explicit IntelFunction(IFunctionList *owner, const IntelFunction &src);
	virtual ~IntelFunction();
	virtual void clear();
	virtual IntelFunction *Clone(IFunctionList *owner) const;
	IntelCommand *item(size_t index) const { return reinterpret_cast<IntelCommand *>(IFunction::item(index)); }
	IntelCommand *ReadValidCommand(IArchitecture &file, uint64_t address);
	void ReadMarkerCommands(IArchitecture &file, MarkerCommandList &command_list, uint64_t address, uint32_t options);
	virtual bool Compile(const CompileContext &ctx);
	virtual void AfterCompile(const CompileContext &ctx);
	virtual void CompileLinks(const CompileContext &ctx);
	virtual bool Init(const CompileContext &ctx);
	virtual bool Prepare(const CompileContext &ctx);
	virtual bool PrepareExtCommands(const CompileContext &ctx);
	virtual void CompileInfo(const CompileContext &ctx);
	IntelCommand *AddCommand(OperandSize value_size, uint64_t value);
	IntelCommand *AddCommand(const std::string &value);
	IntelCommand *AddCommand(const os::unicode_string &value);
	IntelCommand *AddCommand(const Data &value);
	IntelCommand *Add(uint64_t address);
	IntelCommand *AddCommand(IntelCommandType type, IntelOperand operand1 = IntelOperand(), IntelOperand operand2 = IntelOperand(), IntelOperand operand3 = IntelOperand());
	SectionCryptorList *section_cryptor_list() { return section_cryptor_list_; }
	IntelCommand *GetCommandByAddress(uint64_t address) const;
	IntelCommand *GetCommandByNearAddress(uint64_t address) const;
	virtual void ReadFromBuffer(Buffer &buffer, IArchitecture &file);
	bool ParseNewSEH(IArchitecture &file, uint64_t address);
	bool ParseCxxSEH(IArchitecture &file, uint64_t address);
	bool ParseCompressedCxxSEH(IArchitecture &file, uint64_t address, uint64_t begin);
	bool ParseScopeSEH(IArchitecture &file, uint64_t address, uint32_t table_count);
	virtual IntelCommand *ParseCommand(IArchitecture &file, uint64_t address, bool dump_mode = false);
	uint64_t ParseParam(IArchitecture &file, size_t index, uint64_t &param_reference);
protected:
	virtual IntelCommand *CreateCommand();
	virtual IntelCommand *ParseString(IArchitecture &file, uint64_t address, size_t len);
	virtual void ParseBeginCommands(IArchitecture &file);
	virtual void ParseEndCommands(IArchitecture &file);
	virtual uint64_t GetNextAddress(IArchitecture &file);
	virtual IntelFunction *CreateFunction(IFunction *parent = NULL) { return new IntelFunction(NULL, cpu_address_size(), parent); }
	void CompileToNative(const CompileContext &ctx);
	void CompileToVM(const CompileContext &ctx);
	void CreateBlocks();
private:
	bool ParseFilterSEH(IArchitecture &file, uint64_t address);
	bool ParseSwitch(IArchitecture &file, uint64_t address, OperandSize value_size, uint64_t add_value, IntelCommand *parent_command, size_t mode, size_t max_table_count);
	bool ParseSEH3(IArchitecture &file, uint64_t address);
	bool ParseSEH4(IArchitecture &file, uint64_t address);
	bool ParseVB6SEH(IArchitecture &file, uint64_t address);
	bool ParseBCBSEH(IArchitecture &file, uint64_t address, uint64_t next_address, uint8_t version);
	bool ParseDelphiSEH(IArchitecture &file, uint64_t address);
	CompilerFunction *ParseCompilerFunction(IArchitecture &file, uint64_t address);
	IntelCommand *AddGate(ICommand *to_command, AddressRange *address_range);
	IntelCommand *AddShortGate(ICommand *to_command, AddressRange *address_range);

	uint64_t GetRegistrValue(uint8_t reg, size_t end_index);
	uint64_t GetRegistrMaxValue(uint8_t reg, size_t end_index, IArchitecture &file);
	void GetFreeRegisters(size_t index, CommandInfoList &command_info_list) const;
	void Mutate(const CompileContext &ctx, bool for_virtualization);

	SectionCryptorList *section_cryptor_list_;
	std::set<uint64_t> break_case_list_;

	// no copy ctr or assignment op
	IntelFunction(const IntelFunction &);
	IntelFunction &operator =(const IntelFunction &);
};

#endif // INTEL_FUNCTION_H