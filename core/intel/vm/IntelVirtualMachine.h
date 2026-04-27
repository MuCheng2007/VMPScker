#ifndef INTEL_VIRTUAL_MACHINE_H
#define INTEL_VIRTUAL_MACHINE_H

#include "../ir/IntelCommandType.h"
#include "../ir/IntelOpcodeInfo.h"
#include "../ir/IntelMisc.h"
#include "../ir/IntelFunction.h"
#include "../../processors.h"
#include <unordered_map>

class IntelVirtualMachineList;
class IntelVirtualMachineProcessor;
class IntelVMCommand;
class CommandBlock;
class ValueCommand;

class IntelVirtualMachine : public BaseVirtualMachine
{
public:
	IntelVirtualMachine(IntelVirtualMachineList *owner, VirtualMachineType type, uint8_t id, IntelVirtualMachineProcessor *processor);
	~IntelVirtualMachine();
	void Init(const CompileContext &ctx, const IntelOpcodeList &visible_opcode_list);
	void Prepare(const CompileContext &ctx);
	ByteList *registr_order() { return &registr_order_; }
	virtual bool backward_direction() const { return backward_direction_; }
	void CompileCommand(IntelVMCommand &vm_command);
	void CompileBlock(CommandBlock &block, bool need_encrypt);
	void AddExtJmpCommand(uint8_t id);
	ValueCryptor *entry_cryptor() const { return &const_cast<ValueCryptor &>(entry_cryptor_); }
	VirtualMachineType type() const { return type_; }
	IntelCommand *entry_command() const { return entry_command_; }
	IntelCommand *init_command() const { return init_command_; }
	virtual IntelFunction *processor() const;
private:
	IntelCommand *AddReadCommand(OperandSize size, OpcodeCryptor *command_cryptor, uint8_t registr);
	void AddValueCommand(ValueCommand &value_command, bool is_decrypt, uint8_t registr);
	void AddEndHandlerCommands(IntelCommand *to_command, OpcodeCryptor *command_cryptor);
	IntelCommand *CloneHandler(IntelCommand *handler);
	void InitCommands(const CompileContext &ctx, const IntelOpcodeList &visible_opcode_list);
	void AddCallCommands(CallingConvention calling_convention, IntelCommand *call_entry, uint8_t registr);
	IntelOpcodeInfo *GetOpcode(IntelCommandType command_type, OperandType operand_type, OperandSize size, uint8_t value);
	bool IsRegistrUsed(uint8_t registr);
	std::vector<OpcodeCryptor *> GetOpcodeCryptorList(IntelVMCommand *command);
	VirtualMachineType type_; 
	IntelVirtualMachineProcessor *processor_;
	IntelRegistrList registr_list_;
	IntelOpcodeList opcode_list_;
	std::unordered_map<uint64_t, IntelOpcodeInfo::circular_queue> opcode_stack_;
	ByteList registr_order_;
	ValueCryptor entry_cryptor_;
	OpcodeCryptor *command_cryptor_;
	std::vector<OpcodeCryptor *> cryptor_list_;
	IntelCommand *entry_command_;
	IntelCommand *init_command_;
	IntelCommand *ext_jmp_command_;
	bool backward_direction_;
	std::vector<IntelCommand *> vm_links_;
	uint8_t stack_registr_;
	uint8_t pcode_registr_;
	uint8_t jmp_registr_;
	uint8_t crypt_registr_;
	IntelRegistrList free_registr_list_;
	
	// no copy ctr or assignment op
	IntelVirtualMachine(const IntelVirtualMachine &);
	IntelVirtualMachine &operator =(const IntelVirtualMachine &);
};

#endif // INTEL_VIRTUAL_MACHINE_H