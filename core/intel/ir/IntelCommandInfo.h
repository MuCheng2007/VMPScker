#ifndef INTEL_COMMAND_INFO_H
#define INTEL_COMMAND_INFO_H

#include "../../processors.h"
#include "IntelOperand.h"

class IntelCommandInfoList : public CommandInfoList
{
public:
	explicit IntelCommandInfoList(OperandSize cpu_address_size);
	virtual void Add(AccessType access_type, uint8_t value, OperandType operand_type, OperandSize size);
	void AddOperand(const IntelOperand &operand, AccessType access_type);
	void set_base_segment(IntelSegment base_segment) { base_segment_ = base_segment; }
private:
	OperandSize cpu_address_size_;
	IntelSegment base_segment_;
};

#endif // INTEL_COMMAND_INFO_H