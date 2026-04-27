#include "IntelCommandInfo.h"
#include "IntelCommand.h"

/*
 * IntelCommandInfoList
 */

IntelCommandInfoList::IntelCommandInfoList(OperandSize cpu_address_size)
	: CommandInfoList(), cpu_address_size_(cpu_address_size), base_segment_(segDefault)
{

}

void IntelCommandInfoList::Add(AccessType access_type, uint8_t value, OperandType operand_type, OperandSize size)
{
	CommandInfoList::Add(access_type, value, operand_type, (cpu_address_size_ == osQWord && access_type == atWrite && operand_type == otRegistr && size == osDWord) ? osQWord : size);
}

void IntelCommandInfoList::AddOperand(const IntelOperand& operand, AccessType access_type)
{
	static const OperandType operand_types[] = {
		otValue,
		otRegistr,
		otMemory,
		otSegmentRegistr,
		otControlRegistr,
		otDebugRegistr,
		otFPURegistr,
		otHiPartRegistr,
		otBaseRegistr,
		otMMXRegistr,
		otXMMRegistr
	};

	for (size_t i = 0; i < _countof(operand_types); i++) {
		OperandType ot = operand_types[i];
		if ((operand.type & ot) == 0)
			continue;

		switch (ot) { //-V719
		case otRegistr:
		case otSegmentRegistr:
		case otControlRegistr:
		case otDebugRegistr:
		case otMMXRegistr:
		case otXMMRegistr:
			if (operand.type & otMemory) {
				Add(atRead, operand.registr, ot, operand.address_size);
			}
			else {
				Add(access_type, operand.registr, ot, operand.size);
			}
			break;

		case otHiPartRegistr:
			Add(access_type, operand.registr, ot, operand.size);
			break;

		case otBaseRegistr:
			if (operand.type & otMemory) {
				Add(atRead, operand.base_registr, otRegistr, operand.address_size);
			}
			else {
				Add(access_type, operand.base_registr, otRegistr, operand.size);
			}
			break;

		case otFPURegistr:
			Add(access_type, 0, ot, operand.size);
			break;

		case otMemory:
			Add(access_type, operand.effective_base_segment(base_segment_), ot, operand.size);
			break;
		}
	}
}
