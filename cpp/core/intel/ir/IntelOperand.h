#ifndef INTEL_OPERAND_H
#define INTEL_OPERAND_H

#include "IntelCommandType.h"
#include "../../processors.h"
#include "../../objects.h"

class IFixup;
class IRelocation;

struct IntelOperand {
	uint64_t value;
	IFixup *fixup;
	IRelocation *relocation;
	uint16_t type;
	OperandSize size;
	uint8_t registr;
	uint8_t base_registr;
	uint8_t scale_registr;
	uint8_t value_pos;
	OperandSize address_size;
	OperandSize value_size;
	bool show_size;
	bool is_large_value;

	IntelOperand() 
	{ 
		Clear();
	}

	void Clear() 
	{
		type = otNone;
		fixup = NULL;
		relocation = NULL;
		registr = 0;
		base_registr = 0;
		scale_registr = 0;
		size = osDefault;
		value_size = address_size = osDefault;
		value_pos = 0;
		value = 0;
		show_size = false;
		is_large_value = false;
	}

	IntelSegment effective_base_segment(IntelSegment base_segment) const
	{
		if (base_segment == segDefault && 
				(((type & otBaseRegistr) && (base_registr == regESP || base_registr == regEBP)) ||
				((type & otRegistr) && (registr == regESP || registr == regEBP)))) {
				return segSS;
		} else {
			return (base_segment == segDefault) ? segDS : base_segment;
		}
	}

	IntelOperand(uint32_t type_, OperandSize size_, uint8_t registr_ = 0, uint64_t value_ = 0, IFixup *fixup_ = NULL);

	uint64_t encode() const
	{
		uint64_t res = static_cast<uint64_t>(type) << 48;
		if (type & (otRegistr | otSegmentRegistr | otControlRegistr | otDebugRegistr | otFPURegistr | otHiPartRegistr | otMMXRegistr | otXMMRegistr))
			res |= static_cast<uint64_t>(registr) << 44;
		if (type & otBaseRegistr)
			res |= static_cast<uint64_t>(base_registr) << 40;
		if (type & otValue)
			res |= static_cast<uint32_t>(value);
		return res;
	}

	void decode(uint64_t value_)
	{
		type = (value_ >> 48) & 0xffff;
		if (type & (otRegistr | otSegmentRegistr | otControlRegistr | otDebugRegistr | otFPURegistr | otHiPartRegistr | otMMXRegistr | otXMMRegistr))
			registr = (value_ >> 44) & 0xf;
		if (type & otBaseRegistr)
			base_registr = (value_ >> 40) & 0xf;
		if (type & otValue)
			value = static_cast<uint32_t>(value_);
	}

	bool operator == (const IntelOperand &operand) const
	{
		if (type != operand.type)
			return false;
		if (type & (otRegistr | otSegmentRegistr | otControlRegistr | otDebugRegistr | otFPURegistr | otHiPartRegistr | otMMXRegistr | otXMMRegistr)) {
			if (registr != operand.registr)
				return false;
		}
		if ((type & (otMemory | otRegistr)) == (otMemory | otRegistr)) {
			if (scale_registr != operand.scale_registr)
				return false;
		}
		if (type & otBaseRegistr) {
			if (base_registr != operand.base_registr)
				return false;
		}
		if (type & otValue) {
			if (value != operand.value)
				return false;
		}
		return true;
	}

	bool operator != (const IntelOperand &operand) const
	{
		return !(operator == (operand));
	}
};

#endif // INTEL_OPERAND_H