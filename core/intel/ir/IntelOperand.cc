#include "IntelOperand.h"
#include "../../files.h"
#include "../../osutils.h"
#include "../../../runtime/crypto.h"

// Copied from intel.cc: IntelOperand implementation
// Line range: ~48 (constructor)

IntelOperand::IntelOperand(uint32_t type_, OperandSize size_, uint8_t registr_ /*= 0*/, uint64_t value_ /*= 0*/, IFixup *fixup_ /*= NULL*/)
{
	Clear();

	if (type_ == (otMemory | otRegistr) && registr_ == regEBP) {
		type_ = otMemory | otBaseRegistr | otValue;
		registr_ <<= 4;
	}

	type = type_;
	size = size_;
	registr = registr_ & 0x0f;
	base_registr = (registr_ & 0xf0) >> 4;
	value = value_;
	if (fixup_ == LARGE_VALUE) {
		is_large_value = true;
		value_size = osDWord;
	} else if (fixup_) {
		fixup = fixup_;
		value_size = (fixup == NEED_FIXUP) ? size_ : fixup->size();
	} else if ((type & (otMemory | otValue)) == (otMemory | otValue) && (type & (otRegistr | otBaseRegistr))) {
		value_size = (ByteToInt64(static_cast<uint8_t>(value)) == value) ? osByte : osDWord;
	} else {
		value_size = size_;
	}
}
