#include "IntelStack.h"
#include "../../files/utils.h"
#include "../../files/architecture.h"
#include "../../processors.h"
#include "../../osutils.h"
#include "../../../runtime/crypto.h"

// Copied from intel.cc:
// - IntelStackValue (lines: ~16494 - 16724)
// - IntelFlagsValue (lines: ~16725 - 16996)
// - IntelStack (lines: ~16997 - 17045)
// - IntelRegistrStorage (lines: ~17046 - 17082)


/**
* IntelStackValue
*/

IntelStackValue::IntelStackValue(IntelStack* owner, ValueType type, uint64_t value)
	: IObject(), owner_(owner), type_(type), value_(value), is_modified_(false)
{

}

IntelStackValue::~IntelStackValue()
{
	if (owner_)
		owner_->RemoveObject(this);
}

void IntelStackValue::Calc(IntelCommandType command_type, uint16_t command_flags, bool inverse_flags, OperandSize size, uint64_t op2, IntelFlagsValue* flags)
{
	if (type_ != vtValue)
		throw std::runtime_error("Runtime error at Calc");

	uint64_t op1 = value_;
	uint64_t result;
	switch (command_type) {
	case cmAdd:
		result = op1 + op2;
		break;
	case cmAdc:
		result = op1 + op2 + ((flags->value() & fl_C) ? 1 : 0);
		break;
	case cmCmp:
	case cmSub:
		result = op1 - op2;
		break;
	case cmSbb:
		result = op1 - op2 - ((flags->value() & fl_C) ? 1 : 0);
		break;
	case cmTest:
	case cmAnd:
		result = op1 & op2;
		break;
	case cmOr:
		result = op1 | op2;
		break;
	case cmXor:
		result = op1 ^ op2;
		break;
	case cmSetXX:
		result = flags->Check(command_flags) ? 1 : 0;
		if (inverse_flags)
			result = result ? 0 : 1;
		break;
	case cmCmov:
		if (flags->Check(command_flags) != (inverse_flags == false))
			return;

		result = op2;
		break;
	case cmShr:
		op2 &= (size == osQWord) ? 0x3f : 0x1f;
		if (!op2)
			return;

		switch (size) {
		case osByte:
			result = static_cast<uint8_t>(op1) >> op2;
			break;
		case osWord:
			result = static_cast<uint16_t>(op1) >> op2;
			break;
		case osDWord:
			result = static_cast<uint32_t>(op1) >> op2;
			break;
		default:
			result = op1 >> op2;
			break;
		}
		break;
	case cmSar:
		op2 &= (size == osQWord) ? 0x3f : 0x1f;
		if (!op2)
			return;

		switch (size) {
		case osByte:
			result = static_cast<int8_t>(op1) >> op2;
			break;
		case osWord:
			result = static_cast<int16_t>(op1) >> op2;
			break;
		case osDWord:
			result = static_cast<int32_t>(op1) >> op2;
			break;
		default:
			result = static_cast<int64_t>(op1) >> op2;
			break;
		}
		break;
	case cmShl:
	case cmSal:
		op2 &= (size == osQWord) ? 0x3f : 0x1f;
		if (!op2)
			return;

		switch (size) {
		case osByte:
			result = static_cast<uint8_t>(op1) << op2;
			break;
		case osWord:
			result = static_cast<uint16_t>(op1) << op2;
			break;
		case osDWord:
			result = static_cast<uint32_t>(op1) << op2;
			break;
		default:
			result = op1 << op2;
			break;
		}
		break;
	case cmRol:
		op2 &= (size == osQWord) ? 0x3f : 0x1f;
		if (!op2)
			return;

		switch (size) {
		case osByte:
			result = _rotl8(static_cast<uint8_t>(op1), static_cast<uint8_t>(op2));
			break;
		case osWord:
			result = _rotl16(static_cast<uint16_t>(op1), static_cast<uint8_t>(op2));
			break;
		case osDWord:
			result = _rotl32(static_cast<uint32_t>(op1), static_cast<uint8_t>(op2));
			break;
		default:
			result = _rotl64(op1, static_cast<uint8_t>(op2));
			break;
		}
		break;
	case cmRor:
		op2 &= (size == osQWord) ? 0x3f : 0x1f;
		if (!op2)
			return;

		switch (size) {
		case osByte:
			result = _rotr8(static_cast<uint8_t>(op1), static_cast<uint8_t>(op2));
			break;
		case osWord:
			result = _rotr16(static_cast<uint16_t>(op1), static_cast<uint8_t>(op2));
			break;
		case osDWord:
			result = _rotr32(static_cast<uint32_t>(op1), static_cast<uint8_t>(op2));
			break;
		default:
			result = _rotr64(op1, static_cast<uint8_t>(op2));
			break;
		}
		break;
	case cmMov:
	case cmLea:
	case cmMovsx:
	case cmMovsxd:
	case cmMovzx:
		result = op2;
		break;
	case cmCbw:
		result = static_cast<int64_t>(static_cast<int8_t>(op2));
		break;
	case cmCwde:
		result = static_cast<int64_t>(static_cast<int16_t>(op2));
		break;
	case cmCdqe:
		result = static_cast<int64_t>(static_cast<int32_t>(op2));
		break;
	case cmCwd:
		result = (static_cast<int16_t>(op2) < 0) ? (uint64_t)-1 : 0;
		break;
	case cmCdq:
		result = (static_cast<int32_t>(op2) < 0) ? (uint64_t)-1 : 0;
		break;
	case cmCqo:
		result = (static_cast<int64_t>(op2) < 0) ? (uint64_t)-1 : 0;
		break;
	case cmNot:
		result = ~op1;
		break;
	case cmNeg:
		result = 0 - op1;
		break;
	case cmBt:
		op2 &= (OperandSizeToValue(size) * 8 - 1);
		result = op1;
		break;
	case cmBtr:
		op2 &= (OperandSizeToValue(size) * 8 - 1);
		result = op1 & ~((uint64_t)1 << op2);
		break;
	case cmBtc:
		op2 &= (OperandSizeToValue(size) * 8 - 1);
		result = op1 ^ ((uint64_t)1 << op2);
		break;
	case cmBts:
		op2 &= (OperandSizeToValue(size) * 8 - 1);
		result = op1 | ((uint64_t)1 << op2);
		break;
	case cmBswap:
		switch (size) {
		case osDWord:
			result = __builtin_bswap32(static_cast<uint32_t>(op1));
			break;
		case osQWord:
			result = __builtin_bswap64(op1);
			break;
		default:
			throw std::runtime_error("Runtime error at Calc");
		}
		break;
	default:
		throw std::runtime_error("Runtime error at Calc");
	}

	if (flags)
		flags->Calc(command_type, size, op1, op2, result);

	if (command_type == cmCmp || command_type == cmTest || command_type == cmBt)
		return;

	memcpy(&value_, &result, OperandSizeToValue(size));
}

/**
* IntelFlagsValue
*/

IntelFlagsValue::IntelFlagsValue()
	: IObject(), mask_(0), value_(0)
{

}

uint16_t IntelFlagsValue::GetRandom() const
{
	std::vector<uint16_t> list;

	if (mask_ & fl_Z)
		list.push_back(fl_Z);
	if (mask_ & fl_S)
		list.push_back(fl_S);
	if (mask_ & fl_C)
		list.push_back(fl_C);
	if (mask_ & fl_O)
		list.push_back(fl_O);
	if ((mask_ & (fl_C | fl_Z)) == (fl_C | fl_Z))
		list.push_back(fl_C | fl_Z);
	if ((mask_ & (fl_S | fl_O)) == (fl_S | fl_O))
		list.push_back(fl_S | fl_O);
	if ((mask_ & (fl_Z | fl_S | fl_O)) == (fl_Z | fl_S | fl_O))
		list.push_back(fl_Z | fl_S | fl_O);

	return list.empty() ? 0 : list[rand() % list.size()];
}

bool IntelFlagsValue::Check(uint16_t flags) const
{
	bool s, z, o;

	switch (flags) {
	case (fl_S | fl_O):
		s = (value_ & fl_S) != 0;
		o = (value_ & fl_O) != 0;
		return s != o;
	case (fl_Z | fl_S | fl_O):
		z = (value_ & fl_Z) != 0;
		s = (value_ & fl_S) != 0;
		o = (value_ & fl_O) != 0;
		return z || (s != o);
	default:
		return (value_ & flags) != 0;
	}
}

void IntelFlagsValue::exclude(uint16_t mask)
{
	mask_ &= ~mask;
	value_ &= ~mask;
}

void IntelFlagsValue::Calc(IntelCommandType command_type, OperandSize size, uint64_t op1, uint64_t op2, uint64_t result)
{
	uint64_t tmp;
	uint64_t sign_mask = (uint64_t)1 << (OperandSizeToValue(size) * 8 - 1);
	uint64_t value_mask = sign_mask | (sign_mask - 1);
	uint16_t prev_value = value_;

	switch (command_type) {
	case cmAdd:
	case cmAdc:
		exclude(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		mask_ |= fl_C;
		if (command_type == cmAdc && (prev_value & fl_C)) {
			if ((result & value_mask) <= (op1 & value_mask))
				value_ |= fl_C;
		}
		else {
			if ((result & value_mask) < (op1 & value_mask))
				value_ |= fl_C;
		}

		mask_ |= fl_O;
		if ((~(op1 ^ op2) & (op2 ^ result)) & sign_mask)
			value_ |= fl_O;
		break;
	case cmCmp:
	case cmSub:
	case cmSbb:
		exclude(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		mask_ |= fl_C;
		if (command_type == cmSbb && (prev_value & fl_C)) {
			if ((op1 & value_mask) <= (result & value_mask))
				value_ |= fl_C;
		}
		else {
			if ((op1 & value_mask) < (op2 & value_mask))
				value_ |= fl_C;
		}

		mask_ |= fl_O;
		if (((op1 ^ op2) & (op1 ^ result)) & sign_mask)
			value_ |= fl_O;
		break;
	case cmNeg:
		exclude(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		mask_ |= fl_C;
		if (result & value_mask)
			value_ |= fl_C;

		mask_ |= fl_O;
		if ((result & value_mask) == sign_mask)
			value_ |= fl_O;
		break;
	case cmOr:
	case cmXor:
	case cmAnd:
	case cmTest:
		exclude(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		mask_ |= fl_C;
		mask_ |= fl_O;
		break;
	case cmShr:
		exclude(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		switch (size) {
		case osByte:
			tmp = static_cast<uint8_t>(op1) >> (op2 - 1);
			break;
		case osWord:
			tmp = static_cast<uint16_t>(op1) >> (op2 - 1);
			break;
		case osDWord:
			tmp = static_cast<uint32_t>(op1) >> (op2 - 1);
			break;
		default:
			tmp = op1 >> (op2 - 1);
			break;
		}
		mask_ |= fl_C;
		if (tmp & 1)
			value_ |= fl_C;

		if (op2 == 1) {
			mask_ |= fl_O;
			if (op1 & sign_mask)
				value_ |= fl_O;
		}
		break;

	case cmSar:
		exclude(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		switch (size) {
		case osByte:
			tmp = static_cast<int8_t>(op1) >> (op2 - 1);
			break;
		case osWord:
			tmp = static_cast<int16_t>(op1) >> (op2 - 1);
			break;
		case osDWord:
			tmp = static_cast<int32_t>(op1) >> (op2 - 1);
			break;
		default:
			tmp = op1 >> (op2 - 1);
			break;
		}
		mask_ |= fl_C;
		if (tmp & 1)
			value_ |= fl_C;

		if (op2 == 1)
			mask_ |= fl_O;
		break;

	case cmShl:
	case cmSal:
		exclude(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		switch (size) {
		case osByte:
			tmp = static_cast<uint8_t>(op1) << (op2 - 1);
			break;
		case osWord:
			tmp = static_cast<uint16_t>(op1) << (op2 - 1);
			break;
		case osDWord:
			tmp = static_cast<uint32_t>(op1) << (op2 - 1);
			break;
		default:
			tmp = op1 << (op2 - 1);
			break;
		}
		mask_ |= fl_C;
		if (tmp & sign_mask)
			value_ |= fl_C;

		if (op2 == 1) {
			mask_ |= fl_O;
			if (((result & sign_mask) != 0) != ((value_ & fl_C) != 0))
				value_ |= fl_O;
		}
		break;


	case cmRcl:
	case cmRcr:
		exclude(fl_O | fl_C);

		// TODO
		return;
	case cmRol:
		exclude(fl_O | fl_C);

		mask_ |= fl_C;
		if (result & 1)
			value_ |= fl_C;

		if (op2 == 1) {
			mask_ |= fl_O;
			if (((result & sign_mask) != 0) != ((value_ & fl_C) != 0))
				value_ |= fl_O;
		}
		return;
	case cmRor:
		exclude(fl_O | fl_C);

		mask_ |= fl_C;
		if (result & sign_mask)
			value_ |= fl_C;

		if (op2 == 1) {
			mask_ |= fl_O;
			if (((result & sign_mask) != 0) != (((result << 1) & sign_mask) != 0))
				value_ |= fl_O;
		}
		return;
	case cmStc:
		mask_ |= fl_C;
		value_ |= fl_C;
		return;
	case cmClc:
		mask_ |= fl_C;
		value_ &= ~fl_C;
		return;
	case cmCmc:
		if (mask_ & fl_C)
			value_ ^= fl_C;
		return;
	case cmBt:
	case cmBtr:
	case cmBtc:
	case cmBts:
		exclude(fl_O | fl_S | fl_A | fl_P | fl_C); // fl_Z is unaffected

		mask_ |= fl_C;
		if ((op1 >> op2) & 1)
			value_ |= fl_C;
		return;
	default:
		return;
	}

	mask_ |= fl_Z;
	if ((result & value_mask) == 0)
		value_ |= fl_Z;

	mask_ |= fl_S;
	if (result & sign_mask)
		value_ |= fl_S;
}

/**
* IntelStack
*/

IntelStack::IntelStack()
	: ObjectList<IntelStackValue>()
{

}

IntelStackValue* IntelStack::Add(ValueType type, uint64_t value)
{
	IntelStackValue* res = new IntelStackValue(this, type, value);
	AddObject(res);
	return res;
};

IntelStackValue* IntelStack::Insert(size_t index, ValueType type, uint64_t value)
{
	IntelStackValue* res = new IntelStackValue(this, type, value);
	InsertObject(index, res);
	return res;
}

IntelStackValue* IntelStack::GetRegistr(uint8_t reg) const
{
	for (size_t i = 0; i < count(); i++) {
		IntelStackValue* res = item(i);
		if (res->type() == vtRegistr && res->value() == reg)
			return res;
	}
	return NULL;
}

IntelStackValue* IntelStack::GetRandom(uint32_t types)
{
	std::vector<IntelStackValue*> list;
	for (size_t i = 0; i < count(); i++) {
		IntelStackValue* stack_item = item(i);
		if (stack_item->type() & types) {
			if (stack_item->type() == vtRegistr && (stack_item->value() == regEFX || stack_item->value() == regEmpty))
				continue;

			list.push_back(stack_item);
		}
	}
	return list.empty() ? NULL : list[rand() % list.size()];
}


/**
* IntelRegistrStorage
*/

IntelRegistrStorage::IntelRegistrStorage()
	: IntelStack()
{

}

IntelRegistrValue* IntelRegistrStorage::item(size_t index) const
{
	return reinterpret_cast<IntelRegistrValue*>(IntelStack::item(index));
}

IntelRegistrValue* IntelRegistrStorage::GetRegistr(uint8_t reg) const
{
	for (size_t i = 0; i < count(); i++) {
		IntelRegistrValue* res = item(i);
		if (res->registr() == reg)
			return res;
	}
	return NULL;
};

IntelRegistrValue* IntelRegistrStorage::Add(uint8_t reg, uint64_t value)
{
	IntelRegistrValue* res = GetRegistr(reg);
	if (res)
		res->set_value(value);
	else {
		res = new IntelRegistrValue(this, reg, value);
		AddObject(res);
	}
	return res;
}
