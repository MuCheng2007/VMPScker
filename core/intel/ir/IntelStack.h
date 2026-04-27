#ifndef INTEL_STACK_H
#define INTEL_STACK_H

#include "../../processors.h"
#include "IntelCommandType.h"

class IntelStack;
class IntelFlagsValue;

enum ValueType {
	vtNone = 0,
	vtValue = 1,
	vtRegistr = 2,
	vtReturnAddress = 4
};

class IntelStackValue : public IObject
{
public:
	IntelStackValue(IntelStack *owner, ValueType type, uint64_t value);
	~IntelStackValue();
	ValueType type() const { return type_; }
	uint64_t value() const { return value_; }
	void set_value(uint64_t value) { value_ = value; }
	bool is_modified() const { return is_modified_; }
	void set_is_modified(bool value) { is_modified_ = value; }
	void Calc(IntelCommandType command_type, uint16_t command_flags, bool inverse_flags, OperandSize size, uint64_t op2, IntelFlagsValue *flags);
private:
	IntelStack *owner_;
	ValueType type_;
	uint64_t value_;
	bool is_modified_;
};

class IntelStack : public ObjectList<IntelStackValue>
{
public:
	IntelStack();
	IntelStackValue *Add(ValueType type, uint64_t value);
	IntelStackValue *Insert(size_t index, ValueType type, uint64_t value);
	IntelStackValue *GetRegistr(uint8_t reg) const;
	IntelStackValue *GetRandom(uint32_t types);
};

class IntelRegistrValue : public IntelStackValue
{
public:
	IntelRegistrValue(IntelStack *owner, uint8_t registr, uint64_t value)
		: IntelStackValue(owner, vtValue, value), registr_(registr) { }
	uint8_t registr() const { return registr_; }
private:
	uint8_t registr_;
};

class IntelFlagsValue : public IObject
{
public:
	IntelFlagsValue();
	uint32_t mask() const { return mask_; }
	uint32_t value() const { return value_; }
	void Calc(IntelCommandType command_type, OperandSize size, uint64_t op1, uint64_t op2, uint64_t result);
	uint16_t GetRandom() const;
	bool Check(uint16_t flags) const;
	void clear() {
		mask_ = 0;
		value_ = 0;
	}
private:
	void exclude(uint16_t mask);

	uint32_t mask_;
	uint32_t value_;
};

class IntelRegistrStorage : public IntelStack
{
public:
	IntelRegistrStorage();
	IntelRegistrValue *item(size_t index) const;
	IntelRegistrValue *GetRegistr(uint8_t reg) const;
	IntelRegistrValue *Add(uint8_t reg, uint64_t value);
};

#endif // INTEL_STACK_H