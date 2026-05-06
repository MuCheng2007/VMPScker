#include "proc_crypto.h"
#include "../../runtime/crypto.h"
#include <intrin.h>
#include <stdexcept>


/**
 * ValueCommand
 */

ValueCommand::ValueCommand(ValueCryptor* owner, OperandSize size, CryptCommandType type, uint64_t value)
	: IObject(), owner_(owner), type_(type), size_(size)
{
	switch (size_) {
	case osByte:
		value_ = static_cast<uint8_t>(value);
		break;
	case osWord:
		value_ = static_cast<uint16_t>(value);
		break;
	case osDWord:
		value_ = static_cast<uint32_t>(value);
		break;
	default:
		value_ = value;
	}
}

ValueCommand::ValueCommand(ValueCryptor* owner, const ValueCommand& src)
	: IObject(), owner_(owner)
{
	size_ = src.size_;
	type_ = src.type_;
	value_ = src.value_;
}

ValueCommand* ValueCommand::Clone(ValueCryptor* owner) const
{
	ValueCommand* command = new ValueCommand(owner, *this);
	return command;
}

ValueCommand::~ValueCommand()
{
	if (owner_)
		owner_->RemoveObject(this);
}

CryptCommandType ValueCommand::type(bool is_decrypt) const
{
	CryptCommandType command = type_;
	if (is_decrypt) {
		switch (command) {
		case ccAdd:
			command = ccSub;
			break;
		case ccSub:
			command = ccAdd;
			break;
		case ccInc:
			command = ccDec;
			break;
		case ccDec:
			command = ccInc;
			break;
		case ccRol:
			command = ccRor;
			break;
		case ccRor:
			command = ccRol;
			break;
		}
	}
	return command;
}

uint64_t ValueCommand::Encrypt(uint64_t value)
{
	return Calc(value, false);
}

uint64_t ValueCommand::Decrypt(uint64_t value)
{
	return Calc(value, true);
}

uint64_t ValueCommand::Calc(uint64_t value, bool is_decrypt)
{
	switch (type(is_decrypt)) {
	case ccAdd: case ccInc:
		value += value_;
		break;
	case ccSub: case ccDec:
		value -= value_;
		break;
	case ccXor:
		value ^= value_;
		break;
	case ccNot:
		value = ~value;
		break;
	case ccNeg:
		value = 0 - value;
		break;
	case ccBswap:
		switch (size_) {
		case osWord:
			value = __builtin_bswap16(static_cast<uint16_t>(value));
			break;
		case osDWord:
			value = __builtin_bswap32(static_cast<uint32_t>(value));
			break;
		case osQWord:
			value = __builtin_bswap64(value);
			break;
		}
		break;
	case ccRol:
		switch (size_) {
		case osByte:
			value = _rotl8(static_cast<uint8_t>(value), static_cast<int>(value_));
			break;
		case osWord:
			value = _rotl16(static_cast<uint16_t>(value), static_cast<int>(value_));
			break;
		case osDWord:
			value = _rotl32(static_cast<uint32_t>(value), static_cast<int>(value_));
			break;
		case osQWord:
			value = _rotl64(value, static_cast<int>(value_));
			break;
		}
		break;
	case ccRor:
		switch (size_) {
		case osByte:
			value = _rotr8(static_cast<uint8_t>(value), static_cast<int>(value_));
			break;
		case osWord:
			value = _rotr16(static_cast<uint16_t>(value), static_cast<int>(value_));
			break;
		case osDWord:
			value = _rotr32(static_cast<uint32_t>(value), static_cast<int>(value_));
			break;
		case osQWord:
			value = _rotr64(value, static_cast<int>(value_));
			break;
		}
		break;
	}

	return value;
}

/**
 * ValueCryptor
 */

ValueCryptor::ValueCryptor()
	: ObjectList<ValueCommand>(), size_(osByte)
{

}

ValueCryptor::ValueCryptor(const ValueCryptor& src)
	: ObjectList<ValueCommand>(src)
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
	size_ = src.size_;
}

ValueCryptor* ValueCryptor::Clone() const
{
	ValueCryptor* cryptor = new ValueCryptor(*this);
	return cryptor;
}

uint64_t ValueCryptor::Encrypt(uint64_t value)
{
	size_t i;
	for (i = 0; i < count(); i++) {
		value = item(i)->Encrypt(value);
	}
	return value;
}

uint64_t ValueCryptor::Decrypt(uint64_t value)
{
	size_t i;
	for (i = count(); i > 0; i--) {
		value = item(i - 1)->Decrypt(value);
	}
	return value;
}

void ValueCryptor::Init(OperandSize size)
{
	clear();

	size_ = size;
	CryptCommandType last_command = ccUnknown;
	for (;;) {
		CryptCommandType command = static_cast<CryptCommandType>(rand() % ccUnknown);
		if (command == last_command)
			continue;

		uint64_t value = 0;
		switch (command) {
		case ccAdd: case ccSub:
			if (last_command == ccAdd || last_command == ccSub || last_command == ccInc || last_command == ccDec)
				continue;
			value = DWordToInt64(rand32());
			break;
		case ccInc: case ccDec:
			if (last_command == ccAdd || last_command == ccSub || last_command == ccInc || last_command == ccDec)
				continue;
			value = 1;
			break;
		case ccXor:
			value = DWordToInt64(rand32());
			break;
		case ccBswap:
			if (size_ == osByte || size_ == osWord)
				continue;
			break;
		case ccRol: case ccRor:
			if (last_command == ccRol || last_command == ccRor)
				continue;

			value = rand() % BYTES_TO_BITS(OperandSizeToValue(size_));
			if (!value)
				value = 1;
			break;
		}
		last_command = command;

		Add(command, value);

		size_t c = count();
		if (c > 100 || (c > 3 && (rand() & 1)))
			break;
	}
}

void ValueCryptor::Add(CryptCommandType command, uint64_t value)
{
	AddObject(new ValueCommand(this, size_, command, value));
}

/**
 * OpcodeCryptor
 */

OpcodeCryptor::OpcodeCryptor()
	: ValueCryptor(), type_(ccUnknown)
{

}

void OpcodeCryptor::Init(OperandSize size)
{
	//static CryptCommandType opcode_commands[] = {ccAdd, ccSub, ccXor};
	//type_ = opcode_commands[rand() % _countof(opcode_commands)];
	type_ = ccXor;
	ValueCryptor::Init(size);
}

uint64_t OpcodeCryptor::EncryptOpcode(uint64_t value1, uint64_t value2)
{
	return Calc(value1, value2, false);
}

uint64_t OpcodeCryptor::DecryptOpcode(uint64_t value1, uint64_t value2)
{
	return Calc(value1, value2, true);
}

uint64_t OpcodeCryptor::Calc(uint64_t value1, uint64_t value2, bool is_decrypt)
{
	CryptCommandType command = type_;
	if (is_decrypt) {
		switch (command) {
		case ccAdd:
			command = ccSub;
			break;
		case ccSub:
			command = ccAdd;
			break;
		}
	}

	switch (command) {
	case ccAdd:
		return value1 + value2;
	case ccSub:
		return value1 - value2;
	case ccXor:
		return value1 ^ value2;
	}

	return 0;
}