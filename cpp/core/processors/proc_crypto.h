/**
 * Processors crypto classes.
 * ValueCommand, ValueCryptor, OpcodeCryptor
 */

#ifndef PROC_CRYPTO_H
#define PROC_CRYPTO_H

#include "proc_types.h"
#include "proc_interfaces.h"

class ValueCryptor;

/**
 * Value encryption command
 */
class ValueCommand : public IObject
{
public:
	explicit ValueCommand(ValueCryptor *owner, OperandSize size, CryptCommandType type, uint64_t value);
	explicit ValueCommand(ValueCryptor *owner, const ValueCommand &src);
	~ValueCommand();
	ValueCommand *Clone(ValueCryptor *owner) const;
	CryptCommandType type(bool is_decrypt = false) const;
	uint64_t Encrypt(uint64_t value);
	uint64_t Decrypt(uint64_t value);
	uint64_t value() const { return value_; }
	OperandSize size() const { return size_; }
private:
	uint64_t value_;
	ValueCryptor *owner_;
	uint64_t Calc(uint64_t value, bool is_decrypt);
	CryptCommandType type_;
	OperandSize size_;
};

/**
 * Value encryptor/decryptor
 */
class ValueCryptor : public ObjectList<ValueCommand>
{
public:
	ValueCryptor();
	ValueCryptor(const ValueCryptor &src);
	ValueCryptor *Clone() const;
	virtual void Init(OperandSize size);
	uint64_t Encrypt(uint64_t value);
	uint64_t Decrypt(uint64_t value);
	OperandSize size() const { return size_; }
	void set_size(OperandSize size) { size_ = size; }
	void Add(CryptCommandType command, uint64_t value);
private:
	OperandSize size_;
	// no assignment op
	ValueCryptor &operator =(const ValueCryptor &);
};

/**
 * Opcode encryptor/decryptor
 */
class OpcodeCryptor : public ValueCryptor
{
public:
	OpcodeCryptor();
	virtual void Init(OperandSize size);
	uint64_t EncryptOpcode(uint64_t value1, uint64_t value2);
	uint64_t DecryptOpcode(uint64_t value1, uint64_t value2);
	CryptCommandType type() const { return type_; }
private:
	uint64_t Calc(uint64_t value1, uint64_t value2, bool is_decrypt);
	CryptCommandType type_;
};

#endif // PROC_CRYPTO_H
