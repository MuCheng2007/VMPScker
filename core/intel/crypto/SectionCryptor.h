#ifndef SECTION_CRYPTOR_H
#define SECTION_CRYPTOR_H

#include "../../processors.h"

typedef std::vector<uint8_t> ByteList;

class SectionCryptorList;

class SectionCryptor : public IObject
{
public:
	explicit SectionCryptor(SectionCryptorList *owner, OperandSize cpu_address_size);
	~SectionCryptor();
	ByteList *registr_order() { return &registr_order_; }
	SectionCryptor *end_cryptor();
	void set_end_cryptor(SectionCryptor *cryptor);
private:
	SectionCryptorList *owner_;
	ByteList registr_order_;
	SectionCryptor *parent_cryptor_;
};

class SectionCryptorList : public ObjectList<SectionCryptor>
{
public:
	explicit SectionCryptorList(IFunction *owner);
	SectionCryptor *Add();
private:
	IFunction *owner_;
};

#endif // SECTION_CRYPTOR_H