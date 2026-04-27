#include "SectionCryptor.h"
#include "../../processors.h"
#include "../ir/IntelCommandType.h"
#include "../ir/IntelFunction.h"
#include "../ir/IntelCommand.h"
#include "../../lang.h"

// Copied from intel.cc:
// - SectionCryptor (lines: ~19063 - 19985)
// - SectionCryptorList (lines: ~19986 - 20293)
/**
 * SectionCryptor
 */

SectionCryptor::SectionCryptor(SectionCryptorList* owner, OperandSize cpu_address_size)
	: owner_(owner), parent_cryptor_(NULL)
{
	size_t i;

	registr_order_.push_back(regEFX);
	registr_order_.push_back(regEAX);
	registr_order_.push_back(regECX);
	registr_order_.push_back(regEDX);
	registr_order_.push_back(regEBX);
	registr_order_.push_back(regEBP);
	registr_order_.push_back(regESI);
	registr_order_.push_back(regEDI);
	if (cpu_address_size == osQWord) {
		for (i = 8; i < 16; i++) {
			registr_order_.push_back((uint8_t)i);
		}
	}
	for (i = 0; i < registr_order_.size(); i++) {
		std::swap(registr_order_[i], registr_order_[rand() % registr_order_.size()]);
	}
}

SectionCryptor::~SectionCryptor()
{
	if (owner_)
		owner_->RemoveObject(this);
}

void SectionCryptor::set_end_cryptor(SectionCryptor* cryptor)
{
	if (cryptor == this || cryptor->end_cryptor() == this)
		return;

	if (parent_cryptor_)
		parent_cryptor_->set_end_cryptor(cryptor);
	else
		parent_cryptor_ = cryptor;
}

SectionCryptor* SectionCryptor::end_cryptor()
{
	SectionCryptor* cur_cryptor = this;
	while (cur_cryptor->parent_cryptor_) {
		cur_cryptor = cur_cryptor->parent_cryptor_;
	}
	return cur_cryptor;
}

/**
 * SectionCryptorList
 */

SectionCryptorList::SectionCryptorList(IFunction* owner)
	: ObjectList<SectionCryptor>(), owner_(owner)
{

}

SectionCryptor* SectionCryptorList::Add()
{
	SectionCryptor* section_cryptor = new SectionCryptor(this, owner_->cpu_address_size());
	AddObject(section_cryptor);
	return section_cryptor;
}