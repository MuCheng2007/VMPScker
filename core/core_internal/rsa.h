#ifndef RSA_H
#define RSA_H

#include "../../runtime/common.h"
#include "../../runtime/crypto.h"

class Data;

class RSA {
public:
	RSA();
	RSA(const std::vector<uint8_t> &public_exp, const std::vector<uint8_t> &private_exp, const std::vector<uint8_t> &modulus);
	~RSA();
	bool Encrypt(Data &data);
	bool Decrypt(Data &data);
	bool CreateKeyPair(size_t key_length);
	std::vector<uint8_t> public_exp() const;
	std::vector<uint8_t> private_exp() const;
	std::vector<uint8_t> modulus() const;
private:
	BigNumber *private_exp_;
	BigNumber *public_exp_;
	BigNumber *modulus_;

	// no copy ctr or assignment op
	RSA(const RSA &);
	RSA &operator =(const RSA &);
};

#endif
