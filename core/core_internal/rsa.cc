#include "rsa.h"

#include "../objects.h"

RSA::RSA()
{
	private_exp_ = new BigNumber();
	public_exp_ = new BigNumber();
	modulus_ = new BigNumber();
}

RSA::RSA(const std::vector<uint8_t> &public_exp, const std::vector<uint8_t> &private_exp, const std::vector<uint8_t> &modulus)
{
	private_exp_ = new BigNumber(private_exp.data(), private_exp.size());
	public_exp_ = new BigNumber(public_exp.data(), public_exp.size());
	modulus_ = new BigNumber(modulus.data(), modulus.size());
}

RSA::~RSA()
{
	delete private_exp_;
	delete public_exp_;
	delete modulus_;
}

bool RSA::Encrypt(Data &data)
{
	if (!private_exp_->size() || !modulus_->size())
		return false;

	BigNumber x(data.data(), data.size());
	if (*modulus_ < x)
		return false;

	BigNumber y = x.modpow(*private_exp_, *modulus_);
	size_t len = y.size();
	data.resize(len);
	for (size_t i = 0; i < len; i++) {
		data[i] = y[len - 1 - i];
	}

	return true;
}

bool RSA::Decrypt(Data &data)
{
	if (!public_exp_->size() || !modulus_->size())
		return false;

	BigNumber x(data.data(), data.size());
	if (*modulus_ < x)
		return false;

	BigNumber y = x.modpow(*public_exp_, *modulus_);
	size_t len = y.size();
	data.resize(len);
	for (size_t i = 0; i < len; i++) {
		data[i] = y[len - 1 - i];
	}

	return true;
}

static std::vector<uint8_t> bignum_to_vector(const BigNumber &value)
{
	std::vector<uint8_t> res;
	size_t len = value.size();
	res.resize(len);
	for (size_t i = 0; i < len; i++) {
		res[i] = value[len - 1 - i];
	}
	return res;
}

std::vector<uint8_t> RSA::public_exp() const
{
	return bignum_to_vector(*public_exp_);
}

std::vector<uint8_t> RSA::private_exp() const
{
	return bignum_to_vector(*private_exp_);
}

std::vector<uint8_t> RSA::modulus() const
{
	return bignum_to_vector(*modulus_);
}



bool RSA::CreateKeyPair(size_t key_length)
{
	bool res = false;
	struct {LPCWSTR name; DWORD type;} providers[] =  // structure of providers names and types. we'll try them one by one until they end or we'll find one that works
	{
		{MS_STRONG_PROV, PROV_RSA_FULL},
		{NULL, PROV_RSA_FULL},
		{NULL, PROV_RSA_SCHANNEL},
		{NULL, PROV_RSA_AES},
	};


	for (size_t i = 0; i < _countof(providers) && !res; i++) {
		HCRYPTPROV prov;
		if (CryptAcquireContext(&prov, NULL, providers[i].name, providers[i].type, CRYPT_VERIFYCONTEXT)) {
			HCRYPTKEY key;
			if (CryptGenKey(prov, CALG_RSA_KEYX, MAKELONG(CRYPT_EXPORTABLE, key_length), &key)) {
				DWORD len = (DWORD)(key_length * 2);
				uint8_t *data = new uint8_t[len];
				memset(data, 0, len);
				if (CryptExportKey(key, NULL, PRIVATEKEYBLOB, 0, data, &len)) {
					BLOBHEADER *header = reinterpret_cast<BLOBHEADER *>(data);
					if ((header->aiKeyAlg & ALG_TYPE_RSA) == ALG_TYPE_RSA) {
						RSAPUBKEY *rsa_key = reinterpret_cast<RSAPUBKEY *>(data + sizeof(BLOBHEADER));
						if (rsa_key->magic == 0x32415352 && rsa_key->bitlen == key_length) {
							// RSA2

							delete private_exp_;
							delete public_exp_;
							delete modulus_;

							int bytes_in_key = rsa_key->bitlen / 8;
							public_exp_ = new BigNumber(reinterpret_cast<uint8_t *>(&rsa_key->pubexp), 4, true);
							private_exp_ = new BigNumber(data + len - bytes_in_key, bytes_in_key, true);
							modulus_ = new BigNumber(data + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY), bytes_in_key, true);

							res = true;
						}
					}
				}
				delete [] data;
			}
		}
	}

	return res;
}
