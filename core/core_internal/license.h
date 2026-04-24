#ifndef LICENSE_H
#define LICENSE_H

#include "../../runtime/common.h"
#include "../objects.h"
#include "rsa.h"

enum Algorithm {
	alNone,
	alRSA
};

enum SerialNumberFlags {
	HAS_USER_NAME		= 0x0001,
	HAS_EMAIL			= 0x0002,
	HAS_EXP_DATE		= 0x0004,
	HAS_MAX_BUILD_DATE	= 0x0008,
	HAS_TIME_LIMIT		= 0x0010,
	HAS_HARDWARE_ID		= 0x0020,
	HAS_USER_DATA		= 0x0040,
	SN_FLAGS_PADDING	= 0xFFFF
};

struct LicenseDate {
	uint16_t Year;
	uint8_t Month;
	uint8_t Day;
	LicenseDate(uint32_t value = 0)
	{
		Day = value & 0xff;
		Month = (value >> 8) & 0xff;	
		Year = (value >> 16) & 0xffff;	
	};
	LicenseDate(uint16_t year, uint8_t month, uint8_t day)
		: Year(year), Month(month), Day(day) {};
	uint32_t value() const { return (Year << 16) | (Month << 8) | Day; }
};

struct LicenseInfo {
	uint32_t Flags;
	std::string CustomerName;
	std::string CustomerEmail;
	LicenseDate ExpireDate;
	std::string HWID;
	uint8_t RunningTimeLimit;
	LicenseDate MaxBuildDate;
	std::string UserData;
	LicenseInfo() : Flags(0), RunningTimeLimit(0) {}
};

class Core;
class LicensingManager;

class License : public IObject
{
public:
	explicit License(LicensingManager *owner, LicenseDate date, const std::string &customer_name, const std::string &customer_email, const std::string &order_ref, 
		const std::string &comments, const std::string &serial_number, bool blocked);
	~License();
	std::string customer_name() const { return customer_name_; }
	std::string customer_email() const { return customer_email_; }
	std::string order_ref() const { return order_ref_; }
	std::string comments() const { return comments_; }
	std::string serial_number() const { return serial_number_; }
	bool blocked() const { return blocked_; }
	void GetHash(uint8_t hash[20]);
	LicenseDate date() const { return date_; }
	void set_customer_name(const std::string &value);
	void set_customer_email(const std::string &value);
	void set_order_ref(const std::string &value);
	void set_date(LicenseDate value);
	void set_comments(const std::string &value);
	void set_blocked( bool value);
	LicenseInfo *info();
	void Notify(MessageType type, IObject *sender, const std::string &message = "") const;
private:
	LicensingManager *owner_;
	LicenseDate date_;
	std::string customer_name_;
	std::string customer_email_;
	std::string order_ref_;
	std::string comments_;
	std::string serial_number_;
	bool blocked_;
	LicenseInfo *info_;

	// no copy ctr or assignment op
	License(const License &);
	License &operator =(const License &);
};

class LicensingManager : public ObjectList<License>
{
public:
	explicit LicensingManager(Core *owner = NULL);
	virtual bool GetLicenseData(Data &data) const;
	virtual void clear();
	bool Open(const std::string &file_name);
	bool Save();
	bool SaveAs(const std::string &file_name);
	bool empty() const { return algorithm_ == alNone; }
	uint64_t product_code() const;
	bool Init(size_t key_len);
	Algorithm algorithm() const { return algorithm_; }
	uint16_t bits() const { return bits_; }
	std::vector<uint8_t> public_exp() const { return public_exp_; }
	std::vector<uint8_t> private_exp() const { return private_exp_; }
	std::vector<uint8_t> modulus() const { return modulus_; }
	std::vector<uint8_t> hash() const;
	std::string activation_server() const { return activation_server_; }
	void set_activation_server(const std::string &activation_server) { activation_server_ = activation_server; }
	void set_build_date(uint32_t build_date) { build_date_ = build_date; }
	std::string GenerateSerialNumber(const LicenseInfo &license_info);
	bool DecryptSerialNumber(const std::string &serial_number, LicenseInfo &license_info);
	License *Add(LicenseDate date, const std::string &customer_name, const std::string &customer_email, const std::string &order_ref, 
		const std::string &comments, const std::string &serial_number, bool blocked);
	License *GetLicenseBySerialNumber(const std::string &serial_number);
	bool CompareParameters(const LicensingManager &manager) const;
	virtual void Notify(MessageType type, IObject *sender, const std::string &message = "") const;
	virtual void AddObject(License *license);
	virtual void RemoveObject(License *license);
private:
	void changed();
	Core *owner_;
	std::string file_name_;
	Algorithm algorithm_;
	uint16_t bits_;
	std::vector<uint8_t> public_exp_;
	std::vector<uint8_t> private_exp_;
	std::vector<uint8_t> modulus_;
	std::vector<uint8_t> product_code_;
	std::string activation_server_;
	uint32_t build_date_;
};

#endif
