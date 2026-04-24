#include "license.h"

#include "../../runtime/crypto.h"
#include "../lang.h"
#include "../osutils.h"
#include "../files.h"
#include "../core.h"
#include "core_utils.h"

License::License(LicensingManager *owner, LicenseDate date, const std::string &customer_name, const std::string &customer_email, const std::string &order_ref, 
	const std::string &comments, const std::string &serial_number, bool blocked)
	: owner_(owner), date_(date), customer_name_(customer_name), customer_email_(customer_email), order_ref_(order_ref), 
	comments_(comments), serial_number_(serial_number), blocked_(blocked), info_(NULL)
{

}

License::~License()
{
	delete info_;
	if (owner_)
		owner_->RemoveObject(this);
}

void License::GetHash(uint8_t hash[20])
{
	std::vector<uint8_t> binary_serial;
	Base64ToVector(serial_number_.c_str(), serial_number_.size(), binary_serial);

	SHA1 sha;
	sha.Input(&binary_serial[0], binary_serial.size());
	const uint8_t *src = sha.Result();
	memcpy(hash, src, 20);
}

void License::set_customer_name(const std::string &value)
{
	if (customer_name_ != value) {
		customer_name_ = value;
		Notify(mtChanged, this);
	}
}

void License::set_customer_email(const std::string &value) 
{ 
	if (customer_email_ != value) {
		customer_email_ = value;
		Notify(mtChanged, this);
	}
}

void License::set_order_ref(const std::string &value) 
{ 
	if (order_ref_ != value) {
		order_ref_ = value;
		Notify(mtChanged, this);
	}
}

void License::set_date(LicenseDate value) 
{ 
	if (date_.value() != value.value()) {
		date_ = value; 
		Notify(mtChanged, this);
	}
}

void License::set_comments(const std::string &value) 
{ 
	if (comments_ != value) {
		comments_ = value; 
		Notify(mtChanged, this);
	}
}

void License::set_blocked(bool value) 
{ 
	if (blocked_ != value) {
		blocked_ = value; 
		Notify(mtChanged, this);
	}
}

void License::Notify(MessageType type, IObject *sender, const std::string &message) const
{
	if (owner_)
		owner_->Notify(type, sender, message);
}

LicenseInfo *License::info()
{
	if (!info_ && owner_) {
		LicenseInfo *tmp_info = new LicenseInfo();
		if (owner_->DecryptSerialNumber(serial_number_, *tmp_info))
			info_ = tmp_info;
		else
			delete tmp_info;
	}

	return info_;
}

LicensingManager::LicensingManager(Core *owner)
	: ObjectList<License>(), owner_(owner), algorithm_(alNone), bits_(0), build_date_(0)
{

}

void LicensingManager::clear()
{
	ObjectList<License>::clear();
	file_name_.clear();
	algorithm_ = alNone;
	bits_ = 0;
	product_code_.clear();
	public_exp_.clear();
	private_exp_.clear();
	modulus_.clear();
	activation_server_.clear();
}

void LicensingManager::changed()
{
	if (owner_)
		owner_->Notify(mtChanged, this);
}

bool LicensingManager::Init(size_t key_len)
{
	RSA rsa;
	if (!rsa.CreateKeyPair(key_len))
		return false;

	std::string file_name = file_name_;
	clear();
	file_name_ = file_name;
	algorithm_ = alRSA;
	bits_ = (uint16_t)key_len;
	public_exp_ = rsa.public_exp();
	private_exp_ = rsa.private_exp();
	modulus_ = rsa.modulus();
	srand(os::GetTickCount());
	for (size_t i = 0; i < 8; i++) {
		product_code_.push_back(rand());
	}
	changed();

	return true;
}

bool LicensingManager::GetLicenseData(Data &data) const
{
	if (algorithm_ == alNone)
		return false;

	size_t i;
	std::vector<std::vector<uint8_t> > black_list;

	for (i = 0; i < count(); i++) {
		License *license = item(i);
		if (!license->blocked())
			continue;

		uint8_t hash[20];
		license->GetHash(hash);
		black_list.push_back(std::vector<uint8_t>(hash, hash + sizeof(hash)));
	}
	std::sort(black_list.begin(), black_list.end());

	uint32_t build_date = build_date_;
	if (!build_date) {
		SYSTEM_TIME time;
		os::GetLocalTime(&time);
		build_date = (time.year << 16) + (time.month << 8) + time.day;
	}

	for (i = 0; i < FIELD_COUNT; i++) {
		data.PushDWord(0);
	}

	data.WriteDWord(FIELD_BUILD_DATE * sizeof(uint32_t), build_date);

	data.WriteDWord(FIELD_PUBLIC_EXP_OFFSET * sizeof(uint32_t), static_cast<uint32_t>(data.size()));
	data.WriteDWord(FIELD_PUBLIC_EXP_SIZE * sizeof(uint32_t), static_cast<uint32_t>(public_exp_.size()));
	data.PushBuff(public_exp_.data(), public_exp_.size());

	data.WriteDWord(FIELD_MODULUS_OFFSET * sizeof(uint32_t), static_cast<uint32_t>(data.size()));
	data.WriteDWord(FIELD_MODULUS_SIZE * sizeof(uint32_t), static_cast<uint32_t>(modulus_.size()));
	data.PushBuff(modulus_.data(), modulus_.size());

	data.WriteDWord(FIELD_BLACKLIST_OFFSET * sizeof(uint32_t), static_cast<uint32_t>(data.size()));
	data.WriteDWord(FIELD_BLACKLIST_SIZE * sizeof(uint32_t), static_cast<uint32_t>(black_list.size() * 20));
	if (!black_list.empty()) {
		for (i = 0; i < black_list.size(); i++) {
			data.PushBuff(black_list[i].data(), black_list[i].size());
		}
	}

	data.WriteDWord(FIELD_ACTIVATION_URL_OFFSET * sizeof(uint32_t), static_cast<uint32_t>(data.size()));
	data.WriteDWord(FIELD_ACTIVATION_URL_SIZE * sizeof(uint32_t), static_cast<uint32_t>(activation_server_.size()));
	if (!activation_server_.empty())
		data.PushBuff(activation_server_.data(), activation_server_.size());

	data.resize(AlignValue(data.size(), 8));
	size_t crc_pos = data.size();
	data.WriteDWord(FIELD_CRC_OFFSET * sizeof(uint32_t), static_cast<uint32_t>(crc_pos));

	// calc CRC
	SHA1 sha1;
	sha1.Input(data.data(), crc_pos);
	data.PushBuff(sha1.Result(), 16);
	return true;
}

bool LicensingManager::Open(const std::string &file_name)
{
	clear();

	file_name_ = file_name;

	TiXmlDocument doc;
	if (!doc.LoadFile(file_name.c_str()))
		return false;

	unsigned int u;
	TiXmlElement *root_node = doc.FirstChildElement("Document");
	TiXmlElement *license_manager_node = root_node ? root_node->FirstChildElement("LicenseManager") : NULL;
	if (license_manager_node) {
		std::string str;
		license_manager_node->QueryStringAttribute("Algorithm", &str);
		if (str.compare("RSA") == 0) {
			algorithm_ = alRSA;
			str.clear();
			license_manager_node->QueryStringAttribute("ProductCode", &str);
			Base64ToVector(str.c_str(), str.size(), product_code_);
			u = 0;
			license_manager_node->QueryUnsignedAttribute("Bits", &u);
			bits_ = u;
			str.clear();
			license_manager_node->QueryStringAttribute("PublicExp", &str);
			Base64ToVector(str.c_str(), str.size(), public_exp_);
			str.clear();
			license_manager_node->QueryStringAttribute("PrivateExp", &str);
			Base64ToVector(str.c_str(), str.size(), private_exp_);
			str.clear();
			license_manager_node->QueryStringAttribute("Modulus", &str);
			Base64ToVector(str.c_str(), str.size(), modulus_);
			license_manager_node->QueryStringAttribute("ActivationServer", &activation_server_);

			if ((bits_ & 0xf) || bits_ < 1024 || bits_ > 16384 || public_exp_.empty() || private_exp_.empty() || modulus_.empty())
				algorithm_ = alNone;
		}

		if (algorithm_ != alNone) {
			TiXmlElement *license_node = license_manager_node->FirstChildElement("License");
			while (license_node) {
				std::string date_str;
				std::string customer_name;
				std::string customer_email;
				std::string order_ref;
				std::string serial_number;
				std::string comments;
				bool blocked = false;
				
				license_node->QueryStringAttribute("Date", &date_str);
				license_node->QueryStringAttribute("CustomerName", &customer_name);
				license_node->QueryStringAttribute("CustomerEmail", &customer_email);
				license_node->QueryStringAttribute("OrderRef", &order_ref);
				license_node->QueryStringAttribute("SerialNumber", &serial_number);
				license_node->QueryBoolAttribute("Blocked", &blocked);
				TiXmlElement *comments_node = license_node->FirstChildElement("Comments");
				const char *str = comments_node ? comments_node->GetText() : license_node->GetText();
				if (str)
					comments = std::string(str);

				Add(LicenseDate(atoi(date_str.substr(0, 4).c_str()), atoi(date_str.substr(5, 2).c_str()), atoi(date_str.substr(8, 2).c_str())),
					customer_name, customer_email, order_ref, comments, serial_number, blocked);
				license_node = license_node->NextSiblingElement("License");
			}
		}
	}

	changed();
	return true;
}

bool LicensingManager::Save()
{
	if (file_name_.empty())
		return false;

	TiXmlDocument doc;
	if (!doc.LoadFile(file_name_.c_str()))
		doc.LinkEndChild(new TiXmlDeclaration("1.0", "UTF-8", ""));

	TiXmlElement *root_node = doc.FirstChildElement("Document");
	if (!root_node) {
		root_node = new TiXmlElement("Document");
		doc.LinkEndChild(root_node);
	}

	TiXmlElement *license_manager_node = root_node->FirstChildElement("LicenseManager");
	if (!license_manager_node) {
		license_manager_node = new TiXmlElement("LicenseManager");
		root_node->LinkEndChild(license_manager_node);
	} else {
		license_manager_node->Clear();
	}

	if (!product_code_.empty())
		license_manager_node->SetAttribute("ProductCode", VectorToBase64(product_code_));
	if (!activation_server_.empty())
		license_manager_node->SetAttribute("ActivationServer", activation_server_);
	if (algorithm_ != alNone) {
		license_manager_node->SetAttribute("Algorithm", "RSA");
		license_manager_node->SetAttribute("Bits", bits_);
		license_manager_node->SetAttribute("PublicExp", VectorToBase64(public_exp_));
		license_manager_node->SetAttribute("PrivateExp", VectorToBase64(private_exp_));
		license_manager_node->SetAttribute("Modulus", VectorToBase64(modulus_));
		for (size_t i = 0; i < count(); i++) {
			License *license = item(i);

			TiXmlElement *license_node = new TiXmlElement("License");
			license_manager_node->LinkEndChild(license_node);
			license_node->SetAttribute("Date", string_format("%.4d-%.2d-%.2d", license->date().Year, license->date().Month, license->date().Day));
			if (!license->customer_name().empty())
				license_node->SetAttribute("CustomerName", license->customer_name());
			if (!license->customer_email().empty())
				license_node->SetAttribute("CustomerEmail", license->customer_email());
			if (!license->order_ref().empty())
				license_node->SetAttribute("OrderRef", license->order_ref());
			license_node->SetAttribute("SerialNumber", license->serial_number());
			if (license->blocked())
				license_node->SetAttribute("Blocked", license->blocked());
			if (!license->comments().empty())
				license_node->LinkEndChild(new TiXmlText(license->comments()));
		}
	}

	if (!doc.SaveFile(file_name_.c_str()))
		return false;

	return true;
}

bool LicensingManager::SaveAs(const std::string &file_name)
{
	std::string old_file_name = file_name_;
	file_name_ = file_name;
	if (!Save()) {
		file_name_ = old_file_name;
		return false;
	}
	if (old_file_name != file_name_)
		changed();
	return true;
}

License *LicensingManager::Add(LicenseDate date, const std::string &customer_name, const std::string &customer_email, const std::string &order_ref, 
	const std::string &comments, const std::string &serial_number, bool blocked)
{
	License *license = new License(this, date, customer_name, customer_email, order_ref, comments, serial_number, blocked);
	AddObject(license);
	return license;
}

uint64_t LicensingManager::product_code() const
{
	uint64_t res = 0;
	if (!product_code_.empty())
		memcpy(&res, &product_code_[0], std::min(product_code_.size(), sizeof(res)));
	return res;
}

std::vector<uint8_t> LicensingManager::hash() const
{
	std::vector<uint8_t> res;
	if (!modulus_.empty()) {
		SHA1 sha;
		sha.Input(modulus_.data(), modulus_.size());
		res.insert(res.end(), sha.Result(), sha.Result() + sha.ResultSize());
	}
	return res;
}

enum SerialNumberChunks {
	SERIAL_CHUNK_VERSION				= 0x01,	//	1 byte of data - version
	SERIAL_CHUNK_USER_NAME				= 0x02,	//	1 + N bytes - length + N bytes of customer's name (without enging \0).
	SERIAL_CHUNK_EMAIL					= 0x03,	//	1 + N bytes - length + N bytes of customer's email (without ending \0).
	SERIAL_CHUNK_HWID					= 0x04,	//	1 + N bytes - length + N bytes of hardware id (N % 4 == 0)
	SERIAL_CHUNK_EXP_DATE				= 0x05,	//	4 bytes - (year << 16) + (month << 8) + (day)
	SERIAL_CHUNK_RUNNING_TIME_LIMIT		= 0x06,	//	1 byte - number of minutes
	SERIAL_CHUNK_PRODUCT_CODE			= 0x07,	//	8 bytes - used for decrypting some parts of exe-file
	SERIAL_CHUNK_USER_DATA				= 0x08,	//	1 + N bytes - length + N bytes of user data
	SERIAL_CHUNK_MAX_BUILD				= 0x09,	//	4 bytes - (year << 16) + (month << 8) + (day)

	SERIAL_CHUNK_END					= 0xFF	//	4 bytes - checksum: the first four bytes of sha-1 hash from the data before that chunk
};

std::string LicensingManager::GenerateSerialNumber(const LicenseInfo &info)
{
	if (algorithm_ == alNone)
		throw std::runtime_error(language[lsLicensingParametersNotInitialized]);

	Data data;

	data.PushByte(SERIAL_CHUNK_VERSION);
	data.PushByte(1);

	if (info.Flags & HAS_USER_NAME)	{
		data.PushByte(SERIAL_CHUNK_USER_NAME);
		if (info.CustomerName.size() > 255)
			throw std::runtime_error(language[lsCustomerNameTooLong]);
		data.PushByte((uint8_t)info.CustomerName.size());
		data.PushBuff(info.CustomerName.c_str(), info.CustomerName.size());
	}

	if (info.Flags & HAS_EMAIL)	{
		data.PushByte(SERIAL_CHUNK_EMAIL);
		if (info.CustomerEmail.size() > 255)
			throw std::runtime_error(language[lsEmailTooLong]);
		data.PushByte((uint8_t)info.CustomerEmail.size());
		data.PushBuff(info.CustomerEmail.c_str(), info.CustomerEmail.size());
	}

	if (info.Flags & HAS_HARDWARE_ID) {
		data.PushByte(SERIAL_CHUNK_HWID);
		std::vector<uint8_t> hwid;
		Base64ToVector(info.HWID.c_str(), info.HWID.size(), hwid);
		if (!hwid.size() || hwid.size() > 255 || hwid.size() % 4 != 0)
			throw std::runtime_error(language[lsInvalidHWID]);
		data.PushByte((uint8_t)hwid.size());
		data.PushBuff(&hwid[0], hwid.size());
	}

	if (info.Flags & HAS_EXP_DATE) {
		data.PushByte(SERIAL_CHUNK_EXP_DATE);
		data.PushDWord(info.ExpireDate.value());
	}

	if (info.Flags & HAS_TIME_LIMIT) {
		data.PushByte(SERIAL_CHUNK_RUNNING_TIME_LIMIT);
		data.PushByte(info.RunningTimeLimit);
	}

	if (product_code_.size() != 8)
		throw std::runtime_error(language[lsInvalidProductCode]);
	data.PushByte(SERIAL_CHUNK_PRODUCT_CODE);
	data.PushBuff(&product_code_[0], product_code_.size());

	if (info.Flags & HAS_USER_DATA)	{
		data.PushByte(SERIAL_CHUNK_USER_DATA);
		if (info.UserData.size() > 255)
			throw std::runtime_error(language[lsUserDataTooLong]);
		data.PushByte((uint8_t)info.UserData.size());
		data.PushBuff(info.UserData.c_str(), info.UserData.size());
	}

	if (info.Flags & HAS_MAX_BUILD_DATE) {
		data.PushByte(SERIAL_CHUNK_MAX_BUILD);
		data.PushDWord(info.MaxBuildDate.value());
	}

	// compute hash
	{
		SHA1 sha;
		sha.Input(data.data(), data.size());
		data.PushByte(SERIAL_CHUNK_END);
		const uint8_t *p = sha.Result();
		for (size_t i = 0; i < 4; i++) {
			data.PushByte(p[3 - i]);
		}
	}

	// add padding
	size_t min_padding = 8 + 3;
	size_t max_padding = min_padding + 16;
	size_t max_bytes = bits_ / 8;
	if (data.size() + min_padding > max_bytes)
		throw std::runtime_error(language[lsSerialNumberTooLong]);

	srand(os::GetTickCount());
	size_t padding_bytes = min_padding + rand() % (max_padding - min_padding);

	data.InsertBuff(0, data.data(), padding_bytes);
	data[0] = 0;
	data[1] = 2;
	data[padding_bytes - 1] = 0;
	for (size_t i = 2; i < padding_bytes - 1; i++) {
		uint8_t b = 0;
		while (!b) {
			b = rand();
		}
		data[i] = b;
	}
	while (data.size() < max_bytes) {
		data.PushByte(rand());
	}

	{
		RSA rsa(public_exp_, private_exp_, modulus_);
		if (!rsa.Encrypt(data))
			throw std::runtime_error(language[lsSerialNumberTooLong]);
	}

	size_t len = Base64EncodeGetRequiredLength(data.size());
	char *buffer = new char[len];
	Base64Encode(data.data(), data.size(), buffer, len);
	std::string res = std::string(buffer, len);
	delete [] buffer;

	return res;
}

bool LicensingManager::DecryptSerialNumber(const std::string &serial_number, LicenseInfo &license_info)
{
	if (serial_number.empty())
		return false;

	size_t len = serial_number.size();
	uint8_t *buffer = new uint8_t[len];
	Base64Decode(serial_number.c_str(), serial_number.size(), buffer, len);
	Data data;
	data.PushBuff(buffer, len);
	delete [] buffer;

	{
		RSA rsa(public_exp_, private_exp_, modulus_);
		if (!rsa.Decrypt(data))
			return false;
	}

	if (data.size() < (8 + 3 + 1 + 4) || data[0] != 0 || data[1] != 2)
		return false;

	size_t i;
	for (i = 2; i < data.size() && data[i] != 0; i++) {
	}

	i++;
	size_t pos = i;
	while (pos < data.size()) {
		uint8_t b = data[pos++];
		switch (b) {
		case SERIAL_CHUNK_VERSION:
			b = data[pos++];
			if (b < 1 || b > 2)
				return false;
			break;
		case SERIAL_CHUNK_USER_NAME:
			b = data[pos++];
			license_info.CustomerName = std::string(reinterpret_cast<char *>(&data[pos]), b);
			license_info.Flags |= HAS_USER_NAME;
			pos += b;
			break;
		case SERIAL_CHUNK_EMAIL:
			b = data[pos++];
			license_info.CustomerEmail = std::string(reinterpret_cast<char *>(&data[pos]), b);
			license_info.Flags |= HAS_EMAIL;
			pos += b;
			break;
		case SERIAL_CHUNK_HWID:
			b = data[pos++];
			{
				size_t len = Base64EncodeGetRequiredLength(b);
				char *buffer = new char[len];
				Base64Encode(&data[pos], b, buffer, len);
				license_info.HWID = std::string(buffer, len);
				delete [] buffer;
			}
			license_info.Flags |= HAS_HARDWARE_ID;
			pos += b;
			break;
		case SERIAL_CHUNK_EXP_DATE:
			license_info.ExpireDate = LicenseDate(data.ReadDWord(pos));
			license_info.Flags |= HAS_EXP_DATE;
			pos += 4;
			break;
		case SERIAL_CHUNK_RUNNING_TIME_LIMIT:
			license_info.RunningTimeLimit = data[pos];
			license_info.Flags |= HAS_TIME_LIMIT;
			pos++;
			break;
		case SERIAL_CHUNK_PRODUCT_CODE:
			pos += 8;
			break;
		case SERIAL_CHUNK_USER_DATA:
			b = data[pos++];
			license_info.UserData = std::string(reinterpret_cast<char *>(&data[pos]), b);
			license_info.Flags |= HAS_USER_DATA;
			pos += b;
			break;
		case SERIAL_CHUNK_MAX_BUILD:
			license_info.MaxBuildDate = LicenseDate(data.ReadDWord(pos));
			license_info.Flags |= HAS_MAX_BUILD_DATE;
			pos += 4;
			break;
		case SERIAL_CHUNK_END:
			if (pos + 4 > data.size())
				return false;
			{
				SHA1 sha;
				sha.Input(&data[i], pos - i - 1);
				const uint8_t *p = sha.Result();
				for (size_t j = 0; j < 4; j++) {
					if (data[pos + j] != p[3 - j])
						return false;
				}
			}
			return true;
		}
	}

	return false;
}

License *LicensingManager::GetLicenseBySerialNumber(const std::string &serial_number)
{
	std::vector<uint8_t> binary_serial;
	Base64ToVector(serial_number.c_str(), serial_number.size(), binary_serial);

	SHA1 sha;
	sha.Input(&binary_serial[0], binary_serial.size());
	const uint8_t *src = sha.Result();
	uint8_t hash[20];
	memcpy(hash, src, sizeof(hash));

	for (size_t i = 0; i < count(); i++) {
		License *license = item(i);
		uint8_t license_hash[20];
		license->GetHash(license_hash);
		if (memcmp(hash, license_hash, sizeof(hash)) == 0)
			return license;
	}

	return NULL;
}

bool LicensingManager::CompareParameters(const LicensingManager &manager) const
{
	return (algorithm_ == alRSA 
			&& algorithm_ == manager.algorithm_ 
			&& bits_ == manager.bits_
			&& public_exp_ == manager.public_exp_
			&& private_exp_ == manager.private_exp_
			&& modulus_ == manager.modulus_
			&& product_code_ == manager.product_code_);
}

void LicensingManager::Notify(MessageType type, IObject *sender, const std::string &message) const
{
	if (owner_)
		owner_->Notify(type, sender, message);
}

void LicensingManager::AddObject(License *license)
{
	ObjectList<License>::AddObject(license);
	Notify(mtAdded, license);
}

void LicensingManager::RemoveObject(License *license)
{
	Notify(mtDeleted, license);
	ObjectList<License>::RemoveObject(license);
}
