#include "watermark.h"

#include "../inifile.h"
#include "../files/architecture.h"
#include "../files/utils.h"
#include "core.h"
#include "core_utils.h"

Watermark::Watermark(WatermarkManager *owner)
	: IObject(), owner_(owner), id_(-1), use_count_(0), enabled_(false)
{

}

Watermark::Watermark(WatermarkManager *owner, const std::string &name, const std::string &value, size_t use_count, bool enabled)
	: IObject(), owner_(owner), id_(-1), name_(name), value_(value), use_count_(use_count), enabled_(enabled)
{
	Compile();
}

Watermark::~Watermark()
{
	if (owner_)
		owner_->RemoveObject(this);
}

void Watermark::Notify(MessageType type, IObject *sender, const std::string &message) const
{
	if (owner_)
		owner_->Notify(type, sender, message);
}

void Watermark::set_name(const std::string &name)
{
	if (name_ != name) {
		name_ = name;
		Notify(mtChanged, this);
	}
}

void Watermark::set_value(const std::string &value)
{
	if (value_ != value) {
		value_ = value;
		Notify(mtChanged, this);
	}
}

void Watermark::set_enabled(bool value)
{
	if (enabled_ != value) {
		enabled_ = value;
		Notify(mtChanged, this);
	}
}

void Watermark::inc_use_count()
{
	use_count_++;
	Notify(mtChanged, this);
}

void Watermark::ReadFromIni(IniFile &file, size_t id)
{
	id_ = id;
	name_ = file.ReadString("Watermarks", string_format("Name%d", id).c_str());
	value_ = file.ReadString("Watermarks", string_format("Value%d", id).c_str());
	use_count_ = file.ReadInt("Watermarks", string_format("UseCount%d", id).c_str());
	enabled_ = file.ReadBool("Watermarks", string_format("Enabled%d", id).c_str(), true);
	Compile();
}

void Watermark::ReadFromNode(TiXmlElement *node)
{
	unsigned int u;

	u = 0;
	node->QueryUnsignedAttribute("Id", &u);
	id_ = u;
	node->QueryStringAttribute("Name", &name_);
	u = 0;
	node->QueryUnsignedAttribute("UseCount", &u);
	use_count_ = u;
	enabled_ = true;
	node->QueryBoolAttribute("Enabled", &enabled_);
	if (const char *str = node->GetText())
		value_ = std::string(str);
	Compile();
}

void Watermark::SaveToNode(TiXmlElement *node)
{
	if (!node)
		return;

	node->Clear();
	node->SetAttribute("Id", (int)id_);
	node->SetAttribute("Name", name_);
	node->SetAttribute("UseCount", (int)use_count_);
	if (enabled_)
		node->RemoveAttribute("Enabled");
	else 
		node->SetAttribute("Enabled", enabled_);
	node->LinkEndChild(new TiXmlText(value_));
}

void Watermark::SaveToFile(SettingsFile &file)
{
	GlobalLocker locker;
	if (id_ == NOT_ID)
		id_ = file.inc_watermark_id();

	TiXmlElement *node = file.watermark_node(id_, true);
	if (node) {
		SaveToNode(node);
		file.Save();
	}
}

void Watermark::DeleteFromFile(SettingsFile &file)
{
	TiXmlElement *node = file.watermark_node(id_);
	if (node && node->Parent()->RemoveChild(node))
		file.Save();
}

void Watermark::Compile()
{
	dump_.clear();
	mask_.clear();

	if (value_.size() == 0)
		return;

	for (size_t i = 0; i < value_.size(); i++) {
		size_t p = i / 2;
		if (p >= dump_.size()) {
			dump_.push_back(0);
			mask_.push_back(0);
		}

		uint8_t m = 0xff;
		uint8_t b;
		char c = value_[i];
		if ((c >= '0') && (c <= '9')) {
			b = c - '0';
		} else if ((c >= 'A') && (c <= 'F')) {
			b = c - 'A' + 0x0a;
		} else if ((c >= 'a') && (c <= 'f')) {
			b = c - 'a' + 0x0a;
		} else {
			m = 0;
			b = rand();
		}

		if ((i & 1) == 0) {
			dump_[p] = (dump_[p] & 0x0f) | (b << 4);
			mask_[p] = (mask_[p] & 0x0f) | (m << 4);
		} else {
			dump_[p] = (dump_[p] & 0xf0) | (b & 0x0f);
			mask_[p] = (mask_[p] & 0xf0) | (m & 0x0f);
		}
	}
}

bool Watermark::SearchByte(uint8_t value)
{
	if (dump_.size() == 0)
		return false;

	bool res = false;
	for (int i = (int)(pos_.size() - 1); i >= -1; i--) {
		size_t p = (i == -1) ? 0 : pos_[i];
		if ((dump_[p] & mask_[p]) == (value & mask_[p])) {
			p++;
			if (p == dump_.size()) {
				res = true;
				if (i > -1)
					pos_.erase(pos_.begin() + i);
			} else if (i == -1) {
				pos_.push_back(p);
			} else {
				pos_[i] = p;
			}
		} else if (i > -1) {
			pos_.erase(pos_.begin() + i);
		}
	}

	return res;
}

bool Watermark::AreSimilar(const std::string &v1, const std::string &v2)
{
	// v1 is part of v2 or is vice versa
	int v1_in_v2_pos = 0, v1_in_v2_pos_max = int(v2.length()) - int(v1.length());
	int v2_in_v1_pos = 0, v2_in_v1_pos_max = int(v1.length()) - int(v2.length());

	while(v1_in_v2_pos <= v1_in_v2_pos_max)
	{
		size_t v1p = 0;
		for(; v1p < v1.length(); v1p++)
		{
			if(!SymbolsMatch(v1[v1p], v2[v1_in_v2_pos + v1p]))
				break;
		}
		if(v1p == v1.length())
			return true;
		v1_in_v2_pos++;
	}
	if(v1_in_v2_pos_max == v2_in_v1_pos_max)
		return false;
	while(v2_in_v1_pos <= v2_in_v1_pos_max)
	{
		size_t v2p = 0;
		for(; v2p < v2.length(); v2p++)
		{
			if(!SymbolsMatch(v2[v2p], v1[v2_in_v1_pos + v2p]))
				break;
		}
		if(v2p == v2.length())
			return true;
		v2_in_v1_pos++;
	}
	return false;
}

bool Watermark::SymbolsMatch(char v1, char v2)
{
	if(v1 == '?' || v2 == '?')
		return true;
	assert('a' > 'A');
	if(v1 >= 'a')
		v1 = v1 - 'a' + 'A';
	if(v2 >= 'a')
		v2 = v2 - 'a' + 'A';
	return v1 == v2;
}

WatermarkManager::WatermarkManager(Core *owner)
	: ObjectList<Watermark>(), owner_(owner)
{

}

Watermark *WatermarkManager::Add(const std::string name, const std::string value, size_t use_count, bool enabled)
{
	Watermark *watermark = new Watermark(this, name, value, use_count, enabled);
	AddObject(watermark);
	Notify(mtAdded, watermark);
	return watermark;
}

Watermark *WatermarkManager::GetWatermarkByName(const std::string &name)
{
	for (size_t i = 0; i < count(); i++) {
		Watermark *watermark = item(i);
		if (watermark->name() == name)
			return watermark;
	}
	return NULL;
}

void WatermarkManager::InitSearch() const
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->InitSearch();
	}
}

void WatermarkManager::Notify(MessageType type, IObject *sender, const std::string &message) const
{
	if (owner_)
		owner_->Notify(type, sender, message);
}

void WatermarkManager::RemoveObject(Watermark *watermark)
{
	Notify(mtDeleted, watermark);
	ObjectList<Watermark>::RemoveObject(watermark);
}

void WatermarkManager::ReadFromIni(const std::string &file_name)
{
	IniFile file(file_name.c_str());
	std::vector<std::string> key_list = file.ReadSection("Watermarks", "Name");
	for (size_t i = 0; i < key_list.size(); i++) {
		std::string str = key_list[i];
		size_t id = StrToIntDef(&str[4], -1);
		if (id == NOT_ID)
			continue;

		Watermark *watermark = new Watermark(this);
		watermark->ReadFromIni(file, id);
		AddObject(watermark);
	}
}

void WatermarkManager::ReadFromFile(SettingsFile &file)
{
	TiXmlElement *watermarks_node = file.watermarks_node();
	if (!watermarks_node)
		return;

	TiXmlElement *node = watermarks_node->FirstChildElement("Watermark");
	while (node) {
		Watermark *watermark = new Watermark(this);
		watermark->ReadFromNode(node);
		AddObject(watermark);
		node = node->NextSiblingElement(node->Value());
	}
}

void WatermarkManager::SaveToFile(SettingsFile &file)
{
	TiXmlElement *watermarks_node = file.watermarks_node();
	if (!watermarks_node)
		return;

	watermarks_node->Clear();
	size_t id = 0;
	for (size_t i = 0; i < count(); i++) {
		TiXmlElement *node = new TiXmlElement("Watermark");
		watermarks_node->LinkEndChild(node);

		Watermark *watermark = item(i);
		watermark->SaveToNode(node);
		if (id < watermark->id())
			id = watermark->id();
	}
	watermarks_node->SetAttribute("Id", (int)(id + 1));
}

Watermark *WatermarkManager::GetWatermarkByValue(const std::string &value) const
{
	for (size_t i = 0; i < count(); i++) {
		Watermark *watermark = item(i);
		if (watermark->value() == value)
			return watermark;
	}
	return NULL;
}

bool WatermarkManager::IsUniqueWatermark(const std::string &value) const
{
	for (size_t i = 0; i < count(); i++) {
		Watermark *watermark = item(i);
		if (Watermark::AreSimilar(watermark->value(), value))
			return false;
	}
	return true;
}

std::string WatermarkManager::CreateValue() const
{
	std::string res;
	res.reserve(2 * (20 + 0xFF));
	do {
		res.clear();
		size_t c = 20 + rand() % 0x100;
		for (size_t i = 0; i < 2 * c; i++) {
			if (rand() & 1)
				res += '?';
			else
				res += string_format("%x", rand() % 0x10);
		}
	} while (!IsUniqueWatermark(res));
	return res;
}
