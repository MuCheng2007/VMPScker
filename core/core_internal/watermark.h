#ifndef WATERMARK_H
#define WATERMARK_H

#include "../../runtime/common.h"
#include "../objects.h"

class WatermarkManager;
class IniFile;
class SettingsFile;

class Watermark : public IObject
{
public:
	Watermark(WatermarkManager *owner);
	Watermark(WatermarkManager *owner, const std::string &name, const std::string &value, size_t use_count, bool enabled);
	~Watermark();
	size_t id() const { return id_; }
	std::string name() const { return name_; }
	bool enabled() const { return enabled_; }
	std::string value() const { return value_; }
	size_t use_count() const { return use_count_; }
	void set_name(const std::string &name);
	void set_value(const std::string &value);
	void set_enabled(bool value);
	void Compile();
	bool SearchByte(uint8_t value);
	std::vector<uint8_t> dump() const { return dump_; }
	void inc_use_count();
	void ReadFromIni(IniFile &file, size_t id);
	void ReadFromNode(TiXmlElement *node);
	void SaveToNode(TiXmlElement *node);
	void SaveToFile(SettingsFile &file);
	void DeleteFromFile(SettingsFile &file);
	void InitSearch() { pos_.clear(); }
	virtual void Notify(MessageType type, IObject *sender, const std::string &message = "") const;
	static bool AreSimilar(const std::string &v1, const std::string &v2);
	static bool SymbolsMatch(char v1, char v2);
private:
	WatermarkManager *owner_;
	size_t id_;
	std::string name_;
	std::string value_;
	size_t use_count_;
	bool enabled_;
	std::vector<uint8_t> dump_;
	std::vector<uint8_t> mask_;
	std::vector<size_t> pos_;
};

class Core;

class WatermarkManager : public ObjectList<Watermark>
{
public:
	WatermarkManager(Core *owner);
	Watermark *Add(const std::string name, const std::string value, size_t use_count = 0, bool enabled = true);
	Watermark *GetWatermarkByName(const std::string &name);
	void InitSearch() const;
	virtual void Notify(MessageType type, IObject *sender, const std::string &message = "") const;
	void ReadFromFile(SettingsFile &file);
	virtual void RemoveObject(Watermark *watermark);
	void ReadFromIni(const std::string &file_name);
	void SaveToFile(SettingsFile &file);
	std::string CreateValue() const;
	Watermark *GetWatermarkByValue(const std::string &value) const;
	bool IsUniqueWatermark(const std::string &value) const;
private:
	Core *owner_;
};

#endif
