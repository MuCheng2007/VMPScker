/**
 * PE Resource support.
 */

#ifndef PE_RESOURCE_H
#define PE_RESOURCE_H

#include "../files.h"

class PEArchitecture;
class PEResourceList;
class PEDirectory;

enum PEResourceType {
	rtUnknown,
	rtCursor = 1,
	rtBitmap = 2,
	rtIcon = 3,
	rtMenu = 4,
	rtDialog = 5,
	rtStringTable = 6,
	rtFontDir = 7,
	rtFont = 8,
	rtAccelerators = 9,
	rtRCData = 10,
	rtMessageTable = 11,
	rtGroupCursor = 12,
	rtGroupIcon = 14,
	rtVersionInfo = 16,
	rtDlgInclude = 17,
	rtPlugPlay = 19,
	rtVXD = 20,
	rtAniCursor = 21,
	rtAniIcon = 22,
	rtHTML = 23,
	rtManifest = 24,
	rtDialogInit = 240,
	rtToolbar = 241
};

class PEResource : public BaseResource
{
public:
	explicit PEResource(IResource *owner, PEResourceType type, uint32_t name_offset, uint32_t data_offset);
	explicit PEResource(IResource *owner, const PEResource &src);
	virtual PEResource *Clone(IResource *owner) const;
	PEResource *item(size_t index) const;
	virtual uint32_t type() const { return type_; }
	virtual uint64_t address() const { return is_directory() ? 0 : address_; }
	virtual size_t size() const { return is_directory() ? 0 : data_.item.Size; }
	virtual std::string name() const { return has_name() ? "\"" + name_ + "\"" : name_; }
	virtual bool is_directory() const { return (data_offset_ & IMAGE_RESOURCE_DATA_IS_DIRECTORY) != 0; }
	virtual PEResource *GetResourceByName(const std::string &name) const;
	void set_name(const std::string &name) { name_ = name; }
	bool has_name() const { return (name_offset_ & IMAGE_RESOURCE_NAME_IS_STRING) != 0; }
	bool need_store() const;
	virtual std::string id() const;
	void ReadFromFile(PEArchitecture &file, uint64_t root_address);
	// PE format
	void WriteHeader(Data &data);
	void WriteEntry(Data &data);
	void WriteName(Data &data);
	size_t WriteData(Data &data, PEArchitecture &file);
	// ResourceManager format
	void WriteHeader(IFunction &data);
	void WriteEntry(IFunction &data);
	void WriteName(IFunction &data, size_t root_index, uint32_t key);
	void WriteData(IFunction &data, PEArchitecture &file, uint32_t key);
private:
	PEResource *Add(PEResourceType type, uint32_t name_offset, uint32_t data_offset);

	PEResourceType type_;
	uint32_t name_offset_;
	uint32_t data_offset_;
	union {
		IMAGE_RESOURCE_DIRECTORY dir;
		IMAGE_RESOURCE_DATA_ENTRY item;
	} data_;
	std::string name_;
	uint64_t address_;
	size_t entry_offset_;
	size_t data_entry_offset_;
};

class PEResourceList : public BaseResourceList
{
public:
	explicit PEResourceList(PEArchitecture *owner);
	explicit PEResourceList(PEArchitecture *owner, const PEResourceList &src);

	using BaseResourceList::Clone;
	PEResourceList *Clone(PEArchitecture *owner) const;
	PEResource *item(size_t index) const;
	void ReadFromFile(PEArchitecture &file, PEDirectory &dir);
	size_t WriteToFile(PEArchitecture &file, uint64_t address);
	void Compile(PEArchitecture &file, bool for_packing);
	size_t size() const { return data_.size(); }
	size_t store_size() const { return store_size_; }
	void WritePackData(Data &data);
	void CreateCommands(PEArchitecture &file, IFunction &data);
private:
	PEResource *Add(PEResourceType type, uint32_t name_offset, uint32_t data_offset);
	IMAGE_RESOURCE_DIRECTORY dir_;
	Data data_;
	std::vector<size_t> link_list_;
	size_t store_size_;
};

#endif // PE_RESOURCE_H
