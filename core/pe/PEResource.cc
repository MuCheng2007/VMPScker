

#include "../../runtime/common.h"
#include "../../runtime/crypto.h"
#include "../objects.h"
#include "../osutils.h"
#include "../streams.h"
#include "../files.h"
#include "../processors.h"
#include "PEResource.h"
#include "PEDirectory.h"
#include "PEArchitecture.h"
#include "../lang.h"
#include "../core_internal/core.h"

// Intel module
#include "../intel/ir/IntelFunction.h"
#include "../intel/ir/IntelCommand.h"


/**
 * PEResource
 */

PEResource::PEResource(IResource* owner, PEResourceType type, uint32_t name_offset, uint32_t data_offset)
	: BaseResource(owner), type_(type), name_offset_(name_offset), data_offset_(data_offset),
	address_(0), entry_offset_(0), data_entry_offset_(0)
{
	memset(&data_, 0, sizeof(data_));
}

PEResource::PEResource(IResource* owner, const PEResource& src)
	: BaseResource(owner, src)
{
	type_ = src.type_;
	name_offset_ = src.name_offset_;
	data_offset_ = src.data_offset_;
	data_ = src.data_;
	name_ = src.name_;
	address_ = src.address_;
	entry_offset_ = src.entry_offset_;
	data_entry_offset_ = src.data_entry_offset_;
}

PEResource* PEResource::Clone(IResource* owner) const
{
	PEResource* resource = new PEResource(owner, *this);
	return resource;
}

PEResource* PEResource::item(size_t index) const
{
	return reinterpret_cast<PEResource*>(IResource::item(index));
}

PEResource* PEResource::GetResourceByName(const std::string& name) const
{
	for (size_t i = 0; i < count(); i++) {
		PEResource* resource = item(i);
		if (resource->has_name() && resource->name_ == name)
			return resource;
	}
	return NULL;
}

PEResource* PEResource::Add(PEResourceType type, uint32_t name_offset, uint32_t data_offset)
{
	PEResource* resource = new PEResource(this, type, name_offset, data_offset);
	AddObject(resource);
	return resource;
}

void PEResource::ReadFromFile(PEArchitecture& file, uint64_t root_address)
{
	if (has_name()) {
		// name_offset is a string
		if (!file.AddressSeek(root_address + (name_offset_ & ~IMAGE_RESOURCE_NAME_IS_STRING)))
			throw std::runtime_error("Format error");

		uint16_t len = file.ReadWord();
		os::unicode_string wname;
		wname.resize(len);
		if (!wname.empty())
			file.Read(&wname[0], wname.size() * sizeof(os::unicode_char));
		name_ = os::ToUTF8(wname);
	}
	else {
		// name_offset is an Id
		name_ = string_format("%d", name_offset_);
	}

	if (!file.AddressSeek(root_address + (data_offset_ & ~IMAGE_RESOURCE_DATA_IS_DIRECTORY)))
		throw std::runtime_error("Format error");

	if (is_directory()) {
		// read resource directory
		IMAGE_RESOURCE_DIRECTORY_ENTRY dir_entry;
		size_t i;
		file.Read(&data_.dir, sizeof(data_.dir));
		for (i = 0; i < static_cast<size_t>(data_.dir.NumberOfIdEntries + data_.dir.NumberOfNamedEntries); i++) {
			file.Read(&dir_entry, sizeof(dir_entry));
			Add(type_, dir_entry.u.Name, dir_entry.u2.OffsetToData);
		}
		for (i = 0; i < count(); i++) {
			item(i)->ReadFromFile(file, root_address);
		}
	}
	else {
		// read resource item
		file.Read(&data_.item, sizeof(data_.item));
		address_ = file.image_base() + data_.item.OffsetToData;
	}
}

void PEResource::WriteHeader(Data& data)
{
	size_t i;

	if (is_directory()) {
		// write resource directory
		data_offset_ = (uint32_t)(data.size() | IMAGE_RESOURCE_DATA_IS_DIRECTORY);
		data.WriteDWord(entry_offset_ + sizeof(uint32_t), data_offset_);

		data_.dir.NumberOfIdEntries = 0;
		data_.dir.NumberOfNamedEntries = 0;
		for (i = 0; i < count(); i++) {
			if (item(i)->has_name()) {
				data_.dir.NumberOfNamedEntries++;
			}
			else {
				data_.dir.NumberOfIdEntries++;
			}
		}
		data.PushBuff(&data_.dir, sizeof(data_.dir));

		for (i = 0; i < static_cast<size_t>(data_.dir.NumberOfIdEntries + data_.dir.NumberOfNamedEntries); i++) {
			item(i)->WriteEntry(data);
		}
	}
	else {
		// write resource item
		data_entry_offset_ = data.size();
		data.WriteDWord(entry_offset_ + sizeof(uint32_t), (uint32_t)data_entry_offset_);

		data.PushBuff(&data_.item, sizeof(data_.item));
	}
}

void PEResource::WriteHeader(IFunction& data)
{
	size_t i, size;
	IntelFunction& func = reinterpret_cast<IntelFunction&>(data);

	size = 0;
	for (i = 0; i < func.count(); i++) {
		IntelCommand* command = func.item(i);
		size += OperandSizeToValue(command->operand(0).size);
	}

	if (is_directory()) {
		// write resource directory
		func.item(entry_offset_ + 1)->set_operand_value(0, size | IMAGE_RESOURCE_DATA_IS_DIRECTORY);

		data_.dir.NumberOfIdEntries = 0;
		data_.dir.NumberOfNamedEntries = 0;
		for (i = 0; i < count(); i++) {
			if (item(i)->has_name()) {
				data_.dir.NumberOfNamedEntries++;
			}
			else {
				data_.dir.NumberOfIdEntries++;
			}
		}
		func.AddCommand(osDWord, data_.dir.NumberOfNamedEntries);
		func.AddCommand(osDWord, data_.dir.NumberOfIdEntries);

		for (i = 0; i < static_cast<size_t>(data_.dir.NumberOfIdEntries + data_.dir.NumberOfNamedEntries); i++) {
			item(i)->WriteEntry(data);
		}
	}
	else {
		// write resource item
		func.item(entry_offset_ + 1)->set_operand_value(0, size);

		data_entry_offset_ = func.count();
		func.AddCommand(osDWord, 0);
		func.AddCommand(osDWord, data_.item.Size);
		func.AddCommand(osDWord, data_.item.CodePage);
		func.AddCommand(osDWord, data_.item.Reserved);
	}
}

void PEResource::WriteEntry(Data& data)
{
	IMAGE_RESOURCE_DIRECTORY_ENTRY dir_entry;

	entry_offset_ = data.size();
	dir_entry.u.Name = name_offset_;
	dir_entry.u2.OffsetToData = data_offset_;
	data.PushBuff(&dir_entry, sizeof(dir_entry));
}

void PEResource::WriteEntry(IFunction& data)
{
	IntelFunction& func = reinterpret_cast<IntelFunction&>(data);

	entry_offset_ = func.count();
	func.AddCommand(osDWord, name_offset_);
	func.AddCommand(osDWord, 0);
}

void PEResource::WriteName(Data& data)
{
	if (!has_name())
		return;

	name_offset_ = (uint32_t)(data.size() | IMAGE_RESOURCE_NAME_IS_STRING);
	data.WriteDWord(entry_offset_, name_offset_);

	os::unicode_string wname = os::FromUTF8(name_);
	data.PushWord(static_cast<uint16_t>(wname.size()));
	data.PushBuff(wname.c_str(), wname.size() * sizeof(os::unicode_char));
}

void PEResource::WriteName(IFunction& data, size_t root_index, uint32_t key)
{
	if (!has_name())
		return;

	IntelFunction& func = reinterpret_cast<IntelFunction&>(data);

	size_t i, size;
	size = 0;
	for (i = root_index; i < func.count(); i++) {
		IntelCommand* command = func.item(i);
		size += (command->type() == cmDB) ? command->dump_size() : OperandSizeToValue(command->operand(0).size);
	}
	func.item(entry_offset_)->set_operand_value(0, size | IMAGE_RESOURCE_NAME_IS_STRING);

	os::unicode_string unicode_name = os::FromUTF8(name_);
	const os::unicode_char* p = unicode_name.c_str();
	Data str;
	for (size_t i = 0; i < unicode_name.size() + 1; i++) {
		str.PushWord(static_cast<uint16_t>(p[i] ^ (_rotl32(key, static_cast<int>(i)) + i)));
	}
	func.AddCommand(str);
}

size_t PEResource::WriteData(Data& data, PEArchitecture& file)
{
	if (is_directory())
		return -1;

	if (!file.AddressSeek(address()))
		throw std::runtime_error("Invalid data address");

	// resource data must be aligned
	size_t new_size = data.size();
	new_size = AlignValue(new_size, OperandSizeToValue(file.cpu_address_size()));
	for (size_t i = data.size(); i < new_size; i++) {
		data.PushByte(0);
	}

	std::vector<uint8_t> buf;
	buf.resize(data_.item.Size);
	file.Read(buf.data(), buf.size());

	data.WriteDWord(data_entry_offset_, static_cast<uint32_t>(data.size()));
	data.PushBuff(buf.data(), buf.size());

	return data_entry_offset_;
}

void PEResource::WriteData(IFunction& func, PEArchitecture& file, uint32_t key)
{
	if (is_directory() || !data_.item.Size)
		return;

	if (!file.AddressSeek(address()))
		throw std::runtime_error("Invalid data address");

	std::vector<uint8_t> buf;
	buf.resize(data_.item.Size);
	file.Read(buf.data(), buf.size());

	Data d;
	for (size_t i = 0; i < buf.size(); i++) {
		d.PushByte(buf[i] ^ static_cast<uint8_t>(_rotl32(key, static_cast<int>(i)) + i));
	}

	ICommand* command = func.AddCommand(d);
	command->include_option(roCreateNewBlock);

	CommandLink* link = func.item(data_entry_offset_)->AddLink(0, ltOffset, command);
	link->set_sub_value(file.image_base());
}

bool PEResource::need_store() const
{
	switch (type_) {
	case rtIcon: case rtGroupIcon: case rtVersionInfo:
	case rtManifest: case rtMessageTable: case rtHTML:
		return true;
	case rtUnknown:
		const IResource* resource = this;
		while (resource->owner() && resource->owner()->type() != (uint32_t)-1) {
			resource = resource->owner();
		}
		std::string tmp = resource->name();
		std::transform(tmp.begin(), tmp.end(), tmp.begin(), toupper);
		return (tmp.compare("\"TYPELIB\"") == 0
			|| tmp.compare("\"REGISTRY\"") == 0
			|| tmp.compare("\"MUI\"") == 0);
	}
	return false;
}

std::string PEResource::id() const
{
	std::string res;
	const PEResource* resource = this;
	while (resource->owner()) {
		res = resource->name() + (res.empty() ? "" : "\\") + res;
		resource = reinterpret_cast<PEResource*>(resource->owner());
	}
	return res;
}

/**
 * PEResourceList
 */

PEResourceList::PEResourceList(PEArchitecture* owner)
	: BaseResourceList(owner), store_size_(0)
{
	memset(&dir_, 0, sizeof(dir_));
}

PEResourceList::PEResourceList(PEArchitecture* owner, const PEResourceList& src)
	: BaseResourceList(owner, src)
{
	dir_ = src.dir_;
	store_size_ = src.store_size_;
}

PEResource* PEResourceList::item(size_t index) const
{
	return reinterpret_cast<PEResource*>(IResourceList::item(index));
}

PEResourceList* PEResourceList::Clone(PEArchitecture* owner) const
{
	PEResourceList* list = new PEResourceList(owner, *this);
	return list;
}

PEResource* PEResourceList::Add(PEResourceType type, uint32_t name_offset, uint32_t data_offset)
{
	PEResource* resource = new PEResource(this, type, name_offset, data_offset);
	AddObject(resource);
	return resource;
}

void PEResourceList::ReadFromFile(PEArchitecture& file, PEDirectory& directory)
{
	if (!directory.address())
		return;

	if (!file.AddressSeek(directory.address()))
		throw std::runtime_error("Format error");

	size_t i;
	IMAGE_RESOURCE_DIRECTORY_ENTRY dir_entry;
	file.Read(&dir_, sizeof(dir_));
	for (i = 0; i < static_cast<size_t>(dir_.NumberOfNamedEntries) + static_cast<size_t>(dir_.NumberOfIdEntries); i++) {
		file.Read(&dir_entry, sizeof(dir_entry));
		Add(dir_entry.u.s.NameIsString ? rtUnknown : static_cast<PEResourceType>(dir_entry.u.Id), dir_entry.u.Name, dir_entry.u2.OffsetToData);
	}

	for (i = 0; i < count(); i++) {
		PEResource* resource = item(i);
		resource->ReadFromFile(file, directory.address());
		switch (resource->type()) {
		case rtCursor:
			resource->set_name("Cursor");
			break;
		case rtBitmap:
			resource->set_name("Bitmap");
			break;
		case rtIcon:
			resource->set_name("Icon");
			break;
		case rtMenu:
			resource->set_name("Menu");
			break;
		case rtDialog:
			resource->set_name("Dialog");
			break;
		case rtStringTable:
			resource->set_name("String Table");
			break;
		case rtFontDir:
			resource->set_name("Font Directory");
			break;
		case rtFont:
			resource->set_name("Font");
			break;
		case rtAccelerators:
			resource->set_name("Accelerators");
			break;
		case rtRCData:
			resource->set_name("RCData");
			break;
		case rtMessageTable:
			resource->set_name("Message Table");
			break;
		case rtGroupCursor:
			resource->set_name("Cursor Group");
			break;
		case rtGroupIcon:
			resource->set_name("Icon Group");
			break;
		case rtVersionInfo:
			resource->set_name("Version Info");
			break;
		case rtDlgInclude:
			resource->set_name("DlgInclude");
			break;
		case rtPlugPlay:
			resource->set_name("Plug Play");
			break;
		case rtVXD:
			resource->set_name("VXD");
			break;
		case rtAniCursor:
			resource->set_name("Animated Cursor");
			break;
		case rtAniIcon:
			resource->set_name("Animated Icon");
			break;
		case rtHTML:
			resource->set_name("HTML");
			break;
		case rtManifest:
			resource->set_name("Manifest");
			break;
		case rtDialogInit:
			resource->set_name("Dialog Init");
			break;
		case rtToolbar:
			resource->set_name("Toolbar");
			break;
		}
	}
}

void PEResourceList::Compile(PEArchitecture& file, bool for_packing)
{
	std::vector<PEResource*> list;
	size_t i, j, c, pos;
	PEResource* resource;

	data_.clear();
	link_list_.clear();

	// create resource list
	for (i = 0; i < count(); i++) {
		list.push_back(item(i));
	}

	for (i = 0; i < list.size(); i++) {
		resource = list[i];
		for (j = 0; j < resource->count(); j++) {
			list.push_back(resource->item(j));
		}
	}

	// write root directory
	dir_.NumberOfIdEntries = 0;
	dir_.NumberOfNamedEntries = 0;
	for (i = 0; i < count(); i++) {
		if (item(i)->has_name()) {
			dir_.NumberOfNamedEntries++;
		}
		else {
			dir_.NumberOfIdEntries++;
		}
	}
	data_.PushBuff(&dir_, sizeof(dir_));
	for (i = 0; i < static_cast<size_t>(dir_.NumberOfIdEntries + dir_.NumberOfNamedEntries); i++) {
		item(i)->WriteEntry(data_);
	}

	// write items
	for (i = 0; i < list.size(); i++) {
		list[i]->WriteHeader(data_);
	}

	for (i = 0; i < list.size(); i++) {
		list[i]->WriteName(data_);
	}

	store_size_ = 0;
	c = for_packing ? 2 : 1;
	for (j = 0; j < c; j++) {
		for (i = 0; i < list.size(); i++) {
			resource = list[i];
			if (for_packing) {
				if (resource->excluded_from_packing() || resource->need_store()) {
					if (j != 0)
						continue;
				}
				else {
					if (j == 0)
						continue;
				}
			}

			pos = resource->WriteData(data_, file);
			if (pos != (size_t)-1)
				link_list_.push_back(pos);
		}

		if (j == 0)
			store_size_ = data_.size();
	}
}

size_t PEResourceList::WriteToFile(PEArchitecture& file, uint64_t address)
{
	size_t i, pos;
	Data out = data_;
	uint32_t rva = static_cast<uint32_t>(address - file.image_base());

	for (i = 0; i < link_list_.size(); i++) {
		pos = link_list_[i];
		out.WriteDWord(pos, out.ReadDWord(pos) + rva);
	}

	return file.Write(out.data(), (store_size_) ? store_size_ : out.size());
}

void PEResourceList::WritePackData(Data& data)
{
	data.PushBuff(data_.data() + store_size_, data_.size() - store_size_);
}
