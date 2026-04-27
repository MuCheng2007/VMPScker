#include "../../runtime/common.h"
#include "../objects.h"
#include "../osutils.h"
#include "../streams.h"
#include "../files.h"
#include "PEDebug.h"
#include "PEDirectory.h"
#include "PEArchitecture.h"

/**
 * PEDebugData
 */


PEDebugData::PEDebugData(PEDebugDirectory* owner)
	: IObject(), owner_(owner), characteristics_(0), time_date_stamp_(0),
	major_version_(0), minor_version_(0), type_(0), size_(0), address_(0),
	offset_(0)
{

}

PEDebugData::PEDebugData(PEDebugDirectory* owner, const PEDebugData& src)
	: IObject(), owner_(owner)
{
	characteristics_ = src.characteristics_;
	time_date_stamp_ = src.time_date_stamp_;
	major_version_ = src.major_version_;
	minor_version_ = src.minor_version_;
	type_ = src.type_;
	size_ = src.size_;
	address_ = src.address_;
	offset_ = src.offset_;
}

PEDebugData::~PEDebugData()
{
	if (owner_)
		owner_->RemoveObject(this);
}

PEDebugData* PEDebugData::Clone(PEDebugDirectory* owner) const
{
	PEDebugData* data = new PEDebugData(owner, *this);
	return data;
}

void PEDebugData::ReadFromFile(PEArchitecture& file)
{
	IMAGE_DEBUG_DIRECTORY data;
	file.Read(&data, sizeof(data));
	characteristics_ = data.Characteristics;
	time_date_stamp_ = data.TimeDateStamp;
	major_version_ = data.MajorVersion;
	minor_version_ = data.MinorVersion;
	type_ = data.Type;
	size_ = data.SizeOfData;
	address_ = data.AddressOfRawData ? data.AddressOfRawData + file.image_base() : 0;
	offset_ = data.PointerToRawData;
}

void PEDebugData::WriteToFile(PEArchitecture& file)
{
	IMAGE_DEBUG_DIRECTORY data;
	data.Characteristics = characteristics_;
	data.TimeDateStamp = time_date_stamp_;
	data.MajorVersion = major_version_;
	data.MinorVersion = minor_version_;
	data.Type = type_;
	data.SizeOfData = size_;
	data.AddressOfRawData = address_ ? static_cast<uint32_t>(address_ - file.image_base()) : 0;
	data.PointerToRawData = offset_;
	file.Write(&data, sizeof(data));
}

/**
 * PEDebugDirectory
 */

PEDebugDirectory::PEDebugDirectory()
	: ObjectList<PEDebugData>(), address_(0)
{

}

PEDebugDirectory::PEDebugDirectory(const PEDebugDirectory& src)
	: ObjectList<PEDebugData>(src)
{
	address_ = src.address_;
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

PEDebugDirectory* PEDebugDirectory::Clone() const
{
	PEDebugDirectory* res = new PEDebugDirectory(*this);
	return res;
}

PEDebugData* PEDebugDirectory::Add()
{
	PEDebugData* data = new PEDebugData(this);
	AddObject(data);
	return data;
}

void PEDebugDirectory::ReadFromFile(PEArchitecture& file, PEDirectory& directory)
{
	if (!directory.address())
		return;

	if (!file.AddressSeek(directory.address()))
		throw std::runtime_error("Format error");

	address_ = directory.address();

	size_t c = directory.size() / sizeof(IMAGE_DEBUG_DIRECTORY);
	for (size_t i = 0; i < c; i++) {
		PEDebugData* data = Add();
		data->ReadFromFile(file);
	}
}

void PEDebugDirectory::WriteToFile(PEArchitecture& file)
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->WriteToFile(file);
	}
}

void PEDebugDirectory::FreeByManager(MemoryManager& manager) const
{
	if (!address_)
		return;

	manager.Add(address_, count() * sizeof(IMAGE_DEBUG_DIRECTORY));
	for (size_t i = 0; i < count(); i++) {
		PEDebugData* data = item(i);
		if (data->address() && data->size())
			manager.Add(data->address(), data->size());
	}
}
