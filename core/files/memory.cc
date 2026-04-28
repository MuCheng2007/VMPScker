/**
 * Memory management and CRC tables implementations.
 * Rust mapping target: mod memory
 */

#include "memory.h"
#include "utils.h"
#include "../files.h"
#include "sections.h"
#include "../processors/proc_crypto.h"
#include "../../runtime/crypto.h"

/**
 * MemoryRegion
 */

MemoryRegion::MemoryRegion(MemoryManager *owner, uint64_t address, size_t size,  uint32_t type, IFunction *parent_function)
	: IObject(), owner_(owner), address_(address), end_address_(address + size), type_(type), parent_function_(parent_function)
{

}

MemoryRegion::~MemoryRegion()
{
	if (owner_)
		owner_->RemoveObject(this);
}

uint64_t MemoryRegion::Alloc(uint64_t memory_size, uint32_t memory_type)
{
	if (size() < memory_size)
		return 0;

	if (memory_type != mtNone) {
		if (((memory_type & mtReadable) != 0 && (type_ & mtReadable) == 0)
			|| ((memory_type & mtWritable) != 0 && (type_ & mtWritable) == 0)
			|| ((memory_type & mtExecutable) != 0 && (type_ & mtExecutable) == 0)
			|| ((memory_type & mtNotPaged) != 0 && (type_ & mtNotPaged) == 0)
			|| ((memory_type & mtDiscardable) != (type_ & mtDiscardable)))
			return 0;
	}

	uint64_t res = address_;
	address_ += memory_size;
	return res;
}

int MemoryRegion::CompareWith(const MemoryRegion &obj) const
{
	if (address() < obj.address())
		return -1;
	if (address() > obj.address())
		return 1;
	return 0;
}

bool MemoryRegion::Merge(const MemoryRegion &src)
{
	if (type_ == src.type() && end_address_ == src.address()) {
		end_address_ = src.end_address();
		return true;
	}

	return false;
}

MemoryRegion *MemoryRegion::Subtract(uint64_t remove_address, size_t size)
{
	MemoryRegion *res = NULL;
	uint64_t remove_end_address = remove_address + size;
	if (address_ < remove_address)
	{
		if (end_address_ > remove_end_address)
		{
			// create overflow region
			res = new MemoryRegion(*this);
			res->address_ = remove_end_address;
		}
		if (end_address_ > remove_address)
		{
			end_address_ = remove_address;
		}
	} else
	{
		if (address_ < remove_end_address)
		{
			address_ = std::min(end_address_, remove_end_address);
		}
	}
	return res;
}

/**
 * MemoryManager
 */

MemoryManager::MemoryManager(IArchitecture *owner)
	: ObjectList<MemoryRegion>(), owner_(owner)
{

}

void MemoryManager::Add(uint64_t address, size_t size)
{
	Add(address, size, owner_->segment_list()->GetMemoryTypeByAddress(address), NULL);
}

void MemoryManager::Remove(uint64_t address, size_t size)
{
	if (size == 0 || count() == 0)
		return;

	const_iterator it = std::upper_bound(begin(), end(), address, CompareHelper());
	if (it != begin())
		it--;

	for (size_t i = it - begin(); i < count();) {
		MemoryRegion *region = item(i);
		if (region->address() >= address + size)
			break;

		MemoryRegion *sub_region = region->Subtract(address, size);
		if (sub_region) {
			InsertObject(i + 1, sub_region);
			break;
		}

		if (!region->size()) {
			erase(i);
			region->set_owner(NULL);
			delete region;
		} else {
			i++;
		}
	}
}

void MemoryManager::Add(uint64_t address, size_t size, uint32_t type, IFunction *parent_function)
{
	if (!size)
		return;

	const_iterator it = std::lower_bound(begin(), end(), address, CompareHelper());
	size_t index = (it == end()) ? NOT_ID : it - begin();
	if (index != NOT_ID) {
		if (index > 0) {
			MemoryRegion *prev_region = item(index - 1);
			if (prev_region->end_address() > address) {
				if (prev_region->end_address() >= address + size)
					return;
				size = static_cast<size_t>(address + size - prev_region->end_address());
				address = prev_region->end_address();
			}
		}
		MemoryRegion *next_region = item(index);
		if (next_region->end_address() < address + size)
			Add(next_region->end_address(), static_cast<size_t>(address + size - next_region->end_address()), type, parent_function);
		if (next_region->address() < address + size) {
			size = static_cast<size_t>(next_region->address() - address);
			if (!size)
				return;
		}
	}

	MemoryRegion *region = new MemoryRegion(this, address, size, type, parent_function);
	if (index == NOT_ID) {
		AddObject(region);
	} else {
		InsertObject(index, region);
	}
}

size_t MemoryManager::IndexOfAddress(uint64_t address) const
{
	if (count() == 0)
		return NOT_ID;

	const_iterator it = std::upper_bound(begin(), end(), address, CompareHelper());
	if (it != begin())
		it--;

	MemoryRegion *region = *it;
	if (region->address() <= address && region->end_address() > address)
		return (it - begin());

	return NOT_ID;
}

uint64_t MemoryManager::Alloc(size_t size, uint32_t memory_type, uint64_t address, size_t alignment)
{
	size_t i, delta, start, end;
	MemoryRegion *region;
	uint64_t res, tmp_address;

	if (address) {
		start = IndexOfAddress(address);
		if (start == NOT_ID)
			return 0;
		end = start + 1;
	} else {
		start = 0;
		end = count();
	}

	for (i = start; i < end; i++) {
		region = item(i);
		tmp_address = (address) ? address : region->address();
		if (alignment > 1)
			tmp_address = AlignValue(tmp_address, alignment);

		if (region->address() < tmp_address) {
			// need to separate the region
			delta = static_cast<size_t>(tmp_address - region->address());
			if (region->size() < delta + size)
				continue;
				
			// alloc memory for new region
			res = region->Alloc(delta, memory_type);
			if (res == 0)
				continue;

			// insert new region
			InsertObject(i, new MemoryRegion(this, res, delta, (region->type() & mtSolid) ? region->type() & ~mtExecutable : region->type(), region->parent_function()));
			i++;
		}

		res = region->Alloc(size, memory_type);
		if (res) {
			if (!region->size()) {
				erase(i);
				region->set_owner(NULL);
				delete region;
			}
			return res;
		}
	}

	if ((memory_type & mtDiscardable) && !address)
		return Alloc(size, memory_type & (~mtDiscardable), address, alignment);

	return 0;
}

MemoryRegion *MemoryManager::GetRegionByAddress(uint64_t address) const
{
	size_t i = IndexOfAddress(address);
	return (i == NOT_ID) ? NULL : item(i);
}

void MemoryManager::Pack()
{
	for (size_t i = count(); i > 1; i--) {
		MemoryRegion *dst = item(i - 2);
		MemoryRegion *src = item(i - 1);
		if (dst->Merge(*src)) {
			erase(i - 1);
			src->set_owner(NULL);
			delete src;
		}
	}
}

/**
 * CRCTable
 */

CRCTable::CRCTable(ValueCryptor *cryptor, size_t max_size)
	: cryptor_(NULL), max_size_(max_size)
{ 
	manager_ = new MemoryManager(NULL);
	if (cryptor)
		cryptor_ = new CRCValueCryptor(static_cast<uint32_t>(cryptor->item(0)->value()));
}

CRCTable::~CRCTable()
{ 
	delete manager_;
	delete cryptor_;
}

void CRCTable::Add(uint64_t address, size_t size)
{
	manager_->Add(address, size, mtReadable);
}

void CRCTable::Remove(uint64_t address, size_t size)
{
	manager_->Remove(address, size);
}

size_t CRCTable::WriteToFile(IArchitecture &file, bool is_positions, uint32_t *hash)
{
	size_t i;
	std::vector<uint8_t> dump;
	uint64_t address_base = is_positions ? 0 : file.image_base();

	manager_->Pack();

	uint64_t pos = file.Tell();
	crc_info_list_.reserve(manager_->count());
	for (i = 0; i < manager_->count(); i++) {
		MemoryRegion *region = manager_->item(i);

		if (is_positions) {
			file.Seek(region->address());
		} else {
			if (!file.AddressSeek(region->address()))
				continue;
		}

		dump.resize(region->size());
		file.Read(&dump[0], dump.size());
		CRCInfo crc_info(static_cast<uint32_t>(region->address() - address_base), dump);
		 
		crc_info_list_.push_back(crc_info);
	}
	file.Seek(pos);

	// need random order in the vector
	for (i = 0; i < crc_info_list_.size(); i++)
		std::swap(crc_info_list_[i], crc_info_list_[rand() % crc_info_list_.size()]);

	if (cryptor_) {
		for (i = 0; i < crc_info_list_.size(); i++) {
			CRCInfo crc_info = crc_info_list_[i];
			uint32_t address = crc_info.pod.address;
			uint32_t size = crc_info.pod.size;
			crc_info.pod.address = cryptor_->Encrypt(crc_info.pod.address);
			crc_info.pod.size = cryptor_->Encrypt(crc_info.pod.size);
			crc_info.pod.hash = cryptor_->Encrypt(crc_info.pod.hash);
			crc_info_list_[i] = crc_info;
		}
	}

	if (max_size_) {
		size_t max_count = max_size_ / sizeof(CRCInfo::POD);
		if (max_count < crc_info_list_.size())
			crc_info_list_.resize(max_count);
	}

	// write to file
	size_t res = 0;
	if (crc_info_list_.size())
		res = file.Write(&crc_info_list_[0].pod, crc_info_list_.size() * sizeof(CRCInfo::POD));
	if (max_size_) {
		for (size_t i = res; i < max_size_; i += sizeof(uint32_t)) {
			file.WriteDWord(rand32());
		}
	}
	if (hash)
		*hash = CalcCRC(crc_info_list_.size() ? &crc_info_list_[0].pod : NULL, res);
	return res;
}

/**
 * CRCInfo
 */

CRCInfo::CRCInfo(uint32_t address_, const std::vector<uint8_t> &dump)
{
	pod.address = address_;
	pod.size = static_cast<uint32_t>(dump.size());
	pod.hash = CalcCRC(&dump[0], dump.size());
}
