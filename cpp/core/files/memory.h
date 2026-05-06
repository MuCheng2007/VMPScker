/**
 * Memory management and CRC tables.
 * Rust mapping target: mod memory
 */

#ifndef FILES_MEMORY_H
#define FILES_MEMORY_H

#include "../../runtime/common.h"
#include "../objects.h"
#include "types.h"

class MemoryManager;
class IArchitecture;
class IFunction;
class ValueCryptor;
class CRCValueCryptor;

class MemoryRegion: public IObject
{
public:
	explicit MemoryRegion(MemoryManager *owner, uint64_t address, size_t size, 
		uint32_t type, IFunction *parent_function);
	~MemoryRegion();
	uint64_t address() const { return address_; }
	uint64_t end_address() const { return end_address_; }
	size_t size() const { return static_cast<size_t>(end_address_ - address_); }
	uint32_t type() const { return type_; }
	IFunction *parent_function() const { return parent_function_; }
	uint64_t Alloc(uint64_t memory_size, uint32_t memory_type);
	
	using IObject::CompareWith;
	int CompareWith(const MemoryRegion &obj) const;
	bool Merge(const MemoryRegion &src);
	MemoryRegion *Subtract(uint64_t remove_address, size_t size);
	void exclude_type(MemoryTypeFlags type) { type_ &= ~type; }
	void set_owner(MemoryManager *owner) { owner_ = owner; }
private:
	MemoryManager *owner_;
	uint64_t address_;
	uint64_t end_address_;
	uint32_t type_;
	IFunction *parent_function_;
};

class MemoryManager : public ObjectList<MemoryRegion>
{
public:
	explicit MemoryManager(IArchitecture *owner);
	uint64_t Alloc(size_t size, uint32_t memory_type, uint64_t address = 0, size_t alignment = 0);
	MemoryRegion *GetRegionByAddress(uint64_t address) const;
	void Add(uint64_t address, size_t size);
	void Add(uint64_t address, size_t size, uint32_t type, IFunction *parent_function = NULL);
	void Remove(uint64_t address, size_t size);
	void Pack();
	IArchitecture *owner() const { return owner_; }
private:
	size_t IndexOfAddress(uint64_t address) const;
	struct CompareHelper {
		bool operator () (const MemoryRegion *region, uint64_t address) const
		{
			return (region->address() < address);
		}

		bool operator () (uint64_t address, const MemoryRegion *region) const
		{
			return (address < region->address());
		}
	};

	IArchitecture *owner_;
};

struct CRCInfo {
	struct POD {
		uint32_t address;
		uint32_t size;
		uint32_t hash;
	} pod;

	CRCInfo() 
	{
		pod.address = 0;
		pod.size = 0;
		pod.hash = 0;
	}

	CRCInfo(uint32_t address_, const std::vector<uint8_t> &dump);
};

class CRCTable
{
public:
	CRCTable(ValueCryptor *cryptor, size_t max_size);
	~CRCTable();
	void Add(uint64_t address, size_t size);
	void Remove(uint64_t address, size_t size);
	size_t WriteToFile(IArchitecture &file, bool is_positions, uint32_t *hash = NULL);
private:
	std::vector<CRCInfo> crc_info_list_;
	MemoryManager *manager_;
	CRCValueCryptor *cryptor_;
	size_t max_size_;

	// no copy ctr or assignment op
	CRCTable(const CRCTable &);
	CRCTable &operator =(const CRCTable &);
};

#endif // FILES_MEMORY_H
