#ifndef PE_DEBUG_H
#define PE_DEBUG_H

#include "../objects.h"

class PEArchitecture;
class PEDirectory;
class PEDebugDirectory;

class PEDebugData : public IObject
{
public:
	explicit PEDebugData(PEDebugDirectory *owner);
	explicit PEDebugData(PEDebugDirectory *owner, const PEDebugData &src);
	~PEDebugData();
	PEDebugData *Clone(PEDebugDirectory *owner) const;
	void ReadFromFile(PEArchitecture &file);
	void WriteToFile(PEArchitecture &file);
	uint64_t address() const { return address_; }
	uint32_t offset() const { return offset_; }
	uint32_t size() const { return size_; }
	uint32_t type() const { return type_; }
	void set_address(uint64_t address) { address_ = address; }
	void set_offset(uint32_t offset) { offset_ = offset; }
private:
	PEDebugDirectory *owner_;
    uint32_t characteristics_;
    uint32_t time_date_stamp_;
    uint16_t major_version_;
    uint16_t minor_version_;
    uint32_t type_;
    uint32_t size_;
    uint64_t address_;
	uint32_t offset_;
};

class PEDebugDirectory : public ObjectList<PEDebugData>
{
public:
	explicit PEDebugDirectory();
	explicit PEDebugDirectory(const PEDebugDirectory &src);
	PEDebugDirectory *Clone() const;
	uint64_t address() const { return address_; }
	void ReadFromFile(PEArchitecture &file, PEDirectory &directory);
	void WriteToFile(PEArchitecture &file);
	void FreeByManager(MemoryManager &manager) const;
private:
	PEDebugData *Add();
	uint64_t address_;

	// not impl
	PEDebugDirectory &operator =(const PEDebugDirectory &);
};

#endif // PE_DEBUG_H
