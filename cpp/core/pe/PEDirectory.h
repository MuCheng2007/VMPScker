/**
 * PE Directory support.
 */

#ifndef PE_DIRECTORY_H
#define PE_DIRECTORY_H

#include "../files/sections.h"
#include "../files/memory.h"

class PEArchitecture;
class PEDirectoryList;

class PEDirectory : public BaseLoadCommand
{
public:
	explicit PEDirectory(PEDirectoryList *owner, uint32_t type);
	explicit PEDirectory(PEDirectoryList *owner, const PEDirectory &src);
	virtual uint64_t address() const { return address_; }
	virtual uint32_t size() const { return size_; }
	virtual uint32_t type() const { return type_; }
	uint32_t physical_size() const { return physical_size_ ? physical_size_ : size_; }
	void set_physical_size(uint32_t physical_size) { physical_size_ = physical_size; }
	virtual std::string name() const;
	void ReadFromFile(PEArchitecture &file);
	void WriteToFile(PEArchitecture &file) const;
	virtual PEDirectory *Clone(ILoadCommandList *owner) const;
	void clear();
	void set_address(uint64_t address) { address_ = address; }
	void set_size(uint32_t size) { size_ = size; }
	void Rebase(uint64_t delta_base);
	virtual bool visible() const { return (address_ || size_); }
	void FreeByManager(MemoryManager &manager);
private:
	uint64_t address_;
	uint32_t size_;
	uint32_t type_;
	uint32_t physical_size_;
};

class PEDirectoryList : public BaseCommandList
{
public:
	explicit PEDirectoryList(PEArchitecture *owner);
	explicit PEDirectoryList(PEArchitecture *owner, const PEDirectoryList &src);
	PEDirectoryList *Clone(PEArchitecture *owner) const;
	PEDirectory *item(size_t index) const;
	void ReadFromFile(PEArchitecture &file, uint32_t count);
	void WriteToFile(PEArchitecture &file) const;
	PEDirectory *GetCommandByType(uint32_t type) const;
	PEDirectory *GetCommandByAddress(uint64_t address) const;
private:
	PEDirectory *Add(uint32_t type);
};

#endif // PE_DIRECTORY_H
