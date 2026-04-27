/**
 * PE TLS Directory support.
 */

#ifndef PE_TLS_H
#define PE_TLS_H

#include "../files.h"

class PEArchitecture;
class PEDirectory;

class PETLSDirectory : public ReferenceList
{
public:
	explicit PETLSDirectory();
	explicit PETLSDirectory(const PETLSDirectory &src);
	PETLSDirectory *Clone() const;
	void ReadFromFile(PEArchitecture &file, PEDirectory &directory);
	void FreeByManager(MemoryManager &manager);
	uint64_t address() const { return address_; }
	uint64_t start_address_of_raw_data() const { return start_address_of_raw_data_; }
	uint64_t end_address_of_raw_data() const { return end_address_of_raw_data_; }
	uint64_t address_of_index() const { return address_of_index_; }
	uint64_t address_of_call_backs() const { return address_of_call_backs_; }
	uint32_t size_of_zero_fill() const { return size_of_zero_fill_; }
	uint32_t characteristics() const { return characteristics_; }
	void set_start_address_of_raw_data(uint64_t value) { start_address_of_raw_data_ = value; }
	void set_end_address_of_raw_data(uint64_t value) { end_address_of_raw_data_ = value; }
private:
	uint64_t address_;
	uint64_t start_address_of_raw_data_;
	uint64_t end_address_of_raw_data_;
	uint64_t address_of_index_;
	uint64_t address_of_call_backs_;
	uint32_t size_of_zero_fill_;
	uint32_t characteristics_;

	// no assignment op
	PETLSDirectory &operator =(const PETLSDirectory &);
};

#endif // PE_TLS_H
