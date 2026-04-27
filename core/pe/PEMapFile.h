/**
 * PE Map File support (PDB/COFF).
 */

#ifndef PE_MAP_FILE_H
#define PE_MAP_FILE_H

#include "../files.h"

class FileStream;
class PEArchitecture;

class COFFStringTable
{
public:
	std::string GetString(uint32_t pos) const;
	void ReadFromFile(PEArchitecture &file);
	void ReadFromFile(FileStream &file);
private:
	std::vector<char> data_;
};

class COFFFile : public BaseMapFile
{
public:
	bool Parse(const char *file_name, const std::vector<uint64_t> &segments);
	virtual std::string file_name() const { return file_name_; }
	virtual uint64_t time_stamp() const { return time_stamp_; }
private:
	void AddSymbol(size_t segment, size_t offset, const std::string &name);
	uint64_t time_stamp_;
	std::string file_name_;
	std::vector<uint64_t> segments_;
};

class pdb_reader;

class PDBFile : public BaseMapFile
{
public:
	explicit PDBFile();
	virtual bool Parse(const char *file_name, const std::vector<uint64_t> &segments);
	virtual std::string file_name() const { return file_name_; }
	virtual uint64_t time_stamp() const { return time_stamp_; }
	std::vector<uint8_t> guid() const { return guid_; }
	void set_time_stamp(uint64_t value) { time_stamp_ = value; }
private:
	bool ReadSymbols(pdb_reader &reader);
	void codeview_dump_symbols(const std::vector<uint8_t> &root, size_t offset);
	std::string GetTypeName(size_t type, const std::string &name);
	void AddSymbol(size_t segment, size_t offset, const std::string &name);
	void AddSection(size_t segment, size_t offset, uint64_t size, const std::string &name);

	std::string file_name_;
	uint64_t time_stamp_;
	std::vector<uint8_t> guid_;
	std::vector<uint64_t> segments_;
	size_t types_first_index_;
	std::vector<uint8_t> types_data_;
	std::vector<const union codeview_type *> types_offset_;
	std::set<std::pair<uint64_t, std::string> > map_;
};

#endif // PE_MAP_FILE_H
