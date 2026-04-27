/**
 * PE Import support.
 */

#ifndef PE_IMPORT_H
#define PE_IMPORT_H

#include "../files.h"

class PEArchitecture;
class PEDirectory;
class PEImport;
class PEImportList;

class PEImportFunction : public BaseImportFunction
{
public:
	explicit PEImportFunction(PEImport *owner);
	explicit PEImportFunction(PEImport *owner, const std::string &name);
	explicit PEImportFunction(PEImport *owner, uint64_t address, APIType type, MapFunction *map_function);
	explicit PEImportFunction(PEImport *owner, const PEImportFunction &src);
	virtual PEImportFunction *Clone(IImport *owner) const;
	bool ReadFromFile(PEArchitecture &arch, uint32_t &rva);
	virtual uint64_t address() const { return address_; }
	virtual std::string name() const { return name_; }
	bool is_ordinal() const { return is_ordinal_; }
	uint32_t ordinal() const { return ordinal_; }
	void FreeByManager(MemoryManager &manager, bool free_iat);
	virtual void Rebase(uint64_t delta_base);
	virtual std::string display_name(bool show_ret = true) const;
	bool IsInternal(const CompileContext &ctx) const;
private:
	std::string name_;
	uint64_t name_address_;
	uint64_t address_;
	bool is_ordinal_;
	uint32_t ordinal_;
};

class PEImport : public BaseImport
{
public:
	explicit PEImport(PEImportList *owner);
	explicit PEImport(PEImportList *owner, bool is_sdk);
	explicit PEImport(PEImportList *owner, const std::string &name);
	explicit PEImport(PEImportList *owner, const PEImport &src);
	virtual PEImport *Clone(IImportList *owner) const;
	PEImportFunction *item(size_t index) const;
	bool ReadFromFile(PEArchitecture &file);
	void WriteToFile(PEArchitecture &file) const;
	virtual std::string name() const { return name_; }
	virtual bool is_sdk() const { return is_sdk_; }
	bool FreeByManager(MemoryManager &manager, bool free_iat);
	virtual void Rebase(uint64_t delta_base);
	void set_name(const std::string &name) { name_ = name; }
protected:
	virtual	PEImportFunction *Add(uint64_t address, APIType type, MapFunction *map_function);
private:
	std::string name_;
	uint64_t name_address_;
	bool is_sdk_;
	uint64_t original_first_thunk_address_;
	uint64_t first_thunk_address_;
	uint32_t time_stamp_;
	uint32_t forwarder_chain_;
};

class PEImportList : public BaseImportList
{
public:
	explicit PEImportList(PEArchitecture *owner);
	explicit PEImportList(PEArchitecture *owner, const PEImportList &src);
	virtual PEImportList *Clone(PEArchitecture *owner) const;
	PEImport *item(size_t index) const;
	virtual PEImportFunction *GetFunctionByAddress(uint64_t address) const;
	void ReadFromFile(PEArchitecture &file, PEDirectory &dir);
	void FreeByManager(MemoryManager &manager, bool free_iat);
	virtual void Rebase(uint64_t delta_base);
	void WriteToFile(PEArchitecture &file, bool skip_sdk = false) const;
protected:
	virtual PEImport *AddSDK();
private:
	uint64_t address_;
};

#endif // PE_IMPORT_H
