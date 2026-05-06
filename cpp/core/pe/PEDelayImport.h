#ifndef PE_DELAY_IMPORT_H
#define PE_DELAY_IMPORT_H

#include "../objects.h"

class PEArchitecture;
class PEDirectory;
class PEDelayImport;
class PEDelayImportList;

class PEDelayImportFunction : public IObject
{
public:
	explicit PEDelayImportFunction(PEDelayImport *owner);
	explicit PEDelayImportFunction(PEDelayImport *owner, const PEDelayImportFunction &src);
	~PEDelayImportFunction();
	PEDelayImportFunction *Clone(PEDelayImport *owner) const;
	bool ReadFromFile(PEArchitecture &file, uint64_t add_value);
	std::string name() const { return name_; }
	bool is_ordinal() const { return is_ordinal_; }
	uint32_t ordinal() const { return ordinal_; }
private:
	PEDelayImport *owner_;

	std::string name_;
	bool is_ordinal_;
	uint32_t ordinal_;
};

class PEDelayImport : public ObjectList<PEDelayImportFunction>
{
public:
	explicit PEDelayImport(PEDelayImportList *owner);
	explicit PEDelayImport(PEDelayImportList *owner, const PEDelayImport &src);
	~PEDelayImport();
	PEDelayImport *Clone(PEDelayImportList *owner) const;
	bool ReadFromFile(PEArchitecture &file);
	virtual std::string name() const { return name_; }
	uint32_t flags() const { return flags_; }
	uint64_t module() const { return module_; }
	uint64_t iat() const { return iat_; }
	uint64_t bound_iat() const { return bound_iat_; }
	uint64_t unload_iat() const { return unload_iat_; }
	uint32_t time_stamp() const { return time_stamp_; }
private:
	PEDelayImportList *owner_;

	std::string name_;
	uint32_t flags_;
	uint64_t module_;
	uint64_t iat_;
	uint64_t bound_iat_;
	uint64_t unload_iat_;
	uint32_t time_stamp_;
};

class PEDelayImportList : public ObjectList<PEDelayImport>
{
public:
	explicit PEDelayImportList();
	explicit PEDelayImportList(const PEDelayImportList &src);
	PEDelayImportList *Clone() const;
	void ReadFromFile(PEArchitecture &file, PEDirectory &dir);
};

#endif // PE_DELAY_IMPORT_H
