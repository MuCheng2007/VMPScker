/**
 * PE Fixup/Relocation support.
 */

#ifndef PE_FIXUP_H
#define PE_FIXUP_H

#include "../files.h"

class PEArchitecture;
class PEFixupList;
class PEDirectory;
class PERelocationList;

class PEFixup : public BaseFixup
{
public:
	explicit PEFixup(PEFixupList *owner, uint64_t address, uint8_t type);
	explicit PEFixup(PEFixupList *owner, const PEFixup &src);
	virtual uint64_t address() const { return address_; }
	virtual FixupType type() const;
	virtual OperandSize size() const;
	virtual PEFixup *Clone(IFixupList *owner) const;
	uint8_t internal_type() const { return type_; }
	virtual void set_address(uint64_t address) { address_ = address; }
	virtual void Rebase(IArchitecture &file, uint64_t delta_base);
private:
	uint64_t address_;
	uint8_t type_;
};

class PEFixupList : public BaseFixupList
{
public:
	explicit PEFixupList();
	explicit PEFixupList(const PEFixupList &src);
	virtual PEFixupList *Clone() const;
	PEFixup *item(size_t index) const;
	void ReadFromFile(PEArchitecture &file, PEDirectory &dir);
	void WriteToData(Data &data, uint64_t image_base);
	size_t WriteToFile(PEArchitecture &file);
	virtual IFixup *AddDefault(OperandSize cpu_address_size, bool is_code);
private:
	PEFixup *Add(uint64_t address, uint8_t type);

	// no assignment op
	PEFixupList &operator =(const PEFixupList &);
};

class PERelocation : public BaseRelocation
{
public:
	explicit PERelocation(PERelocationList *owner, uint64_t address, uint64_t source, OperandSize size, uint32_t addend);
	explicit PERelocation(PERelocationList *owner, const PERelocation &src);
	virtual PERelocation *Clone(IRelocationList *owner) const;
	uint64_t source() const { return source_; }
	uint32_t addend() const { return addend_; }
	virtual ISymbol *symbol() const { return NULL; }
private:
	uint64_t source_;
	uint32_t addend_;
};

class PERelocationList : public BaseRelocationList
{
public:
	explicit PERelocationList();
	explicit PERelocationList(const PERelocationList &src);
	virtual PERelocationList *Clone() const;
	PERelocation *item(size_t index) const;
	void ReadFromFile(PEArchitecture &file);
	void WriteToData(Data &data, uint64_t image_base);
private:
	void ParseMinGW(PEArchitecture &file, uint64_t address, uint64_t start, uint64_t end);
	PERelocation *Add(uint64_t address, uint64_t source, OperandSize size, uint32_t addend);
	uint64_t address_;
	uint64_t mem_address_;

	// no assignment op
	PERelocationList &operator =(const PERelocationList &);
};

#endif // PE_FIXUP_H
