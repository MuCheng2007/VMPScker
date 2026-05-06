/**
 * Executable sections and load commands abstractions.
 * Rust mapping target: mod sections
 */

#ifndef FILES_SECTIONS_H
#define FILES_SECTIONS_H

#include "../../runtime/common.h"
#include "../objects.h"
#include "types.h"

class IArchitecture;

// ---------------------------------------------------------------------------
// Load Commands (Format-specific chunks like Mach-O segments/commands)
// ---------------------------------------------------------------------------

class ILoadCommandList;

class ILoadCommand : public IObject
{
public:
	virtual uint64_t address() const = 0;
	virtual uint32_t size() const = 0;
	virtual uint32_t type() const = 0;
	virtual std::string name() const = 0;
	virtual bool visible() const = 0;
	virtual void Rebase(uint64_t delta_base) = 0;
	virtual ILoadCommand *Clone(ILoadCommandList *owner) const = 0;
	virtual OperandSize address_size() const = 0;
	virtual ILoadCommandList *owner() const = 0;
};

class ILoadCommandList : public ObjectList<ILoadCommand>
{
public:
	virtual ILoadCommand *GetCommandByType(uint32_t type) const = 0;
	virtual void Rebase(uint64_t delta_base) = 0;
	virtual IArchitecture *owner() const = 0;
};

class BaseLoadCommand : public ILoadCommand
{
public:
	explicit BaseLoadCommand(ILoadCommandList *owner);
	explicit BaseLoadCommand(ILoadCommandList *owner, const BaseLoadCommand &src);
	~BaseLoadCommand();
	virtual std::string name() const;
	virtual bool visible() const { return true; }
	virtual OperandSize address_size() const;
	ILoadCommandList *owner() const { return owner_; }
private:
	ILoadCommandList *owner_;
};

class BaseCommandList : public ILoadCommandList
{
public:
	explicit BaseCommandList(IArchitecture *owner);
	explicit BaseCommandList(IArchitecture *owner, const BaseCommandList &src);
	virtual ILoadCommand *GetCommandByType(uint32_t type) const;
	virtual void Rebase(uint64_t delta_base);
	virtual IArchitecture *owner() const { return owner_; }
private:
	IArchitecture *owner_;
};

// ---------------------------------------------------------------------------
// Sections (PE sections, Mach-O sections/segments, ELF segments)
// ---------------------------------------------------------------------------

class ISectionList;

class ISection : public IObject
{
public:
	virtual uint64_t address() const = 0;
	virtual uint64_t size() const = 0;
	virtual uint32_t physical_offset() const = 0;
	virtual uint32_t physical_size() const = 0;
	virtual std::string name() const = 0;
	virtual uint32_t memory_type() const = 0;
	virtual void include_write_type(uint32_t write_type) = 0;
	virtual uint32_t write_type() const = 0;
	virtual void update_type(uint32_t mt) = 0;
	virtual ISection *parent() const = 0;
	virtual uint32_t flags() const = 0;
	virtual void Rebase(uint64_t delta_base) = 0;
	virtual ISection *Clone(ISectionList *owner) const = 0;
	virtual bool excluded_from_packing() const = 0;
	virtual void set_excluded_from_packing(bool value) = 0;
	virtual bool excluded_from_memory_protection() const = 0;
	virtual void set_excluded_from_memory_protection(bool value) = 0;
	virtual OperandSize address_size() const = 0;
	virtual Data hash() const = 0;
	virtual bool need_parse() const = 0;
	virtual ISectionList *owner() const = 0;
};

class ISectionList : public ObjectList<ISection>
{
public:
	virtual ISection *GetSectionByAddress(uint64_t address) const = 0;
	virtual ISection *GetSectionByOffset(uint64_t offset) const = 0;
	virtual ISection *GetSectionByName(const std::string &name) const = 0;
	virtual ISection *GetSectionByName(ISection *segment, const std::string &name) const = 0;
	virtual uint32_t GetMemoryTypeByAddress(uint64_t address) const = 0;
	virtual void Rebase(uint64_t delta_base) = 0;
	virtual IArchitecture *owner() const = 0;
};

class BaseSection : public ISection
{
public:
	explicit BaseSection(ISectionList *owner);
	explicit BaseSection(ISectionList *owner, const BaseSection &src);
	~BaseSection();
	virtual uint32_t write_type() const { return write_type_; }
	virtual void include_write_type(uint32_t write_type) { write_type_ |= write_type; }
	virtual ISection *parent() const { return NULL; }
	virtual bool excluded_from_packing() const { return excluded_from_packing_; };
	virtual void set_excluded_from_packing(bool value);
	virtual bool excluded_from_memory_protection() const { return excluded_from_memory_protection_; };
	virtual void set_excluded_from_memory_protection(bool value);
	virtual OperandSize address_size() const;
	virtual Data hash() const;
	virtual bool need_parse() const { return need_parse_; }
	void set_need_parse(bool value) { need_parse_ = value; }
	virtual ISectionList *owner() const { return owner_; }
private:
	void Notify(MessageType type, IObject *sender, const std::string &message = "") const;
	ISectionList *owner_;
	uint32_t write_type_;
	bool excluded_from_packing_;
	bool excluded_from_memory_protection_;
	bool need_parse_;
};

class BaseSectionList : public ISectionList
{
public:
	explicit BaseSectionList(IArchitecture *owner);
	explicit BaseSectionList(IArchitecture *owner, const BaseSectionList &src);
	virtual ISection *GetSectionByAddress(uint64_t address) const;
	virtual ISection *GetSectionByOffset(uint64_t offset) const;
	virtual ISection *GetSectionByName(const std::string &name) const;
	virtual ISection *GetSectionByName(ISection *segment, const std::string &name) const;
	virtual uint32_t GetMemoryTypeByAddress(uint64_t address) const;
	virtual void Rebase(uint64_t delta_base);
	virtual IArchitecture *owner() const { return owner_; }
private:
	IArchitecture *owner_;
};

#endif // FILES_SECTIONS_H
