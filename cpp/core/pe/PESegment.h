/**
 * PE Segment/Section support.
 */

#ifndef PE_SEGMENT_H
#define PE_SEGMENT_H

#include "../files/sections.h"

class PEArchitecture;
class PESegmentList;
class PESectionList;

class PESegment : public BaseSection
{
public:
	explicit PESegment(PESegmentList *owner);
	explicit PESegment(PESegmentList *owner, uint64_t address, uint32_t size, uint32_t physical_offset, 
		uint32_t physical_size, uint32_t flags, const std::string &name);
	explicit PESegment(PESegmentList *owner, const PESegment &src);
	virtual uint64_t address() const { return address_; }
	virtual uint64_t size() const { return size_; }
	virtual uint32_t physical_offset() const { return physical_offset_; }
	virtual uint32_t physical_size() const { return physical_size_; }
	virtual std::string name() const { return name_; }
	virtual uint32_t memory_type() const;
	virtual uint32_t flags() const { return flags_; }
	void set_flags(uint32_t flags) { flags_ = flags; }
	void set_size(uint32_t size) { size_ = size; }
	void set_physical_size(uint32_t size) { physical_size_ = size; }
	void set_physical_offset(uint32_t offset) { physical_offset_ = offset; }
	void set_name(const std::string &name) { name_ = name; }
	void ReadFromFile(PEArchitecture &file);
	void WriteToFile(PEArchitecture &file) const;
	virtual PESegment *Clone(ISectionList *owner) const;
	virtual void update_type(uint32_t mt);
	virtual void Rebase(uint64_t delta_base);
private:
	std::string name_;
	uint64_t address_;
	uint32_t size_;
	uint32_t physical_offset_;
	uint32_t physical_size_;
	uint32_t flags_;
};

class PESegmentList : public BaseSectionList
{
public:
	explicit PESegmentList(PEArchitecture *owner);
	explicit PESegmentList(PEArchitecture *owner, const PESegmentList &src);
	~PESegmentList();
	PESegmentList *Clone(PEArchitecture *owner) const;
	PESegment *item(size_t index) const;
	PESegment *GetSectionByAddress(uint64_t address) const;
	void ReadFromFile(PEArchitecture &file, uint32_t count);
	void WriteToFile(PEArchitecture &file) const;
	PESegment *last() const;
	PESegment *Add(uint64_t address, uint32_t size, uint32_t physical_offset, uint32_t physical_size, uint32_t flags, const std::string &name);
	PESegment *header_segment() const { return header_segment_; }
private:
	PESegment *Add();

	PESegment *header_segment_;

	// no copy ctr or assignment op
	PESegmentList(const PESegmentList &);
	PESegmentList &operator =(const PESegmentList &);
};

class PESection : public BaseSection
{
public:
	explicit PESection(PESectionList *owner, PESegment *parent, uint64_t address, uint64_t size, const std::string &name);
	explicit PESection(PESectionList *owner, const PESection &src);
	virtual std::string name() const { return name_; }
	virtual uint64_t address() const { return address_; }
	virtual uint64_t size() const { return size_; }
	virtual uint32_t physical_offset() const { return parent_->physical_offset() + static_cast<uint32_t>(address_ - parent_->address()); }
	virtual uint32_t physical_size() const { return static_cast<uint32_t>(size_); }
	virtual uint32_t memory_type() const { return parent_->memory_type(); }
	virtual uint32_t flags() const { return 0; }
	virtual void update_type(uint32_t mt) {}
	virtual PESection *Clone(ISectionList *owner) const;
	virtual void Rebase(uint64_t delta_base);
	virtual PESegment *parent() const { return parent_; }
	void set_parent(PESegment *parent) { parent_ = parent; }
private:
	std::string name_;
	uint64_t address_;
	uint64_t size_;
	PESegment *parent_;
};

class PESectionList : public BaseSectionList
{
public:
	explicit PESectionList(PEArchitecture *owner);
	explicit PESectionList(PEArchitecture *owner, const PESectionList &src);
	virtual PESectionList *Clone(PEArchitecture *owner) const;
	PESection *item(size_t index) const;
	PESection *Add(PESegment *parent, uint64_t address, uint64_t size, const std::string &name);
};

#endif // PE_SEGMENT_H
