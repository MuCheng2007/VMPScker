
#include "../../runtime/common.h"
#include "../../runtime/crypto.h"
#include "../objects.h"
#include "../osutils.h"
#include "../streams.h"
#include "../files/architecture.h"
#include "../files/sections.h"
#include "../files/utils.h"
#include "PESegment.h"
#include "PEArchitecture.h"

/**
 * PESegment
 */

PESegment::PESegment(PESegmentList* owner)
	: BaseSection(owner), address_(0), size_(0), physical_offset_(0), physical_size_(0), flags_(0)
{

}

PESegment::PESegment(PESegmentList* owner, uint64_t address, uint32_t size, uint32_t physical_offset,
	uint32_t physical_size, uint32_t flags, const std::string& name)
	: BaseSection(owner), name_(name), address_(address), size_(size), physical_offset_(physical_offset), physical_size_(physical_size), flags_(flags)
{

}

PESegment::PESegment(PESegmentList* owner, const PESegment& src)
	: BaseSection(owner, src)
{
	address_ = src.address_;
	size_ = src.size_;
	physical_offset_ = src.physical_offset_;
	physical_size_ = src.physical_size_;
	flags_ = src.flags_;
	name_ = src.name_;
}

PESegment* PESegment::Clone(ISectionList* owner) const
{
	PESegment* section = new PESegment(reinterpret_cast<PESegmentList*>(owner), *this);
	return section;
}

void PESegment::ReadFromFile(PEArchitecture& file)
{
	IMAGE_SECTION_HEADER section_header;

	file.Read(&section_header, sizeof(section_header));
	name_ = std::string(reinterpret_cast<char*>(&section_header.Name), strnlen(reinterpret_cast<char*>(&section_header.Name), sizeof(section_header.Name)));
	size_ = section_header.Misc.VirtualSize;
	address_ = section_header.VirtualAddress + file.image_base();
	physical_offset_ = section_header.PointerToRawData;
	physical_size_ = section_header.SizeOfRawData;
	flags_ = section_header.Characteristics;
}

void PESegment::WriteToFile(PEArchitecture& file) const
{
	IMAGE_SECTION_HEADER section_header = IMAGE_SECTION_HEADER();

	memcpy(section_header.Name, name_.c_str(), std::min(name_.size(), sizeof(section_header.Name)));
	section_header.Misc.VirtualSize = size_;
	section_header.VirtualAddress = static_cast<uint32_t>(address_ - file.image_base());
	section_header.PointerToRawData = (physical_size_) ? physical_offset_ : 0;
	section_header.SizeOfRawData = physical_size_;
	section_header.Characteristics = flags_;

	file.Write(&section_header, sizeof(section_header));
}

uint32_t PESegment::memory_type() const
{
	uint32_t res = mtNone;
	if (flags_ & IMAGE_SCN_MEM_READ)
		res |= mtReadable;
	if (flags_ & IMAGE_SCN_MEM_WRITE)
		res |= mtWritable;
	if (flags_ & IMAGE_SCN_MEM_EXECUTE)
		res |= mtExecutable;
	if (flags_ & IMAGE_SCN_MEM_DISCARDABLE)
		res |= mtDiscardable;
	if (flags_ & IMAGE_SCN_MEM_NOT_PAGED)
		res |= mtNotPaged;
	if (flags_ & IMAGE_SCN_MEM_SHARED)
		res |= mtShared;
	return res;
}

void PESegment::update_type(uint32_t mt)
{
	if (mt & mtReadable) {
		flags_ |= IMAGE_SCN_MEM_READ;
		if ((mt & mtExecutable) == 0)
			flags_ |= IMAGE_SCN_CNT_INITIALIZED_DATA;
	}
	if (mt & mtWritable)
		flags_ |= IMAGE_SCN_MEM_WRITE;
	if (mt & mtExecutable)
		flags_ |= IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;
	if ((mt & (mtDiscardable | mtNotDiscardable)) == mtDiscardable)
		flags_ |= IMAGE_SCN_MEM_DISCARDABLE;
	else
		flags_ &= ~IMAGE_SCN_MEM_DISCARDABLE;
	if (mt & mtNotPaged)
		flags_ |= IMAGE_SCN_MEM_NOT_PAGED;
	if (mt & mtShared)
		flags_ |= IMAGE_SCN_MEM_SHARED;
}

void PESegment::Rebase(uint64_t delta_base)
{
	address_ += delta_base;
}

/**
 * PESegmentList
 */

PESegmentList::PESegmentList(PEArchitecture* owner)
	: BaseSectionList(owner), header_segment_(NULL)
{

}

PESegmentList::PESegmentList(PEArchitecture* owner, const PESegmentList& src)
	: BaseSectionList(owner, src), header_segment_(NULL)
{
	if (src.header_segment_)
		header_segment_ = src.header_segment_->Clone(NULL);
}

PESegmentList::~PESegmentList()
{
	delete header_segment_;
}

PESegmentList* PESegmentList::Clone(PEArchitecture* owner) const
{
	PESegmentList* section_list = new PESegmentList(owner, *this);
	return section_list;
}

PESegment* PESegmentList::Add()
{
	PESegment* section = new PESegment(this);
	AddObject(section);
	return section;
}

PESegment* PESegmentList::Add(uint64_t address, uint32_t size, uint32_t physical_offset, uint32_t physical_size, uint32_t flags, const std::string& name)
{
	PESegment* section = new PESegment(this, address, size, physical_offset, physical_size, flags, name);
	AddObject(section);
	return section;
}

PESegment* PESegmentList::item(size_t index) const
{
	return reinterpret_cast<PESegment*>(BaseSectionList::item(index));
}

PESegment* PESegmentList::GetSectionByAddress(uint64_t address) const
{
	PESegment* res = reinterpret_cast<PESegment*>(BaseSectionList::GetSectionByAddress(address));
	if (!res && header_segment_ && address >= header_segment_->address() && address < header_segment_->address() + header_segment_->size())
		res = header_segment_;
	return res;
}

PESegment* PESegmentList::last() const
{
	return reinterpret_cast<PESegment*>(BaseSectionList::last());
}

void PESegmentList::ReadFromFile(PEArchitecture& file, uint32_t count)
{
	Reserve(count);
	for (size_t i = 0; i < count; i++) {
		Add()->ReadFromFile(file);
	}
	if (header_segment_) {
		delete header_segment_;
		header_segment_ = NULL;
	}
	if (this->count()) {
		PESegment* first_segment = item(0);
		header_segment_ = new PESegment(NULL, file.image_base(), static_cast<uint32_t>(first_segment->address() - file.image_base()), 0, first_segment->physical_offset(), 0, ".header");
	}
}

void PESegmentList::WriteToFile(PEArchitecture& file) const
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->WriteToFile(file);
	}
}

/**
 * PESection
 */

PESection::PESection(PESectionList* owner, PESegment* parent, uint64_t address, uint64_t size, const std::string& name)
	: BaseSection(owner), name_(name), address_(address), size_(size), parent_(parent)
{

}

PESection::PESection(PESectionList* owner, const PESection& src)
	: BaseSection(owner, src)
{
	address_ = src.address_;
	size_ = src.size_;
	name_ = src.name_;
	parent_ = src.parent_;
}

PESection* PESection::Clone(ISectionList* owner) const
{
	PESection* section = new PESection(reinterpret_cast<PESectionList*>(owner), *this);
	return section;
}

void PESection::Rebase(uint64_t delta_base)
{
	address_ += delta_base;
}

/**
 * PESectionList
 */

PESectionList::PESectionList(PEArchitecture* owner)
	: BaseSectionList(owner)
{

}

PESectionList::PESectionList(PEArchitecture* owner, const PESectionList& src)
	: BaseSectionList(owner, src)
{

}

PESectionList* PESectionList::Clone(PEArchitecture* owner) const
{
	PESectionList* section_list = new PESectionList(owner, *this);
	return section_list;
}

PESection* PESectionList::item(size_t index) const
{
	return reinterpret_cast<PESection*>(BaseSectionList::item(index));
}

PESection* PESectionList::Add(PESegment* parent, uint64_t address, uint64_t size, const std::string& name)
{
	PESection* section = new PESection(this, parent, address, size, name);
	AddObject(section);
	return section;
}
