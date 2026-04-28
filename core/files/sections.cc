/**
 * Executable sections and load commands implementations.
 * Rust mapping target: mod sections
 */

#include "sections.h"
#include "../files.h" // IArchitecture definition

/**
 * BaseLoadCommand
 */

BaseLoadCommand::BaseLoadCommand(ILoadCommandList *owner)
	: ILoadCommand(), owner_(owner)
{

}

BaseLoadCommand::BaseLoadCommand(ILoadCommandList *owner, const BaseLoadCommand & /*src*/)
	: ILoadCommand(), owner_(owner)
{

}

BaseLoadCommand::~BaseLoadCommand()
{
	if (owner_)
		owner_->RemoveObject(this);
}

std::string BaseLoadCommand::name() const
{
	return string_format("%d", type());
}

OperandSize BaseLoadCommand::address_size() const
{
	return owner_->owner()->cpu_address_size();
}

/**
 * BaseCommandList
 */

BaseCommandList::BaseCommandList(IArchitecture *owner)
	: ILoadCommandList(), owner_(owner)
{

}

BaseCommandList::BaseCommandList(IArchitecture *owner, const BaseCommandList &src)
	: ILoadCommandList(src), owner_(owner)
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

ILoadCommand *BaseCommandList::GetCommandByType(uint32_t type) const
{
	for (size_t i = 0; i < count(); i++) {
		ILoadCommand *command = item(i);
		if (command->type() == type)
			return command;
	}

	return NULL;
}

void BaseCommandList::Rebase(uint64_t delta_base)
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->Rebase(delta_base);
	}
}

/**
 * BaseSection
 */

BaseSection::BaseSection(ISectionList *owner)
	: ISection(), owner_(owner), write_type_(mtNone), excluded_from_packing_(false), excluded_from_memory_protection_(false), need_parse_(true)
{

}

BaseSection::BaseSection(ISectionList *owner, const BaseSection &src)
	: ISection(), owner_(owner)
{
	write_type_ = src.write_type_;
	excluded_from_packing_ = src.excluded_from_packing_;
	excluded_from_memory_protection_ = src.excluded_from_memory_protection_;
	need_parse_ = src.need_parse_;
}

BaseSection::~BaseSection()
{
 	if (owner_)
		owner_->RemoveObject(this);
}

OperandSize BaseSection::address_size() const
{
	return owner_->owner()->cpu_address_size();
}

void BaseSection::set_excluded_from_packing(bool value)
{ 
	if (excluded_from_packing_ != value) {
		excluded_from_packing_ = value;
		Notify(mtChanged, this);
	}
}

void BaseSection::set_excluded_from_memory_protection(bool value)
{ 
	if (excluded_from_memory_protection_ != value) {
		excluded_from_memory_protection_ = value;
		Notify(mtChanged, this);
	}
}

void BaseSection::Notify(MessageType type, IObject *sender, const std::string &message) const
{
	if (owner_ && owner_->owner())
		owner_->owner()->Notify(type, sender, message);
}

Data BaseSection::hash() const
{
	Data res;
	res.PushBuff(name().c_str(), name().size() + 1);
	res.PushByte(excluded_from_packing());
	res.PushByte(excluded_from_memory_protection());
	return res;
}

/**
 * BaseSectionList
 */

BaseSectionList::BaseSectionList(IArchitecture *owner)
	: ISectionList(), owner_(owner)
{

}

BaseSectionList::BaseSectionList(IArchitecture *owner, const BaseSectionList &src)
	: ISectionList(src), owner_(owner)
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

ISection *BaseSectionList::GetSectionByAddress(uint64_t address) const
{
	for (size_t i = 0; i < count(); i++) {
		ISection *section = item(i);
		if (address >= section->address() && address < section->address() + section->size())
			return section;
	}
	return NULL;
}

ISection *BaseSectionList::GetSectionByOffset(uint64_t offset) const
{
	for (size_t i = 0; i < count(); i++) {
		ISection *section = item(i);
		if (offset >= section->physical_offset() && offset < static_cast<uint64_t>(section->physical_offset()) + static_cast<uint64_t>(section->physical_size()))
			return section;
	}
	return NULL;
}

uint32_t BaseSectionList::GetMemoryTypeByAddress(uint64_t address) const
{
	ISection *section = GetSectionByAddress(address);
	return section ? section->memory_type() : (uint32_t)mtNone;
}

ISection *BaseSectionList::GetSectionByName(const std::string &name) const
{
	for (size_t i = 0; i < count(); i++) {
		ISection *section  = item(i);
		if (section->name() == name)
			return section;
	}
	return NULL;
}

ISection *BaseSectionList::GetSectionByName(ISection *segment, const std::string &name) const
{
	for (size_t i = 0; i < count(); i++) {
		ISection *section = item(i);
		if (section->parent() == segment && section->name() == name)
			return section;
	}
	return NULL;
}

void BaseSectionList::Rebase(uint64_t delta_base)
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->Rebase(delta_base);
	}
}
