/**
 * PE Directory support.
 */

#include "../../runtime/common.h"
#include "../objects.h"
#include "../osutils.h"
#include "../streams.h"
#include "../files.h"
#include "PEDirectory.h"
#include "PEArchitecture.h"


/**
 * PEDirectory
 */

PEDirectory::PEDirectory(PEDirectoryList* owner, uint32_t type)
	: BaseLoadCommand(owner), address_(0), size_(0), type_(type), physical_size_(0)
{

}

PEDirectory::PEDirectory(PEDirectoryList* owner, const PEDirectory& src)
	: BaseLoadCommand(owner, src)
{
	address_ = src.address_;
	size_ = src.size_;
	type_ = src.type_;
	physical_size_ = src.physical_size_;
}

PEDirectory* PEDirectory::Clone(ILoadCommandList* owner) const
{
	PEDirectory* dir = new PEDirectory(reinterpret_cast<PEDirectoryList*>(owner), *this);
	return dir;
}

void PEDirectory::clear()
{
	address_ = 0;
	size_ = 0;
	physical_size_ = 0;
}

void PEDirectory::ReadFromFile(PEArchitecture& file)
{
	IMAGE_DATA_DIRECTORY dir;

	file.Read(&dir, sizeof(IMAGE_DATA_DIRECTORY));

	address_ = (dir.VirtualAddress == 0) ? 0 : dir.VirtualAddress + file.image_base();
	size_ = dir.Size;
}

void PEDirectory::WriteToFile(PEArchitecture& file) const
{
	IMAGE_DATA_DIRECTORY dir;

	dir.VirtualAddress = address_ ? static_cast<uint32_t>(address_ - file.image_base()) : 0;
	dir.Size = size_;

	file.Write(&dir, sizeof(IMAGE_DATA_DIRECTORY));
}

std::string PEDirectory::name() const
{
	switch (type_) {
	case IMAGE_DIRECTORY_ENTRY_EXPORT:
		return std::string("Export");
	case IMAGE_DIRECTORY_ENTRY_IMPORT:
		return std::string("Import");
	case IMAGE_DIRECTORY_ENTRY_RESOURCE:
		return std::string("Resource");
	case IMAGE_DIRECTORY_ENTRY_EXCEPTION:
		return std::string("Exception");
	case IMAGE_DIRECTORY_ENTRY_SECURITY:
		return std::string("Security");
	case IMAGE_DIRECTORY_ENTRY_BASERELOC:
		return std::string("Relocation");
	case IMAGE_DIRECTORY_ENTRY_DEBUG:
		return std::string("Debug");
	case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:
		return std::string("Architecture");
	case IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
		return std::string("Reserved");
	case IMAGE_DIRECTORY_ENTRY_TLS:
		return std::string("Thread Local Storage");
	case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
		return std::string("Configuration");
	case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
		return std::string("Bound Import");
	case IMAGE_DIRECTORY_ENTRY_IAT:
		return std::string("Import Address Table");
	case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
		return std::string("Delay Import");
	case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
		return std::string(".NET MetaData");
	}

	return BaseLoadCommand::name();
}

void PEDirectory::Rebase(uint64_t delta_base)
{
	if (address_)
		address_ += delta_base;
}

void PEDirectory::FreeByManager(MemoryManager& manager)
{
	if (!address() || !physical_size())
		return;

	size_t size = physical_size();
	manager.Add(address_, size);
	IArchitecture* file = manager.owner();
	for (size_t i = 0; i < size; i++) {
		IFixup* fixup = file->fixup_list()->GetFixupByAddress(address_ + i);
		if (fixup)
			fixup->set_deleted(true);
	}
}

/**
 * PEDirectoryList
 */

PEDirectoryList::PEDirectoryList(PEArchitecture* owner)
	: BaseCommandList(owner)
{

}

PEDirectoryList::PEDirectoryList(PEArchitecture* owner, const PEDirectoryList& src)
	: BaseCommandList(owner, src)
{

}

PEDirectory* PEDirectoryList::item(size_t index) const
{
	return reinterpret_cast<PEDirectory*>(BaseCommandList::item(index));
}

PEDirectoryList* PEDirectoryList::Clone(PEArchitecture* owner) const
{
	PEDirectoryList* directory_list = new PEDirectoryList(owner, *this);
	return directory_list;
}

PEDirectory* PEDirectoryList::Add(uint32_t type)
{
	PEDirectory* dir = new PEDirectory(this, type);
	AddObject(dir);
	return dir;
}

PEDirectory* PEDirectoryList::GetCommandByType(uint32_t type) const
{
	return reinterpret_cast<PEDirectory*>(BaseCommandList::GetCommandByType(type));
}

PEDirectory* PEDirectoryList::GetCommandByAddress(uint64_t address) const
{
	for (size_t i = 0; i < count(); i++) {
		PEDirectory* dir = item(i);
		if (dir->address() == address)
			return dir;
	}

	return NULL;
}

void PEDirectoryList::ReadFromFile(PEArchitecture& file, uint32_t count)
{
	for (uint32_t i = 0; i < count; i++) {
		Add(i)->ReadFromFile(file);
	}
}

void PEDirectoryList::WriteToFile(PEArchitecture& file) const
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->WriteToFile(file);
	}
}
