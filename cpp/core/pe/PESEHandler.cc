

#include "../../runtime/common.h"
#include "../objects.h"
#include "../osutils.h"
#include "../streams.h"
#include "../files/architecture.h"
#include "../files/seh.h"
#include "../files/utils.h"
#include "PESEHandler.h"
#include "PEArchitecture.h"

/**
 * PESEHandler
 */


PESEHandler::PESEHandler(ISEHandlerList* owner, uint64_t address)
	: BaseSEHandler(owner), address_(address), deleted_(false)
{

}

PESEHandler::PESEHandler(ISEHandlerList* owner, const PESEHandler& src)
	: BaseSEHandler(owner)
{
	address_ = src.address_;
	deleted_ = src.deleted_;
}

PESEHandler* PESEHandler::Clone(ISEHandlerList* owner) const
{
	PESEHandler* handler = new PESEHandler(owner, *this);
	return handler;
}

void PESEHandler::Rebase(uint64_t delta_base)
{
	address_ += delta_base;
}

/**
* PESEHandlerList
*/

PESEHandlerList::PESEHandlerList()
	: BaseSEHandlerList()
{

}

PESEHandlerList::PESEHandlerList(const PESEHandlerList& src)
	: BaseSEHandlerList(src)
{

}

PESEHandlerList* PESEHandlerList::Clone() const
{
	PESEHandlerList* list = new PESEHandlerList(*this);
	return list;
}

PESEHandler* PESEHandlerList::item(size_t index) const
{
	return reinterpret_cast<PESEHandler*>(BaseSEHandlerList::item(index));
}

PESEHandler* PESEHandlerList::Add(uint64_t address)
{
	PESEHandler* handler = new PESEHandler(this, address);
	AddObject(handler);
	return handler;
}

void PESEHandlerList::Rebase(uint64_t delta_base)
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->Rebase(delta_base);
	}
}

void PESEHandlerList::Pack()
{
	for (size_t i = count(); i > 0; i--) {
		PESEHandler* handler = item(i - 1);
		if (handler->is_deleted())
			delete handler;
	}
}

/**
 * PELoadConfigDirectory
 */

PELoadConfigDirectory::PELoadConfigDirectory()
	: IObject(), seh_table_address_(0), security_cookie_(0), cfg_table_address_(0), guard_flags_(0), cfg_check_function_(0)
{
	seh_handler_list_ = new PESEHandlerList();
	cfg_address_list_ = new PECFGAddressTable();
}

PELoadConfigDirectory::PELoadConfigDirectory(const PELoadConfigDirectory& src)
	: IObject(src)
{
	seh_table_address_ = src.seh_table_address_;
	security_cookie_ = src.security_cookie_;
	cfg_table_address_ = src.cfg_table_address_;
	guard_flags_ = src.guard_flags_;
	cfg_check_function_ = src.cfg_check_function_;
	seh_handler_list_ = src.seh_handler_list_->Clone();
	cfg_address_list_ = src.cfg_address_list_->Clone();
}

PELoadConfigDirectory::~PELoadConfigDirectory()
{
	delete seh_handler_list_;
	delete cfg_address_list_;
}

PELoadConfigDirectory* PELoadConfigDirectory::Clone() const
{
	PELoadConfigDirectory* list = new PELoadConfigDirectory(*this);
	return list;
}

void PELoadConfigDirectory::ReadFromFile(PEArchitecture& file, PEDirectory& dir)
{
	if (!dir.address())
		return;

	if (!file.AddressSeek(dir.address()))
		throw std::runtime_error("Invalid address of the load config directory");

	size_t handler_count;
	size_t cfg_table_count;
	uint64_t pos = file.Tell();
	size_t size = file.ReadDWord();
	file.Seek(pos);
	if (file.cpu_address_size() == osQWord) {
		IMAGE_LOAD_CONFIG_DIRECTORYEX64 load_config_directory = IMAGE_LOAD_CONFIG_DIRECTORYEX64();
		file.Read(&load_config_directory, std::min(sizeof(load_config_directory), size));
		security_cookie_ = load_config_directory.SecurityCookie;
		if (load_config_directory.Size > dir.physical_size())
			dir.set_physical_size(load_config_directory.Size);
		seh_table_address_ = load_config_directory.SEHandlerTable;
		handler_count = static_cast<size_t>(load_config_directory.SEHandlerCount);
		cfg_check_function_ = load_config_directory.GuardCFCheckFunctionPointer;
		cfg_table_address_ = load_config_directory.GuardCFFunctionTable;
		cfg_table_count = static_cast<size_t>(load_config_directory.GuardCFFunctionCount);
		guard_flags_ = load_config_directory.GuardFlags;
	}
	else {
		IMAGE_LOAD_CONFIG_DIRECTORYEX32 load_config_directory = IMAGE_LOAD_CONFIG_DIRECTORYEX32();
		file.Read(&load_config_directory, std::min(sizeof(load_config_directory), size));
		security_cookie_ = load_config_directory.SecurityCookie;
		if (load_config_directory.Size > dir.physical_size())
			dir.set_physical_size(load_config_directory.Size);
		seh_table_address_ = load_config_directory.SEHandlerTable;
		handler_count = load_config_directory.SEHandlerCount;
		cfg_check_function_ = load_config_directory.GuardCFCheckFunctionPointer;
		cfg_table_address_ = load_config_directory.GuardCFFunctionTable;
		cfg_table_count = load_config_directory.GuardCFFunctionCount;
		guard_flags_ = load_config_directory.GuardFlags;
	}

	if (seh_table_address_) {
		if (!file.AddressSeek(seh_table_address_))
			throw std::runtime_error("Invalid address of seh handler table");
		for (size_t i = 0; i < handler_count; i++) {
			seh_handler_list_->Add(file.ReadDWord() + file.image_base());
		}
	}

	if (cfg_table_address_) {
		if (!file.AddressSeek(cfg_table_address_))
			throw std::runtime_error("Invalid address of cfg handler table");
		size_t data_size = (guard_flags_ & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT;
		std::vector<uint8_t> data;
		data.resize(data_size);
		for (size_t i = 0; i < cfg_table_count; i++) {
			PECFGAddress* cfg_address = cfg_address_list_->Add(file.ReadDWord() + file.image_base());
			if (data_size) {
				file.Read(data.data(), data.size());
				cfg_address->set_data(data);
			}
		}
	}
}

size_t PELoadConfigDirectory::WriteToFile(PEArchitecture& file)
{
	PEDirectory* dir = file.command_list()->GetCommandByType(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
	if (!dir || !dir->address())
		return 0;

	size_t res = 0;
	PESegment* last_section = file.segment_list()->last();
	if (seh_table_address_) {
		seh_handler_list_->Pack();
		seh_handler_list_->Sort();
		seh_table_address_ = last_section->address() + file.Resize(AlignValue(file.size(), 0x10)) - last_section->physical_offset();
		for (size_t i = 0; i < seh_handler_list_->count(); i++) {
			res += file.WriteDWord(static_cast<uint32_t>(seh_handler_list_->item(i)->address() - file.image_base()));
		}
	}

	if (cfg_table_address_) {
		cfg_table_address_ = last_section->address() + file.Resize(AlignValue(file.size(), 0x10)) - last_section->physical_offset();
		size_t data_size = (guard_flags_ & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT;
		for (size_t i = 0; i < cfg_address_list_->count(); i++) {
			PECFGAddress* cfg_address = cfg_address_list_->item(i);
			res += file.WriteDWord(static_cast<uint32_t>(cfg_address->address() - file.image_base()));
			if (data_size) {
				std::vector<uint8_t> data = cfg_address->data();
				if (data.empty())
					data.resize(data_size);
				res += file.Write(data.data(), data.size());
			}
		}
	}

	uint64_t pos = file.Tell();
	if (file.AddressSeek(dir->address())) {
		uint64_t config_pos = file.Tell();
		size_t size = file.ReadDWord();
		file.Seek(config_pos);
		if (file.cpu_address_size() == osQWord) {
			IMAGE_LOAD_CONFIG_DIRECTORYEX64 load_config_directory = IMAGE_LOAD_CONFIG_DIRECTORYEX64();
			size = std::min(sizeof(load_config_directory), size);
			file.Read(&load_config_directory, size);
			load_config_directory.SecurityCookie = security_cookie_;
			load_config_directory.SEHandlerTable = seh_table_address_;
			load_config_directory.SEHandlerCount = seh_table_address_ ? seh_handler_list_->count() : 0;
			load_config_directory.GuardCFCheckFunctionPointer = cfg_check_function_;
			load_config_directory.GuardCFFunctionTable = cfg_table_address_;
			load_config_directory.GuardCFFunctionCount = cfg_table_address_ ? cfg_address_list_->count() : 0;
			file.Seek(config_pos);
			file.Write(&load_config_directory, size);
		}
		else {
			IMAGE_LOAD_CONFIG_DIRECTORYEX32 load_config_directory = IMAGE_LOAD_CONFIG_DIRECTORYEX32();
			size = std::min(sizeof(load_config_directory), size);
			file.Read(&load_config_directory, size);
			load_config_directory.SecurityCookie = static_cast<uint32_t>(security_cookie_);
			load_config_directory.SEHandlerTable = static_cast<uint32_t>(seh_table_address_);
			load_config_directory.SEHandlerCount = seh_table_address_ ? static_cast<uint32_t>(seh_handler_list_->count()) : 0;
			load_config_directory.GuardCFCheckFunctionPointer = static_cast<uint32_t>(cfg_check_function_);
			load_config_directory.GuardCFFunctionTable = static_cast<uint32_t>(cfg_table_address_);
			load_config_directory.GuardCFFunctionCount = cfg_table_address_ ? static_cast<uint32_t>(cfg_address_list_->count()) : 0;
			file.Seek(config_pos);
			file.Write(&load_config_directory, size);
		}
	}
	file.Seek(pos);

	return res;
}

void PELoadConfigDirectory::FreeByManager(MemoryManager& manager)
{
	if (seh_table_address_ && seh_handler_list_->count())
		manager.Add(seh_table_address_, OperandSizeToValue(osDWord) * seh_handler_list_->count());

	if (cfg_table_address_ && cfg_address_list_->count()) {
		size_t data_size = (guard_flags_ & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT;
		manager.Add(cfg_table_address_, (OperandSizeToValue(osDWord) + data_size) * cfg_address_list_->count());
	}
}

void PELoadConfigDirectory::Rebase(uint64_t delta_base)
{
	if (seh_table_address_)
		seh_table_address_ += delta_base;
	if (cfg_table_address_)
		cfg_table_address_ += delta_base;
	seh_handler_list_->Rebase(delta_base);
	cfg_address_list_->Rebase(delta_base);
}

/**
* PECFGAddress
*/

PECFGAddress::PECFGAddress(PECFGAddressTable* owner, uint64_t address)
	: IObject(), owner_(owner), address_(address)
{

}

PECFGAddress::PECFGAddress(PECFGAddressTable* owner, const PECFGAddress& src)
	: IObject(), owner_(owner)
{
	address_ = src.address_;
	data_ = src.data_;
}

PECFGAddress::~PECFGAddress()
{
	if (owner_)
		owner_->RemoveObject(this);
}

PECFGAddress* PECFGAddress::Clone(PECFGAddressTable* owner) const
{
	PECFGAddress* res = new PECFGAddress(owner, *this);
	return res;
}

void PECFGAddress::Rebase(uint64_t delta_base)
{
	address_ += delta_base;
}

/**
* PECFGAddressTable
*/

PECFGAddressTable::PECFGAddressTable()
	: ObjectList<PECFGAddress>()
{

}

PECFGAddressTable::PECFGAddressTable(const PECFGAddressTable& src)
	: ObjectList<PECFGAddress>()
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

PECFGAddressTable* PECFGAddressTable::Clone() const
{
	return new PECFGAddressTable(*this);
}

PECFGAddress* PECFGAddressTable::Add(uint64_t address)
{
	PECFGAddress* res = new PECFGAddress(this, address);
	AddObject(res);
	return res;
}

void PECFGAddressTable::Rebase(uint64_t delta_base)
{
	for (size_t i = 0; i < count(); i++) {
		item(i)->Rebase(delta_base);
	}
}
