
#include "../../runtime/common.h"
#include "../objects.h"
#include "../osutils.h"
#include "../streams.h"
#include "../files/architecture.h"
#include "../files/fixups.h"
#include "../files/relocations.h"
#include "../files/utils.h"
#include "../files/compiler_func.h"
#include "PEFixup.h"
#include "PEDirectory.h"
#include "PEArchitecture.h"

/**
 * PEFixup
 */

PEFixup::PEFixup(PEFixupList* owner, uint64_t address, uint8_t type)
	: BaseFixup(owner), address_(address), type_(type)
{

}

PEFixup::PEFixup(PEFixupList* owner, const PEFixup& src)
	: BaseFixup(owner, src)
{
	address_ = src.address_;
	type_ = src.type_;
}

PEFixup* PEFixup::Clone(IFixupList* owner) const
{
	PEFixup* fixup = new PEFixup(reinterpret_cast<PEFixupList*>(owner), *this);
	return fixup;
}

FixupType PEFixup::type() const
{
	switch (type_) {
	case IMAGE_REL_BASED_HIGH:
		return ftHigh;
	case IMAGE_REL_BASED_LOW:
		return ftLow;
	case IMAGE_REL_BASED_HIGHLOW:
	case IMAGE_REL_BASED_DIR64:
		return ftHighLow;
	default:
		return ftUnknown;
	}
}

OperandSize PEFixup::size() const
{
	return type_ == IMAGE_REL_BASED_DIR64 ? osQWord : osDWord;
}

void PEFixup::Rebase(IArchitecture& file, uint64_t delta_base)
{
	if (!file.AddressSeek(address_))
		return;

	uint64_t pos = file.Tell();
	uint64_t value;
	switch (type_) {
	case IMAGE_REL_BASED_LOW:
		value = file.ReadWord();
		value += delta_base;
		file.Seek(pos);
		file.WriteWord(static_cast<uint16_t>(value));
		break;
	case IMAGE_REL_BASED_HIGH:
		value = file.ReadWord();
		value += delta_base >> 16;
		file.Seek(pos);
		file.WriteWord(static_cast<uint16_t>(value));
		break;
	case IMAGE_REL_BASED_HIGHLOW:
		value = file.ReadDWord();
		value += delta_base;
		file.Seek(pos);
		file.WriteDWord(static_cast<uint32_t>(value));
		break;
	case IMAGE_REL_BASED_DIR64:
		value = file.ReadQWord();
		value += delta_base;
		file.Seek(pos);
		file.WriteQWord(value);
		break;
	}
	address_ += delta_base;
}

/**
 * PEFixupList
 */

PEFixupList::PEFixupList()
	: BaseFixupList()
{

}

PEFixupList::PEFixupList(const PEFixupList& src)
	: BaseFixupList(src)
{

}

PEFixup* PEFixupList::item(size_t index) const
{
	return reinterpret_cast<PEFixup*>(BaseFixupList::item(index));
}

PEFixupList* PEFixupList::Clone() const
{
	PEFixupList* fixup_list = new PEFixupList(*this);
	return fixup_list;
}

PEFixup* PEFixupList::Add(uint64_t address, uint8_t type)
{
	PEFixup* fixup = new PEFixup(this, address, type);
	AddObject(fixup);
	return fixup;
}

IFixup* PEFixupList::AddDefault(OperandSize cpu_address_size, bool is_code)
{
	return Add(0, (cpu_address_size == osDWord) ? IMAGE_REL_BASED_HIGHLOW : IMAGE_REL_BASED_DIR64);
}

void PEFixupList::ReadFromFile(PEArchitecture& file, PEDirectory& dir)
{
	if (!dir.address())
		return;

	if (!file.AddressSeek(dir.address()))
		throw std::runtime_error("Invalid address of the base relocation table");

	IMAGE_BASE_RELOCATION reloc;
	for (uint32_t processed = 0; processed < dir.size(); processed += reloc.SizeOfBlock) {
		file.Read(&reloc, sizeof(reloc));
		if (reloc.SizeOfBlock == 0)
			break;

		if (reloc.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || (reloc.SizeOfBlock & 1) != 0)
			throw std::runtime_error("Invalid size of the base relocation block");

		size_t c = (reloc.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) >> 1;
		for (size_t i = 0; i < c; i++) {
			uint16_t type_offset = file.ReadWord();
			uint8_t type = (type_offset >> 12);
			if (type == IMAGE_REL_BASED_ABSOLUTE)
				continue;

			PEFixup* fixup = Add(reloc.VirtualAddress + file.image_base() + (type_offset & 0xfff), type);
			if (fixup->type() == ftUnknown)
				throw std::runtime_error("Invalid base relocation type");
		}
	}
}

void PEFixupList::WriteToData(Data& data, uint64_t image_base)
{
	Sort();

	size_t size_pos = 0;
	IMAGE_BASE_RELOCATION reloc = IMAGE_BASE_RELOCATION();
	uint16_t empty_offset = 0;
	for (size_t i = 0; i < count(); i++) {
		PEFixup* fixup = item(i);
		uint32_t rva = static_cast<uint32_t>(fixup->address() - image_base);
		uint32_t block_rva = rva & 0xfffff000;
		if (reloc.SizeOfBlock == 0 || block_rva != reloc.VirtualAddress) {
			if (reloc.SizeOfBlock) {
				if (reloc.SizeOfBlock & 3) {
					data.PushWord(empty_offset);
					reloc.SizeOfBlock += sizeof(empty_offset);
				}
				data.WriteDWord(size_pos, reloc.SizeOfBlock);
			}
			size_pos = data.size() + 4;
			reloc.VirtualAddress = block_rva;
			reloc.SizeOfBlock = sizeof(reloc);
			data.PushBuff(&reloc, sizeof(reloc));
			empty_offset = (static_cast<uint16_t>(rva - block_rva) & 0xf00) << 4 | IMAGE_REL_BASED_ABSOLUTE;
		}
		uint16_t type_offset = (static_cast<uint16_t>(rva - block_rva) & 0xfff) << 4 | fixup->internal_type();
		data.PushWord(type_offset);
		reloc.SizeOfBlock += sizeof(type_offset);
	}

	if (reloc.SizeOfBlock) {
		if (reloc.SizeOfBlock & 3) {
			data.PushWord(empty_offset);
			reloc.SizeOfBlock += sizeof(empty_offset);
		}
		data.WriteDWord(size_pos, reloc.SizeOfBlock);
	}
}

size_t PEFixupList::WriteToFile(PEArchitecture& file)
{
	Sort();

	Data data;
	size_t size_pos = 0;
	IMAGE_BASE_RELOCATION reloc = IMAGE_BASE_RELOCATION();
	uint16_t empty_offset = 0;
	for (size_t i = 0; i < count(); i++) {
		PEFixup* fixup = item(i);
		uint32_t rva = static_cast<uint32_t>(fixup->address() - file.image_base());
		uint32_t block_rva = rva & 0xfffff000;
		if (reloc.SizeOfBlock == 0 || block_rva != reloc.VirtualAddress) {
			if (reloc.SizeOfBlock) {
				if (reloc.SizeOfBlock & 3) {
					data.PushWord(empty_offset);
					reloc.SizeOfBlock += sizeof(empty_offset);
				}
				data.WriteDWord(size_pos, reloc.SizeOfBlock);
			}
			size_pos = data.size() + 4;
			reloc.VirtualAddress = block_rva;
			reloc.SizeOfBlock = sizeof(reloc);
			data.PushBuff(&reloc, sizeof(reloc));
			empty_offset = IMAGE_REL_BASED_ABSOLUTE << 12 | (static_cast<uint16_t>(rva - block_rva) & 0xf00);
		}
		uint16_t type_offset = fixup->internal_type() << 12 | (static_cast<uint16_t>(rva - block_rva) & 0xfff);
		data.PushWord(type_offset);
		reloc.SizeOfBlock += sizeof(type_offset);
	}

	if (reloc.SizeOfBlock) {
		if (reloc.SizeOfBlock & 3) {
			data.PushWord(empty_offset);
			reloc.SizeOfBlock += sizeof(empty_offset);
		}
		data.WriteDWord(size_pos, reloc.SizeOfBlock);
	}

	return file.Write(data.data(), data.size());
}

/**
 * PERelocation
 */


PERelocation::PERelocation(PERelocationList* owner, uint64_t address, uint64_t source, OperandSize size, uint32_t addend)
	: BaseRelocation(owner, address, size), source_(source), addend_(addend)
{

}

PERelocation::PERelocation(PERelocationList* owner, const PERelocation& src)
	: BaseRelocation(owner, src)
{
	source_ = src.source_;
	addend_ = src.addend_;
}

PERelocation* PERelocation::Clone(IRelocationList* owner) const
{
	PERelocation* relocation = new PERelocation(reinterpret_cast<PERelocationList*>(owner), *this);
	return relocation;
}

/**
 * PERelocationList
 */

PERelocationList::PERelocationList()
	: BaseRelocationList(), address_(0), mem_address_(0)
{

}

PERelocationList::PERelocationList(const PERelocationList& src)
	: BaseRelocationList(src)
{
	address_ = src.address_;
	mem_address_ = src.mem_address_;
}

PERelocationList* PERelocationList::Clone() const
{
	PERelocationList* list = new PERelocationList(*this);
	return list;
}

PERelocation* PERelocationList::item(size_t index) const
{
	return reinterpret_cast<PERelocation*>(IRelocationList::item(index));
}

PERelocation* PERelocationList::Add(uint64_t address, uint64_t target, OperandSize size, uint32_t addend)
{
	PERelocation* relocation = new PERelocation(this, address, target, size, addend);
	AddObject(relocation);
	return relocation;
}

void PERelocationList::ParseMinGW(PEArchitecture& file, uint64_t address, uint64_t start, uint64_t end)
{
	if ((end < start) || (end - start < 8) ||
		((file.segment_list()->GetMemoryTypeByAddress(address) & mtWritable) == 0) ||
		((file.segment_list()->GetMemoryTypeByAddress(start) & mtReadable) == 0))
		return;

	struct RelocationHeader {
		uint32_t magic1;
		uint32_t magic2;
		uint32_t version;
	};

	struct RelocationV1 {
		uint32_t addend;
		uint32_t target;
	};

	struct RelocationV2 {
		uint32_t sym;
		uint32_t target;
		uint32_t flags;
	};

	file.AddressSeek(start);

	RelocationHeader header;
	header.magic1 = 0;
	header.magic2 = 0;
	header.version = 0;
	if (end - start >= sizeof(header)) {
		uint64_t pos = file.Tell();
		file.Read(&header, sizeof(header));
		if (header.magic1 == 0 && header.magic2 == 0) {
			start += sizeof(header);
		}
		else {
			file.Seek(pos);
			header.version = 0;
		}
	}

	address_ = address;
	switch (header.version) {
	case 0:
		while (start < end) {
			RelocationV1 item;
			file.Read(&item, sizeof(item));
			start += sizeof(item);

			Add(file.image_base() + item.target, 0, file.cpu_address_size(), item.addend);
		}
		break;
	case 1:
		while (start < end) {
			RelocationV2 item;
			file.Read(&item, sizeof(item));
			start += sizeof(item);

			OperandSize item_size;
			switch (item.flags) {
			case 8:
				item_size = osByte;
				break;
			case 16:
				item_size = osWord;
				break;
			case 32:
				item_size = osDWord;
				break;
			case 64:
				if (file.cpu_address_size() == osQWord)
					item_size = osQWord;
				else
					throw std::runtime_error("Invalid relocation flags");
				break;
			default:
				throw std::runtime_error("Invalid relocation flags");
			}

			Add(file.image_base() + item.target, file.image_base() + item.sym, item_size, 0);
		}
		break;
	default:
		return;
	}
}

void PERelocationList::ReadFromFile(PEArchitecture& file)
{
	for (size_t i = 0; i < file.compiler_function_list()->count(); i++) {
		CompilerFunction* compiler_function = file.compiler_function_list()->item(i);
		if (compiler_function->type() == cfRelocatorMinGW)
			ParseMinGW(file, compiler_function->value(0), compiler_function->value(1), compiler_function->value(2));
	}

	for (size_t i = 0; i < count(); i++) {
		PERelocation* relocation = item(i);

		if (relocation->source()) {
			IImportFunction* import_function = file.import_list()->GetFunctionByAddress(relocation->source());
			if (import_function) {
				import_function->exclude_option(ioNoReferences);
				import_function->include_option(ioHasDataReference);
			}
		}
	}
}

void PERelocationList::WriteToData(Data& data, uint64_t image_base)
{
	for (size_t i = 0; i < count(); i++) {
		PERelocation* relocation = item(i);

		data.PushDWord(static_cast<uint32_t>(relocation->address() - image_base));
		if (!relocation->source()) {
			data.PushDWord(relocation->addend());
			data.PushDWord(0);
		}
		else {
			data.PushDWord(static_cast<uint32_t>(relocation->source() - image_base));
			data.PushDWord(relocation->size() + 1);
		}
	}

	if (address_) {
		data.PushDWord(static_cast<uint32_t>(address_ - image_base));
		data.PushDWord(1);
		data.PushDWord(0);
	}
}
