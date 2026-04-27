
#include "../../runtime/common.h"
#include "../objects.h"
#include "../osutils.h"
#include "../streams.h"
#include "../files.h"
#include "PETLS.h"
#include "PEDirectory.h"
#include "PEArchitecture.h"

/**
 * PETLSDirectory
 */


PETLSDirectory::PETLSDirectory()
	: ReferenceList(), address_(0), start_address_of_raw_data_(0), end_address_of_raw_data_(0), address_of_index_(0),
	address_of_call_backs_(0), size_of_zero_fill_(0), characteristics_(0)
{

}

PETLSDirectory* PETLSDirectory::Clone() const
{
	PETLSDirectory* dir = new PETLSDirectory(*this);
	return dir;
}

PETLSDirectory::PETLSDirectory(const PETLSDirectory& src)
	: ReferenceList(src)
{
	address_ = src.address_;
	start_address_of_raw_data_ = src.start_address_of_raw_data_;
	end_address_of_raw_data_ = src.end_address_of_raw_data_;
	address_of_index_ = src.address_of_index_;
	address_of_call_backs_ = src.address_of_call_backs_;
	size_of_zero_fill_ = src.size_of_zero_fill_;
	characteristics_ = src.characteristics_;
}

void PETLSDirectory::ReadFromFile(PEArchitecture& file, PEDirectory& directory)
{
	if (!directory.address())
		return;

	if (!file.AddressSeek(directory.address()))
		throw std::runtime_error("Format error");

	address_ = directory.address();

	if (file.cpu_address_size() == osDWord) {
		IMAGE_TLS_DIRECTORY32 tls;
		file.Read(&tls, sizeof(tls));
		start_address_of_raw_data_ = tls.StartAddressOfRawData;
		end_address_of_raw_data_ = tls.EndAddressOfRawData;
		address_of_index_ = tls.AddressOfIndex;
		address_of_call_backs_ = tls.AddressOfCallBacks;
		size_of_zero_fill_ = tls.SizeOfZeroFill;
#if (NTDDI_VERSION < NTDDI_WIN10_NI)
		characteristics_ = tls.Characteristics;
#else
		characteristics_ = 0;
#endif
	}
	else {
		IMAGE_TLS_DIRECTORY64 tls;
		file.Read(&tls, sizeof(tls));
		start_address_of_raw_data_ = tls.StartAddressOfRawData;
		end_address_of_raw_data_ = tls.EndAddressOfRawData;
		address_of_index_ = tls.AddressOfIndex;
		address_of_call_backs_ = tls.AddressOfCallBacks;
		size_of_zero_fill_ = tls.SizeOfZeroFill;
#if (NTDDI_VERSION < NTDDI_WIN10_NI)
		characteristics_ = tls.Characteristics;
#else
		characteristics_ = 0;
#endif
	}

	if (!address_of_call_backs_)
		return;

	if (!file.AddressSeek(address_of_call_backs_))
		throw std::runtime_error("Format error");

	size_t value_size = OperandSizeToValue(file.cpu_address_size());
	uint64_t call_back = 0;
	while (true) {
		file.Read(&call_back, value_size);
		if (!call_back)
			break;
		Add(call_back, 0);
	}
}

void PETLSDirectory::FreeByManager(MemoryManager& manager)
{
	if (!address_)
		return;

	PEArchitecture* file = reinterpret_cast<PEArchitecture*>(manager.owner());
	size_t value_size = OperandSizeToValue(file->cpu_address_size());
	manager.Add(address_, value_size * 4 + sizeof(uint32_t) * 2);

	for (size_t i = 0; i < 4; i++) {
		IFixup* fixup = file->fixup_list()->GetFixupByAddress(address_ + value_size * i);
		if (fixup)
			fixup->set_deleted(true);
	}

	if (address_of_call_backs_) {
		manager.Add(address_of_call_backs_, value_size * (count() + 1));
		for (size_t i = 0; i < count(); i++) {
			IFixup* fixup = file->fixup_list()->GetFixupByAddress(address_of_call_backs_ + value_size * i);
			if (fixup)
				fixup->set_deleted(true);
		}
	}
}
