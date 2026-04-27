#include "../../runtime/common.h"
#include "../../runtime/crypto.h"
#include "../objects.h"
#include "../osutils.h"
#include "../streams.h"
#include "../files.h"
#include "../processors.h"
#include "PEExport.h"
#include "PEDirectory.h"
#include "PEArchitecture.h"
#include "../lang.h"
#include "../core_internal/core.h"

// Intel module
#include "../intel/ir/IntelFunction.h"
#include "../intel/ir/IntelCommand.h"

/**
 * PEExport
 */


PEExport::PEExport(PEExportList* owner, uint64_t address, uint32_t ordinal)
	: BaseExport(owner), address_(address), ordinal_(ordinal), address_of_name_(0)
{

}

PEExport::PEExport(PEExportList* owner, const PEExport& src)
	: BaseExport(owner, src)
{
	address_ = src.address_;
	ordinal_ = src.ordinal_;
	name_ = src.name_;
	forwarded_name_ = src.forwarded_name_;
	address_of_name_ = src.address_of_name_;
}

PEExport* PEExport::Clone(IExportList* owner) const
{
	PEExport* exp = new PEExport(reinterpret_cast<PEExportList*>(owner), *this);
	return exp;
}

int PEExport::CompareWith(const IObject& obj) const
{
	const PEExport& exp = reinterpret_cast<const PEExport&>(obj);
	if (ordinal() < exp.ordinal())
		return -1;
	if (ordinal() > exp.ordinal())
		return 1;
	return 0;
}

void PEExport::ReadFromFile(PEArchitecture& file, uint64_t address_of_name, bool is_forwarded)
{
	address_of_name_ = address_of_name;
	if (address_of_name_) {
		if (!file.AddressSeek(address_of_name_))
			throw std::runtime_error("Format error");
		name_ = file.ReadString();
	}

	if (is_forwarded) {
		if (!file.AddressSeek(address_))
			throw std::runtime_error("Format error");
		forwarded_name_ = file.ReadString();
	}
}

void PEExport::FreeByManager(MemoryManager& manager)
{
	if (!forwarded_name_.empty())
		manager.Add(address_, forwarded_name_.size() + 1);

	if (address_of_name_)
		manager.Add(address_of_name_, name_.size() + 1);
}

void PEExport::Rebase(uint64_t delta_base)
{
	if (address_)
		address_ += delta_base;
	if (address_of_name_)
		address_of_name_ += delta_base;
}

std::string PEExport::display_name(bool show_ret) const
{
	return DemangleName(name_).display_name(show_ret);
}

/**
 * PEExportList
 */

PEExportList::PEExportList(PEArchitecture* owner)
	: BaseExportList(owner), address_(0), name_address_(0), characteristics_(0), time_date_stamp_(0), major_version_(0), minor_version_(0),
	number_of_functions_(0), address_of_functions_(0), number_of_names_(0), address_of_names_(0), address_of_name_ordinals_(0)
{

}

PEExportList::PEExportList(PEArchitecture* owner, const PEExportList& src)
	: BaseExportList(owner, src)
{
	address_ = src.address_;
	name_address_ = src.name_address_;
	characteristics_ = src.characteristics_;
	time_date_stamp_ = src.time_date_stamp_;
	major_version_ = src.major_version_;
	minor_version_ = src.minor_version_;
	name_ = src.name_;
	number_of_functions_ = src.number_of_functions_;
	address_of_functions_ = src.address_of_functions_;
	number_of_names_ = src.number_of_names_;
	address_of_names_ = src.address_of_names_;
	address_of_name_ordinals_ = src.address_of_name_ordinals_;
}

PEExportList* PEExportList::Clone(PEArchitecture* owner) const
{
	PEExportList* export_list = new PEExportList(owner, *this);
	return export_list;
}

PEExport* PEExportList::item(size_t index) const
{
	return reinterpret_cast<PEExport*>(IExportList::item(index));
}

PEExport* PEExportList::Add(uint64_t address, uint32_t ordinal)
{
	PEExport* exp = new PEExport(this, address, ordinal);
	AddObject(exp);
	return exp;
}

void PEExportList::AddAntidebug()
{
	size_t i;
	PEExport* exp;
	std::map<uint32_t, PEExport*> map;
	for (i = 0; i < count(); i++) {
		exp = item(i);
		map[exp->ordinal()] = exp;
	}
	uint32_t free_ordinal = 0;
	for (uint32_t ordinal = 1; ordinal <= 0xffff; ordinal++) {
		if (map.find(ordinal) == map.end()) {
			free_ordinal = ordinal;
			break;
		}
	}
	if (!free_ordinal)
		return;

	exp = Add(0, free_ordinal);
	std::string name;
	name.resize(3100);
	for (i = 0; i < name.size(); i++) {
		name[i] = 1 + rand() % 0xff;
	}
	exp->set_name(name);
}

PEExport* PEExportList::GetExportByOrdinal(uint32_t ordinal)
{
	for (size_t i = 0; i < count(); i++) {
		PEExport* exp = item(i);
		if (exp->ordinal() == ordinal)
			return exp;
	}

	return NULL;
}

void PEExportList::ReadFromFile(PEArchitecture& file, PEDirectory& dir)
{
	IMAGE_EXPORT_DIRECTORY export_directory;
	uint32_t i;
	uint32_t rva;
	PEExport* export_function;
	std::vector<NameInfo> name_info_list;

	if (!dir.address())
		return;

	address_ = dir.address();
	if (!file.AddressSeek(address_))
		throw std::runtime_error("Format error");

	file.Read(&export_directory, sizeof(export_directory));
	characteristics_ = export_directory.Characteristics;
	time_date_stamp_ = export_directory.TimeDateStamp;
	major_version_ = export_directory.MajorVersion;
	minor_version_ = export_directory.MinorVersion;

	name_address_ = export_directory.Name;
	if (name_address_) {
		name_address_ += file.image_base();
		if (!file.AddressSeek(name_address_))
			throw std::runtime_error("Format error");
		name_ = file.ReadString();
	}

	number_of_functions_ = export_directory.NumberOfFunctions;
	if (number_of_functions_) {
		address_of_functions_ = export_directory.AddressOfFunctions + file.image_base();
		if (!file.AddressSeek(address_of_functions_))
			throw std::runtime_error("Format error");
		for (i = 0; i < number_of_functions_; i++) {
			rva = file.ReadDWord();
			if (rva)
				Add(rva + file.image_base(), export_directory.Base + i);
		}
	}

	number_of_names_ = export_directory.NumberOfNames;
	if (number_of_names_) {
		address_of_names_ = export_directory.AddressOfNames + file.image_base();
		if (!file.AddressSeek(address_of_names_))
			throw std::runtime_error("Format error");

		for (i = 0; i < number_of_names_; i++) {
			NameInfo name_info;
			name_info.address_of_name = file.ReadDWord();
			name_info.ordinal_index = 0;
			name_info_list.push_back(name_info);
		}

		address_of_name_ordinals_ = export_directory.AddressOfNameOrdinals + file.image_base();
		if (!file.AddressSeek(address_of_name_ordinals_))
			throw std::runtime_error("Format error");
		for (i = 0; i < number_of_names_; i++) {
			name_info_list[i].ordinal_index = export_directory.Base + file.ReadWord();
		}
	}

	for (i = 0; i < count(); i++) {
		export_function = item(i);

		std::vector<NameInfo>::iterator it = std::find(name_info_list.begin(), name_info_list.end(), export_function->ordinal());
		export_function->ReadFromFile(file, (it == name_info_list.end()) ? 0 : it->address_of_name + file.image_base(),
			(export_function->address() >= dir.address() && export_function->address() < dir.address() + dir.size()));
	}
}

void PEExportList::FreeByManager(MemoryManager& manager)
{
	if (!address_)
		return;

	manager.Add(address_, sizeof(IMAGE_EXPORT_DIRECTORY));

	if (name_address_)
		manager.Add(name_address_, name_.size() + 1);

	if (number_of_functions_)
		manager.Add(address_of_functions_, number_of_functions_ * sizeof(uint32_t));

	if (number_of_names_) {
		manager.Add(address_of_names_, number_of_names_ * sizeof(uint32_t));
		manager.Add(address_of_name_ordinals_, number_of_names_ * sizeof(uint16_t));
	}

	for (size_t i = 0; i < count(); i++) {
		item(i)->FreeByManager(manager);
	}
}

void PEExportList::ReadFromBuffer(Buffer& buffer, IArchitecture& file)
{
	static const APIType export_function_types[] = {
		atSetupImage,
		atFreeImage,
		atDecryptStringA,
		atDecryptStringW,
		atFreeString,
		atSetSerialNumber,
		atGetSerialNumberState,
		atGetSerialNumberData,
		atGetCurrentHWID,
		atActivateLicense,
		atDeactivateLicense,
		atGetOfflineActivationString,
		atGetOfflineDeactivationString,
		atIsValidImageCRC,
		atIsDebuggerPresent,
		atIsVirtualMachinePresent,
		atDecryptBuffer,
		atIsProtected,
		atCalcCRC,
		atLoaderData,
		atLoadResource,
		atFindResourceA,
		atFindResourceExA,
		atFindResourceW,
		atFindResourceExW,
		atLoadStringA,
		atLoadStringW,
		atEnumResourceNamesA,
		atEnumResourceNamesW,
		atEnumResourceLanguagesA,
		atEnumResourceLanguagesW,
		atEnumResourceTypesA,
		atEnumResourceTypesW
	};

	BaseExportList::ReadFromBuffer(buffer, file);

	assert(count() == _countof(export_function_types));
	for (size_t i = 0; i < count(); i++) {
		item(i)->set_type(export_function_types[i]);
	}
}

uint32_t PEExportList::WriteToData(IFunction& data, uint64_t image_base)
{
	if (!count())
		return 0;

	IntelFunction& func = reinterpret_cast<IntelFunction&>(data);

	// export functions must be sorted by ordinals
	Sort();
	size_t start_index = func.count();
	uint32_t ordinal_base = item(0)->ordinal();

	func.AddCommand(osDWord, characteristics_);
	func.AddCommand(osDWord, time_date_stamp_);
	func.AddCommand(osWord, major_version_);
	func.AddCommand(osWord, minor_version_);

	IntelCommand* name_command = func.AddCommand(osDWord, 0);

	func.AddCommand(osDWord, ordinal_base);

	IntelCommand* functions_count = func.AddCommand(osDWord, 0);
	functions_count->AddLink(0, ltOffset);

	IntelCommand* name_pointers_count = func.AddCommand(osDWord, 0);
	name_pointers_count->AddLink(0, ltOffset);

	IntelCommand* address_table = func.AddCommand(osDWord, 0);
	address_table->AddLink(0, ltOffset);

	IntelCommand* name_pointers = func.AddCommand(osDWord, 0);
	name_pointers->AddLink(0, ltOffset);

	IntelCommand* ordinal_table = func.AddCommand(osDWord, 0);
	ordinal_table->AddLink(0, ltOffset);

	// create ordinals
	size_t index = func.count();
	uint32_t last_ordinal = ordinal_base;
	std::vector<ExportInfo> export_name_list;
	PEExport* export_function;
	IntelCommand* command;
	size_t i, j;
	for (i = 0; i < count(); i++) {
		export_function = item(i);
		if (!export_function->name().empty())
			export_name_list.push_back(ExportInfo(export_function));
		for (j = last_ordinal; j < export_function->ordinal(); j++) {
			func.AddCommand(osDWord, 0);
		}
		command = func.AddCommand(osDWord, export_function->address() ? export_function->address() - image_base : 0);
		if (!export_function->forwarded_name().empty())
			command->AddLink(0, ltOffset);
		last_ordinal = export_function->ordinal() + 1;
	}
	address_table->link()->set_to_command(func.item(index));
	functions_count->set_operand_value(0, func.count() - index);

	// create forwarded names
	for (i = 0; i < count(); i++) {
		export_function = item(i);
		if (export_function->forwarded_name().empty())
			continue;

		command = func.AddCommand(export_function->forwarded_name());
		func.item(index + export_function->ordinal() - ordinal_base)->link()->set_to_command(command);
	}

	if (!export_name_list.empty()) {
		// names must be sorted
		std::sort(export_name_list.begin(), export_name_list.end());

		// create ordinal table
		index = func.count();
		for (i = 0; i < export_name_list.size(); i++) {
			export_function = export_name_list[i].export_function;
			func.AddCommand(osWord, export_function->ordinal() - ordinal_base);
		}
		name_pointers_count->set_operand_value(0, export_name_list.size());
		ordinal_table->link()->set_to_command(func.item(index));

		// create names
		index = func.count();
		for (i = 0; i < export_name_list.size(); i++) {
			command = func.AddCommand(osDWord, 0);
			command->AddLink(0, ltOffset);
		}
		for (i = 0; i < export_name_list.size(); i++) {
			export_function = export_name_list[i].export_function;
			command = func.AddCommand(export_function->name());
			func.item(index + i)->link()->set_to_command(command);
		}
		name_pointers->link()->set_to_command(func.item(index));
	}

	// create DLL name
	if (!name().empty()) {
		command = func.AddCommand(name());
		name_command->AddLink(0, ltOffset, command);
	}

	command = func.item(start_index);
	command->include_option(roCreateNewBlock);
	command->set_alignment(OperandSizeToValue(func.cpu_address_size()));
	uint32_t res = 0;
	for (i = start_index; i < func.count(); i++) {
		command = func.item(i);
		if (command->link())
			command->link()->set_sub_value(image_base);

		command->CompileToNative();
		res += (uint32_t)command->dump_size();
	}
	return res;
}
