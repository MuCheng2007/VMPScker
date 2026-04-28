/**
 * Map file parsing and function address mapping implementations.
 * Rust mapping target: mod mapping
 */
#include "sections.h" 
#include "mapping.h"
#include "architecture.h"
#include "exports.h"
#include "imports.h"    // full IArchitecture, IFile, IExportList, IImportList
#include "../objects.h"
#include "../osutils.h"
#include "../streams.h"

/**
 * MapObject
 */

MapObject::MapObject(MapSection *owner, size_t segment, uint64_t address, uint64_t size, const std::string &name)
	: IObject(), owner_(owner), segment_(segment), address_(address), size_(size), name_(name)
{

}

MapObject::~MapObject()
{
	if (owner_)
		owner_->RemoveObject(this);
}

/**
 * MapSection
 */

MapSection::MapSection(IMapFile *owner, MapSectionType type)
	: ObjectList<MapObject>(), owner_(owner), type_(type)
{

}

MapSection::~MapSection()
{
	if (owner_)
		owner_->RemoveObject(this);
}

void MapSection::Add(size_t segment, uint64_t address, uint64_t size, const std::string &name)
{
	MapObject *object = new MapObject(this, segment, address, size, name);
	AddObject(object);
}

/**
 * BaseMapFile / MapFile
 */

BaseMapFile::BaseMapFile()
	: IMapFile()
{

}

MapSection *BaseMapFile::GetSectionByType(MapSectionType type) const
{
	for (size_t i = 0; i < count(); i++) {
		MapSection *section = item(i);
		if (section->type() == type)
			return section;
	}
	return NULL;
}

MapSection *BaseMapFile::Add(MapSectionType type)
{
	MapSection *section = new MapSection(this, type);
	AddObject(section);
	return section;
}

MapFile::MapFile()
	: BaseMapFile(), time_stamp_(0)
{

}

static const char *skip_spaces(const char *str)
{
	while (*str && isspace(*str))
		str++;
	return str;
}

static int cmp_skip_spaces(const char *str1, const char *str2)
{
	unsigned char c1;
	unsigned char c2;
	do {
		c1 = *(str1++);
		if (isspace(c1)) {
			c1 = ' ';
			while (isspace(*str1))
				str1++;
		}
		c2 = *(str2++);
		if (!c1)
			break;
	} while (c1 == c2);
	
	if (c1 < c2)
		return -1;
	else if (c1 > c2)
		return 1;
	return 0;
}

bool MapFile::Parse(const char *file_name, const std::vector<uint64_t> &segments)
{
	clear();
	time_stamp_ = 0;
	file_name_ = file_name;

	FileStream fs;
	if (!fs.Open(file_name, fmOpenRead | fmShareDenyNone))
		return false;

	enum State {
		stBegin,
		stTimeStamp,
		stSections,
		stAddressDelphi,
		stAddressVC,
		stAddressApple,
		stAddressGCC,
		stAddressBCB,
		stStaticSymbols,
	};

	State state = stBegin;

	std::string line;
	std::vector<std::string> columns;
	while (fs.ReadLine(line)) {
		const char *str = skip_spaces(line.c_str());

		switch (state) {
		case stBegin:
			if (strncmp(str, "Timestamp is", 12) == 0) {
				state = stTimeStamp;
				str += 12;
			} else if (strncmp(str, "Start", 5) == 0) {
				state = stSections;
				continue;
			} else if (cmp_skip_spaces(str, "# Address Size File Name") == 0) {
				state = stAddressApple;
				continue;
			} else if (strncmp(str, "Linker script and memory map", 29) == 0) {
				state = stAddressGCC;
				continue;
			}
			break;
		case stSections:
			if (cmp_skip_spaces(str, "Address Publics by Value") == 0) {
				state = stAddressDelphi;
				continue;
			} else if (cmp_skip_spaces(str, "Address Publics by Value Rva+Base Lib:Object") == 0) {
				state = stAddressVC;
				continue;
			} else if (cmp_skip_spaces(str, "Address Publics by Name") == 0) {
				state = stAddressBCB;
				continue;
			}
			break;
		case stAddressVC:
			if (strncmp(str, "Static symbols", 14) == 0) {
				state = stStaticSymbols;
				continue;
			}
			break;
		case stAddressBCB:
			if (cmp_skip_spaces(str, "Address Publics by Value") == 0)
				state = stAddressDelphi;
			continue;
		}

		if (state == stBegin)
			continue;

		columns.clear();
		while (*str) {
			str = skip_spaces(str);
			const char *begin = str;
			bool in_block = false;
			while (*str) {
				if (*str == '[')
					in_block = true;
				else if (*str == ']')
					in_block = false;
				else if (!in_block && isspace(*str))
					break;
				str++;
			}
			if (str != begin)
				columns.push_back(std::string(begin, str - begin));
			if (state == stAddressDelphi || state == stAddressGCC || (state == stAddressApple && columns.size() == 3)) {
				columns.push_back(skip_spaces(str));
				break;
			}
		}

		switch (state) { //-V719
		case stTimeStamp:
			if (columns.size() > 0) {
				char *last;
				uint64_t value = _strtoui64(columns[0].c_str(), &last, 16);
				if (*last == 0)
					time_stamp_ = value;
			}
			state = stBegin;
			break;
			
		case stSections:
			if (columns.size() == 4) {
				MapSection *section = GetSectionByType(msSections);
				if (!section)
					section = Add(msSections);

				char *last;
				size_t segment = strtol(columns[0].c_str(), &last, 16);
				if (*last != ':')
					continue;
				uint64_t address = _strtoui64(last + 1, &last, 16);
				if (*last != 0)
					continue;

				uint64_t size = _strtoui64(columns[1].c_str(), &last, 16);

				if (segment >= segments.size())
					continue;

				if (address < segments[segment])
					address += segments[segment];

				section->Add(segment, address, size, columns[2]);
			}
			break;

		case stAddressDelphi:
		case stAddressVC:
		case stStaticSymbols:
			if (columns.size() >= 2) {
				MapSection *section = GetSectionByType(msFunctions);
				if (!section)
					section = Add(msFunctions);

				char *last;
				size_t segment;
				uint64_t address;
				if (columns.size() >= 3) {
					segment = NOT_ID;
					address = _strtoui64(columns[2].c_str(), &last, 16);
					if (*last != 0)
						continue;
				} else {
					segment = strtol(columns[0].c_str(), &last, 16);
					if (*last != ':')
						continue;
					address = _strtoui64(last + 1, &last, 16);
					if (*last != 0)
						continue;
				}
				section->Add(segment, address, 0, columns[1]);
			}
			break;

		case stAddressApple:
			if (columns.size() == 4) {
				MapSection *section = GetSectionByType(msFunctions);
				if (!section)
					section = Add(msFunctions);

				char *last;
				uint64_t address = _strtoui64(columns[0].c_str(), &last, 16);
				if (*last != 0)
					continue;
				section->Add(NOT_ID, address, 0, columns[3]);
			}
			break;

		case stAddressGCC:
			if (columns.size() >= 2) {
				MapSection *section = GetSectionByType(msFunctions);
				if (!section)
					section = Add(msFunctions);

				char *last;
				uint64_t address = _strtoui64(columns[0].c_str(), &last, 16);
				if (*last != 0)
					continue;
				if (columns[1].find("0x") == 0 || columns[1].find(" = ") != NOT_ID || columns[1].find("PROVIDE (") == 0)
					continue;
				section->Add(NOT_ID, address, 0, columns[1]);
			}
			break;
		}
	}
	return true;
}

/**
 * MapFunction
 */

MapFunction::MapFunction(MapFunctionList *owner, uint64_t address, ObjectType type, const FunctionName &name)
	: IObject(), owner_(owner), address_(address), type_(type), name_(name), end_address_(0), name_address_(0), name_length_(0), 
	compilation_type_(ctNone), lock_to_key_(false), strings_protection_(false)
{
	reference_list_ = new ReferenceList();
	equal_address_list_ = new ReferenceList();
}

MapFunction::MapFunction(MapFunctionList *owner, const MapFunction &src)
	: IObject(src), owner_(owner)
{
	address_ = src.address_;
	end_address_ = src.end_address_;
	name_address_ = src.name_address_;
	name_length_ = src.name_length_;
	type_ = src.type_;
	name_ = src.name_;
	compilation_type_ = src.compilation_type_;
	lock_to_key_ = src.lock_to_key_;
	strings_protection_ = src.strings_protection_;
	reference_list_ = src.reference_list_->Clone();
	equal_address_list_ = src.equal_address_list_->Clone();
}

MapFunction::~MapFunction() 
{
	if (owner_)
		owner_->RemoveObject(this);

	delete reference_list_;
	delete equal_address_list_;
}

MapFunction *MapFunction::Clone(MapFunctionList *owner) const
{
	MapFunction *func = new MapFunction(owner, *this);
	return func;
}

void MapFunction::Rebase(uint64_t delta_base)
{
	reference_list_->Rebase(delta_base);

	address_ += delta_base;
	if (end_address_)
		end_address_ += delta_base;
	if (name_address_)
		name_address_ += delta_base;
}

std::string MapFunction::display_address(const std::string &arch_name) const
{
	OperandSize address_size = owner_->owner()->cpu_address_size();
	std::string res;
	res.append(arch_name).append(DisplayValue(address_size, address()));
	for (size_t i = 0; i < equal_address_list()->count(); i++) {
		res.append(", ").append(arch_name).append(DisplayValue(address_size, equal_address_list()->item(i)->address()));
	}
	return res;
}

MapFunctionHash MapFunction::hash() const
{
	return MapFunctionHash(type_, name_.name());
}

bool MapFunction::is_code() const
{
	switch (type_) {
	case otMarker:
	case otAPIMarker:
	case otCode:
	case otString:
	case otExport:
		return true;
	default:
		return false;
	}
}

void MapFunction::set_name(const FunctionName &name)
{
	if (name_ != name) {
		if (owner_)
			owner_->RemoveObject(this);
		name_ = name;
		if (owner_)
			owner_->AddObject(this);
	}
}

/**
 * MapFunctionList
 */

MapFunctionList::MapFunctionList(IArchitecture *owner)
	: ObjectList<MapFunction>(), owner_(owner)
{

}

MapFunctionList::MapFunctionList(IArchitecture *owner, const MapFunctionList &src)
	: ObjectList<MapFunction>(src), owner_(owner)
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

void MapFunctionList::ReadFromFile(IArchitecture &file)
{
	uint32_t memory_type;
	size_t i, j;
	MapFunction *func;
	uint64_t address;

	IExportList *export_list = file.export_list();
	for (i = 0; i < export_list->count(); i++) {
		IExport *exp = export_list->item(i);
		address = exp->address();
		func = GetFunctionByAddress(address);
		if (func) {
			if (func->type() == otCode)
				func->set_type(otExport);
		} else {
			memory_type = file.segment_list()->GetMemoryTypeByAddress(address);
			if (memory_type != mtNone)
				Add(address, 0, (memory_type & mtExecutable) ? otExport : otData, DemangleName(exp->name()));
		}
	}

	IImportList *import_list = file.import_list();
	for (i = 0; i < import_list->count(); i++) {
		IImport *import = import_list->item(i);
		for (j = 0; j < import->count(); j++) {
			IImportFunction *import_function = import->item(j);
			address = import_function->address();
			func = address ? GetFunctionByAddress(address) : GetFunctionByName(import_function->full_name());
			if (func) {
				func->set_type(otImport);
			} else {
				func = Add(address, 0, otImport, import_function->full_name());
			}
			import_function->set_map_function(func);
		}
	}

	address = file.entry_point();
	if (address && !GetFunctionByAddress(address)) {
		memory_type = file.segment_list()->GetMemoryTypeByAddress(address);
		if (memory_type != mtNone)
			Add(address, 0, (memory_type & mtExecutable) ? otCode : otData, FunctionName("EntryPoint"));
	}
}

MapFunction *MapFunctionList::GetFunctionByAddress(uint64_t address) const
{
	std::map<uint64_t, MapFunction*>::const_iterator it = address_map_.find(address);
	if (it != address_map_.end())
		return it->second;

	return NULL;
}

MapFunction *MapFunctionList::GetFunctionByName(const std::string &name) const
{
	std::map<std::string, std::vector<MapFunction*> >::const_iterator it = name_map_.find(name);
	if (it != name_map_.end() && !it->second.empty())
		return it->second.at(0);

	return NULL;
}

std::vector<uint64_t> MapFunctionList::GetAddressListByName(const std::string &name, bool code_only) const
{
	std::vector<uint64_t> res;
	std::map<std::string, std::vector<MapFunction*> >::const_iterator it = name_map_.find(name);
	if (it != name_map_.end()) {
		for (size_t i = 0; i < it->second.size(); i++) {
			MapFunction *map_function = it->second.at(i);
			if (code_only && !map_function->is_code())
				continue;

			res.push_back(map_function->address());
		}
	}
	return res;
}

MapFunction *MapFunctionList::Add(uint64_t address, uint64_t end_address, ObjectType type, const FunctionName &name)
{
	MapFunction *map_function = NULL;
	if (type == otString && !name.name().empty()) {
		MapFunction *map_function = GetFunctionByAddress(address);
		if (!map_function)
			map_function = GetFunctionByName(name.name());
		if (map_function) {
			if (map_function->type() == otString) {
				if (map_function->address() != address && !map_function->equal_address_list()->GetReferenceByAddress(address)) {
					address_map_[address] = map_function;
					map_function->equal_address_list()->Add(address, end_address);
				}
			} else {
				name_map_[name.name()].push_back(map_function);
				map_function->set_type(otString);
				map_function->set_name(name);
				map_function->set_end_address(end_address);
			}
			return map_function;
		}
	}

	map_function = new MapFunction(this, address, type, name);
	AddObject(map_function);
	if (end_address)
		map_function->set_end_address(end_address);

	return map_function;
}

void MapFunctionList::AddObject(MapFunction *func) 
{
	ObjectList<MapFunction>::AddObject(func);

	/* If key exists, do not add to std::map. */
	if (address_map_.find(func->address()) == address_map_.end())
		address_map_[func->address()] = func;

	std::map<std::string, std::vector<MapFunction*> >::iterator it = name_map_.find(func->name());
	if (it == name_map_.end())
		name_map_[func->name()].push_back(func);
	else
		it->second.push_back(func);
}

void MapFunctionList::RemoveObject(MapFunction *func) 
{
	ObjectList<MapFunction>::RemoveObject(func);

	std::map<std::string, std::vector<MapFunction*> >::iterator it = name_map_.find(func->name());
	if (it != name_map_.end()) {
		std::vector<MapFunction*>::iterator v = std::find(it->second.begin(), it->second.end(), func);
		if (v != it->second.end()) {
			it->second.erase(v);
			if (it->second.empty())
				name_map_.erase(it);
		}
	}
}

void MapFunctionList::clear()
{
	address_map_.clear();
	name_map_.clear();
	ObjectList<MapFunction>::clear();
}

MapFunctionList *MapFunctionList::Clone(IArchitecture *owner) const
{
	MapFunctionList *map_function_list = new MapFunctionList(owner, *this);
	return map_function_list;
}

void MapFunctionList::Rebase(uint64_t delta_base)
{
	address_map_.clear();
	for (size_t i = 0; i < count(); i++) {
		MapFunction *func = item(i);
		func->Rebase(delta_base);
		if (address_map_.find(func->address()) == address_map_.end())
			address_map_[func->address()] = func;
	}
}

void MapFunctionList::ReadFromBuffer(Buffer &buffer, IArchitecture &file)
{
	size_t i, c, k, j, tag;
	uint64_t address, operand_address, end_address;
	uint64_t add_address = file.image_base();

	c = buffer.ReadDWord();
	for (i = 0; i < c; i++) {
		address = buffer.ReadDWord() + add_address;
		end_address = buffer.ReadDWord() + add_address;
		MapFunction *map_function = Add(address, end_address, otString, FunctionName(""));

		k = buffer.ReadDWord();
		for (j = 0; j < k; j++) {
			address = buffer.ReadDWord() + add_address;
			operand_address = buffer.ReadDWord() + add_address;
			tag = buffer.ReadByte();

			map_function->reference_list()->Add(address, operand_address, tag);
		}
	}
}

/**
 * MapFunctionArch
 */

MapFunctionArch::MapFunctionArch(MapFunctionBundle *owner, IArchitecture *arch, MapFunction *func)
	: IObject(), owner_(owner), arch_(arch), func_(func)
{

}

MapFunctionArch::~MapFunctionArch()
{
	if (owner_)
		owner_->RemoveObject(this);
}

/**
 * MapFunctionBundle
 */

MapFunctionBundle::MapFunctionBundle(MapFunctionBundleList *owner, ObjectType type, const FunctionName &name)
	: ObjectList<MapFunctionArch>(), owner_(owner), type_(type), name_(name)
{

}

MapFunctionBundle::~MapFunctionBundle()
{
	if (owner_)
		owner_->RemoveObject(this);
}

MapFunctionArch *MapFunctionBundle::Add(IArchitecture *arch, MapFunction *func)
{
	MapFunctionArch *farch = new MapFunctionArch(this, arch, func);
	AddObject(farch);
	return farch;
}

MapFunction *MapFunctionBundle::GetFunctionByArch(IArchitecture *arch) const
{
	for (size_t i = 0; i < count(); i++) {
		MapFunctionArch *func_arch = item(i);
		if (func_arch->arch() == arch)
			return func_arch->func();
	}
	return NULL;
}

bool MapFunctionBundle::is_code() const
{
	switch (type()) {
	case otMarker:
	case otAPIMarker:
	case otCode:
	case otString:
		return true;
	case otExport:
		{
			for (size_t i = 0; i < count(); i++) {
				MapFunctionArch *func_arch = item(i);
				if ((func_arch->arch()->segment_list()->GetMemoryTypeByAddress(func_arch->func()->address()) & mtExecutable) == 0)
					return false;
			}
		}
		return true;
	default:
		return false;
	}
}

std::string MapFunctionBundle::display_address() const
{
	bool show_arch_name = (owner_ && owner_->show_arch_name());
	std::string res;
	for (size_t i = 0; i < count(); i++) {
		MapFunction *func = item(i)->func();
		if (!res.empty())
			res.append(", ");
		res.append(func->display_address(show_arch_name ? item(i)->arch()->name().append(".") : std::string()));
	}
	return res;
}

/**
 * MapFunctionBundleList
 */

MapFunctionBundleList::MapFunctionBundleList(IFile *owner)
	: ObjectList<MapFunctionBundle>(), owner_(owner), show_arch_name_(false)
{

}

void MapFunctionBundleList::ReadFromFile(IFile &file)
{
	for (size_t i = 0; i < file.count(); i++) {
		IArchitecture *arch = file.item(i);
		if (!arch->function_list())
			continue;

		for (size_t j = 0; j < arch->map_function_list()->count(); j++) {
			Add(arch, arch->map_function_list()->item(j));
		}
	}
}

MapFunctionBundle *MapFunctionBundleList::Add(IArchitecture *arch, MapFunction *func)
{
	MapFunctionBundle *bundle = GetFunctionByHash(func->hash());
	if (!bundle) {
		bundle = new MapFunctionBundle(this, func->type(), func->full_name());
		AddObject(bundle);
	}
	bundle->Add(arch, func);
	return bundle;
}

void MapFunctionBundleList::AddObject(MapFunctionBundle *bundle)
{
	ObjectList<MapFunctionBundle>::AddObject(bundle);

	MapFunctionHash hash = bundle->hash();
	if (map_.find(hash) == map_.end())
		map_[hash] = bundle;
}

MapFunctionBundle *MapFunctionBundleList::GetFunctionByHash(const MapFunctionHash &hash) const
{
	std::map<MapFunctionHash, MapFunctionBundle *>::const_iterator it = map_.find(hash);
	if (it != map_.end())
		return it->second;

	return NULL;
}

MapFunctionBundle *MapFunctionBundleList::GetFunctionByAddress(IArchitecture *arch, uint64_t address) const
{
	MapFunction *func = arch->map_function_list()->GetFunctionByAddress(address);
	if (func)
		return GetFunctionByHash(func->hash());

	return NULL;
}
