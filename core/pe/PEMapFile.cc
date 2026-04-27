/**
 * PE Map File support (PDB/COFF).
 */

#include "../../runtime/common.h"
#include "../objects.h"
#include "../osutils.h"
#include "../streams.h"
#include "../files.h"
#include "PEMapFile.h"
#include "PEArchitecture.h"
#include "../pdb.h"

/**
* PDBFile
*/

PDBFile::PDBFile()
	: BaseMapFile(), time_stamp_(0)
{

}

bool PDBFile::Parse(const char* file_name, const std::vector<uint64_t>& segments)
{
	clear();
	guid_.clear();
	time_stamp_ = 0;
	file_name_ = file_name;

	PdbFileStream fs;
	if (!fs.Open(file_name, fmOpenRead | fmShareDenyNone))
		return false;

	segments_ = segments;

	size_t sign_len2 = sizeof(pdb2) - 1, sign_len7 = sizeof(pdb7) - 1;
	size_t sign_len = std::max(sign_len2, sign_len7);
	std::vector<uint8_t> head(sign_len);
	if (fs.RawRead(0, &head))
	{
		if (!memcmp(&head[0], pdb2, sign_len2))
		{
			pdb_jg_reader reader(fs);
			if (!reader.init())
				return false;
			time_stamp_ = reader.root->TimeDateStamp;
			return ReadSymbols(reader);
		}
		else if (!memcmp(&head[0], pdb7, sign_len7))
		{
			pdb_ds_reader reader(fs);
			if (!reader.init())
				return false;
			guid_.insert(guid_.begin(), reinterpret_cast<const uint8_t*>(&reader.root->guid), reinterpret_cast<const uint8_t*>(&reader.root->guid) + sizeof(reader.root->guid));
			return ReadSymbols(reader);
		}
	}

	return false;
}

bool PDBFile::ReadSymbols(pdb_reader& reader)
{
	// read types
	if (reader.read_file(PDB_STREAM_TPI, types_data_)) {
		PDB_TYPES* types = reinterpret_cast<PDB_TYPES*>(types_data_.data());

		size_t offset;
		if (types->version < 19960000) {
			const PDB_TYPES_OLD* types_old = reinterpret_cast<const PDB_TYPES_OLD*>(types);
			offset = sizeof(PDB_TYPES_OLD);
			types_first_index_ = types_old->first_index;
		}
		else {
			offset = types->type_offset;
			types_first_index_ = types->first_index;
		}

		int length;
		for (size_t i = offset; i < types_data_.size(); i += length)
		{
			const union codeview_type* type = reinterpret_cast<const union codeview_type*>(types_data_.data() + i);
			length = type->generic.len + 2;
			if (!type->generic.id || length < 4)
				break;

			types_offset_.push_back(type);
		}
	}

	PDB_SYMBOLS* symbols;
	std::vector<uint8_t> vsymbols, vmodimage;

	if (!reader.read_file(PDB_STREAM_DBI, vsymbols))
		return false;
	symbols = reinterpret_cast<PDB_SYMBOLS*>(vsymbols.data());

	// read global symbol table
	if (reader.read_file(symbols->gsym_file, vmodimage))
		codeview_dump_symbols(vmodimage, 0);

	// read per-module symbol / linenumber tables
	const char* file = reinterpret_cast<const char*>(symbols) + sizeof(PDB_SYMBOLS);
	while (static_cast<size_t>(file - reinterpret_cast<const char*>(symbols)) < sizeof(PDB_SYMBOLS) + symbols->module_size)
	{
		int file_nr, symbol_size;
		const char* file_name;

		if (symbols->version < 19970000)
		{
			const PDB_SYMBOL_FILE* sym_file = reinterpret_cast<const PDB_SYMBOL_FILE*>(file);
			file_nr = sym_file->file;
			file_name = sym_file->filename;
			symbol_size = sym_file->symbol_size;
		}
		else
		{
			const PDB_SYMBOL_FILE_EX* sym_file = reinterpret_cast<const PDB_SYMBOL_FILE_EX*>(file);
			file_nr = sym_file->file;
			file_name = sym_file->filename;
			symbol_size = sym_file->symbol_size;
		}
		if (symbol_size && reader.read_file(file_nr, vmodimage))
			codeview_dump_symbols(vmodimage, sizeof(uint32_t));
		file_name += strlen(file_name) + 1;
		file = reinterpret_cast<char*>(reinterpret_cast<size_t>(file_name + strlen(file_name) + 1 + 3) & ~3);
	}
	return true;
}

void PDBFile::AddSymbol(size_t segment, size_t offset, const std::string& name)
{
	if (!segment || segment >= segments_.size())
		return;

	uint64_t address = segments_[segment] + offset;
	std::pair<uint64_t, std::string> key(address, name);
	if (map_.find(key) != map_.end())
		return;
	map_.insert(key);

	MapSection* section = GetSectionByType(msFunctions);
	if (!section)
		section = Add(msFunctions);

	section->Add(NOT_ID, address, 0, name);
}

void PDBFile::AddSection(size_t segment, size_t offset, uint64_t size, const std::string& name)
{
	if (segment >= segments_.size())
		return;

	MapSection* section = GetSectionByType(msSections);
	if (!section)
		section = Add(msSections);

	section->Add(segment, segments_[segment] + offset, size, name);
}

size_t leaf_length(const uint16_t* type)
{
	size_t res = sizeof(*type);
	switch (*type++) {
	case LF_CHAR:
		res += 1;
		break;
	case LF_SHORT:
	case LF_USHORT:
		res += 2;
		break;
	case LF_LONG:
	case LF_ULONG:
		res += 4;
		break;
	case LF_REAL32:
		res += 4;
		break;
	case LF_REAL48:
		res += 6;
		break;
	case LF_REAL80:
		res += 10;
		break;
	case LF_REAL128:
		res += 16;
		break;
	case LF_QUADWORD:
	case LF_UQUADWORD:
		res += 8;
		break;
	case LF_COMPLEX32:
		res += 4;
		break;
	case LF_COMPLEX80:
		res += 10;
		break;
	case LF_COMPLEX128:
		res += 16;
		break;
	case LF_VARSTRING:
		res += 2 + *type;
		break;
	}

	return res;
}

std::string PDBFile::GetTypeName(size_t data_type, const std::string& name)
{
	std::string res;
	const p_string* p_str;

	if (data_type < types_first_index_) {
		switch (data_type) {
		case T_VOID:
			res = "void";
			break;
		case T_CHAR:
			res = "char";
			break;
		case T_SHORT:
			res = "short";
			break;
		case T_LONG:
			res = "long";
			break;
		case T_QUAD:
			res = "__int64";
			break;
		case T_UCHAR:
			res = "unsigned char";
			break;
		case T_USHORT:
			res = "unsigned short";
			break;
		case T_ULONG:
			res = "unsigned long";
			break;
		case T_UQUAD:
			res = "unsigned __int64";
			break;
		case T_BOOL08:
		case T_BOOL16:
		case T_BOOL32:
		case T_BOOL64:
			res = "bool";
			break;
		case T_REAL32:
			res = "float";
			break;
		case T_REAL64:
			res = "double";
			break;
		case T_REAL80:
			res = "long double";
			break;
		case T_RCHAR:
			res = "char";
			break;
		case T_INT4:
			res = "int";
			break;
		case T_UINT4:
			res = "unsigned int";
			break;
		case T_WCHAR:
			res = "wchar_t";
			break;
		case T_CHAR16:
			res = "char16_t";
			break;
		case T_CHAR32:
			res = "char32_t";
			break;
		case T_PVOID: case T_PCHAR: case T_PSHORT: case T_PLONG: case T_PQUAD: case T_PUCHAR: case T_PUSHORT: case T_PULONG:
		case T_PUQUAD: case T_PBOOL08: case T_PBOOL16: case T_PBOOL32: case T_PBOOL64: case T_PREAL32: case T_PREAL64: case T_PREAL80:
		case T_PREAL128: case T_PREAL48: case T_PCPLX32: case T_PCPLX64: case T_PCPLX80: case T_PCPLX128: case T_PRCHAR: case T_PWCHAR:
		case T_PINT2: case T_PUINT2: case T_PINT4: case T_PUINT4: case T_PINT8: case T_PUINT8: case T_PCHAR16: case T_PCHAR32:

		case T_PFVOID: case T_PFCHAR: case T_PFSHORT: case T_PFLONG: case T_PFQUAD: case T_PFUCHAR: case T_PFUSHORT: case T_PFULONG:
		case T_PFUQUAD: case T_PFBOOL08: case T_PFBOOL16: case T_PFBOOL32: case T_PFBOOL64: case T_PFREAL32: case T_PFREAL64: case T_PFREAL80:
		case T_PFREAL128: case T_PFREAL48: case T_PFCPLX32: case T_PFCPLX64: case T_PFCPLX80: case T_PFCPLX128: case T_PFRCHAR: case T_PFWCHAR:
		case T_PFINT2: case T_PFUINT2: case T_PFINT4: case T_PFUINT4: case T_PFINT8: case T_PFUINT8: case T_PFCHAR16: case T_PFCHAR32:

		case T_PHVOID: case T_PHCHAR: case T_PHSHORT: case T_PHLONG: case T_PHQUAD: case T_PHUCHAR: case T_PHUSHORT: case T_PHULONG:
		case T_PHUQUAD: case T_PHBOOL08: case T_PHBOOL16: case T_PHBOOL32: case T_PHBOOL64: case T_PHREAL32: case T_PHREAL64: case T_PHREAL80:
		case T_PHREAL128: case T_PHREAL48: case T_PHCPLX32: case T_PHCPLX64: case T_PHCPLX80: case T_PHCPLX128: case T_PHRCHAR: case T_PHWCHAR:
		case T_PHINT2: case T_PHUINT2: case T_PHINT4: case T_PHUINT4: case T_PHINT8: case T_PHUINT8: case T_PHCHAR16: case T_PHCHAR32:

		case T_32PVOID: case T_32PCHAR: case T_32PSHORT: case T_32PLONG: case T_32PQUAD: case T_32PUCHAR: case T_32PUSHORT: case T_32PULONG:
		case T_32PUQUAD: case T_32PBOOL08: case T_32PBOOL16: case T_32PBOOL32: case T_32PBOOL64: case T_32PREAL32: case T_32PREAL64: case T_32PREAL80:
		case T_32PREAL128: case T_32PREAL48: case T_32PCPLX32: case T_32PCPLX64: case T_32PCPLX80: case T_32PCPLX128: case T_32PRCHAR: case T_32PWCHAR:
		case T_32PINT2: case T_32PUINT2: case T_32PINT4: case T_32PUINT4: case T_32PINT8: case T_32PUINT8: case T_32PCHAR16: case T_32PCHAR32:

		case T_32PFVOID: case T_32PFCHAR: case T_32PFSHORT: case T_32PFLONG: case T_32PFQUAD: case T_32PFUCHAR: case T_32PFUSHORT: case T_32PFULONG:
		case T_32PFUQUAD: case T_32PFBOOL08: case T_32PFBOOL16: case T_32PFBOOL32: case T_32PFBOOL64: case T_32PFREAL32: case T_32PFREAL64: case T_32PFREAL80:
		case T_32PFREAL128: case T_32PFREAL48: case T_32PFCPLX32: case T_32PFCPLX64: case T_32PFCPLX80: case T_32PFCPLX128: case T_32PFRCHAR: case T_32PFWCHAR:
		case T_32PFINT2: case T_32PFUINT2: case T_32PFINT4: case T_32PFUINT4: case T_32PFINT8: case T_32PFUINT8: case T_32PFCHAR16: case T_32PFCHAR32:

		case T_64PVOID: case T_64PCHAR: case T_64PSHORT: case T_64PLONG: case T_64PQUAD: case T_64PUCHAR: case T_64PUSHORT: case T_64PULONG:
		case T_64PUQUAD: case T_64PBOOL08: case T_64PBOOL16: case T_64PBOOL32: case T_64PBOOL64: case T_64PREAL32: case T_64PREAL64: case T_64PREAL80:
		case T_64PREAL128: case T_64PREAL48: case T_64PCPLX32: case T_64PCPLX64: case T_64PCPLX80: case T_64PCPLX128: case T_64PRCHAR: case T_64PWCHAR:
		case T_64PINT2: case T_64PUINT2: case T_64PINT4: case T_64PUINT4: case T_64PINT8: case T_64PUINT8: case T_64PCHAR16: case T_64PCHAR32:
			return GetTypeName(data_type & T_BASICTYPE_MASK, (!name.empty() && name.front() != '*' ? "* " : "*") + name);
		}
	}
	else if (data_type - types_first_index_ < types_offset_.size()) {
		const union codeview_type* type = types_offset_[data_type - types_first_index_];
		switch (type->generic.id) {
		case LF_MODIFIER_V1:
			if (type->modifier_v1.attribute & 0x01)
				res += "const ";
			if (type->modifier_v1.attribute & 0x02)
				res += "volatile ";
			if (type->modifier_v1.attribute & 0x04)
				res += "unaligned ";
			if (type->modifier_v1.attribute & ~0x07)
				res += "unknown ";
			if (!res.empty())
				res.pop_back();
			res = GetTypeName(type->modifier_v1.type, res);
		case LF_MODIFIER_V2:
			if (type->modifier_v2.attribute & 0x01)
				res += "const ";
			if (type->modifier_v2.attribute & 0x02)
				res += "volatile ";
			if (type->modifier_v2.attribute & 0x04)
				res += "unaligned ";
			if (type->modifier_v2.attribute & ~0x07)
				res += "unknown ";
			if (!res.empty())
				res.pop_back();
			res = GetTypeName(type->modifier_v2.type, res);
			break;
		case LF_POINTER_V1:
			return GetTypeName(type->pointer_v1.datatype, (!name.empty() && name.front() != '*' ? "* " : "*") + name);
		case LF_POINTER_V2:
			if (type->pointer_v2.attribute & 0x80)
				res = "&&";
			else if (type->pointer_v2.attribute & 0x20)
				res = '&';
			else
				res = '*';
			if (!name.empty() && name.front() != res.back())
				res += ' ';
			return GetTypeName(type->pointer_v2.datatype, res + name);
		case LF_ARRAY_V1:
			return GetTypeName(type->array_v1.elemtype, (!name.empty() && name.front() != '*' ? "* " : "*") + name);
		case LF_ARRAY_V2:
			return GetTypeName(type->array_v2.elemtype, (!name.empty() && name.front() != '*' ? "* " : "*") + name);
		case LF_ARRAY_V3:
			return GetTypeName(type->array_v3.elemtype, (!name.empty() && name.front() != '*' ? "* " : "*") + name);
		case LF_STRUCTURE_V1:
		case LF_CLASS_V1:
			p_str = reinterpret_cast<const p_string*>(reinterpret_cast<const char*>(&type->struct_v1.structlen) + leaf_length(&type->struct_v1.structlen));
			res = (type->generic.id == LF_CLASS_V1 ? "class " : "struct ") + std::string(p_str->name, p_str->namelen);
			break;
		case LF_STRUCTURE_V2:
		case LF_CLASS_V2:
			p_str = reinterpret_cast<const p_string*>(reinterpret_cast<const char*>(&type->struct_v2.structlen) + leaf_length(&type->struct_v2.structlen));
			res = (type->generic.id == LF_CLASS_V2 ? "class " : "struct ") + std::string(p_str->name, p_str->namelen);
			break;
		case LF_STRUCTURE_V3:
		case LF_CLASS_V3:
			res = (type->generic.id == LF_CLASS_V3 ? "class " : "struct ") + std::string(reinterpret_cast<const char*>(&type->struct_v3.structlen) + leaf_length(&type->struct_v3.structlen));
			break;
		case LF_ARGLIST_V1:
		{
			const union codeview_reftype* ref_type = reinterpret_cast<const union codeview_reftype*>(type);
			if (ref_type->arglist_v2.num == 0)
				res = GetTypeName(T_VOID, "");
			else for (size_t i = 0; i < ref_type->arglist_v1.num; i++) {
				if (i > 0)
					res += ',';
				res += GetTypeName(ref_type->arglist_v1.args[i], "");
			}
		}
		break;
		case LF_ARGLIST_V2:
		{
			const union codeview_reftype* ref_type = reinterpret_cast<const union codeview_reftype*>(type);
			if (ref_type->arglist_v2.num == 0)
				res = GetTypeName(T_VOID, "");
			else for (size_t i = 0; i < ref_type->arglist_v2.num; i++) {
				if (i > 0)
					res += ',';
				res += GetTypeName(ref_type->arglist_v2.args[i], "");
			}
		}
		break;
		case LF_PROCEDURE_V1:
			return GetTypeName(type->procedure_v1.rvtype, '(' + name + ')' + '(' + GetTypeName(type->procedure_v1.arglist, "") + ')');
		case LF_PROCEDURE_V2:
			return GetTypeName(type->procedure_v2.rvtype, '(' + name + ')' + '(' + GetTypeName(type->procedure_v2.arglist, "") + ')');
		case LF_UNION_V1:
			p_str = reinterpret_cast<const p_string*>(reinterpret_cast<const char*>(&type->union_v1.un_len) + leaf_length(&type->union_v1.un_len));
			res = "union " + std::string(p_str->name, p_str->namelen);
			break;
		case LF_UNION_V2:
			p_str = reinterpret_cast<const p_string*>(reinterpret_cast<const char*>(&type->union_v2.un_len) + leaf_length(&type->union_v2.un_len));
			res = "union " + std::string(p_str->name, p_str->namelen);
			break;
		case LF_UNION_V3:
			res = "union " + std::string(reinterpret_cast<const char*>(&type->union_v3.un_len) + leaf_length(&type->union_v3.un_len));
			break;
		case LF_ENUM_V1:
			res = "enum " + std::string(type->enumeration_v1.p_name.name, type->enumeration_v1.p_name.namelen);
			break;
		case LF_ENUM_V2:
			res = "enum " + std::string(type->enumeration_v2.p_name.name, type->enumeration_v2.p_name.namelen);
			break;
		case LF_ENUM_V3:
			res = "enum " + std::string(type->enumeration_v3.name);
			break;
		default:
			res = "???";
		}
	}

	if (!res.empty() && !name.empty())
		res += ' ';
	return res + name;
}

void PDBFile::codeview_dump_symbols(const std::vector<uint8_t>& root, size_t offset)
{
	size_t i;
	int length;
	for (i = offset; i < root.size(); i += length)
	{
		const union codeview_symbol* sym = reinterpret_cast<const union codeview_symbol*>(&root[0] + i);
		length = sym->generic.len + 2;
		if (!sym->generic.id || length < 4) break;
		switch (sym->generic.id)
		{
		case S_GDATA_V2:
		case S_LDATA_V2:
			AddSymbol(sym->data_v2.segment, sym->data_v2.offset, GetTypeName(sym->data_v2.symtype, std::string(sym->data_v2.p_name.name, sym->data_v2.p_name.namelen)));
			break;
		case S_LDATA_V3:
		case S_GDATA_V3:
			AddSymbol(sym->data_v3.segment, sym->data_v3.offset, GetTypeName(sym->data_v3.symtype, std::string(sym->data_v3.name)));
			break;
		case S_PUB_V2:
			AddSymbol(sym->public_v2.segment, sym->public_v2.offset, std::string(sym->public_v2.p_name.name, sym->public_v2.p_name.namelen));
			break;
		case S_PUB_V3:
			AddSymbol(sym->public_v3.segment, sym->public_v3.offset, std::string(sym->public_v3.name));
			break;
		case S_THUNK_V1:
			AddSymbol(sym->thunk_v1.segment, sym->thunk_v1.offset, std::string(sym->thunk_v1.p_name.name, sym->thunk_v1.p_name.namelen));
			break;
		case S_THUNK_V3:
			AddSymbol(sym->thunk_v3.segment, sym->thunk_v3.offset, std::string(sym->thunk_v3.name));
			break;
			//case S_GPROC_V1:
		case S_LPROC_V1:
			AddSymbol(sym->proc_v1.segment, sym->proc_v1.offset, std::string(sym->proc_v1.p_name.name, sym->proc_v1.p_name.namelen));
			break;
			//case S_GPROC_V2:
		case S_LPROC_V2:
			AddSymbol(sym->proc_v2.segment, sym->proc_v2.offset, std::string(sym->proc_v2.p_name.name, sym->proc_v2.p_name.namelen));
			break;
		case S_LPROC_V3:
			//case S_GPROC_V3:
			AddSymbol(sym->proc_v3.segment, sym->proc_v3.offset, std::string(sym->proc_v3.name));
			break;
		case S_SUBSECTINFO_V3:
			AddSection(*reinterpret_cast<const unsigned short*>(reinterpret_cast<const char*>(sym) + 16),
				*reinterpret_cast<const unsigned*>(reinterpret_cast<const char*>(sym) + 12),
				*reinterpret_cast<const unsigned*>(reinterpret_cast<const char*>(sym) + 4),
				std::string(reinterpret_cast<const char*>(sym) + 18));
			break;
		case S_LTHREAD_V1:
		case S_GTHREAD_V1:
			AddSymbol(sym->thread_v1.segment, sym->thread_v1.offset, std::string(sym->thread_v1.p_name.name, sym->thread_v1.p_name.namelen));
			break;
		case S_LTHREAD_V2:
		case S_GTHREAD_V2:
			AddSymbol(sym->thread_v2.segment, sym->thread_v2.offset, std::string(sym->thread_v2.p_name.name, sym->thread_v2.p_name.namelen));
			break;
		case S_LTHREAD_V3:
		case S_GTHREAD_V3:
			AddSymbol(sym->thread_v3.segment, sym->thread_v3.offset, std::string(sym->thread_v3.name));
			break;
		case S_PROCREF_V1:
		case S_DATAREF_V1:
		case S_LPROCREF_V1:
			length += (*(reinterpret_cast<const char*>(sym) + length) + 1 + 3) & ~3;
			break;
		}
	}
}

/**
 * COFFStringTable
 */

std::string COFFStringTable::GetString(uint32_t pos) const
{
	if (pos < sizeof(uint32_t))
		throw std::runtime_error("Invalid index for string table");

	if (pos >= data_.size())
		throw std::runtime_error("Invalid index for string table");

	size_t i, len;

	len = data_.size() - pos;
	for (i = 0; i < len; i++) {
		if (data_[pos + i] == 0) {
			len = i;
			break;
		}
	}
	if (len == data_.size() - pos)
		throw std::runtime_error("Invalid format");

	return std::string(&data_[pos], len);
}

void COFFStringTable::ReadFromFile(PEArchitecture& file)
{
	uint32_t size = file.ReadDWord();
	if (size < sizeof(size))
		throw std::runtime_error("Invalid format");

	data_.resize(size);
	file.Read(data_.data() + sizeof(uint32_t), data_.size() - sizeof(uint32_t));
}

void COFFStringTable::ReadFromFile(FileStream& file)
{
	uint32_t size = 0;
	file.Read(&size, sizeof(size));
	if (size < sizeof(size))
		throw std::runtime_error("Invalid format");

	data_.resize(size);
	file.Read(data_.data() + sizeof(uint32_t), data_.size() - sizeof(uint32_t));
}

/**
* COFFFile
*/

bool COFFFile::Parse(const char* file_name, const std::vector<uint64_t>& segments)
{
	clear();
	time_stamp_ = 0;
	file_name_ = file_name;

	FileStream fs;
	if (!fs.Open(file_name, fmOpenRead | fmShareDenyNone))
		return false;

	segments_ = segments;

	IMAGE_DOS_HEADER dos_header;
	if (fs.Read(&dos_header, sizeof(dos_header)) == sizeof(dos_header) && dos_header.e_magic == IMAGE_DOS_SIGNATURE) {
		if (fs.Seek(dos_header.e_lfanew, soBeginning) != (uint64_t)-1) {
			uint32_t signature = 0;
			fs.Read(&signature, sizeof(signature));
			if (signature == IMAGE_NT_SIGNATURE) {
				IMAGE_FILE_HEADER image_header = IMAGE_FILE_HEADER();
				fs.Read(&image_header, sizeof(image_header));
				if (image_header.PointerToSymbolTable) {
					time_stamp_ = image_header.TimeDateStamp;
					if (fs.Seek(image_header.PointerToSymbolTable + image_header.NumberOfSymbols * sizeof(IMAGE_SYMBOL), soBeginning) != (uint64_t)-1) {
						COFFStringTable string_table;
						string_table.ReadFromFile(fs);

						fs.Seek(image_header.PointerToSymbolTable, soBeginning);
						for (size_t i = 0; i < image_header.NumberOfSymbols; i++) {
							std::string name;
							IMAGE_SYMBOL sym;
							fs.Read(&sym, sizeof(sym));
							switch (sym.StorageClass) {
							case IMAGE_SYM_CLASS_EXTERNAL:
							case IMAGE_SYM_CLASS_STATIC:
								if (sym.N.Name.Short == 0) {
									name = string_table.GetString(sym.N.Name.Long);
								}
								else {
									name = std::string(reinterpret_cast<char*>(&sym.N.ShortName), strnlen(reinterpret_cast<char*>(&sym.N.ShortName), sizeof(sym.N.ShortName)));
								}
								AddSymbol(sym.SectionNumber, sym.Value, name);
							}
						}
						return true;
					}
				}
			}
		}
	}
	return false;
}

void COFFFile::AddSymbol(size_t segment, size_t offset, const std::string& name)
{
	if (!segment || segment >= segments_.size())
		return;

	uint64_t address = segments_[segment] + offset;
	MapSection* section = GetSectionByType(msFunctions);
	if (!section)
		section = Add(msFunctions);

	section->Add(NOT_ID, address, 0, name);
}
