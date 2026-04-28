/**
 * Utility function implementations for files module.
 * Rust mapping target: mod utils
 */

#include "../../runtime/common.h"
#include "../objects.h"
#include "../osutils.h"
#include "utils.h"

#include "../../third-party/demangle/undname.h"
#include "../../third-party/demangle/demangle.h"
#include "../../third-party/demangle/unmangle.h"

uint16_t OperandSizeToValue(OperandSize os)
{
	switch (os) {
	case osByte:
		return sizeof(uint8_t);
	case osWord:
		return sizeof(uint16_t);
	case osDWord:
		return sizeof(uint32_t);
	case osQWord:
		return sizeof(uint64_t);
	case osTByte:
		return 10;
	case osOWord:
		return 128;
	case osXMMWord:
		return 16;
	case osYMMWord:
		return 32;
	case osFWord:
		return 6;
	default:
		return 0;
	}
}

uint16_t OperandSizeToStack(OperandSize os)
{
	return OperandSizeToValue(os == osByte ? osWord : os);
}

std::string NameToString(const char name[], size_t name_size)
{
	size_t i, len;

	len = name_size;
	for (i = 0; i < name_size; i++) {
		if (name[i] == '\0') {
			len = i;
			break;
		}
	}
	return std::string(name, len);
}

std::string DisplayString(const std::string &str)
{
	std::string res;
	size_t p = 0;
	for (size_t i = 0; i < str.size(); i ++) {
		uint8_t c = static_cast<uint8_t>(str[i]);
		if (c < 32) {
			if (i > p)
				res += str.substr(p, i - p);
			switch (c) {
			case '\n':
				res += "\\n";
				break;
			case '\r':
				res += "\\r";
				break;
			case '\t':
				res += "\\t";
				break;
			default:
				res += string_format("\\%d", c);
				break;
			}
			p = i + 1;
		}
	}
	if (p) {
		res += str.substr(p);
		return res;
	}

	return str;
}

std::string DisplayValue(OperandSize size, uint64_t value)
{
	const char *format = (size == osQWord) ? "%.16llX" : "%.8X";
	return string_format(format, value);
}

extern "C" {
	void *C_alloca(size_t size)
	{
		return malloc(size);
	}
};

static FunctionName demangle_gcc(const std::string &name)
{
	const char *name_to_demangle = name.c_str();
	/* Apple special case: double-underscore. Remove first underscore. */
	if (name.size() >= 2 && name.substr(0, 2).compare("__") == 0)
		name_to_demangle++;

	std::string res;
	char *demangled_name = cplus_demangle_v3(name_to_demangle, DMGL_PARAMS | DMGL_ANSI | DMGL_TYPES);
	if (demangled_name) {
		res = demangled_name;
		free(demangled_name);
	}
	
	return FunctionName(res);
}

static FunctionName demangle_borland(const std::string &name)
{
	std::string name_to_demangle = name;

    char demangled_name[1024];
	demangled_name[0] = 0;

	int code = unmangle(&name_to_demangle[0], demangled_name, sizeof(demangled_name), NULL, NULL, 1);
	if ((code & (UM_BUFOVRFLW | UM_ERROR | UM_NOT_MANGLED)) == 0)
		return FunctionName(demangled_name);
	
	return FunctionName("");
}

static FunctionName demangle_msvc(const std::string &name)
{
	unsigned short flags = 
		UNDNAME_NO_LEADING_UNDERSCORES |
		UNDNAME_NO_MS_KEYWORDS |
		UNDNAME_NO_ALLOCATION_MODEL |
		UNDNAME_NO_ALLOCATION_LANGUAGE |
		UNDNAME_NO_MS_THISTYPE |
		UNDNAME_NO_CV_THISTYPE |
		UNDNAME_NO_THISTYPE |
		UNDNAME_NO_ACCESS_SPECIFIERS |
		UNDNAME_NO_THROW_SIGNATURES |
		UNDNAME_NO_MEMBER_TYPE |
		UNDNAME_NO_RETURN_UDT_MODEL |
		UNDNAME_32_BIT_DECODE;

	size_t name_pos = 0;
	char *demangled_name = undname(name.c_str(), flags, &name_pos);
	if (demangled_name) {
		std::string res = std::string(demangled_name);
		free(demangled_name);
		return FunctionName(res, name_pos);
	}

	return FunctionName("");
}

FunctionName DemangleName(const std::string &name)
{
	if (name.empty())
		return FunctionName(""); 

	typedef FunctionName (tdemangler)(const std::string &name);
	static tdemangler *demanglers[] = { 
		&demangle_msvc,
		&demangle_gcc,
		&demangle_borland
	};

	for (size_t i = 0; i < _countof(demanglers); i++) {
		FunctionName res = demanglers[i](name);
		if (!res.name().empty())
			return res;
	}
	return name;
}
