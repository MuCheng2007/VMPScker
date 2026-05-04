#ifndef INTEL_MISC_H
#define INTEL_MISC_H

#include "../../processors.h"
#include "../../files/types.h"
#include "../../files/markers.h"
#include "IntelCommandType.h"
#include <vector>

class IArchitecture;
class IntelCommand;
class MapFunction;
class MapFunctionList;

struct DisasmContext {
	IArchitecture *file;
	bool lower_reg;
	bool lower_address;
	uint8_t rex_prefix;
	uint8_t vex_registr;
	bool use_last_byte;
};

struct AsmContext {
	uint8_t rex_prefix;
};

enum CompileOperandOption {
	coSaveResult = 0x0001,
	coAsPointer = 0x0002,
	coInverse = 0x0004,
	coFixup = 0x0008,
	coAsWord = 0x0010
};

class IntelRegistrList : public std::vector<uint8_t>
{
public:
	IntelRegistrList() : std::vector<uint8_t>() {}
	uint8_t GetRandom(bool no_solid = false)
	{
		if (empty())
			return regEmpty;
		uint8_t res;
		while (true) {
			size_t i = rand() % size();
			res = at(i);
			if (no_solid && (res == regESI || res == regEDI || res == regEBP))
				continue;
			erase(begin() + i);
			break;
		}
		return res;
	}
	void remove(uint8_t reg)
	{
		iterator it = std::find(begin(), end(), reg);
		if (it != end())
			erase(it);
	}
	void remove(const IntelRegistrList &reg_list)
	{
		for (size_t i = 0; i < reg_list.size(); i++) {
			remove(reg_list[i]);
		}
	}
};

struct IntelVirtualMachineObfuscation
{
	IntelCommand *begin_;
	IntelCommand *end_;

	IntelVirtualMachineObfuscation(IntelCommand *begin, IntelCommand *end) : begin_(begin), end_(end) {
	}
};

class IntelFileHelper : public IObject
{
public:
	explicit IntelFileHelper();
	~IntelFileHelper();
	void Parse(IArchitecture &file);
private:
	void AddMarker(IArchitecture &file, uint64_t address, uint64_t name_reference, uint64_t name_address, ObjectType type, uint8_t tag, bool is_unicode);
	void AddString(IArchitecture &file, uint64_t address, uint64_t reference, bool is_unicode);
	void AddEndMarker(IArchitecture &file, uint64_t address, uint64_t next_address, ObjectType type);

	std::vector<MapFunction *> string_list_;
	MapFunctionList *marker_name_list_;
	size_t marker_index_;
	
	// no copy ctr or assignment op
	IntelFileHelper(const IntelFileHelper &);
	IntelFileHelper &operator =(const IntelFileHelper &);
};

#endif // INTEL_MISC_H