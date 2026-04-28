#include "IntelCommand.h"
#include "IntelVMCommand.h"
#include "IntelFunction.h"
#include "IntelFunctionList.h"
#include "../../processors.h"
#include "../../core_internal/core.h"
#include "../../files/architecture.h"
#include "../../files/mapping.h"
#include "../../files/types.h"
#include "../../pe/pefile.h"
#include "../../packer.h"
#include "../../streams.h"
#include "../../core_internal/watermark.h"
#include "../../../runtime/crypto.h"
#include "../../core_internal/file_manager.h"
#include "../../core_internal/license.h"

// VM layer
#include "../vm/IntelVirtualMachine.h"
#include "../vm/IntelVirtualMachineList.h"


/**
 * IntelCommand
 */

IntelCommand::IntelCommand(IFunction* owner, OperandSize size, uint64_t address)
	: BaseCommand(owner), address_(address), size_(size), type_(cmUnknown), flags_(0), preffix_command_(cmUnknown),
	base_segment_(segDefault), command_pos_(0), original_dump_size_(0), section_options_(0), vex_operand_(0),
	ext_vm_entry_(NULL), begin_section_cryptor_(NULL), end_section_cryptor_(NULL), seh_handler_(NULL)
{
	vm_command_info_list_ = new IntelCommandInfoList(size);
	if (address_)
		include_option(roClearOriginalCode);
#ifdef CHECKED
	update_hash();
#endif
}

IntelCommand::IntelCommand(IFunction* owner, OperandSize size, IntelCommandType type, IntelOperand operand1, IntelOperand operand2, IntelOperand operand3)
	: BaseCommand(owner), address_(0), size_(size), type_(cmUnknown), flags_(0), preffix_command_(cmUnknown), base_segment_(segDefault),
	command_pos_(0), original_dump_size_(0), section_options_(0), vex_operand_(0), ext_vm_entry_(NULL), begin_section_cryptor_(NULL),
	end_section_cryptor_(NULL), seh_handler_(NULL)
{
	vm_command_info_list_ = new IntelCommandInfoList(size);
	type_ = type;
	operand_[0] = operand1;
	operand_[1] = operand2;
	operand_[2] = operand3;
	for (size_t i = 0; i < _countof(operand_); i++) {
		IntelOperand* operand = &operand_[i];
		if (operand->size == osDefault)
			operand->size = size_;
		if (operand->address_size == osDefault)
			operand->address_size = size_;
	}
#ifdef CHECKED
	update_hash();
#endif
}

IntelCommand::IntelCommand(IFunction* owner, OperandSize size, const std::string& value)
	: BaseCommand(owner, value), address_(0), size_(size), type_(cmUnknown), flags_(0),
	preffix_command_(cmUnknown), base_segment_(segDefault), command_pos_(0), original_dump_size_(0), section_options_(0),
	vex_operand_(0), ext_vm_entry_(NULL), begin_section_cryptor_(NULL), end_section_cryptor_(NULL), seh_handler_(NULL)
{
	vm_command_info_list_ = new IntelCommandInfoList(size);
	type_ = cmDB;
#ifdef CHECKED
	update_hash();
#endif
}

IntelCommand::IntelCommand(IFunction* owner, OperandSize size, const os::unicode_string& value)
	: BaseCommand(owner, value), address_(0), size_(size), type_(cmUnknown), flags_(0),
	preffix_command_(cmUnknown), base_segment_(segDefault), command_pos_(0), original_dump_size_(0), section_options_(0),
	ext_vm_entry_(NULL), begin_section_cryptor_(NULL), end_section_cryptor_(NULL), seh_handler_(NULL)
{
	vm_command_info_list_ = new IntelCommandInfoList(size);
	type_ = cmDB;
#ifdef CHECKED
	update_hash();
#endif
}

IntelCommand::IntelCommand(IFunction* owner, OperandSize size, const Data& value)
	: BaseCommand(owner, value), address_(0), size_(size), type_(cmUnknown), flags_(0),
	preffix_command_(cmUnknown), base_segment_(segDefault), command_pos_(0), original_dump_size_(0), section_options_(0),
	ext_vm_entry_(NULL), begin_section_cryptor_(NULL), end_section_cryptor_(NULL), seh_handler_(NULL)
{
	vm_command_info_list_ = new IntelCommandInfoList(size);
	type_ = cmDB;
#ifdef CHECKED
	update_hash();
#endif
}

void IntelCommand::Init(IntelCommandType type, IntelOperand operand1, IntelOperand operand2, IntelOperand operand3)
{
	type_ = type;
	operand_[0] = operand1;
	operand_[1] = operand2;
	operand_[2] = operand3;
	for (size_t i = 0; i < _countof(operand_); i++) {
		IntelOperand* operand = &operand_[i];
		if (operand->size == osDefault)
			operand->size = size_;
		if (operand->address_size == osDefault)
			operand->address_size = size_;
	}
}

void IntelCommand::Init(const Data& data)
{
	type_ = cmDB;
	set_dump(data.data(), data.size());
}

void IntelCommand::InitUnknown()
{
	clear();
	type_ = cmUnknown;
	PushByte(0);
}

IntelCommand::IntelCommand(IFunction* owner, const IntelCommand& src)
	: BaseCommand(owner, src), section_options_(0), ext_vm_entry_(NULL), begin_section_cryptor_(NULL), end_section_cryptor_(NULL)
{
	vm_command_info_list_ = new IntelCommandInfoList(src.size());
	address_ = src.address_;
	size_ = src.size_;
	type_ = src.type_;
	flags_ = src.flags_;
	preffix_command_ = src.preffix_command_;
	base_segment_ = src.base_segment_;
	command_pos_ = src.command_pos_;
	original_dump_size_ = src.original_dump_size_;
	vex_operand_ = src.vex_operand_;
	seh_handler_ = src.seh_handler_;

	for (size_t i = 0; i < _countof(operand_); i++) {
		operand_[i] = src.operand_[i];
	}
#ifdef CHECKED
	update_hash();
#endif
}

IntelCommand::~IntelCommand()
{
	delete vm_command_info_list_;
}

void IntelCommand::clear()
{
	type_ = cmUnknown;
	base_segment_ = segDefault;
	preffix_command_ = cmUnknown;
	flags_ = 0;
	command_pos_ = 0;
	for (size_t i = 0; i < _countof(operand_); i++) {
		operand_[i].Clear();
	}
	vm_command_info_list_->clear();
	BaseCommand::clear();
}

IntelCommand* IntelCommand::Clone(IFunction* owner) const
{
	IntelCommand* command = new IntelCommand(owner, *this);
	return command;
}

bool IntelCommand::is_data() const
{
	return (type_ == cmDB || type_ == cmDW || type_ == cmDD || type_ == cmDQ || type_ == cmSleb || type_ == cmUleb || type_ == cmDC);
}

bool IntelCommand::is_end() const
{
	return (type_ == cmRet || type_ == cmIret || type_ == cmJmp || ((type_ == cmCall || type_ == cmJmpWithFlag) && (options() & roUseAsJmp)) || is_data());
}

static const char* size_name[] = {
	"byte",
	"word",
	"dword",
	"qword",
	"tbyte",
	"oword",
	"xmmword",
	"ymmword",
	"fword"
};

static const char* segment_name[] = {
	"es",
	"cs",
	"ss",
	"ds",
	"fs",
	"gs"
};

static const char* registr_name[4][22] = {
	{"al","cl","dl","bl","spl","bpl","sil","dil","r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b","fl","tl","rl","il","kl","el"},
	{"ax","cx","dx","bx","sp","bp","si","di","r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w","fx","tx","rx","ix","kx","ex"},
	{"eax","ecx","edx","ebx","esp","ebp","esi","edi","r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d","efx","etx","erx","eix","ekx","eex"},
	{"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15","rfx","rtx","rrx","rix","rkx","rex"}
};

bool IntelCommand::GetOperandText(std::string& str, size_t index) const
{
	const IntelOperand* operand = &operand_[index];

	if (operand->type == otNone)
		return false;

	str.clear();
	if (operand->type & otMemory) {
		if (operand->show_size)
			str.append(size_name[operand->size]).append(" ptr ");

		if (base_segment_ != segDefault && type_ != cmLea)
			str.append(segment_name[base_segment_]).append(":");

		str.append("[");
		if (operand->type & otBaseRegistr)
			str.append(registr_name[operand->address_size][operand->base_registr]);
	}

	if (operand->type & otRegistr) {
		if (operand->type & otMemory) {
			if (operand->type & otBaseRegistr)
				str.append("+");
			str.append(registr_name[operand->address_size][operand->registr]);
			if (operand->scale_registr)
				str.append(string_format("*%d", 2 << (operand->scale_registr - 1)));
		}
		else {
			str.append(operand->size > osQWord ? "???" : registr_name[operand->size][operand->registr]);
		}
	}
	else if (operand->type & otHiPartRegistr) {
		str.append(std::string(registr_name[osWord][operand->registr & 3], 1));
		str.append("h");
	}
	else if (operand->type & otFPURegistr) {
		str.append(string_format("st%d", operand->registr));
	}
	else if (operand->type & otSegmentRegistr) {
		str.append(operand->registr > segGS ? "???" : segment_name[operand->registr]);
	}
	else if (operand->type & otControlRegistr) {
		str.append(string_format("cr%d", operand->registr));
	}
	else if (operand->type & otDebugRegistr) {
		str.append(string_format("dr%d", operand->registr));
	}
	else if (operand->type & otMMXRegistr) {
		str.append(string_format("mm%d", operand->registr));
	}
	else if (operand->type & otXMMRegistr) {
		str.append(string_format((operand->size == osYMMWord) ? "ymm%d" : "xmm%d", operand->registr));
	}

	if (operand->type & otValue) {
		int64_t value = operand->value;
		bool is_neg = (value < 0 && (operand->size > operand->value_size || (operand->type & (otMemory | otRegistr | otBaseRegistr)) > otMemory));
		if (is_neg) {
			str.append("-");
			value = -value;
		}
		else if (operand->type & (otRegistr | otBaseRegistr)) {
			str.append("+");
		}

		if (operand->type == otValue && operand->size == osFWord) {
			switch (operand->value_size) {
			case osWord:
				str.append(string_format("%.4X:%.4X", static_cast<uint16_t>(operand->value >> 16), static_cast<uint16_t>(operand->value)));
				break;
			case osDWord:
				str.append(string_format("%.4X:%.8X", static_cast<uint16_t>(operand->value >> 32), static_cast<uint32_t>(operand->value)));
				break;
			}
		}
		else {
			switch (operand->value_size) {
			case osByte:
				str.append(string_format("%.2X", static_cast<uint8_t>(value)));
				break;
			case osWord:
				str.append(string_format("%.4X", static_cast<uint16_t>(value)));
				break;
			case osDWord:
				str.append(string_format("%.8X", static_cast<uint32_t>(value)));
				break;
			case osQWord:
				str.append(string_format("%.16llX", value));
				break;
			}
		}
	}

	if (operand->type & otMemory)
		str.append("]");

	return true;
}

std::string IntelCommand::text() const
{
	std::string res, operand_text;
	size_t i;

	if (type_ == cmDB) {
		res.append(intel_command_name[type_]);
		for (i = 0; i < dump_size(); i++) {
			if (i > 0)
				res.append(",");
			res.append(string_format(" %.2X", dump(i)));
		}
	}
	else {
		if (options() & roLockPrefix)
			res.append("lock ");

		if (preffix_command_ != cmUnknown)
			res.append(intel_command_name[preffix_command_]).append(" ");

		if (options() & roVexPrefix)
			res.append("v");

		if (type_ == cmJCXZ && operand_[1].size > osWord) {
			res.append(operand_[1].size == osDWord ? "jecxz" : "jrcxz");
		}
		else {
			res.append(intel_command_name[type_]);
		}

		if (flags_) {
			if (options() & roInverseFlag)
				res.append("n");
			switch (flags_) {
			case fl_O:
				res.append("o");
				break;
			case fl_C:
				res.append("b");
				break;
			case fl_Z:
				res.append("z");
				break;
			case fl_C | fl_Z:
				res.append("be");
				break;
			case fl_P:
				res.append("p");
				break;
			case fl_S | fl_O:
				res.append("l");
				break;
			case fl_S:
				res.append("s");
				break;
			case fl_Z | fl_S | fl_O:
				res.append("le");
				break;
			default:
				res.append("?");
				break;
			}
		}

		switch (type_) {
		case cmLods:
		case cmScas:
		case cmCmps:
		case cmMovs:
		case cmStos:
		case cmIns:
		case cmOuts:
			res.append(std::string(size_name[operand_[0].size], 1));
			break;
		case cmPusha:
		case cmPopa:
		case cmPushf:
		case cmPopf:
		case cmIret:
			if (operand_[0].size > osWord)
				res.append(std::string(size_name[operand_[0].size], 1));
			break;
		case cmXlat:
			res.append(std::string(size_name[osByte], 1));
			break;
		case cmRet:
			if ((options() & roFar) != 0)
				res.append("f");
			break;
		}

		for (i = 0; i < _countof(operand_); i++) {
			if (vex_operand_ && (vex_operand_ & 0x3) == i) {
				res.append(", ");
				res.append(string_format((vex_operand_ & 4) ? "ymm%d" : "xmm%d", (vex_operand_ >> 4) & 0x0f));
			}

			if (!GetOperandText(operand_text, i))
				break;

			if (i > 0)
				res.append(",");
			res.append(" ").append(operand_text);
		}
	}

	return res;
}

CommentInfo IntelCommand::comment()
{
	CommentInfo res = BaseCommand::comment();
	if (res.type != ttUnknown)
		return res;

	res.type = ttNone;
	if ((options() & roFar) == 0) {
		IArchitecture* file = owner()->owner()->owner();
		if (file) {
			size_t operand_index = NOT_ID;
			for (size_t i = 2; i > 0; i--) {
				if (operand_[i - 1].type == otValue || operand_[i - 1].type == (otMemory | otValue)) {
					operand_index = i - 1;
					break;
				}
			}
			if (operand_index != NOT_ID) {
				uint64_t address = operand_[operand_index].value;
				if (IRelocation* relocation = operand_[operand_index].relocation) {
					if (IImportFunction* import_function = file->import_list()->GetFunctionByAddress(relocation->address())) {
						res.value = string_format("%c %s", 3, import_function->full_name().c_str());
						res.type = ttImport;
					}
					else if (ISymbol* symbol = relocation->symbol()) {
						address = symbol->address();
						res.value = string_format("%c %s", 3, symbol->display_name().c_str());
						if (file->export_list()->GetExportByAddress(address))
							res.type = ttExport;
						else if (file->segment_list()->GetMemoryTypeByAddress(address) & mtExecutable)
							res.type = ttFunction;
						else
							res.type = ttVariable;
					}
				}
				else if (IImportFunction* import_function = file->import_list()->GetFunctionByAddress(address)) {
					res.value = string_format("%c %s", 3, import_function->full_name().c_str());
					res.type = ttImport;
				}
				else if (IRelocation* relocation = file->relocation_list() ? file->relocation_list()->GetRelocationByAddress(address) : NULL) {
					if (ISymbol* symbol = relocation->symbol()) {
						address = symbol->address();
						res.value = string_format("%c %s", 3, symbol->display_name().c_str());
						if (file->export_list()->GetExportByAddress(address))
							res.type = ttExport;
						else if (file->segment_list()->GetMemoryTypeByAddress(address) & mtExecutable)
							res.type = ttFunction;
						else
							res.type = ttVariable;
					}
				}
				else if (MapFunction* map_function = file->map_function_list()->GetFunctionByAddress(address)) {
					if (map_function->type() == otData) {
						if (map_function->name().compare("`string'") == 0) {
							std::string str = file->ReadString(address);
							if (!str.empty()) {
								res.value = string_format("%c string \"%s\"", 3, DisplayString(str).c_str());
								res.type = ttString;
							}
						}
						else {
							res.value = string_format("%c %s", 3, map_function->name().c_str());
							res.type = ttVariable;
						}
					}
					else {
						res.value = string_format("%c %s", 3, map_function->name().c_str());
						switch (map_function->type()) {
						case otString:
							res.type = ttString;
							break;
						case otExport:
							res.type = ttExport;
							break;
						default:
							res.type = ttFunction;
							break;
						}
					}
				}
				else if (type_ == cmLea || operand_[operand_index].type == otValue) {
					if (type_ == cmCall || type_ == cmJmp || type_ == cmJmpWithFlag || type_ == cmLoope || type_ == cmLoopne || type_ == cmLoop || type_ == cmJCXZ) {
						res.value = (next_address() > address) ? char(2) : char(4);
						res.type = ttJmp;
					}
					else {
						std::string str = file->ReadString(address);
						if (!str.empty()) {
							res.value = string_format("%c string \"%s\"", 3, DisplayString(str).c_str());
							res.type = ttString;
						}
					}
				}
			}
		}
	}

	set_comment(res);

	return res;
}

std::string IntelCommand::dump_str() const
{
	std::string res;
	if (type_ == cmUnknown) {
		for (size_t i = 0; i < dump_size(); i++) {
			res += "??";
		}
		return res;
	}

	res = BaseCommand::dump_str();

	size_t i, c;
	c = 0;
	for (i = 0; i < command_pos_; i++) {
		res.insert((i + 1) * 2 + c, ":");
		c++;
	}
	for (i = 0; i < _countof(operand_); i++) {
		const IntelOperand* operand = &operand_[i];
		if (operand->type == otNone)
			break;

		if ((operand->type & otValue) && operand->value_pos) {
			res.insert(operand->value_pos * 2 + c, " ");
			c++;
		}
	}

	return res;
}

std::string IntelCommand::display_address() const
{
	return DisplayValue(size(), address());
}

bool IntelCommand::is_equal(const IntelCommand& command) const
{
	if (type_ != command.type_)
		return false;
	for (size_t i = 0; i < _countof(operand_); i++) {
		if (operand_[i] != command.operand_[i])
			return false;
	}
	return true;
}

IntelOperand* IntelCommand::GetFreeOperand()
{
	for (size_t i = 0; i < _countof(operand_); i++) {
		IntelOperand* operand = &operand_[i];
		if (operand->type == otNone) {
			operand->Clear();
			return operand;
		}
	}

	return NULL;
}

static OperandSize GetOperandSize(uint8_t code, const DisasmContext& ctx)
{
	if ((code & 1) == 0)
		return osByte;
	if (ctx.rex_prefix & rexW)
		return osQWord;
	if (ctx.lower_reg)
		return osWord;
	return osDWord;
}

static OperandSize GetDefaultOperandSize(const DisasmContext& ctx)
{
	if ((ctx.rex_prefix & rexW) == 0 && ctx.lower_reg)
		return osWord;
	return ctx.file->cpu_address_size();
}

static OperandSize GetAddressSize(const DisasmContext& ctx)
{
	OperandSize cpu_address_size = ctx.file->cpu_address_size();

	if (ctx.lower_address)
		return (cpu_address_size == osQWord) ? osDWord : osWord;
	return cpu_address_size;
}

void IntelCommand::ReadFlags(uint8_t code)
{
	switch ((code >> 1) & 7) {
	case 0x00:
		flags_ = fl_O;
		break;
	case 0x01:
		flags_ = fl_C;
		break;
	case 0x02:
		flags_ = fl_Z;
		break;
	case 0x03:
		flags_ = fl_C | fl_Z;
		break;
	case 0x04:
		flags_ = fl_S;
		break;
	case 0x05:
		flags_ = fl_P;
		break;
	case 0x06:
		flags_ = fl_S | fl_O;
		break;
	case 0x07:
		flags_ = fl_Z | fl_S | fl_O;
		break;
	}

	if (code & 1)
		include_option(roInverseFlag);
}

void IntelCommand::ReadReg(uint8_t code, OperandSize operand_size, OperandType operand_type, const DisasmContext& ctx)
{
	IntelOperand* operand = GetFreeOperand();
	if (operand == NULL)
		throw std::runtime_error("ReadReg no free operands");

	operand->type = operand_type;
	operand->size = operand_size;
	operand->registr = (code & 7);

	if (ctx.rex_prefix && operand_type == otRegistr) {
		if (ctx.rex_prefix & rexB)
			operand->registr |= 8;
	}
	else if (operand_type == otRegistr && operand_size == osByte && operand->registr >= 4) {
		operand->type = otHiPartRegistr;
		operand->registr &= 3;
	}
}

void IntelCommand::ReadRegFromRM(uint8_t code, OperandSize operand_size, OperandType operand_type, const DisasmContext& ctx)
{
	IntelOperand* operand = GetFreeOperand();
	if (operand == NULL)
		throw std::runtime_error("ReadRegFromRM no free operands");

	operand->type = operand_type;
	operand->size = operand_size;
	operand->registr = ((code >> 3) & 7);

	if (ctx.rex_prefix && (operand_type == otRegistr || operand_type == otDebugRegistr || operand_type == otControlRegistr || operand_type == otXMMRegistr)) {
		if (ctx.rex_prefix & rexR)
			operand->registr |= 8;
	}
	else if (operand_type == otRegistr && operand_size == osByte && operand->registr >= 4) {
		operand->type = otHiPartRegistr;
		operand->registr &= 3;
	}
}

void IntelCommand::ReadRM(uint8_t code, OperandSize operand_size, OperandType operand_type, bool show_size, const DisasmContext& ctx)
{
	IntelOperand* operand = GetFreeOperand();
	if (operand == NULL)
		throw std::runtime_error("ReadRM no free operands");

	OperandSize value_size = osByte;
	uint8_t sib;

	switch (code & 0xc0) {
	case 0x00:
		if ((!ctx.lower_address && (code & 7) == 5) || (ctx.lower_address && (code & 7) == 6)) {
			operand->type = otMemory | otValue;
			value_size = GetAddressSize(ctx);
		}
		else {
			operand->type = otMemory | otRegistr;
		}
		break;
	case 0x40:
		operand->type = otMemory | otRegistr | otValue;
		break;
	case 0x80:
		operand->type = otMemory | otRegistr | otValue;
		value_size = GetAddressSize(ctx);
		break;
	default:
		operand->type = operand_type;
		break;
	}
	operand->size = operand_size;

	if (operand->type & otMemory) {
		operand->show_size = show_size;
		operand->address_size = GetAddressSize(ctx);

		if (operand->address_size == osWord) {
			if ((code & 7) < 4) {
				operand->base_registr = (code & 2) == 0 ? regEBX : regEBP;
				operand->type |= otBaseRegistr;
			}

			if (operand->type & otRegistr) {
				switch (code & 7) {
				case 0x00:
					operand->registr = regESI;
					operand->base_registr = regEBX;
					break;
				case 0x01:
					operand->registr = regEDI;
					operand->base_registr = regEBX;
					break;
				case 0x02:
					operand->registr = regESI;
					operand->base_registr = regEBP;
					break;
				case 0x03:
					operand->registr = regEDI;
					operand->base_registr = regEBP;
					break;
				case 0x04:
					operand->registr = regESI;
					break;
				case 0x05:
					operand->registr = regEDI;
					break;
				case 0x06:
					operand->registr = regEBP;
					break;
				case 0x07:
					operand->registr = regEBX;
					break;
				}
			}
		}
		else {
			if ((code & 7) == 4) {
				sib = ReadByte(*ctx.file);
				operand->registr = ((sib >> 3) & 7);
				operand->base_registr = (sib & 7);
				operand->type |= otBaseRegistr;

				if (ctx.rex_prefix) {
					if (ctx.rex_prefix & rexB)
						operand->base_registr |= 8;
					if (ctx.rex_prefix & rexX)
						operand->registr |= 8;
				}

				if (operand->registr == regESP)
					operand->type &= ~otRegistr;
				else
					operand->scale_registr = (sib >> 6);

				if ((code & 0xc0) == 0 && (operand->base_registr & 7) == regEBP) {
					operand->type &= ~otBaseRegistr;
					operand->type |= otValue;
				}

				if (operand->type & otValue) {
					switch (code & 0xc0) {
					case 0x00:
						value_size = osDWord;
						break;
					case 0x40:
						value_size = osByte;
						break;
					case 0x80:
						value_size = osDWord;
						break;
					}
				}
			}
			else {
				operand->registr = (code & 7);
				if (ctx.rex_prefix) {
					if (ctx.rex_prefix & rexB)
						operand->registr |= 8;
				}
			}
		}

		if (operand->type & otValue) {
			operand->value_size = value_size;
			operand->value_pos = static_cast<uint8_t>(dump_size());
			switch (value_size) {
			case osByte:
				operand->value = ByteToInt64(ReadByte(*ctx.file));
				break;
			case osWord:
				operand->value = WordToInt64(ReadWord(*ctx.file));
				break;
			case osDWord:
				operand->value = DWordToInt64(ReadDWord(*ctx.file));
				break;
			case osQWord:
				operand->value = DWordToInt64(ReadDWord(*ctx.file));
				if (operand->type == (otValue | otMemory))
					operand->is_large_value = true;
				break;
			}
		}
	}
	else {
		operand->registr = (code & 7);
		if (ctx.rex_prefix && (operand_type == otRegistr || operand_type == otDebugRegistr || operand_type == otControlRegistr || operand_type == otXMMRegistr)) {
			if (ctx.rex_prefix & rexB)
				operand->registr |= 8;
		}
		else if (operand_type == otRegistr && operand_size == osByte && operand->registr >= 4) {
			operand->type = otHiPartRegistr;
			operand->registr &= 3;
		}
	}
}

IntelOperand* IntelCommand::ReadValue(OperandSize operand_size, OperandSize value_size, const DisasmContext& ctx)
{
	IntelOperand* operand = GetFreeOperand();
	if (operand == NULL)
		throw std::runtime_error("ReadValue no free operands");

	operand->type = otValue;
	operand->size = operand_size;
	operand->value_size = value_size;
	operand->value_pos = static_cast<uint8_t>(dump_size());

	switch (value_size) {
	case osByte:
		operand->value = ByteToInt64(ReadByte(*ctx.file));
		break;
	case osWord:
		operand->value = WordToInt64(ReadWord(*ctx.file));
		break;
	case osDWord:
		operand->value = DWordToInt64(ReadDWord(*ctx.file));
		break;
	case osQWord:
		operand->value = ReadQWord(*ctx.file);
		break;
	}

	if (operand_size == osFWord)
		operand->value |= static_cast<uint64_t>(ReadWord(*ctx.file)) << (value_size == osWord ? 16 : 32);

	return operand;
}

void IntelCommand::ReadValueAddAddress(OperandSize operand_size, OperandSize value_size, const DisasmContext& ctx)
{
	IntelOperand* operand = ReadValue(operand_size, value_size, ctx);
	operand->value += next_address();
	operand->value_size = operand_size;

	switch (operand_size) {
	case osWord:
		operand->value = static_cast<uint16_t>(operand->value);
		break;
	case osDWord:
		operand->value = static_cast<uint32_t>(operand->value);
		break;
	}
}

uint64_t IntelCommand::ReadValueFromFile(IArchitecture& file, OperandSize value_size)
{
	DisasmContext ctx;
	IntelOperand* operand;

	switch (value_size) {
	case osByte:
		type_ = cmDB;
		break;
	case osWord:
		type_ = cmDW;
		break;
	case osDWord:
		type_ = cmDD;
		break;
	case osQWord:
		type_ = cmDQ;
		break;
	default:
		throw std::runtime_error("Invalid value size");
	}

	ctx.file = &file;
	ctx.lower_address = false;
	ctx.lower_reg = false;
	ctx.rex_prefix = 0;

	operand = ReadValue(value_size, value_size, ctx);
	operand->fixup = file.fixup_list()->GetFixupByAddress(address() + operand->value_pos);

	if (file.relocation_list())
		operand->relocation = file.relocation_list()->GetRelocationByAddress(address() + operand->value_pos);

	return operand->value;
}

enum OperandFlags {
	of_None = 0,

	of_Registr = 0x01000000,
	of_DebugRegistr = 0x02000000,
	of_ControlRegistr = 0x03000000,
	of_FPURegistr = 0x04000000,
	of_MMXRegistr = 0x05000000,
	of_XMMRegistr = 0x06000000,
	of_Value = 0x07000000,
	of_SegmentRegistr = 0x08000000,

	of_RM = 0x10000000,
	of_RegRM = 0x20000000,
	of_Reg = 0x30000000,
	of_Const = 0x40000000,
	of_Relative = 0x50000000,
	of_Far = 0x60000000,
	of_Memory = 0x70000000,
	of_XReg = 0x80000000,

	of_size = 0x00000100,
	of_mem_word = 0x00000200,
	of_mem_only = 0x00000400,
	of_reg_only = 0x00000800,

	of_value_b = 0x00000001,
	of_value_w = 0x00000002,
	of_value_z = 0x00000003,
	of_value_v = 0x00000004,

	of_E = (of_RM | of_Registr),
	of_G = (of_RegRM | of_Registr),
	of_IB = (of_Value | of_value_b),
	of_IW = (of_Value | of_value_w),
	of_IZ = (of_Value | of_value_z),
	of_IV = (of_Value | of_value_v),
	of_M = (of_RM | of_Registr | of_mem_only),
	of_J = (of_Value | of_Relative),
	of_S = (of_RegRM | of_SegmentRegistr),
	of_A = (of_Value | of_Far),
	of_O = (of_Value | of_Memory),
	of_V = (of_RegRM | of_XMMRegistr),
	of_W = (of_RM | of_XMMRegistr),
	of_X = (of_XReg | of_XMMRegistr),
	of_ST = (of_Const | of_FPURegistr),
	of_U = (of_RM | of_XMMRegistr | of_reg_only),
	of_C = (of_RegRM | of_ControlRegistr),
	of_R = (of_RM | of_Registr | of_reg_only),
	of_D = (of_RegRM | of_DebugRegistr),
	of_Q = (of_RM | of_MMXRegistr),
	of_P = (of_RegRM | of_MMXRegistr),
	of_N = (of_RM | of_MMXRegistr | of_reg_only),
	of_FI = (of_Const | of_Value),
	of_FS = (of_Const | of_SegmentRegistr),
	of_FG = (of_Const | of_Registr),
	of_Z = (of_Reg | of_Registr),

	of_b = 0x00010000,
	of_w = 0x00020000,
	of_v = 0x00030000,
	of_d = 0x00040000,
	of_z = 0x00050000,
	of_p = 0x00060000,
	of_t = 0x00070000,
	of_q = 0x00080000,
	of_s = 0x00090000,
	of_dq = 0x000E0000,
	of_qq = 0x000F0000,
	of_o = 0x00130000,
	of_x = 0x00150000,
	of_vdef = 0x00FC0000,
	of_cpu = 0x00FD0000,
	of_adr = 0x00FE0000,
	of_def = 0x00FF0000,

	of_Eb = (of_E | of_b),
	of_Ew = (of_E | of_w),
	of_Ed = (of_E | of_d),
	of_Eq = (of_E | of_q),
	of_Ev = (of_E | of_v),
	of_Ex = (of_E | of_x | of_size),
	of_Edef = (of_E | of_def),
	of_Gb = (of_G | of_b),
	of_Gw = (of_G | of_w),
	of_Gd = (of_G | of_d),
	of_Gv = (of_G | of_v),
	of_Gz = (of_G | of_z),
	of_Gx = (of_G | of_x),
	of_FGb = (of_FG | of_b),
	of_FGw = (of_FG | of_w),
	of_FGv = (of_FG | of_v),
	of_IBb = (of_IB | of_b),
	of_IBv = (of_IB | of_v),
	of_IZv = (of_IZ | of_v),
	of_IVv = (of_IV | of_v),
	of_IWw = (of_IW | of_w),
	of_Ma = (of_M | of_v),
	of_FSdef = (of_FS | of_def),
	of_Jb = (of_J | of_b),
	of_Jz = (of_J | of_z),
	of_Sw = (of_S | of_w),
	of_Mb = (of_M | of_b),
	of_Mw = (of_M | of_w),
	of_Mv = (of_M | of_v),
	of_Md = (of_M | of_d),
	of_Mq = (of_M | of_q),
	of_Mt = (of_M | of_t),
	of_Ms = (of_M | of_s),
	of_Mp = (of_M | of_p),
	of_Mdq = (of_M | of_dq),
	of_Mdef = (of_M | of_vdef | of_size),
	of_Mx = (of_M | of_x),
	of_Ap = (of_A | of_p),
	of_Ob = (of_O | of_b),
	of_Ov = (of_O | of_v),
	of_FIb = (of_FI | of_b),
	of_Vdq = (of_V | of_dq),
	of_Vqq = (of_V | of_qq),
	of_Vdef = (of_V | of_vdef),
	of_Ww = (of_W | of_w | of_size),
	of_Wd = (of_W | of_d | of_size),
	of_Wq = (of_W | of_q | of_size),
	of_Wdq = (of_W | of_dq | of_size),
	of_Wdef = (of_W | of_vdef | of_size),
	of_Xdq = (of_X | of_dq),
	of_Xdef = (of_X | of_vdef),
	of_Udq = (of_U | of_dq),
	of_Udef = (of_U | of_vdef),
	of_Nq = (of_N | of_q),
	of_Zb = (of_Z | of_b),
	of_Zv = (of_Z | of_v),
	of_Zdef = (of_Z | of_def),
	of_Rcpu = (of_R | of_cpu),
	of_Ccpu = (of_C | of_cpu),
	of_Dcpu = (of_D | of_cpu),
	of_Qd = (of_Q | of_d),
	of_Qq = (of_Q | of_q),
	of_Pq = (of_P | of_q),
};

void IntelCommand::ReadCommand(IntelCommandType type, uint32_t of_1, uint32_t of_2, uint32_t of_3, DisasmContext& ctx)
{
	size_t i;
	uint32_t of;
	uint8_t code;
	OperandSize os;
	IntelOperand* operand;
	OperandType ot;
	bool need_read_code;
	uint32_t ofs[] = { of_1, of_2, of_3 };

	type_ = type;

	if (ctx.use_last_byte) {
		code = dump(dump_size() - 1);
		need_read_code = false;
	}
	else {
		code = 0;
		need_read_code = true;
	}

	for (i = 0; i < _countof(ofs); i++) {
		of = ofs[i];

		if (of == of_None)
			break;

		switch (of & 0x00FF0000) {
		case of_b:
			os = osByte;
			break;
		case of_w:
			os = osWord;
			break;
		case of_d:
			os = osDWord;
			break;
		case of_q:
			os = osQWord;
			break;
		case of_v:
			os = GetOperandSize(1, ctx);
			break;
		case of_z:
			os = ((ctx.rex_prefix & rexW) == 0 && ctx.lower_reg) ? osWord : osDWord;
			break;
		case of_x:
			os = (ctx.rex_prefix & rexW) ? osQWord : osDWord;
			break;
		case of_adr:
			os = GetAddressSize(ctx);
			break;
		case of_def:
			os = GetDefaultOperandSize(ctx);
			break;
		case of_p:
			os = osFWord;
			break;
		case of_t:
			os = osTByte;
			break;
		case of_cpu:
			os = size_;
			break;
		case of_s:
			// FIXME
			os = osByte;
			break;
		case of_o:
			os = osOWord;
			break;
		case of_dq:
			os = osXMMWord;
			break;
		case of_qq:
			os = osYMMWord;
			break;
		case of_vdef:
			os = ((options() & roVexPrefix) && (ctx.rex_prefix & 0x80)) ? osYMMWord : osXMMWord;
			break;
		default:
			os = osByte;
			break;
		}

		switch (of & 0x0F000000) {
		case of_Registr:
			ot = otRegistr;
			break;
		case of_DebugRegistr:
			ot = otDebugRegistr;
			break;
		case of_ControlRegistr:
			ot = otControlRegistr;
			break;
		case of_FPURegistr:
			ot = otFPURegistr;
			break;
		case of_MMXRegistr:
			ot = otMMXRegistr;
			break;
		case of_XMMRegistr:
			ot = otXMMRegistr;
			break;
		case of_Value:
			ot = otValue;
			break;
		case of_SegmentRegistr:
			ot = otSegmentRegistr;
			break;
		default:
			operand_[i].size = os;
			continue;
		}

		if (ot == otValue) {
			switch (of & 0xF0000000) {
			case of_Relative:
				ReadValueAddAddress(GetDefaultOperandSize(ctx), os, ctx);
				break;
			case of_Const:
				operand = &operand_[i];
				operand->type = otValue;
				operand->size = os;
				operand->value_size = os;
				operand->value = (of & 0xFF);
				break;
			case of_Far:
				ReadValue(os, GetDefaultOperandSize(ctx), ctx);
				break;
			case of_Memory:
				ReadValue(os, GetAddressSize(ctx), ctx);
				operand_[i].type |= otMemory;
				break;
			default:
				switch (of & 0x0F) {
				case of_value_b:
					ReadValue(os, osByte, ctx);
					break;
				case of_value_w:
					ReadValue(os, osWord, ctx);
					break;
				case of_value_z:
					ReadValue(os, (ctx.lower_reg) ? osWord : osDWord, ctx);
					break;
				case of_value_v:
					ReadValue(os, GetOperandSize(1, ctx), ctx);
					break;
				}
				break;
			}
		}
		else {
			switch (of & 0xF0000000) {
			case of_RM:
				if (need_read_code) {
					code = ReadByte(*ctx.file);
					need_read_code = false;
				}
				ReadRM(code, os, ot, (of & of_size) != 0, ctx);
				operand = &operand_[i];
				if ((operand->type & otMemory) == 0) {
					if ((of & of_mem_only) != 0) {
						type_ = cmDB;
						return;
					}
				}
				else {
					if ((of & of_reg_only) != 0) {
						type_ = cmDB;
						return;
					}
					if ((of & of_mem_word) != 0)
						operand->size = osWord;
				}
				break;
			case of_RegRM:
				if (need_read_code) {
					code = ReadByte(*ctx.file);
					need_read_code = false;
				}
				ReadRegFromRM(code, os, ot, ctx);
				break;
			case of_Reg:
				ReadReg((of & 0xff), os, ot, ctx);
				break;
			case of_XReg:
				code = ReadByte(*ctx.file);
				ReadReg((code >> 4), os, ot, ctx);
				break;
			case of_Const:
				operand = &operand_[i];
				operand->type = ot;
				operand->size = os;
				operand->registr = (of & 7);
				break;
			}

			operand = &operand_[i];
			switch (operand->type) {
			case otSegmentRegistr:
				if (operand->registr > segGS) {
					type_ = cmDB;
					return;
				}
				break;
			case otControlRegistr:
				if (operand->registr == 1
					|| operand->registr == 5
					|| operand->registr == 6
					|| operand->registr >= 9) {
					type_ = cmDB;
					return;
				}
				break;
			case otDebugRegistr:
				if (operand->registr >= 8) {
					type_ = cmDB;
					return;
				}
				break;
			}
		}
	}
};

size_t IntelCommand::ReadFromFile(IArchitecture& file)
{
	uint8_t code, prefix;
	OperandSize os;
	DisasmContext ctx;
	IntelOperand* operand;
	uint8_t vex_bytes[2];
	size_t i, vex_operand_index;

	clear();
	size_ = file.cpu_address_size();

	ctx.file = &file;
	ctx.lower_address = false;
	ctx.lower_reg = false;
	ctx.rex_prefix = 0;
	ctx.use_last_byte = false;
	ctx.vex_registr = 0;

	vex_operand_index = 0;
	prefix = 0;
	vex_bytes[0] = 0;
	vex_bytes[1] = 0;
	while (type_ == cmUnknown) {
		command_pos_ = dump_size();
		code = vex_bytes[0] ? vex_bytes[0] : ReadByte(file);
		switch (code) {
		case 0x00:
			ReadCommand(cmAdd, of_Eb, of_Gb, of_None, ctx);
			break;
		case 0x01:
			ReadCommand(cmAdd, of_Ev, of_Gv, of_None, ctx);
			break;
		case 0x02:
			ReadCommand(cmAdd, of_Gb, of_Eb, of_None, ctx);
			break;
		case 0x03:
			ReadCommand(cmAdd, of_Gv, of_Ev, of_None, ctx);
			break;
		case 0x04:
			ReadCommand(cmAdd, of_FGb | regEAX, of_IBb, of_None, ctx);
			break;
		case 0x05:
			ReadCommand(cmAdd, of_FGv | regEAX, of_IZv, of_None, ctx);
			break;
		case 0x06:
			if (size_ == osQWord) {
				type_ = cmDB;
			}
			else {
				ReadCommand(cmPush, of_FSdef | segES, of_None, of_None, ctx);
			}
			break;
		case 0x07:
			if (size_ == osQWord) {
				type_ = cmDB;
			}
			else {
				ReadCommand(cmPop, of_FSdef | segES, of_None, of_None, ctx);
			}
			break;
		case 0x08:
			ReadCommand(cmOr, of_Eb, of_Gb, of_None, ctx);
			break;
		case 0x09:
			ReadCommand(cmOr, of_Ev, of_Gv, of_None, ctx);
			break;
		case 0x0a:
			ReadCommand(cmOr, of_Gb, of_Eb, of_None, ctx);
			break;
		case 0x0b:
			ReadCommand(cmOr, of_Gv, of_Ev, of_None, ctx);
			break;
		case 0x0c:
			ReadCommand(cmOr, of_FGb | regEAX, of_IBb, of_None, ctx);
			break;
		case 0x0d:
			ReadCommand(cmOr, of_FGv | regEAX, of_IZv, of_None, ctx);
			break;
		case 0x0e:
			if (size_ == osQWord) {
				type_ = cmDB;
			}
			else {
				ReadCommand(cmPush, of_FSdef | segCS, of_None, of_None, ctx);
			}
			break;

			// Secondary Opcode Map
		case 0x0f:
			code = vex_bytes[1] ? vex_bytes[1] : ReadByte(file);
			switch (code) {
			case 0x00:
				code = ReadByte(file);
				ctx.use_last_byte = true;
				switch ((code >> 3) & 7) {
				case 0x00:
					ReadCommand(cmSldt, of_Ev | of_mem_word, of_None, of_None, ctx);
					break;
				case 0x01:
					ReadCommand(cmStr, of_Ev | of_mem_word, of_None, of_None, ctx);
					break;
				case 0x02:
					ReadCommand(cmLldt, of_Ew, of_None, of_None, ctx);
					break;
				case 0x03:
					ReadCommand(cmLtr, of_Ew, of_None, of_None, ctx);
					break;
				case 0x04:
					ReadCommand(cmVerr, of_Ew, of_None, of_None, ctx);
					break;
				case 0x05:
					ReadCommand(cmVerw, of_Ew, of_None, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x01:
				code = ReadByte(file);
				ctx.use_last_byte = true;
				if (code >= 0xc0) {
					switch (code) {
					case 0xc1:
						type_ = cmVmcall;
						break;
					case 0xc2:
						type_ = cmVmlaunch;
						break;
					case 0xc3:
						type_ = cmVmresume;
						break;
					case 0xc4:
						type_ = cmVmxoff;
						break;
					case 0xc8:
						type_ = cmMonitor;
						break;
					case 0xc9:
						type_ = cmMwait;
						break;
					case 0xd0:
						type_ = cmXgetbv;
						break;
					case 0xd1:
						type_ = cmXsetbv;
						break;
					case 0xd8:
						type_ = cmVmrun;
						break;
					case 0xd9:
						type_ = cmVmmcall;
						break;
					case 0xda:
						type_ = cmVmload;
						break;
					case 0xdb:
						type_ = cmVmsave;
						break;
					case 0xdc:
						type_ = cmStgi;
						break;
					case 0xdd:
						type_ = cmClgi;
						break;
					case 0xde:
						type_ = cmSkinit;
						break;
					case 0xdf:
						type_ = cmInvlpga;
						break;
					case 0xf8:
						type_ = cmSwapgs;
						break;
					case 0xf9:
						type_ = cmRdtscp;
						break;
					default:
						type_ = cmDB;
						break;
					}
				}
				else {
					switch ((code >> 3) & 7) {
					case 0x00:
						ReadCommand(cmSgdt, of_Ms, of_None, of_None, ctx);
						break;
					case 0x01:
						ReadCommand(cmSidt, of_Ms, of_None, of_None, ctx);
						break;
					case 0x02:
						ReadCommand(cmLgdt, of_Ms, of_None, of_None, ctx);
						break;
					case 0x03:
						ReadCommand(cmLidt, of_Ms, of_None, of_None, ctx);
						break;
					case 0x04:
						ReadCommand(cmSmsw, of_Ev | of_mem_word, of_None, of_None, ctx);
						break;
					case 0x06:
						ReadCommand(cmLmsw, of_Ew, of_None, of_None, ctx);
						break;
					case 0x07:
						ReadCommand(cmInvlpg, of_Mb, of_None, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
				}
				break;
			case 0x02:
				ReadCommand(cmLar, of_Gv, of_Ew, of_None, ctx);
				break;
			case 0x03:
				ReadCommand(cmLsl, of_Gv, of_Ew, of_None, ctx);
				break;
			case 0x05:
				type_ = cmSyscall;
				break;
			case 0x06:
				type_ = cmClts;
				break;
			case 0x07:
				type_ = cmSysret;
				break;
			case 0x08:
				type_ = cmInvd;
				break;
			case 0x09:
				type_ = cmWbinvd;
				break;
			case 0x0b:
				type_ = cmUd2;
				break;
			case 0x0d:
				code = ReadByte(file);
				ctx.use_last_byte = true;
				switch ((code >> 3) & 7) {
				case 0x00:
					ReadCommand(cmPrefetch, of_Mb, of_None, of_None, ctx);
					break;
				case 0x01:
					ReadCommand(cmPrefetchw, of_Mb, of_None, of_None, ctx);
					break;
				default:
					ReadCommand(cmPrefetch, of_Mb, of_None, of_None, ctx);
					break;
				}
				break;
			case 0x0e:
				type_ = cmFemms;
				break;
			case 0x10:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmMovups, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmMovupd, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					ReadCommand(cmMovsd, of_Vdq, of_Wq, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					ReadCommand(cmMovss, of_Vdq, of_Wd, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x11:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmMovups, of_Wdef, of_Vdef, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmMovupd, of_Wdef, of_Vdef, of_None, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					ReadCommand(cmMovsd, of_Wq, of_Vdq, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					ReadCommand(cmMovss, of_Wd, of_Vdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x12:
				switch (prefix) {
				case 0x00:
					code = ReadByte(file);
					ctx.use_last_byte = true;
					if ((code & 0xc0) == 0xc0) {
						vex_operand_index = 1;
						ReadCommand(cmMovhlps, of_Vdq, of_Udq, of_None, ctx);
					}
					else {
						vex_operand_index = 1;
						ReadCommand(cmMovlps, of_Vdq, of_Mq, of_None, ctx);
					}
					break;
				case 0x66:
					vex_operand_index = 1;
					ReadCommand(cmMovlpd, of_Vdq, of_Mq, of_None, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					ReadCommand(cmMovddup, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					ReadCommand(cmMovsldup, of_Vdef, of_Wdef, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x13:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmMovlps, of_Mq, of_Vdq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmMovlpd, of_Mq, of_Vdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x14:
				switch (prefix) {
				case 0x00:
					vex_operand_index = 1;
					ReadCommand(cmUnpcklps, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0x66:
					vex_operand_index = 1;
					ReadCommand(cmUnpcklpd, of_Vdef, of_Wdef, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x15:
				switch (prefix) {
				case 0x00:
					vex_operand_index = 1;
					ReadCommand(cmUnpckhps, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0x66:
					vex_operand_index = 1;
					ReadCommand(cmUnpckhpd, of_Vdef, of_Wdef, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x16:
				switch (prefix) {
				case 0x00:
					code = ReadByte(file);
					ctx.use_last_byte = true;
					if ((code & 0xc0) == 0xc0) {
						ReadCommand(cmMovlhps, of_Vdq, of_Udq, of_None, ctx);
					}
					else {
						ReadCommand(cmMovhps, of_Vdq, of_Mq, of_None, ctx);
					}
					break;
				case 0x66:
					ReadCommand(cmMovhpd, of_Vdq, of_Mq, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					ReadCommand(cmMovshdup, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x17:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmMovhps, of_Mq, of_Vdq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmMovhpd, of_Mq, of_Vdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x18:
				code = ReadByte(file);
				ctx.use_last_byte = true;
				switch ((code >> 3) & 7) {
				case 0x00:
					ReadCommand(cmPrefetchnta, of_Mb, of_None, of_None, ctx);
					break;
				case 0x01:
					ReadCommand(cmPrefetcht0, of_Mb, of_None, of_None, ctx);
					break;
				case 0x02:
					ReadCommand(cmPrefetcht1, of_Mb, of_None, of_None, ctx);
					break;
				case 0x03:
					ReadCommand(cmPrefetcht2, of_Mb, of_None, of_None, ctx);
					break;
				default:
					type_ = cmNop;
					break;
				}
				break;
			case 0x19: case 0x1a: case 0x1b: case 0x1c: case 0x1d: case 0x1e: case 0x1f:
				ReadCommand(cmNop, of_Ev, of_None, of_None, ctx);
				break;
			case 0x20:
				ReadCommand(cmMov, of_Rcpu, of_Ccpu, of_None, ctx);
				break;
			case 0x21:
				ReadCommand(cmMov, of_Rcpu, of_Dcpu, of_None, ctx);
				break;
			case 0x22:
				ReadCommand(cmMov, of_Ccpu, of_Rcpu, of_None, ctx);
				break;
			case 0x23:
				ReadCommand(cmMov, of_Dcpu, of_Rcpu, of_None, ctx);
				break;
			case 0x28:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmMovaps, of_Vdq, of_Wdq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmMovapd, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x29:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmMovaps, of_Wdq, of_Vdq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmMovapd, of_Wdq, of_Vdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x2a:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmCvtpi2ps, of_Vdq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmCvtpi2pd, of_Vdq, of_Qq, of_None, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					vex_operand_index = 1;
					ReadCommand(cmCvtsi2sd, of_Vdq, of_Ex, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					vex_operand_index = 1;
					ReadCommand(cmCvtsi2ss, of_Vdq, of_Ex, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x2b:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmMovntps, of_Mdef, of_Vdef, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmMovntpd, of_Mdef, of_Vdef, of_None, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					ReadCommand(cmMovntsd, of_Mq, of_Vdq, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					ReadCommand(cmMovntss, of_Md, of_Vdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x2c:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmCvttps2pi, of_Pq, of_Wdq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmCvttpd2pi, of_Pq, of_Wdq, of_None, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					ReadCommand(cmCvttsd2si, of_Gx, of_Wq, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					ReadCommand(cmCvttss2si, of_Gx, of_Wd, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x2d:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmCvtps2pi, of_Pq, of_Wq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmCvtpd2pi, of_Pq, of_Wdq, of_None, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					ReadCommand(cmCvtsd2si, of_Gx, of_Wq, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					ReadCommand(cmCvtss2si, of_Gx, of_Wd, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x2e:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmUcomiss, of_Vdq, of_Wd, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmUcomisd, of_Vdq, of_Wq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x2f:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmComiss, of_Vdq, of_Wdq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmComisd, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x30:
				type_ = cmWrmsr;
				break;

			case 0x31:
				type_ = cmRdtsc;
				break;

			case 0x32:
				type_ = cmRdmsr;
				break;

			case 0x33:
				type_ = cmRdpmc;
				break;

			case 0x34:
				if (size_ == osQWord)
					type_ = cmDB;
				else
					type_ = cmSysenter;
				break;

			case 0x35:
				if (size_ == osQWord)
					type_ = cmDB;
				else
					type_ = cmSysexit;
				break;

			case 0x37:
				type_ = cmGetsec;
				break;

			case 0x38:
				code = ReadByte(file);
				switch (code) {
				case 0x00:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPshufb, of_Pq, of_Qq, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPshufb, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x01:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPhaddw, of_Pq, of_Qq, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPhaddw, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x02:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPhaddd, of_Pq, of_Qq, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPhaddd, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x03:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPhaddsw, of_Pq, of_Qq, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPhaddsw, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x04:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPmaddubsw, of_Pq, of_Qq, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPmaddubsw, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x05:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPhsubw, of_Pq, of_Qq, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPhsubw, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x06:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPhsubd, of_Pq, of_Qq, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPhsubd, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x07:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPhsubsw, of_Pq, of_Qq, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPhsubsw, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x08:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPsignb, of_Pq, of_Qq, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPsignb, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x09:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPsignw, of_Pq, of_Qq, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPsignw, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x0a:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPsignd, of_Pq, of_Qq, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPsignd, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x0b:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPmulhrsw, of_Pq, of_Qq, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPmulhrsw, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x0c:
					switch (prefix) {
					case 0x66:
						if (options() & roVexPrefix) {
							vex_operand_index = 1;
							ReadCommand(cmVpermilps, of_Vdef, of_Wdef, of_None, ctx);
						}
						else
							type_ = cmDB;
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x0d:
					switch (prefix) {
					case 0x66:
						if (options() & roVexPrefix) {
							vex_operand_index = 1;
							ReadCommand(cmVpermilpd, of_Vdef, of_Wdef, of_None, ctx);
						}
						else
							type_ = cmDB;
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x0e:
					switch (prefix) {
					case 0x66:
						if (options() & roVexPrefix)
							ReadCommand(cmVtestps, of_Vdef, of_Wdef, of_None, ctx);
						else
							type_ = cmDB;
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x0f:
					switch (prefix) {
					case 0x66:
						if (options() & roVexPrefix)
							ReadCommand(cmVtestpd, of_Vdef, of_Wdef, of_None, ctx);
						else
							type_ = cmDB;
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x10:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPblendvb, of_Vdef, of_Wdef, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x14:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPblendps, of_Vdef, of_Wdef, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x15:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPblendpd, of_Vdef, of_Wdef, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x17:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPtest, of_Vdef, of_Wdef, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x18:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmVbroadcastss, of_Vdef, of_Wd, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x19:
					switch (prefix) {
					case 0x66:
						if (ctx.rex_prefix & 0x80)
							ReadCommand(cmVbroadcastsd, of_Vdef, of_Wq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x1a:
					switch (prefix) {
					case 0x66:
						if (ctx.rex_prefix & 0x80)
							ReadCommand(cmVbroadcastf128, of_Vdef, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x1c:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPabsb, of_Pq, of_Qq, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPabsb, of_Vdef, of_Wdef, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x1d:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPabsw, of_Pq, of_Qq, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPabsw, of_Vdef, of_Wdef, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x1e:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPabsd, of_Pq, of_Qq, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPabsd, of_Vdef, of_Wdef, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x20:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPmovsxbw, of_Vdef, of_Wq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x21:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPmovsxbd, of_Vdef, of_Wd, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x22:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPmovsxbq, of_Vdef, of_Ww, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x23:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPmovsxwd, of_Vdef, of_Wq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x24:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPmovsxwq, of_Vdef, of_Wd, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x25:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPmovsxdq, of_Vdef, of_Wq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x28:
					switch (prefix) {
					case 0x66:
						vex_operand_index = 1;
						ReadCommand(cmPmuldq, of_Vdef, of_Wdef, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x29:
					switch (prefix) {
					case 0x66:
						vex_operand_index = 1;
						ReadCommand(cmPcmpeqq, of_Vdef, of_Wdef, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x2a:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmMovntdqa, of_Vdef, of_Mdef, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x2b:
					switch (prefix) {
					case 0x66:
						vex_operand_index = 1;
						ReadCommand(cmPackusdw, of_Vdef, of_Wdef, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x2c:
					switch (prefix) {
					case 0x66:
						vex_operand_index = 1;
						ReadCommand(cmMaskmovps, of_Vdef, of_Mdef, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x2d:
					switch (prefix) {
					case 0x66:
						vex_operand_index = 1;
						ReadCommand(cmMaskmovpd, of_Vdef, of_Mdef, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x2e:
					switch (prefix) {
					case 0x66:
						vex_operand_index = 1;
						ReadCommand(cmMaskmovps, of_Mdef, of_Vdef, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x2f:
					switch (prefix) {
					case 0x66:
						vex_operand_index = 1;
						ReadCommand(cmMaskmovpd, of_Mdef, of_Vdef, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x30:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPmovzxbw, of_Vdq, of_Wq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x31:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPmovzxbd, of_Vdq, of_Wd, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x32:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPmovzxbq, of_Vdq, of_Ww, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x33:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPmovzxwd, of_Vdq, of_Wq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x34:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPmovzxwq, of_Vdq, of_Wd, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x35:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPmovzxdq, of_Vdq, of_Wq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x37:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPcmpgtq, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x38:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPminsb, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x39:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPminsd, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x3a:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPminuw, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x3b:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPminud, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x3c:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPmaxsb, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x3d:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPmaxsd, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x3e:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPmaxuw, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x3f:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPmaxud, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x40:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPmulld, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;

				case 0x9d:
					switch (prefix) {
					case 0x66:
						vex_operand_index = 1;
						if (ctx.rex_prefix & rexW)
							ReadCommand(cmFnmadd132sd, of_Vdq, of_Wq, of_None, ctx);
						else
							ReadCommand(cmFnmadd132ss, of_Vdq, of_Wd, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;

				case 0xad:
					switch (prefix) {
					case 0x66:
						vex_operand_index = 1;
						if (ctx.rex_prefix & rexW)
							ReadCommand(cmFnmadd213sd, of_Vdq, of_Wq, of_None, ctx);
						else
							ReadCommand(cmFnmadd213ss, of_Vdq, of_Wd, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;

				case 0xbd:
					switch (prefix) {
					case 0x66:
						vex_operand_index = 1;
						if (ctx.rex_prefix & rexW)
							ReadCommand(cmFnmadd231sd, of_Vdq, of_Wq, of_None, ctx);
						else
							ReadCommand(cmFnmadd231ss, of_Vdq, of_Wd, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;

				case 0xdb:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmAesimc, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0xdc:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmAesenc, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0xdd:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmAesenclast, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0xde:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmAesdec, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0xdf:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmAesdeclast, of_Vdq, of_Wdq, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0xf0:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmMovbe, of_Gv, of_Mv, of_None, ctx);
						break;
					case 0xf2:
						preffix_command_ = cmUnknown;
						ReadCommand(cmCrc32, of_Gx, of_Mb | of_size, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0xf1:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmMovbe, of_Mv, of_Gv, of_None, ctx);
						break;
					case 0xf2:
						preffix_command_ = cmUnknown;
						ReadCommand(cmCrc32, of_Gx, of_Mv | of_size, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;

					// FIXME
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x3a:
				code = ReadByte(file);
				switch (code) {
				case 0x04:
					switch (prefix) {
					case 0x66:
						if (options() & roVexPrefix)
							ReadCommand(cmVpermilps, of_Vdef, of_Wdef, of_IBb, ctx);
						else
							type_ = cmDB;
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x05:
					switch (prefix) {
					case 0x66:
						if (options() & roVexPrefix)
							ReadCommand(cmVpermilpd, of_Vdef, of_Wdef, of_IBb, ctx);
						else
							type_ = cmDB;
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x06:
					switch (prefix) {
					case 0x66:
						if (options() & roVexPrefix) {
							vex_operand_index = 1;
							ReadCommand(cmVperm2f128, of_Vdef, of_Wdef, of_IBb, ctx);
						}
						else
							type_ = cmDB;
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x08:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmRoundps, of_Vdef, of_Wdef, of_IBb, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x09:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmRoundpd, of_Vdef, of_Wdef, of_IBb, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x0c:
					switch (prefix) {
					case 0x66:
						vex_operand_index = 1;
						ReadCommand(cmBlendps, of_Vdef, of_Wdef, of_IBb, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x0d:
					switch (prefix) {
					case 0x66:
						vex_operand_index = 1;
						ReadCommand(cmBlendpd, of_Vdef, of_Wdef, of_IBb, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x0e:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPblendw, of_Vdq, of_Wdq, of_IBb, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x0f:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPalignr, of_Pq, of_Qq, of_IBb, ctx);
						break;
					case 0x66:
						ReadCommand(cmPalignr, of_Vdq, of_Wdq, of_IBb, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x14:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPextrb, of_Ed, of_Vdq, of_IBb, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x16:
					switch (prefix) {
					case 0x66:
						if (ctx.rex_prefix & rexW)
							ReadCommand(cmPextrq, of_Eq, of_Vdq, of_IBb, ctx);
						else
							ReadCommand(cmPextrd, of_Ed, of_Vdq, of_IBb, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x18:
					switch (prefix) {
					case 0x66:
						vex_operand_index = 1;
						ReadCommand(cmInsertf128, of_Vdef, of_Wdq, of_IBb, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x19:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmExtractf128, of_Wdq, of_Vqq, of_IBb, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x20:
					switch (prefix) {
					case 0x66:
						vex_operand_index = 1;
						ReadCommand(cmPinsrb, of_Vdq, of_Eb, of_IBb, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x22:
					switch (prefix) {
					case 0x66:
						vex_operand_index = 1;
						if (ctx.rex_prefix & rexW)
							ReadCommand(cmPinsrq, of_Vdq, of_Eq, of_IBb, ctx);
						else
							ReadCommand(cmPinsrd, of_Vdq, of_Ed, of_IBb, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x40:
					switch (prefix) {
					case 0x66:
						vex_operand_index = 1;
						ReadCommand(cmDpps, of_Vdef, of_Wdef, of_IBb, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x4a:
					switch (prefix) {
					case 0x66:
						vex_operand_index = 1;
						ReadCommand(cmBlendvps, of_Vdef, of_Wdef, of_Xdef, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x4b:
					switch (prefix) {
					case 0x66:
						vex_operand_index = 1;
						ReadCommand(cmBlendvpd, of_Vdef, of_Wdef, of_Xdef, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x63:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPcmpistri, of_Vdq, of_Wdq, of_IBb, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0xdf:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmAeskeygenassist, of_Vdq, of_Wdq, of_IBb, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				default:
					type_ = cmDB;
				}
				break;

			case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47:
			case 0x48: case 0x49: case 0x4a: case 0x4b: case 0x4c: case 0x4d: case 0x4e: case 0x4f:
				ReadFlags(code);
				ReadCommand(cmCmov, of_Gv, of_Ev, of_None, ctx);
				break;
			case 0x50:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmMovmskps, of_Gd, of_Udef, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmMovmskpd, of_Gd, of_Udef, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x51:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmSqrtps, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmSqrtpd, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					ReadCommand(cmSqrtsd, of_Vdq, of_Wq, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					ReadCommand(cmSqrtss, of_Vdq, of_Wd, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x52:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmRsqrtps, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					ReadCommand(cmRsqrtss, of_Vdq, of_Wd, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x53:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmRcpps, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					ReadCommand(cmRcpss, of_Vdq, of_Wd, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x54:
				switch (prefix) {
				case 0x00:
					vex_operand_index = 1;
					ReadCommand(cmAndps, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0x66:
					vex_operand_index = 1;
					ReadCommand(cmAndpd, of_Vdef, of_Wdef, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x55:
				switch (prefix) {
				case 0x00:
					vex_operand_index = 1;
					ReadCommand(cmAndnps, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0x66:
					vex_operand_index = 1;
					ReadCommand(cmAndnpd, of_Vdef, of_Wdef, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x56:
				switch (prefix) {
				case 0x00:
					vex_operand_index = 1;
					ReadCommand(cmOrps, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0x66:
					vex_operand_index = 1;
					ReadCommand(cmOrpd, of_Vdef, of_Wdef, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x57:
				switch (prefix) {
				case 0x00:
					vex_operand_index = 1;
					ReadCommand(cmXorps, of_Vdef, of_Wdq, of_None, ctx);
					break;
				case 0x66:
					vex_operand_index = 1;
					ReadCommand(cmXorpd, of_Vdef, of_Wdef, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x58:
				switch (prefix) {
				case 0x00:
					vex_operand_index = 1;
					ReadCommand(cmAddps, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0x66:
					vex_operand_index = 1;
					ReadCommand(cmAddpd, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					vex_operand_index = 1;
					ReadCommand(cmAddsd, of_Vdq, of_Wq, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					vex_operand_index = 1;
					ReadCommand(cmAddss, of_Vdq, of_Wd, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x59:
				switch (prefix) {
				case 0x00:
					vex_operand_index = 1;
					ReadCommand(cmMulps, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0x66:
					vex_operand_index = 1;
					ReadCommand(cmMulpd, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					vex_operand_index = 1;
					ReadCommand(cmMulsd, of_Vdq, of_Wq, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					vex_operand_index = 1;
					ReadCommand(cmMulss, of_Vdq, of_Wd, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x5a:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmCvtps2pd, of_Vdef, of_Wdq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmCvtpd2ps, of_Vdq, of_Wdef, of_None, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					vex_operand_index = 1;
					ReadCommand(cmCvtsd2ss, of_Vdq, of_Wq, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					vex_operand_index = 1;
					ReadCommand(cmCvtss2sd, of_Vdq, of_Wd, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x5b:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmCvtdq2ps, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmCvtps2dq, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					ReadCommand(cmCvttps2dq, of_Vdef, of_Wdef, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x5c:
				switch (prefix) {
				case 0x00:
					vex_operand_index = 1;
					ReadCommand(cmSubps, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0x66:
					vex_operand_index = 1;
					ReadCommand(cmSubpd, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					vex_operand_index = 1;
					ReadCommand(cmSubsd, of_Vdq, of_Wq, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					vex_operand_index = 1;
					ReadCommand(cmSubss, of_Vdq, of_Wd, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x5d:
				switch (prefix) {
				case 0x00:
					vex_operand_index = 1;
					ReadCommand(cmMinps, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0x66:
					vex_operand_index = 1;
					ReadCommand(cmMinpd, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					vex_operand_index = 1;
					ReadCommand(cmMinsd, of_Vdq, of_Wq, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					vex_operand_index = 1;
					ReadCommand(cmMinss, of_Vdq, of_Wd, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x5e:
				switch (prefix) {
				case 0x00:
					vex_operand_index = 1;
					ReadCommand(cmDivps, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0x66:
					vex_operand_index = 1;
					ReadCommand(cmDivpd, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					vex_operand_index = 1;
					ReadCommand(cmDivsd, of_Vdq, of_Wq, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					vex_operand_index = 1;
					ReadCommand(cmDivss, of_Vdq, of_Wd, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x5f:
				switch (prefix) {
				case 0x00:
					vex_operand_index = 1;
					ReadCommand(cmMaxps, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0x66:
					vex_operand_index = 1;
					ReadCommand(cmMaxpd, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					vex_operand_index = 1;
					ReadCommand(cmMaxsd, of_Vdq, of_Wq, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					vex_operand_index = 1;
					ReadCommand(cmMaxss, of_Vdq, of_Wd, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x60:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPunpcklbw, of_Pq, of_Qd, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPunpcklbw, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x61:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPunpcklwd, of_Pq, of_Qd, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPunpcklwd, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x62:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPunpckldq, of_Pq, of_Qd, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPunpckldq, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x63:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPacksswb, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPacksswb, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x64:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPcmpgtb, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPcmpgtb, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x65:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPcmpgtw, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPcmpgtw, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x66:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPcmpgtd, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPcmpgtd, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x67:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPackuswb, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPackuswb, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x68:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPunpckhbw, of_Pq, of_Qd, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPunpckhbw, of_Vdq, of_Wq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x69:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPunpckhwd, of_Pq, of_Qd, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPunpckhwd, of_Vdq, of_Wq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x6a:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPunpckhdq, of_Pq, of_Qd, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPunpckhdq, of_Vdq, of_Wq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x6b:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPackssdw, of_Pq, of_Qd, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPackssdw, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x6c:
				switch (prefix) {
				case 0x66:
					ReadCommand(cmPunpcklqdq, of_Vdq, of_Wq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x6d:
				switch (prefix) {
				case 0x66:
					ReadCommand(cmPunpckhqdq, of_Vdq, of_Wq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x6e:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmMovd, of_Pq, of_Ex, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmMovd, of_Vdq, of_Ex, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x6f:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmMovq, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmMovdqa, of_Vdq, of_Wdq, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					ReadCommand(cmMovdqu, of_Vdef, of_Wdef, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x70:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPshufw, of_Pq, of_Qq, of_IBb, ctx);
					break;
				case 0x66:
					ReadCommand(cmPshufd, of_Vdq, of_Wdq, of_IBb, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					ReadCommand(cmPshuflw, of_Vdq, of_Wdq, of_IBb, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					ReadCommand(cmPshufhw, of_Vdq, of_Wdq, of_IBb, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x71:
				code = ReadByte(file);
				ctx.use_last_byte = true;
				switch ((code >> 3) & 7) {
				case 0x02:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPsrlw, of_Nq, of_IBb, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPsrlw, of_Udq, of_IBb, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x04:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPsraw, of_Nq, of_IBb, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPsraw, of_Udq, of_IBb, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x06:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPsllw, of_Nq, of_IBb, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPsllw, of_Udq, of_IBb, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x72:
				code = ReadByte(file);
				ctx.use_last_byte = true;
				switch ((code >> 3) & 7) {
				case 0x02:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPsrld, of_Nq, of_IBb, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPsrld, of_Udq, of_IBb, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x04:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPsrad, of_Nq, of_IBb, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPsrad, of_Udq, of_IBb, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x06:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPslld, of_Nq, of_IBb, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPslld, of_Udq, of_IBb, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x73:
				code = ReadByte(file);
				ctx.use_last_byte = true;
				switch ((code >> 3) & 7) {
				case 0x02:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPsrlq, of_Nq, of_IBb, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPsrlq, of_Udq, of_IBb, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x03:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPsrldq, of_Udq, of_IBb, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x06:
					switch (prefix) {
					case 0x00:
						ReadCommand(cmPsllq, of_Nq, of_IBb, of_None, ctx);
						break;
					case 0x66:
						ReadCommand(cmPsllq, of_Udq, of_IBb, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				case 0x07:
					switch (prefix) {
					case 0x66:
						ReadCommand(cmPslldq, of_Udq, of_IBb, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x74:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPcmpeqb, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					vex_operand_index = 1;
					ReadCommand(cmPcmpeqb, of_Vdef, of_Wdef, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x75:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPcmpeqw, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					vex_operand_index = 1;
					ReadCommand(cmPcmpeqw, of_Vdef, of_Wdef, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x76:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPcmpeqd, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					vex_operand_index = 1;
					ReadCommand(cmPcmpeqd, of_Vdef, of_Wdef, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x77:
				if (prefix == 0)
					if (options() & roVexPrefix) {
						type_ = ctx.rex_prefix & 0x80 ? cmVzeroall : cmVzeroupper;
					}
					else {
						type_ = cmEmms;
					}
				else
					type_ = cmDB;
				break;

			case 0x78:
				/* Stick on Intel decoding here; ignore AMD. */
				if (prefix == 0) {
					type_ = cmVmread;
					os = size_;
					code = ReadByte(file);
					ReadRM(code, os, otRegistr, false, ctx);
					ReadRegFromRM(code, os, otRegistr, ctx);
				}
				else {
					type_ = cmDB;
				}
				break;

			case 0x79:
				/* Stick on Intel decoding here; ignore AMD. */
				if (prefix == 0) {
					type_ = cmVmwrite;
					os = size_;
					code = ReadByte(file);
					ReadRegFromRM(code, os, otRegistr, ctx);
					ReadRM(code, os, otRegistr, false, ctx);
				}
				else {
					type_ = cmDB;
				}
				break;

			case 0x7c:
				switch (prefix) {
				case 0x66:
					vex_operand_index = 1;
					ReadCommand(cmHaddpd, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					vex_operand_index = 1;
					ReadCommand(cmHaddps, of_Vdef, of_Wdef, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x7d:
				switch (prefix) {
				case 0x66:
					vex_operand_index = 1;
					ReadCommand(cmHsubpd, of_Vdef, of_Wdef, of_None, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					vex_operand_index = 1;
					ReadCommand(cmHsubps, of_Vdef, of_Wdef, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x7e:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmMovd, of_Ex, of_Pq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmMovd, of_Ex, of_Vdq, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					ReadCommand(cmMovq, of_Vdq, of_Wq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0x7f:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmMovq, of_Qq, of_Pq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmMovdqa, of_Wdq, of_Vdq, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					ReadCommand(cmMovdqu, of_Wdef, of_Vdef, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86: case 0x87:
			case 0x88: case 0x89: case 0x8a: case 0x8b: case 0x8c: case 0x8d: case 0x8e: case 0x8f:
				ReadFlags(code);
				ReadCommand(cmJmpWithFlag, of_Jz, of_None, of_None, ctx);
				break;

			case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
			case 0x98: case 0x99: case 0x9a: case 0x9b: case 0x9c: case 0x9d: case 0x9e: case 0x9f:
				ReadFlags(code);
				ReadCommand(cmSetXX, of_Eb, of_None, of_None, ctx);
				break;
			case 0xa0:
				ReadCommand(cmPush, of_FSdef | segFS, of_None, of_None, ctx);
				break;
			case 0xa1:
				ReadCommand(cmPop, of_FSdef | segFS, of_None, of_None, ctx);
				break;
			case 0xa2:
				type_ = cmCpuid;
				break;
			case 0xa3:
				ReadCommand(cmBt, of_Ev, of_Gv, of_None, ctx);
				break;
			case 0xa4:
				ReadCommand(cmShld, of_Ev, of_Gv, of_IBb, ctx);
				break;
			case 0xa5:
				ReadCommand(cmShld, of_Ev, of_Gv, of_FGb | regECX, ctx);
				break;
			case 0xa8:
				ReadCommand(cmPush, of_FSdef | segGS, of_None, of_None, ctx);
				break;
			case 0xa9:
				ReadCommand(cmPop, of_FSdef | segGS, of_None, of_None, ctx);
				break;
			case 0xaa:
				type_ = cmRsm;
				break;
			case 0xab:
				ReadCommand(cmBts, of_Ev, of_Gv, of_None, ctx);
				break;
			case 0xac:
				ReadCommand(cmShrd, of_Ev, of_Gv, of_IBb, ctx);
				break;
			case 0xad:
				ReadCommand(cmShrd, of_Ev, of_Gv, of_FGb | regECX, ctx);
				break;
			case 0xae:
				code = ReadByte(file);
				ctx.use_last_byte = true;
				switch ((code >> 3) & 7) {
				case 0x00:
					ReadCommand(cmFxsave, of_M, of_None, of_None, ctx);
					break;
				case 0x01:
					ReadCommand(cmFxrstor, of_M, of_None, of_None, ctx);
					break;
				case 0x02:
					ReadCommand(cmLdmxcsr, of_Md, of_None, of_None, ctx);
					break;
				case 0x03:
					ReadCommand(cmStmxcsr, of_Md, of_None, of_None, ctx);
					break;
				case 0x04:
					ReadCommand(cmXsave, of_M, of_None, of_None, ctx);
					break;
				case 0x05:
					if ((code & 0xc0) == 0xc0) {
						type_ = cmLfence;
					}
					else {
						ReadCommand(cmXrstor, of_M, of_None, of_None, ctx);
					}
					break;
				case 0x06:
					if ((code & 0xc0) == 0xc0) {
						type_ = cmMfence;
					}
					else {
						ReadCommand(cmXsaveopt, of_M, of_None, of_None, ctx);
					}
					break;
				case 0x07:
					if ((code & 0xc0) == 0xc0) {
						type_ = cmSfence;
					}
					else {
						ReadCommand(cmClflush, of_M, of_None, of_None, ctx);
					}
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xaf:
				ReadCommand(cmImul, of_Gv, of_Ev, of_None, ctx);
				break;
			case 0xb0:
				ReadCommand(cmCmpxchg, of_Eb, of_Gb, of_None, ctx);
				break;
			case 0xb1:
				ReadCommand(cmCmpxchg, of_Ev, of_Gv, of_None, ctx);
				break;
			case 0xb2:
				ReadCommand(cmLss, of_Gz, of_Mp, of_None, ctx);
				break;
			case 0xb3:
				ReadCommand(cmBtr, of_Ev, of_Gv, of_None, ctx);
				break;
			case 0xb4:
				ReadCommand(cmLfs, of_Gz, of_Mp, of_None, ctx);
				break;
			case 0xb5:
				ReadCommand(cmLgs, of_Gz, of_Mp, of_None, ctx);
				break;
			case 0xb6:
				ReadCommand(cmMovzx, of_Gv, of_Eb | of_size, of_None, ctx);
				break;
			case 0xb7:
				ReadCommand(cmMovzx, of_Gv, of_Ew | of_size, of_None, ctx);
				break;
			case 0xb8:
				switch (prefix) {
				case 0xF3:
					preffix_command_ = cmUnknown;
					ReadCommand(cmPopcnt, of_Gv, of_Ev, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xb9:
				switch (prefix) {
				case 0x00:
				case 0x66:
					type_ = cmUd1;
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xba:
				if (prefix == 0 || prefix == 0x66) {
					code = ReadByte(file);
					ctx.use_last_byte = true;
					switch ((code >> 3) & 7) {
					case 0x04:
						ReadCommand(cmBt, of_Ev | of_size, of_IBb, of_None, ctx);
						break;
					case 0x05:
						ReadCommand(cmBts, of_Ev | of_size, of_IBb, of_None, ctx);
						break;
					case 0x06:
						ReadCommand(cmBtr, of_Ev | of_size, of_IBb, of_None, ctx);
						break;
					case 0x07:
						ReadCommand(cmBtc, of_Ev | of_size, of_IBb, of_None, ctx);
						break;
					default:
						type_ = cmDB;
						break;
					}
				}
				else {
					type_ = cmDB;
				}
				break;

			case 0xbb:
				switch (prefix) {
				case 0x00:
				case 0x66:
					ReadCommand(cmBtc, of_Ev, of_Gv, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0xbc:
				switch (prefix) {
				case 0x00:
				case 0x66:
					ReadCommand(cmBsf, of_Gv, of_Ev, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					ReadCommand(cmTzcnt, of_Gv, of_Ev, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xbd:
				switch (prefix) {
				case 0x00:
				case 0x66:
					ReadCommand(cmBsr, of_Gv, of_Ev, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					ReadCommand(cmLzcnt, of_Gv, of_Ev, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xbe:
				switch (prefix) {
				case 0x00:
				case 0x66:
					ReadCommand(cmMovsx, of_Gv, of_Eb | of_size, of_None, ctx);
					break;
				default:
					type_ = cmDB;
				}
				break;
			case 0xbf:
				switch (prefix) {
				case 0x00:
				case 0x66:
					ReadCommand(cmMovsx, of_Gv, of_Ew | of_size, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xc0:
				ReadCommand(cmXadd, of_Eb, of_Gb, of_None, ctx);
				break;
			case 0xc1:
				ReadCommand(cmXadd, of_Ev, of_Gv, of_None, ctx);
				break;
			case 0xc2:
				switch (prefix) {
				case 0x00:
					vex_operand_index = 1;
					ReadCommand(cmCmpps, of_Vdef, of_Wdef, of_IBb, ctx);
					break;
				case 0x66:
					vex_operand_index = 1;
					ReadCommand(cmCmppd, of_Vdef, of_Wdef, of_IBb, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					vex_operand_index = 1;
					ReadCommand(cmCmpsd, of_Vdq, of_Wq, of_IBb, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					vex_operand_index = 1;
					ReadCommand(cmCmpss, of_Vdq, of_Wd, of_IBb, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0xc3:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmMovnti, of_Mx, of_Gx, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0xc4:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPinsrw, of_Pq, of_Ew | of_size, of_IBb, ctx);
					break;
				case 0x66:
					ReadCommand(cmPinsrw, of_Vdq, of_Ew | of_size, of_IBb, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0xc5:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPextrw, of_Gd, of_Nq, of_IBb, ctx);
					break;
				case 0x66:
					ReadCommand(cmPextrw, of_Gd, of_Udq, of_IBb, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0xc6:
				switch (prefix) {
				case 0x00:
					vex_operand_index = 1;
					ReadCommand(cmShufps, of_Vdef, of_Wdef, of_IBb, ctx);
					break;
				case 0x66:
					vex_operand_index = 1;
					ReadCommand(cmShufpd, of_Vdef, of_Wdef, of_IBb, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0xc7:
				code = ReadByte(file);
				ctx.use_last_byte = true;
				switch ((code >> 3) & 7) {
				case 0x01:
					ReadCommand(cmCmpxchg8b, of_Mq, of_None, of_None, ctx);
					break;
				case 0x06:
					if (code && 0xc0 == 0xc0)
						ReadCommand(cmRdrand, of_Zv | code, of_None, of_None, ctx);
					else
						ReadCommand(cmVmptrld, of_Mq, of_None, of_None, ctx);
					break;
				case 0x07:
					if (code && 0xc0 == 0xc0)
						ReadCommand(cmRdseed, of_Zv | code, of_None, of_None, ctx);
					else
						ReadCommand(cmVmptrst, of_Mq, of_None, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0xc8: case 0xc9: case 0xca: case 0xcb: case 0xcc: case 0xcd: case 0xce: case 0xcf:
				ReadCommand(cmBswap, of_Zv | code, of_None, of_None, ctx);
				break;
			case 0xd0:
				switch (prefix) {
				case 0x66:
					ReadCommand(cmAddsubpd, of_Vdq, of_Wdq, of_None, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					ReadCommand(cmAddsubps, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xd1:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPsrlw, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPsrlw, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xd2:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPsrld, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPsrld, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xd3:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPsrlq, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPsrlq, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xd4:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPaddq, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPaddq, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xd5:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPmullw, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPmullw, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xd6:
				switch (prefix) {
				case 0x66:
					ReadCommand(cmMovq, of_Wq, of_Vdq, of_None, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					ReadCommand(cmMovdq2q, of_Pq, of_Udq, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					ReadCommand(cmMovq2dq, of_Vdq, of_Nq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xd7:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPmovmskb, of_Gd, of_Nq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPmovmskb, of_Gd, of_Udq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xd8:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPsubusb, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPsubusb, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xd9:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPsubusw, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPsubusw, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xda:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPminub, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPminub, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xdb:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPand, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPand, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xdc:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPaddusb, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPaddusb, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xdd:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPaddusw, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPaddusw, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xde:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPmaxub, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPmaxub, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xdf:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPandn, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPandn, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xe0:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPavgb, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPavgb, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xe1:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPsraw, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPsraw, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xe2:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPsrad, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPsrad, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xe3:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPavgw, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPavgw, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xe4:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPmulhuw, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPmulhuw, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xe5:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPmulhw, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPmulhw, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xe6:
				switch (prefix) {
				case 0x66:
					ReadCommand(cmCvttpd2dq, of_Vdq, of_Wdef, of_None, ctx);
					break;
				case 0xF2:
					preffix_command_ = cmUnknown;
					ReadCommand(cmCvtpd2dq, of_Vdq, of_Wdef, of_None, ctx);
					break;
				case 0xF3:
					preffix_command_ = cmUnknown;
					ReadCommand(cmCvtdq2pd, of_Vdef, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xe7:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmMovntq, of_Mq, of_Pq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmMovntdq, of_Mdq, of_Vdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xe8:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPsubsb, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPsubsb, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xe9:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPsubsw, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPsubsw, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xea:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPminsw, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPminsw, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xeb:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPor, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPor, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xec:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPaddsb, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPaddsb, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xed:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPaddsw, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPaddsw, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xee:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPmaxsw, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPmaxsw, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xef:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPxor, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					vex_operand_index = 1;
					ReadCommand(cmPxor, of_Vdef, of_Wdef, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0xf0:
				switch (prefix) {
				case 0xF2:
					preffix_command_ = cmUnknown;
					ReadCommand(cmLddqu, of_Vdef, of_Mdef, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;

			case 0xf1:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPsllw, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPsllw, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xf2:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPslld, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPslld, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xf3:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPsllq, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPsllq, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xf4:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPmuludq, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPmuludq, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xf5:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPmaddwd, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPmaddwd, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xf6:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPsadbw, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPsadbw, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xf7:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmMaskmovq, of_Pq, of_Nq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmMaskmovdqu, of_Vdq, of_Udq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xf8:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPsubb, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPsubb, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xf9:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPsubw, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPsubw, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xfa:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPsubd, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPsubd, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xfb:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPsubq, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPsubq, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xfc:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPaddb, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPaddb, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xfd:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPaddw, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPaddw, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xfe:
				switch (prefix) {
				case 0x00:
					ReadCommand(cmPaddd, of_Pq, of_Qq, of_None, ctx);
					break;
				case 0x66:
					ReadCommand(cmPaddd, of_Vdq, of_Wdq, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
				break;
			case 0xff:
				type_ = cmUd0;
				break;

			default:
				type_ = cmDB;
				break;
			}
			break;

			// End

		case 0x10:
			ReadCommand(cmAdc, of_Eb, of_Gb, of_None, ctx);
			break;
		case 0x11:
			ReadCommand(cmAdc, of_Ev, of_Gv, of_None, ctx);
			break;
		case 0x12:
			ReadCommand(cmAdc, of_Gb, of_Eb, of_None, ctx);
			break;
		case 0x13:
			ReadCommand(cmAdc, of_Gv, of_Ev, of_None, ctx);
			break;
		case 0x14:
			ReadCommand(cmAdc, of_FGb | regEAX, of_IBb, of_None, ctx);
			break;
		case 0x15:
			ReadCommand(cmAdc, of_FGv | regEAX, of_IZv, of_None, ctx);
			break;
		case 0x16:
			if (size_ == osQWord) {
				type_ = cmDB;
			}
			else {
				ReadCommand(cmPush, of_FSdef | segSS, of_None, of_None, ctx);
			}
			break;
		case 0x17:
			if (size_ == osQWord) {
				type_ = cmDB;
			}
			else {
				ReadCommand(cmPop, of_FSdef | segSS, of_None, of_None, ctx);
			}
			break;
		case 0x18:
			ReadCommand(cmSbb, of_Eb, of_Gb, of_None, ctx);
			break;
		case 0x19:
			ReadCommand(cmSbb, of_Ev, of_Gv, of_None, ctx);
			break;
		case 0x1a:
			ReadCommand(cmSbb, of_Gb, of_Eb, of_None, ctx);
			break;
		case 0x1b:
			ReadCommand(cmSbb, of_Gv, of_Ev, of_None, ctx);
			break;
		case 0x1c:
			ReadCommand(cmSbb, of_FGb | regEAX, of_IBb, of_None, ctx);
			break;
		case 0x1d:
			ReadCommand(cmSbb, of_FGv | regEAX, of_IZv, of_None, ctx);
			break;
		case 0x1e:
			if (size_ == osQWord) {
				type_ = cmDB;
			}
			else {
				ReadCommand(cmPush, of_FSdef | segDS, of_None, of_None, ctx);
			}
			break;
		case 0x1f:
			if (size_ == osQWord) {
				type_ = cmDB;
			}
			else {
				ReadCommand(cmPop, of_FSdef | segDS, of_None, of_None, ctx);
			}
			break;
		case 0x20:
			ReadCommand(cmAnd, of_Eb, of_Gb, of_None, ctx);
			break;
		case 0x21:
			ReadCommand(cmAnd, of_Ev, of_Gv, of_None, ctx);
			break;
		case 0x22:
			ReadCommand(cmAnd, of_Gb, of_Eb, of_None, ctx);
			break;
		case 0x23:
			ReadCommand(cmAnd, of_Gv, of_Ev, of_None, ctx);
			break;
		case 0x24:
			ReadCommand(cmAnd, of_FGb | regEAX, of_IBb, of_None, ctx);
			break;
		case 0x25:
			ReadCommand(cmAnd, of_FGv | regEAX, of_IZv, of_None, ctx);
			break;
		case 0x26:
			base_segment_ = segES;
			ctx.rex_prefix = 0;
			break;
		case 0x27:
			type_ = (size_ == osQWord) ? cmDB : cmDaa;
			break;
		case 0x28:
			ReadCommand(cmSub, of_Eb, of_Gb, of_None, ctx);
			break;
		case 0x29:
			ReadCommand(cmSub, of_Ev, of_Gv, of_None, ctx);
			break;
		case 0x2a:
			ReadCommand(cmSub, of_Gb, of_Eb, of_None, ctx);
			break;
		case 0x2b:
			ReadCommand(cmSub, of_Gv, of_Ev, of_None, ctx);
			break;
		case 0x2c:
			ReadCommand(cmSub, of_FGb | regEAX, of_IBb, of_None, ctx);
			break;
		case 0x2d:
			ReadCommand(cmSub, of_FGv | regEAX, of_IZv, of_None, ctx);
			break;
		case 0x2e:
			base_segment_ = segCS; ctx.rex_prefix = 0;
			break;
		case 0x2f:
			type_ = (size_ == osQWord) ? cmDB : cmDas;
			break;
		case 0x30:
			ReadCommand(cmXor, of_Eb, of_Gb, of_None, ctx);
			break;
		case 0x31:
			ReadCommand(cmXor, of_Ev, of_Gv, of_None, ctx);
			break;
		case 0x32:
			ReadCommand(cmXor, of_Gb, of_Eb, of_None, ctx);
			break;
		case 0x33:
			ReadCommand(cmXor, of_Gv, of_Ev, of_None, ctx);
			break;
		case 0x34:
			ReadCommand(cmXor, of_FGb | regEAX, of_IBb, of_None, ctx);
			break;
		case 0x35:
			ReadCommand(cmXor, of_FGv | regEAX, of_IZv, of_None, ctx);
			break;
		case 0x36:
			base_segment_ = segSS;
			ctx.rex_prefix = 0;
			break;
		case 0x37:
			type_ = (size_ == osQWord) ? cmDB : cmAaa;
			break;
		case 0x38:
			ReadCommand(cmCmp, of_Eb, of_Gb, of_None, ctx);
			break;
		case 0x39:
			ReadCommand(cmCmp, of_Ev, of_Gv, of_None, ctx);
			break;
		case 0x3a:
			ReadCommand(cmCmp, of_Gb, of_Eb, of_None, ctx);
			break;
		case 0x3b:
			ReadCommand(cmCmp, of_Gv, of_Ev, of_None, ctx);
			break;
		case 0x3c:
			ReadCommand(cmCmp, of_FGb | regEAX, of_IBb, of_None, ctx);
			break;
		case 0x3d:
			ReadCommand(cmCmp, of_FGv | regEAX, of_IZv, of_None, ctx);
			break;
		case 0x3e:
			base_segment_ = segDS;
			ctx.rex_prefix = 0;
			break;
		case 0x3f:
			type_ = (size_ == osQWord) ? cmDB : cmAas;
			break;
		case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47:
			if (size_ == osQWord) {
				ctx.rex_prefix = code;
			}
			else {
				ReadCommand(cmInc, of_Zdef | code, of_None, of_None, ctx);
			}
			break;
		case 0x48: case 0x49: case 0x4a: case 0x4b: case 0x4c: case 0x4d: case 0x4e: case 0x4f:
			if (size_ == osQWord) {
				ctx.rex_prefix = code;
			}
			else {
				ReadCommand(cmDec, of_Zdef | code, of_None, of_None, ctx);
			}
			break;
		case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
			ReadCommand(cmPush, of_Zdef | code, of_None, of_None, ctx);
			break;
		case 0x58: case 0x59: case 0x5a: case 0x5b: case 0x5c: case 0x5d: case 0x5e: case 0x5f:
			ReadCommand(cmPop, of_Zdef | code, of_None, of_None, ctx);
			break;
		case 0x60:
			if (size_ == osQWord) {
				type_ = cmDB;
			}
			else {
				ReadCommand(cmPusha, of_def, of_None, of_None, ctx);
			}
			break;
		case 0x61:
			if (size_ == osQWord) {
				type_ = cmDB;
			}
			else {
				ReadCommand(cmPopa, of_def, of_None, of_None, ctx);
			}
			break;
		case 0x62:
			if (size_ == osQWord) {
				type_ = cmDB;
			}
			else {
				ReadCommand(cmBound, of_Gv, of_Ma, of_None, ctx);
			}
			break;
		case 0x63:
			if (size_ == osQWord) {
				ReadCommand(cmMovsxd, of_Gv, of_Ed | of_size, of_None, ctx);
			}
			else {
				ReadCommand(cmArpl, of_Ew, of_Gw, of_None, ctx);
			}
			break;
		case 0x64:
			base_segment_ = segFS;
			ctx.rex_prefix = 0;
			break;
		case 0x65:
			base_segment_ = segGS;
			ctx.rex_prefix = 0;
			break;
		case 0x66:
			ctx.lower_reg = true;
			if (prefix == 0)
				prefix = code;
			break;
		case 0x67:
			ctx.lower_address = true;
			break;
		case 0x68:
			ReadCommand(cmPush, of_IZ | of_def, of_None, of_None, ctx);
			break;
		case 0x69:
			ReadCommand(cmImul, of_Gv, of_Ev, of_IZv, ctx);
			break;
		case 0x6a:
			ReadCommand(cmPush, of_IB | of_def, of_None, of_None, ctx);
			break;
		case 0x6b:
			ReadCommand(cmImul, of_Gv, of_Ev, of_IBv, ctx);
			break;
		case 0x6c:
			ReadCommand(cmIns, of_b, of_adr, of_None, ctx);
			break;
		case 0x6d:
			ReadCommand(cmIns, of_z, of_adr, of_None, ctx);
			break;
		case 0x6e:
			ReadCommand(cmOuts, of_b, of_adr, of_None, ctx);
			break;
		case 0x6f:
			ReadCommand(cmOuts, of_z, of_adr, of_None, ctx);
			break;
		case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
		case 0x78: case 0x79: case 0x7a: case 0x7b: case 0x7c: case 0x7d: case 0x7e: case 0x7f:
			ReadFlags(code);
			ReadCommand(cmJmpWithFlag, of_Jb, of_adr, of_None, ctx);
			break;
		case 0x80:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			switch ((code >> 3) & 7) {
			case 0x00:
				ReadCommand(cmAdd, of_Eb | of_size, of_IBb, of_None, ctx);
				break;
			case 0x01:
				ReadCommand(cmOr, of_Eb | of_size, of_IBb, of_None, ctx);
				break;
			case 0x02:
				ReadCommand(cmAdc, of_Eb | of_size, of_IBb, of_None, ctx);
				break;
			case 0x03:
				ReadCommand(cmSbb, of_Eb | of_size, of_IBb, of_None, ctx);
				break;
			case 0x04:
				ReadCommand(cmAnd, of_Eb | of_size, of_IBb, of_None, ctx);
				break;
			case 0x05:
				ReadCommand(cmSub, of_Eb | of_size, of_IBb, of_None, ctx);
				break;
			case 0x06:
				ReadCommand(cmXor, of_Eb | of_size, of_IBb, of_None, ctx);
				break;
			case 0x07:
				ReadCommand(cmCmp, of_Eb | of_size, of_IBb, of_None, ctx);
				break;
			default:
				type_ = cmDB;
				break;
			}
			break;
		case 0x81:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			switch ((code >> 3) & 7) {
			case 0x00:
				ReadCommand(cmAdd, of_Ev | of_size, of_IZv, of_None, ctx);
				break;
			case 0x01:
				ReadCommand(cmOr, of_Ev | of_size, of_IZv, of_None, ctx);
				break;
			case 0x02:
				ReadCommand(cmAdc, of_Ev | of_size, of_IZv, of_None, ctx);
				break;
			case 0x03:
				ReadCommand(cmSbb, of_Ev | of_size, of_IZv, of_None, ctx);
				break;
			case 0x04:
				ReadCommand(cmAnd, of_Ev | of_size, of_IZv, of_None, ctx);
				break;
			case 0x05:
				ReadCommand(cmSub, of_Ev | of_size, of_IZv, of_None, ctx);
				break;
			case 0x06:
				ReadCommand(cmXor, of_Ev | of_size, of_IZv, of_None, ctx);
				break;
			case 0x07:
				ReadCommand(cmCmp, of_Ev | of_size, of_IZv, of_None, ctx);
				break;
			default:
				type_ = cmDB;
				break;
			}
			break;
		case 0x82:
			if (size_ == osQWord) {
				type_ = cmDB;
			}
			else {
				code = ReadByte(file);
				ctx.use_last_byte = true;
				switch ((code >> 3) & 7) {
				case 0x00:
					ReadCommand(cmAdd, of_Eb | of_size, of_IBb, of_None, ctx);
					break;
				case 0x01:
					ReadCommand(cmOr, of_Eb | of_size, of_IBb, of_None, ctx);
					break;
				case 0x02:
					ReadCommand(cmAdc, of_Eb | of_size, of_IBb, of_None, ctx);
					break;
				case 0x03:
					ReadCommand(cmSbb, of_Eb | of_size, of_IBb, of_None, ctx);
					break;
				case 0x04:
					ReadCommand(cmAnd, of_Eb | of_size, of_IBb, of_None, ctx);
					break;
				case 0x05:
					ReadCommand(cmSub, of_Eb | of_size, of_IBb, of_None, ctx);
					break;
				case 0x06:
					ReadCommand(cmXor, of_Eb | of_size, of_IBb, of_None, ctx);
					break;
				case 0x07:
					ReadCommand(cmCmp, of_Eb | of_size, of_IBb, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
			}
			break;
		case 0x83:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			switch ((code >> 3) & 7) {
			case 0x00:
				ReadCommand(cmAdd, of_Ev | of_size, of_IBv, of_None, ctx);
				break;
			case 0x01:
				ReadCommand(cmOr, of_Ev | of_size, of_IBv, of_None, ctx);
				break;
			case 0x02:
				ReadCommand(cmAdc, of_Ev | of_size, of_IBv, of_None, ctx);
				break;
			case 0x03:
				ReadCommand(cmSbb, of_Ev | of_size, of_IBv, of_None, ctx);
				break;
			case 0x04:
				ReadCommand(cmAnd, of_Ev | of_size, of_IBv, of_None, ctx);
				break;
			case 0x05:
				ReadCommand(cmSub, of_Ev | of_size, of_IBv, of_None, ctx);
				break;
			case 0x06:
				ReadCommand(cmXor, of_Ev | of_size, of_IBv, of_None, ctx);
				break;
			case 0x07:
				ReadCommand(cmCmp, of_Ev | of_size, of_IBv, of_None, ctx);
				break;
			default:
				type_ = cmDB;
				break;
			}
			break;
		case 0x84:
			ReadCommand(cmTest, of_Eb, of_Gb, of_None, ctx);
			break;
		case 0x85:
			ReadCommand(cmTest, of_Ev, of_Gv, of_None, ctx);
			break;
		case 0x86:
			ReadCommand(cmXchg, of_Eb, of_Gb, of_None, ctx);
			break;
		case 0x87:
			ReadCommand(cmXchg, of_Ev, of_Gv, of_None, ctx);
			break;
		case 0x88:
			ReadCommand(cmMov, of_Eb, of_Gb, of_None, ctx);
			break;
		case 0x89:
			ReadCommand(cmMov, of_Ev, of_Gv, of_None, ctx);
			break;
		case 0x8a:
			ReadCommand(cmMov, of_Gb, of_Eb, of_None, ctx);
			break;
		case 0x8b:
			ReadCommand(cmMov, of_Gv, of_Ev, of_None, ctx);
			break;
		case 0x8c:
			ReadCommand(cmMov, of_Ev | of_mem_word, of_Sw, of_None, ctx);
			break;
		case 0x8d:
			ReadCommand(cmLea, of_Gv, of_Mv, of_None, ctx);
			break;
		case 0x8e:
			ReadCommand(cmMov, of_Sw, of_Ew, of_None, ctx);
			break;
		case 0x8f:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			switch ((code >> 3) & 7) {
			case 0x00:
				ReadCommand(cmPop, of_Edef | of_size, of_None, of_None, ctx);
				break;
			default:
				type_ = cmDB;
				break;
			}
			break;
		case 0x90:
			if (prefix == 0xF3) {
				preffix_command_ = cmUnknown;
				type_ = cmPause;
			}
			else {
				if (size_ == osQWord && (ctx.rex_prefix & rexB) != 0) {
					ReadCommand(cmXchg, of_Zv | regEAX, of_FGv | regEAX, of_None, ctx);
				}
				else {
					type_ = cmNop;
				}
			}
			break;
		case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
			ReadCommand(cmXchg, of_Zv | code, of_FGv | regEAX, of_None, ctx);
			break;
		case 0x98:
			os = GetOperandSize(1, ctx);
			switch (os) {
			case osWord:
				type_ = cmCbw;
				break;
			case osDWord:
				type_ = cmCwde;
				break;
			default:
				type_ = cmCdqe;
				break;
			}
			break;
		case 0x99:
			os = GetOperandSize(1, ctx);
			switch (os) {
			case osWord:
				type_ = cmCwd;
				break;
			case osDWord:
				type_ = cmCdq;
				break;
			default:
				type_ = cmCqo;
				break;
			}
			break;
		case 0x9a:
			if (size_ == osQWord)
				type_ = cmDB;
			else {
				include_option(roFar);
				ReadCommand(cmCall, of_Ap, of_None, of_None, ctx);
			}
			break;
		case 0x9b:
			type_ = cmWait;
			{
				Data old_dump;
				for (i = 0; i < dump_size(); i++) {
					old_dump.PushByte(dump(i));
				}
				uint64_t pos = file.Tell();
				code = ReadByte(file);
				switch (code) {
				case 0xd9:
					code = ReadByte(file);
					ctx.use_last_byte = true;
					if ((code & 0xc0) != 0xc0) {
						switch ((code >> 3) & 7) {
						case 0x06:
							ReadCommand(cmFstenv, of_Mb, of_None, of_None, ctx);
							break;
						case 0x07:
							ReadCommand(cmFstcw, of_Mw | of_size, of_None, of_None, ctx);
							break;
						}
					}
					break;
				case 0xdb:
					code = ReadByte(file);
					ctx.use_last_byte = true;
					switch (code) {
					case 0xe2:
						type_ = cmFclex;
						break;
					case 0xe3:
						type_ = cmFinit;
						break;
					}
					break;
				case 0xdd:
					code = ReadByte(file);
					ctx.use_last_byte = true;
					if ((code & 0xc0) != 0xc0) {
						switch ((code >> 3) & 7) {
						case 0x06:
							ReadCommand(cmFsave, of_Mb, of_None, of_None, ctx);
							break;
						case 0x07:
							ReadCommand(cmFstsw, of_Mw | of_size, of_None, of_None, ctx);
							break;
						}
					}
					break;
				case 0xdf:
					code = ReadByte(file);
					ctx.use_last_byte = true;
					if (code == 0xe0)
						ReadCommand(cmFstsw, of_FGw | regEAX, of_None, of_None, ctx);
					break;
				}
				if (type_ == cmWait) {
					set_dump(old_dump.data(), old_dump.size());
					file.Seek(pos);
				}
			}
			break;
		case 0x9c:
			ReadCommand(cmPushf, of_def, of_None, of_None, ctx);
			break;
		case 0x9d:
			ReadCommand(cmPopf, of_def, of_None, of_None, ctx);
			break;
		case 0x9e:
			ReadCommand(cmSahf, of_b, of_None, of_None, ctx);
			break;
		case 0x9f:
			ReadCommand(cmLahf, of_b, of_None, of_None, ctx);
			break;
		case 0xa0:
			ReadCommand(cmMov, of_FGb | regEAX, of_Ob, of_None, ctx);
			break;
		case 0xa1:
			ReadCommand(cmMov, of_FGv | regEAX, of_Ov, of_None, ctx);
			break;
		case 0xa2:
			ReadCommand(cmMov, of_Ob, of_FGb | regEAX, of_None, ctx);
			break;
		case 0xa3:
			ReadCommand(cmMov, of_Ov, of_FGv | regEAX, of_None, ctx);
			break;
		case 0xa4:
			ReadCommand(cmMovs, of_b, of_adr, of_None, ctx);
			break;
		case 0xa5:
			ReadCommand(cmMovs, of_v, of_adr, of_None, ctx);
			break;
		case 0xa6:
			ReadCommand(cmCmps, of_b, of_adr, of_None, ctx);
			break;
		case 0xa7:
			ReadCommand(cmCmps, of_v, of_adr, of_None, ctx);
			break;
		case 0xa8:
			ReadCommand(cmTest, of_FGb | regEAX, of_IBb, of_None, ctx);
			break;
		case 0xa9:
			ReadCommand(cmTest, of_FGv | regEAX, of_IZv, of_None, ctx);
			break;
		case 0xaa:
			ReadCommand(cmStos, of_b, of_adr, of_None, ctx);
			break;
		case 0xab:
			ReadCommand(cmStos, of_v, of_adr, of_None, ctx);
			break;
		case 0xac:
			ReadCommand(cmLods, of_b, of_adr, of_None, ctx);
			break;
		case 0xad:
			ReadCommand(cmLods, of_v, of_adr, of_None, ctx);
			break;
		case 0xae:
			ReadCommand(cmScas, of_b, of_adr, of_None, ctx);
			break;
		case 0xaf:
			ReadCommand(cmScas, of_v, of_adr, of_None, ctx);
			break;
		case 0xb0: case 0xb1: case 0xb2: case 0xb3: case 0xb4: case 0xb5: case 0xb6: case 0xb7:
			ReadCommand(cmMov, of_Zb | code, of_IBb, of_None, ctx);
			break;
		case 0xb8: case 0xb9: case 0xba: case 0xbb: case 0xbc: case 0xbd: case 0xbe: case 0xbf:
			ReadCommand(cmMov, of_Zv | code, of_IVv, of_None, ctx);
			break;
		case 0xc0:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			switch ((code >> 3) & 7) {
			case 0x00:
				ReadCommand(cmRol, of_Eb | of_size, of_IBb, of_None, ctx);
				break;
			case 0x01:
				ReadCommand(cmRor, of_Eb | of_size, of_IBb, of_None, ctx);
				break;
			case 0x02:
				ReadCommand(cmRcl, of_Eb | of_size, of_IBb, of_None, ctx);
				break;
			case 0x03:
				ReadCommand(cmRcr, of_Eb | of_size, of_IBb, of_None, ctx);
				break;
			case 0x04:
				ReadCommand(cmShl, of_Eb | of_size, of_IBb, of_None, ctx);
				break;
			case 0x05:
				ReadCommand(cmShr, of_Eb | of_size, of_IBb, of_None, ctx);
				break;
			case 0x06:
				ReadCommand(cmSal, of_Eb | of_size, of_IBb, of_None, ctx);
				break;
			case 0x07:
				ReadCommand(cmSar, of_Eb | of_size, of_IBb, of_None, ctx);
				break;
			default:
				type_ = cmDB;
				break;
			}
			break;
		case 0xc1:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			switch ((code >> 3) & 7) {
			case 0x00:
				ReadCommand(cmRol, of_Ev | of_size, of_IBb, of_None, ctx);
				break;
			case 0x01:
				ReadCommand(cmRor, of_Ev | of_size, of_IBb, of_None, ctx);
				break;
			case 0x02:
				ReadCommand(cmRcl, of_Ev | of_size, of_IBb, of_None, ctx);
				break;
			case 0x03:
				ReadCommand(cmRcr, of_Ev | of_size, of_IBb, of_None, ctx);
				break;
			case 0x04:
				ReadCommand(cmShl, of_Ev | of_size, of_IBb, of_None, ctx);
				break;
			case 0x05:
				ReadCommand(cmShr, of_Ev | of_size, of_IBb, of_None, ctx);
				break;
			case 0x06:
				ReadCommand(cmSal, of_Ev | of_size, of_IBb, of_None, ctx);
				break;
			case 0x07:
				ReadCommand(cmSar, of_Ev | of_size, of_IBb, of_None, ctx);
				break;
			default:
				type_ = cmDB;
				break;
			}
			break;
		case 0xc2:
			ReadCommand(cmRet, of_IWw, of_None, of_None, ctx);
			break;
		case 0xc3:
			type_ = cmRet;
			break;
		case 0xc4:
			code = ReadByte(file);
			if (size_ == osDWord && (code & 0xc0) == 0) {
				ctx.use_last_byte = true;
				ReadCommand(cmLes, of_Gz, of_Mp, of_None, ctx);
			}
			else {
				if (prefix || ctx.rex_prefix || (options() & roLockPrefix))
					type_ = cmDB;
				else {
					include_option(roVexPrefix);
					uint8_t vex_1 = code;
					uint8_t vex_2 = ReadByte(file);
					switch (vex_1 & 0x1f) {
					case 1:
						vex_bytes[0] = 0x0f;
						break;
					case 2:
						vex_bytes[0] = 0x0f;
						vex_bytes[1] = 0x38;
						break;
					case 3:
						vex_bytes[0] = 0x0f;
						vex_bytes[1] = 0x3a;
						break;
					default:
						type_ = cmDB;
					}
					switch (vex_2 & 3) {
					case 1:
						prefix = 0x66;
						break;
					case 2:
						prefix = 0xf3;
						break;
					case 3:
						prefix = 0xf2;
						break;
					}
					ctx.rex_prefix = static_cast<uint8_t>(~vex_1) >> 5; // REX.RXB
					ctx.rex_prefix |= (vex_2 & 0x80) >> 4; // REX.W
					ctx.rex_prefix |= (vex_2 & 4) << 5; // VEX.L
					ctx.vex_registr = ((~vex_2) >> 3) & 0xf;
				}
			}
			break;
		case 0xc5:
			code = ReadByte(file);
			if (size_ == osDWord && (code & 0xc0) == 0) {
				ctx.use_last_byte = true;
				ReadCommand(cmLds, of_Gz, of_Mp, of_None, ctx);
			}
			else {
				if (prefix || ctx.rex_prefix || (options() & roLockPrefix))
					type_ = cmDB;
				else {
					include_option(roVexPrefix);
					uint8_t vex_1 = code;
					vex_bytes[0] = 0x0f;
					switch (vex_1 & 3) {
					case 1:
						prefix = 0x66;
						break;
					case 2:
						prefix = 0xf3;
						break;
					case 3:
						prefix = 0xf2;
						break;
					}
					ctx.rex_prefix = (static_cast<uint8_t>(~vex_1) & 0x80) >> 5;  // REX.R
					ctx.rex_prefix |= (vex_1 & 4) << 5; // VEX.L
					ctx.vex_registr = ((~vex_1) >> 3) & 0xf;
				}
			}
			break;
		case 0xc6:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			switch ((code >> 3) & 7) {
			case 0x00:
				ReadCommand(cmMov, of_Eb | of_size, of_IBb, of_None, ctx);
				break;
			default:
				type_ = cmDB;
				break;
			}
			break;
		case 0xc7:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			switch ((code >> 3) & 7) {
			case 0x00:
				ReadCommand(cmMov, of_Ev | of_size, of_IZv, of_None, ctx);
				break;
			default:
				type_ = cmDB;
				break;
			}
			break;
		case 0xc8:
			ReadCommand(cmEnter, of_IWw, of_IBb, of_None, ctx);
			break;
		case 0xc9:
			type_ = cmLeave;
			break;
		case 0xca:
			include_option(roFar);
			ReadCommand(cmRet, of_IWw, of_None, of_None, ctx);
			break;
		case 0xcb:
			include_option(roFar);
			type_ = cmRet;
			break;
		case 0xcc:
			ReadCommand(cmInt, of_FIb | 3, of_None, of_None, ctx);
			break;
		case 0xcd:
			ReadCommand(cmInt, of_IBb, of_None, of_None, ctx);
			break;
		case 0xce:
			if (size_ == osQWord) {
				type_ = cmDB;
			}
			else {
				type_ = cmInto;
			}
			break;
		case 0xcf:
			ReadCommand(cmIret, of_v, of_None, of_None, ctx);
			break;
		case 0xd0:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			switch ((code >> 3) & 7) {
			case 0x00:
				ReadCommand(cmRol, of_Eb | of_size, of_FIb | 1, of_None, ctx);
				break;
			case 0x01:
				ReadCommand(cmRor, of_Eb | of_size, of_FIb | 1, of_None, ctx);
				break;
			case 0x02:
				ReadCommand(cmRcl, of_Eb | of_size, of_FIb | 1, of_None, ctx);
				break;
			case 0x03:
				ReadCommand(cmRcr, of_Eb | of_size, of_FIb | 1, of_None, ctx);
				break;
			case 0x04:
				ReadCommand(cmShl, of_Eb | of_size, of_FIb | 1, of_None, ctx);
				break;
			case 0x05:
				ReadCommand(cmShr, of_Eb | of_size, of_FIb | 1, of_None, ctx);
				break;
			case 0x06:
				ReadCommand(cmSal, of_Eb | of_size, of_FIb | 1, of_None, ctx);
				break;
			case 0x07:
				ReadCommand(cmSar, of_Eb | of_size, of_FIb | 1, of_None, ctx);
				break;
			default:
				type_ = cmDB;
				break;
			}
			break;
		case 0xd1:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			switch ((code >> 3) & 7) {
			case 0x00:
				ReadCommand(cmRol, of_Ev | of_size, of_FIb | 1, of_None, ctx);
				break;
			case 0x01:
				ReadCommand(cmRor, of_Ev | of_size, of_FIb | 1, of_None, ctx);
				break;
			case 0x02:
				ReadCommand(cmRcl, of_Ev | of_size, of_FIb | 1, of_None, ctx);
				break;
			case 0x03:
				ReadCommand(cmRcr, of_Ev | of_size, of_FIb | 1, of_None, ctx);
				break;
			case 0x04:
				ReadCommand(cmShl, of_Ev | of_size, of_FIb | 1, of_None, ctx);
				break;
			case 0x05:
				ReadCommand(cmShr, of_Ev | of_size, of_FIb | 1, of_None, ctx);
				break;
			case 0x06:
				ReadCommand(cmSal, of_Ev | of_size, of_FIb | 1, of_None, ctx);
				break;
			case 0x07:
				ReadCommand(cmSar, of_Ev | of_size, of_FIb | 1, of_None, ctx);
				break;
			default:
				type_ = cmDB;
				break;
			}
			break;
		case 0xd2:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			switch ((code >> 3) & 7) {
			case 0x00:
				ReadCommand(cmRol, of_Eb | of_size, of_FGb | regECX, of_None, ctx);
				break;
			case 0x01:
				ReadCommand(cmRor, of_Eb | of_size, of_FGb | regECX, of_None, ctx);
				break;
			case 0x02:
				ReadCommand(cmRcl, of_Eb | of_size, of_FGb | regECX, of_None, ctx);
				break;
			case 0x03:
				ReadCommand(cmRcr, of_Eb | of_size, of_FGb | regECX, of_None, ctx);
				break;
			case 0x04:
				ReadCommand(cmShl, of_Eb | of_size, of_FGb | regECX, of_None, ctx);
				break;
			case 0x05:
				ReadCommand(cmShr, of_Eb | of_size, of_FGb | regECX, of_None, ctx);
				break;
			case 0x06:
				ReadCommand(cmSal, of_Eb | of_size, of_FGb | regECX, of_None, ctx);
				break;
			case 0x07:
				ReadCommand(cmSar, of_Eb | of_size, of_FGb | regECX, of_None, ctx);
				break;
			default:
				type_ = cmDB;
				break;
			}
			break;
		case 0xd3:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			switch ((code >> 3) & 7) {
			case 0x00:
				ReadCommand(cmRol, of_Ev | of_size, of_FGb | regECX, of_None, ctx);
				break;
			case 0x01:
				ReadCommand(cmRor, of_Ev | of_size, of_FGb | regECX, of_None, ctx);
				break;
			case 0x02:
				ReadCommand(cmRcl, of_Ev | of_size, of_FGb | regECX, of_None, ctx);
				break;
			case 0x03:
				ReadCommand(cmRcr, of_Ev | of_size, of_FGb | regECX, of_None, ctx);
				break;
			case 0x04:
				ReadCommand(cmShl, of_Ev | of_size, of_FGb | regECX, of_None, ctx);
				break;
			case 0x05:
				ReadCommand(cmShr, of_Ev | of_size, of_FGb | regECX, of_None, ctx);
				break;
			case 0x06:
				ReadCommand(cmSal, of_Ev | of_size, of_FGb | regECX, of_None, ctx);
				break;
			case 0x07:
				ReadCommand(cmSar, of_Ev | of_size, of_FGb | regECX, of_None, ctx);
				break;
			default:
				type_ = cmDB;
				break;
			}
			break;
		case 0xd4:
			if (size_ == osQWord) {
				type_ = cmDB;
			}
			else {
				ReadCommand(cmAam, of_IBb, of_None, of_None, ctx);
			}
			break;
		case 0xd5:
			if (size_ == osQWord) {
				type_ = cmDB;
			}
			else {
				ReadCommand(cmAad, of_IBb, of_None, of_None, ctx);
			}
			break;
		case 0xd7:
			ReadCommand(cmXlat, of_adr, of_None, of_None, ctx);
			break;
		case 0xd8:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			if ((code & 0xc0) != 0xc0) {
				switch ((code >> 3) & 7) {
				case 0x00:
					ReadCommand(cmFadd, of_Md | of_size, of_None, of_None, ctx);
					break;
				case 0x01:
					ReadCommand(cmFmul, of_Md | of_size, of_None, of_None, ctx);
					break;
				case 0x02:
					ReadCommand(cmFcom, of_Md | of_size, of_None, of_None, ctx);
					break;
				case 0x03:
					ReadCommand(cmFcomp, of_Md | of_size, of_None, of_None, ctx);
					break;
				case 0x04:
					ReadCommand(cmFsub, of_Md | of_size, of_None, of_None, ctx);
					break;
				case 0x05:
					ReadCommand(cmFsubr, of_Md | of_size, of_None, of_None, ctx);
					break;
				case 0x06:
					ReadCommand(cmFdiv, of_Md | of_size, of_None, of_None, ctx);
					break;
				case 0x07:
					ReadCommand(cmFdivr, of_Md | of_size, of_None, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
			}
			else {
				switch ((code >> 3) & 7) {
				case 0x00:
					ReadCommand(cmFadd, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				case 0x01:
					ReadCommand(cmFmul, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				case 0x02:
					ReadCommand(cmFcom, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				case 0x03:
					ReadCommand(cmFcomp, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				case 0x04:
					ReadCommand(cmFsub, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				case 0x05:
					ReadCommand(cmFsubr, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				case 0x06:
					ReadCommand(cmFdiv, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				case 0x07:
					ReadCommand(cmFdivr, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
			}
			break;
		case 0xd9:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			if ((code & 0xc0) != 0xc0) {
				switch ((code >> 3) & 7) {
				case 0x00:
					ReadCommand(cmFld, of_Md | of_size, of_None, of_None, ctx);
					break;
				case 0x02:
					ReadCommand(cmFst, of_Md | of_size, of_None, of_None, ctx);
					break;
				case 0x03:
					ReadCommand(cmFstp, of_Md | of_size, of_None, of_None, ctx);
					break;
				case 0x04:
					ReadCommand(cmFldenv, of_Mb, of_None, of_None, ctx);
					break;
				case 0x05:
					ReadCommand(cmFldcw, of_Mw | of_size, of_None, of_None, ctx);
					break;
				case 0x06:
					ReadCommand(cmFnstenv, of_Mb, of_None, of_None, ctx);
					break;
				case 0x07:
					ReadCommand(cmFnstcw, of_Mw | of_size, of_None, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
			}
			else {
				switch (code) {
				case 0xc0: case 0xc1: case 0xc2: case 0xc3:
				case 0xc4: case 0xc5: case 0xc6: case 0xc7:
					ReadCommand(cmFld, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				case 0xc8: case 0xc9: case 0xca: case 0xcb:
				case 0xcc: case 0xcd: case 0xce: case 0xcf:
					ReadCommand(cmFxch, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				case 0xd0:
					type_ = cmFnop;
					break;
				case 0xd8: case 0xd9: case 0xda: case 0xdb:
				case 0xdc: case 0xdd: case 0xde: case 0xdf:
					ReadCommand(cmFstp1, of_ST | code, of_None, of_None, ctx);
					break;
				case 0xe0:
					type_ = cmFchs;
					break;
				case 0xe1:
					type_ = cmFabs;
					break;
				case 0xe4:
					type_ = cmFtst;
					break;
				case 0xe5:
					type_ = cmFxam;
					break;
				case 0xe8:
					type_ = cmFld1;
					break;
				case 0xe9:
					type_ = cmFldl2t;
					break;
				case 0xea:
					type_ = cmFldl2e;
					break;
				case 0xeb:
					type_ = cmFldpi;
					break;
				case 0xec:
					type_ = cmFldlg2;
					break;
				case 0xed:
					type_ = cmFldln2;
					break;
				case 0xee:
					type_ = cmFldz;
					break;
				case 0xf0:
					type_ = cmF2xm1;
					break;
				case 0xf1:
					type_ = cmFyl2x;
					break;
				case 0xf2:
					type_ = cmFptan;
					break;
				case 0xf3:
					type_ = cmFpatan;
					break;
				case 0xf4:
					type_ = cmFxtract;
					break;
				case 0xf5:
					type_ = cmFprem1;
					break;
				case 0xf6:
					type_ = cmFdecstp;
					break;
				case 0xf7:
					type_ = cmFincstp;
					break;
				case 0xf8:
					type_ = cmFprem;
					break;
				case 0xf9:
					type_ = cmFyl2xp1;
					break;
				case 0xfa:
					type_ = cmFsqrt;
					break;
				case 0xfb:
					type_ = cmFsincos;
					break;
				case 0xfc:
					type_ = cmFrndint;
					break;
				case 0xfd:
					type_ = cmFscale;
					break;
				case 0xfe:
					type_ = cmFsin;
					break;
				case 0xff:
					type_ = cmFcos;
					break;
				default:
					type_ = cmDB;
					break;
				}
			}
			break;
		case 0xda:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			if ((code & 0xc0) != 0xc0) {
				switch ((code >> 3) & 7) {
				case 0x00:
					ReadCommand(cmFiadd, of_Md | of_size, of_None, of_None, ctx);
					break;
				case 0x01:
					ReadCommand(cmFimul, of_Md | of_size, of_None, of_None, ctx);
					break;
				case 0x02:
					ReadCommand(cmFicom, of_Md | of_size, of_None, of_None, ctx);
					break;
				case 0x03:
					ReadCommand(cmFicomp, of_Md | of_size, of_None, of_None, ctx);
					break;
				case 0x04:
					ReadCommand(cmFisub, of_Md | of_size, of_None, of_None, ctx);
					break;
				case 0x05:
					ReadCommand(cmFisubr, of_Md | of_size, of_None, of_None, ctx);
					break;
				case 0x06:
					ReadCommand(cmFidiv, of_Md | of_size, of_None, of_None, ctx);
					break;
				case 0x07:
					ReadCommand(cmFidivr, of_Md | of_size, of_None, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
			}
			else {
				switch (code) {
				case 0xc0: case 0xc1: case 0xc2: case 0xc3:
				case 0xc4: case 0xc5: case 0xc6: case 0xc7:
					ReadCommand(cmFcmovb, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				case 0xc8: case 0xc9: case 0xca: case 0xcb:
				case 0xcc: case 0xcd: case 0xce: case 0xcf:
					ReadCommand(cmFcmove, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				case 0xd0: case 0xd1: case 0xd2: case 0xd3:
				case 0xd4: case 0xd5: case 0xd6: case 0xd7:
					ReadCommand(cmFcmovbe, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				case 0xd8: case 0xd9: case 0xda: case 0xdb:
				case 0xdc: case 0xdd: case 0xde: case 0xdf:
					ReadCommand(cmFcmovu, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				case 0xe9:
					type_ = cmFucompp;
					break;
				default:
					type_ = cmDB;
					break;
				}
			}
			break;
		case 0xdb:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			if ((code & 0xc0) != 0xc0) {
				switch ((code >> 3) & 7) {
				case 0x00:
					ReadCommand(cmFild, of_Md | of_size, of_None, of_None, ctx);
					break;
				case 0x01:
					ReadCommand(cmFisttp, of_Md | of_size, of_None, of_None, ctx);
					break;
				case 0x02:
					ReadCommand(cmFist, of_Md | of_size, of_None, of_None, ctx);
					break;
				case 0x03:
					ReadCommand(cmFistp, of_Md | of_size, of_None, of_None, ctx);
					break;
				case 0x05:
					ReadCommand(cmFld, of_Mt | of_size, of_None, of_None, ctx);
					break;
				case 0x07:
					ReadCommand(cmFstp, of_Mt | of_size, of_None, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
			}
			else {
				switch (code) {
				case 0xc0: case 0xc1: case 0xc2: case 0xc3:
				case 0xc4: case 0xc5: case 0xc6: case 0xc7:
					ReadCommand(cmFcmovnb, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				case 0xc8: case 0xc9: case 0xca: case 0xcb:
				case 0xcc: case 0xcd: case 0xce: case 0xcf:
					ReadCommand(cmFcmovne, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				case 0xd0: case 0xd1: case 0xd2: case 0xd3:
				case 0xd4: case 0xd5: case 0xd6: case 0xd7:
					ReadCommand(cmFcmovnbe, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				case 0xd8: case 0xd9: case 0xda: case 0xdb:
				case 0xdc: case 0xdd: case 0xde: case 0xdf:
					ReadCommand(cmFcmovnu, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				case 0xe2:
					type_ = cmFnclex;
					break;
				case 0xe3:
					type_ = cmFninit;
					break;
				case 0xe8: case 0xe9: case 0xea: case 0xeb:
				case 0xec: case 0xed: case 0xee: case 0xef:
					ReadCommand(cmFucomi, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				case 0xf0: case 0xf1: case 0xf2: case 0xf3:
				case 0xf4: case 0xf5: case 0xf6: case 0xf7:
					ReadCommand(cmFcomi, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
			}
			break;
		case 0xdc:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			if ((code & 0xc0) != 0xc0) {
				switch ((code >> 3) & 7) {
				case 0x00:
					ReadCommand(cmFadd, of_Mq | of_size, of_None, of_None, ctx);
					break;
				case 0x01:
					ReadCommand(cmFmul, of_Mq | of_size, of_None, of_None, ctx);
					break;
				case 0x02:
					ReadCommand(cmFcom, of_Mq | of_size, of_None, of_None, ctx);
					break;
				case 0x03:
					ReadCommand(cmFcomp, of_Mq | of_size, of_None, of_None, ctx);
					break;
				case 0x04:
					ReadCommand(cmFsub, of_Mq | of_size, of_None, of_None, ctx);
					break;
				case 0x05:
					ReadCommand(cmFsubr, of_Mq | of_size, of_None, of_None, ctx);
					break;
				case 0x06:
					ReadCommand(cmFdiv, of_Mq | of_size, of_None, of_None, ctx);
					break;
				case 0x07:
					ReadCommand(cmFdivr, of_Mq | of_size, of_None, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
			}
			else {
				switch ((code >> 3) & 7) {
				case 0x00:
					ReadCommand(cmFadd, of_ST | code, of_ST | 0, of_None, ctx);
					break;
				case 0x01:
					ReadCommand(cmFmul, of_ST | code, of_ST | 0, of_None, ctx);
					break;
				case 0x02:
					ReadCommand(cmFcom2, of_ST | code, of_None, of_None, ctx);
					break;
				case 0x03:
					ReadCommand(cmFcomp3, of_ST | code, of_None, of_None, ctx);
					break;
				case 0x04:
					ReadCommand(cmFsubr, of_ST | code, of_ST | 0, of_None, ctx);
					break;
				case 0x05:
					ReadCommand(cmFsub, of_ST | code, of_ST | 0, of_None, ctx);
					break;
				case 0x06:
					ReadCommand(cmFdivr, of_ST | code, of_ST | 0, of_None, ctx);
					break;
				case 0x07:
					ReadCommand(cmFdiv, of_ST | code, of_ST | 0, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
			}
			break;
		case 0xdd:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			if ((code & 0xc0) != 0xc0) {
				switch ((code >> 3) & 7) {
				case 0x00:
					ReadCommand(cmFld, of_Mq | of_size, of_None, of_None, ctx);
					break;
				case 0x01:
					ReadCommand(cmFisttp, of_Mq | of_size, of_None, of_None, ctx);
					break;
				case 0x02:
					ReadCommand(cmFst, of_Mq | of_size, of_None, of_None, ctx);
					break;
				case 0x03:
					ReadCommand(cmFstp, of_Mq | of_size, of_None, of_None, ctx);
					break;
				case 0x04:
					ReadCommand(cmFrstor, of_Mb, of_None, of_None, ctx);
					break;
				case 0x06:
					ReadCommand(cmFnsave, of_Mb, of_None, of_None, ctx);
					break;
				case 0x07:
					ReadCommand(cmFnstsw, of_Mw | of_size, of_None, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
			}
			else {
				switch ((code >> 3) & 7) {
				case 0x00:
					ReadCommand(cmFfree, of_ST | code, of_None, of_None, ctx);
					break;
				case 0x01:
					ReadCommand(cmFxch4, of_ST | code, of_None, of_None, ctx);
					break;
				case 0x02:
					ReadCommand(cmFst, of_ST | code, of_None, of_None, ctx);
					break;
				case 0x03:
					ReadCommand(cmFstp, of_ST | code, of_None, of_None, ctx);
					break;
				case 0x04:
					ReadCommand(cmFucom, of_ST | code, of_None, of_None, ctx);
					break;
				case 0x05:
					ReadCommand(cmFucomp, of_ST | code, of_None, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
			}
			break;
		case 0xde:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			if ((code & 0xc0) != 0xc0) {
				switch ((code >> 3) & 7) {
				case 0x00:
					ReadCommand(cmFiadd, of_Mw | of_size, of_None, of_None, ctx);
					break;
				case 0x01:
					ReadCommand(cmFimul, of_Mw | of_size, of_None, of_None, ctx);
					break;
				case 0x02:
					ReadCommand(cmFicom, of_Mw | of_size, of_None, of_None, ctx);
					break;
				case 0x03:
					ReadCommand(cmFicomp, of_Mw | of_size, of_None, of_None, ctx);
					break;
				case 0x04:
					ReadCommand(cmFisub, of_Mw | of_size, of_None, of_None, ctx);
					break;
				case 0x05:
					ReadCommand(cmFisubr, of_Mw | of_size, of_None, of_None, ctx);
					break;
				case 0x06:
					ReadCommand(cmFidiv, of_Mw | of_size, of_None, of_None, ctx);
					break;
				case 0x07:
					ReadCommand(cmFidivr, of_Mw | of_size, of_None, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
			}
			else {
				switch (code) {
				case 0xc0: case 0xc1: case 0xc2: case 0xc3:
				case 0xc4: case 0xc5: case 0xc6: case 0xc7:
					ReadCommand(cmFaddp, of_ST | code, of_ST | 0, of_None, ctx);
					break;
				case 0xc8: case 0xc9: case 0xca: case 0xcb:
				case 0xcc: case 0xcd: case 0xce: case 0xcf:
					ReadCommand(cmFmulp, of_ST | code, of_ST | 0, of_None, ctx);
					break;
				case 0xd0: case 0xd1: case 0xd2: case 0xd3:
				case 0xd4: case 0xd5: case 0xd6: case 0xd7:
					ReadCommand(cmFcomp5, of_ST | code, of_None, of_None, ctx);
					break;
				case 0xd9:
					type_ = cmFcompp;
					break;
				case 0xe0: case 0xe1: case 0xe2: case 0xe3:
				case 0xe4: case 0xe5: case 0xe6: case 0xe7:
					ReadCommand(cmFsubrp, of_ST | code, of_ST | 0, of_None, ctx);
					break;
				case 0xe8: case 0xe9: case 0xea: case 0xeb:
				case 0xec: case 0xed: case 0xee: case 0xef:
					ReadCommand(cmFsubp, of_ST | code, of_ST | 0, of_None, ctx);
					break;
				case 0xf0: case 0xf1: case 0xf2: case 0xf3:
				case 0xf4: case 0xf5: case 0xf6: case 0xf7:
					ReadCommand(cmFdivrp, of_ST | code, of_ST | 0, of_None, ctx);
					break;
				case 0xf8: case 0xf9: case 0xfa: case 0xfb:
				case 0xfc: case 0xfd: case 0xfe: case 0xff:
					ReadCommand(cmFdivp, of_ST | code, of_ST | 0, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
			}
			break;
		case 0xdf:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			if ((code & 0xc0) != 0xc0) {
				switch ((code >> 3) & 7) {
				case 0x00:
					ReadCommand(cmFild, of_Mw | of_size, of_None, of_None, ctx);
					break;
				case 0x01:
					ReadCommand(cmFisttp, of_Mw | of_size, of_None, of_None, ctx);
					break;
				case 0x02:
					ReadCommand(cmFist, of_Mw | of_size, of_None, of_None, ctx);
					break;
				case 0x03:
					ReadCommand(cmFistp, of_Mw | of_size, of_None, of_None, ctx);
					break;
				case 0x04:
					ReadCommand(cmFbld, of_Mt, of_None, of_None, ctx);
					break;
				case 0x05:
					ReadCommand(cmFild, of_Mq | of_size, of_None, of_None, ctx);
					break;
				case 0x06:
					ReadCommand(cmFbstp, of_Mt, of_None, of_None, ctx);
					break;
				case 0x07:
					ReadCommand(cmFistp, of_Mq | of_size, of_None, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
			}
			else {
				switch (code) {
				case 0xc0: case 0xc1: case 0xc2: case 0xc3:
				case 0xc4: case 0xc5: case 0xc6: case 0xc7:
					ReadCommand(cmFfreep, of_ST | code, of_None, of_None, ctx);
					break;
				case 0xc8: case 0xc9: case 0xca: case 0xcb:
				case 0xcc: case 0xcd: case 0xce: case 0xcf:
					ReadCommand(cmFxch7, of_ST | code, of_None, of_None, ctx);
					break;
				case 0xd0: case 0xd1: case 0xd2: case 0xd3:
				case 0xd4: case 0xd5: case 0xd6: case 0xd7:
					ReadCommand(cmFstp8, of_ST | code, of_None, of_None, ctx);
					break;
				case 0xd8: case 0xd9: case 0xda: case 0xdb:
				case 0xdc: case 0xdd: case 0xde: case 0xdf:
					ReadCommand(cmFstp9, of_ST | code, of_None, of_None, ctx);
					break;
				case 0xe0:
					ReadCommand(cmFnstsw, of_FGw | regEAX, of_None, of_None, ctx);
					break;
				case 0xe8: case 0xe9: case 0xea: case 0xeb:
				case 0xec: case 0xed: case 0xee: case 0xef:
					ReadCommand(cmFucomip, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				case 0xf0: case 0xf1: case 0xf2: case 0xf3:
				case 0xf4: case 0xf5: case 0xf6: case 0xf7:
					ReadCommand(cmFcomip, of_ST | 0, of_ST | code, of_None, ctx);
					break;
				default:
					type_ = cmDB;
					break;
				}
			}
			break;
		case 0xe0:
			ReadCommand(cmLoopne, of_Jb, of_adr, of_None, ctx);
			break;
		case 0xe1:
			ReadCommand(cmLoope, of_Jb, of_adr, of_None, ctx);
			break;
		case 0xe2:
			ReadCommand(cmLoop, of_Jb, of_adr, of_None, ctx);
			break;
		case 0xe3:
			ReadCommand(cmJCXZ, of_Jb, of_adr, of_None, ctx);
			break;
		case 0xe4:
			ReadCommand(cmIn, of_FGb | regEAX, of_IBb, of_None, ctx);
			break;
		case 0xe5:
			ReadCommand(cmIn, of_FGv | regEAX, of_IBb, of_None, ctx);
			break;
		case 0xe6:
			ReadCommand(cmOut, of_IBb, of_FGb | regEAX, of_None, ctx);
			break;
		case 0xe7:
			ReadCommand(cmOut, of_IBb, of_FGv | regEAX, of_None, ctx);
			break;
		case 0xe8:
			ReadCommand(cmCall, of_Jz, of_None, of_None, ctx);
			break;
		case 0xe9:
			ReadCommand(cmJmp, of_Jz, of_None, of_None, ctx);
			break;
		case 0xea:
			if (size_ == osQWord)
				type_ = cmDB;
			else {
				include_option(roFar);
				ReadCommand(cmJmp, of_Ap, of_None, of_None, ctx);
			}
			break;
		case 0xeb:
			ReadCommand(cmJmp, of_Jb, of_None, of_None, ctx);
			break;
		case 0xec:
			ReadCommand(cmIn, of_FGb | regEAX, of_FGw | regEDX, of_None, ctx);
			break;
		case 0xed:
			ReadCommand(cmIn, of_FGv | regEAX, of_FGw | regEDX, of_None, ctx);
			break;
		case 0xee:
			ReadCommand(cmOut, of_FGw | regEDX, of_FGb | regEAX, of_None, ctx);
			break;
		case 0xef:
			ReadCommand(cmOut, of_FGw | regEDX, of_FGv | regEAX, of_None, ctx);
			break;
		case 0xf0:
			include_option(roLockPrefix);
			break;
		case 0xf1:
			ReadCommand(cmInt, of_FIb | 1, of_None, of_None, ctx);
			break;
		case 0xf2:
			preffix_command_ = cmRepne;
			prefix = code;
			break;
		case 0xf3:
			preffix_command_ = cmRep;
			prefix = code;
			break;
		case 0xf4:
			type_ = cmHlt;
			break;
		case 0xf5:
			type_ = cmCmc;
			break;
		case 0xf6:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			switch ((code >> 3) & 7) {
			case 0x00:
			case 0x01:
				ReadCommand(cmTest, of_Eb | of_size, of_IBb, of_None, ctx);
				break;
			case 0x02:
				ReadCommand(cmNot, of_Eb | of_size, of_None, of_None, ctx);
				break;
			case 0x03:
				ReadCommand(cmNeg, of_Eb | of_size, of_None, of_None, ctx);
				break;
			case 0x04:
				ReadCommand(cmMul, of_Eb | of_size, of_None, of_None, ctx);
				break;
			case 0x05:
				ReadCommand(cmImul, of_Eb | of_size, of_None, of_None, ctx);
				break;
			case 0x06:
				ReadCommand(cmDiv, of_Eb | of_size, of_None, of_None, ctx);
				break;
			case 0x07:
				ReadCommand(cmIdiv, of_Eb | of_size, of_None, of_None, ctx);
				break;
			}
			break;
		case 0xf7:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			switch ((code >> 3) & 7) {
			case 0x00:
			case 0x01:
				ReadCommand(cmTest, of_Ev | of_size, of_IZv, of_None, ctx);
				break;
			case 0x02:
				ReadCommand(cmNot, of_Ev | of_size, of_None, of_None, ctx);
				break;
			case 0x03:
				ReadCommand(cmNeg, of_Ev | of_size, of_None, of_None, ctx);
				break;
			case 0x04:
				ReadCommand(cmMul, of_Ev | of_size, of_None, of_None, ctx);
				break;
			case 0x05:
				ReadCommand(cmImul, of_Ev | of_size, of_None, of_None, ctx);
				break;
			case 0x06:
				ReadCommand(cmDiv, of_Ev | of_size, of_None, of_None, ctx);
				break;
			case 0x07:
				ReadCommand(cmIdiv, of_Ev | of_size, of_None, of_None, ctx);
				break;
			}
			break;
		case 0xf8:
			type_ = cmClc;
			break;
		case 0xf9:
			type_ = cmStc;
			break;
		case 0xfa:
			type_ = cmCli;
			break;
		case 0xfb:
			type_ = cmSti;
			break;
		case 0xfc:
			type_ = cmCld;
			break;
		case 0xfd:
			type_ = cmStd;
			break;
		case 0xfe:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			switch ((code >> 3) & 7) {
			case 0x00:
				ReadCommand(cmInc, of_Eb | of_size, of_None, of_None, ctx);
				break;
			case 0x01:
				ReadCommand(cmDec, of_Eb | of_size, of_None, of_None, ctx);
				break;
			default:
				type_ = cmDB;
				break;
			}
			break;
		case 0xff:
			code = ReadByte(file);
			ctx.use_last_byte = true;
			switch ((code >> 3) & 7) {
			case 0x00:
				ReadCommand(cmInc, of_Ev | of_size, of_None, of_None, ctx);
				break;
			case 0x01:
				ReadCommand(cmDec, of_Ev | of_size, of_None, of_None, ctx);
				break;
			case 0x02:
				ReadCommand(cmCall, of_Edef | of_size, of_None, of_None, ctx);
				break;
			case 0x03:
				include_option(roFar);
				ReadCommand(cmCall, of_Mp | of_size, of_None, of_None, ctx);
				break;
			case 0x04:
				ReadCommand(cmJmp, of_Edef | of_size, of_None, of_None, ctx);
				break;
			case 0x05:
				include_option(roFar);
				ReadCommand(cmJmp, of_Mp | of_size, of_None, of_None, ctx);
				break;
			case 0x06:
				ReadCommand(cmPush, of_Edef | of_size, of_None, of_None, ctx);
				break;
			default:
				type_ = cmDB;
				break;
			}
			break;

		default:
			type_ = cmDB;
			break;
		}
	}

	if ((options() & roVexPrefix) && vex_operand_index) {
		vex_operand_ = (vex_operand_index & 3) | (operand_[0].size == osYMMWord ? 4 : 0) | (ctx.vex_registr << 4);
	}

	if (file.seh_handler_list())
		set_seh_handler(file.seh_handler_list()->GetHandlerByAddress(address_));

	for (i = 0; i < _countof(operand_); i++) {
		operand = &operand_[i];
		if (operand->type & otValue) {
			if (operand->is_large_value)
				operand->value += next_address();
			operand->fixup = file.fixup_list()->GetFixupByAddress(address() + operand->value_pos);

			if (file.relocation_list())
				operand->relocation = file.relocation_list()->GetRelocationByAddress(address() + operand->value_pos);
		}
	}

	original_dump_size_ = dump_size();

	return original_dump_size_;
}

void IntelCommand::ReadArray(IArchitecture& file, size_t len)
{
	type_ = cmDB;
	Read(file, len);
	original_dump_size_ = dump_size();
}

int32_t IntelCommand::ReadCompressedValue(IArchitecture& file)
{
	uint32_t res;
	uint8_t b = ReadByte(file);
	if ((b & 1) == 0)
		res = b >> 1;
	else if ((b & 2) == 0) {
		res = b >> 2;
		res |= ReadByte(file) << 6;
	}
	else if ((b & 4) == 0) {
		res = b >> 3;
		res |= ReadByte(file) << 5;
		res |= ReadByte(file) << 13;
	}
	else if ((b & 8) == 0) {
		res = b >> 4;
		res |= ReadByte(file) << 4;
		res |= ReadByte(file) << 12;
		res |= ReadByte(file) << 20;
	}
	else
		res = ReadDWord(file);

	Init(cmDC, IntelOperand(otValue, osDWord, 0, res));

	return res;
}

void IntelCommand::set_address(uint64_t address)
{
	address_ = address;

	if (type_ == cmJmp || type_ == cmCall || type_ == cmJmpWithFlag || type_ == cmLoop || type_ == cmLoope || type_ == cmLoopne || type_ == cmJCXZ) {
		if (operand_[0].type == otValue) {
			CompileToNative();
			return;
		}
	}

	if (size_ == osQWord) {
		for (size_t i = 0; i < _countof(operand_); i++) {
			IntelOperand* operand = &operand_[i];
			if (operand->type == otNone)
				break;

			if (operand->type == (otMemory | otValue) && operand->is_large_value)
				WriteDWord(operand->value_pos, static_cast<uint32_t>(operand->value - next_address()));
		}
	}
}

void IntelCommand::PushReg(size_t operand_index, uint8_t add_code, AsmContext& ctx)
{
	IntelOperand* operand = &operand_[operand_index];
	uint8_t registr = operand->registr;

	switch (operand->type) {
	case otRegistr:
		if (registr > 7) {
			registr &= 7;
			ctx.rex_prefix |= rexB;
		}
		else if (operand->size == osByte && registr > 3) {
			ctx.rex_prefix |= 0x40;
		}
		break;
	case otHiPartRegistr:
		registr |= 4;
		break;
	case otControlRegistr:
	case otDebugRegistr:
		if (registr > 7) {
			registr &= 7;
			ctx.rex_prefix |= rexB;
		}
		break;
	}
	PushByte(add_code | registr);
}

void IntelCommand::PushRegAndRM(size_t reg_operand_index, size_t rm_operand_index, AsmContext& ctx)
{
	IntelOperand* operand = &operand_[reg_operand_index];
	uint8_t registr = operand->registr;

	switch (operand->type) {
	case otRegistr:
		if (registr > 7) {
			registr &= 7;
			ctx.rex_prefix |= rexR;
		}
		else if (operand->size == osByte && registr > 3) {
			ctx.rex_prefix |= 0x40;
		}
		break;
	case otHiPartRegistr:
		registr |= 4;
		break;
	case otControlRegistr:
	case otDebugRegistr:
	case otXMMRegistr:
		if (registr > 7) {
			registr &= 7;
			ctx.rex_prefix |= rexR;
		}
		break;
	case otSegmentRegistr:
	case otMMXRegistr:
		break;
	default:
		throw std::runtime_error("Runtime error at PushRegAndRM: " + text());
	}

	PushRM(rm_operand_index, registr << 3, ctx);
}

void IntelCommand::PushRM(size_t operand_index, uint8_t add_code, AsmContext& ctx)
{
	IntelOperand* operand = &operand_[operand_index];
	uint8_t registr;

	switch (operand->type) {
	case otRegistr:
		registr = operand->registr;
		if (registr > 7) {
			registr &= 7;
			ctx.rex_prefix |= rexB;
		}
		else if (operand->size == osByte && registr > 3) {
			ctx.rex_prefix |= 0x40;
		}
		PushByte(add_code | 0xc0 | registr);
		break;
	case otDebugRegistr:
	case otControlRegistr:
	case otXMMRegistr:
		registr = operand->registr;
		if (registr > 7) {
			registr &= 7;
			ctx.rex_prefix |= rexB;
		}
		PushByte(add_code | 0xc0 | registr);
		break;
	case otHiPartRegistr:
		registr = operand->registr | 4;
		PushByte(add_code | 0xc0 | registr);
		break;
	default:
		if (operand->type & otMemory) {
			IntelOperand new_operand, * mem_operand = operand;
			if (((mem_operand->type & (otBaseRegistr | otRegistr | otValue)) == otRegistr && (mem_operand->registr & 7) == 5) ||
				((mem_operand->type & (otBaseRegistr | otRegistr | otValue)) == (otBaseRegistr | otRegistr) && (mem_operand->base_registr & 7) == 5)) {
				new_operand = *mem_operand;
				mem_operand = &new_operand;
				mem_operand->type |= otValue;
				mem_operand->value_size = osByte;
				mem_operand->value = 0;
			}

			if (mem_operand->type & otValue) {
				if ((mem_operand->type & (otRegistr | otBaseRegistr)) == 0) {
					add_code |= 0x5;
				}
				else {
					add_code |= (mem_operand->value_size == osByte) ? 0x40 : 0x80;
				}
			}

			if (mem_operand->type & otBaseRegistr) {
				PushByte(add_code | 0x4);

				if (mem_operand->type & otRegistr) {
					registr = mem_operand->registr;
					if (registr > 7) {
						registr &= 7;
						ctx.rex_prefix |= rexX;
					}
					add_code = (mem_operand->scale_registr << 6) | (registr << 3);
				}
				else {
					add_code = 0x20;
				}

				registr = mem_operand->base_registr;
				if (registr > 7) {
					registr &= 7;
					ctx.rex_prefix |= rexB;
				}

				PushByte(add_code | registr);
			}
			else if (mem_operand->type & otRegistr) {
				registr = mem_operand->registr;
				if (mem_operand->scale_registr) {
					if (registr > 7) {
						registr &= 7;
						ctx.rex_prefix |= rexX;
					}
					PushByte((add_code & ~0xc0) | 0x4);
					PushByte((mem_operand->scale_registr << 6) | (registr << 3) | 0x5);
				}
				else {
					if (registr > 7) {
						registr &= 7;
						ctx.rex_prefix |= rexB;
					}
					PushByte(add_code | registr);
					if (registr == 4)
						PushByte((registr << 3) | 0x4);
				}
			}
			else {
				PushByte(add_code);
			}

			if (mem_operand->type & otValue) {
				mem_operand->value_pos = static_cast<uint8_t>(dump_size());
				if (mem_operand->value_size == osByte && !mem_operand->is_large_value) {
					PushByte(static_cast<uint8_t>(mem_operand->value));
				}
				else {
					PushDWord(static_cast<uint32_t>(mem_operand->value));
				}
			}
		}
		else {
			throw std::runtime_error("Runtime error at PushRM: " + text());
		}
	}
}

void IntelCommand::PushBytePrefix(uint8_t prefix)
{
	PushByte(prefix);
	command_pos_ = dump_size();
}

void IntelCommand::PushWordPrefix()
{
	PushBytePrefix(0x66);
}

void IntelCommand::PushPrefix(AsmContext& ctx)
{
	switch (operand_[0].size) {
	case osWord:
		PushWordPrefix();
		break;
	case osQWord:
		ctx.rex_prefix = rexW;
		break;
	}
}

void IntelCommand::PushFlags(uint8_t add_code)
{
	uint8_t b;

	switch (flags_) {
	case fl_O:
		b = 0;
		break;
	case fl_C:
		b = 2;
		break;
	case fl_Z:
		b = 4;
		break;
	case fl_C | fl_Z:
		b = 6;
		break;
	case fl_S:
		b = 8;
		break;
	case fl_P:
		b = 0xa;
		break;
	case fl_S | fl_O:
		b = 0xc;
		break;
	case fl_Z | fl_S | fl_O:
		b = 0xe;
		break;
	default:
		b = 0;
	}

	if ((options() & roInverseFlag) != 0)
		b |= 1;

	PushByte(add_code | b);
}

void IntelCommand::CompileToNative()
{
	if (type() == cmDB)
		return;

	BaseCommand::clear();

	IntelOperand* operand, * operand1, * mem_operand;
	AsmContext ctx;
	uint8_t i;
	uint8_t b;
	IntelSegment segment;

	if (options() & roLockPrefix)
		PushByte(0xf0);

	switch (preffix_command_) {
	case cmRepne:
		PushByte(0xf2);
		break;
	case cmRep:
	case cmRepe:
		PushByte(0xf3);
		break;
	}

	if (base_segment_ != segDefault) {
		for (i = 0; i < _countof(operand_); i++) {
			operand = &operand_[i];
			if (operand->type & otMemory) {
				if (operand->type & otBaseRegistr) {
					b = operand->base_registr;
				}
				else if (operand->type & otRegistr) {
					b = operand->registr;
				}
				else {
					b = regEAX;
				}
				segment = (b == regEBP || b == regESP) ? segSS : segDS;
				if (segment != base_segment_) {
					switch (base_segment_) { //-V719
					case segES:
						PushByte(0x26);
						break;
					case segSS:
						PushByte(0x36);
						break;
					case segCS:
						PushByte(0x2e);
						break;
					case segDS:
						PushByte(0x3e);
						break;
					case segFS:
						PushByte(0x64);
						break;
					case segGS:
						PushByte(0x65);
						break;
					}
				}
			}
		}
	}

	command_pos_ = dump_size();
	ctx.rex_prefix = 0;
	switch (type()) {
	case cmDW:
		operand = &operand_[0];
		operand->value_pos = static_cast<uint8_t>(dump_size());
		PushWord(static_cast<uint16_t>(operand->value));
		break;

	case cmDD:
		operand = &operand_[0];
		operand->value_pos = static_cast<uint8_t>(dump_size());
		PushDWord(static_cast<uint32_t>(operand->value));
		break;

	case cmDQ:
		operand = &operand_[0];
		operand->value_pos = static_cast<uint8_t>(dump_size());
		PushQWord(operand->value);
		break;

	case cmUleb:
		break;

	case cmSleb:
		break;

	case cmDC:
		operand = &operand_[0];
		operand->value_pos = static_cast<uint8_t>(dump_size());
		if (options() & roFillNop) {
			PushByte(0x0f);
			PushDWord(static_cast<uint32_t>(operand->value));
		}
		else {
			uint32_t value = static_cast<uint32_t>(operand->value);
			if (value < 0x80) {
				PushByte(static_cast<uint8_t>((value << 1) + 0));
			}
			else if (value < 0x80 * 0x80) {
				PushByte(static_cast<uint8_t>((value << 2) + 1));
				PushByte(static_cast<uint8_t>(value >> 6));
			}
			else if (value < 0x80 * 0x80 * 0x80) {
				PushByte(static_cast<uint8_t>((value << 3) + 3));
				PushByte(static_cast<uint8_t>(value >> 5));
				PushByte(static_cast<uint8_t>(value >> 13));
			}
			else if (value < 0x80 * 0x80 * 0x80 * 0x80) {
				PushByte(static_cast<uint8_t>((value << 4) + 7));
				PushByte(static_cast<uint8_t>(value >> 4));
				PushByte(static_cast<uint8_t>(value >> 12));
				PushByte(static_cast<uint8_t>(value >> 20));
			}
			else {
				PushByte(0x0f);
				PushDWord(value);
			}
		}
		break;

	case cmPush:
		operand = &operand_[0];
		if (operand->size == osWord)
			PushWordPrefix();

		switch (operand->type) {
		case otRegistr:
			PushReg(0, 0x50, ctx);
			break;
		case otValue:
			if (operand->value_size == osByte) {
				PushByte(0x6a);
			}
			else {
				PushByte(0x68);
			}
			operand->value_pos = static_cast<uint8_t>(dump_size());
			switch (operand->value_size) {
			case osByte:
				PushByte(static_cast<uint8_t>(operand->value));
				break;
			case osWord:
				PushWord(static_cast<uint16_t>(operand->value));
				break;
			default:
				PushDWord(static_cast<uint32_t>(operand->value));
				break;
			}
			break;
		case otSegmentRegistr:
			switch (operand->registr) {
			case segES:
				if (size_ == osDWord)
					PushByte(0x06);
				break;
			case segCS:
				if (size_ == osDWord)
					PushByte(0x0e);
				break;
			case segSS:
				if (size_ == osDWord)
					PushByte(0x16);
				break;
			case segDS:
				if (size_ == osDWord)
					PushByte(0x1e);
				break;
			case segFS:
				PushByte(0x0f);
				PushByte(0xa0);
				break;
			case segGS:
				PushByte(0x0f);
				PushByte(0xa8);
				break;
			}
			break;
		default:
			if (operand->type & otMemory) {
				PushByte(0xff);
				PushRM(0, 0x30, ctx);
			}
		}
		break;

	case cmPop:
		operand = &operand_[0];
		if (operand->size == osWord)
			PushWordPrefix();

		switch (operand->type) {
		case otRegistr:
			PushReg(0, 0x58, ctx);
			break;
		case otSegmentRegistr:
			switch (operand->registr) {
			case segES:
				if (size_ == osDWord)
					PushByte(0x07);
				break;
			case segCS:
				if (size_ == osDWord)
					PushByte(0x0f);
				break;
			case segSS:
				if (size_ == osDWord)
					PushByte(0x17);
				break;
			case segDS:
				if (size_ == osDWord)
					PushByte(0x1f);
				break;
			case segFS:
				PushByte(0x0f);
				PushByte(0xa1);
				break;
			case segGS:
				PushByte(0x0f);
				PushByte(0xa9);
				break;
			}
			break;
		default:
			if (operand->type & otMemory) {
				PushByte(0x8f);
				PushRM(0, 0x00, ctx);
			}
		}
		break;

	case cmPusha:
		if (size_ == osDWord) {
			if (operand_[0].size == osWord)
				PushWordPrefix();
			PushByte(0x60);
		}
		break;

	case cmPopa:
		if (size_ == osDWord) {
			if (operand_[0].size == osWord)
				PushWordPrefix();
			PushByte(0x61);
		}
		break;

	case cmPushf:
		if (operand_[0].size == osWord)
			PushWordPrefix();
		PushByte(0x9c);
		break;

	case cmPopf:
		if (operand_[0].size == osWord)
			PushWordPrefix();
		PushByte(0x9d);
		break;

	case cmNop:
		PushByte(0x90);
		break;

	case cmPause:
		PushByte(0xf3);
		PushByte(0x90);
		break;

	case cmRdtsc:
		PushByte(0x0f);
		PushByte(0x31);
		break;

	case cmCpuid:
		PushByte(0x0f);
		PushByte(0xa2);
		break;

	case cmCmc:
		PushByte(0xf5);
		break;

	case cmClc:
		PushByte(0xf8);
		break;

	case cmStc:
		PushByte(0xf9);
		break;

	case cmCld:
		PushByte(0xfc);
		break;

	case cmStd:
		PushByte(0xfd);
		break;

	case cmSahf:
		PushByte(0x9e);
		break;

	case cmLahf:
		PushByte(0x9f);
		break;

	case cmCbw:
		PushByte(0x66);
		PushByte(0x98);
		break;

	case cmCwde:
		PushByte(0x98);
		break;

	case cmCdqe:
		if (size_ == osQWord) {
			PushByte(0x48);
			PushByte(0x98);
		}
		break;

	case cmCwd:
		PushByte(0x66);
		PushByte(0x99);
		break;

	case cmCdq:
		PushByte(0x99);
		break;

	case cmCqo:
		if (size_ == osQWord) {
			PushByte(0x48);
			PushByte(0x99);
		}
		break;

	case cmRet:
		operand = &operand_[0];
		b = (options() & roFar) ? 8 : 0;
		switch (operand->type) {
		case otNone:
			PushByte(0xc3 | b);
			break;
		case otValue:
			PushByte(0xc2 | b);
			PushWord(static_cast<uint16_t>(operand->value));
			break;
		}
		break;

	case cmIret:
		if (operand_[0].size == osWord)
			PushWordPrefix();
		PushByte(0xcf);
		break;

	case cmJmp:
		operand = &operand_[0];
		operand1 = &operand_[1];
		if (operand1->type == otValue) {
			PushByte(0xea);
			operand->value_pos = static_cast<uint8_t>(dump_size());
			PushDWord(static_cast<uint32_t>(operand->value));
			operand1->value_pos = static_cast<uint8_t>(dump_size());
			PushWord(static_cast<uint16_t>(operand1->value));
		}
		else if (options() & roFar) {
			PushByte(0xff);
			PushRM(0, 0x28, ctx);
		}
		else if (operand->type == otValue) {
			PushByte(0xe9);
			operand->value_pos = static_cast<uint8_t>(dump_size());
			PushDWord(static_cast<uint32_t>(operand->value - next_address() - 4));
		}
		else {
			PushByte(0xff);
			PushRM(0, 0x20, ctx);
		}
		break;

	case cmCall:
		operand = &operand_[0];
		operand1 = &operand_[1];
		if (operand1->type == otValue) {
			PushByte(0x9a);
			operand->value_pos = static_cast<uint8_t>(dump_size());
			PushDWord(static_cast<uint32_t>(operand->value));
			operand1->value_pos = static_cast<uint8_t>(dump_size());
			PushWord(static_cast<uint16_t>(operand1->value));
		}
		else if (options() & roFar) {
			PushByte(0xff);
			PushRM(0, 0x18, ctx);
		}
		else if (operand->type == otValue) {
			PushByte(0xe8);
			operand->value_pos = static_cast<uint8_t>(dump_size());
			PushDWord(static_cast<uint32_t>(operand->value - next_address() - 4));
		}
		else {
			PushByte(0xff);
			PushRM(0, 0x10, ctx);
		}
		break;

	case cmSyscall:
		PushByte(0x0f);
		PushByte(0x05);
		break;

	case cmSysenter:
		if (size_ == osDWord) {
			PushByte(0x0f);
			PushByte(0x34);
		}
		break;

	case cmSetXX:
		PushByte(0x0f);
		PushFlags(0x90);
		PushRM(0, 0, ctx);
		break;

	case cmJmpWithFlag:
		operand = &operand_[0];
		PushByte(0x0f);
		PushFlags(0x80);
		operand->value_pos = static_cast<uint8_t>(dump_size());
		PushDWord(static_cast<uint32_t>(operand->value - next_address() - 4));
		break;

	case cmLoopne:
		operand = &operand_[0];
		PushByte(0xe0);
		operand->value_pos = static_cast<uint8_t>(dump_size());
		PushByte(static_cast<uint8_t>(operand->value - next_address() - 1));
		break;

	case cmLoope:
		operand = &operand_[0];
		PushByte(0xe1);
		operand->value_pos = static_cast<uint8_t>(dump_size());
		PushByte(static_cast<uint8_t>(operand->value - next_address() - 1));
		break;

	case cmLoop:
		operand = &operand_[0];
		PushByte(0xe2);
		operand->value_pos = static_cast<uint8_t>(dump_size());
		PushByte(static_cast<uint8_t>(operand->value - next_address() - 1));
		break;

	case cmJCXZ:
		if (operand_[1].size == osWord)
			PushBytePrefix(0x67);
		operand = &operand_[0];
		PushByte(0xe3);
		operand->value_pos = static_cast<uint8_t>(dump_size());
		PushByte(static_cast<uint8_t>(operand->value - next_address() - 1));
		break;

	case cmMovs:
		operand = &operand_[0];
		PushPrefix(ctx);
		PushByte((operand->size == osByte) ? 0xa4 : 0xa5);
		break;

	case cmCmps:
		operand = &operand_[0];
		PushPrefix(ctx);
		PushByte((operand->size == osByte) ? 0xa6 : 0xa7);
		break;

	case cmStos:
		operand = &operand_[0];
		PushPrefix(ctx);
		PushByte((operand->size == osByte) ? 0xaa : 0xab);
		break;

	case cmLods:
		operand = &operand_[0];
		PushPrefix(ctx);
		PushByte((operand->size == osByte) ? 0xac : 0xad);
		break;

	case cmScas:
		operand = &operand_[0];
		PushPrefix(ctx);
		PushByte((operand->size == osByte) ? 0xae : 0xaf);
		break;

	case cmCmov:
		PushPrefix(ctx);
		PushByte(0x0f);
		PushFlags(0x40);
		PushRegAndRM(0, 1, ctx);
		break;

	case cmIn:
		operand = &operand_[0];
		PushByte(0xec | ((operand->size == osByte) ? 0 : 1));
		break;

	case cmInt:
		operand = &operand_[0];
		switch (operand->value) {
		case 0:
			PushByte(0xce);
			break;
		case 3:
			PushByte(0xcc);
			break;
		default:
			PushByte(0xcd);
			PushByte(static_cast<uint8_t>(operand->value));
			break;
		}
		break;

	case cmAdd: case cmOr: case cmAdc: case cmSbb: case cmAnd: case cmSub: case cmXor: case cmCmp:
		operand = &operand_[0];
		operand1 = &operand_[1];
		switch (type_) {
		case cmAdd: b = 0 << 3; break;
		case cmOr: b = 1 << 3; break;
		case cmAdc: b = 2 << 3; break;
		case cmSbb: b = 3 << 3; break;
		case cmAnd: b = 4 << 3; break;
		case cmSub: b = 5 << 3; break;
		case cmXor: b = 6 << 3; break;
		case cmCmp: b = 7 << 3; break;
		}
		PushPrefix(ctx);
		if (operand1->type == otValue) {
			i = (operand->size == osByte) ? 0 : 1;
			if (operand->type == otRegistr && operand->registr == regEAX && operand->size == operand1->value_size) {
				PushByte(b | 0x4 | i);
			}
			else {
				if (operand->size != osByte && operand1->value_size == osByte)
					i |= 2;
				PushByte(0x80 | i);
				PushRM(0, b, ctx);
			}

			operand1->value_pos = static_cast<uint8_t>(dump_size());
			switch (operand1->value_size) {
			case osByte:
				PushByte(static_cast<uint8_t>(operand1->value));
				break;
			case osWord:
				PushWord(static_cast<uint16_t>(operand1->value));
				break;
			default:
				PushDWord(static_cast<uint32_t>(operand1->value));
				break;
			}
		}
		else {
			i = (operand->type & otMemory) ? 0 : 1;
			PushByte(b | (i << 1) | ((operand->size == osByte) ? 0 : 1));
			PushRegAndRM(1 - i, i, ctx);
		}
		break;

	case cmTest:
		operand = &operand_[0];
		operand1 = &operand_[1];
		i = (operand->size == osByte) ? 0 : 1;
		PushPrefix(ctx);
		if (operand1->type == otValue) {
			if (operand->type == otRegistr && operand->registr == regEAX) {
				PushByte(0xa8 | i);
			}
			else {
				PushByte(0xf6 | i);
				PushRM(0, 0, ctx);
			}

			operand1->value_pos = static_cast<uint8_t>(dump_size());
			switch (operand1->value_size) {
			case osByte:
				PushByte(static_cast<uint8_t>(operand1->value));
				break;
			case osWord:
				PushWord(static_cast<uint16_t>(operand1->value));
				break;
			default:
				PushDWord(static_cast<uint32_t>(operand1->value));
				break;
			}
		}
		else {
			PushByte(0x84 | i);
			i = (operand->type & otMemory) ? 0 : 1;
			PushRegAndRM(1 - i, i, ctx);
		}
		break;

	case cmXchg:
		operand = &operand_[0];
		operand1 = &operand_[1];
		PushPrefix(ctx);
		if (operand->size != osByte && operand->type == otRegistr && operand1->type == otRegistr &&
			(operand->registr == regEAX || operand1->registr == regEAX)) {
			i = (operand1->registr == regEAX) ? 0 : 1;
			PushReg(i, 0x90, ctx);
		}
		else {
			i = (operand->type & otMemory) ? 0 : 1;
			PushByte(0x86 | ((operand->size == osByte) ? 0 : 1));
			PushRegAndRM(1 - i, i, ctx);
		}
		break;

	case cmXadd:
		operand = &operand_[0];
		PushPrefix(ctx);
		PushByte(0x0f);
		PushByte(0xc0 | ((operand->size == osByte) ? 0 : 1));
		PushRegAndRM(1, 0, ctx);
		break;

	case cmLea:
		PushPrefix(ctx);
		PushByte(0x8d);
		PushRegAndRM(0, 1, ctx);
		break;

	case cmNot: case cmNeg: case cmMul: case cmDiv: case cmIdiv:
		operand = &operand_[0];
		switch (type_) {
		case cmNot: b = 2 << 3; break;
		case cmNeg: b = 3 << 3; break;
		case cmMul: b = 4 << 3; break;
			//unreachable case cmImul: b = 5 << 3; break;
		case cmDiv: b = 6 << 3; break;
		case cmIdiv: b = 7 << 3; break;
		}
		i = (operand->size == osByte) ? 0 : 1;
		PushPrefix(ctx);
		PushByte(0xf6 | i);
		PushRM(0, b, ctx);
		break;

	case cmImul:
		PushPrefix(ctx);
		if (operand_[2].type != otNone) {
			operand = &operand_[2];
			i = (operand->value_size == osByte) ? 1 : 0;
			PushByte(0x69 | (i << 1));
			PushRegAndRM(0, 1, ctx);
			switch (operand->value_size) {
			case osByte:
				PushByte(static_cast<uint8_t>(operand->value));
				break;
			case osWord:
				PushWord(static_cast<uint16_t>(operand->value));
				break;
			default:
				PushDWord(static_cast<uint32_t>(operand->value));
				break;
			}
		}
		else if (operand_[1].type != otNone) {
			PushByte(0x0f);
			PushByte(0xaf);
			PushRegAndRM(0, 1, ctx);
		}
		else {
			operand = &operand_[0];
			i = (operand->size == osByte) ? 0 : 1;
			PushByte(0xf6 | i);
			PushRM(0, 0x28, ctx);
		}
		break;

	case cmInc: case cmDec:
		operand = &operand_[0];
		b = (type_ == cmInc) ? 0 : 8;
		PushPrefix(ctx);
		if (operand->type == otRegistr && size_ != osQWord && size_ == operand->size) {
			PushReg(0, 0x40 | b, ctx);
		}
		else {
			i = (operand->size == osByte) ? 0 : 1;
			PushByte(0xfe | i);
			PushRM(0, b, ctx);
		}
		break;

	case cmShl: case cmShr: case cmRol: case cmRor: case cmRcl: case cmRcr: case cmSal: case cmSar:
		operand = &operand_[0];
		operand1 = &operand_[1];
		i = (operand->size == osByte) ? 0 : 1;
		switch (type_) {
		case cmRol: b = 0 << 3; break;
		case cmRor: b = 1 << 3; break;
		case cmRcl: b = 2 << 3; break;
		case cmRcr: b = 3 << 3; break;
		case cmShl: b = 4 << 3; break;
		case cmShr: b = 5 << 3; break;
		case cmSal: b = 6 << 3; break;
		case cmSar: b = 7 << 3; break;
		}
		PushPrefix(ctx);
		if (operand1->type == otRegistr && operand1->registr == regECX && operand1->size == osByte) {
			PushByte(0xd2 | i);
			PushRM(0, b, ctx);
		}
		else if (operand1->type == otValue) {
			if (operand1->value == 1) {
				PushByte(0xd0 | i);
				PushRM(0, b, ctx);
			}
			else {
				PushByte(0xc0 | i);
				PushRM(0, b, ctx);
				PushByte(static_cast<uint8_t>(operand1->value));
			}
		}
		break;

	case cmShld: case cmShrd:
		operand = &operand_[2];
		PushPrefix(ctx);
		PushByte(0x0f);
		PushByte((type_ == cmShld ? 0xa4 : 0xac) | ((operand->type == otValue) ? 0 : 1));
		PushRegAndRM(1, 0, ctx);
		if (operand->type == otValue)
			PushByte(static_cast<uint8_t>(operand->value));
		break;

	case cmBsr:
		PushPrefix(ctx);
		PushByte(0x0f);
		PushByte(0xbd);
		PushRegAndRM(0, 1, ctx);
		break;

	case cmBsf:
		PushPrefix(ctx);
		PushByte(0x0f);
		PushByte(0xbc);
		PushRegAndRM(0, 1, ctx);
		break;

	case cmBt: case cmBts: case cmBtr: case cmBtc:
		//operand = &operand_[0];
		operand1 = &operand_[1];
		PushPrefix(ctx);
		PushByte(0x0f);
		if (operand1->type == otValue) {
			PushByte(0xba);
			switch (type_) {
			case cmBt: b = 4 << 3; break;
			case cmBts: b = 5 << 3; break;
			case cmBtr: b = 6 << 3; break;
			case cmBtc: b = 7 << 3; break;
			}
			PushRM(0, b, ctx);
			PushByte(static_cast<uint8_t>(operand1->value));
		}
		else {
			switch (type_) {
			case cmBt: b = 0 << 3; break;
			case cmBts: b = 1 << 3; break;
			case cmBtr: b = 2 << 3; break;
			case cmBtc: b = 3 << 3; break;
			}
			PushByte(0xa3 | b);
			PushRegAndRM(1, 0, ctx);
		}
		break;

	case cmMovups: case cmMovupd: case cmMovsd: case cmMovss:
		operand = &operand_[0];
		i = (operand->type & otMemory) ? 0 : 1;
		switch (type_) {
		case cmMovupd: PushBytePrefix(0x66); break;
		case cmMovsd: PushBytePrefix(0xf2); break;
		case cmMovss: PushBytePrefix(0xf3); break;
		}
		PushByte(0x0f);
		PushByte(0x10 | (1 - i));
		PushRegAndRM(1 - i, i, ctx);
		break;

	case cmMovaps: case cmMovapd:
		operand = &operand_[0];
		i = (operand->type & otMemory) ? 0 : 1;
		switch (type_) {
		case cmMovapd: PushBytePrefix(0x66); break;
		}
		PushByte(0x0f);
		PushByte(0x28 | (1 - i));
		PushRegAndRM(1 - i, i, ctx);
		break;

	case cmMovsx:
		operand1 = &operand_[1];
		if (operand1->size < osDWord) {
			PushPrefix(ctx);
			PushByte(0x0f);
			PushByte(0xbe | ((operand1->size == osWord) ? 1 : 0));
			PushRegAndRM(0, 1, ctx);
		}
		break;

	case cmMovsxd:
		if (size_ == osQWord) {
			PushPrefix(ctx);
			PushByte(0x63);
			PushRegAndRM(0, 1, ctx);
		}
		break;

	case cmMovzx:
		operand1 = &operand_[1];
		if (operand1->size < osDWord) {
			PushPrefix(ctx);
			PushByte(0x0f);
			PushByte(0xb6 | ((operand1->size == osWord) ? 1 : 0));
			PushRegAndRM(0, 1, ctx);
		}
		break;

	case cmMov:
		operand = &operand_[0];
		operand1 = &operand_[1];
		if (operand1->type == otValue) {
			PushPrefix(ctx);
			i = (operand->size == osByte) ? 0 : 1;
			if (operand->type == otRegistr && operand1->value_size == operand->size) {
				PushReg(0, static_cast<uint8_t>(0xb0 | (i << 3)), ctx);
			}
			else {
				PushByte(0xc6 | i);
				PushRM(0, 0, ctx);
			}
			operand1->value_pos = static_cast<uint8_t>(dump_size());
			switch (operand1->value_size) {
			case osByte:
				PushByte(static_cast<uint8_t>(operand1->value));
				break;
			case osWord:
				PushWord(static_cast<uint16_t>(operand1->value));
				break;
			case osDWord:
				PushDWord(static_cast<uint32_t>(operand1->value));
				break;
			case osQWord:
				PushQWord(operand1->value);
				break;
			}
		}
		else if ((operand->type | operand1->type) & otControlRegistr) {
			i = (operand->type == otControlRegistr) ? 1 : 0;
			PushByte(0x0f);
			PushByte(0x20 | (i << 1));
			PushRegAndRM(1 - i, i, ctx);
		}
		else if ((operand->type | operand1->type) & otDebugRegistr) {
			i = (operand->type == otDebugRegistr) ? 1 : 0;
			PushByte(0x0f);
			PushByte(0x21 | (i << 1));
			PushRegAndRM(1 - i, i, ctx);
		}
		else if ((operand->type | operand1->type) & otSegmentRegistr) {
			i = (operand->type == otSegmentRegistr) ? 1 : 0;
			if (operand->size == osWord)
				PushWordPrefix();
			PushByte(0x8c | (i << 1));
			PushRegAndRM(1 - i, i, ctx);
		}
		else {
			i = (operand->type & otMemory) ? 0 : 1;
			PushPrefix(ctx);
			operand = &operand_[1 - i];
			mem_operand = &operand_[i];
			if (operand->type == otRegistr && operand->registr == regEAX && mem_operand->type == (otValue | otMemory) && !mem_operand->is_large_value) {
				PushByte(0xa1 | ((1 - i) << 1));
				mem_operand->value_pos = static_cast<uint8_t>(dump_size());
				if (size_ == osDWord) {
					PushDWord(static_cast<uint32_t>(mem_operand->value));
				}
				else {
					PushQWord(mem_operand->value);
				}
			}
			else {
				PushByte(0x88 | (i << 1) | ((operand->size == osByte) ? 0 : 1));
				PushRegAndRM(1 - i, i, ctx);
			}
		}
		break;

	case cmMovd:
		operand = &operand_[0];
		operand1 = &operand_[1];
		if ((operand->type | operand1->type) & otXMMRegistr) {
			i = (operand->type == otXMMRegistr) ? 1 : 0;
			PushBytePrefix(0x66);
			PushByte(0x0f);
			PushByte(i ? 0x6e : 0x7e);
			PushRegAndRM(1 - i, i, ctx);
		}
		else if ((operand->type | operand1->type) & otMMXRegistr) {
			i = (operand->type == otMMXRegistr) ? 1 : 0;
			PushByte(0x0f);
			PushByte(i ? 0x6e : 0x7e);
			PushRegAndRM(1 - i, i, ctx);
		}
		break;

	case cmMovdqa:
		operand = &operand_[0];
		i = (operand->type == otXMMRegistr) ? 1 : 0;
		PushBytePrefix(0x66);
		PushByte(0x0f);
		PushByte(i ? 0x6f : 0x7f);
		PushRegAndRM(1 - i, i, ctx);
		break;

	case cmMovq:
		operand = &operand_[0];
		operand1 = &operand_[1];
		i = (operand->type & otMemory) ? 0 : 1;
		if ((operand->type | operand1->type) & otXMMRegistr) {
			PushBytePrefix(i ? 0xf3 : 0x66);
			PushByte(0x0f);
			PushByte(i ? 0x7e : 0xd6);
			PushRegAndRM(1 - i, i, ctx);
		}
		else if ((operand->type | operand1->type) & otMMXRegistr) {
			PushByte(0x0f);
			PushByte(i ? 0x6f : 0x7f);
			PushRegAndRM(1 - i, i, ctx);
		}
		break;

	case cmMovdqu:
		operand = &operand_[0];
		i = (operand->type & otMemory) ? 0 : 1;
		PushBytePrefix(0xf3);
		PushByte(0x0f);
		PushByte(i ? 0x6f : 0x7f);
		PushRegAndRM(1 - i, i, ctx);
		break;

	case cmPslldq:
		PushBytePrefix(0x66);
		PushByte(0x0f);
		PushByte(0x73);
		PushReg(0, 0xc0 | (7 << 3), ctx);
		PushByte(static_cast<uint8_t>(operand_[1].value));
		break;

	case cmPunpcklqdq:
		PushBytePrefix(0x66);
		PushByte(0x0f);
		PushByte(0x6c);
		PushRegAndRM(0, 1, ctx);
		break;

	case cmPunpckhqdq:
		PushBytePrefix(0x66);
		PushByte(0x0f);
		PushByte(0x6d);
		PushRegAndRM(0, 1, ctx);
		break;

	case cmPsrld:
		operand = &operand_[0];
		operand1 = &operand_[1];
		if ((operand->type | operand1->type) & otXMMRegistr)
			PushBytePrefix(0x66);
		if (operand1->type == otValue) {
			PushByte(0x0f);
			PushByte(0x72);
			PushReg(0, 0xc0 | (2 << 3), ctx);
			PushByte(static_cast<uint8_t>(operand_[1].value));
		}
		else {
			PushByte(0x0f);
			PushByte(0xd2);
			PushRegAndRM(0, 1, ctx);
		}
		break;

	case cmPsrlq:
		operand = &operand_[0];
		operand1 = &operand_[1];
		if ((operand->type | operand1->type) & otXMMRegistr)
			PushBytePrefix(0x66);
		if (operand1->type == otValue) {
			PushByte(0x0f);
			PushByte(0x73);
			PushReg(0, 0xc0 | (2 << 3), ctx);
			PushByte(static_cast<uint8_t>(operand_[1].value));
		}
		else {
			PushByte(0x0f);
			PushByte(0xd3);
			PushRegAndRM(0, 1, ctx);
		}
		break;

	case cmPaddq:
		operand = &operand_[0];
		operand1 = &operand_[1];
		if ((operand->type | operand1->type) & otXMMRegistr)
			PushBytePrefix(0x66);
		PushByte(0x0f);
		PushByte(0xd4);
		PushRegAndRM(0, 1, ctx);
		break;

	case cmPsubq:
		operand = &operand_[0];
		operand1 = &operand_[1];
		if ((operand->type | operand1->type) & otXMMRegistr)
			PushBytePrefix(0x66);
		PushByte(0x0f);
		PushByte(0xfb);
		PushRegAndRM(0, 1, ctx);
		break;

	case cmPand:
		operand = &operand_[0];
		operand1 = &operand_[1];
		if ((operand->type | operand1->type) & otXMMRegistr)
			PushBytePrefix(0x66);
		PushByte(0x0f);
		PushByte(0xdb);
		PushRegAndRM(0, 1, ctx);
		break;

	case cmPinsrw:
		operand = &operand_[0];
		operand1 = &operand_[1];
		if ((operand->type | operand1->type) & otXMMRegistr)
			PushBytePrefix(0x66);
		PushByte(0x0f);
		PushByte(0xc4);
		PushRegAndRM(0, 1, ctx);
		PushByte(static_cast<uint8_t>(operand_[2].value));
		break;

	case cmPextrw:
		operand = &operand_[0];
		operand1 = &operand_[1];
		if ((operand->type | operand1->type) & otXMMRegistr)
			PushBytePrefix(0x66);
		PushByte(0x0f);
		PushByte(0xc5);
		PushRegAndRM(0, 1, ctx);
		PushByte(static_cast<uint8_t>(operand_[2].value));
		break;

	case cmShufpd:
		operand = &operand_[0];
		operand1 = &operand_[1];
		PushBytePrefix(0x66);
		PushByte(0x0f);
		PushByte(0xc6);
		PushRegAndRM(0, 1, ctx);
		PushByte(static_cast<uint8_t>(operand_[2].value));
		break;

	case cmPshufd:
		PushBytePrefix(0x66);
		PushByte(0x0f);
		PushByte(0x70);
		PushRegAndRM(0, 1, ctx);
		PushByte(static_cast<uint8_t>(operand_[2].value));
		break;

	case cmPshuflw:
		PushBytePrefix(0xf2);
		PushByte(0x0f);
		PushByte(0x70);
		PushRegAndRM(0, 1, ctx);
		PushByte(static_cast<uint8_t>(operand_[2].value));
		break;

	case cmPaddd:
		operand = &operand_[0];
		operand1 = &operand_[1];
		if ((operand->type | operand1->type) & otXMMRegistr)
			PushBytePrefix(0x66);
		PushByte(0x0f);
		PushByte(0xfe);
		PushRegAndRM(0, 1, ctx);
		break;

	case cmPsubd:
		operand = &operand_[0];
		operand1 = &operand_[1];
		if ((operand->type | operand1->type) & otXMMRegistr)
			PushBytePrefix(0x66);
		PushByte(0x0f);
		PushByte(0xfa);
		PushRegAndRM(0, 1, ctx);
		break;

	case cmPunpcklbw:
		operand = &operand_[0];
		operand1 = &operand_[1];
		if ((operand->type | operand1->type) & otXMMRegistr)
			PushBytePrefix(0x66);
		PushByte(0x0f);
		PushByte(0x60);
		PushRegAndRM(0, 1, ctx);
		break;

	case cmPunpcklwd:
		operand = &operand_[0];
		operand1 = &operand_[1];
		if ((operand->type | operand1->type) & otXMMRegistr)
			PushBytePrefix(0x66);
		PushByte(0x0f);
		PushByte(0x61);
		PushRegAndRM(0, 1, ctx);
		break;

	case cmPunpckldq:
		operand = &operand_[0];
		operand1 = &operand_[1];
		if ((operand->type | operand1->type) & otXMMRegistr)
			PushBytePrefix(0x66);
		PushByte(0x0f);
		PushByte(0x62);
		PushRegAndRM(0, 1, ctx);
		break;

	case cmMovlpd:
		operand = &operand_[1];
		if (operand->type == otXMMRegistr) {
			PushBytePrefix(0x66);
			PushByte(0x0f);
			PushByte(0x13);
			PushRegAndRM(1, 0, ctx);
		}
		break;

	case cmMovlhps:
		PushByte(0x0f);
		PushByte(0x16);
		PushRegAndRM(0, 1, ctx);
		break;

	case cmMovhlps:
		PushByte(0x0f);
		PushByte(0x12);
		PushRegAndRM(0, 1, ctx);
		break;

	case cmFld:
		operand = &operand_[0];
		if (operand->type == otFPURegistr) {
			PushByte(0xd9);
			PushReg(0, 0xc0, ctx);
		}
		else {
			switch (operand->size) {
			case osDWord:
				PushByte(0xd9);
				PushRM(0, 0, ctx);
				break;
			case osQWord:
				PushByte(0xdd);
				PushRM(0, 0, ctx);
				break;
			case osTByte:
				PushByte(0xdb);
				PushRM(0, 5 << 3, ctx);
			}
		}
		break;

	case cmFild:
		operand = &operand_[0];
		switch (operand->size) {
		case osWord:
			PushByte(0xdf);
			PushRM(0, 0, ctx);
			break;
		case osDWord:
			PushByte(0xdb);
			PushRM(0, 0, ctx);
			break;
		case osQWord:
			PushByte(0xdf);
			PushRM(0, 5 << 3, ctx);
			break;
		}
		break;

	case cmFadd:
		operand = &operand_[0];
		if (operand->type == otFPURegistr) {
			if (operand->registr == 0) {
				PushByte(0xd8);
				PushRM(1, 0xc0, ctx);
			}
			else {
				PushByte(0xdc);
				PushRM(0, 0xc0, ctx);
			}
		}
		else {
			switch (operand->size) {
			case osDWord:
				PushByte(0xd8);
				PushRM(0, 0, ctx);
				break;
			case osQWord:
				PushByte(0xdc);
				PushRM(0, 0, ctx);
				break;
			}
		}
		break;

	case cmFsub:
		operand = &operand_[0];
		if (operand->type == otFPURegistr) {
			if (operand->registr == 0) {
				PushByte(0xd8);
				PushRM(1, 0xc0 | (4 << 3), ctx);
			}
			else {
				PushByte(0xdc);
				PushRM(0, 0xc0 | (5 << 3), ctx);
			}
		}
		else {
			switch (operand->size) {
			case osDWord:
				PushByte(0xd8);
				PushRM(0, 4 << 3, ctx);
				break;
			case osQWord:
				PushByte(0xdc);
				PushRM(0, 4 << 3, ctx);
				break;
			}
		}
		break;

	case cmFsubr:
		operand = &operand_[0];
		if (operand->type == otFPURegistr) {
			if (operand->registr == 0) {
				PushByte(0xd8);
				PushRM(1, 0xc0 | (5 << 3), ctx);
			}
			else {
				PushByte(0xdc);
				PushRM(0, 0xc0 | (4 << 3), ctx);
			}
		}
		else {
			switch (operand->size) {
			case osDWord:
				PushByte(0xd8);
				PushRM(0, 5 << 3, ctx);
				break;
			case osQWord:
				PushByte(0xdc);
				PushRM(0, 5 << 3, ctx);
				break;
			}
		}
		break;

	case cmFst:
		operand = &operand_[0];
		if (operand->type == otFPURegistr) {
			PushByte(0xdd);
			PushRM(0, 0xc0 | (2 << 3), ctx);
		}
		else {
			switch (operand->size) {
			case osDWord:
				PushByte(0xd9);
				PushRM(0, 2 << 3, ctx);
				break;
			case osQWord:
				PushByte(0xdd);
				PushRM(0, 2 << 3, ctx);
				break;
			}
		}
		break;

	case cmFstp:
		operand = &operand_[0];
		if (operand->type == otFPURegistr) {
			PushByte(0xdd);
			PushRM(0, 0xc0 | (3 << 3), ctx);
		}
		else {
			switch (operand->size) {
			case osDWord:
				PushByte(0xd9);
				PushRM(0, 3 << 3, ctx);
				break;
			case osQWord:
				PushByte(0xdd);
				PushRM(0, 3 << 3, ctx);
				break;
			case osTByte:
				PushByte(0xdb);
				PushRM(0, 7 << 3, ctx);
				break;
			}
		}
		break;

	case cmFist:
		operand = &operand_[0];
		switch (operand->size) {
		case osWord:
			PushByte(0xdf);
			PushRM(0, 2 << 3, ctx);
			break;
		case osDWord:
			PushByte(0xdb);
			PushRM(0, 2 << 3, ctx);
			break;
		}
		break;

	case cmFistp:
		operand = &operand_[0];
		switch (operand->size) {
		case osWord:
			PushByte(0xdf);
			PushRM(0, 3 << 3, ctx);
			break;
		case osDWord:
			PushByte(0xdb);
			PushRM(0, 3 << 3, ctx);
			break;
		case osQWord:
			PushByte(0xdf);
			PushRM(0, 7 << 3, ctx);
			break;
		}
		break;

	case cmFisub:
		operand = &operand_[0];
		switch (operand->size) {
		case osWord:
			PushByte(0xde);
			PushRM(0, 4 << 3, ctx);
			break;
		case osDWord:
			PushByte(0xda);
			PushRM(0, 4 << 3, ctx);
			break;
		}
		break;

	case cmFdiv:
		operand = &operand_[0];
		if (operand->type == otFPURegistr) {
			if (operand->registr == 0) {
				PushByte(0xd8);
				PushRM(1, 0xc0 | (6 << 3), ctx);
			}
			else {
				PushByte(0xdc);
				PushRM(0, 0xc0 | (7 << 3), ctx);
			}
		}
		else {
			switch (operand->size) {
			case osDWord:
				PushByte(0xd8);
				PushRM(0, 6 << 3, ctx);
				break;
			case osQWord:
				PushByte(0xdc);
				PushRM(0, 6 << 3, ctx);
				break;
			}
		}
		break;

	case cmFmul:
		operand = &operand_[0];
		if (operand->type == otFPURegistr) {
			if (operand->registr == 0) {
				PushByte(0xd8);
				PushRM(1, 0xc0 | (1 << 3), ctx);
			}
			else {
				PushByte(0xdc);
				PushRM(0, 0xc0 | (1 << 3), ctx);
			}
		}
		else {
			switch (operand->size) {
			case osDWord:
				PushByte(0xd8);
				PushRM(0, 1 << 3, ctx);
				break;
			case osQWord:
				PushByte(0xdc);
				PushRM(0, 1 << 3, ctx);
				break;
			}
		}
		break;

	case cmFcomp:
		operand = &operand_[0];
		if (operand->type == otFPURegistr) {
			PushByte(0xd8);
			PushRM(0, 0xc0 | (3 << 3), ctx);
		}
		else {
			switch (operand->size) {
			case osDWord:
				PushByte(0xd8);
				PushRM(0, 3 << 3, ctx);
				break;
			case osQWord:
				PushByte(0xdc);
				PushRM(0, 3 << 3, ctx);
				break;
			}
		}
		break;

	case cmFnstcw:
		PushByte(0xd9);
		PushRM(0, 7 << 3, ctx);
		break;

	case cmFstcw:
		PushByte(0x9b);
		PushByte(0xd9);
		PushRM(0, 7 << 3, ctx);
		break;

	case cmFnstsw:
		PushByte(0xdd);
		PushRM(0, 7 << 3, ctx);
		break;

	case cmFstsw:
		PushByte(0x9b);
		PushByte(0xdd);
		PushRM(0, 7 << 3, ctx);
		break;

	case cmFldcw:
		PushByte(0xd9);
		PushRM(0, 5 << 3, ctx);
		break;

	case cmWait:
		PushByte(0x9b);
		break;

	case cmFchs:
		PushByte(0xd9);
		PushByte(0xe0);
		break;

	case cmFsqrt:
		PushByte(0xd9);
		PushByte(0xfa);
		break;

	case cmF2xm1:
		PushByte(0xd9);
		PushByte(0xf0);
		break;

	case cmFabs:
		PushByte(0xd9);
		PushByte(0xe1);
		break;

	case cmFclex:
		PushByte(0x9b);
		PushByte(0xdb);
		PushByte(0xe2);
		break;

	case cmFcos:
		PushByte(0xd9);
		PushByte(0xff);
		break;

	case cmFdecstp:
		PushByte(0xd9);
		PushByte(0xf6);
		break;

	case cmFincstp:
		PushByte(0xd9);
		PushByte(0xf7);
		break;

	case cmFinit:
		PushByte(0x9b);
		PushByte(0xdb);
		PushByte(0xe3);
		break;

	case cmFldln2:
		PushByte(0xd9);
		PushByte(0xed);
		break;

	case cmFldz:
		PushByte(0xd9);
		PushByte(0xee);
		break;

	case cmFld1:
		PushByte(0xd9);
		PushByte(0xe8);
		break;

	case cmFldpi:
		PushByte(0xd9);
		PushByte(0xeb);
		break;

	case cmFpatan:
		PushByte(0xd9);
		PushByte(0xf3);
		break;

	case cmFprem:
		PushByte(0xd9);
		PushByte(0xf8);
		break;

	case cmFprem1:
		PushByte(0xd9);
		PushByte(0xf5);
		break;

	case cmFptan:
		PushByte(0xd9);
		PushByte(0xf2);
		break;

	case cmFrndint:
		PushByte(0xd9);
		PushByte(0xfc);
		break;

	case cmFsin:
		PushByte(0xd9);
		PushByte(0xfe);
		break;

	case cmFtst:
		PushByte(0xd9);
		PushByte(0xe4);
		break;

	case cmFyl2x:
		PushByte(0xd9);
		PushByte(0xf1);
		break;

	case cmFldlg2:
		PushByte(0xd9);
		PushByte(0xec);
		break;

	case cmBswap:
		operand = &operand_[0];
		if (operand->type == otRegistr) {
			PushPrefix(ctx);
			PushByte(0x0f);
			PushReg(0, 0xc8, ctx);
		}
		break;

	case cmUd2:
		PushByte(0x0f);
		PushByte(0x0b);
		break;

	case cmPxor:
		operand = &operand_[0];
		if (operand->type == otMMXRegistr) {
			PushByte(0x0f);
			PushByte(0xef);
			PushRegAndRM(0, 1, ctx);
		}
		else if (operand->type == otXMMRegistr) {
			PushByte(0x66);
			PushByte(0x0f);
			PushByte(0xef);
			PushRegAndRM(0, 1, ctx);
		}
		break;

	case cmXorps:
		operand = &operand_[0];
		if (operand->type == otXMMRegistr) {
			PushByte(0x0f);
			PushByte(0x57);
			PushRegAndRM(0, 1, ctx);
		}
		break;

	case cmCrc:
		PushByte(0xcc);
		break;
	}

	if (ctx.rex_prefix) {
		if (size_ == osQWord) {
			InsertByte(command_pos_, 0x40 | ctx.rex_prefix);
			command_pos_++;
			for (i = 0; i < _countof(operand_); i++) {
				operand = &operand_[i];
				if (operand->type == otNone)
					break;
				if (operand->type & otValue)
					operand->value_pos++;
			}
		}
		else {
			// 32-bit commands can not have REX preffix
			command_pos_ = dump_size();
		}
	}

	if (command_pos_ == dump_size())
		throw std::runtime_error("Runtime error at CompileToNative: " + text());

	for (i = 0; i < _countof(operand_); i++) {
		operand = &operand_[i];
		if (operand->is_large_value)
			WriteDWord(operand->value_pos, static_cast<uint32_t>(operand->value - next_address()));
	}

	if (options() & roFillNop) {
		for (size_t j = dump_size(); j < original_dump_size_; j++) {
			PushByte(0x90);
		}
	}
}

void IntelCommand::set_operand_value(size_t operand_index, uint64_t value)
{
	operand_[operand_index].value = value;
}

void IntelCommand::set_operand_fixup(size_t operand_index, IFixup* fixup)
{
	operand_[operand_index].fixup = fixup;
}

void IntelCommand::set_operand_relocation(size_t operand_index, IRelocation* relocation)
{
	operand_[operand_index].relocation = relocation;
}

void IntelCommand::set_operand_scale(size_t operand_index, uint8_t value)
{
	operand_[operand_index].scale_registr = value;
}

void IntelCommand::set_link_value(size_t link_index, uint64_t value)
{
	IntelVMCommand* vm_command = vm_links_[link_index];
	vm_command->set_value(value);
	vm_command->Compile();
}

void IntelCommand::set_jmp_value(size_t link_index, uint64_t value)
{
	IntelVMCommand* vm_command = jmp_links_[link_index];
	vm_command->set_value(value);
	vm_command->Compile();
}

void IntelCommand::ReadFromBuffer(Buffer& buffer, IArchitecture& file)
{
	uint8_t b;
	uint16_t opt;
	size_t i, j, r;
	uint32_t dw;
	uint64_t add_address = file.image_base();

	r = buffer.ReadByte();
	address_ = buffer.ReadDWord() + add_address;
	type_ = static_cast<IntelCommandType>(buffer.ReadWord());
	BaseCommand::ReadFromBuffer(buffer, file);

	if (r & 0x8)
		preffix_command_ = static_cast<IntelCommandType>(buffer.ReadWord());

	original_dump_size_ = (r & 0x10) ? buffer.ReadWord() : buffer.ReadByte();

	if (r & 0x40)
		base_segment_ = static_cast<IntelSegment>(buffer.ReadByte());

	if (r & 0x80)
		flags_ = buffer.ReadWord();

	if (type_ == cmDB) {
		for (i = 0; i < original_dump_size_; i++) {
			PushByte(buffer.ReadByte());
		}
	}
	else {
		for (i = 0; i < original_dump_size_; i++) {
			PushByte(0);
		}
		for (j = 0; j < (r & 3); j++) {
			IntelOperand* operand = &operand_[j];
			operand->size = static_cast<OperandSize>(buffer.ReadByte());
			opt = buffer.ReadWord();
			operand->type = opt & 0xfff;

			if (operand->type & (otRegistr | otSegmentRegistr | otControlRegistr | otDebugRegistr | otFPURegistr | otHiPartRegistr | otMMXRegistr | otXMMRegistr))
				operand->registr = buffer.ReadByte();

			if (operand->type & otBaseRegistr)
				operand->base_registr = buffer.ReadByte();

			if (operand->type & otValue) {
				operand->value_size = static_cast<OperandSize>(buffer.ReadByte());
				if (opt & 0x9000) {
					dw = buffer.ReadDWord();
					operand->value = dw + add_address;
				}
				else {
					switch (operand->value_size) {
					case osByte:
						operand->value = ByteToInt64(buffer.ReadByte());
						break;
					case osWord:
						operand->value = WordToInt64(buffer.ReadWord());
						break;
					case osDWord:
						operand->value = DWordToInt64(buffer.ReadDWord());
						break;
					case osQWord:
						operand->value = buffer.ReadQWord();
						break;
					}
				}

				if (opt & 0x8000) {
					b = buffer.ReadByte();
					if (b == 1) {
						operand->fixup = NEED_FIXUP;
					}
					else if (b == 2) {
						operand->is_large_value = true;
					}
				}
			}

			if (operand->type & otMemory) {
				if (opt & 0x4000)
					operand->scale_registr = buffer.ReadByte();
				operand->address_size = (opt & 0x2000) ? static_cast<OperandSize>(buffer.ReadByte()) : size_;
			}
		}
	}
}

void IntelCommand::WriteToFile(IArchitecture& file)
{
	for (size_t i = 0; i < _countof(operand_); i++) {
		IntelOperand* operand = &operand_[i];
		if (operand->type == otNone)
			break;

		if (operand->type & otValue) {
			if (operand->fixup) {
				if (operand->fixup == NEED_FIXUP) {
					ISection* segment = file.segment_list()->GetSectionByAddress(address_);
					operand->fixup = file.fixup_list()->AddDefault(file.cpu_address_size(), segment && (segment->memory_type() & mtExecutable) != 0);
				}
				operand->fixup->set_address(address_ + operand->value_pos);
			}
			if (operand->relocation)
				operand->relocation->set_address(address_ + operand->value_pos);
		}
	}

	if (seh_handler_) {
		if (seh_handler_ == NEED_SEH_HANDLER) {
			seh_handler_ = file.seh_handler_list()->Add(address());
		}
		else {
			seh_handler_->set_address(address());
		}
	}

	BaseCommand::WriteToFile(file);
}

void IntelCommand::Rebase(uint64_t delta_base)
{
	if (!address_)
		return;

	if ((type_ == cmJmp || type_ == cmCall || type_ == cmJmpWithFlag) && operand_[0].type == otValue) {
		operand_[0].value += delta_base;
	}
	else {
		for (size_t i = 0; i < _countof(operand_); i++) {
			IntelOperand* operand = &operand_[i];
			if (operand->type == otNone)
				break;

			if ((operand->type & otValue) && (operand->fixup || operand->is_large_value))
				operand->value += delta_base;
		}
	}

	address_ += delta_base;

#ifdef CHECKED
	update_hash();
#endif
}

IntelVMCommand* IntelCommand::AddVMCommand(const CompileContext& ctx, IntelCommandType command_type, OperandType operand_type, OperandSize operand_size, uint64_t value, uint32_t options, IFixup* fixup)
{
	bool need_popf = false;
	if ((command_type == cmAdd || command_type == cmNor || command_type == cmNand || command_type == cmShr || command_type == cmShl) && !value) {
		need_popf = true;
		value = true;
	}

	IntelVMCommand* vm_command = NULL;
	if ((owner()->compilation_options() & coLockToKey) && command_type == cmPush && operand_type == otValue && (options & voLinkCommand)) {
		vm_command = new IntelVMCommand(this, command_type, operand_type, osDWord, value, options);
		vm_command->set_crypt_command(cmXadd, operand_size, ctx.options.licensing_manager->product_code());
	}
	if (!vm_command)
		vm_command = new IntelVMCommand(this, command_type, operand_type, operand_size, value, options);

	AddObject(vm_command);
	if (options & voLinkCommand)
		vm_links_.push_back(vm_command);
	if (command_type == cmJmp)
		jmp_links_.push_back(vm_command);

	uint32_t new_options = options & (voSectionCommand | voNoCRC);
	if (need_popf)
		AddVMCommand(ctx, cmPop, otRegistr, size_, regEmpty, new_options);

	if ((ctx.options.flags & cpMemoryProtection) && (new_options & voNoCRC) == 0 && vm_command->command_type() == cmPush && vm_command->operand_type() == otValue && vm_command->size() > osByte) {
		new_options |= voNoCRC;
		IntelVMCommand* address_command = AddVMCommand(ctx, cmPush, otValue, size_, 0, new_options | voFixup);
		AddVMCommand(ctx, cmPush, otMemory, vm_command->size(), segDS, new_options);
		AddVMCommand(ctx, cmAdd, otNone, vm_command->size(), false, new_options);

		internal_links_.Add(vlCRCValue, address_command, vm_command);
	}

	if (vm_command->crypt_command() == cmXadd) {
		size_t i;
		IntelVMCommand* cur_command = vm_command;
		// read session key
		uint64_t address = ctx.runtime->export_list()->GetAddressByType(atLoaderData);
		IntelVMCommand* from_command = AddVMCommand(ctx, cmPush, otValue, size_, address, new_options | voFixup);
		ICommand* to_command = ctx.file->function_list()->GetCommandByAddress(address, true);
		if (to_command)
			internal_links_.Add(vlNone, from_command, to_command);
		AddVMCommand(ctx, cmPush, otMemory, size_, segDS, new_options);
		AddVMCommand(ctx, cmPush, otValue, size_, ctx.runtime_var_index[VAR_SESSION_KEY] * OperandSizeToValue(size_), new_options);
		AddVMCommand(ctx, cmAdd, otNone, size_, false);
		AddVMCommand(ctx, cmPush, otMemory, size_, segDS, new_options);
		AddVMCommand(ctx, cmPop, otRegistr, size_, regETX, new_options);
		// add session key
		AddVMCommand(ctx, cmPush, otRegistr, osDWord, regETX, new_options);
		AddVMCommand(ctx, cmAdd, otNone, osDWord, false, new_options);
		for (i = 1; i < 4; i++) {
			cur_command->set_link_command(AddVMCommand(ctx, cmPush, otValue, osDWord, 0, new_options));
			// add session key
			AddVMCommand(ctx, cmPush, otRegistr, osDWord, regETX, new_options);
			AddVMCommand(ctx, cmAdd, otNone, osDWord, false, new_options);
			cur_command = cur_command->link_command();
		}
		AddVMCommand(ctx, cmPush, otRegistr, size_, regESP, new_options);

		address = ctx.runtime->export_list()->GetAddressByType(atDecryptBuffer);
		from_command = AddVMCommand(ctx, cmPush, otValue, size_, address, new_options | voFixup);
		to_command = ctx.file->function_list()->GetCommandByAddress(address, true);
		if (to_command)
			internal_links_.Add(vlNone, from_command, to_command);
		AddVMCommand(ctx, cmCall, otNone, size_, 1, new_options);
		AddVMCommand(ctx, cmPop, otRegistr, size_, regEmpty, new_options);

		// correct stack
		if (ctx.file->calling_convention() == ccCdecl)
			AddVMCommand(ctx, cmPop, otRegistr, size_, regEmpty, new_options);
		if (size_ == osQWord) {
			AddVMCommand(ctx, cmPop, otRegistr, osQWord, regEmpty, new_options);
		}
		else {
			AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty, new_options);
			AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty, new_options);
			AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty, new_options);
		}

		// add session key
		if (size_ == osQWord) {
			AddVMCommand(ctx, cmPush, otRegistr, size_, regESP, new_options);
			AddVMCommand(ctx, cmPush, otValue, size_, OperandSizeToStack(osDWord), new_options);
			AddVMCommand(ctx, cmAdd, otNone, size_, false, new_options);
			AddVMCommand(ctx, cmPush, otMemory, osDWord, segSS, new_options);

			AddVMCommand(ctx, cmPush, otRegistr, osDWord, regETX, new_options);
			AddVMCommand(ctx, cmAdd, otNone, osDWord, false);

			AddVMCommand(ctx, cmPush, otRegistr, size_, regESP, new_options);
			AddVMCommand(ctx, cmPush, otValue, size_, 2 * OperandSizeToStack(osDWord), new_options);
			AddVMCommand(ctx, cmAdd, otNone, size_, false, new_options);
			AddVMCommand(ctx, cmPop, otMemory, osDWord, segSS, new_options);
		}
		AddVMCommand(ctx, cmPush, otRegistr, osDWord, regETX, new_options);
		AddVMCommand(ctx, cmAdd, otNone, osDWord, false, new_options);
	}

	if ((options & voFixup) && (ctx.options.flags & cpStripFixups) == 0) {
		if (vm_command->is_data()) {
			vm_command->set_fixup(fixup);
		}
		else {
			FixupType fixup_type = (fixup && fixup != NEED_FIXUP) ? fixup->type() : ftHighLow;
			switch (fixup_type) {
			case ftHigh:
				AddVMCommand(ctx, cmPush, otRegistr, operand_size, regERX, new_options);
				AddVMCommand(ctx, cmPop, otRegistr, osWord, regEmpty, new_options);
				AddVMCommand(ctx, cmPush, otValue, osWord, 0, new_options);
				if (options & voInverseValue) {
					AddVMCommand(ctx, cmPush, otRegistr, size_, regESP, new_options);
					AddVMCommand(ctx, cmPush, otMemory, operand_size, segSS, new_options);
					AddVMCommand(ctx, cmNor, otNone, operand_size, false, new_options);
					AddVMCommand(ctx, cmPush, otValue, operand_size, 1, new_options);
					AddVMCommand(ctx, cmAdd, otNone, operand_size, false, new_options);
				}
				AddVMCommand(ctx, cmAdd, otNone, operand_size, false, new_options);
				break;

			case ftLow:
				AddVMCommand(ctx, cmPush, otValue, osWord, 0, options);
				AddVMCommand(ctx, cmPush, otRegistr, osWord, regERX, new_options);
				if (options & voInverseValue) {
					AddVMCommand(ctx, cmPush, otRegistr, size_, regESP, new_options);
					AddVMCommand(ctx, cmPush, otMemory, operand_size, segSS, new_options);
					AddVMCommand(ctx, cmNor, otNone, operand_size, false, new_options);
					AddVMCommand(ctx, cmPush, otValue, operand_size, 1, new_options);
					AddVMCommand(ctx, cmAdd, otNone, operand_size, false, new_options);
				}
				AddVMCommand(ctx, cmAdd, otNone, operand_size, false, new_options);
				break;

			case ftHighLow:
				AddVMCommand(ctx, cmPush, otRegistr, operand_size, regERX, new_options);
				if (options & voInverseValue) {
					AddVMCommand(ctx, cmPush, otRegistr, operand_size, regERX, new_options);
					AddVMCommand(ctx, cmNor, otNone, operand_size, false, new_options);
					AddVMCommand(ctx, cmPush, otValue, operand_size, 1, new_options);
					AddVMCommand(ctx, cmAdd, otNone, operand_size, false, new_options);
				}
				AddVMCommand(ctx, cmAdd, otNone, operand_size, false, new_options);
				break;
			}
		}
	}

	if (command_type == cmRet || command_type == cmIret || command_type == cmJmp)
		section_options_ |= rtCloseSection;

	return vm_command;
}

void IntelCommand::AddCorrectOperandSizeSection(const CompileContext& ctx, OperandSize src, OperandSize dst)
{
	int i = (int)(OperandSizeToStack(dst) - OperandSizeToStack(src));
	switch (i) {
	case -2:
		AddVMCommand(ctx, cmPop, otRegistr, osWord, regEmpty);
		break;
	case -4:
		AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);
		break;
	case -6:
		AddVMCommand(ctx, cmPop, otRegistr, osWord, regEmpty);
		AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);
		break;
	case 2:
		AddVMCommand(ctx, cmPush, otValue, osWord, 0);
		break;
	case 4:
		AddVMCommand(ctx, cmPush, otValue, osDWord, 0);
		break;
	case 6:
		AddVMCommand(ctx, cmPush, otValue, osWord, 0);
		AddVMCommand(ctx, cmPush, otValue, osDWord, 0);
		break;
	}
}

void IntelCommand::AddRegistrAndValueSection(const CompileContext& ctx, uint8_t registr, OperandSize registr_size, uint64_t value, bool need_pushf)
{
	if (rand() & 1) {
		AddVMCommand(ctx, cmPush, otRegistr, registr_size, registr);
		AddVMCommand(ctx, cmPush, otRegistr, registr_size, registr);

		AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, registr_size, false);
		AddVMCommand(ctx, cmPush, otValue, registr_size, ~value);
		AddVMCommand(ctx, cmNor, otNone, registr_size, need_pushf);
	}
	else {
		AddVMCommand(ctx, cmPush, otRegistr, registr_size, registr);
		AddVMCommand(ctx, cmPush, otValue, registr_size, value);
		AddVMCommand(ctx, cmNand, otNone, registr_size, false);

		AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
		AddVMCommand(ctx, cmPush, otMemory, registr_size, segSS);
		AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, registr_size, need_pushf);
	}
}

void IntelCommand::AddRegistrOrValueSection(const CompileContext& ctx, uint8_t registr, OperandSize registr_size, uint64_t value, bool need_pushf)
{
	AddVMCommand(ctx, cmPush, otRegistr, registr_size, registr);
	AddVMCommand(ctx, cmPush, otValue, registr_size, value);
	AddVMCommand(ctx, cmNor, otNone, registr_size, false);

	AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
	AddVMCommand(ctx, cmPush, otMemory, registr_size, segSS);
	AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, registr_size, need_pushf);
}

void IntelCommand::AddCombineFlagsSection(const CompileContext& ctx, uint16_t mask)
{
	AddRegistrAndValueSection(ctx, regEFX, size_, mask);
	AddRegistrAndValueSection(ctx, regEIX, size_, ~mask);
	AddVMCommand(ctx, cmAdd, otNone, size_, false);
	AddVMCommand(ctx, cmPop, otRegistr, size_, regEFX);
}

void IntelCommand::AddCorrectFlagSection(const CompileContext& ctx, uint16_t flags)
{
	AddRegistrAndValueSection(ctx, regEFX, size_, flags);
	AddVMCommand(ctx, cmPush, otRegistr, size_, regEFX);
	AddVMCommand(ctx, cmPush, otValue, size_, flags);
	AddVMCommand(ctx, cmNor, otNone, size_, false);
	AddVMCommand(ctx, cmNor, otNone, size_, false);
	AddVMCommand(ctx, cmPop, otRegistr, size_, regEFX);
}

void IntelCommand::AddExtractFlagSection(const CompileContext& ctx, uint16_t flags, bool is_inverse, uint8_t extract_to)
{
	bool one_bit = (flags & (flags - 1)) == 0;
	uint16_t check_flag = one_bit ? flags : (uint16_t)fl_Z;
	int c = 0;

	if (check_flag > extract_to) {
		while (check_flag > extract_to) {
			c++;
			check_flag >>= 1;
		}
	}
	else if (check_flag < extract_to) {
		while (check_flag < extract_to) {
			c--;
			check_flag <<= 1;
		}
	}
	if (c != 0)
		AddVMCommand(ctx, cmPush, otValue, osWord, abs(c));

	if (one_bit) {
		AddVMCommand(ctx, cmPush, otRegistr, size_, regEFX);
		if (!is_inverse) {
			AddVMCommand(ctx, cmPush, otRegistr, size_, regEFX);
			AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, size_, false);
		}
		AddVMCommand(ctx, cmPush, otValue, size_, ~flags);
		AddVMCommand(ctx, cmNor, otNone, size_, false);
	}
	else {
		bool is_os = (flags & fl_OS) == fl_OS;
		if (is_os) {
			AddRegistrAndValueSection(ctx, regEFX, size_, fl_S, true);
			AddVMCommand(ctx, cmPop, otRegistr, size_, regETX);
			AddVMCommand(ctx, cmPop, otRegistr, size_, regEmpty);

			AddRegistrAndValueSection(ctx, regEFX, size_, fl_O, true);
			AddVMCommand(ctx, cmPop, otRegistr, size_, regEIX);
			AddVMCommand(ctx, cmPop, otRegistr, size_, regEmpty);

			AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
			AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
			AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, size_, false);

			AddVMCommand(ctx, cmPush, otRegistr, size_, regEIX);
			AddVMCommand(ctx, cmPush, otRegistr, size_, regEIX);
			AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, size_, false);

			AddVMCommand(ctx, cmNor, otNone, size_, false);
			AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
			AddVMCommand(ctx, cmPush, otRegistr, size_, regEIX);
			AddVMCommand(ctx, cmNor, otNone, size_, false);

			AddVMCommand(ctx, cmNor, otNone, size_, false);
			AddVMCommand(ctx, cmPop, otRegistr, size_, regETX);

			if (is_inverse) {
				AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
				AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
				AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, size_, false);
				AddVMCommand(ctx, cmPop, otRegistr, size_, regETX);
			}
			check_flag = flags & ~fl_OS;
		}
		else {
			check_flag = flags;
		}

		if (check_flag) {
			AddRegistrAndValueSection(ctx, regEFX, size_, check_flag, true);
			AddVMCommand(ctx, cmPop, otRegistr, size_, is_os ? regEIX : regETX);
			AddVMCommand(ctx, cmPop, otRegistr, size_, regEmpty);

			if (is_os) {
				AddVMCommand(ctx, cmPush, otRegistr, size_, regEIX);
				AddVMCommand(ctx, cmPush, otRegistr, size_, regEIX);
				AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, size_, false);

				AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);

				if (is_inverse) {
					AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
					AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, size_, false);
				}

				AddVMCommand(ctx, cmNor, otNone, size_, false);
				AddVMCommand(ctx, cmPop, otRegistr, size_, regETX);
			}

			if (!is_inverse) {
				AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
				AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
				AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, size_, false);
				AddVMCommand(ctx, cmPop, otRegistr, size_, regETX);
			}
		}

		AddRegistrAndValueSection(ctx, regETX, size_, fl_Z);
	}

	if (c != 0)
		AddVMCommand(ctx, c > 0 ? cmShr : cmShl, otNone, size_, false);
}

void IntelCommand::AddJmpWithFlagSection(const CompileContext& ctx, IntelCommandType jmp_command_type)
{
	OperandSize os = operand_[1].size;
	uint8_t extract_to;
	extract_to = 1;

	switch (jmp_command_type) {
	case cmCmpxchg:
		AddExtractFlagSection(ctx, fl_Z, false, extract_to);
		break;

	case cmJmpWithFlag:
		AddExtractFlagSection(ctx, flags_, (options() & roInverseFlag) != 0, extract_to);
		break;

	case cmJCXZ:
		AddVMCommand(ctx, cmPush, otRegistr, size_, regEFX);

		AddVMCommand(ctx, cmPush, otValue, os, 0);
		AddVMCommand(ctx, cmPush, otRegistr, os, regECX);
		AddVMCommand(ctx, cmAdd, otNone, os, true);
		AddVMCommand(ctx, cmPop, otRegistr, size_, regEFX);
		AddVMCommand(ctx, cmPop, otRegistr, os, regEmpty);

		AddExtractFlagSection(ctx, fl_Z, false, extract_to);
		AddVMCommand(ctx, cmPop, otRegistr, size_, regETX);

		AddVMCommand(ctx, cmPop, otRegistr, size_, regEFX);

		AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
		break;

	case cmLoop: case cmRep:
		AddVMCommand(ctx, cmPush, otRegistr, size_, regEFX);

		AddVMCommand(ctx, cmPush, otValue, os, -1);
		AddVMCommand(ctx, cmPush, otRegistr, os, regECX);
		AddVMCommand(ctx, cmAdd, otNone, os, true);
		AddVMCommand(ctx, cmPop, otRegistr, size_, regEFX);
		AddVMCommand(ctx, cmPop, otRegistr, os, regECX);

		AddExtractFlagSection(ctx, fl_Z, true, extract_to);
		AddVMCommand(ctx, cmPop, otRegistr, size_, regETX);

		AddVMCommand(ctx, cmPop, otRegistr, size_, regEFX);

		AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
		break;

	case cmLoopne: case cmRepne: case cmLoope: case cmRepe:
		AddVMCommand(ctx, cmPush, otRegistr, size_, regEFX);

		AddVMCommand(ctx, cmPush, otValue, os, -1);
		AddVMCommand(ctx, cmPush, otRegistr, os, regECX);
		AddVMCommand(ctx, cmAdd, otNone, os, true);
		AddVMCommand(ctx, cmPop, otRegistr, size_, regETX);
		AddVMCommand(ctx, cmPop, otRegistr, os, regECX);

		if (jmp_command_type == cmLoope || jmp_command_type == cmRepe) {
			AddVMCommand(ctx, cmPush, otRegistr, size_, regEFX);
			AddVMCommand(ctx, cmPush, otRegistr, size_, regEFX);
			AddVMCommand(ctx, cmNor, otNone, size_, false);
			AddVMCommand(ctx, cmPop, otRegistr, size_, regEFX);
		}

		AddVMCommand(ctx, cmPush, otRegistr, size_, regEFX);
		AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
		AddVMCommand(ctx, cmNor, otNone, size_, false);

		AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
		AddVMCommand(ctx, cmPush, otMemory, size_, segSS);

		AddVMCommand(ctx, cmNor, otNone, size_, false);
		AddVMCommand(ctx, cmPop, otRegistr, size_, regEFX);

		AddExtractFlagSection(ctx, fl_Z, true, extract_to);
		AddVMCommand(ctx, cmPop, otRegistr, size_, regETX);

		AddVMCommand(ctx, cmPop, otRegistr, size_, regEFX);

		AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
		break;
	}

	AddVMCommand(ctx, cmPush, otValue, size_, (uint64_t)-1);
	AddVMCommand(ctx, cmAdd, otNone, size_, false);
	AddVMCommand(ctx, cmPop, otRegistr, size_, regEIX);

	// first address AND !condition
	AddVMCommand(ctx, cmPush, otValue, size_, 0, voLinkCommand);
	AddVMCommand(ctx, cmPush, otRegistr, size_, regEIX);
	AddVMCommand(ctx, cmPush, otRegistr, size_, regEIX);
	AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, size_, false);
	AddVMCommand(ctx, cmNand, otNone, size_, false);
	AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
	AddVMCommand(ctx, cmPush, otMemory, size_, segSS);
	AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, size_, false);

	// second address AND condition
	AddVMCommand(ctx, cmPush, otValue, size_, 0, voLinkCommand);
	AddVMCommand(ctx, cmPush, otRegistr, size_, regEIX);
	AddVMCommand(ctx, cmNand, otNone, size_, false);
	AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
	AddVMCommand(ctx, cmPush, otMemory, size_, segSS);
	AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, size_, false);

	// OR addresses 
	AddVMCommand(ctx, cmAdd, otNone, size_, false);

	AddVMCommand(ctx, cmPush, otRegistr, size_, regERX);
	AddVMCommand(ctx, cmAdd, otNone, size_, false);
	AddEndSection(ctx, cmJmp, 0, voUseEndSectionCryptor);
}

void IntelCommand::AddBeginSection(const CompileContext& ctx, uint32_t options)
{
	options |= voSectionCommand;

	if (count() == 0)
		section_options_ |= rtBeginSection;

	SectionCryptor* section_cryptor;
	if (options & voUseBeginSectionCryptor) {
		section_cryptor = begin_section_cryptor_;
	}
	else if (options & voUseEndSectionCryptor) {
		section_cryptor = end_section_cryptor_;
	}
	else {
		section_cryptor = NULL;
	}

	ByteList* registr_order = (section_cryptor) ? section_cryptor->end_cryptor()->registr_order() : reinterpret_cast<IntelVirtualMachine*>(block()->virtual_machine())->registr_order();

	AddVMCommand(ctx, cmPop, otRegistr, size_, regERX, options);
	options &= ~voLinkCommand;

	for (size_t i = registr_order->size(); i > 0; i--) {
		uint8_t reg = registr_order->at(i - 1);
		AddVMCommand(ctx, cmPop, otRegistr, size_, reg, options);
	}

	AddVMCommand(ctx, cmPop, otRegistr, size_, regEmpty, options);
	AddVMCommand(ctx, cmPop, otRegistr, size_, regEmpty, options);
}

IntelCommandType CryptorCommandToIntel(CryptCommandType crypt_command)
{
	IntelCommandType res;
	switch (crypt_command) {
	case ccAdd:
		res = cmAdd;
		break;
	case ccSub:
		res = cmSub;
		break;
	case ccXor:
		res = cmXor;
		break;
	case ccInc:
		res = cmInc;
		break;
	case ccDec:
		res = cmDec;
		break;
	case ccBswap:
		res = cmBswap;
		break;
	case ccRol:
		res = cmRol;
		break;
	case ccRor:
		res = cmRor;
		break;
	case ccNot:
		res = cmNot;
		break;
	case ccNeg:
		res = cmNeg;
		break;
	default:
		res = cmUnknown;
		break;
	}

	return res;
}

void IntelCommand::AddCryptorSection(const CompileContext& ctx, ValueCryptor* cryptor, bool is_decrypt)
{
	if (!cryptor)
		return;

	CompileContext new_ctx = ctx;
	new_ctx.options.flags &= ~cpMemoryProtection;

	size_t i;
	IntelCommand tmp_command(owner(), size_);
	tmp_command.set_block(block());
	tmp_command.include_option(roNoSaveFlags);
	IntelOperand first_operand = IntelOperand(otMemory | otRegistr, cryptor->size(), regESP);
	size_t c = cryptor->count();
	for (i = 0; i < c; i++) {
		ValueCommand* value_command = cryptor->item(is_decrypt ? c - i - 1 : i);
		IntelCommandType command_type = CryptorCommandToIntel(value_command->type(is_decrypt));
		if (command_type == cmUnknown)
			throw std::runtime_error("Unknown cryptor command");

		IntelOperand second_operand;
		if (command_type == cmAdd || command_type == cmSub || command_type == cmXor || command_type == cmRol || command_type == cmRor)
			second_operand = IntelOperand(otValue, (command_type == cmRol || command_type == cmRor) ? osByte : cryptor->size(), 0, value_command->value());
		tmp_command.Init(command_type, first_operand, second_operand);
		tmp_command.CompileToVM(new_ctx);
	}
	for (i = 0; i < tmp_command.count(); i++) {
		AddObject(tmp_command.item(i)->Clone(this));
	}
}

void IntelCommand::AddCheckBreakpointSection(const CompileContext& ctx, OperandSize address_size)
{
	if (address_size < size_) {
		AddVMCommand(ctx, cmPop, otRegistr, address_size, regEIX);
		AddVMCommand(ctx, cmPush, otRegistr, address_size, regEIX);
		AddVMCommand(ctx, cmPush, otValue, osDWord, 0, 0);
		AddVMCommand(ctx, cmPush, otRegistr, address_size, regEIX);
	}
	else {
		AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
		AddVMCommand(ctx, cmPush, otMemory, address_size, segSS);
	}

	AddVMCommand(ctx, cmPush, otMemory, osWord, segDS);
	AddVMCommand(ctx, cmPop, otRegistr, osWord, regEIX);

	AddVMCommand(ctx, cmPush, otRegistr, osByte, regEIX);
	AddVMCommand(ctx, cmPush, otValue, osByte, 0 - 0xcc); // short "int 03"
	AddVMCommand(ctx, cmAdd, otNone, osByte, true);
	AddVMCommand(ctx, cmPop, otRegistr, size_, regETX);
	AddVMCommand(ctx, cmPop, otRegistr, osByte, regEmpty);

	AddVMCommand(ctx, cmPush, otRegistr, osWord, regEIX);
	AddVMCommand(ctx, cmPush, otValue, osWord, 0 - 0x03cd); // long "int 03"
	AddVMCommand(ctx, cmAdd, otNone, osWord, true);
	AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
	AddVMCommand(ctx, cmNor, otNone, size_, false);
	AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
	AddVMCommand(ctx, cmPush, otMemory, size_, segSS);
	AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, size_, false);
	AddVMCommand(ctx, cmPop, otRegistr, size_, regETX);
	AddVMCommand(ctx, cmPop, otRegistr, osWord, regEmpty);

	AddVMCommand(ctx, cmPush, otRegistr, osWord, regEIX);
	AddVMCommand(ctx, cmPush, otValue, osWord, 0 - 0x0b0f); // "ud2"
	AddVMCommand(ctx, cmAdd, otNone, osWord, true);
	AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
	AddVMCommand(ctx, cmNor, otNone, size_, false);
	AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
	AddVMCommand(ctx, cmPush, otMemory, size_, segSS);
	AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, size_, false);
	AddVMCommand(ctx, cmPop, otRegistr, size_, regETX);
	AddVMCommand(ctx, cmPop, otRegistr, osWord, regEmpty);

	// extract Z flag to random value
	AddVMCommand(ctx, cmPush, otValue, osWord, 6);
	AddVMCommand(ctx, cmPush, otRegistr, address_size, regETX);
	AddVMCommand(ctx, cmShr, otNone, address_size, false);
	AddVMCommand(ctx, cmPush, otValue, address_size, ~1);
	AddVMCommand(ctx, cmNor, otNone, address_size, false);
	AddVMCommand(ctx, cmPush, otValue, address_size, (uint64_t)-1);
	AddVMCommand(ctx, cmAdd, otNone, address_size, false);
	AddVMCommand(ctx, cmPush, otValue, address_size, rand32());
	AddVMCommand(ctx, cmNand, otNone, address_size, false);
	AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
	AddVMCommand(ctx, cmPush, otMemory, address_size, segSS);
	AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, address_size, false);

	AddVMCommand(ctx, cmAdd, otNone, address_size, false);
}

void IntelCommand::AddCheckCRCSection(const CompileContext& ctx, OperandSize address_size)
{
	AddVMCommand(ctx, cmRdtsc, otNone, size_, 0);
	AddVMCommand(ctx, cmAdd, otNone, osDWord, false);
	AddVMCommand(ctx, cmPush, otValue, osDWord, rand32());
	AddVMCommand(ctx, cmAdd, otNone, osDWord, false);
	AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEIX);

	IntelVMCommand* vm_command = AddVMCommand(ctx, cmPush, otValue, osDWord, 0);
	internal_links_.Add(vlCRCTableCount, vm_command, NULL);
	AddVMCommand(ctx, cmPush, otRegistr, osDWord, regEIX);
	AddVMCommand(ctx, cmPush, otValue, osDWord, 0);
	AddVMCommand(ctx, cmDiv, otNone, osDWord, true);
	AddVMCommand(ctx, cmPop, otRegistr, size_, regEmpty);

	AddVMCommand(ctx, cmPush, otValue, osDWord, sizeof(CRCInfo::POD));
	AddVMCommand(ctx, cmMul, otNone, osDWord, true);
	AddVMCommand(ctx, cmPop, otRegistr, size_, regEmpty);

	AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);
	AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEIX);

	AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);

	if (size_ == osQWord)
		AddVMCommand(ctx, cmPush, otValue, osDWord, 0);
	AddVMCommand(ctx, cmPush, otRegistr, osDWord, regEIX);
	vm_command = AddVMCommand(ctx, cmPush, otValue, size_, 0, voFixup);
	internal_links_.Add(vlCRCTableAddress, vm_command, NULL);
	AddVMCommand(ctx, cmAdd, otNone, size_, false);
	AddVMCommand(ctx, cmPop, otRegistr, size_, regEIX);

	if (address_size == osQWord)
		AddVMCommand(ctx, cmPush, otValue, osDWord, 0);

	if (size_ == osQWord)
		AddVMCommand(ctx, cmPush, otValue, osDWord, 0);
	AddVMCommand(ctx, cmPush, otRegistr, size_, regEIX);
	assert(sizeof(CRCInfo::POD) == 12);
	AddVMCommand(ctx, cmPush, otValue, size_, offsetof(CRCInfo::POD, size));
	AddVMCommand(ctx, cmAdd, otNone, size_, false);
	AddVMCommand(ctx, cmPush, otMemory, osDWord, segDS);
	AddCryptorSection(ctx, ctx.file->function_list()->crc_cryptor(), true);

	if (size_ == osQWord)
		AddVMCommand(ctx, cmPush, otValue, osDWord, 0);
	AddVMCommand(ctx, cmPush, otRegistr, size_, regEIX);
	AddVMCommand(ctx, cmPush, otMemory, osDWord, segDS);
	AddCryptorSection(ctx, ctx.file->function_list()->crc_cryptor(), true);
	AddVMCommand(ctx, cmPush, otValue, size_, ctx.file->image_base(), voFixup);
	AddVMCommand(ctx, cmAdd, otNone, size_, false);

	AddVMCommand(ctx, cmCrc, otNone, size_, 0);

	AddVMCommand(ctx, cmPush, otRegistr, size_, regEIX);
	AddVMCommand(ctx, cmPush, otValue, size_, offsetof(CRCInfo::POD, hash));
	AddVMCommand(ctx, cmAdd, otNone, size_, false);
	AddVMCommand(ctx, cmPush, otMemory, osDWord, segDS);

	AddVMCommand(ctx, cmAdd, otNone, osDWord, false);

	AddVMCommand(ctx, cmAdd, otNone, address_size, false);
}

void IntelCommand::AddEndSection(const CompileContext& ctx, IntelCommandType end_command, uint8_t end_value, uint32_t options)
{
	options |= voSectionCommand;

	SectionCryptor* section_cryptor;
	if (options & voUseBeginSectionCryptor) {
		section_cryptor = begin_section_cryptor_;
	}
	else if (options & voUseEndSectionCryptor) {
		section_cryptor = end_section_cryptor_;
	}
	else {
		section_cryptor = NULL;
	}

	ByteList* registr_order;
	if (section_cryptor)
		registr_order = section_cryptor->end_cryptor()->registr_order();
	else if (end_command == cmJmp && end_value == 0xff)
		registr_order = link()->to_command()->block()->virtual_machine()->registr_order();
	else
		registr_order = block()->virtual_machine()->registr_order();

	switch (end_command) {
	case cmRet:
	{
		OperandSize address_size = (end_value == 1) ? osDWord : size_;
		if (ctx.options.flags & cpCheckDebugger)
			AddCheckBreakpointSection(ctx, address_size);
		if (ctx.options.flags & cpMemoryProtection)
			AddCheckCRCSection(ctx, address_size);
	}
	break;

	case cmJmp:
		AddVMCommand(ctx, cmPop, otRegistr, size_, regEIX, options);
		AddVMCommand(ctx, cmPush, otRegistr, size_, regEmpty, options);
		AddVMCommand(ctx, cmPush, otRegistr, size_, regEmpty, options);
		break;
	}

	for (size_t i = 0; i < registr_order->size(); i++) {
		uint8_t reg = registr_order->at(i);
		AddVMCommand(ctx, cmPush, otRegistr, size_, reg, options);
	}

	if (end_command != cmRet)
		AddVMCommand(ctx, cmPush, otRegistr, size_, regERX, options);

	section_options_ |= rtEndSection;

	if (end_command != cmNop) {
		if (end_command == cmJmp)
			AddVMCommand(ctx, cmPush, otRegistr, size_, regEIX, options);
		AddVMCommand(ctx, end_command, otNone, size_, end_value, options);
	}
}

uint64_t IntelCommand::AddStoreEIPSection(const CompileContext& ctx, uint64_t prev_eip)
{
	if (ctx.file->runtime_function_list() && ctx.file->runtime_function_list()->count()) {
		uint64_t value;
		AddressRange* range = address_range();
		if (range) {
			FunctionInfo* info = range->owner();
			uint64_t end_prolog = info->begin() + info->prolog_size();
			if (range->original_begin() > end_prolog || !address_) {
				value = range->original_begin();
			}
			else if (address_ <= end_prolog) {
				value = address_;
			}
			else {
				value = end_prolog;
			}
		}
		else {
			value = 0;
		}
		if (prev_eip != value) {
			AddVMCommand(ctx, cmPush, otValue, size_, value, voFixup);
			AddVMCommand(ctx, cmPop, otRegistr, size_, regExtended + 0);
		}
		return value;
	}
	return -1;
}

void IntelCommand::AddStoreExtRegistrSection(const CompileContext& ctx, uint8_t registr)
{
	if (ctx.file->runtime_function_list() && ctx.file->runtime_function_list()->count()) {
		uint8_t ext_registr;
		if (registr == regESP) {
			ext_registr = regExtended + 1;
		}
		else {
			if (!address_range() || address_range()->owner()->frame_registr() != registr)
				return;

			switch (registr) {
			case regEBP:
				ext_registr = regExtended + 2;
				break;
			case regESI:
				ext_registr = regExtended + 3;
				break;
			case regEDI:
				ext_registr = regExtended + 4;
				break;
			case regEBX:
				ext_registr = regExtended + 5;
				break;
			default:
				return;
			}
		}

		AddVMCommand(ctx, cmPush, otRegistr, size_, registr);
		AddVMCommand(ctx, cmPop, otRegistr, size_, ext_registr);
	}
}

void IntelCommand::AddStoreExtRegistersSection(const CompileContext& ctx)
{
	if (ctx.file->runtime_function_list() && ctx.file->runtime_function_list()->count()) {
		AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
		AddVMCommand(ctx, cmPop, otRegistr, size_, regExtended + 1);

		AddVMCommand(ctx, cmPush, otRegistr, size_, regEBP);
		AddVMCommand(ctx, cmPop, otRegistr, size_, regExtended + 2);

		AddVMCommand(ctx, cmPush, otRegistr, size_, regESI);
		AddVMCommand(ctx, cmPop, otRegistr, size_, regExtended + 3);

		AddVMCommand(ctx, cmPush, otRegistr, size_, regEDI);
		AddVMCommand(ctx, cmPop, otRegistr, size_, regExtended + 4);

		AddVMCommand(ctx, cmPush, otRegistr, size_, regEBX);
		AddVMCommand(ctx, cmPop, otRegistr, size_, regExtended + 5);
	}
}

void IntelCommand::AddExtSection(const CompileContext& ctx, IntelCommand* next_command)
{
	if (next_command) {
		if (ctx.options.flags & cpEncryptBytecode) {
			block()->AddCorrectCommand(AddVMCommand(ctx, cmPush, otValue, size_, rand64(), voSectionCommand));
		}
		else {
			AddVMCommand(ctx, cmPush, otRegistr, size(), regEmpty, voSectionCommand);
		}
		AddVMCommand(ctx, cmPush, otRegistr, size(), regEmpty, voSectionCommand);
		end_section_cryptor_ = next_command->begin_section_cryptor_;
		AddEndSection(ctx, cmNop, 0, voUseEndSectionCryptor);
		item(count() - 1)->include_option(voInitOffset);
	}
	else {
		AddBeginSection(ctx, voUseBeginSectionCryptor);
		if ((section_options() & rtLinkedToExt) && begin_section_cryptor_) {
			if (ctx.options.flags & cpEncryptBytecode) {
				block()->AddCorrectCommand(AddVMCommand(ctx, cmPush, otValue, size_, rand64(), voSectionCommand));
			}
			else {
				AddVMCommand(ctx, cmPush, otRegistr, size_, regEmpty, voSectionCommand);
			}
			AddVMCommand(ctx, cmPush, otRegistr, size_, regEmpty, voSectionCommand);
			AddEndSection(ctx, cmNop);
			item(count() - 1)->include_option(voInitOffset);
			section_options_ &= ~rtEndSection;
			size_t c = count();
			AddBeginSection(ctx);
			ext_vm_entry_ = item(c);
		}
	}
}

void IntelCommand::AddCorrectESPSection(const CompileContext& ctx, OperandSize operand_size, size_t value)
{
	size_t i, j;
	IntelVMCommand* vm_command;

	j = 0;
	for (i = count(); i > 0; i--) {
		vm_command = item(i - 1);
		if (vm_command->options() & voSectionCommand) {
			j = i;
			break;
		}
	}

	for (i = j; i < count() - 1; i++) {
		vm_command = item(i);
		value += vm_command->GetStackLevel();
	}

	if (value) {
		AddVMCommand(ctx, cmPush, otValue, operand_size, value);
		AddVMCommand(ctx, cmAdd, otNone, operand_size, false);
	}
}

void IntelCommand::CompileOperand(const CompileContext& ctx, size_t operand_index, uint32_t options)
{
	IntelOperand* operand = &operand_[operand_index];
	OperandSize operand_size = operand->size;
	uint32_t vm_options = 0;
	if (operand->type & otValue) {
		if (operand->fixup || (options & coFixup) || operand->is_large_value)
			vm_options |= voFixup;
		if (link() && link()->operand_index() == (int)operand_index)
			vm_options |= voLinkCommand;
	}
	if (options & coAsWord) {
		operand_size = osWord;
	}
	else if (options & coAsPointer) {
		operand_size = size_;
	}

	switch (operand->type) {
	case otSegmentRegistr:
		if (options & coSaveResult) {
			AddVMCommand(ctx, cmPop, otSegmentRegistr, osWord, operand->registr);
			AddCorrectOperandSizeSection(ctx, operand_size, osWord);
		}
		else {
			AddCorrectOperandSizeSection(ctx, osWord, operand_size);
			AddVMCommand(ctx, cmPush, otSegmentRegistr, osWord, operand->registr);
		}
		break;

	case otDebugRegistr:
		if (options & coSaveResult) {
			AddVMCommand(ctx, cmPop, otDebugRegistr, operand_size, operand->registr);
		}
		else {
			AddVMCommand(ctx, cmPush, otDebugRegistr, operand_size, operand->registr);
		}
		break;

	case otControlRegistr:
		if (options & coSaveResult) {
			AddVMCommand(ctx, cmPop, otControlRegistr, operand_size, operand->registr);
		}
		else {
			AddVMCommand(ctx, cmPush, otControlRegistr, operand_size, operand->registr);
		}
		break;

	case otHiPartRegistr:
		if (options & coSaveResult) {
			AddVMCommand(ctx, cmPop, otHiPartRegistr, operand_size, operand->registr);
		}
		else {
			AddVMCommand(ctx, cmPush, otHiPartRegistr, operand_size, operand->registr);
		}
		break;

	case otRegistr:
		if (options & coSaveResult) {
			AddVMCommand(ctx, cmPop, otRegistr, operand_size, operand->registr);
			if (size_ == osQWord && operand_size == osDWord) {
				AddVMCommand(ctx, cmPush, otValue, osDWord, 0);
				AddVMCommand(ctx, cmPop, otHiPartRegistr, osDWord, operand->registr);
			}
			AddStoreExtRegistrSection(ctx, operand->registr);
		}
		else {
			AddVMCommand(ctx, cmPush, otRegistr, operand_size, operand->registr);
			if (operand->registr == regESP)
				AddCorrectESPSection(ctx, operand_size, 0);
		}
		break;

	case otValue:
		if ((options & coInverse) && (vm_options & voFixup) == 0) {
			AddVMCommand(ctx, cmPush, otValue, operand_size, ~operand->value, vm_options, operand->fixup);
			options &= ~coInverse;
		}
		else
			AddVMCommand(ctx, cmPush, otValue, operand_size, operand->value, vm_options, operand->fixup);
		break;

	default:
		if (operand->type & otMemory) {
			if (operand->type & otBaseRegistr) {
				AddCorrectOperandSizeSection(ctx, operand->address_size, size_);
				AddVMCommand(ctx, cmPush, otRegistr, operand->address_size, operand->base_registr);
				if (operand->base_registr == regESP)
					AddCorrectESPSection(ctx, size_, type_ == cmPop ? OperandSizeToStack(operand_size) : 0);
			}
			if (operand->type & otRegistr) {
				if (operand->scale_registr > 0)
					AddVMCommand(ctx, cmPush, otValue, osWord, operand->scale_registr);
				AddCorrectOperandSizeSection(ctx, operand->address_size, size_);
				AddVMCommand(ctx, cmPush, otRegistr, operand->address_size, operand->registr);
				if (operand->registr == regESP)
					AddCorrectESPSection(ctx, size_, type_ == cmPop ? OperandSizeToStack(operand_size) : 0);
				if (operand->scale_registr > 0)
					AddVMCommand(ctx, cmShl, otNone, size_, false);
				if (operand->type & otBaseRegistr)
					AddVMCommand(ctx, cmAdd, otNone, size_, false);
			}
			if (operand->type & otValue) {
				AddVMCommand(ctx, cmPush, otValue, size_, operand->value, vm_options, operand->fixup);
				if (operand->type & (otBaseRegistr | otRegistr))
					AddVMCommand(ctx, cmAdd, otNone, size_, false);
			}

			if ((options & coAsPointer) == 0) {
				if (options & coSaveResult) {
					AddVMCommand(ctx, cmPop, otMemory, operand_size, operand->effective_base_segment(base_segment_));
				}
				else {
					AddVMCommand(ctx, cmPush, otMemory, operand_size, operand->effective_base_segment(base_segment_));
				}
			}
		}
	}

	if (options & coInverse) {
		if (operand->type & otMemory) {
			AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
			AddVMCommand(ctx, cmPush, otMemory, operand_size, segSS);
		}
		else {
			CompileOperand(ctx, operand_index);
		}
		AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, operand_size, false);
	}
}

void IntelCommand::CompileToVM(const CompileContext& ctx)
{
	if (link() && link()->type() == ltNative) {
		AddVMCommand(ctx, cmPush, otValue, size_, 0, voLinkCommand | voFixup);
		AddEndSection(ctx, cmRet);
		return;
	}

	size_t i;
	OperandSize os, adr_os;
	IntelOperand* operand;
	uint16_t flags;
	size_t value;
	bool save_flags = (options() & roNoSaveFlags) == 0;

	if ((options() & roLockPrefix) && type_ != cmXchg) {
		switch (type_) {
		case cmAdd: case cmAnd: case cmSub: case cmXor: case cmOr: case cmXadd:
			i = (operand_[0].type & otMemory) ? 0 : 1;
			CompileOperand(ctx, 1 - i);
			CompileOperand(ctx, i, coAsPointer);
			AddVMCommand(ctx, type_, otMemory, operand_[0].size, operand_[i].effective_base_segment(base_segment_));
			AddVMCommand(ctx, cmPop, otRegistr, size_, save_flags ? regEFX : regEmpty);
			if (type_ == cmXadd)
				CompileOperand(ctx, 1 - i, coSaveResult);
			break;
		default:
			throw std::runtime_error("Runtime error at CompileToVM: " + text());
		}
	}
	else
		switch (type_) {
		case cmBt: case cmBtr: case cmBts: case cmBtc:
			uint8_t mask;
			switch (operand_[0].size) {
			case osWord: mask = 15; break;
			case osDWord: mask = 31; break;
			default: mask = 63; break;
			}

			if (operand_[0].type & otMemory) {
				os = osByte;
				uint8_t old_mask = mask;
				mask = 7;

				if (operand_[1].type == otValue) {
					AddVMCommand(ctx, cmPush, otValue, osWord, operand_[1].value & mask);
					AddVMCommand(ctx, cmPush, otValue, size_, (operand_[1].value & old_mask) >> 3);
				}
				else {
					CompileOperand(ctx, 1, coAsWord);
					AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
					AddVMCommand(ctx, cmPush, otMemory, osWord, segSS);
					AddVMCommand(ctx, cmNor, otNone, osWord, false);
					AddVMCommand(ctx, cmPush, otValue, osWord, ~mask);
					AddVMCommand(ctx, cmNor, otNone, osWord, false);

					AddVMCommand(ctx, cmPush, otValue, osWord, 3);
					AddCorrectOperandSizeSection(ctx, operand_[1].size, size_);
					CompileOperand(ctx, 1);
					AddVMCommand(ctx, cmShr, otNone, size_, false);
				}

				CompileOperand(ctx, 0, coAsPointer);
				AddVMCommand(ctx, cmAdd, otNone, size_, false);
				AddVMCommand(ctx, cmPop, otRegistr, size_, regETX);

				AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
				AddVMCommand(ctx, cmPush, otMemory, osByte, operand_[0].effective_base_segment(base_segment_));
				AddVMCommand(ctx, cmShr, otNone, os, false);
			}
			else {
				os = operand_[0].size;

				if (operand_[1].type == otValue) {
					AddVMCommand(ctx, cmPush, otValue, osWord, operand_[1].value & mask);
				}
				else {
					CompileOperand(ctx, 1, coAsWord);
					AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
					AddVMCommand(ctx, cmPush, otMemory, osWord, segSS);
					AddVMCommand(ctx, cmNor, otNone, osWord, false);
					AddVMCommand(ctx, cmPush, otValue, osWord, ~mask);
					AddVMCommand(ctx, cmNor, otNone, osWord, false);
				}

				CompileOperand(ctx, 0);
				AddVMCommand(ctx, cmShr, otNone, os, false);
			}

			AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
			AddVMCommand(ctx, cmPush, otMemory, osWord, segSS);
			AddVMCommand(ctx, cmNor, otNone, osWord, false);

			AddVMCommand(ctx, cmPush, otValue, osWord, ~fl_C);
			AddVMCommand(ctx, cmNor, otNone, osWord, false);

			AddVMCommand(ctx, cmPush, otRegistr, osWord, regEFX);
			AddVMCommand(ctx, cmPush, otRegistr, osWord, regEFX);
			AddVMCommand(ctx, cmNor, otNone, osWord, false);
			AddVMCommand(ctx, cmPush, otValue, osWord, fl_C);
			AddVMCommand(ctx, cmNor, otNone, osWord, false);

			AddVMCommand(ctx, cmAdd, otNone, osWord, false);

			AddVMCommand(ctx, cmPop, otRegistr, osWord, regEFX);

			AddCorrectOperandSizeSection(ctx, os, osWord);

			if (type_ != cmBt) {
				if (operand_[1].type == otValue) {
					if (operand_[0].type & otMemory) {
						AddVMCommand(ctx, cmPush, otValue, os, 1ull << (operand_[1].value & 7));
					}
					else {
						AddVMCommand(ctx, cmPush, otValue, os, 1ull << operand_[1].value);
					}
				}
				else {
					CompileOperand(ctx, 1, coAsWord);
					AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
					AddVMCommand(ctx, cmPush, otMemory, osWord, segSS);
					AddVMCommand(ctx, cmNor, otNone, osWord, false);
					AddVMCommand(ctx, cmPush, otValue, osWord, ~mask);
					AddVMCommand(ctx, cmNor, otNone, osWord, false);

					AddVMCommand(ctx, cmPush, otValue, os, 1);
					AddVMCommand(ctx, cmShl, otNone, os, false);
				}

				switch (type_) {
				case cmBts:
					if (operand_[0].type & otMemory) {
						AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
						AddVMCommand(ctx, cmPush, otMemory, osByte, operand_[0].effective_base_segment(base_segment_));
					}
					else {
						CompileOperand(ctx, 0);
					}
					AddVMCommand(ctx, cmNor, otNone, os, false);

					AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
					AddVMCommand(ctx, cmPush, otMemory, os, segSS);
					break;
				case cmBtr:
					if (operand_[0].type & otMemory) {
						AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
						AddVMCommand(ctx, cmPush, otMemory, osByte, operand_[0].effective_base_segment(base_segment_));

						AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
						AddVMCommand(ctx, cmPush, otMemory, osByte, segSS);
						AddVMCommand(ctx, cmNor, otNone, osByte, false);
					}
					else {
						CompileOperand(ctx, 0, coInverse);
					}
					break;
				case cmBtc:
					if (operand_[0].type & otMemory) {
						AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
						AddVMCommand(ctx, cmPush, otMemory, osByte, operand_[0].effective_base_segment(base_segment_));
						AddVMCommand(ctx, cmNor, otNone, os, false);

						AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
						AddVMCommand(ctx, cmPush, otMemory, osByte, operand_[0].effective_base_segment(base_segment_));
						AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
						AddVMCommand(ctx, cmPush, otMemory, osByte, segSS);
						AddVMCommand(ctx, cmNor, otNone, osByte, false);
					}
					else {
						CompileOperand(ctx, 0);
						AddVMCommand(ctx, cmNor, otNone, os, false);

						CompileOperand(ctx, 0, coInverse);
					}

					if (operand_[1].type == otValue) {
						if (operand_[0].type & otMemory) {
							AddVMCommand(ctx, cmPush, otValue, os, ~(1 << (operand_[1].value & 7)));
						}
						else {
							AddVMCommand(ctx, cmPush, otValue, os, ~(1 << operand_[1].value));
						}
					}
					else {
						CompileOperand(ctx, 1, coAsWord);
						AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
						AddVMCommand(ctx, cmPush, otMemory, osWord, segSS);
						AddVMCommand(ctx, cmNor, otNone, osWord, false);
						AddVMCommand(ctx, cmPush, otValue, osWord, ~mask);
						AddVMCommand(ctx, cmNor, otNone, osWord, false);

						AddVMCommand(ctx, cmPush, otValue, os, 1);
						AddVMCommand(ctx, cmShl, otNone, os, false);

						AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
						AddVMCommand(ctx, cmPush, otMemory, os, segSS);

						AddVMCommand(ctx, cmNor, otNone, os, false);
					}
					AddVMCommand(ctx, cmNor, otNone, os, false);
					break;
				}

				AddVMCommand(ctx, cmNor, otNone, os, false);

				if (operand_[0].type & otMemory) {
					AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
					AddVMCommand(ctx, cmPop, otMemory, osByte, operand_[0].effective_base_segment(base_segment_));
				}
				else {
					CompileOperand(ctx, 0, coSaveResult);
				}
			}
			break;

		case cmPush:
			CompileOperand(ctx, 0);
			AddStoreExtRegistrSection(ctx, regESP);
			break;

		case cmPop:
			CompileOperand(ctx, 0, coSaveResult);
			AddStoreExtRegistrSection(ctx, regESP);
			break;

		case cmMov:
			CompileOperand(ctx, 1);
			CompileOperand(ctx, 0, coSaveResult);
			break;

		case cmLea:
			CompileOperand(ctx, 1, coAsPointer);
			CompileOperand(ctx, 0, coSaveResult);
			AddCorrectOperandSizeSection(ctx, size_, operand_[0].size);
			break;

		case cmNot:
			CompileOperand(ctx, 0, coInverse);
			CompileOperand(ctx, 0, coSaveResult);
			break;

		case cmNeg:
			CompileOperand(ctx, 0);

			os = operand_[0].size;
			AddVMCommand(ctx, cmPush, otValue, os, -1);
			AddVMCommand(ctx, cmAdd, otNone, os, true);
			AddVMCommand(ctx, cmPop, otRegistr, size_, save_flags ? regEFX : regEmpty);

			AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
			AddVMCommand(ctx, cmPush, otMemory, os, segSS);
			AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, os, true);
			AddVMCommand(ctx, cmPop, otRegistr, size_, save_flags ? regEIX : regEmpty);

			CompileOperand(ctx, 0, coSaveResult);

			if (save_flags)
				AddCombineFlagsSection(ctx, fl_P | fl_O | fl_A | fl_C);
			break;

		case cmAdd: case cmAdc: case cmXadd:
			if (type_ == cmXadd)
				CompileOperand(ctx, 0);
			CompileOperand(ctx, 1);

			os = operand_[0].size;
			if (type_ == cmAdc) {
				AddCorrectOperandSizeSection(ctx, osWord, os);
				AddRegistrAndValueSection(ctx, regEFX, osWord, fl_C);
				AddVMCommand(ctx, cmAdd, otNone, os, true);
				AddVMCommand(ctx, cmPop, otRegistr, size_, save_flags ? regEIX : regEmpty);
			}

			CompileOperand(ctx, 0);
			AddVMCommand(ctx, cmAdd, otNone, os, true);
			AddVMCommand(ctx, cmPop, otRegistr, size_, save_flags ? regEFX : regEmpty);

			CompileOperand(ctx, 0, coSaveResult);

			if (type_ == cmXadd)
				CompileOperand(ctx, 1, coSaveResult);

			if (type_ == cmAdc && save_flags) {
				AddRegistrAndValueSection(ctx, regEIX, size_, fl_C | fl_A | fl_O);
				AddVMCommand(ctx, cmPush, otRegistr, size_, regEFX);
				AddVMCommand(ctx, cmNor, otNone, size_, false);

				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otMemory, size_, segSS);
				AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, size_, false);
				AddVMCommand(ctx, cmPop, otRegistr, size_, regEFX);
			}
			break;

		case cmSbb:
			CompileOperand(ctx, 1);

			os = operand_[0].size;
			AddCorrectOperandSizeSection(ctx, osWord, os);
			AddRegistrAndValueSection(ctx, regEFX, osWord, fl_C);
			AddVMCommand(ctx, cmAdd, otNone, os, false);

			AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
			AddVMCommand(ctx, cmPush, otMemory, os, segSS);
			AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, os, false);

			AddVMCommand(ctx, cmPush, otValue, os, 1);
			AddVMCommand(ctx, cmAdd, otNone, os, false);

			CompileOperand(ctx, 0);

			AddVMCommand(ctx, cmAdd, otNone, os, true);
			AddVMCommand(ctx, cmPop, otRegistr, size_, save_flags ? regEFX : regEmpty);

			CompileOperand(ctx, 0, coSaveResult);

			if (save_flags)
				AddCorrectFlagSection(ctx, fl_A | fl_C);
			break;

		case cmSub: case cmCmp:
			CompileOperand(ctx, 1);
			CompileOperand(ctx, 0, coInverse);

			os = operand_[0].size;
			AddVMCommand(ctx, cmAdd, otNone, os, true);
			AddVMCommand(ctx, cmPop, otRegistr, size_, save_flags ? regEFX : regEmpty);

			AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
			AddVMCommand(ctx, cmPush, otMemory, os, segSS);

			AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, os, true);
			AddVMCommand(ctx, cmPop, otRegistr, size_, save_flags ? regEIX : regEmpty);

			if (type_ == cmCmp) {
				AddVMCommand(ctx, cmPop, otRegistr, os, regEmpty);
			}
			else {
				CompileOperand(ctx, 0, coSaveResult);
			}

			if (save_flags)
				AddCombineFlagsSection(ctx, fl_P | fl_O | fl_A | fl_C);
			break;

		case cmInc:
			os = operand_[0].size;
			AddVMCommand(ctx, cmPush, otValue, os, 1);
			CompileOperand(ctx, 0);

			AddVMCommand(ctx, cmAdd, otNone, os, true);
			AddVMCommand(ctx, cmPop, otRegistr, size_, save_flags ? regEIX : regEmpty);

			CompileOperand(ctx, 0, coSaveResult);

			if (save_flags)
				AddCombineFlagsSection(ctx, fl_C);
			break;

		case cmDec:
			os = operand_[0].size;
			AddVMCommand(ctx, cmPush, otValue, os, -1);
			CompileOperand(ctx, 0);

			AddVMCommand(ctx, cmAdd, otNone, os, true);
			AddVMCommand(ctx, cmPop, otRegistr, size_, save_flags ? regEIX : regEmpty);

			CompileOperand(ctx, 0, coSaveResult);

			if (save_flags) {
				AddCombineFlagsSection(ctx, fl_C);
				AddCorrectFlagSection(ctx, fl_A);
			}
			break;

		case cmXlat:
			os = operand_[0].size;
			AddCorrectOperandSizeSection(ctx, os, size_);

			AddCorrectOperandSizeSection(ctx, osWord, os);
			AddVMCommand(ctx, cmPush, otRegistr, osByte, regEAX);

			AddVMCommand(ctx, cmPush, otRegistr, os, regEBX);
			AddVMCommand(ctx, cmAdd, otNone, os, false);
			AddVMCommand(ctx, cmPush, otMemory, osByte, (base_segment_ == segDefault) ? segDS : base_segment_);
			AddVMCommand(ctx, cmPop, otRegistr, osByte, regEAX);
			break;

		case cmSetXX:
			AddExtractFlagSection(ctx, flags_, (options() & roInverseFlag) != 0, 1);
			CompileOperand(ctx, 0, coSaveResult);
			AddCorrectOperandSizeSection(ctx, size_, osWord);
			break;

		case cmAnd: case cmTest:
			os = operand_[0].size;
			if (rand() & 1) {
				CompileOperand(ctx, 1, coInverse);
				CompileOperand(ctx, 0, coInverse);
				AddVMCommand(ctx, cmNor, otNone, os, true);
			}
			else {
				CompileOperand(ctx, 1);
				CompileOperand(ctx, 0);
				AddVMCommand(ctx, cmNand, otNone, os, false);

				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otMemory, os, segSS);
				AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, os, true);
			}
			AddVMCommand(ctx, cmPop, otRegistr, size_, save_flags ? regEFX : regEmpty);

			if (type_ == cmTest) {
				AddVMCommand(ctx, cmPop, otRegistr, os, regEmpty);
			}
			else {
				CompileOperand(ctx, 0, coSaveResult);
			}
			break;

		case cmXor:
			os = operand_[0].size;
			if (rand() & 1) {
				CompileOperand(ctx, 1, coInverse);
				CompileOperand(ctx, 0, coInverse);
				AddVMCommand(ctx, cmNor, otNone, os, false);

				CompileOperand(ctx, 1);
				CompileOperand(ctx, 0);
				AddVMCommand(ctx, cmNor, otNone, os, false);

				AddVMCommand(ctx, cmNor, otNone, os, true);
			}
			else {
				CompileOperand(ctx, 1, coInverse);
				CompileOperand(ctx, 0);
				AddVMCommand(ctx, cmNand, otNone, os, false);

				CompileOperand(ctx, 1);
				CompileOperand(ctx, 0, coInverse);
				AddVMCommand(ctx, cmNand, otNone, os, false);

				AddVMCommand(ctx, cmNand, otNone, os, true);
			}
			AddVMCommand(ctx, cmPop, otRegistr, size_, save_flags ? regEFX : regEmpty);

			CompileOperand(ctx, 0, coSaveResult);
			break;

		case cmOr:
			os = operand_[0].size;
			if (rand() & 1) {
				CompileOperand(ctx, 1);
				CompileOperand(ctx, 0);
				AddVMCommand(ctx, cmNor, otNone, os, false);

				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otMemory, os, segSS);
				AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, os, true);
			}
			else {
				CompileOperand(ctx, 1, coInverse);
				CompileOperand(ctx, 0, coInverse);
				AddVMCommand(ctx, cmNand, otNone, os, true);
			}
			AddVMCommand(ctx, cmPop, otRegistr, size_, save_flags ? regEFX : regEmpty);

			CompileOperand(ctx, 0, coSaveResult);
			break;

		case cmShld: case cmShrd:
			CompileOperand(ctx, 2);
			CompileOperand(ctx, 1);
			CompileOperand(ctx, 0);

			os = operand_[0].size;
			if (os == osWord) {
				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otMemory, osDWord, segSS);
			}

			AddVMCommand(ctx, type_, otNone, os == osQWord ? osQWord : osDWord, true);
			AddVMCommand(ctx, cmPop, otRegistr, size_, save_flags ? regEFX : regEmpty);

			CompileOperand(ctx, 0, coSaveResult);

			if (os == osWord)
				AddVMCommand(ctx, cmPop, otRegistr, osWord, regEmpty);
			break;

		case cmRol: case cmRor:
			CompileOperand(ctx, 1);
			CompileOperand(ctx, 0);

			os = operand_[0].size;
			switch (os) {
			case osByte:
				AddVMCommand(ctx, cmPush, otValue, osWord, 8);
				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otValue, size_, 2);
				AddVMCommand(ctx, cmAdd, otNone, size_, false);
				AddVMCommand(ctx, cmPush, otMemory, osWord, segSS);
				AddVMCommand(ctx, cmShl, otNone, osWord, false);
				AddVMCommand(ctx, cmAdd, otNone, osWord, false);

				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otMemory, osWord, segSS);
				break;
			case osWord:
				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otMemory, osWord, segSS);
				break;
			}

			adr_os = (os == osQWord) ? osQWord : osDWord;
			AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
			AddVMCommand(ctx, cmPush, otMemory, adr_os, segSS);

			AddVMCommand(ctx, type_ == cmRol ? cmShld : cmShrd, otNone, adr_os, true);
			AddVMCommand(ctx, cmPop, otRegistr, size_, save_flags ? regEIX : regEmpty);

			CompileOperand(ctx, 0, coSaveResult);

			if (os == osByte || os == osWord)
				AddVMCommand(ctx, cmPop, otRegistr, osWord, regEmpty);

			if (save_flags)
				AddCombineFlagsSection(ctx, fl_P | fl_A | fl_Z | fl_S);
			break;

		case cmShl: case cmSal: case cmShr:
			CompileOperand(ctx, 1);
			CompileOperand(ctx, 0);

			os = operand_[0].size;
			AddVMCommand(ctx, type_ == cmShr ? cmShr : cmShl, otNone, os, true);
			AddVMCommand(ctx, cmPop, otRegistr, size_, save_flags ? regEFX : regEmpty);

			CompileOperand(ctx, 0, coSaveResult);
			break;

		case cmSar:
			CompileOperand(ctx, 1);

			os = operand_[0].size;
			adr_os = (os == osQWord) ? osQWord : osDWord;
			AddVMCommand(ctx, cmPush, otValue, adr_os, 1);
			AddVMCommand(ctx, cmPush, otValue, osWord, OperandSizeToValue(os) * 8 - 1);
			if (os == osByte || os == osWord)
				AddVMCommand(ctx, cmPush, otValue, osWord, 0);

			CompileOperand(ctx, 0);
			AddVMCommand(ctx, cmShr, otNone, adr_os, false);
			AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
			AddVMCommand(ctx, cmPush, otMemory, adr_os, segSS);
			AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, adr_os, false);
			AddVMCommand(ctx, cmAdd, otNone, adr_os, false);

			switch (os) {
			case osByte:
				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otMemory, osWord, segSS);

				AddVMCommand(ctx, cmPush, otValue, osWord, 8);
				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otValue, size_, 2);
				AddVMCommand(ctx, cmAdd, otNone, size_, false);
				AddVMCommand(ctx, cmPush, otMemory, osWord, segSS);
				AddVMCommand(ctx, cmShl, otNone, osWord, false);

				CompileOperand(ctx, 0);

				AddVMCommand(ctx, cmAdd, otNone, osWord, false);
				break;
			case osWord:
				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otMemory, osWord, segSS);
				CompileOperand(ctx, 0);
				break;
			default:
				CompileOperand(ctx, 0);
				break;
			}

			AddVMCommand(ctx, cmShrd, otNone, adr_os, true);
			AddVMCommand(ctx, cmPop, otRegistr, size_, save_flags ? regEFX : regEmpty);

			CompileOperand(ctx, 0, coSaveResult);

			if (os == osByte || os == osWord)
				AddVMCommand(ctx, cmPop, otRegistr, osWord, regEmpty);
			break;

		case cmRcl: case cmRcr:
			AddVMCommand(ctx, cmPush, otValue, osByte, 8);
			AddRegistrAndValueSection(ctx, regEFX, osWord, fl_C);
			AddVMCommand(ctx, cmShl, otNone, osWord, true);
			AddVMCommand(ctx, cmPop, otRegistr, size_, regEmpty);

			os = operand_[0].size;
			CompileOperand(ctx, 1);
			AddVMCommand(ctx, cmAdd, otNone, osWord, true);
			AddVMCommand(ctx, cmPop, otRegistr, size_, regEmpty);

			CompileOperand(ctx, 0);

			AddVMCommand(ctx, type_, otNone, os, true);
			AddVMCommand(ctx, cmPop, otRegistr, size_, save_flags ? regEIX : regEmpty);
			CompileOperand(ctx, 0, coSaveResult);

			if (save_flags)
				AddCombineFlagsSection(ctx, fl_S | fl_Z | fl_A | fl_P);
			break;

		case cmCbw: case cmCwde: case cmCwd: case cmCdq: case cmCdqe: case cmCqo:
			switch (type_) {
			case cmCbw:
				os = osByte;
				break;
			case cmCwde: case cmCwd:
				os = osWord;
				break;
			case cmCdq: case cmCdqe:
				os = osDWord;
				break;
			default:
				os = osQWord;
				break;
			}
			AddVMCommand(ctx, cmPush, otValue, os, 1);

			AddVMCommand(ctx, cmPush, otValue, osWord, OperandSizeToValue(os) * 8 - 1);
			AddVMCommand(ctx, cmPush, otRegistr, os, regEAX);
			AddVMCommand(ctx, cmShr, otNone, os, false);

			AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
			AddVMCommand(ctx, cmPush, otMemory, os, segSS);
			AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, os, false);

			AddVMCommand(ctx, cmAdd, otNone, os, false);

			switch (type_) {
			case cmCbw:
				AddVMCommand(ctx, cmPop, otHiPartRegistr, osByte, regEAX);
				break;
			case cmCwde:
				AddVMCommand(ctx, cmPush, otRegistr, osWord, regEAX);
				AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEAX);
				if (size_ == osQWord) {
					AddVMCommand(ctx, cmPush, otValue, osDWord, 0);
					AddVMCommand(ctx, cmPop, otHiPartRegistr, osDWord, regEAX);
				}
				break;
			case cmCwd:
				AddVMCommand(ctx, cmPop, otRegistr, osWord, regEDX);
				break;
			case cmCdq:
				AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEDX);
				if (size_ == osQWord) {
					AddVMCommand(ctx, cmPush, otValue, osDWord, 0);
					AddVMCommand(ctx, cmPop, otHiPartRegistr, osDWord, regEDX);
				}
				break;
			case cmCdqe:
				AddVMCommand(ctx, cmPush, otRegistr, osDWord, regEAX);
				AddVMCommand(ctx, cmPop, otRegistr, osQWord, regEAX);
				break;
			default:
				AddVMCommand(ctx, cmPop, otRegistr, osQWord, regEDX);
				break;
			}
			break;

		case cmMovsx:
		case cmMovsxd:
			if (operand_[1].size == operand_[0].size) {
				CompileOperand(ctx, 1);
			}
			else {
				AddCorrectOperandSizeSection(ctx, operand_[1].size, operand_[0].size);
				CompileOperand(ctx, 1);

				AddVMCommand(ctx, cmPush, otValue, osWord, OperandSizeToValue(operand_[1].size) * 8);
				AddVMCommand(ctx, cmPush, otValue, osWord, OperandSizeToValue(operand_[1].size) * 8 - 1);

				os = operand_[0].size;
				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otValue, size_, OperandSizeToValue(osWord) * 2);
				AddVMCommand(ctx, cmAdd, otNone, size_, false);
				AddVMCommand(ctx, cmPush, otMemory, os, segSS);

				AddVMCommand(ctx, cmShr, otNone, os, false);

				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otMemory, os, segSS);
				AddVMCommand(ctx, (rand() & 1) ? cmNor : cmNand, otNone, os, false);

				AddVMCommand(ctx, cmPush, otValue, os, 1);
				AddVMCommand(ctx, cmAdd, otNone, os, false);

				AddVMCommand(ctx, cmShl, otNone, os, false);

				AddVMCommand(ctx, cmAdd, otNone, os, false);
			}

			CompileOperand(ctx, 0, coSaveResult);
			break;

		case cmMovzx:
			AddCorrectOperandSizeSection(ctx, operand_[1].size, operand_[0].size);
			CompileOperand(ctx, 1);
			CompileOperand(ctx, 0, coSaveResult);
			break;

		case cmPushf:
			AddVMCommand(ctx, cmPush, otRegistr, operand_[0].size, regEFX);
			AddStoreExtRegistrSection(ctx, regESP);
			break;

		case cmPopf:
			AddVMCommand(ctx, cmPop, otRegistr, operand_[0].size, regEFX);
			AddRegistrAndValueSection(ctx, regEFX, size_, ~0x8ff);
			AddVMCommand(ctx, cmPopf, otNone, size_, 0);
			AddStoreExtRegistrSection(ctx, regESP);
			break;

		case cmPusha:
			os = operand_[0].size;

			AddVMCommand(ctx, cmPush, otRegistr, os, regEAX);
			AddVMCommand(ctx, cmPush, otRegistr, os, regECX);
			AddVMCommand(ctx, cmPush, otRegistr, os, regEDX);
			AddVMCommand(ctx, cmPush, otRegistr, os, regEBX);

			AddVMCommand(ctx, cmPush, otRegistr, os, regESP);
			AddVMCommand(ctx, cmPush, otValue, os, OperandSizeToValue(os) * 4);
			AddVMCommand(ctx, cmAdd, otNone, os, false);

			AddVMCommand(ctx, cmPush, otRegistr, os, regEBP);
			AddVMCommand(ctx, cmPush, otRegistr, os, regESI);
			AddVMCommand(ctx, cmPush, otRegistr, os, regEDI);
			AddStoreExtRegistrSection(ctx, regESP);
			break;

		case cmPopa:
			os = operand_[0].size;

			AddVMCommand(ctx, cmPop, otRegistr, os, regEDI);
			AddVMCommand(ctx, cmPop, otRegistr, os, regESI);
			AddVMCommand(ctx, cmPop, otRegistr, os, regEBP);
			AddVMCommand(ctx, cmPop, otRegistr, os, regEmpty);
			AddVMCommand(ctx, cmPop, otRegistr, os, regEBX);
			AddVMCommand(ctx, cmPop, otRegistr, os, regEDX);
			AddVMCommand(ctx, cmPop, otRegistr, os, regECX);
			AddVMCommand(ctx, cmPop, otRegistr, os, regEAX);
			AddStoreExtRegistrSection(ctx, regESP);
			break;

		case cmLahf:
			AddVMCommand(ctx, cmPush, otRegistr, osWord, regEFX);
			AddVMCommand(ctx, cmPop, otHiPartRegistr, osByte, regEAX);
			break;

		case cmSahf:
			flags = fl_C | fl_P | fl_A | fl_Z | fl_S;

			AddVMCommand(ctx, cmPush, otHiPartRegistr, osByte, regEAX);
			AddVMCommand(ctx, cmPush, otHiPartRegistr, osByte, regEAX);
			AddVMCommand(ctx, cmNor, otNone, osByte, false);
			AddVMCommand(ctx, cmPush, otValue, osByte, ~flags);
			AddVMCommand(ctx, cmNor, otNone, osByte, false);

			AddRegistrAndValueSection(ctx, regEFX, osWord, ~flags);
			AddVMCommand(ctx, cmAdd, otNone, osWord, false);
			AddVMCommand(ctx, cmPop, otRegistr, osWord, regEFX);
			break;

		case cmXchg:
			if ((operand_[0].type | operand_[1].type) & otMemory) {
				i = (operand_[0].type & otMemory) ? 0 : 1;
				CompileOperand(ctx, 1 - i);
				CompileOperand(ctx, i, coAsPointer);
				AddVMCommand(ctx, cmXchg, otMemory, operand_[0].size, operand_[i].effective_base_segment(base_segment_));
				CompileOperand(ctx, 1 - i, coSaveResult);
			}
			else {
				operand = &operand_[1];
				if (operand->type == otRegistr && operand->size > osByte && operand->registr == regESP) {
					CompileOperand(ctx, 0);
					CompileOperand(ctx, 1);
					CompileOperand(ctx, 0, coSaveResult);
					CompileOperand(ctx, 1, coSaveResult);
				}
				else {
					CompileOperand(ctx, 1);
					CompileOperand(ctx, 0);
					CompileOperand(ctx, 1, coSaveResult);
					CompileOperand(ctx, 0, coSaveResult);
				}
			}
			break;

		case cmFnop: case cmNop:
			// do nothing
			break;

		case cmClc:
			AddRegistrAndValueSection(ctx, regEFX, size_, ~fl_C);
			AddVMCommand(ctx, cmPop, otRegistr, size_, regEFX);
			break;

		case cmStc:
			AddRegistrOrValueSection(ctx, regEFX, size_, fl_C);
			AddVMCommand(ctx, cmPop, otRegistr, size_, regEFX);
			break;

		case cmCmc:
			AddVMCommand(ctx, cmPush, otRegistr, size_, regEFX);
			AddVMCommand(ctx, cmPush, otRegistr, size_, regEFX);
			AddVMCommand(ctx, cmNor, otNone, size_, false);

			AddVMCommand(ctx, cmPush, otValue, size_, ~fl_C);
			AddVMCommand(ctx, cmNor, otNone, size_, false);

			AddVMCommand(ctx, cmPush, otRegistr, size_, regEFX);
			AddVMCommand(ctx, cmPush, otValue, size_, fl_C);
			AddVMCommand(ctx, cmNor, otNone, size_, false);

			AddVMCommand(ctx, cmNor, otNone, size_, false);

			AddVMCommand(ctx, cmPop, otRegistr, size_, regEFX);
			break;

		case cmCld:
			AddRegistrAndValueSection(ctx, regEFX, size_, ~fl_D);
			AddVMCommand(ctx, cmPop, otRegistr, size_, regEFX);
			AddRegistrAndValueSection(ctx, regEFX, size_, ~0x8ff);
			AddVMCommand(ctx, cmPopf, otNone, size_, false);
			break;

		case cmStd:
			AddRegistrOrValueSection(ctx, regEFX, size_, fl_D);
			AddVMCommand(ctx, cmPop, otRegistr, size_, regEFX);
			AddRegistrAndValueSection(ctx, regEFX, size_, ~0x8ff);
			AddVMCommand(ctx, cmPopf, otNone, size_, false);
			break;

		case cmBswap:
			switch (operand_[0].size) {
			case osWord:
				AddVMCommand(ctx, cmPush, otValue, osWord, 0);
				CompileOperand(ctx, 0, coSaveResult);
				break;
			case osDWord:
				AddVMCommand(ctx, cmPush, otValue, osWord, 8);
				CompileOperand(ctx, 0);
				AddVMCommand(ctx, cmPop, otRegistr, osWord, regETX);
				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otMemory, osWord, segSS);
				AddVMCommand(ctx, cmShl, otNone, osDWord, false);

				AddVMCommand(ctx, cmPush, otValue, osWord, 8);
				AddVMCommand(ctx, cmPush, otRegistr, osWord, regETX);
				AddVMCommand(ctx, cmPush, otRegistr, osWord, regETX);
				AddVMCommand(ctx, cmShl, otNone, osDWord, false);
				AddVMCommand(ctx, cmPop, otRegistr, osWord, regEmpty);

				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otValue, size_, 4);
				AddVMCommand(ctx, cmAdd, otNone, size_, false);
				AddVMCommand(ctx, cmPush, otMemory, osWord, segSS);

				CompileOperand(ctx, 0, coSaveResult);

				AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);
				break;
			case osQWord:
				AddVMCommand(ctx, cmPush, otValue, osWord, 8);
				CompileOperand(ctx, 0);
				AddVMCommand(ctx, cmPop, otRegistr, osDWord, regETX);
				AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);
				AddVMCommand(ctx, cmPush, otRegistr, osDWord, regETX);
				AddVMCommand(ctx, cmPop, otRegistr, osWord, regEmpty);
				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otMemory, osWord, segSS);
				AddVMCommand(ctx, cmShl, otNone, osDWord, false);

				AddVMCommand(ctx, cmPush, otValue, osWord, 8);
				AddVMCommand(ctx, cmPush, otRegistr, osWord, regETX);
				AddVMCommand(ctx, cmPush, otRegistr, osWord, regETX);
				AddVMCommand(ctx, cmShl, otNone, osDWord, false);
				AddVMCommand(ctx, cmPop, otRegistr, osWord, regEmpty);

				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otValue, size_, 4);
				AddVMCommand(ctx, cmAdd, otNone, size_, false);
				AddVMCommand(ctx, cmPush, otMemory, osWord, segSS);

				AddVMCommand(ctx, cmPush, otValue, osWord, 8);
				CompileOperand(ctx, 0);
				AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);
				AddVMCommand(ctx, cmPop, otRegistr, osWord, regETX);
				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otMemory, osWord, segSS);
				AddVMCommand(ctx, cmShl, otNone, osDWord, false);

				AddVMCommand(ctx, cmPush, otValue, osWord, 8);
				AddVMCommand(ctx, cmPush, otRegistr, osWord, regETX);
				AddVMCommand(ctx, cmPush, otRegistr, osWord, regETX);
				AddVMCommand(ctx, cmShl, otNone, osDWord, false);
				AddVMCommand(ctx, cmPop, otRegistr, osWord, regEmpty);

				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otValue, size_, 4);
				AddVMCommand(ctx, cmAdd, otNone, size_, false);
				AddVMCommand(ctx, cmPush, otMemory, osWord, segSS);

				AddVMCommand(ctx, cmPop, otRegistr, osDWord, regETX);
				AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);
				AddVMCommand(ctx, cmPush, otRegistr, osDWord, regETX);
				CompileOperand(ctx, 0, coSaveResult);
				AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);
				break;
			}
			break;

		case cmFstsw:
			operand = &operand_[0];
			if (operand->type == (otMemory | otBaseRegistr) && operand->base_registr == regESP) {
				AddVMCommand(ctx, cmFstsw, otNone, osWord, 0);
			}
			else {
				AddVMCommand(ctx, cmPush, otRegistr, osWord, regEmpty);
				AddVMCommand(ctx, cmFstsw, otNone, osWord, 0);
				CompileOperand(ctx, 0, coSaveResult);
			}
			break;

		case cmFldcw:
			operand = &operand_[0];
			if (operand->type == (otMemory | otBaseRegistr) && operand->base_registr == regESP) {
				AddVMCommand(ctx, cmFldcw, otNone, osWord, 0);
			}
			else {
				CompileOperand(ctx, 0);
				AddVMCommand(ctx, cmFldcw, otNone, osWord, 0);
				AddVMCommand(ctx, cmPop, otRegistr, osWord, regEmpty);
			}
			break;

		case cmFstcw:
			operand = &operand_[0];
			if (operand->type == (otMemory | otBaseRegistr) && operand->base_registr == regESP) {
				AddVMCommand(ctx, cmFstcw, otNone, osWord, 0);
			}
			else {
				AddVMCommand(ctx, cmPush, otRegistr, osWord, regEmpty);
				AddVMCommand(ctx, cmFstcw, otNone, osWord, 0);
				CompileOperand(ctx, 0, coSaveResult);
			}
			break;

		case cmImul: case cmMul:
			os = operand_[0].size;

			if (operand_[2].type != otNone) {
				CompileOperand(ctx, 2);
				CompileOperand(ctx, 1);
			}
			else if (operand_[1].type != otNone) {
				CompileOperand(ctx, 1);
				CompileOperand(ctx, 0);
			}
			else {
				CompileOperand(ctx, 0);
				AddVMCommand(ctx, cmPush, otRegistr, os, regEAX);
			}

			AddVMCommand(ctx, type_, otNone, os, true);
			AddVMCommand(ctx, cmPop, otRegistr, size_, save_flags ? regEIX : regEmpty);

			if (operand_[1].type != otNone) {
				if (os > osByte)
					AddVMCommand(ctx, cmPop, otRegistr, os, regEmpty);
				CompileOperand(ctx, 0, coSaveResult);
			}
			else if (os == osByte) {
				AddVMCommand(ctx, cmPop, otRegistr, osWord, regEAX);
			}
			else {
				AddVMCommand(ctx, cmPop, otRegistr, os, regEDX);
				AddVMCommand(ctx, cmPop, otRegistr, os, regEAX);
				if (size_ == osQWord && os == osDWord) {
					AddVMCommand(ctx, cmPush, otValue, osDWord, 0);
					AddVMCommand(ctx, cmPop, otHiPartRegistr, osDWord, regEAX);
					AddVMCommand(ctx, cmPush, otValue, osDWord, 0);
					AddVMCommand(ctx, cmPop, otHiPartRegistr, osDWord, regEDX);
				}
			}

			if (save_flags)
				AddCombineFlagsSection(ctx, fl_S | fl_Z | fl_A | fl_P);
			break;

		case cmDiv: case cmIdiv:
			os = operand_[0].size;

			CompileOperand(ctx, 0);
			if (os == osByte) {
				AddVMCommand(ctx, cmPush, otRegistr, osWord, regEAX);
			}
			else {
				AddVMCommand(ctx, cmPush, otRegistr, os, regEAX);
				AddVMCommand(ctx, cmPush, otRegistr, os, regEDX);
			}

			AddVMCommand(ctx, type_, otNone, os, true);
			AddVMCommand(ctx, cmPop, otRegistr, size_, save_flags ? regEFX : regEmpty);

			if (os == osByte) {
				AddVMCommand(ctx, cmPop, otRegistr, osWord, regEAX);
			}
			else {
				AddVMCommand(ctx, cmPop, otRegistr, os, regEDX);
				AddVMCommand(ctx, cmPop, otRegistr, os, regEAX);
			}

			if (size_ == osQWord && os == osDWord) {
				AddVMCommand(ctx, cmPush, otValue, osDWord, 0);
				AddVMCommand(ctx, cmPop, otHiPartRegistr, osDWord, regEAX);
				AddVMCommand(ctx, cmPush, otValue, osDWord, 0);
				AddVMCommand(ctx, cmPop, otHiPartRegistr, osDWord, regEDX);
			}
			break;

		case cmJmpWithFlag: case cmJCXZ: case cmLoop: case cmLoope: case cmLoopne:
			AddJmpWithFlagSection(ctx, type_);
			if (section_options_ & rtLinkedNext) {
				AddBeginSection(ctx, voLinkCommand | voUseEndSectionCryptor);
				AddVMCommand(ctx, cmPush, otValue, size_, 0, voLinkCommand | voFixup);
				AddEndSection(ctx, cmJmp, 0, voUseEndSectionCryptor);
			}
			else {
				AddBeginSection(ctx, voLinkCommand | voUseEndSectionCryptor);
				AddVMCommand(ctx, cmPush, otValue, size_, address() + original_dump_size(), voFixup);
				AddEndSection(ctx, cmRet);
			}
			if (section_options_ & rtLinkedFrom) {
				AddBeginSection(ctx, voLinkCommand | voUseEndSectionCryptor);
				AddVMCommand(ctx, cmPush, otValue, size_, 0, voLinkCommand | voFixup);
				AddEndSection(ctx, cmJmp, 0, voUseEndSectionCryptor);
			}
			else {
				AddBeginSection(ctx, voLinkCommand | voUseEndSectionCryptor);
				AddCorrectOperandSizeSection(ctx, operand_[0].size, size_);
				CompileOperand(ctx, 0, coFixup);
				AddEndSection(ctx, cmRet);
			}
			break;

		case cmJmp:
			CompileOperand(ctx, 1, coAsPointer);

			operand = &operand_[0];
			if ((options() & roFar) && (operand->type & otMemory)) {
				CompileOperand(ctx, 0, coAsPointer);
				AddVMCommand(ctx, cmPop, otRegistr, size_, regETX);

				AddVMCommand(ctx, cmPush, otValue, size_, OperandSizeToValue(size_));
				AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
				AddVMCommand(ctx, cmAdd, otNone, size_, false);
				AddVMCommand(ctx, cmPush, otMemory, size_, operand->effective_base_segment(base_segment_));

				AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
				AddVMCommand(ctx, cmPush, otMemory, size_, operand->effective_base_segment(base_segment_));
			}
			else {
				AddCorrectOperandSizeSection(ctx, operand->size, size_);
				CompileOperand(ctx, 0, ((options() & roFar) || operand->type != otValue) ? 0 : coFixup);
			}

			if (section_options_ & rtLinkedFrom) {
				AddEndSection(ctx, cmJmp, (options() & roExternal) ? 0xff : 0, voUseEndSectionCryptor);
			}
			else {
				AddEndSection(ctx, cmRet, (options() & roFar) != 0);
			}
			break;

		case cmCall:
			if ((options() & roInternal) && (section_options_ & rtLinkedFrom) == 0) {
				uint8_t arg_count = static_cast<uint32_t>(operand_[2].value);
				switch (ctx.file->calling_convention()) {
				case ccMSx64:
					if (arg_count > 3)
						AddVMCommand(ctx, cmPush, otRegistr, size_, regR9);
					if (arg_count > 2)
						AddVMCommand(ctx, cmPush, otRegistr, size_, regR8);
					if (arg_count > 1)
						AddVMCommand(ctx, cmPush, otRegistr, size_, regEDX);
					if (arg_count > 0)
						AddVMCommand(ctx, cmPush, otRegistr, size_, regECX);
					break;
				case ccABIx64:
					if (arg_count > 5)
						AddVMCommand(ctx, cmPush, otRegistr, size_, regR9);
					if (arg_count > 4)
						AddVMCommand(ctx, cmPush, otRegistr, size_, regR8);
					if (arg_count > 3)
						AddVMCommand(ctx, cmPush, otRegistr, size_, regECX);
					if (arg_count > 2)
						AddVMCommand(ctx, cmPush, otRegistr, size_, regEDX);
					if (arg_count > 1)
						AddVMCommand(ctx, cmPush, otRegistr, size_, regESI);
					if (arg_count > 0)
						AddVMCommand(ctx, cmPush, otRegistr, size_, regEDI);
					break;
				}
			}
			else {
				if (options() & roFar) {
					AddCorrectOperandSizeSection(ctx, osWord, size_);
					AddVMCommand(ctx, cmPush, otSegmentRegistr, osWord, segCS);
				}
				AddVMCommand(ctx, cmPush, otValue, size_, 0, voLinkCommand | voFixup);
				CompileOperand(ctx, 1, coAsPointer);
			}

			operand = &operand_[0];
			if ((options() & roFar) && (operand->type & otMemory)) {
				CompileOperand(ctx, 0, coAsPointer);
				AddVMCommand(ctx, cmPop, otRegistr, size_, regETX);

				AddVMCommand(ctx, cmPush, otValue, size_, OperandSizeToValue(size_));
				AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
				AddVMCommand(ctx, cmAdd, otNone, size_, false);
				AddVMCommand(ctx, cmPush, otMemory, size_, operand->effective_base_segment(base_segment_));

				AddVMCommand(ctx, cmPush, otRegistr, size_, regETX);
				AddVMCommand(ctx, cmPush, otMemory, size_, operand->effective_base_segment(base_segment_));
			}
			else {
				AddCorrectOperandSizeSection(ctx, operand->size, size_);
				CompileOperand(ctx, 0, ((options() & roFar) || operand->type != otValue) ? 0 : coFixup);
			}

			if (section_options_ & rtLinkedFrom) {
				AddStoreExtRegistersSection(ctx);
				AddEndSection(ctx, cmJmp, (options() & roExternal) ? 0xff : 0, voUseEndSectionCryptor);
			}
			else if (options() & roInternal) {
				if (ctx.options.flags & cpCheckDebugger)
					AddCheckBreakpointSection(ctx, size_);
				if (ctx.options.flags & cpMemoryProtection)
					AddCheckCRCSection(ctx, size_);
				AddVMCommand(ctx, cmCall, otNone, size_, operand_[2].value);
				AddVMCommand(ctx, cmPop, otRegistr, size_, regEAX);
			}
			else {
				AddEndSection(ctx, cmRet, (options() & roFar) != 0);
			}
			break;

		case cmSyscall:
		{
			uint8_t arg_count = static_cast<uint32_t>(operand_[2].value);
			switch (ctx.file->calling_convention()) {
			case ccMSx64:
				if (arg_count > 3)
					AddVMCommand(ctx, cmPush, otRegistr, size_, regR9);
				if (arg_count > 2)
					AddVMCommand(ctx, cmPush, otRegistr, size_, regR8);
				if (arg_count > 1)
					AddVMCommand(ctx, cmPush, otRegistr, size_, regEDX);
				if (arg_count > 0)
					AddVMCommand(ctx, cmPush, otRegistr, size_, regECX);
				break;
			}
		}
		CompileOperand(ctx, 0);
		AddVMCommand(ctx, cmSyscall, otNone, size_, operand_[2].value);
		AddVMCommand(ctx, cmPop, otRegistr, size_, regEAX);
		break;

		case cmCmov:
			AddJmpWithFlagSection(ctx, cmJmpWithFlag);
			AddBeginSection(ctx, voLinkCommand | voUseEndSectionCryptor);
			CompileOperand(ctx, 1);
			CompileOperand(ctx, 0, coSaveResult);

			if (section_options_ & rtLinkedNext) {
				AddVMCommand(ctx, cmPush, otValue, size_, 0, voLinkCommand | voFixup);
				AddEndSection(ctx, cmJmp, 0, voUseEndSectionCryptor);

				AddBeginSection(ctx, voLinkCommand | voUseEndSectionCryptor);
				AddVMCommand(ctx, cmPush, otValue, size_, 0, voLinkCommand | voFixup);
				AddEndSection(ctx, cmJmp, 0, voUseEndSectionCryptor);
			}
			else {
				AddVMCommand(ctx, cmPush, otValue, size_, address() + original_dump_size(), voFixup);
				AddEndSection(ctx, cmRet);

				AddBeginSection(ctx, voLinkCommand | voUseEndSectionCryptor);
				AddVMCommand(ctx, cmPush, otValue, size_, address() + original_dump_size(), voFixup);
				AddEndSection(ctx, cmRet);
			}
			break;

		case cmLods: case cmStos: case cmScas: case cmMovs: case cmCmps: case cmIns: case cmOuts:
			os = operand_[0].size;
			adr_os = operand_[1].size;
			value = OperandSizeToValue(os);

			if (preffix_command_ == cmRep || preffix_command_ == cmRepe || preffix_command_ == cmRepne) {
				if ((section_options_ & rtBeginSection) == 0)
					AddBeginSection(ctx, voUseBeginSectionCryptor);
				AddJmpWithFlagSection(ctx, cmJCXZ);
				AddBeginSection(ctx, voLinkCommand | voUseEndSectionCryptor);
			}

			switch (type_) {
			case cmLods:
				AddCorrectOperandSizeSection(ctx, adr_os, size_);
				AddVMCommand(ctx, cmPush, otRegistr, adr_os, regESI);
				AddVMCommand(ctx, cmPush, otMemory, os, base_segment_ == segDefault ? segDS : base_segment_);

				AddVMCommand(ctx, cmPop, otRegistr, os, regEAX);
				if (size_ == osQWord && os == osDWord) {
					AddVMCommand(ctx, cmPush, otValue, osDWord, 0);
					AddVMCommand(ctx, cmPop, otHiPartRegistr, osDWord, regEAX);
				}
				break;

			case cmStos:
				AddCorrectOperandSizeSection(ctx, adr_os, size_);
				AddVMCommand(ctx, cmPush, otRegistr, os, regEAX);
				AddVMCommand(ctx, cmPush, otRegistr, adr_os, regEDI);
				AddVMCommand(ctx, cmPop, otMemory, os, segES);
				break;

			case cmMovs:
				AddCorrectOperandSizeSection(ctx, adr_os, size_);
				AddVMCommand(ctx, cmPush, otRegistr, adr_os, regESI);
				AddVMCommand(ctx, cmPush, otMemory, os, base_segment_ == segDefault ? segDS : base_segment_);

				AddCorrectOperandSizeSection(ctx, adr_os, size_);
				AddVMCommand(ctx, cmPush, otRegistr, adr_os, regEDI);
				AddVMCommand(ctx, cmPop, otMemory, os, segES);
				break;

			case cmScas:
				AddCorrectOperandSizeSection(ctx, adr_os, size_);
				AddVMCommand(ctx, cmPush, otRegistr, adr_os, regEDI);
				AddVMCommand(ctx, cmPush, otMemory, os, segES);

				AddVMCommand(ctx, cmPush, otRegistr, os, regEAX);
				AddVMCommand(ctx, cmPush, otRegistr, os, regEAX);
				AddVMCommand(ctx, cmNor, otNone, os, false);

				AddVMCommand(ctx, cmAdd, otNone, os, true);
				AddVMCommand(ctx, cmPop, otRegistr, size_, regEFX);

				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otMemory, os, segSS);
				AddVMCommand(ctx, cmNor, otNone, os, true);
				AddVMCommand(ctx, cmPop, otRegistr, size_, regEIX);

				AddVMCommand(ctx, cmPop, otRegistr, os, regEmpty);

				AddCombineFlagsSection(ctx, fl_P | fl_O | fl_A | fl_C);
				break;

			case cmCmps:
				AddCorrectOperandSizeSection(ctx, adr_os, size_);
				AddVMCommand(ctx, cmPush, otRegistr, adr_os, regESI);
				AddVMCommand(ctx, cmPush, otMemory, os, base_segment_ == segDefault ? segDS : base_segment_);

				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otMemory, os, segSS);
				AddVMCommand(ctx, cmNor, otNone, os, false);

				AddCorrectOperandSizeSection(ctx, adr_os, size_);
				AddVMCommand(ctx, cmPush, otRegistr, adr_os, regEDI);
				AddVMCommand(ctx, cmPush, otMemory, os, segES);

				AddVMCommand(ctx, cmAdd, otNone, os, true);
				AddVMCommand(ctx, cmPop, otRegistr, size_, regEFX);

				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otMemory, os, segSS);
				AddVMCommand(ctx, cmNor, otNone, os, true);
				AddVMCommand(ctx, cmPop, otRegistr, size_, regEIX);

				AddVMCommand(ctx, cmPop, otRegistr, os, regEmpty);

				AddCombineFlagsSection(ctx, fl_P | fl_O | fl_A | fl_C);
				break;

			case cmIns:
				AddCorrectOperandSizeSection(ctx, adr_os, size_);

				AddVMCommand(ctx, cmPush, otRegistr, osWord, regEDX);
				AddVMCommand(ctx, cmIn, otNone, os, 0);

				AddVMCommand(ctx, cmPush, otRegistr, adr_os, regEDI);
				AddVMCommand(ctx, cmPop, otMemory, os, segES);
				break;

			case cmOuts:
				AddCorrectOperandSizeSection(ctx, adr_os, size_);

				AddVMCommand(ctx, cmPush, otRegistr, adr_os, regESI);
				AddVMCommand(ctx, cmPush, otMemory, os, base_segment_ == segDefault ? segDS : base_segment_);

				AddVMCommand(ctx, cmPush, otRegistr, osWord, regEDX);
				AddVMCommand(ctx, cmOut, otNone, os, 0);
				break;
			}

			AddExtractFlagSection(ctx, fl_D, true, (uint8_t)(value << 1));

			if (adr_os != size_) {
				AddVMCommand(ctx, cmPop, otRegistr, size_, regETX);
				AddVMCommand(ctx, cmPush, otRegistr, adr_os, regETX);
			}
			AddVMCommand(ctx, cmPush, otValue, adr_os, 0 - value);
			AddVMCommand(ctx, cmAdd, otNone, adr_os, false);

			switch (type_) {
			case cmLods: case cmOuts:
				AddVMCommand(ctx, cmPush, otRegistr, adr_os, regESI);
				AddVMCommand(ctx, cmAdd, otNone, adr_os, false);
				AddVMCommand(ctx, cmPop, otRegistr, adr_os, regESI);
				break;

			case cmStos: case cmScas: case cmIns:
				AddVMCommand(ctx, cmPush, otRegistr, adr_os, regEDI);
				AddVMCommand(ctx, cmAdd, otNone, adr_os, false);
				AddVMCommand(ctx, cmPop, otRegistr, adr_os, regEDI);
				break;

			case cmMovs: case cmCmps:
				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otMemory, adr_os, segSS);

				AddVMCommand(ctx, cmPush, otRegistr, adr_os, regESI);
				AddVMCommand(ctx, cmAdd, otNone, adr_os, false);
				AddVMCommand(ctx, cmPop, otRegistr, adr_os, regESI);

				AddVMCommand(ctx, cmPush, otRegistr, adr_os, regEDI);
				AddVMCommand(ctx, cmAdd, otNone, adr_os, false);
				AddVMCommand(ctx, cmPop, otRegistr, adr_os, regEDI);
				break;
			}

			if (preffix_command_ == cmRep || preffix_command_ == cmRepe || preffix_command_ == cmRepne) {
				AddJmpWithFlagSection(ctx, (type_ == cmScas || type_ == cmCmps) ? preffix_command_ : cmRep);
				if ((section_options_ & rtLinkedNext) == 0) {
					AddBeginSection(ctx, voLinkCommand | voUseEndSectionCryptor);
					AddVMCommand(ctx, cmPush, otValue, size_, address() + original_dump_size(), voFixup);
					AddEndSection(ctx, cmRet);
				}
			}
			break;

		case cmRet:
			operand = &operand_[0];
			if (operand->type == otValue) {
				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otMemory, size_, segSS);

				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otValue, size_, operand->value + OperandSizeToStack(size_));
				AddVMCommand(ctx, cmAdd, otNone, size_, false);
				AddVMCommand(ctx, cmPop, otMemory, size_, segSS);

				if (options() & roFar) {
					AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
					AddVMCommand(ctx, cmPush, otValue, size_, OperandSizeToStack(size_));
					AddVMCommand(ctx, cmAdd, otNone, size_, false);
					AddVMCommand(ctx, cmPush, otMemory, size_, segSS);

					AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
					AddVMCommand(ctx, cmPush, otValue, size_, operand->value + OperandSizeToStack(size_) * 2);
					AddVMCommand(ctx, cmAdd, otNone, size_, false);
					AddVMCommand(ctx, cmPop, otMemory, size_, segSS);
				}

				switch (operand->value) {
				case 2:
					AddVMCommand(ctx, cmPop, otRegistr, osWord, regEmpty);
					break;
				case 4:
					AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);
					break;
				case 8:
					AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);
					AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);
					break;
				case 10:
					AddVMCommand(ctx, cmPop, otRegistr, osWord, regEmpty);
					AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);
					AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);
					break;
				case 12:
					AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);
					AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);
					AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);
					break;
				default:
					AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
					AddVMCommand(ctx, cmPush, otValue, size_, operand->value);
					AddVMCommand(ctx, cmAdd, otNone, size_, false);
					AddVMCommand(ctx, cmPop, otRegistr, size_, regESP);
					break;
				}
			}
			if (options() & roInternal) {
				AddEndSection(ctx, cmJmp, 0);
			}
			else {
				AddEndSection(ctx, cmRet, (options() & roFar) ? 1 : 0);
			}
			break;

		case cmIret:
			AddEndSection(ctx, cmIret);
			break;

		case cmLeave:
			AddVMCommand(ctx, cmPush, otRegistr, size_, regEBP);
			AddVMCommand(ctx, cmPop, otRegistr, size_, regESP);
			AddVMCommand(ctx, cmPop, otRegistr, size_, regEBP);
			break;

		case cmLes: case cmLds: case cmLfs: case cmLgs:
			os = operand_[0].size;
			CompileOperand(ctx, 1, coAsPointer);

			AddVMCommand(ctx, cmPush, otRegistr, osDWord, regESP);
			AddVMCommand(ctx, cmPush, otMemory, osDWord, segSS);
			AddVMCommand(ctx, cmPush, otValue, osDWord, OperandSizeToStack(os));
			AddVMCommand(ctx, cmAdd, otNone, osDWord, false);

			AddVMCommand(ctx, cmPush, otMemory, osWord, operand_[1].effective_base_segment(base_segment_));

			switch (type_) {
			case cmLes:
				AddVMCommand(ctx, cmPop, otSegmentRegistr, osWord, segES);
				break;
			case cmLds:
				AddVMCommand(ctx, cmPop, otSegmentRegistr, osWord, segDS);
				break;
			case cmLfs:
				AddVMCommand(ctx, cmPop, otSegmentRegistr, osWord, segFS);
				break;
			case cmLgs:
				AddVMCommand(ctx, cmPop, otSegmentRegistr, osWord, segGS);
				break;
			}

			AddVMCommand(ctx, cmPush, otMemory, os, operand_[1].effective_base_segment(base_segment_));
			CompileOperand(ctx, 0, coSaveResult);
			break;

		case cmRdtsc:
			AddVMCommand(ctx, cmRdtsc, otNone, size_, 0);
			AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEDX);
			AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEAX);

			if (size_ == osQWord) {
				AddVMCommand(ctx, cmPush, otValue, osDWord, 0);
				AddVMCommand(ctx, cmPop, otHiPartRegistr, osDWord, regEAX);
				AddVMCommand(ctx, cmPush, otValue, osDWord, 0);
				AddVMCommand(ctx, cmPop, otHiPartRegistr, osDWord, regEDX);
			}
			break;

		case cmCpuid:
			AddVMCommand(ctx, cmPush, otRegistr, osDWord, regEAX);
			AddVMCommand(ctx, cmCpuid, otNone, size_, 0);
			AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEDX);
			AddVMCommand(ctx, cmPop, otRegistr, osDWord, regECX);
			AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEBX);
			AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEAX);

			if (size_ == osQWord) {
				AddVMCommand(ctx, cmPush, otValue, osDWord, 0);
				AddVMCommand(ctx, cmPop, otHiPartRegistr, osDWord, regEAX);
				AddVMCommand(ctx, cmPush, otValue, osDWord, 0);
				AddVMCommand(ctx, cmPop, otHiPartRegistr, osDWord, regEBX);
				AddVMCommand(ctx, cmPush, otValue, osDWord, 0);
				AddVMCommand(ctx, cmPop, otHiPartRegistr, osDWord, regECX);
				AddVMCommand(ctx, cmPush, otValue, osDWord, 0);
				AddVMCommand(ctx, cmPop, otHiPartRegistr, osDWord, regEDX);
			}
			break;

		case cmF2xm1: case cmFabs: case cmFclex: case cmFcos: case cmFdecstp: case cmFincstp:
		case cmFinit: case cmFldln2: case cmFldlg2: case cmFprem: case cmFprem1: case cmFptan:
		case cmFrndint: case cmFsin: case cmFtst: case cmFyl2x: case cmFpatan: case cmFldz: case cmFld1:
		case cmFldpi: case cmWait: case cmFchs: case cmFsqrt:
			AddVMCommand(ctx, type_, otNone, size_, 0);
			break;

		case cmFistp: case cmFist: case cmFstp: case cmFst:
			os = operand_[0].size;
			operand = &operand_[0];

			if (operand->type == (otMemory | otBaseRegistr) && operand->base_registr == regESP) {
				AddVMCommand(ctx, type_, otNone, os, 0);
			}
			else {
				switch (os) {
				case osWord:
					AddVMCommand(ctx, cmPush, otRegistr, osWord, regEmpty);
					break;
				case osDWord:
					AddVMCommand(ctx, cmPush, otRegistr, osDWord, regEmpty);
					break;
				case osQWord:
					if (size_ == osQWord) {
						AddVMCommand(ctx, cmPush, otRegistr, osQWord, regEmpty);
					}
					else {
						AddVMCommand(ctx, cmPush, otRegistr, osDWord, regEmpty);
						AddVMCommand(ctx, cmPush, otRegistr, osDWord, regEmpty);
					}
					break;
				case osTByte:
					if (size_ == osQWord) {
						AddVMCommand(ctx, cmPush, otRegistr, osQWord, regEmpty);
					}
					else {
						AddVMCommand(ctx, cmPush, otRegistr, osDWord, regEmpty);
						AddVMCommand(ctx, cmPush, otRegistr, osDWord, regEmpty);
					}
					AddVMCommand(ctx, cmPush, otRegistr, osWord, regEmpty);
					break;
				}

				AddVMCommand(ctx, type_, otNone, os, 0);
				CompileOperand(ctx, 0, coAsPointer);

				IntelSegment base_segment = operand->effective_base_segment(base_segment_);
				switch (os) {
				case osWord:
					AddVMCommand(ctx, cmPop, otMemory, osWord, base_segment);
					break;
				case osDWord:
					AddVMCommand(ctx, cmPop, otMemory, osDWord, base_segment);
					break;
				case osQWord:
					if (size_ == osQWord) {
						AddVMCommand(ctx, cmPop, otMemory, osQWord, base_segment);
					}
					else {
						AddVMCommand(ctx, cmPop, otMemory, osDWord, base_segment);
						CompileOperand(ctx, 0, coAsPointer);
						AddVMCommand(ctx, cmPush, otValue, size_, OperandSizeToValue(osDWord));
						AddVMCommand(ctx, cmAdd, otNone, size_, false);
						AddVMCommand(ctx, cmPop, otMemory, osDWord, base_segment);
					}
					break;
				case osTByte:
					if (size_ == osQWord) {
						AddVMCommand(ctx, cmPop, otMemory, osQWord, base_segment);
					}
					else {
						AddVMCommand(ctx, cmPop, otMemory, osDWord, base_segment);
						CompileOperand(ctx, 0, coAsPointer);
						AddVMCommand(ctx, cmPush, otValue, size_, OperandSizeToValue(osDWord));
						AddVMCommand(ctx, cmAdd, otNone, size_, false);
						AddVMCommand(ctx, cmPop, otMemory, osDWord, base_segment);
					}
					CompileOperand(ctx, 0, coAsPointer);
					AddVMCommand(ctx, cmPush, otValue, size_, OperandSizeToValue(osQWord));
					AddVMCommand(ctx, cmAdd, otNone, size_, false);
					AddVMCommand(ctx, cmPop, otMemory, osWord, base_segment);
					break;
				}
			}
			break;

		case cmFadd: case cmFsub: case cmFisub: case cmFsubr: case cmFdiv: case cmFmul: case cmFcomp:
		case cmFild: case cmFld:
			os = operand_[0].size;
			operand = &operand_[0];

			if (operand->type == (otMemory | otBaseRegistr) && operand->base_registr == regESP) {
				AddVMCommand(ctx, type_, otNone, os, 0);
			}
			else {
				CompileOperand(ctx, 0, coAsPointer);

				IntelSegment base_segment = operand->effective_base_segment(base_segment_);
				switch (os) {
				case osWord:
					AddVMCommand(ctx, cmPush, otMemory, osWord, base_segment);
					break;
				case osDWord:
					AddVMCommand(ctx, cmPush, otMemory, osDWord, base_segment);
					break;
				case osQWord:
					if (size_ == osQWord) {
						AddVMCommand(ctx, cmPush, otMemory, osQWord, base_segment);
					}
					else {
						AddVMCommand(ctx, cmPush, otValue, size_, OperandSizeToValue(osDWord));
						AddVMCommand(ctx, cmAdd, otNone, size_, false);
						AddVMCommand(ctx, cmPush, otMemory, osDWord, base_segment);
						CompileOperand(ctx, 0, coAsPointer);
						AddVMCommand(ctx, cmPush, otMemory, osDWord, base_segment);
					}
					break;
				case osTByte:
					AddVMCommand(ctx, cmPush, otValue, size_, OperandSizeToValue(osQWord));
					AddVMCommand(ctx, cmAdd, otNone, size_, false);
					AddVMCommand(ctx, cmPush, otMemory, osWord, base_segment);
					CompileOperand(ctx, 0, coAsPointer);
					if (size_ == osQWord) {
						AddVMCommand(ctx, cmPush, otMemory, osQWord, base_segment);
					}
					else {
						AddVMCommand(ctx, cmPush, otValue, size_, OperandSizeToValue(osDWord));
						AddVMCommand(ctx, cmAdd, otNone, size_, false);
						AddVMCommand(ctx, cmPush, otMemory, osDWord, base_segment);
						CompileOperand(ctx, 0, coAsPointer);
						AddVMCommand(ctx, cmPush, otMemory, osDWord, base_segment);
					}
					break;
				}

				AddVMCommand(ctx, type_, otNone, os, 0);

				switch (os) {
				case osWord:
					AddVMCommand(ctx, cmPop, otRegistr, osWord, regEmpty);
					break;
				case osDWord:
					AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);
					break;
				case osQWord:
					if (size_ == osQWord) {
						AddVMCommand(ctx, cmPop, otRegistr, osQWord, regEmpty);
					}
					else {
						AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);
						AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);
					}
					break;
				case osTByte:
					if (size_ == osQWord) {
						AddVMCommand(ctx, cmPop, otRegistr, osQWord, regEmpty);
					}
					else {
						AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);
						AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEmpty);
					}
					AddVMCommand(ctx, cmPop, otRegistr, osWord, regEmpty);
					break;
				}
			}
			break;

		case cmCrc:
			switch (ctx.file->calling_convention()) { //-V719
			case ccStdcall:
				// do nothing
				break;
			case ccCdecl:
				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP); //-V760
				AddVMCommand(ctx, cmPush, otValue, size_, OperandSizeToStack(size_));
				AddVMCommand(ctx, cmAdd, otNone, size_, false);
				AddVMCommand(ctx, cmPush, otMemory, size_, segSS);

				AddVMCommand(ctx, cmPush, otRegistr, size_, regESP);
				AddVMCommand(ctx, cmPush, otValue, size_, OperandSizeToStack(size_));
				AddVMCommand(ctx, cmAdd, otNone, size_, false);
				AddVMCommand(ctx, cmPush, otMemory, size_, segSS);
				break;
			case ccMSx64:
				AddVMCommand(ctx, cmPush, otRegistr, size_, regEDX);
				AddVMCommand(ctx, cmPush, otRegistr, size_, regECX);
				break;
			case ccABIx64:
				AddVMCommand(ctx, cmPush, otRegistr, size_, regESI);
				AddVMCommand(ctx, cmPush, otRegistr, size_, regEDI);
				break;
			}
			AddVMCommand(ctx, cmCrc, otNone, size_, 0);
			AddVMCommand(ctx, cmPop, otRegistr, osDWord, regEAX);
			break;

		case cmDD: case cmDQ:
			operand = &operand_[0];
			AddVMCommand(ctx, type_, otValue, (type_ == cmDD) ? osDWord : osQWord, operand->value, voLinkCommand | (operand->fixup ? voFixup : voNone), operand->fixup);
			break;

		default:
			throw std::runtime_error("Runtime error at CompileToVM: " + text());
			break;
		}

	GetCommandInfo(*vm_command_info_list_);
	for (i = vm_command_info_list_->count(); i > 0; i--) {
		CommandInfo* command_info = vm_command_info_list_->item(i - 1);
		if ((command_info->operand_type() == otRegistr || command_info->operand_type() == otHiPartRegistr) && command_info->value() == regEFX)
			delete command_info;
	}
	for (i = 0; i < count(); i++) {
		IntelVMCommand* command = item(i);
		if (command->options() & voSectionCommand) {
			if (section_options() & rtBeginSection)
				continue;
			if (section_options() & rtEndSection)
				break;
		}

		switch (command->command_type()) {
		case cmPush: case cmPop:
			if ((command->operand_type() == otRegistr || command->operand_type() == otHiPartRegistr) &&
				(command->registr() == regEFX || command->registr() == regETX || command->registr() == regEIX || (command->registr() & regExtended)))
				vm_command_info_list_->Add(command->command_type() == cmPush ? atRead : atWrite, command->registr(), command->operand_type(), command->size());
			break;
		case cmCall:
			vm_command_info_list_->Add(atWrite, regEAX, otRegistr, size());
			break;
		case cmCrc:
			vm_command_info_list_->Add(atRead, regESP, otRegistr, size());
			vm_command_info_list_->Add(atWrite, regESP, otRegistr, size());
			vm_command_info_list_->Add(atWrite, regEAX, otRegistr, size());
			break;
		}
	}
}

void IntelCommand::PrepareLink(const CompileContext& ctx)
{
	bool from_native = block() && (block()->type() & mtExecutable) ? true : owner()->compilation_type() == ctMutation;

	IntelCommand* to_command = reinterpret_cast<IntelCommand*>(link()->to_command());
	if (to_command) {
		if (link()->operand_index() > -1) {
			IntelOperand* operand = &operand_[link()->operand_index()];
			if (size_ == osQWord && link()->sub_value() > ctx.file->image_base()) {
				if (link()->operand_index() == 1 && (operand->type & otMemory) && operand_[0].size == osDWord && type_ != cmMovsxd) {
					if (type_ == cmMov) {
						type_ = cmMovsxd;
						operand_[0].size = osQWord;
						CompileToNative();
					}
					else {
						throw std::runtime_error("Runtime error at PrepareLink: " + text());
					}
				}
			}
			if (operand->type & otMemory) {
				if ((operand->type & otValue) == 0) {
					operand->type |= otValue;
					operand->value = 0;
					operand->value_size = osDWord;
					CompileToNative();
				}
				else if (operand->value_size < osDWord) {
					operand->value_size = osDWord;
					CompileToNative();
				}
			}

			if ((operand->type & otValue) == 0)
				throw std::runtime_error("Runtime error at PrepareLink: " + text());
		}

		bool to_native = to_command->block() && (to_command->block()->type() & mtExecutable) ? true : to_command->owner()->compilation_type() == ctMutation;
		if (from_native == to_native) {
			section_options_ |= rtLinkedFrom;
		}
		else {
			section_options_ |= rtLinkedFromOtherType;
		}

		if ((section_options_ & rtLinkedFromOtherType)
			|| link()->type() == ltSEHBlock
			|| link()->type() == ltFinallyBlock
			|| link()->type() == ltFilterSEHBlock
			|| link()->type() == ltDualSEHBlock
			|| link()->type() == ltGateOffset
			|| link()->type() == ltMemSEHBlock
			|| link()->type() == ltExtSEHHandler
			|| link()->type() == ltVBMemSEHBlock) {
			to_command->include_section_option(rtLinkedToExt);
		}
		else {
			to_command->include_section_option(rtLinkedToInt);
		}
	}

	if (from_native)
		return;

	size_t j;
	bool need_next_command = false;
	bool need_init_cryptor = false;
	ICommand* next_command;

	switch (link()->type()) {
	case ltCall:
		if ((options() & roUseAsJmp) == 0)
			need_next_command = true;
		need_init_cryptor = true;
		break;
	case ltJmp:
		if (section_options_ & rtLinkedFrom)
			need_init_cryptor = true;
		break;
	case ltSwitch:
		if (section_options_ & rtLinkedFrom) {
			if (!end_section_cryptor_)
				need_init_cryptor = true;
		}
		break;
	case ltCase:
		if (to_command)
			need_init_cryptor = true;
		break;
	case ltNative:
		if ((options() & roBreaked) == 0 && type_ != cmJmp)
			need_next_command = true;
		break;
	case ltJmpWithFlagNSNS:
		need_next_command = true;
		need_init_cryptor = true;
		break;
	case ltJmpWithFlagNSNA:
		need_next_command = true;
		need_init_cryptor = true;
		break;
	case ltJmpWithFlagNSFS:
		include_section_option(rtLinkedToInt);
		to_command = this;
		link()->set_to_command(to_command);
		need_next_command = true;
		need_init_cryptor = true;
		break;
	case ltJmpWithFlag:
		need_next_command = true;
		need_init_cryptor = true;
		break;
	case ltDualSEHBlock:
		if (to_command) {
			j = owner()->IndexOf(to_command) + 1;
			next_command = owner()->item(j);
			link()->set_next_command(next_command);
			next_command->include_section_option(rtLinkedToExt);
		}
		break;
	}

	if (need_next_command) {
		j = owner()->IndexOf(this) + 1;
		if (j < owner()->count()) {
			next_command = owner()->item(j);
			if (owner()->is_breaked_address(next_command->address()))
				next_command = NULL;
			else {
				if (link()->type() == ltCall) {
					if (to_command != next_command) {
						include_section_option(rtLinkedNext);
						link()->set_next_command(next_command);
						next_command->include_section_option(rtLinkedToExt);
					}
				}
				else {
					include_section_option(rtLinkedNext);
					link()->set_next_command(next_command);
					next_command->include_section_option(link()->type() == ltNative ? rtLinkedToExt : rtLinkedToInt);
				}
			}
		}
	}

	if (need_init_cryptor) {
		SectionCryptorList* section_cryptor_list = reinterpret_cast<IntelFunction*>(owner())->section_cryptor_list();
		SectionCryptor* cur_section_cryptor = NULL;
		IntelCommand* save_cryptor_command = NULL;
		IntelCommand* parent_command = reinterpret_cast<IntelCommand*>(link()->parent_command());

		if (link()->type() == ltCase) {
			cur_section_cryptor = parent_command->end_section_cryptor_;
			if (!cur_section_cryptor) {
				cur_section_cryptor = section_cryptor_list->Add();
				parent_command->end_section_cryptor_ = cur_section_cryptor;
			}
			begin_section_cryptor_ = cur_section_cryptor;
			save_cryptor_command = to_command;
		}
		else {
			if (to_command) {
				if (section_options_ & rtLinkedFromOtherType) {
					if (link()->type() == ltCall) {
						cur_section_cryptor = section_cryptor_list->Add();
					}
					else {
						return;
					}
				}
				else {
					cur_section_cryptor = to_command->begin_section_cryptor_;
					if (!cur_section_cryptor && (options() & roExternal) == 0) {
						cur_section_cryptor = section_cryptor_list->Add();
						to_command->begin_section_cryptor_ = cur_section_cryptor;
					}
				}
			}
			else {
				cur_section_cryptor = section_cryptor_list->Add();
			}
			end_section_cryptor_ = cur_section_cryptor;

			if (link()->type() == ltSwitch && parent_command)
				parent_command->end_section_cryptor_ = cur_section_cryptor;

			if (link()->type() == ltSwitch && to_command && to_command->link() && to_command->link()->parent_command() != this) {
				save_cryptor_command = reinterpret_cast<IntelCommand*>(to_command->link()->parent_command());
			}
			else if (link()->type() == ltJmpWithFlag || link()->type() == ltJmpWithFlagNSNA || link()->type() == ltJmpWithFlagNSFS || link()->type() == ltJmpWithFlagNSNS) {
				save_cryptor_command = reinterpret_cast<IntelCommand*>(link()->next_command());
			}
		}

		if (save_cryptor_command) {
			if (link()->type() == ltSwitch) {
				if (save_cryptor_command->end_section_cryptor_ != cur_section_cryptor) {
					if (save_cryptor_command->end_section_cryptor_) {
						cur_section_cryptor->set_end_cryptor(save_cryptor_command->end_section_cryptor_);
					}
					else {
						save_cryptor_command->end_section_cryptor_ = cur_section_cryptor;
					}
				}
			}
			else {
				if (save_cryptor_command->begin_section_cryptor_ != cur_section_cryptor) {
					if (save_cryptor_command->begin_section_cryptor_) {
						cur_section_cryptor->set_end_cryptor(save_cryptor_command->begin_section_cryptor_);
					}
					else {
						save_cryptor_command->begin_section_cryptor_ = cur_section_cryptor;
					}
				}
			}
		}
	}
}

void IntelCommand::CompileLink(const CompileContext& ctx)
{
	size_t k;
	uint64_t value, value1;

	if (block()->type() & mtExecutable) {
		// native block
		if (!link() || link()->operand_index() == -1)
			return;

		ICommand* to_command = link()->to_command();
		if (to_command) {
			value = (to_command->block()->type() & mtExecutable) ? to_command->address() : to_command->ext_vm_address();
		}
		else if (link()->type() == ltDelta) {
			value = link()->to_address();
		}
		else {
			return;
		}

		if (link()->type() == ltDelta)
			value -= link()->parent_command() ? link()->parent_command()->address() : address();
		set_operand_value(link()->operand_index(), link()->Encrypt(value));
		CompileToNative();
	}
	else {
		// VM block
		for (size_t i = 0; i < internal_links_.count(); i++) {
			InternalLink* internal_link = internal_links_.item(i);
			IntelVMCommand* vm_command = reinterpret_cast<IntelVMCommand*>(internal_link->from_command());

			switch (internal_link->type()) {
			case vlCRCTableAddress:
				value = reinterpret_cast<IntelFunctionList*>(ctx.file->function_list())->runtime_crc_table()->entry()->address();
				break;
			case vlCRCTableCount:
				value = reinterpret_cast<IntelFunctionList*>(ctx.file->function_list())->runtime_crc_table()->region_count();
				break;
			case vlCRCValue:
			{
				IntelVMCommand* value_command = reinterpret_cast<IntelVMCommand*>(internal_link->to_command());
				uint64_t crc_value = reinterpret_cast<IntelVirtualMachineList*>(ctx.file->virtual_machine_list())->GetCRCValue(value, OperandSizeToValue(value_command->size()));
				value_command->set_sub_value(crc_value);
				value_command->Compile();
			}
			break;
			default:
			{
				IntelCommand* command = reinterpret_cast<IntelCommand*>(internal_link->to_command());
				if (!command)
					continue;

				value = command->is_data() ? command->address() : command->owner()->entry()->address();
			}
			break;
			}
			vm_command->set_value(value);
			vm_command->Compile();
		}

		if (vm_links_.empty())
			return;

		ICommand* to_command = link()->to_command();
		ICommand* next_command = link()->next_command();
		ICommand* ext_command;

		switch (link()->type()) {
		case ltSEHBlock: case ltFinallyBlock: case ltExtSEHBlock:
			if (to_command)
				set_link_value(0, link()->gate_command(0)->address());
			break;

		case ltMemSEHBlock: case ltExtSEHHandler: case ltVBMemSEHBlock:
			// do nothing
			break;

		case ltDualSEHBlock: case ltFilterSEHBlock:
			if (to_command)
				set_link_value(0, link()->gate_command(0)->address());
			break;

		case ltJmpWithFlag:
			k = next_command ? 1 : 0;

			value = vm_links_[2]->address();
			value1 = vm_links_[3 + k]->address();
			set_link_value(0, value1);
			set_link_value(1, value);

			if (next_command) {
				if (next_command->block()->virtual_machine()->id() == block()->virtual_machine()->id())
					set_link_value(1, next_command->vm_address());
				else {
					set_link_value(3, next_command->vm_address());
					set_jmp_value(1, next_command->block()->virtual_machine()->id());
				}
			}
			if (to_command) {
				if (section_options_ & rtLinkedFrom) {
					if (to_command->block()->virtual_machine()->id() == block()->virtual_machine()->id())
						set_link_value(0, to_command->vm_address());
					else {
						set_link_value(4 + k, to_command->vm_address());
						set_jmp_value(1 + k, to_command->block()->virtual_machine()->id());
					}
				}
			}
			break;

		case ltJmpWithFlagNSNS:
			value = vm_links_[2]->address();
			value1 = vm_links_[4]->address();

			set_link_value(0, value);
			set_link_value(1, value1);

			if (next_command) {
				value = next_command->vm_address();
				set_link_value(3, value);
				set_link_value(5, value);
			}
			break;

		case ltJmpWithFlagNSNA:
			value = vm_links_[2]->address();
			if (next_command) {
				value1 = vm_links_[4]->address();
			}
			else {
				value1 = vm_links_[3]->address();
			}

			set_link_value(0, value);
			set_link_value(1, value1);

			if (next_command) {
				set_link_value(3, next_command->vm_address());
				set_jmp_value(1, next_command->block()->virtual_machine()->id());
				if (next_command->block()->virtual_machine()->id() == block()->virtual_machine()->id()) {
					set_link_value(1, next_command->vm_address());
				}
				else {
					set_link_value(5, next_command->vm_address());
					set_jmp_value(2, next_command->block()->virtual_machine()->id());
				}
			}
			break;

		case ltJmpWithFlagNSFS:
			value = vm_links_[2]->address();
			if (next_command) {
				value1 = next_command->vm_address();
			}
			else {
				value1 = vm_links_[5]->address();
			}

			set_link_value(0, value1);
			set_link_value(1, value);
			set_link_value(3, value);
			set_link_value(4, value1);
			break;

		case ltJmp:
			if (to_command) {
				if (section_options_ & rtLinkedFromOtherType) {
					value = to_command->address();
				}
				else {
					value = to_command->vm_address();
					set_jmp_value(0, to_command->block()->virtual_machine()->id());
				}
				set_link_value(0, link()->Encrypt(value));
			}
			break;

		case ltCall:
			if ((options() & roInternal) && (section_options_ & rtLinkedFrom) == 0) {
				k = 0;
			}
			else {
				k = 1;
				ext_command = link()->gate_command(0);
				if (ext_command) {
					value = ext_command->address();
				}
				else if (options() & roInternal) {
					value = next_command->ext_vm_address();
				}
				else {
					value = address() + original_dump_size();
				}
				set_link_value(0, value);
			}

			if (section_options_ & rtLinkedFrom) {
				set_link_value(k, to_command->vm_address());
				set_jmp_value(0, to_command->block()->virtual_machine()->id());
			}
			else if (section_options_ & rtLinkedFromOtherType) {
				set_link_value(k, to_command->address());
			}
			break;

		case ltNative:
			set_link_value(0, link()->gate_command(0)->address());
			break;

		case ltOffset:
			if (to_command) {
				if ((section_options_ & rtLinkedFromOtherType) || to_command->is_data()) {
					value = to_command->address();
				}
				else {
					value = to_command->vm_address();
				}
				set_link_value(0, link()->Encrypt(value));
			}
			break;

		case ltGateOffset:
			if (to_command) {
				value = to_command->address();
				set_link_value(0, link()->Encrypt(value));
			}
			break;

		case ltSwitch:
			if (to_command) {
				if (section_options_ & rtLinkedFromOtherType) {
					value = to_command->address();
				}
				else {
					value = to_command->vm_address();
				}
				set_link_value(0, link()->Encrypt(value));
			}
			break;

		case ltCase:
			if (to_command) {
				ext_command = link()->gate_command(0);
				if (section_options_ & rtLinkedFromOtherType) {
					ext_command->set_link_value(0, to_command->address());
					value = ext_command->vm_address();
				}
				else if (ext_command->block()->virtual_machine()->id() != to_command->block()->virtual_machine()->id()) {
					ext_command->set_link_value(0, to_command->vm_address());
					ext_command->set_jmp_value(0, to_command->block()->virtual_machine()->id());
					value = ext_command->vm_address();
				}
				else {
					value = to_command->vm_address();
				}
				set_link_value(0, link()->Encrypt(value));
			}
			break;
		}
	}
}

bool IntelCommand::GetCommandInfo(IntelCommandInfoList& command_info_list) const
{
	OperandSize os, adr_os;

	command_info_list.clear();
	command_info_list.set_base_segment(base_segment_);

	switch (type_) {
	case cmAaa: case cmAas:
		command_info_list.Add(atRead, regEFX, otRegistr, size_);
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_need_flags(fl_A);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.Add(atRead, regEAX, otRegistr, osByte);
		command_info_list.Add(atWrite, regEAX, otRegistr, osWord);
		break;

	case cmAad:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.Add(atRead, regEAX, otRegistr, osWord);
		command_info_list.Add(atWrite, regEAX, otRegistr, osWord);
		break;

	case cmAam:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.Add(atRead, regEAX, otRegistr, osByte);
		command_info_list.Add(atWrite, regEAX, otRegistr, osWord);
		break;

	case cmAdc:
		command_info_list.Add(atRead, regEFX, otRegistr, size_);
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_need_flags(fl_C);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmAdd: case cmAnd:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmBsf: case cmBsr:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmBswap:
		command_info_list.AddOperand(operand_[0], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmBt:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_C);

		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atRead);
		break;

	case cmBtc: case cmBtr: case cmBts:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_C);

		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmCall:
		command_info_list.Add(atRead, regESP, otRegistr, size_);
		command_info_list.Add(atWrite, regESP, otRegistr, size_);
		command_info_list.Add(atWrite, regEIP, otBaseRegistr, size_);

		command_info_list.AddOperand(operand_[0], atRead);
		break;

	case cmSyscall:
		command_info_list.Add(atRead, regESP, otRegistr, size_);
		command_info_list.Add(atWrite, regESP, otRegistr, size_);
		command_info_list.Add(atWrite, regEIP, otBaseRegistr, size_);
		break;

	case cmCbw:
		command_info_list.Add(atRead, regEAX, otRegistr, osByte);
		command_info_list.Add(atWrite, regEAX, otHiPartRegistr, osByte);
		break;

	case cmCwde:
		command_info_list.Add(atRead, regEAX, otRegistr, osWord);
		command_info_list.Add(atWrite, regEAX, otRegistr, osDWord);
		break;

	case cmCdqe:
		command_info_list.Add(atRead, regEAX, otRegistr, osDWord);
		command_info_list.Add(atWrite, regEAX, otRegistr, osQWord);
		break;

	case cmCwd:
		command_info_list.Add(atRead, regEAX, otRegistr, osWord);
		command_info_list.Add(atWrite, regEDX, otRegistr, osWord);
		break;

	case cmCdq:
		command_info_list.Add(atRead, regEAX, otRegistr, osDWord);
		command_info_list.Add(atWrite, regEDX, otRegistr, osDWord);
		break;

	case cmCqo:
		command_info_list.Add(atRead, regEAX, otRegistr, osQWord);
		command_info_list.Add(atWrite, regEDX, otRegistr, osQWord);
		break;

	case cmClc: case cmStc:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_C);
		break;

	case cmCmc:
		command_info_list.Add(atRead, regEFX, otRegistr, size_);
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_need_flags(fl_C);
		command_info_list.set_change_flags(fl_C);
		break;

	case cmCld: case cmStd:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_D);
		break;

	case cmCli: case cmSti:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_I);
		break;

	case cmCmov:
		command_info_list.Add(atRead, regEFX, otRegistr, size_);
		command_info_list.set_need_flags(flags_);

		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmCmp:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atRead);
		break;

	case cmCmps:
		command_info_list.Add(atRead, regEFX, otRegistr, size_);
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_need_flags(fl_D);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		os = operand_[0].size;
		adr_os = operand_[1].size;

		command_info_list.Add(atRead, regESI, otRegistr, adr_os);
		command_info_list.Add(atRead, regEDI, otRegistr, adr_os);
		command_info_list.Add(atWrite, regESI, otRegistr, adr_os);
		command_info_list.Add(atWrite, regEDI, otRegistr, adr_os);

		command_info_list.Add(atRead, segES, otMemory, os);

		if (preffix_command_ == cmRep || preffix_command_ == cmRepe || preffix_command_ == cmRepne) {
			command_info_list.Add(atRead, regECX, otRegistr, adr_os);
			command_info_list.Add(atWrite, regECX, otRegistr, adr_os);
		}
		break;

	case cmCmpxchg:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		os = operand_[0].size;
		command_info_list.Add(atRead, regEAX, otRegistr, os);
		command_info_list.Add(atWrite, regEAX, otRegistr, os);

		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmCmpxchg8b:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_Z);

		command_info_list.Add(atRead, regEAX, otRegistr, osDWord);
		command_info_list.Add(atRead, regEDX, otRegistr, osDWord);
		command_info_list.Add(atWrite, regEAX, otRegistr, osDWord);
		command_info_list.Add(atWrite, regEDX, otRegistr, osDWord);

		command_info_list.Add(atRead, regEBX, otRegistr, osDWord);
		command_info_list.Add(atRead, regECX, otRegistr, osDWord);

		command_info_list.AddOperand(operand_[0], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmCpuid:
		command_info_list.Add(atRead, regEAX, otRegistr, osDWord);

		command_info_list.Add(atWrite, regEAX, otRegistr, osDWord);
		command_info_list.Add(atWrite, regECX, otRegistr, osDWord);
		command_info_list.Add(atWrite, regEDX, otRegistr, osDWord);
		command_info_list.Add(atWrite, regEBX, otRegistr, osDWord);
		break;

	case cmDaa:
		command_info_list.Add(atRead, regEFX, otRegistr, size_);
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_need_flags(fl_A);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.Add(atRead, regEAX, otRegistr, osByte);
		command_info_list.Add(atWrite, regEAX, otRegistr, osByte);
		break;

	case cmDas:
		command_info_list.Add(atRead, regEFX, otRegistr, size_);
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_need_flags(fl_A | fl_C);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.Add(atRead, regEAX, otRegistr, osByte);
		command_info_list.Add(atWrite, regEAX, otRegistr, osByte);
		break;

	case cmDec: case cmInc:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P);

		command_info_list.AddOperand(operand_[0], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmDiv: case cmIdiv:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.AddOperand(operand_[0], atRead);

		os = operand_[0].size;
		if (os == osByte) {
			command_info_list.Add(atRead, regEAX, otRegistr, osWord);
			command_info_list.Add(atWrite, regEAX, otRegistr, osWord);
		}
		else {
			command_info_list.Add(atRead, regEAX, otRegistr, os);
			command_info_list.Add(atWrite, regEAX, otRegistr, os);
			command_info_list.Add(atRead, regEDX, otRegistr, os);
			command_info_list.Add(atWrite, regEDX, otRegistr, os);
		}
		break;

	case cmMul: case cmImul:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		os = operand_[0].size;
		if (operand_[2].type != otNone) {
			command_info_list.AddOperand(operand_[2], atRead);
			command_info_list.AddOperand(operand_[1], atRead);
			command_info_list.AddOperand(operand_[0], atWrite);
		}
		else if (operand_[1].type != otNone) {
			command_info_list.AddOperand(operand_[1], atRead);
			command_info_list.AddOperand(operand_[0], atRead);
			command_info_list.AddOperand(operand_[0], atWrite);
		}
		else {
			command_info_list.AddOperand(operand_[0], atRead);
			command_info_list.Add(atRead, regEAX, otRegistr, os);
		}

		if (operand_[1].type == otNone) {
			if (os == osByte) {
				command_info_list.Add(atWrite, regEAX, otRegistr, osWord);
			}
			else {
				command_info_list.Add(atWrite, regEAX, otRegistr, os);
				command_info_list.Add(atWrite, regEDX, otRegistr, os);
			}
		}
		break;

	case cmJCXZ:
		os = operand_[1].size;
		command_info_list.Add(atRead, regECX, otRegistr, os);

		command_info_list.Add(atWrite, regEIP, otBaseRegistr, size_);
		break;

	case cmJmpWithFlag:
		command_info_list.Add(atRead, regEFX, otRegistr, size_);
		command_info_list.set_need_flags(flags_);

		command_info_list.Add(atWrite, regEIP, otBaseRegistr, size_);
		break;

	case cmJmp:
		command_info_list.Add(atWrite, regEIP, otBaseRegistr, size_);

		command_info_list.AddOperand(operand_[0], atRead);
		break;

	case cmLahf:
		command_info_list.Add(atRead, regEFX, otRegistr, size_);
		command_info_list.set_need_flags(fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.Add(atWrite, regEAX, otHiPartRegistr, osByte);
		break;

	case cmLds:
		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);

		command_info_list.Add(atWrite, segDS, otSegmentRegistr, osWord);
		break;

	case cmLes:
		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);

		command_info_list.Add(atWrite, segES, otSegmentRegistr, osWord);
		break;

	case cmLfs:
		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);

		command_info_list.Add(atWrite, segFS, otSegmentRegistr, osWord);
		break;

	case cmLgs:
		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);

		command_info_list.Add(atWrite, segGS, otSegmentRegistr, osWord);
		break;

	case cmLss:
		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);

		command_info_list.Add(atWrite, segSS, otSegmentRegistr, osWord);
		break;

	case cmLea:
	{
		IntelOperand operand = operand_[1];
		operand.type &= ~otMemory;
		command_info_list.AddOperand(operand, atRead);
	}
	command_info_list.AddOperand(operand_[0], atWrite);
	break;

	case cmLeave:
		command_info_list.Add(atRead, regESP, otRegistr, size_);
		command_info_list.Add(atWrite, regESP, otRegistr, size_);

		command_info_list.Add(atRead, regEBP, otRegistr, size_);
		command_info_list.Add(atWrite, regEBP, otRegistr, size_);
		break;

	case cmLods:
		command_info_list.Add(atRead, regEFX, otRegistr, size_);
		command_info_list.set_need_flags(fl_D);

		os = operand_[0].size;
		adr_os = operand_[1].size;

		command_info_list.Add(atRead, regESI, otRegistr, adr_os);
		command_info_list.Add(atWrite, regESI, otRegistr, adr_os);

		command_info_list.Add(atWrite, regEAX, otRegistr, os);
		command_info_list.Add(atRead, (base_segment_ == segDefault) ? segDS : base_segment_, otMemory, os);

		if (preffix_command_ == cmRep || preffix_command_ == cmRepe || preffix_command_ == cmRepne) {
			command_info_list.Add(atRead, regECX, otRegistr, adr_os);
			command_info_list.Add(atWrite, regECX, otRegistr, adr_os);
		}
		break;

	case cmLoop:
		os = operand_[1].size;
		command_info_list.Add(atRead, regECX, otRegistr, os);
		command_info_list.Add(atWrite, regECX, otRegistr, os);

		command_info_list.Add(atWrite, regEIP, otBaseRegistr, size_);
		break;

	case cmLoope: case cmLoopne:
		command_info_list.Add(atRead, regEFX, otRegistr, size_);
		command_info_list.set_need_flags(fl_Z);

		os = operand_[1].size;
		command_info_list.Add(atRead, regECX, otRegistr, os);
		command_info_list.Add(atWrite, regECX, otRegistr, os);

		command_info_list.Add(atWrite, regEIP, otBaseRegistr, size_);
		break;

	case cmMov: case cmMovsx: case cmMovsxd: case cmMovzx:
		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmMovs:
		command_info_list.Add(atRead, regEFX, otRegistr, size_);
		command_info_list.set_need_flags(fl_D);

		os = operand_[0].size;
		adr_os = operand_[1].size;

		command_info_list.Add(atRead, regESI, otRegistr, adr_os);
		command_info_list.Add(atWrite, regESI, otRegistr, adr_os);
		command_info_list.Add(atRead, regEDI, otRegistr, adr_os);
		command_info_list.Add(atWrite, regEDI, otRegistr, adr_os);

		command_info_list.Add(atRead, (base_segment_ == segDefault) ? segDS : base_segment_, otMemory, os);
		command_info_list.Add(atWrite, segES, otMemory, os);

		if (preffix_command_ == cmRep || preffix_command_ == cmRepe || preffix_command_ == cmRepne) {
			command_info_list.Add(atRead, regECX, otRegistr, adr_os);
			command_info_list.Add(atWrite, regECX, otRegistr, adr_os);
		}
		break;

	case cmNeg:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.AddOperand(operand_[0], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmNop:
		break;

	case cmNot:
		command_info_list.AddOperand(operand_[0], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmOr:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmPop:
		command_info_list.Add(atRead, regESP, otRegistr, size_);
		command_info_list.Add(atWrite, regESP, otRegistr, size_);

		os = operand_[0].size;
		command_info_list.Add(atRead, segSS, otMemory, os);

		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmPopa:
		command_info_list.Add(atRead, regESP, otRegistr, size_);
		command_info_list.Add(atWrite, regESP, otRegistr, size_);

		os = operand_[0].size;
		command_info_list.Add(atRead, segSS, otMemory, os);

		command_info_list.Add(atWrite, regEAX, otRegistr, os);
		command_info_list.Add(atWrite, regECX, otRegistr, os);
		command_info_list.Add(atWrite, regEDX, otRegistr, os);
		command_info_list.Add(atWrite, regEBX, otRegistr, os);
		command_info_list.Add(atWrite, regEBP, otRegistr, os);
		command_info_list.Add(atWrite, regESI, otRegistr, os);
		command_info_list.Add(atWrite, regEDI, otRegistr, os);
		break;

	case cmPopf:
		command_info_list.Add(atRead, regESP, otRegistr, size_);
		command_info_list.Add(atWrite, regESP, otRegistr, size_);

		os = operand_[0].size;
		command_info_list.Add(atRead, segSS, otMemory, os);

		command_info_list.Add(atWrite, regEFX, otRegistr, os);
		command_info_list.set_change_flags(0xFFFF);
		break;

	case cmPush:
		command_info_list.Add(atRead, regESP, otRegistr, size_);
		command_info_list.Add(atWrite, regESP, otRegistr, size_);

		os = operand_[0].size;
		command_info_list.Add(atWrite, segSS, otMemory, os);

		command_info_list.AddOperand(operand_[0], atRead);
		break;

	case cmPusha:
		command_info_list.Add(atRead, regESP, otRegistr, size_);
		command_info_list.Add(atWrite, regESP, otRegistr, size_);

		os = operand_[0].size;
		command_info_list.Add(atWrite, segSS, otMemory, os);

		command_info_list.Add(atRead, regEAX, otRegistr, os);
		command_info_list.Add(atRead, regECX, otRegistr, os);
		command_info_list.Add(atRead, regEDX, otRegistr, os);
		command_info_list.Add(atRead, regEBX, otRegistr, os);
		command_info_list.Add(atRead, regEBP, otRegistr, os);
		command_info_list.Add(atRead, regESI, otRegistr, os);
		command_info_list.Add(atRead, regEDI, otRegistr, os);
		break;

	case cmPushf:
		command_info_list.Add(atRead, regESP, otRegistr, size_);
		command_info_list.Add(atWrite, regESP, otRegistr, size_);

		os = operand_[0].size;
		command_info_list.Add(atWrite, segSS, otMemory, os);

		command_info_list.Add(atRead, regEFX, otRegistr, os);
		command_info_list.set_need_flags(0xFFFF);
		break;

	case cmRet: case cmIret:
		command_info_list.Add(atRead, regESP, otRegistr, size_);
		command_info_list.Add(atWrite, regESP, otRegistr, size_);

		command_info_list.Add(atRead, segSS, otMemory, size_);
		command_info_list.Add(atWrite, regEIP, otBaseRegistr, size_);
		break;

	case cmRcl: case cmRcr:
		command_info_list.Add(atRead, regEFX, otRegistr, size_);
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_need_flags(fl_C);
		command_info_list.set_change_flags(fl_O | fl_C);

		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmRdtsc:
		command_info_list.Add(atWrite, regEAX, otRegistr, osDWord);
		command_info_list.Add(atWrite, regEDX, otRegistr, osDWord);
		break;

	case cmRol: case cmRor:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_O | fl_C);

		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmSahf:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.Add(atRead, regEAX, otHiPartRegistr, osByte);
		break;

	case cmSal: case cmSar:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmSbb:
		command_info_list.Add(atRead, regEFX, otRegistr, size_);
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_need_flags(fl_C);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmScas:
		command_info_list.Add(atRead, regEFX, otRegistr, size_);
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_need_flags(fl_D);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		os = operand_[0].size;
		adr_os = operand_[1].size;

		command_info_list.Add(atRead, regEDI, otRegistr, adr_os);
		command_info_list.Add(atWrite, regEDI, otRegistr, adr_os);

		command_info_list.Add(atRead, regEAX, otRegistr, os);
		command_info_list.Add(atRead, segES, otMemory, os);

		if (preffix_command_ == cmRep || preffix_command_ == cmRepe || preffix_command_ == cmRepne) {
			command_info_list.Add(atRead, regECX, otRegistr, adr_os);
			command_info_list.Add(atWrite, regECX, otRegistr, adr_os);
		}
		break;

	case cmSetXX:
		command_info_list.Add(atRead, regEFX, otRegistr, size_);
		command_info_list.set_need_flags(flags_);

		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmShl: case cmShr:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmShld: case cmShrd:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.AddOperand(operand_[2], atRead);
		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmStos:
		command_info_list.Add(atRead, regEFX, otRegistr, size_);
		command_info_list.set_need_flags(fl_D);

		os = operand_[0].size;
		adr_os = operand_[1].size;

		command_info_list.Add(atRead, regEDI, otRegistr, adr_os);
		command_info_list.Add(atWrite, regEDI, otRegistr, adr_os);

		command_info_list.Add(atRead, regEAX, otRegistr, os);
		command_info_list.Add(atWrite, segES, otMemory, os);

		if (preffix_command_ == cmRep || preffix_command_ == cmRepe || preffix_command_ == cmRepne) {
			command_info_list.Add(atRead, regECX, otRegistr, adr_os);
			command_info_list.Add(atWrite, regECX, otRegistr, adr_os);
		}
		break;

	case cmSub:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmTest:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atRead);
		break;

	case cmXadd:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[1], atWrite);
		command_info_list.AddOperand(operand_[0], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmXchg:
		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[1], atWrite);
		command_info_list.AddOperand(operand_[0], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmXlat:
		adr_os = operand_[0].size;
		command_info_list.Add(atRead, regEBX, otRegistr, adr_os);
		command_info_list.Add(atRead, regEAX, otRegistr, osByte);
		command_info_list.Add(atWrite, regEAX, otRegistr, osByte);

		command_info_list.Add(atRead, (base_segment_ == segDefault) ? segDS : base_segment_, otMemory, osByte);
		break;

	case cmXor:
		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);

		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

		// FPU commands

	case cmWait: case cmFabs: case cmFchs: case cmFclex: case cmFcos: case cmFdecstp:
	case cmFfree: case cmFincstp: case cmFinit: case cmFld1: case cmFldl2t: case cmFldl2e:
	case cmFldlg2: case cmFldln2: case cmFldpi: case cmFldz:
	case cmFpatan: case cmFprem: case cmFprem1: case cmFptan:
	case cmFrndint: case cmFscale: case cmFsin: case cmFsincos: case cmFsqrt:
	case cmFtst: case cmFxam: case cmFxtract: case cmFyl2x: case cmFyl2xp1:
		command_info_list.Add(atRead, 0, otFPURegistr, size_);
		command_info_list.Add(atWrite, 0, otFPURegistr, size_);
		break;

	case cmFadd: case cmFaddp: case cmFiadd: case cmFcom: case cmFcomp: case cmFcompp: case cmFdiv: case cmFidiv: case cmFdivp:
	case cmFdivr: case cmFidivr: case cmFdivrp: case cmFicom: case cmFicomp: case cmFild: case cmFld: case cmFmul: case cmFimul:
	case cmFmulp: case cmFsub: case cmFisub: case cmFsubp: case cmFsubr: case cmFisubr: case cmFsubrp: case cmFucom: case cmFucomp:
	case cmFucompp: case cmFxch:
		os = operand_[0].size;
		command_info_list.Add(atRead, 0, otFPURegistr, os);
		command_info_list.Add(atWrite, 0, otFPURegistr, os);

		command_info_list.AddOperand(operand_[0], atRead);
		break;

	case cmFcomi: case cmFcomip: case cmFucomi: case cmFucomip:
		os = operand_[0].size;
		command_info_list.Add(atRead, 0, otFPURegistr, os);
		command_info_list.Add(atWrite, 0, otFPURegistr, os);

		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_Z | fl_P | fl_C);

		command_info_list.AddOperand(operand_[0], atRead);
		break;

		/*
	case cmFcmov:
		command_info_list.Add(atRead, regEFX, otRegistr, size_);
		command_info_list.set_need_flags(flags_);

		OS:=FOperand[0].OperandSize;
		command_info_list.Add(atRead, 0, otFPURegistr, OS);
		command_info_list.Add(atWrite, 0, otFPURegistr, OS);
		break;
		*/

	case cmFist: case cmFistp: case cmFst: case cmFstp: case cmFstsw: case cmFstcw:
		os = operand_[0].size;
		command_info_list.Add(atRead, 0, otFPURegistr, os);
		command_info_list.Add(atWrite, 0, otFPURegistr, os);

		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	case cmFldcw:
		os = operand_[0].size;
		command_info_list.Add(atRead, 0, otFPURegistr, os);
		command_info_list.Add(atWrite, 0, otFPURegistr, os);

		command_info_list.AddOperand(operand_[0], atRead);
		break;

	case cmFnop:
		break;

	case cmRdrand:
	case cmRdseed:
		command_info_list.AddOperand(operand_[0], atWrite);

		command_info_list.Add(atWrite, regEFX, otRegistr, size_);
		command_info_list.set_change_flags(fl_O | fl_S | fl_Z | fl_A | fl_P | fl_C);
		break;

	case cmMovsd:
	case cmMovss:
	case cmMovupd:
	case cmMovups:
	case cmMovdqu:
	case cmMovq:
	case cmMovlpd:
	case cmMovaps:
		command_info_list.AddOperand(operand_[1], atRead);
		command_info_list.AddOperand(operand_[0], atWrite);
		break;

	default:
		return false;
	}

	return true;
}

bool IntelCommand::Merge(ICommand* command)
{
	if (count() == 0 || command->count() == 0 || command->owner() != owner() || address_range() != command->address_range())
		return false;

	IntelCommand* dest = reinterpret_cast<IntelCommand*>(command);
	size_t i;
	for (i = 0; i < vm_command_info_list_->count(); i++) {
		CommandInfo* command_info = vm_command_info_list_->item(i);
		switch (command_info->operand_type()) {
		case otRegistr:
			if (command_info->value() == regESP || (command_info->value() & regExtended))
				return false;
			break;
		case otControlRegistr:
			if (command_info->type() == atWrite)
				return false;
			break;
		case otMemory:
			if (dest->vm_command_info_list_->GetInfo(atWrite, otRegistr, regESP))
				return false;
			break;
		}
	}

	size_t dest_count = dest->count();
	for (i = 0; i < dest->count(); i++) {
		IntelVMCommand* vm_command = dest->item(i);
		if (vm_command->command_type() == cmJmp || vm_command->command_type() == cmRet || vm_command->command_type() == cmIret) {
			dest_count = i;
			break;
		}
	}

	size_t dest_pos = NOT_ID;
	if (owner()->IndexOf(dest) > owner()->IndexOf(this)) {
		for (i = 0; i < dest_count; i++) {
			if (!dest->item(i)->can_merge(*vm_command_info_list_))
				break;
			dest_pos = i;
		}
		if (dest_pos != NOT_ID)
			dest_pos = rand() % (dest_pos + 1);
	}
	else {
		for (i = dest_count; i > 0; i--) {
			if (!dest->item(i - 1)->can_merge(*vm_command_info_list_))
				break;
			dest_pos = i - 1;
		}
		if (dest_pos != NOT_ID)
			dest_pos = dest_pos + rand() % (dest_count - dest_pos);
	}

	if (dest_pos == NOT_ID)
		return false;

	for (size_t p = 0; p < count(); ) {
		IntelVMCommand* vm_command = item(p);
		if (vm_command->options() & voSectionCommand) {
			if (section_options() & rtBeginSection) {
				p++;
				continue;
			}
			if (section_options() & rtEndSection)
				break;
		}
		RemoveObject(vm_command);
		vm_command->set_owner(dest);
		dest->InsertObject(dest_pos++, vm_command);
	}

	for (i = 0; i < vm_command_info_list_->count(); i++) {
		CommandInfo* command_info = vm_command_info_list_->item(i);
		dest->vm_command_info_list_->Add(command_info->type(), command_info->value(), command_info->operand_type(), command_info->size());
	}

	return true;
}

IntelVMCommand* IntelCommand::item(size_t index) const
{
	return reinterpret_cast<IntelVMCommand*>(BaseCommand::item(index));
}

uint64_t IntelCommand::ext_vm_address() const
{
	return (ext_vm_entry_) ? ext_vm_entry_->address() : vm_address();
}
#ifdef CHECKED
bool IntelCommand::check_hash() const
{
	return (hash_ == calc_hash());
}

void IntelCommand::update_hash()
{
	hash_ = calc_hash();
}

uint32_t IntelCommand::calc_hash() const
{
	Data data;
	data.PushDWord(type_);
	data.PushDWord(preffix_command_);
	data.PushDWord(size_);
	data.PushDWord(base_segment_);
	for (size_t i = 0; i < 3; i++) {
		const IntelOperand* operand = &operand_[i];
		data.PushWord(operand->type);
		data.PushByte(operand->size);
		data.PushByte(operand->registr);
		data.PushByte(operand->base_registr);
		data.PushByte(operand->scale_registr);
		data.PushByte(operand->address_size);
		data.PushByte(operand->value_size);
		data.PushQWord(operand->value);
	}
	SHA1 sha;
	sha.Input(data.data(), data.size());
	return *reinterpret_cast<const uint32_t*>(sha.Result());
}
#endif
