#include "../runtime/crypto.h"
#include "objects.h"
#include "osutils.h"
#include "streams.h"
#include "files/mapping.h"
#include "files/architecture.h"
#include "files/utils.h"
#include "script.h"
#include "core_internal/core.h"

#include "processors.h"

#include "../third-party/libffi/ffi.h"

#include "core_internal/watermark.h"
#include "core_internal/license.h"
#include "core_internal/file_manager.h"

// Intel module
#include "intel/ir/IntelCommand.h"
#include "intel/ir/IntelFunction.h"
#include "intel/ir/IntelFunctionList.h"

// PE module
#include "pe/pefile.h"

/**
 * lua utils
 */

void register_class(lua_State *L, const char *class_name, const luaL_Reg *methods, const luaL_Reg *meta_methods = NULL)
{
	lua_newtable(L);
	int methodtable = lua_gettop(L);
	luaL_newmetatable(L, class_name);
	int metatable = lua_gettop(L);

	lua_pushliteral(L, "__metatable");
	lua_pushvalue(L, methodtable);
	lua_settable(L, metatable);  // hide metatable from Lua getmetatable()

	lua_pushliteral(L, "__index");
	lua_pushvalue(L, methodtable);
	lua_settable(L, metatable);

	if (meta_methods) {
		for (const luaL_Reg *method = meta_methods; method->name != NULL; method++) {
			lua_pushstring(L, method->name);
			lua_pushcfunction(L, method->func);
			lua_settable(L, metatable);
		}
	}
	lua_pop(L, 1);  // drop metatable

	//luaL_register(L, NULL, methods);  // fill methodtable
	luaL_setfuncs(L, methods, 0);
	lua_pop(L, 1);  // drop methodtable

	//lua_register(L, class_name, create_account);
}

void push_object(lua_State *state, const char *class_name, const void *value)
{
	if (!value) {
		lua_pushnil(state);
		return;
	}

	void *data = lua_newuserdata(state, sizeof(value));
	*reinterpret_cast<const void **>(data) = value;
	luaL_getmetatable(state, class_name);
	lua_setmetatable(state, -2);
}

void *check_object(lua_State *state, int index, const char *class_name)
{
	void **data = (void **)(class_name ? luaL_checkudata(state, index, class_name) : lua_touserdata(state, index));
	return *data;
}

void delete_object(lua_State *state, int index, const char *class_name)
{
	void **data = (void **)luaL_checkudata(state, index, class_name);
	delete reinterpret_cast<IObject *>(*data);
	*data = NULL;
}

uint64_t check_uint64(lua_State *L, int index)
{
	int type = lua_type(L, index);
	uint64_t res = 0;
	switch (type) {
	case LUA_TNUMBER: {
		lua_Number d = lua_tonumber(L,index);
		res = static_cast<uint64_t>(d);
		break;
	}
	case LUA_TSTRING: {
		size_t len = 0;
		const uint8_t *str = (const uint8_t *)lua_tolstring(L, index, &len);
		if (len > 8)
			return luaL_error(L, "The string (length = %d) is not an uint64 string", len);
		for (size_t i = 0; i < len; i++) {
			res |= static_cast<uint64_t>(str[i]) << (i * 8);
		}
		break;
	}
	case LUA_TUSERDATA: {
		uint64_t *data = reinterpret_cast<uint64_t *>(luaL_checkudata(L, index, Uint64Binder::class_name()));
		res = *data;
		break;
	}
	default:
		return luaL_error(L, "argument %d error type %s", index, lua_typename(L, type));
	}
	return res;
}

lua_Integer check_integer(lua_State *L, int index)
{
	if (lua_type(L, index) == LUA_TUSERDATA) {
		uint64_t *data = reinterpret_cast<uint64_t *>(luaL_checkudata(L, index, Uint64Binder::class_name()));
		return static_cast<lua_Integer>(*data);
	}
	else
		return luaL_checkinteger(L, index);
}

struct EnumReg {
	const char *name;
	uint32_t value;
};

void register_enum(lua_State *L, const char *enum_name, const EnumReg *values)
{
	lua_newtable(L); int table = lua_gettop(L);

	for (; values->name; values++) {
		lua_pushstring(L, values->name);
		lua_pushnumber(L, values->value);
		lua_settable(L, table);
	}

	lua_setglobal(L, enum_name);
}

void push_uint64(lua_State *state, uint64_t value)
{
	uint64_t *data = reinterpret_cast<uint64_t *>(lua_newuserdata(state, sizeof(value)));
	*data = value;
	luaL_getmetatable(state, Uint64Binder::class_name());
	lua_setmetatable(state, -2);
}

void push_field(lua_State *state, const char *key, int value)
{
	lua_pushinteger(state, value);
	lua_setfield(state, -2, key);
}

void push_date(lua_State *state, LicenseDate date, const char *format)
{
	if (!format)
		lua_pushinteger(state, date.value());
	else if (strcmp(format, "*t") == 0) {
		lua_createtable(state, 0, 3);
		push_field(state, "day", date.Day);
		push_field(state, "month", date.Month);
		push_field(state, "year", date.Year);
	} else {
		tm t = tm();
		t.tm_year = date.Year - 1900;
		t.tm_mon = date.Month - 1;
		t.tm_mday = date.Day;

		char cc[3];
		cc[0] = '%';
		cc[1] = 0;
		cc[2] = 0;

		luaL_Buffer b;
		luaL_buffinit(state, &b);
		while (*format) {
			if (*format != '%')  /* no conversion specifier? */
				luaL_addchar(&b, *format++);
			else {
				format++;
				cc[1] = *format++;
				char buff[200];  /* should be big enough for any conversion result */
				size_t reslen = strftime(buff, sizeof(buff), cc, &t);
				luaL_addlstring(&b, buff, reslen);
			}
		}
		luaL_pushresult(&b);
	}
}

void push_file(lua_State *state, IFile *file)
{
	const char *class_name = NULL;
	if (dynamic_cast<PEFile *>(file)) {
		class_name = PEFileBinder::class_name();
	}
	else {
		file = NULL;
	}
	push_object(state, class_name, file);
}

void push_architecture(lua_State *state, IArchitecture *arch)
{
	const char *class_name = NULL;
	if (dynamic_cast<PEArchitecture *>(arch)) {
		class_name = PEArchitectureBinder::class_name();
	} else {
		arch = NULL;
	}
	push_object(state, class_name, arch);
}

void push_command(lua_State *state, ICommand *command)
{
	const char *class_name = NULL;
	if (dynamic_cast<IntelCommand *>(command)) {
		class_name = IntelCommandBinder::class_name();
	}

	else {
		command = NULL;
	}
	push_object(state, class_name, command);
}

static int log_print(lua_State *state) 
{
	std::string res;
	int n = lua_gettop(state);
	int i;
	lua_getglobal(state, "tostring");
	for (i = 1; i <= n; i++) {
		const char *s;
		size_t l;
		lua_pushvalue(state, -1);  /* function to be called */
		lua_pushvalue(state, i);   /* value to print */
		lua_call(state, 1, 1);
		s = lua_tolstring(state, -1, &l);  /* get result */
		if (s == NULL)
			return luaL_error(state, LUA_QL("tostring") " must return a string to " LUA_QL("print"));
		if (i > 1)
			res += "\t";
		res += std::string(s, l);
		lua_pop(state, 1);  /* pop result */
	}
	Script::core()->Notify(mtScript, NULL, res);
	return 0;
}

int open_lib(lua_State *state)
{
	std::string name = luaL_checklstring(state, 1, NULL);
	FFILibrary *lib = new FFILibrary(name);
	if (!lib->value()) {
		delete lib;
		lib = NULL;
	}
	push_object(state, FFILibraryBinder::class_name(), lib);
	return 1;
}

template<lua_CFunction func>
int SafeFunction(lua_State *L)
{
	int result = 0;
	try {
		result = func(L);
	}
	catch(std::runtime_error &e){
		luaL_error(L, e.what());
	}
	catch(...){
		luaL_error(L, "unknown exception");
	}
	return result;
}

/**
 * Uint64Binder
 */

void Uint64Binder::Register(lua_State *state) 
{
	static const luaL_Reg methods[] = {
		{"__add", &add},
		{"__sub", &sub},
		{"__mul", &mul},
		{"__div", &div},
		{"__mod", &mod},
		{"__unm", &unm},
		{"__pow", &pow},
		{"__eq", &eq},
		{"__lt", &lt},
		{"__le", &le},
		{"__tostring", &tostring},
		{NULL, NULL},
	};

	luaL_newmetatable(state, class_name());
	luaL_setfuncs(state, methods, 0);
	lua_pop(state, 1);

	lua_newtable(state);
	lua_pushcfunction(state, _new);
	lua_setfield(state, -2, "new");
	lua_pushcfunction(state, tostring);
	lua_setfield(state, -2, "tostring");
	lua_pop(state, 1);
}

int Uint64Binder::add(lua_State *L)
{
	uint64_t a = check_uint64(L, 1);
	uint64_t b = check_uint64(L, 2);
	push_uint64(L, a + b);
	return 1;
}

int Uint64Binder::sub(lua_State *L)
{
	uint64_t a = check_uint64(L, 1);
	uint64_t b = check_uint64(L, 2);
	push_uint64(L, a - b);
	return 1;
}

int Uint64Binder::mul(lua_State *L) {
	uint64_t a = check_uint64(L, 1);
	uint64_t b = check_uint64(L, 2);
	push_uint64(L, a * b);
	return 1;
}

int Uint64Binder::div(lua_State *L)
{
	uint64_t a = check_uint64(L, 1);
	uint64_t b = check_uint64(L, 2);
	if (b == 0)
		return luaL_error(L, "div by zero");
	push_uint64(L, a / b);
	return 1;
}

int Uint64Binder::mod(lua_State *L)
{
	uint64_t a = check_uint64(L, 1);
	uint64_t b = check_uint64(L, 2);
	if (b == 0)
		return luaL_error(L, "mod by zero");
	push_uint64(L, a % b);
	return 1;
}

uint64_t _pow64(uint64_t a, uint64_t b)
{
	if (b == 1)
		return a;
	uint64_t a2 = a * a;
	if (b % 2 == 1) {
		return _pow64(a2, b/2) * a;
	} else {
		return _pow64(a2, b/2);
	}
}

int Uint64Binder::pow(lua_State *L)
{
	uint64_t a = check_uint64(L, 1);
	uint64_t b = check_uint64(L, 2);
	uint64_t res;
	if (b > 0) {
		res = _pow64(a, b);
	} else if (b == 0) { //-V
		res = 1;
	} else {
		return luaL_error(L, "pow by negative number %d",(int)b);
	} 
	push_uint64(L, res);
	return 1;
}

int Uint64Binder::unm(lua_State *L)
{
	uint64_t a = check_uint64(L, 1);
	push_uint64(L, 0 - a);
	return 1;
}

int Uint64Binder::eq(lua_State *L)
{
	uint64_t a = check_uint64(L, 1);
	uint64_t b = check_uint64(L, 2);
	lua_pushboolean(L, a == b);
	return 1;
}

int Uint64Binder::lt(lua_State *L)
{
	uint64_t a = check_uint64(L, 1);
	uint64_t b = check_uint64(L, 2);
	lua_pushboolean(L, a < b);
	return 1;
}

int Uint64Binder::le(lua_State *L)
{
	uint64_t a = check_uint64(L, 1);
	uint64_t b = check_uint64(L, 2);
	lua_pushboolean(L, a <= b);
	return 1;
}

int Uint64Binder::_new(lua_State *L)
{
	int top = lua_gettop(L);
	int64_t res;
	switch(top) {
		case 0:
			res = 0;
			break;
		case 1:
			res = check_uint64(L, 1);
			break;
		default: {
			int base = (int)luaL_checkinteger(L,2);
			if (base < 2)
				luaL_error(L, "base must be >= 2");
			const char *str = luaL_checkstring(L, 1);
			res = _strtoui64(str, NULL, base);
			break;
		}
	}
	push_uint64(L, res);
	return 1;
}

int Uint64Binder::tostring(lua_State *L)
{
	static const char *hex = "0123456789ABCDEF";
	uint64_t n = *reinterpret_cast<uint64_t *>(luaL_checkudata(L, 1, class_name()));
	int base = (lua_gettop(L) == 1) ? 16 : (int)luaL_checkinteger(L, 2);
	int shift, mask;
	switch(base) {
	case 0: {
		unsigned char buffer[8];
		for (int i = 0; i < 8; i++) {
			buffer[i] = (n >> (i * 8)) & 0xff;
		}
		lua_pushlstring(L,(const char *)buffer, 8);
		return 1;
		}
	case 10: {
		char buffer[40], *ptr = buffer + _countof(buffer);
		while (ptr > buffer) {
			*--ptr = hex[n % 10];
			n /= 10;
			if (n == 0)
				break;
		}
		lua_pushlstring(L, ptr, _countof(buffer) - (ptr - buffer));
		return 1;
	}
	case 2:
		shift = 1;
		mask = 1;
		break;
	case 8:
		shift = 3;
		mask = 7;
		break;
	case 16:
		shift = 4;
		mask = 0xf;
		break;
	default:
		luaL_error(L, "Unsupport base %d",base);
		return 0;
	}
	char buffer[64];
	for (int i = 0; i < 64; i += shift) {
		buffer[i / shift] = hex[(n >> (64 - shift - i)) & mask];
	}
	lua_pushlstring(L, buffer, 64 / shift);
	return 1;
}

/**
 * FFILibrary
 */

FFILibrary::FFILibrary(const std::string &name) 
	: IObject()
{
	value_ = os::LibraryOpen(name);
	if (value_)
		name_ = name;
}

void FFILibrary::close()
{
	if (value_)
		os::LibraryClose(value_);
	name_.clear();
}

FFILibrary::~FFILibrary()
{
	close();
}

/**
 * FFIFunction
 */

FFIFunction::FFIFunction(HMODULE module, const std::string &name)
	: IObject(), ret_(0), abi_(0), ffi_ret_(NULL)
{
	memset(&cif_, 0, sizeof(cif_));
	value_ = os::GetFunction(module, name);
	if (value_)
		name_ = name;
}

static ffi_type *ffi_types[] = {
	&ffi_type_void,
	&ffi_type_sint8,
	&ffi_type_uchar,
	&ffi_type_sshort,
	&ffi_type_ushort,
	&ffi_type_sint,
	&ffi_type_uint,
	&ffi_type_slong,
	&ffi_type_ulong,
#if PTRDIFF_MAX == 65535
	&ffi_type_uint16,
#elif PTRDIFF_MAX == 2147483647
	&ffi_type_uint32,
#elif PTRDIFF_MAX == 9223372036854775807
	&ffi_type_uint64,
#elif defined(_WIN64)
	&ffi_type_uint64,
#elif defined(_WIN32)
	&ffi_type_uint32,
#else
	#error "ptrdiff_t size not supported"
#endif
	&ffi_type_float,
	&ffi_type_double,
	&ffi_type_pointer,
	&ffi_type_pointer,
	&ffi_type_pointer,
	&ffi_type_pointer,
	&ffi_type_pointer,
	&ffi_type_pointer,
	&ffi_type_sint64,
	&ffi_type_uint64
};

static const ffi_abi abi_types[] = 
{
	FFI_DEFAULT_ABI,
#if defined(_WIN64)
	FFI_DEFAULT_ABI,
	FFI_DEFAULT_ABI,
#else
	FFI_SYSV,
	FFI_STDCALL,
#endif
};

ffi_status FFIFunction::Prepare()
{
	ffi_ret_ = ffi_types[ret_];
	ffi_params_.clear();
	for (size_t i = 0; i < params_.size(); i++) {
		ffi_params_.push_back(ffi_types[params_.at(i)]);
	}
	return ffi_prep_cif(&cif_, abi_types[abi_], static_cast<unsigned int>(params_.size()), ffi_ret_, ffi_params_.data());
}

void FFIFunction::Call(void *ret, void **args)
{
	ffi_call(&cif_, FFI_FN(value_), ret, args);
}

/**
 * FFILibraryBinder
 */

void FFILibraryBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"tostring", &tostring},
		{"name", &tostring},
		{"address", &address},
		{"close", &close},
		{"getFunction", &get_function},
		{NULL, NULL},
	};

	static const luaL_Reg meta_methods[] = {
		{"__tostring", &tostring},
		{"__gc", &gc},
		{NULL, NULL},
	};

	register_class(state, class_name(), methods, meta_methods);

	FFIFunctionBinder::Register(state);
}

int FFILibraryBinder::tostring(lua_State *state)
{
	FFILibrary *lib = reinterpret_cast<FFILibrary *>(check_object(state, 1, class_name()));
	lua_pushstring(state, lib->name().c_str());
	return 1;
}

int FFILibraryBinder::address(lua_State *state)
{
	FFILibrary *lib = reinterpret_cast<FFILibrary *>(check_object(state, 1, class_name()));
	push_uint64(state, reinterpret_cast<uint64_t>(lib->value()));
	return 1;
}

int FFILibraryBinder::close(lua_State *state)
{
	FFILibrary *lib = reinterpret_cast<FFILibrary *>(check_object(state, 1, class_name()));
	lib->close();
	return 0;
}

int FFILibraryBinder::gc(lua_State *state)
{
	delete_object(state, 1, class_name());
	return 0;
}

static const char *type_names[] = {
	"void",
	"byte",
	"char",
	"short",
	"ushort",
	"int",
	"uint",
	"long",
	"ulong",
	"size_t",
	"float",
	"double",
	"string",
	"pointer",
	"ref char",
	"ref int",
	"ref uint",
	"ref double",
	"longlong",
	"ulonglong",
	NULL
};

enum ParamType {
	ptVoid,
	ptByte,
	ptChar,
	ptShort,
	ptUShort,
	ptInt,
	ptUInt,
	ptLong,
	ptULong,
	ptSize_t,
	ptFloat,
	ptDouble,
	ptString,
	ptPointer,
	ptRefChar,
	ptRefInt,
	ptRefUInt,
	ptRefDouble,
	ptLongLong,
	ptULongLong
};

static const char *abi_names[] = {
	"default", 
	"cdecl", 
	"stdcall", 
	NULL
};

int FFILibraryBinder::get_function(lua_State *state)
{
	FFILibrary *lib = reinterpret_cast<FFILibrary *>(check_object(state, 1, class_name()));
	std::string name = luaL_checklstring(state, 2, NULL);
	FFIFunction *func = new FFIFunction(lib->value(), name);
	if (!func->value()) {
		delete func;
		func = NULL;
	} else {
		if(lua_istable(state, 3)) {
			lua_getfield(state, 3, "ret");
			func->set_ret(luaL_checkoption(state, -1, "int", type_names));
			lua_pop(state, 1);
			lua_getfield(state, 3, "abi");
			func->set_abi(luaL_checkoption(state, -1, "default", abi_names));
			lua_pop(state, 1);

			size_t param_count = lua_rawlen(state, 3);
			for (size_t i = 0; i < param_count; i++) {
				lua_rawgeti(state, 3, (int)i + 1);
				func->add_param(luaL_checkoption(state, -1, "int", type_names));
				lua_pop(state, 1);
			}
		} else {
			func->set_ret(luaL_checkoption(state, 3, "int", type_names));

			int param_count = lua_gettop(state) - 3;
			for (int i = 0; i < param_count; i++) {
				func->add_param(luaL_checkoption(state, i + 4, "int", type_names));
			}
		}
		if (func->Prepare() != FFI_OK) {
			delete func;
			return luaL_error(state, "error in libffi preparation");
		}
	}
	push_object(state, FFIFunctionBinder::class_name(), func);
	return 1;
}

/**
 * FFIFunctionBinder
 */

void FFIFunctionBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"tostring", &tostring},
		{"name", &tostring},
		{"address", &address},
		{NULL, NULL},
	};

	static const luaL_Reg meta_methods[] = {
		{"__tostring", &tostring},
		{"__call", &call},
		{"__gc", &gc},
		{NULL, NULL},
	};

	register_class(state, class_name(), methods, meta_methods);
}

int FFIFunctionBinder::tostring(lua_State *state)
{
	FFIFunction *func = reinterpret_cast<FFIFunction *>(check_object(state, 1, class_name()));
	lua_pushstring(state, func->name().c_str());
	return 1;
}

int FFIFunctionBinder::gc(lua_State *state)
{
	delete_object(state, 1, class_name());
	return 0;
}

int FFIFunctionBinder::address(lua_State *state)
{
	FFIFunction *func = reinterpret_cast<FFIFunction *>(check_object(state, 1, class_name()));
	push_uint64(state, reinterpret_cast<uint64_t>(func->value()));
	return 1;
}

int FFIFunctionBinder::call(lua_State *state)
{
	struct FFIValue {
		union {
			size_t i;
			float f;
			double d;
			const char *s;
			void *p;
			long l;
			uint64_t ll;
		};
	};

	FFIFunction *func = reinterpret_cast<FFIFunction *>(check_object(state, 1, class_name()));
	std::vector<void *> args;
	std::vector<FFIValue> values;

	std::vector<int> params = func->params();
	if (!params.empty()) {
		for (size_t i = 0; i < params.size(); i++) {
			FFIValue value;
			int j = 2 + (int)i;
			switch (params[i]) {
			case ptByte:
			case ptChar:
				value.i = static_cast<uint8_t>(lua_tointeger(state, j));
				break;
			case ptShort:
				value.i = static_cast<short>(lua_tointeger(state, j));
				break;
			case ptUShort:
				value.i = static_cast<unsigned short>(lua_tointeger(state, j));
				break;
			case ptInt:
				value.i = static_cast<int>(lua_tointeger(state, j));
				break;
			case ptUInt:
				value.i = static_cast<unsigned int>(lua_tointeger(state, j));
				break;
			case ptLong:
				value.l = static_cast<long>(lua_tointeger(state, j));
				break;
			case ptULong:
				value.l = static_cast<unsigned long>(lua_tointeger(state, j));
				break;
			case ptSize_t:
				value.i = static_cast<size_t>(lua_tointeger(state, j));
				break;
			case ptString:
				value.s = lua_isnil(state, j) ? NULL : lua_tostring(state, j);
				break;
			case ptPointer:
				value.p = lua_isstring(state, j) ? (void*)lua_tostring(state, j) : lua_touserdata(state, j);
				break;
			default:
				return luaL_error(state, "parameter %d is of unknown type", j);
			}
			values.push_back(value);
		}
		for (size_t i = 0; i < values.size(); i++) {
			args.push_back(&values[i]);
		}
	}

	switch(func->ret()) {
	case ptVoid:
		{
			func->Call(NULL, args.data());
			lua_pushnil(state);
		}
		break;
	case ptByte:
	case ptChar:
		{
			size_t ret;
			func->Call(&ret, args.data());
			lua_pushinteger(state, static_cast<unsigned char>(ret));
		}
		break;
	case ptShort: 
		{
			size_t ret;
			func->Call(&ret, args.data());
			lua_pushinteger(state, static_cast<short>(ret));
		}
		break;
	case ptUShort:
		{
			size_t ret;
			func->Call(&ret, args.data());
			lua_pushinteger(state, static_cast<unsigned short>(ret));
		}
		break;
	case ptInt:
		{
			size_t ret;
			func->Call(&ret, args.data());
			lua_pushinteger(state, static_cast<int>(ret));
		}
		break;
	case ptUInt:
		{
			size_t ret;
			func->Call(&ret, args.data());
			lua_pushinteger(state, static_cast<unsigned int>(ret));
		}
		break;
	case ptLong:
		{
			size_t ret;
			func->Call(&ret, args.data());
			lua_pushnumber(state, static_cast<long>(ret));
		}
		break;
	case ptULong:
		{
			size_t ret;
			func->Call(&ret, args.data());
			lua_pushinteger(state, static_cast<unsigned long>(ret));
		}
		break;
	case ptSize_t:
		{
			size_t ret;
			func->Call(&ret, args.data());
			lua_pushinteger(state, ret);
		}
		break;
	case ptFloat:
		{
			float ret;
			func->Call(&ret, args.data());
			lua_pushnumber(state, ret);
		}
		break;
	case ptDouble:
		{
			double ret;
			func->Call(&ret, args.data());
			lua_pushnumber(state, ret);
		}
		break;
	case ptString:
		{
			char *ret;
			func->Call(&ret, args.data());
			if (ret)
				lua_pushstring(state, ret);
			else
				lua_pushnil(state);
		}
		break;		
	case ptPointer:
		{
			void *ret;
			func->Call(&ret, args.data());
			if (ret) 
				lua_pushlightuserdata(state, ret);
			else
				lua_pushnil(state);
		}
		break;				
	default:
		return luaL_error(state, "unknown return type for function %s", func->name().c_str());
	}

	return 1;
}

/**
 * OperandTypeBinder
 */

void OperandTypeBinder::Register(lua_State *state)
{
	static const EnumReg values[] = {
		{"None", otNone},
		{"Value", otValue},
		{"Registr", otRegistr},
		{"Memory", otMemory},
		{"SegmentRegistr", otSegmentRegistr},
		{"ControlRegistr", otControlRegistr},
		{"DebugRegistr", otDebugRegistr},
		{"FPURegistr", otFPURegistr},
		{"HiPartRegistr", otHiPartRegistr},
		{"BaseRegistr", otBaseRegistr},
		{"MMXRegistr", otMMXRegistr},
		{"XMMRegistr", otXMMRegistr},
		{NULL, 0}
	};

	register_enum(state, enum_name(), values);
}

/**
 * OperandSizeBinder
 */

void OperandSizeBinder::Register(lua_State *state)
{
	static const EnumReg values[] = {
		{"Byte", osByte},
		{"Word", osWord},
		{"DWord", osDWord},
		{"QWord", osQWord},
		{"TByte", osTByte},
		{"OWord", osOWord},
		{"FWord", osFWord},
		{NULL, 0}
	};

	register_enum(state, enum_name(), values);
}

/**
 * ObjectTypeBinder
 */

void ObjectTypeBinder::Register(lua_State *state)
{
	static const EnumReg values[] = {
		{"Code", otCode},
		{"Data", otData},
		{"Export", otExport},
		{"Marker", otMarker},
		{"APIMarker", otAPIMarker},
		{"Import", otImport},
		{"String", otString},
		{"Unknown", otUnknown},
		{NULL, 0}
	};

	register_enum(state, enum_name(), values);
}

/**
 * CommandOptionBinder
 */

void CommandOptionBinder::Register(lua_State *state)
{
	static const EnumReg values[] = {
		{"InverseFlag", roInverseFlag},
		{"LockPrefix", roLockPrefix},
		{"VexPrefix", roVexPrefix},
		{"Far", roFar},
		{"Breaked", roBreaked},
		{"ClearOriginalCode", roClearOriginalCode},
		{"NeedCompile", roNeedCompile},
		{"CreateNewBlock", roCreateNewBlock},
		{NULL, 0}
	};

	register_enum(state, enum_name(), values);
}

/**
 * FoldersBinder
 */

void FoldersBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"count", &SafeFunction<count>},
		{"item", &SafeFunction<item>},
		{"add", &SafeFunction<add>},
		{"clear", &SafeFunction<clear>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	FolderBinder::Register(state);
}

int FoldersBinder::item(lua_State *state)
{
	Folder *object = reinterpret_cast<Folder *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, FolderBinder::class_name(), object->item(index));
	return 1;
}

int FoldersBinder::count(lua_State *state)
{
	Folder *object = reinterpret_cast<Folder *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int FoldersBinder::add(lua_State *state)
{
	Folder *object = reinterpret_cast<Folder *>(check_object(state, 1, class_name()));
	std::string name = lua_tostring(state, 2);
	push_object(state, FolderBinder::class_name(), object->Add(name));
	return 1;
}

int FoldersBinder::clear(lua_State *state)
{
	Folder *object = reinterpret_cast<Folder *>(check_object(state, 1, class_name()));
	object->clear();
	return 0;
}

/**
 * FolderBinder
 */

void FolderBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"count", &SafeFunction<count>},
		{"item", &SafeFunction<item>},
		{"add", &SafeFunction<add>},
		{"clear", &SafeFunction<clear>},
		{"name", &SafeFunction<name>},
		{"destroy", &SafeFunction<destroy>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);
}

int FolderBinder::item(lua_State *state)
{
	Folder *object = reinterpret_cast<Folder *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, FolderBinder::class_name(), object->item(index));
	return 1;
}

int FolderBinder::count(lua_State *state)
{
	Folder *object = reinterpret_cast<Folder *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int FolderBinder::add(lua_State *state)
{
	Folder *object = reinterpret_cast<Folder *>(check_object(state, 1, class_name()));
	std::string name = lua_tostring(state, 2);
	push_object(state, FolderBinder::class_name(), object->Add(name));
	return 1;
}

int FolderBinder::clear(lua_State *state)
{
	Folder *object = reinterpret_cast<Folder *>(check_object(state, 1, class_name()));
	object->clear();
	return 0;
}

int FolderBinder::name(lua_State *state)
{
	Folder *object = reinterpret_cast<Folder *>(check_object(state, 1, class_name()));
	std::string name = object->name();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int FolderBinder::destroy(lua_State *state)
{
	delete_object(state, 1, class_name());
	return 0;
}

/**
 * PEFileBinder
 */

void PEFileBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"name", &SafeFunction<name>},
		{"format", &SafeFunction<format>},
		{"size", &SafeFunction<size>},
		{"seek", &SafeFunction<seek>},
		{"tell", &SafeFunction<tell>},
		{"write", &SafeFunction<write>},
		{"count", &SafeFunction<count>},
		{"item", &SafeFunction<item>},
		{"flush", &SafeFunction<flush>},
		{"read", &SafeFunction<read>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	PEFormatBinder::Register(state);
	PEArchitectureBinder::Register(state);
}

int PEFileBinder::item(lua_State *state)
{
	PEFile *object = reinterpret_cast<PEFile *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	IArchitecture *arch = object->item(index);
	const char *class_name = NULL;
	if (dynamic_cast<PEArchitecture *>(arch)) {
		class_name = PEArchitectureBinder::class_name();
	}
	else {
		arch = NULL;
	}

	push_object(state, class_name, object->item(index));
	return 1;
}

int PEFileBinder::count(lua_State *state)
{
	PEFile *object = reinterpret_cast<PEFile *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int PEFileBinder::name(lua_State *state)
{
	PEFile *object = reinterpret_cast<PEFile *>(check_object(state, 1, class_name()));
	std::string name = object->file_name(true);
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int PEFileBinder::format(lua_State *state)
{
	PEFile *object = reinterpret_cast<PEFile *>(check_object(state, 1, class_name()));
	std::string name = object->format_name();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int PEFileBinder::size(lua_State *state)
{
	PEFile *object = reinterpret_cast<PEFile *>(check_object(state, 1, class_name()));
	push_uint64(state, object->size());
	return 1;
}

int PEFileBinder::seek(lua_State *state)
{
	PEFile *object = reinterpret_cast<PEFile *>(check_object(state, 1, class_name()));
	size_t position = static_cast<size_t>(check_integer(state, 2));
	push_uint64(state, object->Seek(position));
	return 1;
}

int PEFileBinder::tell(lua_State *state)
{
	PEFile *object = reinterpret_cast<PEFile *>(check_object(state, 1, class_name()));
	push_uint64(state, object->Tell());
	return 1;
}

int PEFileBinder::write(lua_State *state)
{
	PEFile *object = reinterpret_cast<PEFile *>(check_object(state, 1, class_name()));
	int top = lua_gettop(state);
	int res = 0;
	for (int i = 2; i <= top; i++) {
		size_t l;
		const char *s = luaL_checklstring(state, i, &l);
		res += (int)object->Write(s, l);
    }
	lua_pushinteger(state, res);
	return 1;
}

int PEFileBinder::flush(lua_State *state)
{
	PEFile *object = reinterpret_cast<PEFile *>(check_object(state, 1, class_name()));
	object->Flush();
	return 0;
}

int PEFileBinder::read(lua_State *state)
{
	PEFile *object = reinterpret_cast<PEFile *>(check_object(state, 1, class_name()));
	size_t size = static_cast<size_t>(check_integer(state, 2));
	std::string buffer;
	buffer.resize(size);
	if (!buffer.empty())
		object->Read(&buffer[0], buffer.size());
	lua_pushlstring(state, buffer.c_str(), buffer.size());
	return 1;
}

/**
 * PEArchitectureBinder
 */

void PEArchitectureBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"name", &SafeFunction<name>},
		{"file", &SafeFunction<file>},
		{"entryPoint", &SafeFunction<entry_point>},
		{"imageBase", &SafeFunction<image_base>},
		{"cpuAddressSize", &SafeFunction<cpu_address_size>},
		{"dllCharacteristics", &SafeFunction<dll_characteristics>},
		{"size", &SafeFunction<size>},
		{"segments", &SafeFunction<segments>},
		{"sections", &SafeFunction<sections>},
		{"functions", &SafeFunction<functions>},
		{"directories", &SafeFunction<directories>},
		{"imports", &SafeFunction<imports>},
		{"exports", &SafeFunction<exports>},
		{"resources", &SafeFunction<resources>},
		{"fixups", &SafeFunction<fixups>},
		{"mapFunctions", &SafeFunction<map_functions>},
		{"folders", &SafeFunction<folders>},
		{"addressSeek", &SafeFunction<address_seek>},
		{"seek", &SafeFunction<seek>},
		{"tell", &SafeFunction<tell>},
		{"write", &SafeFunction<write>},
		{"read", &SafeFunction<read>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	PESegmentsBinder::Register(state);
	PESectionsBinder::Register(state);
	PEDirectoriesBinder::Register(state);
	PEImportsBinder::Register(state);
	PEExportsBinder::Register(state);
	PEResourcesBinder::Register(state);
	PEFixupsBinder::Register(state);
	MapFunctionsBinder::Register(state);
}

int PEArchitectureBinder::segments(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	push_object(state, PESegmentsBinder::class_name(), object->segment_list());
	return 1;
}

int PEArchitectureBinder::sections(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	push_object(state, PESectionsBinder::class_name(), object->segment_list());
	return 1;
}

int PEArchitectureBinder::name(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	std::string name = object->name();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int PEArchitectureBinder::file(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	push_object(state, PEFileBinder::class_name(), object->owner());
	return 1;
}

int PEArchitectureBinder::entry_point(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	push_uint64(state, object->entry_point());
	return 1;
}

int PEArchitectureBinder::image_base(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	push_uint64(state, object->image_base());
	return 1;
}

int PEArchitectureBinder::cpu_address_size(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->cpu_address_size());
	return 1;
}

int PEArchitectureBinder::dll_characteristics(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->dll_characteristics());
	return 1;
}

int PEArchitectureBinder::size(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	push_uint64(state, object->size());
	return 1;
}

int PEArchitectureBinder::functions(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	push_object(state, IntelFunctionsBinder::class_name(), object->function_list());
	return 1;
}

int PEArchitectureBinder::directories(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	push_object(state, PEDirectoriesBinder::class_name(), object->command_list());
	return 1;
}

int PEArchitectureBinder::imports(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	push_object(state, PEImportsBinder::class_name(), object->import_list());
	return 1;
}

int PEArchitectureBinder::exports(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	push_object(state, PEExportsBinder::class_name(), object->export_list());
	return 1;
}

int PEArchitectureBinder::resources(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	push_object(state, PEResourcesBinder::class_name(), object->resource_list());
	return 1;
}

int PEArchitectureBinder::fixups(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	push_object(state, PEFixupsBinder::class_name(), object->fixup_list());
	return 1;
}

int PEArchitectureBinder::map_functions(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	push_object(state, MapFunctionsBinder::class_name(), object->map_function_list());
	return 1;
}

int PEArchitectureBinder::folders(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	push_object(state, FoldersBinder::class_name(), object->owner()->folder_list());
	return 1;
}

int PEArchitectureBinder::address_seek(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	uint64_t address = check_uint64(state, 2);
	lua_pushboolean(state, object->AddressSeek(address));
	return 1;
}

int PEArchitectureBinder::seek(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	size_t position = static_cast<size_t>(check_integer(state, 2));
	push_uint64(state, object->Seek(position));
	return 1;
}

int PEArchitectureBinder::tell(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	push_uint64(state, object->Tell());
	return 1;
}

int PEArchitectureBinder::write(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	int top = lua_gettop(state);
	int res = 0;
	for (int i = 2; i <= top; i++) {
		size_t l;
		const char *s = luaL_checklstring(state, i, &l);
		res += (int)object->Write(s, l);
    }
	lua_pushinteger(state, res);
	return 1;
}

int PEArchitectureBinder::read(lua_State *state)
{
	PEArchitecture *object = reinterpret_cast<PEArchitecture *>(check_object(state, 1, class_name()));
	size_t size = static_cast<size_t>(check_integer(state, 2));
	std::string buffer;
	buffer.resize(size);
	if (!buffer.empty())
		object->Read(&buffer[0], buffer.size());
	lua_pushlstring(state, buffer.c_str(), buffer.size());
	return 1;
}

/**
 * PESegmentsBinder
 */

void PESegmentsBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"item", &SafeFunction<item>},
		{"count", &SafeFunction<count>},
		{"itemByAddress", &SafeFunction<GetItemByAddress>},
		{"itemByName", &SafeFunction<GetItemByName>},
		{NULL, NULL}
	};
	register_class(state, class_name(), methods);

	PESegmentBinder::Register(state);
}

int PESegmentsBinder::item(lua_State *state)
{
	PESegmentList *object = reinterpret_cast<PESegmentList *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, PESegmentBinder::class_name(), object->item(index));
	return 1;
}

int PESegmentsBinder::count(lua_State *state)
{
	PESegmentList *object = reinterpret_cast<PESegmentList *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int PESegmentsBinder::GetItemByAddress(lua_State *state)
{
	PESegmentList *object = reinterpret_cast<PESegmentList *>(check_object(state, 1, class_name()));
	uint64_t address = check_uint64(state, 2);
	push_object(state, PESegmentBinder::class_name(), object->GetSectionByAddress(address));
	return 1;
}

int PESegmentsBinder::GetItemByName(lua_State *state)
{
	PESegmentList *object = reinterpret_cast<PESegmentList *>(check_object(state, 1, class_name()));
	std::string name = luaL_checklstring(state, 2, NULL);
	push_object(state, PESegmentBinder::class_name(), object->GetSectionByName(name));
	return 1;
}

/**
 * PESegmentBinder
 */

void PESegmentBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"address", &SafeFunction<address>},
		{"name", &SafeFunction<name>},
		{"setName", &SafeFunction<set_name>},
		{"size", &SafeFunction<size>},
		{"physicalOffset", &SafeFunction<physical_offset>},
		{"physicalSize", &SafeFunction<physical_size>},
		{"flags", &SafeFunction<flags>},
		{"excludedFromPacking", &SafeFunction<excluded_from_packing>},
		{"destroy", &SafeFunction<destroy>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);
}

int PESegmentBinder::size(lua_State *state)
{
	PESegment *object = reinterpret_cast<PESegment *>(check_object(state, 1, class_name()));
	push_uint64(state, object->size());
	return 1;
}

int PESegmentBinder::address(lua_State *state)
{
	PESegment *object = reinterpret_cast<PESegment *>(check_object(state, 1, class_name()));
	push_uint64(state, object->address());
	return 1;
}

int PESegmentBinder::name(lua_State *state)
{
	PESegment *object = reinterpret_cast<PESegment *>(check_object(state, 1, class_name()));
	std::string name = object->name();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int PESegmentBinder::set_name(lua_State *state)
{
	PESegment *object = reinterpret_cast<PESegment *>(check_object(state, 1, class_name()));
	std::string name = luaL_checkstring(state, 2);
	object->set_name(name);
	return 0;
}

int PESegmentBinder::physical_offset(lua_State *state)
{
	PESegment *object = reinterpret_cast<PESegment *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->physical_offset());
	return 1;
}

int PESegmentBinder::physical_size(lua_State *state)
{
	PESegment *object = reinterpret_cast<PESegment *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->physical_size());
	return 1;
}

int PESegmentBinder::flags(lua_State *state)
{
	PESegment *object = reinterpret_cast<PESegment *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->flags());
	return 1;
}

int PESegmentBinder::excluded_from_packing(lua_State *state)
{
	PESegment *object = reinterpret_cast<PESegment *>(check_object(state, 1, class_name()));
	lua_pushboolean(state, object->excluded_from_packing());
	return 1;
}

int PESegmentBinder::destroy(lua_State *state)
{
	delete_object(state, 1, class_name());
	return 0;
}

/**
 * PESectionsBinder
 */

void PESectionsBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"item", &SafeFunction<item>},
		{"count", &SafeFunction<count>},
		{"itemByAddress", &SafeFunction<GetItemByAddress>},
		{NULL, NULL}
	};
	register_class(state, class_name(), methods);

	PESectionBinder::Register(state);
}

int PESectionsBinder::item(lua_State *state)
{
	PESectionList *object = reinterpret_cast<PESectionList *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, PESectionBinder::class_name(), object->item(index));
	return 1;
}

int PESectionsBinder::count(lua_State *state)
{
	PESectionList *object = reinterpret_cast<PESectionList *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int PESectionsBinder::GetItemByAddress(lua_State *state)
{
	PESectionList *object = reinterpret_cast<PESectionList *>(check_object(state, 1, class_name()));
	uint64_t address = check_uint64(state, 2);
	push_object(state, PESectionBinder::class_name(), object->GetSectionByAddress(address));
	return 1;
}

/**
 * PESectionBinder
 */

void PESectionBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"address", &SafeFunction<address>},
		{"name", &SafeFunction<name>},
		{"size", &SafeFunction<size>},
		{"offset", &SafeFunction<offset>},
		{"segment", &SafeFunction<segment>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);
}

int PESectionBinder::size(lua_State *state)
{
	PESection *object = reinterpret_cast<PESection *>(check_object(state, 1, class_name()));
	push_uint64(state, object->size());
	return 1;
}

int PESectionBinder::address(lua_State *state)
{
	PESection *object = reinterpret_cast<PESection *>(check_object(state, 1, class_name()));
	push_uint64(state, object->address());
	return 1;
}

int PESectionBinder::name(lua_State *state)
{
	PESection *object = reinterpret_cast<PESection *>(check_object(state, 1, class_name()));
	std::string name = object->name();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int PESectionBinder::offset(lua_State *state)
{
	PESection *object = reinterpret_cast<PESection *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->physical_offset());
	return 1;
}

int PESectionBinder::segment(lua_State *state)
{
	PESection *object = reinterpret_cast<PESection *>(check_object(state, 1, class_name()));
	push_object(state, PESegmentBinder::class_name(), object->parent());
	return 1;
}

/**
 * PEDirectoriesBinder
 */

void PEDirectoriesBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"item", &SafeFunction<item>},
		{"count", &SafeFunction<count>},
		{"itemByType", &SafeFunction<GetItemByType>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	PEDirectoryBinder::Register(state);
}

int PEDirectoriesBinder::item(lua_State *state)
{
	PEDirectoryList *object = reinterpret_cast<PEDirectoryList *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, PEDirectoryBinder::class_name(), object->item(index));
	return 1;
}

int PEDirectoriesBinder::count(lua_State *state)
{
	PEDirectoryList *object = reinterpret_cast<PEDirectoryList *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int PEDirectoriesBinder::GetItemByType(lua_State *state)
{
	PEDirectoryList *object = reinterpret_cast<PEDirectoryList *>(check_object(state, 1, class_name()));
	uint32_t type = static_cast<uint32_t>(check_integer(state, 2));
	push_object(state, PEDirectoryBinder::class_name(), object->GetCommandByType(type));
	return 1;
}

/**
 * PEDirectoryBinder
 */

void PEDirectoryBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"address", &SafeFunction<address>},
		{"type", &SafeFunction<type>},
		{"name", &SafeFunction<name>},
		{"size", &SafeFunction<size>},
		{"setAddress", &SafeFunction<set_address>},
		{"setSize", &SafeFunction<set_size>},
		{"clear", &SafeFunction<clear>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);
}

int PEDirectoryBinder::size(lua_State *state)
{
	PEDirectory *object = reinterpret_cast<PEDirectory *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->size());
	return 1;
}

int PEDirectoryBinder::address(lua_State *state)
{
	PEDirectory *object = reinterpret_cast<PEDirectory *>(check_object(state, 1, class_name()));
	push_uint64(state, object->address());
	return 1;
}

int PEDirectoryBinder::name(lua_State *state)
{
	PEDirectory *object = reinterpret_cast<PEDirectory *>(check_object(state, 1, class_name()));
	std::string name = object->name();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int PEDirectoryBinder::type(lua_State *state)
{
	PEDirectory *object = reinterpret_cast<PEDirectory *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->type());
	return 1;
}

int PEDirectoryBinder::set_size(lua_State *state)
{
	PEDirectory *object = reinterpret_cast<PEDirectory *>(check_object(state, 1, class_name()));
	uint32_t size = static_cast<uint32_t>(check_integer(state, 2));
	object->set_size(size);
	return 0;
}

int PEDirectoryBinder::set_address(lua_State *state)
{
	PEDirectory *object = reinterpret_cast<PEDirectory *>(check_object(state, 1, class_name()));
	uint64_t address = check_uint64(state, 2);
	object->set_address(address);
	return 0;
}

int PEDirectoryBinder::clear(lua_State *state)
{
	PEDirectory *object = reinterpret_cast<PEDirectory *>(check_object(state, 1, class_name()));
	object->clear();
	return 0;
}

/**
 * PEFormatBinder
 */

void PEFormatBinder::Register(lua_State *state)
{
	static const EnumReg values[] = {
		// Directory Entries
		{"IMAGE_DIRECTORY_ENTRY_EXPORT", IMAGE_DIRECTORY_ENTRY_EXPORT},
		{"IMAGE_DIRECTORY_ENTRY_IMPORT", IMAGE_DIRECTORY_ENTRY_IMPORT},
		{"IMAGE_DIRECTORY_ENTRY_RESOURCE", IMAGE_DIRECTORY_ENTRY_RESOURCE},
		{"IMAGE_DIRECTORY_ENTRY_EXCEPTION", IMAGE_DIRECTORY_ENTRY_EXCEPTION},
		{"IMAGE_DIRECTORY_ENTRY_SECURITY", IMAGE_DIRECTORY_ENTRY_SECURITY},
		{"IMAGE_DIRECTORY_ENTRY_BASERELOC", IMAGE_DIRECTORY_ENTRY_BASERELOC},
		{"IMAGE_DIRECTORY_ENTRY_DEBUG", IMAGE_DIRECTORY_ENTRY_DEBUG},
		{"IMAGE_DIRECTORY_ENTRY_ARCHITECTURE", IMAGE_DIRECTORY_ENTRY_ARCHITECTURE},
		{"IMAGE_DIRECTORY_ENTRY_TLS", IMAGE_DIRECTORY_ENTRY_TLS},
		{"IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG},
		{"IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT},
		{"IMAGE_DIRECTORY_ENTRY_IAT", IMAGE_DIRECTORY_ENTRY_IAT},
		{"IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT},
		{"IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR},
		// Section characteristics
		{"IMAGE_SCN_CNT_CODE", IMAGE_SCN_CNT_CODE},
		{"IMAGE_SCN_CNT_INITIALIZED_DATA", IMAGE_SCN_CNT_INITIALIZED_DATA},
		{"IMAGE_SCN_CNT_UNINITIALIZED_DATA", IMAGE_SCN_CNT_UNINITIALIZED_DATA},
		{"IMAGE_SCN_MEM_DISCARDABLE", IMAGE_SCN_MEM_DISCARDABLE},
		{"IMAGE_SCN_MEM_NOT_CACHED", IMAGE_SCN_MEM_NOT_CACHED},
		{"IMAGE_SCN_MEM_NOT_PAGED", IMAGE_SCN_MEM_NOT_PAGED},
		{"IMAGE_SCN_MEM_SHARED", IMAGE_SCN_MEM_SHARED},
		{"IMAGE_SCN_MEM_EXECUTE", IMAGE_SCN_MEM_EXECUTE},
		{"IMAGE_SCN_MEM_READ", IMAGE_SCN_MEM_READ},
		{"IMAGE_SCN_MEM_WRITE", IMAGE_SCN_MEM_WRITE},
		// DllCharacteristics
		{"IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE},
		{"IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY", IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY},
		{"IMAGE_DLLCHARACTERISTICS_NX_COMPAT", IMAGE_DLLCHARACTERISTICS_NX_COMPAT},
		{"IMAGE_DLLCHARACTERISTICS_NO_ISOLATION", IMAGE_DLLCHARACTERISTICS_NO_ISOLATION},
		{"IMAGE_DLLCHARACTERISTICS_NO_SEH", IMAGE_DLLCHARACTERISTICS_NO_SEH},
		{"IMAGE_DLLCHARACTERISTICS_NO_BIND", IMAGE_DLLCHARACTERISTICS_NO_BIND},
		{"IMAGE_DLLCHARACTERISTICS_WDM_DRIVER", IMAGE_DLLCHARACTERISTICS_WDM_DRIVER},
		{"IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE", IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE},
		// Resource types
		{"RT_CURSOR", rtCursor},
		{"RT_BITMAP", rtBitmap},
		{"RT_ICON", rtIcon},
		{"RT_MENU", rtMenu},
		{"RT_DIALOG", rtDialog},
		{"RT_STRING", rtStringTable},
		{"RT_FONTDIR", rtFontDir},
		{"RT_FONT", rtFont},
		{"RT_ACCELERATOR", rtAccelerators},
		{"RT_RCDATA", rtRCData},
		{"RT_MESSAGETABLE", rtMessageTable},
		{"RT_GROUP_CURSOR", rtGroupCursor},
		{"RT_GROUP_ICON", rtGroupIcon},
		{"RT_VERSION", rtVersionInfo},
		{"RT_DLGINCLUDE", rtDlgInclude},
		{"RT_PLUGPLAY", rtPlugPlay},
		{"RT_VXD", rtVXD},
		{"RT_ANICURSOR", rtAniCursor},
		{"RT_ANIICON", rtAniIcon},
		{"RT_HTML", rtHTML},
		{"RT_MANIFEST", rtManifest},
		{"RT_DLGINIT", rtDialogInit},
		{"RT_TOOLBAR", rtToolbar},
		{NULL, 0}
	};

	register_enum(state, enum_name(), values);
}

/**
 * PEImportsBinder
 */

void PEImportsBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"item", &SafeFunction<item>},
		{"count", &SafeFunction<count>},
		{"itemByName", &SafeFunction<GetItemByName>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	PEImportBinder::Register(state);
}

int PEImportsBinder::item(lua_State *state)
{
	PEImportList *object = reinterpret_cast<PEImportList *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, PEImportBinder::class_name(), object->item(index));
	return 1;
}

int PEImportsBinder::count(lua_State *state)
{
	PEImportList *object = reinterpret_cast<PEImportList *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int PEImportsBinder::GetItemByName(lua_State *state)
{
	PEImportList *object = reinterpret_cast<PEImportList *>(check_object(state, 1, class_name()));
	std::string name = luaL_checklstring(state, 2, NULL);
	push_object(state, PEImportBinder::class_name(), object->GetImportByName(name));
	return 1;
}

/**
 * PEImportBinder
 */

void PEImportBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"name", &SafeFunction<name>},
		{"item", &SafeFunction<item>},
		{"count", &SafeFunction<count>},
		{"isSDK", &SafeFunction<is_sdk>},
		{"setName", &SafeFunction<set_name>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	PEImportFunctionBinder::Register(state);
}

int PEImportBinder::item(lua_State *state)
{
	PEImport *object = reinterpret_cast<PEImport *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, PEImportFunctionBinder::class_name(), object->item(index));
	return 1;
}

int PEImportBinder::count(lua_State *state)
{
	PEImport *object = reinterpret_cast<PEImport *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int PEImportBinder::name(lua_State *state)
{
	PEImport *object = reinterpret_cast<PEImport *>(check_object(state, 1, class_name()));
	std::string name = object->name();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int PEImportBinder::is_sdk(lua_State *state)
{
	PEImport *object = reinterpret_cast<PEImport *>(check_object(state, 1, class_name()));
	lua_pushboolean(state, object->is_sdk());
	return 1;
}

int PEImportBinder::set_name(lua_State *state)
{
	PEImport *object = reinterpret_cast<PEImport *>(check_object(state, 1, class_name()));
	std::string name = luaL_checkstring(state, 2);
	object->set_name(name);
	return 0;
}

/**
 * PEImportFunctionBinder
 */

void PEImportFunctionBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"address", &SafeFunction<address>},
		{"name", &SafeFunction<name>},
		{"type", &SafeFunction<type>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	APITypeBinder::Register(state);
}

int PEImportFunctionBinder::address(lua_State *state)
{
	PEImportFunction *object = reinterpret_cast<PEImportFunction *>(check_object(state, 1, class_name()));
	push_uint64(state, object->address());
	return 1;
}

int PEImportFunctionBinder::name(lua_State *state)
{
	PEImportFunction *object = reinterpret_cast<PEImportFunction *>(check_object(state, 1, class_name()));
	std::string name = object->name();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int PEImportFunctionBinder::type(lua_State *state)
{
	PEImportFunction *object = reinterpret_cast<PEImportFunction *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->type());
	return 1;
}

/**
 * APITypeBinder
 */

void APITypeBinder::Register(lua_State *state)
{
	static const EnumReg values[] = {
		{"None", atNone},
		{"Begin", atBegin},
		{"End", atEnd},
		{"IsVirtualMachinePresent", atIsVirtualMachinePresent},
		{"IsDebuggerPresent", atIsDebuggerPresent},
		{"IsValidImageCRC", atIsValidImageCRC},
		{"DecryptStringA", atDecryptStringA},
		{"DecryptStringW", atDecryptStringW},
		{"FreeString", atFreeString},
		{"ActivateLicense", atActivateLicense},
		{"DeactivateLicense", atDeactivateLicense},
		{"GetOfflineActivationString", atGetOfflineActivationString},
		{"GetOfflineDeactivationString", atGetOfflineDeactivationString},
		{"SetSerialNumber", atSetSerialNumber},
		{"GetSerialNumberState", atGetSerialNumberState},
		{"GetSerialNumberData", atGetSerialNumberData},
		{"GetCurrentHWID", atGetCurrentHWID},
		{"LoadResource", atLoadResource},
		{"FindResourceA", atFindResourceA},
		{"FindResourceExA", atFindResourceExA},
		{"FindResourceW", atFindResourceW},
		{"FindResourceExW", atFindResourceExW},
		{"LoadStringA", atLoadStringA},
		{"LoadStringW", atLoadStringW},
		{"EnumResourceNamesA", atEnumResourceNamesA},
		{"EnumResourceNamesW", atEnumResourceNamesW},
		{"EnumResourceLanguagesA", atEnumResourceLanguagesA},
		{"EnumResourceLanguagesW", atEnumResourceLanguagesW},
		{"EnumResourceTypesA", atEnumResourceTypesA},
		{"EnumResourceTypesW", atEnumResourceTypesW},
		{"DecryptBuffer", atDecryptBuffer},
		{"RuntimeInit", atRuntimeInit},
		{"LoaderData", atLoaderData},
		{NULL, 0}
	};

	register_enum(state, enum_name(), values);
}

/**
 * PEExportsBinder
 */

void PEExportsBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"name", &SafeFunction<name>},
		{"setName", &SafeFunction<set_name>},
		{"item", &SafeFunction<item>},
		{"count", &SafeFunction<count>},
		{"clear", &SafeFunction<clear>},
		{"delete", &SafeFunction<Delete>},
		{"itemByAddress", &SafeFunction<GetItemByAddress>},
		{"itemByName", &SafeFunction<GetItemByName>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	PEExportBinder::Register(state);
}

int PEExportsBinder::item(lua_State *state)
{
	PEExportList *object = reinterpret_cast<PEExportList *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, PEExportBinder::class_name(), object->item(index));
	return 1;
}

int PEExportsBinder::count(lua_State *state)
{
	PEExportList *object = reinterpret_cast<PEExportList *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int PEExportsBinder::clear(lua_State *state)
{
	PEExportList *object = reinterpret_cast<PEExportList *>(check_object(state, 1, class_name()));
	object->clear();
	return 0;
}

int PEExportsBinder::Delete(lua_State *state)
{
	PEExportList *object = reinterpret_cast<PEExportList *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	object->Delete(index);
	return 0;
}

int PEExportsBinder::name(lua_State *state)
{
	PEExportList *object = reinterpret_cast<PEExportList *>(check_object(state, 1, class_name()));
	std::string name = object->name();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int PEExportsBinder::set_name(lua_State *state)
{
	PEExportList *object = reinterpret_cast<PEExportList *>(check_object(state, 1, class_name()));
	std::string name = luaL_checkstring(state, 2);
	object->set_name(name);
	return 0;
}

int PEExportsBinder::GetItemByAddress(lua_State *state)
{
	PEExportList *object = reinterpret_cast<PEExportList *>(check_object(state, 1, class_name()));
	uint64_t address = check_uint64(state, 2);
	push_object(state, PEExportBinder::class_name(), object->GetExportByAddress(address));
	return 1;
}

int PEExportsBinder::GetItemByName(lua_State *state)
{
	PEExportList *object = reinterpret_cast<PEExportList *>(check_object(state, 1, class_name()));
	std::string name = luaL_checklstring(state, 2, NULL);
	push_object(state, PEExportBinder::class_name(), object->GetExportByName(name));
	return 1;
}

/**
 * PEExportBinder
 */

void PEExportBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"address", &SafeFunction<address>},
		{"name", &SafeFunction<name>},
		{"setName", &SafeFunction<set_name>},
		{"ordinal", &SafeFunction<ordinal>},
		{"forwardedName", &SafeFunction<forwarded_name>},
		{"destroy", &SafeFunction<destroy>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);
}

int PEExportBinder::address(lua_State *state)
{
	PEExport *object = reinterpret_cast<PEExport *>(check_object(state, 1, class_name()));
	push_uint64(state, object->address());
	return 1;
}

int PEExportBinder::name(lua_State *state)
{
	PEExport *object = reinterpret_cast<PEExport *>(check_object(state, 1, class_name()));
	std::string name = object->name();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int PEExportBinder::set_name(lua_State *state)
{
	PEExport *object = reinterpret_cast<PEExport *>(check_object(state, 1, class_name()));
	std::string name = luaL_checkstring(state, 2);
	object->set_name(name);
	return 0;
}

int PEExportBinder::ordinal(lua_State *state)
{
	PEExport *object = reinterpret_cast<PEExport *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->ordinal());
	return 1;
}

int PEExportBinder::forwarded_name(lua_State *state)
{
	PEExport *object = reinterpret_cast<PEExport *>(check_object(state, 1, class_name()));
	std::string name = object->forwarded_name();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int PEExportBinder::destroy(lua_State *state)
{
	delete_object(state, 1, class_name());
	return 0;
}

/**
 * PEResourcesBinder
 */

void PEResourcesBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"item", &SafeFunction<item>},
		{"count", &SafeFunction<count>},
		{"clear", &SafeFunction<clear>},
		{"itemByName", &SafeFunction<GetItemByName>},
		{"itemByType", &SafeFunction<GetItemByType>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	PEResourceBinder::Register(state);
}

int PEResourcesBinder::item(lua_State *state)
{
	PEResourceList *object = reinterpret_cast<PEResourceList *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, PEResourceBinder::class_name(), object->item(index));
	return 1;
}

int PEResourcesBinder::count(lua_State *state)
{
	PEResourceList *object = reinterpret_cast<PEResourceList *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int PEResourcesBinder::clear(lua_State *state)
{
	PEResourceList *object = reinterpret_cast<PEResourceList *>(check_object(state, 1, class_name()));
	object->clear();
	return 0;
}

int PEResourcesBinder::GetItemByName(lua_State *state)
{
	PEResourceList *object = reinterpret_cast<PEResourceList *>(check_object(state, 1, class_name()));
	std::string name = luaL_checklstring(state, 2, NULL);
	push_object(state, PEResourceBinder::class_name(), object->GetResourceByName(name));
	return 1;
}

int PEResourcesBinder::GetItemByType(lua_State *state)
{
	PEResourceList *object = reinterpret_cast<PEResourceList *>(check_object(state, 1, class_name()));
	uint32_t type = static_cast<uint32_t>(check_integer(state, 2));
	push_object(state, PEResourceBinder::class_name(), object->GetResourceByType(type));
	return 1;
}

/**
 * PEResourceBinder
 */

void PEResourceBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"item", &SafeFunction<item>},
		{"count", &SafeFunction<count>},
		{"clear", &SafeFunction<clear>},
		{"address", &SafeFunction<address>},
		{"size", &SafeFunction<size>},
		{"name", &SafeFunction<name>},
		{"type", &SafeFunction<type>},
		{"isDirectory", &SafeFunction<is_directory>},
		{"destroy", &SafeFunction<destroy>},
		{"itemByName", &SafeFunction<GetItemByName>},
		{"excludedFromPacking", &SafeFunction<excluded_from_packing>},
		{"setExcludedFromPacking", &SafeFunction<set_excluded_from_packing>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);
}

int PEResourceBinder::item(lua_State *state)
{
	PEResource *object = reinterpret_cast<PEResource *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, class_name(), object->item(index));
	return 1;
}

int PEResourceBinder::count(lua_State *state)
{
	PEResource *object = reinterpret_cast<PEResource *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int PEResourceBinder::clear(lua_State *state)
{
	PEResource *object = reinterpret_cast<PEResource *>(check_object(state, 1, class_name()));
	object->clear();
	return 0;
}

int PEResourceBinder::address(lua_State *state)
{
	PEResource *object = reinterpret_cast<PEResource *>(check_object(state, 1, class_name()));
	push_uint64(state, object->address());
	return 1;
}

int PEResourceBinder::size(lua_State *state)
{
	PEResource *object = reinterpret_cast<PEResource *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->size());
	return 1;
}

int PEResourceBinder::name(lua_State *state)
{
	PEResource *object = reinterpret_cast<PEResource *>(check_object(state, 1, class_name()));
	std::string name = object->name();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int PEResourceBinder::type(lua_State *state)
{
	PEResource *object = reinterpret_cast<PEResource *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->type());
	return 1;
}

int PEResourceBinder::is_directory(lua_State *state)
{
	PEResource *object = reinterpret_cast<PEResource *>(check_object(state, 1, class_name()));
	lua_pushboolean(state, object->is_directory());
	return 1;
}

int PEResourceBinder::destroy(lua_State *state)
{
	delete_object(state, 1, class_name());
	return 0;
}

int PEResourceBinder::GetItemByName(lua_State *state)
{
	PEResource *object = reinterpret_cast<PEResource *>(check_object(state, 1, class_name()));
	std::string name = luaL_checklstring(state, 2, NULL);
	push_object(state, PEResourceBinder::class_name(), object->GetResourceByName(name));
	return 1;
}

int PEResourceBinder::excluded_from_packing(lua_State *state)
{
	PEResource *object = reinterpret_cast<PEResource *>(check_object(state, 1, class_name()));
	lua_pushboolean(state, object->excluded_from_packing());
	return 1;
}

int PEResourceBinder::set_excluded_from_packing(lua_State *state)
{
	PEResource *object = reinterpret_cast<PEResource *>(check_object(state, 1, class_name()));
	bool excluded_from_packing = check_integer(state, 2) == 1;
	object->set_excluded_from_packing(excluded_from_packing);
	return 0;
}

/**
 * PEFixupsBinder
 */

void PEFixupsBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"item", &SafeFunction<item>},
		{"count", &SafeFunction<count>},
		{"indexOf", &SafeFunction<IndexOf>},
		{"itemByAddress", &SafeFunction<GetItemByAddress>},
		{NULL, NULL}
	};
	register_class(state, class_name(), methods);

	PEFixupBinder::Register(state);
}

int PEFixupsBinder::item(lua_State *state)
{
	PEFixupList *object = reinterpret_cast<PEFixupList *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, PEFixupBinder::class_name(), object->item(index));
	return 1;
}

int PEFixupsBinder::count(lua_State *state)
{
	PEFixupList *object = reinterpret_cast<PEFixupList *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int PEFixupsBinder::IndexOf(lua_State *state)
{
	PEFixupList *object = reinterpret_cast<PEFixupList *>(check_object(state, 1, class_name()));
	PEFixup *item = reinterpret_cast<PEFixup *>(check_object(state, 2, PEFixupBinder::class_name()));
	lua_pushinteger(state, object->IndexOf(item) + 1);
	return 1;
}

int PEFixupsBinder::GetItemByAddress(lua_State *state)
{
	PEFixupList *object = reinterpret_cast<PEFixupList *>(check_object(state, 1, class_name()));
	uint64_t address = check_uint64(state, 2);
	push_object(state, PEFixupBinder::class_name(), object->GetFixupByAddress(address));
	return 1;
}

/**
 * PEFixupBinder
 */

void PEFixupBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"address", &SafeFunction<address>},
		{"setDeleted", &SafeFunction<set_deleted>},
		{NULL, NULL}
	};
	register_class(state, class_name(), methods);
}

int PEFixupBinder::address(lua_State *state)
{
	PEFixup *object = reinterpret_cast<PEFixup *>(check_object(state, 1, class_name()));
	push_uint64(state, object->address());
	return 1;
}

int PEFixupBinder::set_deleted(lua_State *state)
{
	PEFixup *object = reinterpret_cast<PEFixup *>(check_object(state, 1, class_name()));
	bool value = lua_toboolean(state, 2) == 1;
	object->set_deleted(value);
	return 0;
}

/**
 * MapFunctionsBinder
 */

void MapFunctionsBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"item", &SafeFunction<item>},
		{"count", &SafeFunction<count>},
		{"itemByAddress", &SafeFunction<GetItemByAddress>},
		{"itemByName", &SafeFunction<GetItemByName>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	MapFunctionBinder::Register(state);
}

int MapFunctionsBinder::item(lua_State *state)
{
	MapFunctionList *object = reinterpret_cast<MapFunctionList *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, MapFunctionBinder::class_name(), object->item(index));
	return 1;
}

int MapFunctionsBinder::count(lua_State *state)
{
	MapFunctionList *object = reinterpret_cast<MapFunctionList *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int MapFunctionsBinder::GetItemByAddress(lua_State *state)
{
	MapFunctionList *object = reinterpret_cast<MapFunctionList *>(check_object(state, 1, class_name()));
	uint64_t address = check_uint64(state, 2);
	push_object(state, MapFunctionBinder::class_name(), object->GetFunctionByAddress(address));
	return 1;
}

int MapFunctionsBinder::GetItemByName(lua_State *state)
{
	MapFunctionList *object = reinterpret_cast<MapFunctionList *>(check_object(state, 1, class_name()));
	std::string name = luaL_checklstring(state, 2, NULL);
	push_object(state, MapFunctionBinder::class_name(), object->GetFunctionByName(name));
	return 1;
}

/**
 * MapFunctionBinder
 */

void MapFunctionBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"address", &SafeFunction<address>},
		{"size", &SafeFunction<size>},
		{"name", &SafeFunction<name>},
		{"type", &SafeFunction<type>},
		{"references", &SafeFunction<references>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	ReferencesBinder::Register(state);
}

int MapFunctionBinder::address(lua_State *state)
{
	MapFunction *object = reinterpret_cast<MapFunction *>(check_object(state, 1, class_name()));
	push_uint64(state, object->address());
	return 1;
}

int MapFunctionBinder::size(lua_State *state)
{
	MapFunction *object = reinterpret_cast<MapFunction *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->end_address() ? static_cast<lua_Integer>(object->end_address() - object->address()) : 0);
	return 1;
}

int MapFunctionBinder::name(lua_State *state)
{
	MapFunction *object = reinterpret_cast<MapFunction *>(check_object(state, 1, class_name()));
	std::string name = object->name();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int MapFunctionBinder::type(lua_State *state)
{
	MapFunction *object = reinterpret_cast<MapFunction *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->type());
	return 1;
}

int MapFunctionBinder::references(lua_State *state)
{
	MapFunction *object = reinterpret_cast<MapFunction *>(check_object(state, 1, class_name()));
	push_object(state, ReferencesBinder::class_name(), object->reference_list());
	return 1;
}

/**
 * ReferencesBinder
 */

void ReferencesBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"item", &SafeFunction<item>},
		{"count", &SafeFunction<count>},
		{"clear", &SafeFunction<clear>},
		{"delete", &SafeFunction<Delete>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	ReferenceBinder::Register(state);
}

int ReferencesBinder::item(lua_State *state)
{
	ReferenceList *object = reinterpret_cast<ReferenceList *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, ReferenceBinder::class_name(), object->item(index));
	return 1;
}

int ReferencesBinder::count(lua_State *state)
{
	ReferenceList *object = reinterpret_cast<ReferenceList *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int ReferencesBinder::clear(lua_State *state)
{
	ReferenceList *object = reinterpret_cast<ReferenceList *>(check_object(state, 1, class_name()));
	object->clear();
	return 0;
}

int ReferencesBinder::Delete(lua_State *state)
{
	ReferenceList *object = reinterpret_cast<ReferenceList *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	object->Delete(index);
	return 0;
}

/**
 * ReferenceBinder
 */

void ReferenceBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"address", &SafeFunction<address>},
		{"operandAddress", &SafeFunction<operand_address>},
		{"tag", &SafeFunction<tag>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);
}

int ReferenceBinder::address(lua_State *state)
{
	Reference *object = reinterpret_cast<Reference *>(check_object(state, 1, class_name()));
	push_uint64(state, object->address());
	return 1;
}

int ReferenceBinder::operand_address(lua_State *state)
{
	Reference *object = reinterpret_cast<Reference *>(check_object(state, 1, class_name()));
	push_uint64(state, object->operand_address());
	return 1;
}

int ReferenceBinder::tag(lua_State *state)
{
	Reference *object = reinterpret_cast<Reference *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->tag());
	return 1;
}

/**
 * IntelFunctionsBinder
 */

void IntelFunctionsBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"item", &SafeFunction<item>},
		{"count", &SafeFunction<count>},
		{"clear", &SafeFunction<clear>},
		{"delete", &SafeFunction<Delete>},
		{"itemByAddress", &SafeFunction<GetItemByAddress>},
		{"itemByName", &SafeFunction<GetItemByName>},
		{"addByAddress", &SafeFunction<AddByAddress>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	IntelFunctionBinder::Register(state);
}

int IntelFunctionsBinder::item(lua_State *state)
{
	IntelFunctionList *object = reinterpret_cast<IntelFunctionList *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, IntelFunctionBinder::class_name(), object->item(index));
	return 1;
}

int IntelFunctionsBinder::count(lua_State *state)
{
	IntelFunctionList *object = reinterpret_cast<IntelFunctionList *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int IntelFunctionsBinder::clear(lua_State *state)
{
	IntelFunctionList *object = reinterpret_cast<IntelFunctionList *>(check_object(state, 1, class_name()));
	object->clear();
	return 0;
}

int IntelFunctionsBinder::Delete(lua_State *state)
{
	IntelFunctionList *object = reinterpret_cast<IntelFunctionList *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	object->Delete(index);
	return 0;
}

int IntelFunctionsBinder::GetItemByAddress(lua_State *state)
{
	IntelFunctionList *object = reinterpret_cast<IntelFunctionList *>(check_object(state, 1, class_name()));
	uint64_t address = check_uint64(state, 2);
	push_object(state, IntelFunctionBinder::class_name(), object->GetFunctionByAddress(address));
	return 1;
}

int IntelFunctionsBinder::GetItemByName(lua_State *state)
{
	IntelFunctionList *object = reinterpret_cast<IntelFunctionList *>(check_object(state, 1, class_name()));
	std::string name = luaL_checklstring(state, 2, NULL);
	push_object(state, IntelFunctionBinder::class_name(), object->GetFunctionByName(name));
	return 1;
}

int IntelFunctionsBinder::AddByAddress(lua_State *state)
{
	IntelFunctionList *object = reinterpret_cast<IntelFunctionList *>(check_object(state, 1, class_name()));
	uint64_t address = check_uint64(state, 2);
	int top = lua_gettop(state);
	CompilationType compilation_type = (top > 2) ? static_cast<CompilationType>(lua_tointeger(state, 3)) : ctVirtualization;
	bool need_compile = (top > 3) ? lua_toboolean(state, 4) == 1 : true;
	push_object(state, IntelFunctionBinder::class_name(), object->AddByAddress(address, compilation_type, 0, need_compile, NULL));
	return 1;
}

/**
 * IntelFunctionBinder
 */

void IntelFunctionBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"address", &SafeFunction<address>},
		{"name", &SafeFunction<name>},
		{"item", &SafeFunction<item>},
		{"count", &SafeFunction<count>},
		{"type", &SafeFunction<type>},
		{"compilationType", &SafeFunction<compilation_type>},
		{"setCompilationType", &SafeFunction<set_compilation_type>},
		{"lockToKey", &SafeFunction<lock_to_key>},
		{"setLockToKey", &SafeFunction<set_lock_to_key>},
		{"needCompile", &SafeFunction<need_compile>},
		{"setNeedCompile", &SafeFunction<set_need_compile>},
		{"links", &SafeFunction<links>},
		{"itemByAddress", &SafeFunction<GetItemByAddress>},
		{"indexOf", &SafeFunction<IndexOf>},
		{"destroy", &SafeFunction<destroy>},
		{"info", &SafeFunction<info>},
		{"ranges", &SafeFunction<ranges>},
		{"xproc", &SafeFunction<x_proc>},
		{"folder", &SafeFunction<folder>},
		{"setFolder", &SafeFunction<set_folder>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	IntelCommandBinder::Register(state);
	CompilationTypeBinder::Register(state);
	CommandLinksBinder::Register(state);
	FunctionInfoListBinder::Register(state);
}

int IntelFunctionBinder::address(lua_State *state)
{
	IntelFunction *object = reinterpret_cast<IntelFunction *>(check_object(state, 1, class_name()));
	push_uint64(state, object->address());
	return 1;
}

int IntelFunctionBinder::name(lua_State *state)
{
	IntelFunction *object = reinterpret_cast<IntelFunction *>(check_object(state, 1, class_name()));
	std::string name = object->name();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int IntelFunctionBinder::item(lua_State *state)
{
	IntelFunction *object = reinterpret_cast<IntelFunction *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, IntelCommandBinder::class_name(), object->item(index));
	return 1;
}

int IntelFunctionBinder::count(lua_State *state)
{
	IntelFunction *object = reinterpret_cast<IntelFunction *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int IntelFunctionBinder::type(lua_State *state)
{
	IntelFunction *object = reinterpret_cast<IntelFunction *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->type());
	return 1;
}

int IntelFunctionBinder::compilation_type(lua_State *state)
{
	IntelFunction *object = reinterpret_cast<IntelFunction *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->compilation_type());
	return 1;
}

int IntelFunctionBinder::set_compilation_type(lua_State *state)
{
	IntelFunction *object = reinterpret_cast<IntelFunction *>(check_object(state, 1, class_name()));
	CompilationType compilation_type = static_cast<CompilationType>(check_integer(state, 2));
	object->set_compilation_type(compilation_type);
	return 0;
}

int IntelFunctionBinder::lock_to_key(lua_State *state)
{
	IntelFunction *object = reinterpret_cast<IntelFunction *>(check_object(state, 1, class_name()));
	lua_pushboolean(state, (object->compilation_options() & coLockToKey) != 0);
	return 1;
}

int IntelFunctionBinder::set_lock_to_key(lua_State *state)
{
	IntelFunction *object = reinterpret_cast<IntelFunction *>(check_object(state, 1, class_name()));
	bool value = lua_toboolean(state, 2) == 1;
	uint32_t options = object->compilation_options();
	if (value) {
		options |= coLockToKey;
	} else {
		options &= ~coLockToKey;
	}
	object->set_compilation_options(options);
	return 0;
}

int IntelFunctionBinder::need_compile(lua_State *state)
{
	IntelFunction *object = reinterpret_cast<IntelFunction *>(check_object(state, 1, class_name()));
	lua_pushboolean(state, object->need_compile());
	return 1;
}

int IntelFunctionBinder::set_need_compile(lua_State *state)
{
	IntelFunction *object = reinterpret_cast<IntelFunction *>(check_object(state, 1, class_name()));
	bool need_compile = lua_toboolean(state, 2) == 1;
	object->set_need_compile(need_compile);
	return 0;
}

int IntelFunctionBinder::links(lua_State *state)
{
	IntelFunction *object = reinterpret_cast<IntelFunction *>(check_object(state, 1, class_name()));
	push_object(state, CommandLinksBinder::class_name(), object->link_list());
	return 1;
}

int IntelFunctionBinder::GetItemByAddress(lua_State *state)
{
	IntelFunction *object = reinterpret_cast<IntelFunction *>(check_object(state, 1, class_name()));
	uint64_t address = check_uint64(state, 2);
	int top = lua_gettop(state);
	bool is_near = (top > 2) ? lua_toboolean(state, 3) == 1 : false;
	push_object(state, IntelCommandBinder::class_name(), is_near ? object->GetCommandByNearAddress(address) : object->GetCommandByAddress(address));
	return 1;
}

int IntelFunctionBinder::IndexOf(lua_State *state)
{
	IntelFunction *object = reinterpret_cast<IntelFunction *>(check_object(state, 1, class_name()));
	IntelCommand *item = reinterpret_cast<IntelCommand *>(check_object(state, 2, IntelCommandBinder::class_name()));
	lua_pushinteger(state, object->IndexOf(item) + 1);
	return 1;
}

int IntelFunctionBinder::destroy(lua_State *state)
{
	delete_object(state, 1, class_name());
	return 0;
}

int IntelFunctionBinder::info(lua_State *state)
{
	IntelFunction *object = reinterpret_cast<IntelFunction *>(check_object(state, 1, class_name()));
	push_object(state, FunctionInfoListBinder::class_name(), object->function_info_list());
	return 1;
}

int IntelFunctionBinder::ranges(lua_State *state)
{
	IntelFunction *object = reinterpret_cast<IntelFunction *>(check_object(state, 1, class_name()));
	push_object(state, FunctionInfoBinder::class_name(), object->range_list());
	return 1;
}

int IntelFunctionBinder::x_proc(lua_State *state)
{
	IntelFunction *object = reinterpret_cast<IntelFunction *>(check_object(state, 1, class_name()));
	uint64_t address = check_uint64(state, 2);
	std::string value = luaL_checklstring(state, 3, NULL);
	object->AddWatermarkReference(address, value);
	return 0;
}

int IntelFunctionBinder::folder(lua_State *state)
{
	IntelFunction *object = reinterpret_cast<IntelFunction *>(check_object(state, 1, class_name()));
	push_object(state, FolderBinder::class_name(), object->folder());
	return 1;
}

int IntelFunctionBinder::set_folder(lua_State *state)
{
	IntelFunction *object = reinterpret_cast<IntelFunction *>(check_object(state, 1, class_name()));
	Folder *folder = reinterpret_cast<Folder *>(check_object(state, 1, FolderBinder::class_name()));
	object->set_folder(folder);
	return 0;
}

/**
 * CommandLinksBinder
 */

void CommandLinksBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"item", &SafeFunction<item>},
		{"count", &SafeFunction<count>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	CommandLinkBinder::Register(state);
}

int CommandLinksBinder::item(lua_State *state)
{
	CommandLinkList *object = reinterpret_cast<CommandLinkList *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, CommandLinkBinder::class_name(), object->item(index));
	return 1;
}

int CommandLinksBinder::count(lua_State *state)
{
	CommandLinkList *object = reinterpret_cast<CommandLinkList *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

/**
 * AddressRangeBinder
 */

void AddressRangeBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"beginAddress", &SafeFunction<begin>},
		{"endAddress", &SafeFunction<end>},
		{"beginEntry", &SafeFunction<begin_entry>},
		{"endEntry", &SafeFunction<end_entry>},
		{"sizeEntry", &SafeFunction<size_entry>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);
}

int AddressRangeBinder::begin(lua_State *state)
{
	AddressRange *object = reinterpret_cast<AddressRange *>(check_object(state, 1, class_name()));
	push_uint64(state, object->begin());
	return 1;
}

int AddressRangeBinder::end(lua_State *state)
{
	AddressRange *object = reinterpret_cast<AddressRange *>(check_object(state, 1, class_name()));
	push_uint64(state, object->end());
	return 1;
}

int AddressRangeBinder::begin_entry(lua_State *state)
{
	AddressRange *object = reinterpret_cast<AddressRange *>(check_object(state, 1, class_name()));
	push_command(state, object->begin_entry());
	return 1;
}

int AddressRangeBinder::end_entry(lua_State *state)
{
	AddressRange *object = reinterpret_cast<AddressRange *>(check_object(state, 1, class_name()));
	push_command(state, object->end_entry());
	return 1;
}

int AddressRangeBinder::size_entry(lua_State *state)
{
	AddressRange *object = reinterpret_cast<AddressRange *>(check_object(state, 1, class_name()));
	push_command(state, object->size_entry());
	return 1;
}

/**
* UnwindOpcodesBinder
*/

void UnwindOpcodesBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"count", &SafeFunction<count>},
		{"item", &SafeFunction<item>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);
}

int UnwindOpcodesBinder::count(lua_State *state)
{
	std::vector<ICommand *> *object = reinterpret_cast<std::vector<ICommand *> *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->size());
	return 1;
}

int UnwindOpcodesBinder::item(lua_State *state)
{
	std::vector<ICommand *> *object = reinterpret_cast<std::vector<ICommand *> *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_command(state, object->at(index));
	return 1;
}

/**
 * FunctionInfoBinder
 */

void FunctionInfoBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"item", &SafeFunction<item>},
		{"count", &SafeFunction<count>},
		{"beginAddress", &SafeFunction<begin>},
		{"endAddress", &SafeFunction<end>},
		{"baseType", &SafeFunction<base_type>},
		{"baseValue", &SafeFunction<base_value>},
		{"prologSize", &SafeFunction<prolog_size>},
		{"frameRegistr", &SafeFunction<frame_registr>},
		{"entry", &SafeFunction<entry>},
		{"dataEntry", &SafeFunction<data_entry>},
		{"unwindOpcodes", &SafeFunction<unwind_opcodes>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	AddressRangeBinder::Register(state);
	UnwindOpcodesBinder::Register(state);
}

int FunctionInfoBinder::item(lua_State *state)
{
	FunctionInfo *object = reinterpret_cast<FunctionInfo *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, AddressRangeBinder::class_name(), object->item(index));
	return 1;
}

int FunctionInfoBinder::count(lua_State *state)
{
	FunctionInfoList *object = reinterpret_cast<FunctionInfoList *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int FunctionInfoBinder::begin(lua_State *state)
{
	FunctionInfo *object = reinterpret_cast<FunctionInfo *>(check_object(state, 1, class_name()));
	push_uint64(state, object->begin());
	return 1;
}

int FunctionInfoBinder::end(lua_State *state)
{
	FunctionInfo *object = reinterpret_cast<FunctionInfo *>(check_object(state, 1, class_name()));
	push_uint64(state, object->end());
	return 1;
}

int FunctionInfoBinder::prolog_size(lua_State *state)
{
	FunctionInfo *object = reinterpret_cast<FunctionInfo *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->prolog_size());
	return 1;
}

int FunctionInfoBinder::frame_registr(lua_State *state)
{
	FunctionInfo *object = reinterpret_cast<FunctionInfo *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->frame_registr());
	return 1;
}

int FunctionInfoBinder::entry(lua_State *state)
{
	FunctionInfo *object = reinterpret_cast<FunctionInfo *>(check_object(state, 1, class_name()));
	push_command(state, object->entry());
	return 1;
}

int FunctionInfoBinder::data_entry(lua_State *state)
{
	FunctionInfo *object = reinterpret_cast<FunctionInfo *>(check_object(state, 1, class_name()));
	push_command(state, object->data_entry());
	return 1;
}

int FunctionInfoBinder::base_type(lua_State *state)
{
	FunctionInfo *object = reinterpret_cast<FunctionInfo *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->base_type());
	return 1;
}

int FunctionInfoBinder::base_value(lua_State *state)
{
	FunctionInfo *object = reinterpret_cast<FunctionInfo *>(check_object(state, 1, class_name()));
	push_uint64(state, object->base_value());
	return 1;
}

int FunctionInfoBinder::unwind_opcodes(lua_State *state)
{
	FunctionInfo *object = reinterpret_cast<FunctionInfo *>(check_object(state, 1, class_name()));
	push_object(state, UnwindOpcodesBinder::class_name(), object->unwind_opcodes());
	return 1;
}

/**
 * FunctionInfoListBinder
 */

void FunctionInfoListBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"item", &SafeFunction<item>},
		{"count", &SafeFunction<count>},
		{"indexOf", &SafeFunction<IndexOf>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	FunctionInfoBinder::Register(state);
}

int FunctionInfoListBinder::item(lua_State *state)
{
	FunctionInfoList *object = reinterpret_cast<FunctionInfoList *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, FunctionInfoBinder::class_name(), object->item(index));
	return 1;
}

int FunctionInfoListBinder::count(lua_State *state)
{
	FunctionInfoList *object = reinterpret_cast<FunctionInfoList *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int FunctionInfoListBinder::IndexOf(lua_State *state)
{
	FunctionInfoList *object = reinterpret_cast<FunctionInfoList *>(check_object(state, 1, class_name()));
	FunctionInfo *item = reinterpret_cast<FunctionInfo *>(check_object(state, 2, FunctionInfoBinder::class_name()));
	lua_pushinteger(state, object->IndexOf(item) + 1);
	return 1;
}

/**
 * CompilationTypeBinder
 */

void CompilationTypeBinder::Register(lua_State *state)
{
	static const EnumReg values[] = {
		{"None", ctNone},
		{"Virtualization", ctVirtualization},
		{"Mutation", ctMutation},
		{"Ultra", ctUltra},
		{NULL, 0}
	};

	register_enum(state, enum_name(), values);
}

/**
 * IntelCommandBinder
 */

void IntelCommandBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"address", &SafeFunction<address>},
		{"type", &SafeFunction<type>},
		{"text", &SafeFunction<text>},
		{"size", &SafeFunction<size>},
		{"dump", &SafeFunction<dump>},
		{"link", &SafeFunction<link>},
		{"flags", &SafeFunction<flags>},
		{"baseSegment", &SafeFunction<base_segment>},
		{"preffix", &SafeFunction<preffix>},
		{"operand", &SafeFunction<operand>},
		{"options", &SafeFunction<options>},
		{"alignment", &SafeFunction<alignment>},
		{"setDump", &SafeFunction<set_dump>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	IntelCommandTypeBinder::Register(state);
	CommandOptionBinder::Register(state);
	IntelOperandBinder::Register(state);
	IntelSegmentBinder::Register(state);
	IntelFlagBinder::Register(state);
	IntelRegistrBinder::Register(state);
}

int IntelCommandBinder::address(lua_State *state)
{
	IntelCommand *object = reinterpret_cast<IntelCommand *>(check_object(state, 1, class_name()));
	push_uint64(state, object->address());
	return 1;
}

int IntelCommandBinder::type(lua_State *state)
{
	IntelCommand *object = reinterpret_cast<IntelCommand *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->type());
	return 1;
}

int IntelCommandBinder::text(lua_State *state)
{
	IntelCommand *object = reinterpret_cast<IntelCommand *>(check_object(state, 1, class_name()));
	std::string text = object->text();
	lua_pushlstring(state, text.c_str(), text.size());
	return 1;
}

int IntelCommandBinder::size(lua_State *state)
{
	IntelCommand *object = reinterpret_cast<IntelCommand *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->dump_size());
	return 1;
}

int IntelCommandBinder::dump(lua_State *state)
{
	IntelCommand *object = reinterpret_cast<IntelCommand *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	lua_pushinteger(state, object->dump(index));
	return 1;
}

int IntelCommandBinder::link(lua_State *state)
{
	IntelCommand *object = reinterpret_cast<IntelCommand *>(check_object(state, 1, class_name()));
	push_object(state, CommandLinkBinder::class_name(), object->link());
	return 1;
}

int IntelCommandBinder::flags(lua_State *state)
{
	IntelCommand *object = reinterpret_cast<IntelCommand *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->flags());
	return 1;
}

int IntelCommandBinder::base_segment(lua_State *state)
{
	IntelCommand *object = reinterpret_cast<IntelCommand *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->base_segment());
	return 1;
}

int IntelCommandBinder::operand(lua_State *state)
{
	IntelCommand *object = reinterpret_cast<IntelCommand *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, IntelOperandBinder::class_name(), object->operand_ptr(index));
	return 1;
}

int IntelCommandBinder::preffix(lua_State *state)
{
	IntelCommand *object = reinterpret_cast<IntelCommand *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->preffix_command());
	return 1;
}

int IntelCommandBinder::options(lua_State *state)
{
	IntelCommand *object = reinterpret_cast<IntelCommand *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->options());
	return 1;
}

int IntelCommandBinder::alignment(lua_State *state)
{
	IntelCommand *object = reinterpret_cast<IntelCommand *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->alignment());
	return 1;
}

int IntelCommandBinder::set_dump(lua_State *state)
{
	IntelCommand *object = reinterpret_cast<IntelCommand *>(check_object(state, 1, class_name()));
	size_t l;
	const char *dump = luaL_checklstring(state, 2, &l);
	object->set_dump(dump, l);
	return 0;
}

/**
 * IntelOperandBinder
 */

void IntelOperandBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"type", &SafeFunction<type>},
		{"size", &SafeFunction<size>},
		{"registr", &SafeFunction<registr>},
		{"baseRegistr", &SafeFunction<base_registr>},
		{"scale", &SafeFunction<scale>},
		{"value", &SafeFunction<value>},
		{"addressSize", &SafeFunction<address_size>},
		{"valueSize", &SafeFunction<value_size>},
		{"fixup", &SafeFunction<fixup>},
		{"isLargeValue", &SafeFunction<is_large_value>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);
}

int IntelOperandBinder::type(lua_State *state)
{
	IntelOperand *object = reinterpret_cast<IntelOperand *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->type);
	return 1;
}

int IntelOperandBinder::size(lua_State *state)
{
	IntelOperand *object = reinterpret_cast<IntelOperand *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->size);
	return 1;
}

int IntelOperandBinder::registr(lua_State *state)
{
	IntelOperand *object = reinterpret_cast<IntelOperand *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->registr);
	return 1;
}

int IntelOperandBinder::base_registr(lua_State *state)
{
	IntelOperand *object = reinterpret_cast<IntelOperand *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->base_registr);
	return 1;
}

int IntelOperandBinder::scale(lua_State *state)
{
	IntelOperand *object = reinterpret_cast<IntelOperand *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->scale_registr);
	return 1;
}

int IntelOperandBinder::value(lua_State *state)
{
	IntelOperand *object = reinterpret_cast<IntelOperand *>(check_object(state, 1, class_name()));
	push_uint64(state, object->value);
	return 1;
}

int IntelOperandBinder::address_size(lua_State *state)
{
	IntelOperand *object = reinterpret_cast<IntelOperand *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->address_size);
	return 1;
}

int IntelOperandBinder::value_size(lua_State *state)
{
	IntelOperand *object = reinterpret_cast<IntelOperand *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->value_size);
	return 1;
}

int IntelOperandBinder::fixup(lua_State *state)
{
	IntelOperand *object = reinterpret_cast<IntelOperand *>(check_object(state, 1, class_name()));
	push_object(state, PEFixupBinder::class_name(), object->fixup);
	return 1;
}

int IntelOperandBinder::is_large_value(lua_State *state)
{
	IntelOperand *object = reinterpret_cast<IntelOperand *>(check_object(state, 1, class_name()));
	lua_pushboolean(state, object->is_large_value);
	return 1;
}

/**
 * IntelCommandTypeBinder
 */

void IntelCommandTypeBinder::Register(lua_State *state)
{
	EnumReg values[_countof(intel_command_name) + 1];
	memset(values, 0, sizeof(values));

	for (size_t i = 0; i < _countof(values) - 1; i++) {
		std::string str_name = (i == cmJmpWithFlag) ? "jxx" : intel_command_name[i];
		if (str_name.empty())
			continue;

		str_name[0] = toupper(str_name[0]);
		size_t size = str_name.size() + 1;
		char *name = new char[size];
		memcpy(name, str_name.c_str(), size);
		values[i].value = (int)i;
		values[i].name = name;
	}

	register_enum(state, enum_name(), values);

	for (size_t i = 0; i < _countof(values) - 1; i++) {
		delete [] values[i].name;
	}
}

/**
 * IntelSegmentBinder
 */

void IntelSegmentBinder::Register(lua_State *state)
{
	static const EnumReg values[] = {
		{"es", segES},
		{"cs", segCS},
		{"ss", segSS},
		{"ds", segDS},
		{"fs", segFS},
		{"gs", segGS},
		{"None", segDefault},
		{NULL, 0}
	};

	register_enum(state, enum_name(), values);
}

/**
 * IntelFlagBinder
 */

void IntelFlagBinder::Register(lua_State *state)
{
	static const EnumReg values[] = {
		{"C", fl_C},
		{"P", fl_P},
		{"A", fl_A},
		{"Z", fl_Z},
		{"S", fl_S},
		{"T", fl_T},
		{"I", fl_I},
		{"D", fl_D},
		{"O", fl_O},
		{NULL, 0}
	};

	register_enum(state, enum_name(), values);
}

/**
 * IntelRegistrBinder
 */

void IntelRegistrBinder::Register(lua_State *state)
{
	static const EnumReg values[] = {
		{"eax", regEAX},
		{"ecx", regECX},
		{"edx", regEDX},
		{"ebx", regEBX},
		{"esp", regESP},
		{"ebp", regEBP},
		{"esi", regESI},
		{"edi", regEDI},
		{"r8", regR8},
		{"r9", regR9},
		{"r10", regR10},
		{"r11", regR11},
		{"r12", regR12},
		{"r13", regR13},
		{"r14", regR14},
		{"r15", regR15},
		{NULL, 0}
	};

	register_enum(state, enum_name(), values);
}

/**
 * CommandLinkBinder
 */

void CommandLinkBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"toAddress", &SafeFunction<to_address>},
		{"type", &SafeFunction<type>},
		{"from", &SafeFunction<from>},
		{"parent", &SafeFunction<parent>},
		{"operand", &SafeFunction<operand>},
		{"subValue", &SafeFunction<sub_value>},
		{"baseInfo", &SafeFunction<base_function_info>},
		{NULL, 0}
	};

	register_class(state, class_name(), methods);

	LinkTypeBinder::Register(state);
}

int CommandLinkBinder::to_address(lua_State *state)
{
	CommandLink *object = reinterpret_cast<CommandLink *>(check_object(state, 1, class_name()));
	push_uint64(state, object->to_address());
	return 1;
}

int CommandLinkBinder::type(lua_State *state)
{
	CommandLink *object = reinterpret_cast<CommandLink *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->type());
	return 1;
}

int CommandLinkBinder::from(lua_State *state)
{
	CommandLink *object = reinterpret_cast<CommandLink *>(check_object(state, 1, class_name()));
	push_command(state, object->from_command());
	return 1;
}

int CommandLinkBinder::parent(lua_State *state)
{
	CommandLink *object = reinterpret_cast<CommandLink *>(check_object(state, 1, class_name()));
	push_command(state, object->parent_command());
	return 1;
}

int CommandLinkBinder::operand(lua_State *state)
{
	CommandLink *object = reinterpret_cast<CommandLink *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->operand_index());
	return 1;
}

int CommandLinkBinder::sub_value(lua_State *state)
{
	CommandLink *object = reinterpret_cast<CommandLink *>(check_object(state, 1, class_name()));
	push_uint64(state, object->sub_value());
	return 1;
}

int CommandLinkBinder::base_function_info(lua_State *state)
{
	CommandLink *object = reinterpret_cast<CommandLink *>(check_object(state, 1, class_name()));
	push_object(state, FunctionInfoBinder::class_name(), object->base_function_info());
	return 1;
}

/**
 * LinkTypeBinder
 */

void LinkTypeBinder::Register(lua_State *state)
{
	static const EnumReg values[] = {
		{"None", ltNone},
		{"SEHBlock", ltSEHBlock},
		{"FinallyBlock", ltFinallyBlock},
		{"DualSEHBlock", ltDualSEHBlock},
		{"FilterSEHBlock", ltFilterSEHBlock},
		{"Jmp", ltJmp},
		{"JmpWithFlag", ltJmpWithFlag},
		{"JmpWithFlagNSFS", ltJmpWithFlagNSFS},
		{"JmpWithFlagNSNA", ltJmpWithFlagNSNA},
		{"JmpWithFlagNSNS", ltJmpWithFlagNSNS},
		{"Call", ltCall},
		{"Case", ltCase},
		{"Switch", ltSwitch},
		{"Native", ltNative},
		{"Offset", ltOffset},
		{"GateOffset", ltGateOffset},
		{"ExtSEHBlock", ltExtSEHBlock},
		{"MemSEHBlock", ltMemSEHBlock},
		{"ExtSEHHandler", ltExtSEHHandler},
		{"VBMemSEHBlock", ltVBMemSEHBlock},
		{NULL, 0}
	};

	register_enum(state, enum_name(), values);
}

/**
 * CoreBinder
 */

void CoreBinder::Register(lua_State *state)
{
	static const luaL_Reg lib_methods[] = {
		{"core", &SafeFunction<instance>},
		{"extractFilePath", &SafeFunction<extract_file_path>},
		{"extractFileName", &SafeFunction<extract_file_name>},
		{"extractFileExt", &SafeFunction<extract_file_ext>},
		{"expandEnvironmentVariables", &SafeFunction<expand_environment_variables>},
		{"setEnvironmentVariable", &SafeFunction<set_environment_variable>},
		{"commandLine", &SafeFunction<command_line>},
		{"openLib", &SafeFunction<open_lib>},
		{NULL, NULL}
	};

	static const luaL_Reg methods[] = {
		{"inputFile", &SafeFunction<input_file>},
		{"inputFileName", &SafeFunction<input_file_name>},
		{"outputFile", &SafeFunction<output_file>},
		{"outputFileName", &SafeFunction<output_file_name>},
		{"setOutputFileName", &SafeFunction<set_output_file_name>},
		{"projectFileName", &SafeFunction<project_file_name>},
		{"watermarks", &SafeFunction<watermarks>},
		{"watermarkName", &SafeFunction<watermark_name>},
		{"setWatermarkName", &SafeFunction<set_watermark_name>},
		{"options", &SafeFunction<options>},
		{"setOptions", &SafeFunction<set_options>},
		{"vmSectionName", &SafeFunction<vm_section_name>},
		{"setVMSectionName", &SafeFunction<set_vm_section_name>},
		{"saveProject", &SafeFunction<save_project>},
		{"inputArchitecture", &SafeFunction<input_architecture>},
		{"outputArchitecture", &SafeFunction<output_architecture>},
		{"licenses", &SafeFunction<licenses>},
		{"files", &SafeFunction<files>},
		{NULL, NULL}
	};

	static const luaL_Reg g_methods[] = {
		{"print", &log_print},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	ProjectOptionBinder::Register(state);
	LicensesBinder::Register(state);
	FilesBinder::Register(state);
	WatermarksBinder::Register(state);

    luaL_newlib(state, lib_methods);
    lua_setglobal(state, "vmprotect");

	lua_getglobal(state, "_G");
	luaL_setfuncs(state, g_methods, 0);
	lua_pop(state, 1);
}

int CoreBinder::instance(lua_State* state)
{
	push_object(state, class_name(), Script::core());
	return 1;
}

int CoreBinder::extract_file_path(lua_State *state)
{
	std::string text = os::ExtractFilePath(lua_tostring(state, 1));
	lua_pushlstring(state, text.c_str(), text.size());
	return 1;
}

int CoreBinder::extract_file_name(lua_State *state)
{
	std::string text = os::ExtractFileName(lua_tostring(state, 1));
	lua_pushlstring(state, text.c_str(), text.size());
	return 1;
}

int CoreBinder::extract_file_ext(lua_State *state)
{
	std::string text = os::ExtractFileExt(lua_tostring(state, 1));
	lua_pushlstring(state, text.c_str(), text.size());
	return 1;
}

int CoreBinder::expand_environment_variables(lua_State *state)
{
	std::string text = os::ExpandEnvironmentVariables(lua_tostring(state, 1));
	lua_pushlstring(state, text.c_str(), text.size());
	return 1;
}

int CoreBinder::set_environment_variable(lua_State *state)
{
	std::string name = luaL_checkstring(state, 1);
	std::string value = luaL_checkstring(state, 2);
	os::SetEnvironmentVariable(name.c_str(), value.c_str());
	return 0;
}

int CoreBinder::command_line(lua_State *state)
{
	std::vector<std::string> command_line = os::CommandLine();
	lua_newtable(state);
	for (size_t i = 0; i < command_line.size(); i++) {
		lua_pushinteger(state, i + 1);
		lua_pushlstring(state, command_line[i].c_str(), command_line[i].size());
		lua_settable(state, -3);
	}
	return 1;
}

int CoreBinder::input_file(lua_State *state)
{
	Core *object = reinterpret_cast<Core *>(check_object(state, 1, class_name()));
	push_file(state, object->input_file());
	return 1;
}

int CoreBinder::input_architecture(lua_State *state)
{
	Core *object = reinterpret_cast<Core *>(check_object(state, 1, class_name()));
	push_architecture(state, object->input_architecture());
	return 1;
}

int CoreBinder::input_file_name(lua_State *state)
{
	Core *object = reinterpret_cast<Core *>(check_object(state, 1, class_name()));
	std::string text = object->input_file_name();
	lua_pushlstring(state, text.c_str(), text.size());
	return 1;
}

int CoreBinder::output_file(lua_State *state)
{
	Core *object = reinterpret_cast<Core *>(check_object(state, 1, class_name()));
	push_file(state, object->output_file());
	return 1;
}

int CoreBinder::output_architecture(lua_State *state)
{
	Core *object = reinterpret_cast<Core *>(check_object(state, 1, class_name()));
	push_architecture(state, object->output_architecture());
	return 1;
}

int CoreBinder::output_file_name(lua_State *state)
{
	Core *object = reinterpret_cast<Core *>(check_object(state, 1, class_name()));
	std::string text = object->absolute_output_file_name();
	lua_pushlstring(state, text.c_str(), text.size());
	return 1;
}

int CoreBinder::set_output_file_name(lua_State *state)
{
	Core *object = reinterpret_cast<Core *>(check_object(state, 1, class_name()));
	std::string name = luaL_checkstring(state, 2);
	object->set_output_file_name(name);
	return 0;
}

int CoreBinder::project_file_name(lua_State *state)
{
	Core *object = reinterpret_cast<Core *>(check_object(state, 1, class_name()));
	std::string text = object->project_file_name();
	lua_pushlstring(state, text.c_str(), text.size());
	return 1;
}

int CoreBinder::licenses(lua_State *state)
{
	Core *object = reinterpret_cast<Core *>(check_object(state, 1, class_name()));
	push_object(state, LicensesBinder::class_name(), object->licensing_manager());
	return 1;
}

int CoreBinder::files(lua_State *state)
{
	Core *object = reinterpret_cast<Core *>(check_object(state, 1, class_name()));
	push_object(state, FilesBinder::class_name(), object->file_manager());
	return 1;
}

int CoreBinder::watermarks(lua_State *state)
{
	Core *object = reinterpret_cast<Core *>(check_object(state, 1, class_name()));
	push_object(state, WatermarksBinder::class_name(), object->watermark_manager());
	return 1;
}

int CoreBinder::watermark_name(lua_State *state)
{
	Core *object = reinterpret_cast<Core *>(check_object(state, 1, class_name()));
	std::string text = object->watermark_name();
	lua_pushlstring(state, text.c_str(), text.size());
	return 1;
}

int CoreBinder::set_watermark_name(lua_State *state)
{
	Core *object = reinterpret_cast<Core *>(check_object(state, 1, class_name()));
	std::string name = luaL_checkstring(state, 2);
	object->set_watermark_name(name);
	return 0;
}

int CoreBinder::options(lua_State *state)
{
	Core *object = reinterpret_cast<Core *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->options());
	return 1;
}

int CoreBinder::set_options(lua_State *state)
{
	Core *object = reinterpret_cast<Core *>(check_object(state, 1, class_name()));
	uint32_t options = static_cast<uint32_t>(check_integer(state, 2));
	object->set_options(options);
	return 0;
}

int CoreBinder::vm_section_name(lua_State *state)
{
	Core *object = reinterpret_cast<Core *>(check_object(state, 1, class_name()));
	std::string text = object->vm_section_name();
	lua_pushlstring(state, text.c_str(), text.size());
	return 1;
}

int CoreBinder::set_vm_section_name(lua_State *state)
{
	Core *object = reinterpret_cast<Core *>(check_object(state, 1, class_name()));
	std::string name = luaL_checkstring(state, 2);
	object->set_vm_section_name(name);
	return 0;
}

int CoreBinder::save_project(lua_State *state)
{
	Core *object = reinterpret_cast<Core *>(check_object(state, 1, class_name()));
	object->Save();
	return 0;
}

/**
 * ProjectOptionBinder
 */

void ProjectOptionBinder::Register(lua_State *state)
{
	static const EnumReg values[] = {
		{"None", 0},
		{"Pack", cpPack},
		{"ImportProtection", cpImportProtection},
		{"MemoryProtection", cpMemoryProtection},
		{"ResourceProtection", cpResourceProtection},
		{"CheckDebugger", cpCheckDebugger},
		{"CheckKernelDebugger", cpCheckKernelDebugger},
		{"CheckVirtualMachine", cpCheckVirtualMachine},
		{"StripFixups", cpStripFixups},
		{"StripDebugInfo", cpStripDebugInfo},
		{"DebugMode", cpDebugMode},
		{NULL, 0}
	};

	register_enum(state, enum_name(), values);
}

/**
 * LicensesBinder
 */

void LicensesBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"item", &SafeFunction<item>},
		{"count", &SafeFunction<count>},
		{"delete", &SafeFunction<Delete>},
		{"clear", &SafeFunction<clear>},
		{"publicExp", &SafeFunction<public_exp>},
		{"privateExp", &SafeFunction<private_exp>},
		{"modulus", &SafeFunction<modulus>},
		{"keyLength", &SafeFunction<key_length>},
		{"hash", &SafeFunction<hash> },
		{"itemBySerialNumber", &SafeFunction<GetLicenseBySerialNumber>},
		{"importLicense", &SafeFunction<import_license>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	LicenseBinder::Register(state);
}

int LicensesBinder::item(lua_State *state)
{
	LicensingManager *object = reinterpret_cast<LicensingManager *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, LicenseBinder::class_name(), object->item(index));
	return 1;
}

int LicensesBinder::count(lua_State *state)
{
	LicensingManager *object = reinterpret_cast<LicensingManager *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int LicensesBinder::clear(lua_State *state)
{
	LicensingManager *object = reinterpret_cast<LicensingManager *>(check_object(state, 1, class_name()));
	object->clear();
	return 0;
}

int LicensesBinder::Delete(lua_State *state)
{
	LicensingManager *object = reinterpret_cast<LicensingManager *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	object->Delete(index);
	return 0;
}

int LicensesBinder::public_exp(lua_State *state)
{
	LicensingManager *object = reinterpret_cast<LicensingManager *>(check_object(state, 1, class_name()));
	std::string name = VectorToBase64(object->public_exp());
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int LicensesBinder::private_exp(lua_State *state)
{
	LicensingManager *object = reinterpret_cast<LicensingManager *>(check_object(state, 1, class_name()));
	std::string name = VectorToBase64(object->private_exp());
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int LicensesBinder::modulus(lua_State *state)
{
	LicensingManager *object = reinterpret_cast<LicensingManager *>(check_object(state, 1, class_name()));
	std::string name = VectorToBase64(object->modulus());
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int LicensesBinder::key_length(lua_State *state)
{
	LicensingManager *object = reinterpret_cast<LicensingManager *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->bits());
	return 1;
}

int LicensesBinder::hash(lua_State *state)
{
	LicensingManager *object = reinterpret_cast<LicensingManager *>(check_object(state, 1, class_name()));
	std::string name = VectorToBase64(object->hash());
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int LicensesBinder::GetLicenseBySerialNumber(lua_State *state)
{
	LicensingManager *object = reinterpret_cast<LicensingManager *>(check_object(state, 1, class_name()));
	std::string serial_number = luaL_checkstring(state, 2);
	push_object(state, LicenseBinder::class_name(), object->GetLicenseBySerialNumber(serial_number));
	return 1;
}

int LicensesBinder::import_license(lua_State *state)
{
	LicensingManager *object = reinterpret_cast<LicensingManager *>(check_object(state, 1, class_name()));
	std::string serial_number = luaL_checkstring(state, 2);
	LicenseInfo info;
	License *license = (object->DecryptSerialNumber(serial_number, info)) ? object->Add(0, info.CustomerName, info.CustomerEmail, "", "", serial_number, false) : NULL;
	push_object(state, LicenseBinder::class_name(), license);
	return 1;
}

/**
 * LicenseInfoBinder
 */

void LicenseInfoBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"flags", &SafeFunction<flags>},
		{"customerName", &SafeFunction<customer_name>},
		{"customerEmail", &SafeFunction<customer_email>},
		{"expireDate", &SafeFunction<expire_date>},
		{"hwid", &SafeFunction<hwid>},
		{"runningTimeLimit", &SafeFunction<running_time_limit>},
		{"maxBuildDate", &SafeFunction<max_build_date>},
		{"userData", &SafeFunction<user_data>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);
}

int LicenseInfoBinder::flags(lua_State *state)
{
	LicenseInfo *object = reinterpret_cast<LicenseInfo *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->Flags);
	return 1;
}

int LicenseInfoBinder::customer_name(lua_State *state)
{
	LicenseInfo *object = reinterpret_cast<LicenseInfo *>(check_object(state, 1, class_name()));
	std::string name = object->CustomerName;
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int LicenseInfoBinder::customer_email(lua_State *state)
{
	LicenseInfo *object = reinterpret_cast<LicenseInfo *>(check_object(state, 1, class_name()));
	std::string name = object->CustomerEmail;
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int LicenseInfoBinder::expire_date(lua_State *state)
{
	LicenseInfo *object = reinterpret_cast<LicenseInfo *>(check_object(state, 1, class_name()));
	push_date(state, object->ExpireDate, luaL_optlstring(state, 2, "%c", NULL));
	return 1;
}

int LicenseInfoBinder::hwid(lua_State *state)
{
	LicenseInfo *object = reinterpret_cast<LicenseInfo *>(check_object(state, 1, class_name()));
	std::string name = object->HWID;
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int LicenseInfoBinder::running_time_limit(lua_State *state)
{
	LicenseInfo *object = reinterpret_cast<LicenseInfo *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->RunningTimeLimit);
	return 1;
}

int LicenseInfoBinder::max_build_date(lua_State *state)
{
	LicenseInfo *object = reinterpret_cast<LicenseInfo *>(check_object(state, 1, class_name()));
	push_date(state, object->MaxBuildDate, luaL_optlstring(state, 2, "%c", NULL));
	return 1;
}

int LicenseInfoBinder::user_data(lua_State *state)
{
	LicenseInfo *object = reinterpret_cast<LicenseInfo *>(check_object(state, 1, class_name()));
	std::string name = object->UserData;
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

/**
 * LicenseBinder
 */

void LicenseBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"date", &SafeFunction<date>},
		{"customerName", &SafeFunction<customer_name>},
		{"customerEmail", &SafeFunction<customer_email>},
		{"orderRef", &SafeFunction<order_ref>},
		{"comments", &SafeFunction<comments>},
		{"serialNumber", &SafeFunction<serial_number>},
		{"blocked", &SafeFunction<blocked>},
		{"setBlocked", &SafeFunction<set_blocked>},
		{"info", &SafeFunction<info>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	LicenseInfoBinder::Register(state);
}

int LicenseBinder::date(lua_State *state)
{
	License *object = reinterpret_cast<License *>(check_object(state, 1, class_name()));
	push_date(state, object->date(), luaL_optlstring(state, 2, "%c", NULL));
	return 1;
}

int LicenseBinder::customer_name(lua_State *state)
{
	License *object = reinterpret_cast<License *>(check_object(state, 1, class_name()));
	std::string name = object->customer_name();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int LicenseBinder::customer_email(lua_State *state)
{
	License *object = reinterpret_cast<License *>(check_object(state, 1, class_name()));
	std::string name = object->customer_email();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int LicenseBinder::order_ref(lua_State *state)
{
	License *object = reinterpret_cast<License *>(check_object(state, 1, class_name()));
	std::string name = object->order_ref();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int LicenseBinder::comments(lua_State *state)
{
	License *object = reinterpret_cast<License *>(check_object(state, 1, class_name()));
	std::string name = object->comments();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int LicenseBinder::serial_number(lua_State *state)
{
	License *object = reinterpret_cast<License *>(check_object(state, 1, class_name()));
	std::string name = object->serial_number();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int LicenseBinder::blocked(lua_State *state)
{
	License *object = reinterpret_cast<License *>(check_object(state, 1, class_name()));
	lua_pushboolean(state, object->blocked());
	return 1;
}

int LicenseBinder::set_blocked(lua_State *state)
{
	License *object = reinterpret_cast<License *>(check_object(state, 1, class_name()));
	object->set_blocked(lua_tointeger(state, 2) != 0);
	return 0;
}

int LicenseBinder::info(lua_State *state)
{
	License *object = reinterpret_cast<License *>(check_object(state, 1, class_name()));
	push_object(state, LicenseInfoBinder::class_name(), object->info());
	return 1;
}

/**
 * FileFoldersBinder
 */

void FileFoldersBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"count", &SafeFunction<count>},
		{"item", &SafeFunction<item>},
		{"add", &SafeFunction<add>},
		{"clear", &SafeFunction<clear>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	FileFolderBinder::Register(state);
}

int FileFoldersBinder::item(lua_State *state)
{
	FileFolder *object = reinterpret_cast<FileFolder *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, FileFolderBinder::class_name(), object->item(index));
	return 1;
}

int FileFoldersBinder::count(lua_State *state)
{
	FileFolder *object = reinterpret_cast<FileFolder *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int FileFoldersBinder::add(lua_State *state)
{
	FileFolder *object = reinterpret_cast<FileFolder *>(check_object(state, 1, class_name()));
	std::string name = lua_tostring(state, 2);
	push_object(state, FileFolderBinder::class_name(), object->Add(name));
	return 1;
}

int FileFoldersBinder::clear(lua_State *state)
{
	FileFolder *object = reinterpret_cast<FileFolder *>(check_object(state, 1, class_name()));
	object->clear();
	return 0;
}
/**
 * FileFolderBinder
 */

void FileFolderBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"count", &SafeFunction<count>},
		{"item", &SafeFunction<item>},
		{"add", &SafeFunction<add>},
		{"clear", &SafeFunction<clear>},
		{"name", &SafeFunction<name>},
		{"destroy", &SafeFunction<destroy>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);
}

int FileFolderBinder::item(lua_State *state)
{
	FileFolder *object = reinterpret_cast<FileFolder *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, FileFolderBinder::class_name(), object->item(index));
	return 1;
}

int FileFolderBinder::count(lua_State *state)
{
	FileFolder *object = reinterpret_cast<FileFolder *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int FileFolderBinder::add(lua_State *state)
{
	Folder *object = reinterpret_cast<Folder *>(check_object(state, 1, class_name()));
	std::string name = lua_tostring(state, 2);
	push_object(state, FileFolderBinder::class_name(), object->Add(name));
	return 1;
}

int FileFolderBinder::clear(lua_State *state)
{
	FileFolder *object = reinterpret_cast<FileFolder *>(check_object(state, 1, class_name()));
	object->clear();
	return 0;
}

int FileFolderBinder::name(lua_State *state)
{
	FileFolder *object = reinterpret_cast<FileFolder *>(check_object(state, 1, class_name()));
	std::string name = object->name();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int FileFolderBinder::destroy(lua_State *state)
{
	delete_object(state, 1, class_name());
	return 0;
}

/**
* FileActionTypeBinder
*/

void FileActionTypeBinder::Register(lua_State *state)
{
	static const EnumReg values[] = {
		{"None", faNone},
		{"Load", faLoad},
		{"Register", faRegister},
		{"Install", faInstall},
		{NULL, 0}
	};

	register_enum(state, enum_name(), values);
}

/**
 * FilesBinder
 */

void FilesBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"item", &SafeFunction<item>},
		{"count", &SafeFunction<count>},
		{"delete", &SafeFunction<Delete>},
		{"clear", &SafeFunction<clear>},
		{"folders", &SafeFunction<folders>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	FileActionTypeBinder::Register(state);
	FileFoldersBinder::Register(state);
	FileBinder::Register(state);
}

int FilesBinder::item(lua_State *state)
{
	FileManager *object = reinterpret_cast<FileManager *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, FileBinder::class_name(), object->item(index));
	return 1;
}

int FilesBinder::count(lua_State *state)
{
	FileManager *object = reinterpret_cast<FileManager *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int FilesBinder::clear(lua_State *state)
{
	FileManager *object = reinterpret_cast<FileManager *>(check_object(state, 1, class_name()));
	object->clear();
	return 0;
}

int FilesBinder::Delete(lua_State *state)
{
	FileManager *object = reinterpret_cast<FileManager *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	object->Delete(index);
	return 0;
}

int FilesBinder::folders(lua_State *state)
{
	FileManager *object = reinterpret_cast<FileManager *>(check_object(state, 1, class_name()));
	push_object(state, FileFoldersBinder::class_name(), object->folder_list());
	return 1;
}

/**
 * FileBinder
 */

void FileBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"name", &SafeFunction<name>},
		{"fileName", &SafeFunction<file_name>},
		{"action", &SafeFunction<action>},
		{"folder", &SafeFunction<folder>},
		{"setName", &SafeFunction<set_name>},
		{"setFileName", &SafeFunction<set_file_name>},
		{"setAction", &SafeFunction<set_action>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);
}

int FileBinder::name(lua_State *state)
{
	InternalFile *object = reinterpret_cast<InternalFile *>(check_object(state, 1, class_name()));
	std::string name = object->name();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int FileBinder::file_name(lua_State *state)
{
	InternalFile *object = reinterpret_cast<InternalFile *>(check_object(state, 1, class_name()));
	std::string name = object->file_name();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int FileBinder::action(lua_State *state)
{
	InternalFile *object = reinterpret_cast<InternalFile *>(check_object(state, 1, class_name()));
	//std::string name = object->file_name();
	lua_pushinteger(state, object->action());
	return 1;
}

int FileBinder::folder(lua_State *state)
{
	InternalFile *object = reinterpret_cast<InternalFile *>(check_object(state, 1, class_name()));
	push_object(state, FileFolderBinder::class_name(), object->folder());
	return 1;
}

int FileBinder::set_name(lua_State *state)
{
	InternalFile *object = reinterpret_cast<InternalFile *>(check_object(state, 1, class_name()));
	std::string name = luaL_checkstring(state, 2);
	object->set_name(name);
	return 0;
}

int FileBinder::set_file_name(lua_State *state)
{
	InternalFile *object = reinterpret_cast<InternalFile *>(check_object(state, 1, class_name()));
	std::string name = luaL_checkstring(state, 2);
	object->set_file_name(name);
	return 0;
}

int FileBinder::set_action(lua_State *state)
{
	InternalFile *object = reinterpret_cast<InternalFile *>(check_object(state, 1, class_name()));
	InternalFileAction action = static_cast<InternalFileAction>(check_integer(state, 2));
	object->set_action(action);
	return 0;
}

/**
 * WatermarksBinder
 */

void WatermarksBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"item", &SafeFunction<item>},
		{"count", &SafeFunction<count>},
		{"delete", &SafeFunction<Delete>},
		{"clear", &SafeFunction<clear>},
		{"itemByName", &SafeFunction<GetItemByName>},
		{"add", &SafeFunction<add>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);

	WatermarkBinder::Register(state);
}

int WatermarksBinder::item(lua_State *state)
{
	WatermarkManager *object = reinterpret_cast<WatermarkManager *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	push_object(state, WatermarkBinder::class_name(), object->item(index));
	return 1;
}

int WatermarksBinder::count(lua_State *state)
{
	WatermarkManager *object = reinterpret_cast<WatermarkManager *>(check_object(state, 1, class_name()));
	lua_pushinteger(state, object->count());
	return 1;
}

int WatermarksBinder::clear(lua_State *state)
{
	WatermarkManager *object = reinterpret_cast<WatermarkManager *>(check_object(state, 1, class_name()));
	object->clear();
	return 0;
}

int WatermarksBinder::Delete(lua_State *state)
{
	WatermarkManager *object = reinterpret_cast<WatermarkManager *>(check_object(state, 1, class_name()));
	size_t index = static_cast<size_t>(check_integer(state, 2) - 1);
	object->Delete(index);
	return 0;
}

int WatermarksBinder::GetItemByName(lua_State *state)
{
	WatermarkManager *object = reinterpret_cast<WatermarkManager *>(check_object(state, 1, class_name()));
	std::string name = luaL_checklstring(state, 2, NULL);
	push_object(state, WatermarkBinder::class_name(), object->GetWatermarkByName(name));
	return 1;
}

int WatermarksBinder::add(lua_State *state)
{
	WatermarkManager *object = reinterpret_cast<WatermarkManager *>(check_object(state, 1, class_name()));
	std::string name = luaL_checklstring(state, 2, NULL);
	std::string value = (lua_gettop(state) > 2) ? luaL_checklstring(state, 3, NULL) : object->CreateValue();
	push_object(state, WatermarkBinder::class_name(), object->Add(name, value));
	return 1;
}

/**
 * WatermarkBinder
 */

void WatermarkBinder::Register(lua_State *state)
{
	static const luaL_Reg methods[] = {
		{"name", &SafeFunction<name>},
		{"value", &SafeFunction<value>},
		{"blocked", &SafeFunction<blocked>},
		{"setBlocked", &SafeFunction<set_blocked>},
		{NULL, NULL}
	};

	register_class(state, class_name(), methods);
}

int WatermarkBinder::name(lua_State *state)
{
	Watermark *object = reinterpret_cast<Watermark *>(check_object(state, 1, class_name()));
	std::string name = object->name();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int WatermarkBinder::value(lua_State *state)
{
	Watermark *object = reinterpret_cast<Watermark *>(check_object(state, 1, class_name()));
	std::string name = object->value();
	lua_pushlstring(state, name.c_str(), name.size());
	return 1;
}

int WatermarkBinder::blocked(lua_State *state)
{
	Watermark *object = reinterpret_cast<Watermark *>(check_object(state, 1, class_name()));
	lua_pushboolean(state, !object->enabled());
	return 1;
}

int WatermarkBinder::set_blocked(lua_State *state)
{
	Watermark *object = reinterpret_cast<Watermark *>(check_object(state, 1, class_name()));
	object->set_enabled(lua_tointeger(state, 2) == 0);
	return 0;
}

/**
 * Script
 */

Core *Script::core_ = NULL;

Script::Script(Core *owner)
	: state_(NULL), need_compile_(true) 
{
	core_ = owner;
};

Script::~Script()
{
	close();
}

void Script::close()
{
	if (state_) {
		lua_close(state_);
		state_ = NULL;
	}
}

bool Script::LoadFromFile(const std::string &file_name)
{
	FileStream file;
	if (!file.Open(file_name.c_str(), fmOpenRead | fmShareDenyNone))
		return false;

	need_compile_ = true;
	text_ = file.ReadAll();
	return true;
}

bool Script::Compile()
{
	close();

	if (!need_compile_)
		return true;

	state_ = luaL_newstate();
	luaL_openlibs(state_);

	Uint64Binder::Register(state_);
	OperandTypeBinder::Register(state_);
	OperandSizeBinder::Register(state_);
	ObjectTypeBinder::Register(state_);
	IntelFunctionsBinder::Register(state_);
	PEFileBinder::Register(state_);
	CoreBinder::Register(state_);
	FFILibraryBinder::Register(state_);

	if (luaL_dostring(state_, text_.c_str()) != LUA_OK) {
		std::string txt = lua_tostring(state_, -1);
		for (size_t i = 0; i < txt.size(); i++) {
			if (txt[i] == '\r')
				txt[i] = ' ';
		}
		core_->Notify(mtError, this, txt);
		return false;
	}
	return true;
}

void Script::set_need_compile(bool need_compile)
{ 
	if (need_compile_ != need_compile) {
		need_compile_ = need_compile;
		core_->Notify(mtChanged, this);
	}
}

void Script::DoBeforeCompilation()
{
	ExecuteFunction("OnBeforeCompilation");
}

void Script::DoAfterCompilation()
{
	ExecuteFunction("OnAfterCompilation");
}

void Script::DoBeforeSaveFile()
{
	ExecuteFunction("OnBeforeSaveFile");
}

void Script::DoAfterSaveFile()
{
	ExecuteFunction("OnAfterSaveFile");
}

void Script::DoBeforePackFile()
{
	ExecuteFunction("OnBeforePackFile");
}

void Script::ExecuteFunction(const std::string &func_name)
{
	if (!need_compile_)
		return;

	int top = lua_gettop(state_);
	lua_getglobal(state_, func_name.c_str());
	if (lua_isfunction(state_, -1)) {
		if (lua_pcall(state_, 0, 0, 0) != LUA_OK) {
			std::string txt = lua_tostring(state_, -1);
			for (size_t i = 0; i < txt.size(); i++) {
				if (txt[i] == '\r')
					txt[i] = ' ';
			}
			throw std::runtime_error("Script error: " + txt);
		}
	}
	lua_settop(state_, top);
}