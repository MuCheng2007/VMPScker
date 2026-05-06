#include "osutils.h"
#include <fstream>

#pragma warning( disable : 4091 )
#include <shlobj.h>
#pragma warning( default: 4091 )

#define FILE_OPEN_MODE(fm) ((fm) & 0xf)
#define FILE_SHARE_MODE(fm) ((fm) & 0xf0)

namespace os
{

static const uint8_t utf8_limits[5] = {0xC0, 0xE0, 0xF0, 0xF8, 0xFC};

unicode_string FromUTF8(const std::string &src)
{
	unicode_string dest;

	size_t pos = 0;
	size_t len = src.size();
	while (pos < len) {
		uint8_t c = src[pos++];

		if (c < 0x80) {
			dest += c;
			continue;
		}

		size_t val_len;
		for (val_len = 0; val_len < _countof(utf8_limits); val_len++) {
			if (c < utf8_limits[val_len])
				break;
		}

		if (val_len == 0)
			continue;

		uint32_t value = c - utf8_limits[val_len - 1];
		while (val_len) {
			if (pos == len)
				break;
			c = src[pos++];
			if (c < 0x80 || c >= 0xC0)
				break;
			value <<= 6;
			value |= (c - 0x80);
			val_len--;
		}

		if (value < 0x10000) {
			dest += static_cast<uint16_t>(value);
		} else if (value <= 0x10FFFF) {
			value -= 0x10000;
			dest += static_cast<uint16_t>(0xD800 + (value >> 10));
			dest += static_cast<uint16_t>(0xDC00 + (value & 0x3FF));
		}
	}

	return dest;
}

#ifdef VMP_GNU
std::wstring UCS4FromUTF8(const std::string &src)
{
	std::wstring dest;

	size_t pos = 0;
	size_t len = src.size();
	while (pos < len) {
		uint8_t c = src[pos++];

		if (c < 0x80) {
			dest += c;
			continue;
		}

		size_t val_len;
		for (val_len = 0; val_len < _countof(utf8_limits); val_len++) {
			if (c < utf8_limits[val_len])
				break;
		}

		if (val_len == 0)
			continue;

		uint32_t value = c - utf8_limits[val_len - 1];
		while (val_len) {
			if (pos == len)
				break;
			c = src[pos++];
			if (c < 0x80 || c >= 0xC0)
				break;
			value <<= 6;
			value |= (c - 0x80);
			val_len--;
		}

		dest += static_cast<wchar_t>(value);
	}

	return dest;
}
#endif

std::string ToUTF8(const unicode_string &src)
{
	std::string dest;

	size_t pos = 0;
	size_t len = src.size();
	while (pos < len) {
		uint16_t c = src[pos++];
		if (c < 0x80) {
			dest += static_cast<char>(c);
			continue;
		}

		uint32_t value;
		if (c >= 0xD800 && c < 0xE000) {
			value = 0xFFFD;
			if (c < 0xDC00 && pos + 1 < len) {
				uint16_t c2 = src[pos++];
				if (c2 >= 0xDC00 && c2 < 0xE000)
					value = 0x10000 + ((c & 0x3FF) << 10) + (c2 & 0x3FF);
			}
		} else {
			value = c;
		}

		size_t val_len;
	    for (val_len = 1; val_len < 5; val_len++) {
			if (value < (static_cast<uint32_t>(1) << (val_len * 5 + 6)))
				break;
		}
		dest += static_cast<char>(utf8_limits[val_len - 1] + (value >> (6 * val_len)));
		while (val_len) {
			val_len--;
			dest += static_cast<char>(0x80 + ((value >> (6 * val_len)) & 0x3F));
		}
	}

	return dest;
}

unicode_string StringToFileName(const char *name)
{
	unicode_string res = FromUTF8(name);
	for (size_t i = 0; i < res.size(); i++) {
		if (res[i] == L'/')
			res[i] = L'\\';
	}
	return res;
}

bool is_separator(char c)
{
    return c == '/'
#ifndef VMP_GNU
      || c == '\\'
#endif
      ;
}

static const char *GetFileName(const char *name)
{
	const char *res = name;
	while (*name) {
		if ((is_separator(name[0])
#ifndef VMP_GNU
			|| name[0] == ':'
#endif
			) && !is_separator(name[1]))
			res = name + 1;
		name++;
	}
	return res;
}

static const char *GetFileExt(const char *name)
{
	name = GetFileName(name);
	const char *res = NULL;
	while (*name) {
		if (*name == ' ')
			res = NULL;
		else if (*name == '.')
			res = name;
		name++;
	}
	return res ? res : name;
}

std::string ExtractFilePath(const char *name)
{
	if (!name)
		return std::string();
	return std::string(name, static_cast<size_t>(GetFileName(name) - name));
}

std::string ExtractFileName(const char *name)
{
	if (!name)
		return std::string();
	return std::string(GetFileName(name));
}

std::string ExtractFileExt(const char *name)
{
	if (!name)
		return std::string();
	return std::string(GetFileExt(name));
}

std::string ChangeFileExt(const char *name, const char *ext)
{
	if (!name)
		return std::string();
	std::string res = std::string(name, static_cast<size_t>(GetFileExt(name) - name));
	if (ext)
		res += ext;
	return res;
}

static bool IsRelative(const char *name)
{
	if (name && (is_separator(*name)
#ifndef VMP_GNU		
		|| (name[0] && name[1] == ':')
#endif
		))
		return false;
	return true;
}

std::string CombinePaths(const char *path, const char *file_name)
{
	if (!path || *path == 0 || !IsRelative(file_name))
		return std::string(file_name ? file_name : "");

	std::string res = path;
	if (!res.empty()) {
#ifdef VMP_GNU
		if (!is_separator(*(res.end() - 1)))
			res += '/';
#else
		if (!is_separator(res.back()))
			res += '\\';
#endif
	}

	return res + file_name;
}

std::string SubtractPath(const char *path, const char *file_name)
{
	if (!path || *path == 0 || !file_name || IsRelative(file_name))
		return std::string(file_name ? file_name : "");

	const char *name = file_name;
	while (*name) {
		char p = *path++;
		char f = *name++;
		if (p != f) {
			if (is_separator(f) && is_separator(p))
				continue;
			if (p == 0)
				return std::string(is_separator(f) ? name : name - 1);
			break;
		}
	}

	return std::string(file_name);
}

std::string GetCurrentPath()
{
#ifdef VMP_GNU
	char buff[PATH_MAX];
	if (!getcwd(buff, sizeof(buff)))
		buff[0] = 0;
	return std::string(buff);
#else
	wchar_t buff[MAX_PATH];
	DWORD size = GetCurrentDirectoryW(_countof(buff), buff);
	return ToUTF8(std::wstring(buff, size));
#endif
}

std::string GetExecutablePath()
{
	std::string res;
	wchar_t buff[MAX_PATH];
	DWORD size = GetModuleFileNameW(NULL, buff, _countof(buff));
	res = ExtractFilePath(ToUTF8(std::wstring(buff, size)).c_str());
	return res;
}

bool FileExists(const char *name)
{
	if (!name)
		return false;
#ifdef VMP_GNU
	struct stat s;
	int res = stat(name, &s);
	if (res == -1)
		return false;
	return true;
#else
	return GetFileAttributesW(FromUTF8(name).c_str()) != INVALID_FILE_ATTRIBUTES;
#endif
}

bool FileDelete(const char *name, bool toRecycleBin /*= false*/)
{
	unicode_string uname = FromUTF8(name);
	if(toRecycleBin)
	{
		SHFILEOPSTRUCTW operation = SHFILEOPSTRUCTW();
		operation.wFunc = FO_DELETE;
		wchar_t full_path[MAX_PATH + 1];
		DWORD lengNoTerm = GetFullPathNameW(uname.c_str(), MAX_PATH, full_path, NULL);
		if(lengNoTerm < MAX_PATH)
		{
			full_path[lengNoTerm + 1] = 0; //double terminated
			operation.pFrom = full_path;
			operation.fFlags = FOF_ALLOWUNDO | FOF_NO_UI;
			if(SHFileOperationW(&operation) == 0) 
				return true;
		}
	}
	return (DeleteFileW(uname.c_str()) != FALSE);
}

bool FileCopy(const char *src, const char *dest)
{
	return (CopyFileW(FromUTF8(src).c_str(), FromUTF8(dest).c_str(), false) != FALSE);
}

// fmCreate			Create a file with the given name. If a file with the given name exists, open the file in write mode.   
// fmOpenRead		Open the file for reading only.   
// fmOpenWrite		Open the file for writing only. Writing to the file completely replaces the current contents.   
// fmOpenReadWrite	Open the file to modify the current contents rather than replace them.   

HANDLE FileCreate(const char *name, uint32_t mode)
{
#ifdef VMP_GNU
	int flags;

	switch (FILE_OPEN_MODE(mode)) {
	case fmOpenRead:
		flags = O_RDONLY;
		break;
	case fmOpenWrite:
		flags = O_WRONLY | O_TRUNC;
		break;
	case fmOpenReadWrite:
		flags = O_RDWR;
		break;
	default:
		return INVALID_HANDLE_VALUE;
	}

	if (mode & fmCreate)
		flags |= (O_CREAT | O_TRUNC);

	return reinterpret_cast<HANDLE>(open(name, flags, (flags & O_CREAT) ? S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH : 0));
#else
	uint32_t desired_access, share_mode;

	switch (FILE_OPEN_MODE(mode)) {
	case fmOpenRead:
		desired_access = GENERIC_READ;
		break;
	case fmOpenWrite:
		desired_access = GENERIC_WRITE;
		break;
	case fmOpenReadWrite:
		desired_access = GENERIC_WRITE | GENERIC_READ;
		break;
	default:
		return INVALID_HANDLE_VALUE;
	}

	switch (FILE_SHARE_MODE(mode)) {
	case fmShareExclusive:
		share_mode = 0;
		break;
	case fmShareDenyWrite:
		share_mode = FILE_SHARE_READ;
		break;
	case fmShareDenyRead:
		share_mode = FILE_SHARE_WRITE;
		break;
	case fmShareDenyNone:
		share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;
		break;
	default:
		return INVALID_HANDLE_VALUE;
	}

	return CreateFileW(FromUTF8(name).c_str(), desired_access, share_mode, NULL, (mode & fmCreate) ? CREATE_ALWAYS : OPEN_EXISTING, 0, NULL);
#endif
}

bool FileClose(HANDLE h)
{
#ifdef VMP_GNU
	return (close(h) == 0);
#else
	return (CloseHandle(h) != 0);
#endif
}

size_t FileRead(HANDLE h, void *buf, size_t size)
{
#ifdef VMP_GNU
	size_t res;
	res = read(h, buf, size);
#else
	size_t res = 0;
	DWORD portion;
	while(size > 0) {
		portion = (DWORD)-1;
		if (portion > size) 
			portion = (DWORD)size;
		if (ReadFile(h, (char *)buf + res, portion, &portion, NULL) == 0)
			return (size_t)-1;

		res += portion;
		size -= portion;
		if (portion == 0)
			break;
	}
#endif
	return res;
}

size_t FileWrite(HANDLE h, const void *buf, size_t size)
{
#ifdef VMP_GNU
	size_t res;
	res = write(h, buf, size);
#else
	size_t res = 0;
	DWORD portion;
	while(size > 0) {
		portion = (DWORD)-1;
		if (portion > size) 
			portion = (DWORD)size;
		if (WriteFile(h, (const char *)buf + res, portion, &portion, NULL) == 0)
			return (size_t)-1;

		res += portion;
		size -= portion;
		if (portion == 0)
			break;
	}
#endif
	return res;
}

uint64_t FileSeek(HANDLE h, uint64_t offset, SeekOrigin origin)
{
	uint64_t res;
#ifdef VMP_GNU
	int method;

	switch (origin) {
	case soBeginning:
		method = SEEK_SET;
		break;
	case soCurrent:
		method = SEEK_CUR;
		break;
	case soEnd:
		method = SEEK_END;
		break;
	default:
		return -1;
	}

	res = lseek(h, offset, method);
#else
	uint32_t method;

	switch (origin) {
	case soBeginning:
		method = FILE_BEGIN;
		break;
	case soCurrent:
		method = FILE_CURRENT;
		break;
	case soEnd:
		method = FILE_END;
		break;
	default:
		return -1;
	}

	uint32_t pos_low = static_cast<uint32_t>(offset);
	uint32_t pos_high = static_cast<uint32_t>(offset >> 32);
	pos_low = SetFilePointer(h, pos_low, (PLONG)&pos_high, method);
	if (pos_low == INVALID_SET_FILE_POINTER && GetLastError() != 0)
		return -1;
	res = (static_cast<uint64_t>(pos_high) << 32) | pos_low;
#endif
	return res;
}

bool FileSetEnd(HANDLE h)
{
#ifdef VMP_GNU
	uint64_t pos = lseek(h, 0, SEEK_CUR);
	if (pos == (uint64_t)-1)
		return false;
    return (ftruncate(h, pos) == 0);
#else
	return (SetEndOfFile(h) != 0);
#endif
}

bool FileGetCheckSum(const char *file_name, uint32_t *check_sum)
{
	if (!file_name)
		return false;

	bool res = false;
	HANDLE file_handle = FileCreate(file_name, fmOpenRead | fmShareDenyNone);
	if (file_handle != INVALID_HANDLE_VALUE) {
#ifdef VMP_GNU
		size_t file_size = lseek(file_handle, 0, SEEK_END);
#else
		uint32_t file_size = GetFileSize(file_handle, NULL);
		HANDLE file_map = CreateFileMappingW(file_handle, NULL, PAGE_READONLY, 0, 0, NULL);
		if (file_map) {
#endif

#ifdef VMP_GNU
			uint16_t *file_view = reinterpret_cast<uint16_t *>(mmap(0, file_size, PROT_READ, MAP_SHARED, file_handle, 0));
			if (file_view != MAP_FAILED) {
#else
			uint16_t *file_view = static_cast<uint16_t *>(MapViewOfFile(file_map, FILE_MAP_READ, 0, 0, 0));
			if (file_view) {
#endif
				bool is_valid_format = false;
				uint32_t header_sum = 0;
				IMAGE_DOS_HEADER *dos_header = reinterpret_cast<IMAGE_DOS_HEADER *>(file_view);
				if (dos_header->e_magic == IMAGE_DOS_SIGNATURE) {
					IMAGE_NT_HEADERS32 *header_32 = reinterpret_cast<IMAGE_NT_HEADERS32 *>(reinterpret_cast<uint8_t *>(file_view) + dos_header->e_lfanew);
					if (header_32->Signature == IMAGE_NT_SIGNATURE) {
						if (header_32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
							header_sum = header_32->OptionalHeader.CheckSum;
							is_valid_format = true;
						} else if (header_32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
							header_sum = reinterpret_cast<IMAGE_NT_HEADERS64 *>(header_32)->OptionalHeader.CheckSum;
							is_valid_format = true;
						}
					}
				}

				if (is_valid_format) {
					uint32_t sum = 0;
					size_t c = (file_size + 1) / sizeof(uint16_t);
					for (size_t i = 0; i < c; i++) {
						sum += file_view[i];
						if (HIWORD(sum))
							sum = LOWORD(sum) + HIWORD(sum);
					}
					sum = static_cast<uint16_t>(LOWORD(sum) + HIWORD(sum));

					if (LOWORD(sum) >= LOWORD(header_sum)) {
						sum -= LOWORD(header_sum);
					} else {
						sum = ((LOWORD(sum) - LOWORD(header_sum)) & 0xFFFF) - 1;
					}

					if (LOWORD(sum) >= HIWORD(header_sum)) {
						sum -= HIWORD(header_sum);
					} else {
						sum = ((LOWORD(sum) - HIWORD(header_sum)) & 0xFFFF) - 1;
					}
					sum += file_size;

					*check_sum = sum;
					res = true;
				}

#ifdef VMP_GNU
				munmap(file_view, file_size);
#else
				UnmapViewOfFile(file_view);
#endif
#ifndef VMP_GNU
			}
			CloseHandle(file_map);
#endif
		}
#ifdef VMP_GNU
		close(file_handle);
#else
		CloseHandle(file_handle);
#endif
	}

	return res;
}

#ifndef VMP_GNU
std::string ToOEM(const unicode_string &src)
{
	std::string res;
	if (!src.empty()) {
		int size = WideCharToMultiByte(CP_OEMCP, 0, src.c_str(), (int)src.size(), NULL, 0, NULL, NULL);
		if (size > 0) {
			res.resize(size);
			WideCharToMultiByte(CP_OEMCP, 0, src.c_str(), (int)src.size(), &res[0], (int)res.size(), NULL, NULL);
		}
	}
	return res;
}
unicode_string FromACP(const std::string &src)
{
	unicode_string res;
	if (!src.empty()) {
		int size = MultiByteToWideChar(CP_ACP, 0, src.c_str(), (int)src.size(), NULL, 0);
		if (size > 0) {
			res.resize(size);
			MultiByteToWideChar(CP_ACP, 0, src.c_str(), (int)src.size(), &res[0], (int)res.size());
		}
	}
	return res;
}
bool ValidateUTF8(const std::string &src)
{
	bool ret = true;
	if (!src.empty()) {
		int res = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, src.c_str(), -1, NULL, NULL);
		if (res == 0 && GetLastError() == ERROR_NO_UNICODE_TRANSLATION) {
			ret = false;
		}
	}
	return ret;
}
#endif

 void Print(const char *text)
 {
 #ifdef VMP_GNU
	std::cout << text << std::flush;
 #else
	std::cout << ToOEM(FromUTF8(text)) << std::flush;
 #endif
 }

std::vector<std::string> CommandLine()
{
	std::vector<std::string> res;
	int num;
	wchar_t **args = CommandLineToArgvW(GetCommandLineW(), &num);
	for (int i = 0; i < num; i++) {
		if (args[i])
			res.push_back(ToUTF8(std::wstring(args[i])));
	}
	return res;
}

#ifdef VMP_GNU
#define TOUPPER(x) toupper(x)
static bool WildcardMatch(const char *name, const char *mask)
#else
#define TOUPPER(x) towupper(x)
static bool WildcardMatch(const wchar_t *name, const wchar_t *mask)
#endif
{
	if (!name || !mask)
		return false;

	while (*name) {
		if (*mask == '*') {
			mask++;
			if (*mask == '\0')
				return true;
			while (*name) {
				if (WildcardMatch(name, mask))
					return true;
				name++;
			}
			return false;
		}
		if (*mask == '?' || TOUPPER(*name) == TOUPPER(*mask)) {
			name++;
			mask++;
		} else {
			return false;
		}
	}
	while (*mask == '*')
		mask++;
	return (*mask == '\0');
}

std::vector<std::string> FindFiles(const char *name, const char *mask, bool only_directories)
{
	std::vector<std::string> res;
	if (!name || !mask)
		return res;

#ifdef VMP_GNU
	DIR *dir;
	struct dirent *ent;
	dir = opendir(name);
	if (dir) {
		while ((ent = readdir(dir))) {
			if (WildcardMatch(ent->d_name, mask))
				res.push_back(CombinePaths(name, ent->d_name));
		}
		closedir(dir);
	}
#else
	std::wstring unicode_mask = FromUTF8(mask);
	WIN32_FIND_DATAW find_data;
	HANDLE h = FindFirstFileW(FromUTF8(std::string(name) + "\\*").c_str(), &find_data);
	if (h != INVALID_HANDLE_VALUE) {
		do {
			if (wcscmp(find_data.cFileName, L".") == 0 || wcscmp(find_data.cFileName, L"..") == 0)
				continue;
			if (only_directories && ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0))
				continue;
			if (!WildcardMatch(find_data.cFileName, unicode_mask.c_str()))
				continue;

			res.push_back(CombinePaths(name, ToUTF8(find_data.cFileName).c_str()));
		} while (FindNextFileW(h, &find_data) != 0);
		FindClose(h);
	}
#endif
	return res;
}

uint32_t GetTickCount()
{
	return ::GetTickCount();
}

#ifdef VMP_GNU
static char* rstrip(char* s)
{
	char* p = s + strlen(s);
	while (p > s && isspace((unsigned char)(*--p)))
		*p = '\0';
	return s;
}

static char* lskip(const char* s)
{
	while (*s && isspace((unsigned char)(*s)))
		s++;
	return (char*)s;
}

static char* find_char_or_comment(const char* s, char c)
{
	int was_whitespace = 0;
	while (*s && *s != c && !(was_whitespace && *s == ';')) {
		was_whitespace = isspace((unsigned char)(*s));
		s++;
	}
	return (char*)s;
}

static void SwapBuffer(unicode_char *buf, size_t size)
{
	for (size_t i = 0; i < size; i++) {
		unicode_char c = buf[i];
		buf[i] = (c >> 8) | (c << 8);
	}
}

bool ProfileString(const char *_section, const char *_key, const char *_value, char const *file_name, std::string *result)
{
	static const uint8_t utf16_le_bom[] = {0xFF, 0xFE};
	static const uint8_t utf16_be_bom[] = {0xFE, 0xFF};
	static const uint8_t utf8_bom[] = {0xEF, 0xBB, 0xBF};

	enum Encoding {
		enNone,
		enUTF16_le,
		enUTF16_be,
		enUTF8
	};

	char *start;
	char *end;
	char *section;
	char *name;
	char *value;
	Encoding encoding = enNone;
	std::stringstream stream;

	HANDLE file = FileCreate(file_name, fmOpenRead | fmShareDenyNone);
	if (file == INVALID_HANDLE_VALUE) {
		if (result)
			return false;
	} else	{
		char bom[3] = {0};
		FileRead(file, bom, sizeof(utf16_le_bom));
		if (memcmp(bom, utf16_le_bom, sizeof(utf16_le_bom)) == 0) {
			encoding = enUTF16_le;
		} else if (memcmp(bom, utf16_be_bom, sizeof(utf16_be_bom)) == 0) {
			encoding = enUTF16_be;
		} else {
			FileRead(file, &bom[2], 1);
			if (memcmp(bom, utf8_bom, sizeof(utf8_bom)) == 0)
				encoding = enUTF8;
		}
		uint64_t begin_pos = (encoding == enNone) ? 0 : FileSeek(file, 0, soCurrent);
		uint64_t end_pos = FileSeek(file, 0, soEnd);
		size_t size = static_cast<size_t>(end_pos - begin_pos);
		if (size) {
			FileSeek(file, begin_pos, soBeginning);
			uint8_t *buff = new uint8_t[size];
			FileRead(file, buff, size);
			FileClose(file);
			if (encoding == enUTF16_be)
				SwapBuffer(reinterpret_cast<unicode_char *>(buff), size / sizeof(unicode_char));
			stream.str((encoding == enUTF16_le || encoding == enUTF16_be) ? ToUTF8(unicode_string(reinterpret_cast<unicode_char *>(buff), size / sizeof(unicode_char))) : std::string(reinterpret_cast<char *>(buff), size));
			delete [] buff;
		}
		FileClose(file);
	}

	bool section_found = false;
	bool value_saved = false;
	std::string line;
	std::vector<std::string> lines;
	while (std::getline(stream, line)) {
		if (!line.empty() && *(line.end() - 1) == '\r')
			line.erase(line.size() - 1);

		if (!result)
			lines.push_back(line);

		start = &line[0];
		start = lskip(rstrip(start));

		if (*start == ';' || *start == '#') {
			/* Per Python ConfigParser, allow '#' comments at start of line */
        } else if (*start == '[') {
			/* A "[section]" line */
			end = find_char_or_comment(start + 1, ']');
			if (*end == ']') {
				*end = '\0';
				if (section_found) {
					if (_key) {
						if (result) {
							return false;
						} else if (!value_saved) {
							std::vector<std::string>::iterator it = lines.end() - 1;
							if (_value)
								lines.insert(it, std::string(_key) + std::string("=") + std::string(_value));
							else
								lines.erase(it);
							value_saved = true;
						}
					} else {
						if (result)
							return true;
					}
				}

				section = start + 1;
				section_found = (_strcmpi(section, _section) == 0);
			}
		} else if (*start && *start != ';') {
			/* Not a comment, must be a name[=:]value pair */
			end = find_char_or_comment(start, '=');
			if (*end != '=') {
				end = find_char_or_comment(start, ':');
			}
			if (*end == '=' || *end == ':') {
				*end = '\0';
				name = rstrip(start);
				value = lskip(end + 1);
				end = find_char_or_comment(value, '\0');
				if (*end == ';')
					*end = '\0';
				rstrip(value);

				if (section_found) {
					if (_key) {
						if (_strcmpi(name, _key) == 0) {
							if (result) {
								*result = value;
								return true;
							} else if (!value_saved) {
								std::vector<std::string>::iterator it = lines.end() - 1;
								if (_value)
									*it = std::string(name) + "=" + std::string(_value);
								else
									lines.erase(it);
								value_saved = true;
							}
						}
					} else {
						if (result) {
							*result += name;
							*result += '\0';
						}
					}
				}
			}
		}
	}

	if (result) {
		return false;
	} else {
		file = FileCreate(file_name, fmCreate | fmOpenWrite | fmShareDenyNone);
		if (file == INVALID_HANDLE_VALUE)
			return false;

		switch (encoding) {
		case enUTF8:
			FileWrite(file, utf8_bom, sizeof(utf8_bom));
			break;
		case enUTF16_le:
			FileWrite(file, utf16_le_bom, sizeof(utf16_le_bom));
			break;
		case enUTF16_be:
			FileWrite(file, utf16_be_bom, sizeof(utf16_be_bom));
			break;
		}

		if (!value_saved) {
			if (!section_found)
				lines.push_back(std::string("[") + std::string(_section) + std::string("]"));
			lines.push_back(std::string(_key) + std::string("=") + std::string(_value));
		}

		for (size_t i = 0; i < lines.size(); i++) {
			std::string str = lines[i] + "\r\n";
			if (encoding == enUTF16_le || encoding == enUTF16_be) {
				unicode_string wstr = FromUTF8(str);
				if (encoding == enUTF16_be)
					SwapBuffer(const_cast<unicode_char *>(wstr.c_str()), wstr.size());
				FileWrite(file, wstr.c_str(), wstr.size() * sizeof(unicode_char));
			} else {
				FileWrite(file, str.c_str(), str.size());
			}
		}
		FileClose(file);
		return true;
	}
}
#endif

bool WriteIniString(const char *section, const char *key, const char *value, const char *file_name)
{
#ifdef VMP_GNU
	return ProfileString(section, key, value, file_name, NULL);
#else
	return WritePrivateProfileStringW(section ? FromUTF8(section).c_str() : NULL, 
										key ? os::FromUTF8(key).c_str() : NULL,
										value ? os::FromUTF8(value).c_str() : NULL, 
										file_name ? os::FromUTF8(file_name).c_str() : NULL
										) != FALSE;
#endif
}

std::string ReadIniString(const char *section, const char *key, const char *default_value, const char *file_name)
{
	std::string res;
#ifdef VMP_GNU
	if (!ProfileString(section, key, default_value, file_name, &res)) {
		if (default_value)
			res = std::string(default_value);
	}
#else
	size_t buffer_size = 1024;
	os::unicode_char *buffer = NULL;
	for (;;) {
		delete [] buffer;
		buffer = new os::unicode_char[buffer_size];
		uint32_t len = GetPrivateProfileStringW(section ? FromUTF8(section).c_str() : NULL,
											key ? FromUTF8(key).c_str() : NULL, 
											default_value ? FromUTF8(default_value).c_str() : NULL, 
											buffer, (DWORD)buffer_size, 
											file_name ? FromUTF8(file_name).c_str() : NULL);
		if (len < buffer_size - sizeof(os::unicode_char)) {
			res = os::ToUTF8(os::unicode_string(buffer, len));
			break;
		}
		buffer_size *= 4;
	}
	delete [] buffer;
#endif
	return res;
}

HPROCESS ProcessOpen(uint32_t id)
{
	return OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);
}

bool ProcessClose(HPROCESS h)
{
#ifdef VMP_GNU
	// do nothing
	return true;
#else
	return (CloseHandle(h) != 0);
#endif
}

size_t ProcessRead(HPROCESS h, void *base_address, void *buf, size_t size)
{
	SIZE_T res;
	if (ReadProcessMemory(h, base_address, buf, size, &res) == 0)
		return -1;
	return res;
}

size_t ProcessWrite(HPROCESS h, void *base_address, const void *buf, size_t size)
{
	SIZE_T res;
	if (WriteProcessMemory(h, base_address, buf, size, &res) == 0)
		return -1;
	return res;
}

uint64_t GetLastWriteTime(const char *name)
{
	uint64_t res = 0;
	HANDLE h = FileCreate(name, fmOpenRead | fmShareDenyNone);
	if (h != INVALID_HANDLE_VALUE) {
#ifdef VMP_GNU
		struct stat stat_buf;
		if (fstat(h, &stat_buf) == 0)
			res = stat_buf.st_mtime;
#else
		FILETIME file_time;
		if (GetFileTime(h, NULL, NULL , &file_time))
			res = (static_cast<uint64_t>(file_time.dwHighDateTime) << 32 | file_time.dwLowDateTime) / 10000000 - 11644473600;
#endif
		FileClose(h);
	}
	return res;
}

std::vector<PROCESS_ITEM> EnumProcesses()
{
	std::vector<PROCESS_ITEM> res;
	DWORD processes[1024], needed;
	if (::EnumProcesses(processes, sizeof(processes), &needed)) {
		size_t count = needed / sizeof(DWORD);
		for (size_t i = 0; i < count; i++) {
			if (!processes[i])
				continue;

			wchar_t process_name[MAX_PATH] = {0};
			HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
			if (process) {
				if (GetModuleFileNameExW(process, 0, process_name, _countof(process_name))) {
					PROCESS_ITEM item;
					item.id = processes[i];
					item.name = ExtractFileName(ToUTF8(process_name).c_str());
					res.push_back(item);
				}
				CloseHandle(process);
			}
		}
	}
	return res;
}

std::vector<MODULE_ITEM> EnumModules(uint32_t process_id)
{
	std::vector<MODULE_ITEM> res;
	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
	if (process) {
        HMODULE mods[1024];
        DWORD needed;

		if (EnumProcessModules(process, mods, sizeof(mods), &needed)) { //-V
			size_t count = needed / sizeof(HMODULE);
			for (size_t i = 0; i < count; i++) {
				wchar_t module_name[MAX_PATH] = {0};
            	if (GetModuleFileNameExW(process, mods[i], module_name, _countof(module_name))) {
					MODULE_ITEM item;
					item.handle = mods[i];
					item.name = ToUTF8(module_name);
					res.push_back(item);
				}
            }
        }
		CloseHandle(process);
    }
	return res;
}

bool GetModuleInformation(HANDLE process, HMODULE module, MODULE_INFO *info, size_t size)
{
	if (size < sizeof(MODULE_INFO))
		return false;

	MODULEINFO moduleInfo;
	if (!::GetModuleInformation(process, module, &moduleInfo, sizeof(moduleInfo)))
		return false;

	info->address = moduleInfo.lpBaseOfDll;
	info->size = moduleInfo.SizeOfImage;
	return true;
}

std::string GetSysAppDataDirectory()
{
	std::string res;
	os::unicode_char buffer[MAX_PATH];

	if (SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA,  NULL, 0, buffer) >= 0)
		res = os::ToUTF8(buffer);
	return res;
}

bool DirectoryCreate(const char *name)
{
	if (!name)
		return false;

#ifdef VMP_GNU
	return (mkdir(name, S_IRWXU | S_IRWXG | S_IRWXO) == 0);
#else
	return (CreateDirectoryW(FromUTF8(name).c_str(), NULL) != 0 || GetLastError() == ERROR_ALREADY_EXISTS);
#endif
}

bool PathCreate(const char *name)
{
	if (!name)
		return false;

	bool res = DirectoryCreate(name);
	if (!res) {
		const char *prev = GetFileName(name);
		if (prev != name && PathCreate(std::string(name, prev - name - 1).c_str()))
			res = DirectoryCreate(name);
	}
	return res;
}

#ifndef VMP_GNU
struct LocaleInfo {
	LCID id;
	char iso_name[6];
};

static const LocaleInfo win_locale_info[] = {
	{0x0436, "af"},
	{0x3801, "ar_AE"},
	{0x3c01, "ar_BH"},
	{0x1401, "ar_DZ"},
	{0x0c01, "ar_EG"},
	{0x0801, "ar_IQ"},
	{0x2c01, "ar_JO"},
	{0x3401, "ar_KW"},
	{0x3001, "ar_LB"},
	{0x1001, "ar_LY"},
	{0x1801, "ar_MA"},
	{0x2001, "ar_OM"},
	{0x4001, "ar_QA"},
	{0x0401, "ar_SA"},
	{0x2801, "ar_SY"},
	{0x1c01, "ar_TN"},
	{0x2401, "ar_YE"},
	{0x0423, "be"},
	{0x0402, "bg"},
	{0x0403, "ca"},
	{0x0405, "cs"},
	{0x0406, "da"},
	{0x0407, "de"},
	{0x0c07, "de_AT"},
	{0x0807, "de_CH"},
	{0x1407, "de_LI"},
	{0x1007, "de_LU"},
	{0x0408, "el"},
	{0x0409, "en"},
	{0x0c09, "en_AU"},
	{0x2809, "en_BZ"},
	{0x1009, "en_CA"},
	{0x0809, "en_GB"},
	{0x1809, "en_IE"},
	{0x2009, "en_JM"},
	{0x1409, "en_NZ"},
	{0x2c09, "en_TT"},
	{0x0409, "en_US"},
	{0x1c09, "en_ZA"},
	{0x040a, "es"},
	{0x2c0a, "es_AR"},
	{0x400a, "es_BO"},
	{0x340a, "es_CL"},
	{0x240a, "es_CO"},
	{0x140a, "es_CR"},
	{0x1c0a, "es_DO"},
	{0x300a, "es_EC"},
	{0x100a, "es_GT"},
	{0x480a, "es_HN"},
	{0x080a, "es_MX"},
	{0x4c0a, "es_NI"},
	{0x180a, "es_PA"},
	{0x280a, "es_PE"},
	{0x500a, "es_PR"},
	{0x3c0a, "es_PY"},
	{0x440a, "es_SV"},
	{0x380a, "es_UY"},
	{0x200a, "es_VE"},
	{0x0425, "et"},
	{0x042d, "eu"},
	{0x0429, "fa"},
	{0x040b, "fi"},
	{0x0438, "fo"},
	{0x040c, "fr"},
	{0x080c, "fr_BE"},
	{0x0c0c, "fr_CA"},
	{0x100c, "fr_CH"},
	{0x140c, "fr_LU"},
	{0x040d, "he"},
	{0x0439, "hi"},
	{0x041a, "hr"},
	{0x040e, "hu"},
	{0x0421, "in"},
	{0x040f, "is"},
	{0x0410, "it"},
	{0x0810, "it_CH"},
	{0x0411, "ja"},
	{0x0812, "ko"},
	{0x0412, "ko"},
	{0x0427, "lt"},
	{0x0426, "lv"},
	{0x042f, "mk"},
	{0x043e, "ms"},
	{0x0458, "mt"},
	{0x0413, "nl"},
	{0x0813, "nl_BE"},
	{0x0814, "no"},
	{0x0414, "no"},
	{0x0415, "pl"},
	{0x0816, "pt"},
	{0x0416, "pt_BR"},
	{0x0418, "ro"},
	{0x0419, "ru"},
	{0x041c, "sq"},
	{0x081a, "sr"},
	{0x0c1a, "sr"},
	{0x041d, "sv"},
	{0x081d, "sv_FI"},
	{0x041e, "th"},
	{0x041f, "tr"},
	{0x0422, "uk"},
	{0x0420, "ur"},
	{0x042a, "vi"},
	{0x0804, "zh"},
	{0x0804, "zh_CN"},
	{0x0c04, "zh_HK"},
	{0x1004, "zh_SG"},
	{0x0404, "zh_TW"}
};
#endif



std::string GetLocaleName(const char *code)
{
	if (!code)
		return std::string();

	std::string res;
	LCID id = 0;

	int begin = 0;
	int end = _countof(win_locale_info);
	while (end - begin > 1) {
		int mid = (begin + end)/2;

		const LocaleInfo *info = win_locale_info + mid;
		int cmp = strcmp(code, info->iso_name);
		if (cmp < 0)
			end = mid;
		else if (cmp > 0)
			begin = mid;
		else {
			id = info->id;
			break;
		}
	}

	if (id) {
		os::unicode_char buffer[1024];
		if (GetLocaleInfoW(id, LOCALE_SNATIVELANGNAME, buffer, sizeof(buffer))) {
			LCMapStringW(id, LCMAP_UPPERCASE, buffer, 1, buffer, 1);
			res = os::ToUTF8(os::unicode_string(buffer));
		}
	}
	if (res.empty())
		res = code;
	return res;
}

std::string GetCurrentLocale()
{
	std::string res;
	LCID id = GetUserDefaultLCID();
	for (size_t i = 0; i < _countof(win_locale_info); i++) {
		if (win_locale_info[i].id == id) {
			res = win_locale_info[i].iso_name;
			break;
		}
	}
	return res;
}

void GetLocalTime(SYSTEM_TIME *res)
{
#ifdef VMP_GNU
	time_t rawtime;
	time(&rawtime);
	struct tm local_tm;
	tm *timeinfo = localtime_r(&rawtime, &local_tm);
	res->year = static_cast<uint16_t>(timeinfo->tm_year + 1900);
	res->month = static_cast<uint8_t>(timeinfo->tm_mon);
	res->day = static_cast<uint8_t>(timeinfo->tm_mday);
#else
	SYSTEMTIME local_time;
	::GetLocalTime(&local_time);
	res->year = local_time.wYear;
	res->month = static_cast<uint8_t>(local_time.wMonth);
	res->day = static_cast<uint8_t>(local_time.wDay);
#endif
}

#ifndef VMP_GNU
#include <fcntl.h>

static const wchar_t letters[] =
L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* Generate a temporary file name based on TMPL.  TMPL must match the
   rules for mk[s]temp (i.e. end in "XXXXXX").  The name constructed
   does not exist at the time of the call to mkstemp.  TMPL is
   overwritten with the result.  */
int
mkstemp (wchar_t *tmpl)
{
	size_t len;
	wchar_t *XXXXXX;
	static unsigned long long value;
	unsigned long long random_time_bits;
	unsigned int count;
	int fd = -1;
	int save_errno = errno;

	/* A lower bound on the number of temporary files to attempt to
		generate.  The maximum total number of temporary file names that
		can exist for a given template is 62**6.  It should never be
		necessary to try all these combinations.  Instead if a reasonable
		number of names is tried (we define reasonable as 62**3) fail to
		give the system administrator the chance to remove the problems.  */
#define ATTEMPTS_MIN (62 * 62 * 62)

	/* The number of times to attempt to generate a temporary file.  To
		conform to POSIX, this must be no smaller than TMP_MAX.  */
#if ATTEMPTS_MIN < TMP_MAX
	unsigned int attempts = TMP_MAX;
#else
	unsigned int attempts = ATTEMPTS_MIN;
#endif

	len = wcsnlen_s (tmpl, MAX_PATH);
	if (len < 6 || wcsncmp (&tmpl[len - 6], L"XXXXXX", MAX_PATH))
	{
		errno = EINVAL;
		return -1;
	}

	/* This is where the Xs start.  */
	XXXXXX = &tmpl[len - 6];

	/* Get some more or less random data.  */
	{
		SYSTEMTIME      stNow;
		FILETIME ftNow;

		// get system time
		GetSystemTime(&stNow);
		stNow.wMilliseconds = 500;
		if (!SystemTimeToFileTime(&stNow, &ftNow))
		{
			errno = -1;
			return -1;
		}

		random_time_bits = (((unsigned long long)ftNow.dwHighDateTime << 32)
			| (unsigned long long)ftNow.dwLowDateTime);
	}
	value += random_time_bits ^ (unsigned long long)GetCurrentThreadId ();

	for (count = 0; count < attempts; value += 7777, ++count)
	{
		unsigned long long v = value;

		/* Fill in the random bits.  */
		XXXXXX[0] = letters[v % 62];
		v /= 62;
		XXXXXX[1] = letters[v % 62];
		v /= 62;
		XXXXXX[2] = letters[v % 62];
		v /= 62;
		XXXXXX[3] = letters[v % 62];
		v /= 62;
		XXXXXX[4] = letters[v % 62];
		v /= 62;
		XXXXXX[5] = letters[v % 62];

		if (0 == _wsopen_s(&fd, tmpl, O_RDWR | O_CREAT | O_EXCL, _SH_DENYRW, _S_IREAD | _S_IWRITE) && fd >= 0)
		{
			errno = save_errno;
			return fd;
		} else if (errno != EEXIST)
		{
			return -1;
		}
	}

	/* We got out of the loop because we ran out of combinations to try.  */
	errno = EEXIST;
	return -1;
}
#endif

std::string GetTempFilePathName(const char *pathname_template /*=NULL*/)
{
	std::string ret;
#ifdef VMP_GNU
	char szTempFileName[PATH_MAX] = "/tmp/vmpXXXXXX";
	if(pathname_template)
		strcpy_s(szTempFileName, pathname_template);
	int fd = mkstemp(szTempFileName);
	if(fd >= 0)
	{
		fchmod(fd, S_IRUSR | S_IWUSR | S_IXUSR);
		ret = szTempFileName;
		close(fd);
	}
#else
	if(pathname_template)
	{
		os::unicode_string tempFileName = os::FromUTF8(pathname_template);
		int fd = mkstemp(const_cast<wchar_t *>(tempFileName.data()));
		if(fd >= 0)
		{
			ret = os::ToUTF8(tempFileName);
			_close(fd);
		}
	} else
	{
		wchar_t lpTempPathBuffer[MAX_PATH], szTempFileName[MAX_PATH];
		DWORD dwRetVal = GetTempPathW(MAX_PATH, lpTempPathBuffer);
		if (dwRetVal <= MAX_PATH && (dwRetVal != 0))
		{
			UINT uRetVal = GetTempFileNameW(lpTempPathBuffer, L"vmp", 0, szTempFileName);
			if (uRetVal > 0)
			{
				ret  = os::ToUTF8(std::wstring(szTempFileName));
			}
		}
	}
#endif
	return ret;
}
std::string GetTempFilePathNameFor(const char *pathname)
{
	std::string ret = os::GetTempFilePathName((std::string(pathname) + ".XXXXXX").c_str());
	if(ret.empty())
	{
		return os::GetTempFilePathName();
	}
	return ret;
}

bool FileMove(const char *oldName, const char *newName)
{
	return MoveFileExW(os::FromUTF8(oldName).c_str(), os::FromUTF8(newName).c_str(), 
		MOVEFILE_COPY_ALLOWED | // used only when different volumes
		MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == TRUE;
}

std::string CombineThisAppDataDirectory(const char *lastPathPart)
{
	return os::CombinePaths(os::CombinePaths(os::GetSysAppDataDirectory().c_str(), "VMProtect Software/VMProtect").c_str(), lastPathPart);
}

HMODULE LibraryOpen(const std::string &name)
{
#ifdef VMP_GNU
	return dlopen(name.c_str(), RTLD_NOW);
#else
	return LoadLibraryW(FromUTF8(name).c_str());
#endif
}

bool LibraryClose(HMODULE h)
{
#ifdef VMP_GNU
	return (dlclose(h) == 0);
#else
	return (FreeLibrary(h) != 0);
#endif
}

void *GetFunction(HMODULE h, const std::string &name)
{
#ifdef VMP_GNU
	return dlsym(h, name.c_str());
#else
	return GetProcAddress(h, name.c_str());
#endif
}

std::string ExpandEnvironmentVariables(const char *path)
{
#ifdef VMP_GNU
	std::string res;
	for (const char *p = path; *p; ) {
		const char *first = strchr(p, '%');
		if (first) {
			const char *next = strchr(first + 1, '%');
			if (next) {
				const char *var_value = getenv(std::string(first + 1, next - first - 1).c_str());
				if (var_value) {
					res.append(p, first - p);
					res.append(var_value);
				} else {
					res.append(p, next + 1 - p);
				}
				p = next + 1;
				continue;
			}
		}

		res.append(p);
		break;
	}
	return res;
#else
	unicode_string src = FromUTF8(path);
	unicode_string res;
	for (const unicode_char *p = src.c_str(); *p; ) {
		const unicode_char *first = wcschr(p, '%');
		if (first) {
			const unicode_char *next = wcschr(first + 1, '%');
			if (next) {
				size_t var_size;
				unicode_string var = unicode_string(first + 1, next - first - 1);
				_wgetenv_s(&var_size, NULL, 0, var.c_str()); //-V530
				if (var_size) {
					res.append(p, first - p);
					unicode_char *var_value = new unicode_char[var_size];
					_wgetenv_s(&var_size, var_value, var_size, var.c_str()); //-V530
					res.append(var_value);
					delete [] var_value;
				} else {
					res.append(p, next + 1 - p);
				}
				p = next + 1;
				continue;
			}
		}

		res.append(p);
		break;
	}
	return ToUTF8(res);
#endif
}

std::string GetEnvironmentVariable(const char *name)
{
#ifdef VMP_GNU
	if (const char *p = getenv(name))
		return std::string(p);
	return std::string();
#else
	unicode_string var = FromUTF8(name);
	unicode_string res;
	size_t var_size;
	_wgetenv_s(&var_size, NULL, 0, var.c_str());
	if (var_size) {
		unicode_char *var_value = new unicode_char[var_size];
		_wgetenv_s(&var_size, var_value, var_size, var.c_str()); //-V530
		res = var_value;
		delete[] var_value;
	}
	return ToUTF8(res);
#endif
}

void SetEnvironmentVariable(const char *name, const char *value)
{
#ifdef VMP_GNU
	setenv(name, value, 1);
#else
	_wputenv_s(FromUTF8(name).c_str(), FromUTF8(value).c_str());
#endif
}

}
