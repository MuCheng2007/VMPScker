#include "core_utils.h"

#include "../../runtime/crypto.h"

#include <cstdlib>
#include <cstring>

uint64_t StrToInt64Def(const char *str, uint64_t default_value)
{
	size_t len = strlen(str);
	if (len == 0)
		return default_value;

	char *end;
	uint64_t res = _strtoi64(str, &end, 0);
	if (end != str + len)
		return default_value;

	return res;
}

void Base64ToVector(const char *src, size_t src_len, std::vector<uint8_t> &dst)
{
	if (!src || !src_len) {
		dst.clear();
		return;
	}
	size_t dst_len = src_len;
	dst.resize(dst_len, 0);
	Base64Decode(src, src_len, &dst[0], dst_len);
	if (dst_len != dst.size())
		dst.resize(dst_len);
}

std::string VectorToBase64(const std::vector<uint8_t> &src)
{
	std::string dst;

	if (!src.empty()) {
		size_t dst_len = Base64EncodeGetRequiredLength(src.size());
		dst.resize(dst_len);
		Base64Encode(&src[0], src.size(), &dst[0], dst_len);
		if (dst_len != dst.size())
			dst.resize(dst_len);
	}
	return dst;
}
