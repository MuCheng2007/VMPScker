#ifndef CORE_UTILS_H
#define CORE_UTILS_H

#include "../../runtime/common.h"

void Base64ToVector(const char *src, size_t src_len, std::vector<uint8_t> &dst);
std::string VectorToBase64(const std::vector<uint8_t> &src);

#endif
