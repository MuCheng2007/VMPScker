/**
 * Utility functions and types for working with executable files.
 * Depends only on: runtime/common.h, files/types.h
 *
 * Rust mapping target: mod utils
 */

#ifndef FILES_UTILS_H
#define FILES_UTILS_H

#include "../../runtime/common.h"
#include "types.h"

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

std::string NameToString(const char name[], size_t name_size);
std::string DisplayString(const std::string &str);
std::string DisplayValue(OperandSize size, uint64_t value);

// ---------------------------------------------------------------------------
// Operand size <-> byte width conversion
// ---------------------------------------------------------------------------

uint16_t OperandSizeToValue(OperandSize os);
uint16_t OperandSizeToStack(OperandSize os);

// ---------------------------------------------------------------------------
// Alignment helper (template, header-only)
// ---------------------------------------------------------------------------

template<typename V, typename A>
V AlignValue(V value, A alignment)
{
	return (value % alignment == 0) ? value : value + alignment - (value % alignment);
}

// ---------------------------------------------------------------------------
// Function name with optional return-type prefix
// Used everywhere a symbol name is tracked.
// Rust mapping: struct FunctionName { name: String, name_pos: usize }
// ---------------------------------------------------------------------------

struct FunctionName {
	FunctionName()
		: name_pos_(0) {}
	FunctionName(const std::string &name, size_t name_pos = 0) 
		: name_(name), name_pos_(name_pos) {}
	std::string name() const { return name_.substr(name_pos_); }
	std::string display_name(bool show_ret = true) const { return DisplayString(show_ret ? name_ : name_.substr(name_pos_)); }
	void clear() 
	{
		name_.clear();
		name_pos_ = 0;
	}
	bool operator==(const FunctionName &name) const
	{
		return (name_ == name.name_) && (name_pos_ == name.name_pos_);
	}
	bool operator!=(const FunctionName &name) const
	{
		return !(operator==(name));
	}
private:
	std::string name_;
	size_t name_pos_;
};

// ---------------------------------------------------------------------------
// Demangling
// ---------------------------------------------------------------------------

FunctionName DemangleName(const std::string &name);

#endif // FILES_UTILS_H
