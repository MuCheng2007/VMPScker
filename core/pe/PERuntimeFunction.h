/**
 * PE Runtime Function support.
 */

#ifndef PE_RUNTIME_FUNCTION_H
#define PE_RUNTIME_FUNCTION_H

#include "../files.h"

class PEArchitecture;
class PERuntimeFunctionList;
class PEDirectory;

class PERuntimeFunction : public BaseRuntimeFunction
{
public:
	explicit PERuntimeFunction(PERuntimeFunctionList *owner, uint64_t address, uint64_t begin, uint64_t end, uint64_t unwind_address);
	explicit PERuntimeFunction(PERuntimeFunctionList *owner, const PERuntimeFunction &src);
	virtual PERuntimeFunction *Clone(IRuntimeFunctionList *owner) const;
	virtual uint64_t address() const { return address_; }
	virtual uint64_t begin() const { return begin_; }
	virtual uint64_t end() const { return end_; }
	virtual uint64_t unwind_address() const { return unwind_address_; }
	virtual void set_begin(uint64_t begin) { begin_ = begin; }
	virtual void set_end(uint64_t end) { end_ = end; }
	virtual void set_unwind_address(uint64_t unwind_address) { unwind_address_ = unwind_address; }
	virtual void Rebase(uint64_t delta_base);
	virtual void Parse(IArchitecture &file, IFunction &dest);
private:
	uint64_t address_;
	uint64_t begin_;
	uint64_t end_;
	uint64_t unwind_address_;
};

class PERuntimeFunctionList : public BaseRuntimeFunctionList
{
public:
	explicit PERuntimeFunctionList();
	explicit PERuntimeFunctionList(const PERuntimeFunctionList &src);
	PERuntimeFunctionList *Clone() const;
	PERuntimeFunction *item(size_t index) const;
	void ReadFromFile(PEArchitecture &file, PEDirectory &directory);
	size_t WriteToFile(PEArchitecture &file);
	virtual PERuntimeFunction *Add(uint64_t address, uint64_t begin, uint64_t end, uint64_t unwind_address, IRuntimeFunction *source, const std::vector<uint8_t> &call_frame_instructions);
	virtual PERuntimeFunction *GetFunctionByAddress(uint64_t address) const;
	void RebaseByFile(IArchitecture &file, uint64_t target_image_base, uint64_t delta_base);
	void FreeByManager(MemoryManager &manager);
	uint64_t address() const { return address_; }
private:
	uint64_t RebaseDWord(IArchitecture &file, uint32_t delta_base);
	uint64_t address_;

	// no assignment op
	PERuntimeFunctionList &operator =(const PERuntimeFunctionList &);
};

#endif // PE_RUNTIME_FUNCTION_H
