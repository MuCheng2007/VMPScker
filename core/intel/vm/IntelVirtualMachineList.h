#ifndef INTEL_VIRTUAL_MACHINE_LIST_H
#define INTEL_VIRTUAL_MACHINE_LIST_H

#include "../../processors.h"
#include <map>

class MemoryManager;
class ICommand;
class IntelVirtualMachine;

class IntelVirtualMachineList : public IVirtualMachineList
{
public:
	IntelVirtualMachineList();
	~IntelVirtualMachineList();
	virtual void Prepare(const CompileContext &ctx);
	IntelVirtualMachine *item(size_t index) const { return reinterpret_cast<IntelVirtualMachine *>(IVirtualMachineList::item(index)); }
	virtual IntelVirtualMachineList *Clone() const;
	uint64_t GetCRCValue(uint64_t &address, size_t size);
	void ClearCRCMap();
private:
	MemoryManager *crc_manager_;
	std::map<uint64_t, ICommand *> map_;

	// no copy ctr or assignment op
	IntelVirtualMachineList(const IntelVirtualMachineList &);
	IntelVirtualMachineList &operator =(const IntelVirtualMachineList &);
};

#endif // INTEL_VIRTUAL_MACHINE_LIST_H