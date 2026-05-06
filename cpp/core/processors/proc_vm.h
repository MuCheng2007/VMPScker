/**
 * Processors VM classes.
 * BaseVirtualMachine
 */

#ifndef PROC_VM_H
#define PROC_VM_H

#include "proc_types.h"
#include "proc_interfaces.h"

/**
 * Base implementation of virtual machine
 */
class BaseVirtualMachine : public IVirtualMachine
{
public:
	BaseVirtualMachine(IVirtualMachineList *owner, uint8_t id);
	~BaseVirtualMachine();
	virtual uint8_t id() const { return id_; }
private:
	IVirtualMachineList *owner_;
	uint8_t id_;
};

#endif // PROC_VM_H
