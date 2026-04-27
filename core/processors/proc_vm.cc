#include "proc_vm.h"
#include "proc_interfaces.h"


/**
* BaseVirtualMachine
*/

BaseVirtualMachine::BaseVirtualMachine(IVirtualMachineList* owner, uint8_t id)
	: IVirtualMachine(), owner_(owner), id_(id)
{

}

BaseVirtualMachine::~BaseVirtualMachine()
{
	if (owner_)
		owner_->RemoveObject(this);
}