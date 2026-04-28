/**
 * Code markers implementations.
 * Rust mapping target: mod markers
 */

#include "markers.h"
#include "../files.h"

/**
 * MarkerCommand
 */

MarkerCommand::MarkerCommand(MarkerCommandList *owner, uint64_t address, uint64_t operand_address, 
	uint64_t name_reference, uint64_t name_address, ObjectType type)
	: IObject(), owner_(owner), address_(address), operand_address_(operand_address), name_address_(name_address), 
	name_reference_(name_reference), type_(type)
{

}

MarkerCommand::MarkerCommand(MarkerCommandList *owner, const MarkerCommand &src)
	: IObject(), owner_(owner) 
{
	address_ = src.address_;
	operand_address_ = src.operand_address_;
	name_address_ = src.name_address_;
	name_reference_ = src.name_reference_;
	type_ = src.type_;
}

MarkerCommand::~MarkerCommand()
{
	if (owner_)
		owner_->RemoveObject(this);
}

MarkerCommand *MarkerCommand::Clone(MarkerCommandList *owner) const
{
	MarkerCommand *command = new MarkerCommand(owner, *this);
	return command;
}

int MarkerCommand::CompareWith(const MarkerCommand &obj) const
{
	if (address() < obj.address())
		return -1;
	if (address() > obj.address())
		return 1;
	return 0;
}

/**
 * MarkerCommandList
 */

MarkerCommandList::MarkerCommandList()
	: ObjectList<MarkerCommand>()
{

}

MarkerCommandList::MarkerCommandList(const MarkerCommandList &src)
	: ObjectList<MarkerCommand>()
{
	for (size_t i = 0; i < src.count(); i++) {
		MarkerCommand *command = src.item(i);
		AddObject(command->Clone(this));
	}
}

MarkerCommand *MarkerCommandList::Add(uint64_t address, uint64_t operand_address, uint64_t name_reference, uint64_t name_address, ObjectType type)
{
	MarkerCommand *command = new MarkerCommand(this, address, operand_address, name_reference, name_address, type);
	AddObject(command);
	return command;
}

MarkerCommandList *MarkerCommandList::Clone() const 
{
	MarkerCommandList *list = new MarkerCommandList(*this);
	return list;
}
