/**
 * Code markers (protection/script/vm).
 * Rust mapping target: mod markers
 */

#ifndef FILES_MARKERS_H
#define FILES_MARKERS_H

#include "../../runtime/common.h"
#include "../objects.h"
#include "types.h"

class MarkerCommandList;

class MarkerCommand: public IObject
{
public:
	explicit MarkerCommand(MarkerCommandList *owner, uint64_t address, uint64_t operand_address, 
		uint64_t name_reference, uint64_t name_address, ObjectType type);
	explicit MarkerCommand(MarkerCommandList *owner, const MarkerCommand &src);
	~MarkerCommand();
	MarkerCommand *Clone(MarkerCommandList *owner) const;
	uint64_t address() const { return address_; }
	uint64_t operand_address() const { return operand_address_; }
	uint64_t name_address() const { return name_address_; }
	uint64_t name_reference() const { return name_reference_; }
	ObjectType type() const { return type_; }
	
	using IObject::CompareWith;
	int CompareWith(const MarkerCommand &obj) const;
private:
	MarkerCommandList *owner_;
	uint64_t address_;
	uint64_t operand_address_;
	uint64_t name_address_;
	uint64_t name_reference_;
	ObjectType type_;

	// no assignment op
	MarkerCommand &operator =(const MarkerCommand &);
};

class MarkerCommandList : public ObjectList<MarkerCommand>
{
public:
	explicit MarkerCommandList();
	explicit MarkerCommandList(const MarkerCommandList &src);
	MarkerCommand *Add(uint64_t address, uint64_t operand_address, uint64_t name_reference, uint64_t name_address, ObjectType type = otUnknown);
	MarkerCommandList *Clone() const;
};

#endif // FILES_MARKERS_H
