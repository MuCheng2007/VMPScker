/**
 * Cross-reference tracking between addresses.
 * Depends only on: runtime/common.h, objects.h
 *
 * Rust mapping target: mod references
 */

#ifndef FILES_REFERENCES_H
#define FILES_REFERENCES_H

#include "../../runtime/common.h"
#include "../objects.h"

class ReferenceList;

// ---------------------------------------------------------------------------
// Reference: a single address cross-reference with optional tag
// Rust mapping: struct Reference { address: u64, operand_address: u64, tag: usize }
// ---------------------------------------------------------------------------

class Reference : public IObject
{
public:
	explicit Reference(ReferenceList *owner, uint64_t address, uint64_t operand_address, size_t tag);
	explicit Reference(ReferenceList *owner, const Reference &src);
	~Reference();
	uint64_t address() const { return address_; }
	uint64_t operand_address() const { return operand_address_; }
	virtual Reference *Clone(ReferenceList *owner) const;
	void Rebase(uint64_t delta_base);
	size_t tag() const { return tag_; }
	ReferenceList *owner() const { return owner_; }
private:
	ReferenceList *owner_;
	uint64_t address_;
	uint64_t operand_address_;
	size_t tag_;
};

// ---------------------------------------------------------------------------
// ReferenceList: ordered collection of References
// Rust mapping: struct ReferenceList(Vec<Reference>)
// ---------------------------------------------------------------------------

class ReferenceList : public ObjectList<Reference>
{
public:
	explicit ReferenceList();
	explicit ReferenceList(const ReferenceList &src);
	virtual ReferenceList *Clone() const;
	Reference *Add(uint64_t address, uint64_t operand_address, size_t tag = 0);
	Reference *GetReferenceByAddress(uint64_t address) const;
	void Rebase(uint64_t delta_base);
private:
	// no assignment op
	ReferenceList &operator =(const ReferenceList &);
};

#endif // FILES_REFERENCES_H
