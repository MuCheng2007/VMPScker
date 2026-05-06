/**
 * Executable exports abstractions.
 * Rust mapping target: mod exports
 */

#ifndef FILES_EXPORTS_H
#define FILES_EXPORTS_H

#include "../../runtime/common.h"
#include "../objects.h"
#include "types.h"

class Buffer;
class IArchitecture;
class IExportList;

class IExport : public IObject
{
public:
	virtual uint64_t address() const = 0;
	virtual std::string name() const = 0;
	virtual std::string forwarded_name() const = 0;
	virtual std::string display_name(bool show_ret = true) const = 0;
	virtual APIType type() const = 0;
	virtual void set_type(APIType type) = 0;
	virtual void Rebase(uint64_t delta_base) = 0;
	virtual IExport *Clone(IExportList *owner) const = 0;
	virtual OperandSize address_size() const = 0;
	virtual bool is_equal(const IExport &src) const = 0;
};

class IExportList : public ObjectList<IExport>
{
public:
	virtual std::string name() const = 0;
	virtual IExport *GetExportByAddress(uint64_t address) const = 0;
	virtual uint64_t GetAddressByType(APIType type) const = 0;
	virtual void ReadFromBuffer(Buffer &buffer, IArchitecture &file) = 0;
	virtual void Rebase(uint64_t delta_base) = 0;
	virtual IArchitecture *owner() const = 0;
	virtual bool is_equal(const IExportList &src) const = 0;
protected:
	virtual IExport *Add(uint64_t address) = 0;
};

class BaseExport : public IExport
{
public:
	explicit BaseExport(IExportList *owner);
	explicit BaseExport(IExportList *owner, const BaseExport &src);
	~BaseExport();
	virtual OperandSize address_size() const;
	virtual bool is_equal(const IExport &src) const;
	virtual APIType type() const { return type_; }
	virtual void set_type(APIType type) { type_ = type; }
private:
	IExportList *owner_;
	APIType type_;
};

class BaseExportList : public IExportList
{
public:
	explicit BaseExportList(IArchitecture *owner);
	explicit BaseExportList(IArchitecture *owner, const BaseExportList &src);
	virtual uint64_t GetAddressByType(APIType type) const;
	IExport *GetExportByAddress(uint64_t address) const;
	IExport *GetExportByName(const std::string &name) const;
	virtual void ReadFromBuffer(Buffer &buffer, IArchitecture &file);
	virtual void Rebase(uint64_t delta_base);
	virtual IArchitecture *owner() const { return owner_; } 
	virtual bool is_equal(const IExportList &src) const;
private:
	IArchitecture *owner_;
};

#endif // FILES_EXPORTS_H
