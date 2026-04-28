/**
 * Executable resources abstractions.
 * Rust mapping target: mod resources
 */

#ifndef FILES_RESOURCES_H
#define FILES_RESOURCES_H

#include "../../runtime/common.h"
#include "../objects.h"
#include "types.h"

class IArchitecture;

class IResource : public ObjectList<IResource>
{
public:
	virtual uint32_t type() const = 0;
	virtual uint64_t address() const = 0;
	virtual size_t size() const = 0;
	virtual std::string name() const = 0;
	virtual IResource *owner() const = 0;
	virtual bool is_directory() const = 0;
	virtual bool need_store() const = 0;
	virtual IResource *Clone(IResource *owner) const = 0;
	virtual IResource *GetResourceByName(const std::string &name) const = 0;
	virtual IResource *GetResourceByType(uint32_t type) const = 0;
	virtual IResource *GetResourceById(const std::string &id) const = 0;
	virtual bool excluded_from_packing() const = 0;
	virtual void set_excluded_from_packing(bool value) = 0;
	virtual OperandSize address_size() const = 0;
	virtual void Notify(MessageType type, IObject *sender, const std::string &message = "") const = 0;
	virtual std::string id() const = 0;
	virtual Data hash() const = 0;
};

class IResourceList : public IResource
{
public:
	virtual std::vector<IResource*> GetResourceList() const = 0;
};

class BaseResource : public IResource
{
public:
	explicit BaseResource(IResource *owner);
	explicit BaseResource(IResource *owner, const BaseResource &src);
	~BaseResource();
	virtual IResource *owner() const { return owner_; }
	virtual IResource *GetResourceByName(const std::string &name) const;
	virtual IResource *GetResourceByType(uint32_t type) const;
	virtual IResource *GetResourceById(const std::string &id) const;
	virtual bool excluded_from_packing() const { return excluded_from_packing_; }
	virtual void set_excluded_from_packing(bool value);
	virtual OperandSize address_size() const;
	virtual void Notify(MessageType type, IObject *sender, const std::string &message = "") const;
	virtual Data hash() const;
private:
	IResource *owner_;
	bool excluded_from_packing_;
};

class BaseResourceList : public IResourceList
{
public:
	explicit BaseResourceList(IArchitecture *owner);
	explicit BaseResourceList(IArchitecture *owner, const BaseResourceList &src);
	virtual uint32_t type() const { return (uint32_t)-1; }
	virtual uint64_t address() const { return 0; }
	virtual size_t size() const { return 0; }
	virtual std::string name() const { return std::string(); }
	virtual IResource *owner() const { return NULL; }
	virtual bool is_directory() const { return true; }
	virtual IResource *Clone(IResource * /*owner*/) const { return NULL; }
	virtual IResource *GetResourceByName(const std::string &name) const;
	virtual IResource *GetResourceByType(uint32_t type) const;
	virtual IResource *GetResourceById(const std::string &id) const;
	virtual bool excluded_from_packing() const { return false; }
	virtual void set_excluded_from_packing(bool /*value*/) { }
	virtual bool need_store() const { return true; }
	virtual std::vector<IResource*> GetResourceList() const;
	virtual std::string id() const { return std::string(); }
	virtual OperandSize address_size() const;
	virtual void Notify(MessageType type, IObject *sender, const std::string &message = "") const;
	virtual Data hash() const { return Data(); }
private:
	IArchitecture *owner_;
};

#endif // FILES_RESOURCES_H
