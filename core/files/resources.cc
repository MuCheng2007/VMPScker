/**
 * Executable resources implementations.
 * Rust mapping target: mod resources
 */

#include "resources.h"
#include "../files.h"

/**
 * BaseResource
 */

BaseResource::BaseResource(IResource *owner)
	: IResource(), owner_(owner), excluded_from_packing_(false)
{

}

BaseResource::BaseResource(IResource *owner, const BaseResource &src)
	: IResource(src), owner_(owner)
{
	excluded_from_packing_ = src.excluded_from_packing_;
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

BaseResource::~BaseResource()
{
	if (owner_)
		owner_->RemoveObject(this);
}

IResource *BaseResource::GetResourceByName(const std::string &name) const
{
	for (size_t i = 0; i < count(); i++) {
		IResource *resource = item(i);
		if (resource->name() == name)
			return resource;
	}
	return NULL;
}

IResource *BaseResource::GetResourceByType(uint32_t type) const
{
	for (size_t i = 0; i < count(); i++) {
		IResource *resource = item(i);
		if (resource->type() == type)
			return resource;
	}
	return NULL;
}

IResource *BaseResource::GetResourceById(const std::string &id) const
{
	if (this->id() == id)
		return (IResource *)this;
	for (size_t i = 0; i < count(); i++) {
		IResource *res = item(i)->GetResourceById(id);
		if (res)
			return res;
	}
	return NULL;
}

void BaseResource::set_excluded_from_packing(bool value)
{
	if (excluded_from_packing_ != value) {
		excluded_from_packing_ = value;
		Notify(mtChanged, this);
	}
}

void BaseResource::Notify(MessageType type, IObject *sender, const std::string &message) const
{
	if (owner_)
		owner_->Notify(type, sender, message);
}

OperandSize BaseResource::address_size() const
{
	return owner()->address_size();
}

Data BaseResource::hash() const
{
	Data res;
	res.PushBuff(name().c_str(), name().size() + 1);
	res.PushByte(excluded_from_packing());
	return res;
}

/**
 * BaseResourceList
 */

BaseResourceList::BaseResourceList(IArchitecture *owner)
	: IResourceList(), owner_(owner)
{

}

BaseResourceList::BaseResourceList(IArchitecture *owner, const BaseResourceList &src)
	: IResourceList(), owner_(owner)
{
	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

IResource *BaseResourceList::GetResourceByName(const std::string &name) const
{
	for (size_t i = 0; i < count(); i++) {
		IResource *resource = item(i);
		if (resource->name() == name)
			return resource;
	}
	return NULL;
}

IResource *BaseResourceList::GetResourceByType(uint32_t type) const
{
	for (size_t i = 0; i < count(); i++) {
		IResource *resource = item(i);
		if (resource->type() == type)
			return resource;
	}
	return NULL;
}

IResource *BaseResourceList::GetResourceById(const std::string &id) const
{
	for (size_t i = 0; i < count(); i++) {
		IResource *res = item(i)->GetResourceById(id);
		if (res)
			return res;
	}
	return NULL;
}

std::vector<IResource*> BaseResourceList::GetResourceList() const
{
	std::vector<IResource*> res;
	size_t i, j;

	for (i = 0; i < count(); i++) {
		res.push_back(item(i));
	}
	for (i = 0; i < res.size(); i++) {
		IResource *resource = res[i];
		for (j = 0; j < resource->count(); j++) {
			res.push_back(resource->item(j));
		}
	}
	return res;
}

OperandSize BaseResourceList::address_size() const
{
	return owner_->cpu_address_size();
}

void BaseResourceList::Notify(MessageType type, IObject *sender, const std::string &message) const
{
	if (owner_)
		owner_->Notify(type, sender, message);
}
