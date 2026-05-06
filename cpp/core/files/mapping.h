#ifndef FILES_MAPPING_H
#define FILES_MAPPING_H

#include "../../runtime/common.h"
#include "../objects.h"
#include "types.h"
#include "utils.h"
#include "references.h"

class IArchitecture;
class IFile;
class Buffer;

// ---------------------------------------------------------------------------
// MapFunctionHash: key for address/name-keyed maps
// ---------------------------------------------------------------------------

struct MapFunctionHash {
	std::string name;
	ObjectType type;
	MapFunctionHash(ObjectType type_, const std::string &name_) : type(type_), name(name_) {}
	bool operator < (const MapFunctionHash &hash) const
	{
		int res = name.compare(hash.name);
		return (res != 0) ? (res < 0) : (type < hash.type);
	}
};

// ---------------------------------------------------------------------------
// MapFunction: one mapped symbol (code, data, import, export, string...)
// Rust mapping: struct MapFunction
// ---------------------------------------------------------------------------

class MapFunctionList;

class MapFunction : public IObject
{
public:
	explicit MapFunction(MapFunctionList *owner, uint64_t address, ObjectType type, const FunctionName &name);
	explicit MapFunction(MapFunctionList *owner, const MapFunction &src);
	virtual ~MapFunction();
	virtual MapFunction *Clone(MapFunctionList *owner) const;
	uint64_t address() const { return address_; }
	ObjectType type() const { return type_; }
	std::string name() const { return name_.name(); }
	std::string display_name(bool show_ret = false) const { return name_.display_name(show_ret); }
	uint64_t end_address() const { return end_address_; }
	uint64_t name_address() const { return name_address_; }
	size_t name_length() const { return name_length_; }
	ReferenceList *reference_list() const { return reference_list_; }
	ReferenceList *equal_address_list() const { return equal_address_list_; }
	CompilationType compilation_type() const { return compilation_type_; }
	bool lock_to_key() const { return lock_to_key_; }
	void set_type(ObjectType type) { type_ = type; }
	void set_end_address(uint64_t end_address) { end_address_ = end_address; }
	void set_name(const FunctionName &name);
	void set_name_address(uint64_t name_address) { name_address_ = name_address; }
	void set_name_length(size_t name_length) { name_length_ = name_length; }
	void set_compilation_type(CompilationType compilation_type) { compilation_type_ = compilation_type; }
	void set_lock_to_key(bool lock_to_key) { lock_to_key_ = lock_to_key; }
	void Rebase(uint64_t delta_base);
	std::string display_address(const std::string &arch_name) const;
	MapFunctionList *owner() const { return owner_; }
	MapFunctionHash hash() const;
	FunctionName full_name() const { return name_; }
	bool is_code() const;
	bool strings_protection() const { return strings_protection_; }
	void set_strings_protection(bool value) { strings_protection_ = value; }
private:
	MapFunctionList *owner_;
	uint64_t address_;
	ObjectType type_;
	FunctionName name_;
	uint64_t end_address_;
	ReferenceList *reference_list_;
	ReferenceList *equal_address_list_;
	uint64_t name_address_;
	size_t name_length_;
	CompilationType compilation_type_;
	bool lock_to_key_;
	bool strings_protection_;

	// no copy ctr or assignment op
	MapFunction(const MapFunction &);
	MapFunction &operator =(const MapFunction &);
};

// ---------------------------------------------------------------------------
// MapFunctionList: all mapped symbols for one architecture
// Rust mapping: struct MapFunctionList
// ---------------------------------------------------------------------------

class MapFunctionList : public ObjectList<MapFunction>
{
public:
	explicit MapFunctionList(IArchitecture *owner);
	explicit MapFunctionList(IArchitecture *owner, const MapFunctionList &src);
	virtual void clear();
	void RemoveObject(MapFunction *func);
	virtual MapFunctionList *Clone(IArchitecture *owner) const;
	void ReadFromFile(IArchitecture &file);
	MapFunction *GetFunctionByAddress(uint64_t address) const;
	MapFunction *GetFunctionByName(const std::string &name) const;
	std::vector<uint64_t> GetAddressListByName(const std::string &name, bool code_only) const;
	MapFunction *Add(uint64_t address, uint64_t end_address, ObjectType type, const FunctionName &name);
	void Rebase(uint64_t delta_base);
	void ReadFromBuffer(Buffer &buffer, IArchitecture &file);
	virtual void AddObject(MapFunction *func);
	IArchitecture *owner() const { return owner_; }
private:
	IArchitecture *owner_;
	std::map<uint64_t, MapFunction*> address_map_;
	std::map<std::string, std::vector<MapFunction*> > name_map_;
};

// ---------------------------------------------------------------------------
// Map file: parsed linker .map symbol file
// ---------------------------------------------------------------------------

class MapSection;

class MapObject : public IObject
{
public:
	explicit MapObject(MapSection *owner, size_t segment, uint64_t address, uint64_t size, const std::string &name);
	virtual ~MapObject();
	size_t segment() const { return segment_; }
	uint64_t address() const { return address_; }
	uint64_t size() const { return size_; }
	std::string name() const { return name_; }
private:
	MapSection *owner_;
	size_t segment_;
	uint64_t address_;
	uint64_t size_;
	std::string name_;
};

// MapSectionType -> files/types.h

class IMapFile;

class MapSection : public ObjectList<MapObject>
{
public:
	explicit MapSection(IMapFile *owner, MapSectionType type);
	virtual ~MapSection();
	MapSectionType type() const { return type_; }
	void Add(size_t segment, uint64_t address, uint64_t size, const std::string &name);
private:
	IMapFile *owner_;
	MapSectionType type_;
};

class IMapFile : public ObjectList<MapSection>
{
public:
	virtual MapSection *GetSectionByType(MapSectionType type) const = 0;
	virtual bool Parse(const char *file_name, const std::vector<uint64_t> &segments) = 0;
	virtual std::string file_name() const = 0;
	virtual uint64_t time_stamp() const = 0;
};

class BaseMapFile : public IMapFile
{
public:
	explicit BaseMapFile();
	virtual MapSection *GetSectionByType(MapSectionType type) const;
protected:
	MapSection *Add(MapSectionType type);
};

class MapFile : public BaseMapFile
{
public:
	explicit MapFile();
	virtual bool Parse(const char *file_name, const std::vector<uint64_t> &segments);
	virtual std::string file_name() const { return file_name_; }
	virtual uint64_t time_stamp() const { return time_stamp_; }
protected:
	void set_time_stamp(uint64_t value) { time_stamp_ = value; }
private:
	std::string file_name_;
	uint64_t time_stamp_;
};

// ---------------------------------------------------------------------------
// MapFunctionBundle: multi-arch grouping of the same MapFunction by name
// Rust mapping: struct MapFunctionBundle
// ---------------------------------------------------------------------------

class MapFunctionBundle;
class MapFunctionBundleList;

class MapFunctionArch : public IObject
{
public:
	explicit MapFunctionArch(MapFunctionBundle *owner, IArchitecture *arch, MapFunction *func);
	~MapFunctionArch();
	IArchitecture *arch() const { return arch_; }
	MapFunction *func() const { return func_; }
private:
	MapFunctionBundle *owner_;
	IArchitecture *arch_;
	MapFunction *func_;
};

class MapFunctionBundle : public ObjectList<MapFunctionArch>
{
public:
	explicit MapFunctionBundle(MapFunctionBundleList *owner, ObjectType type, const FunctionName &name);
	~MapFunctionBundle();
	MapFunctionArch *Add(IArchitecture *arch, MapFunction *func);
	MapFunctionHash hash() const { return MapFunctionHash(type_, name_.name()); }
	ObjectType type() const { return type_; }
	std::string name() const { return name_.name(); }
	std::string display_name(bool show_ret = true) const { return name_.display_name(show_ret); }
	MapFunction *GetFunctionByArch(IArchitecture *arch) const;
	bool is_code() const;
	std::string display_address() const;
	MapFunctionBundleList *owner() const { return owner_; }
	FunctionName full_name() const { return name_; }
private:
	MapFunctionBundleList *owner_;
	ObjectType type_;
	FunctionName name_;
};

class MapFunctionBundleList : public ObjectList<MapFunctionBundle>
{
public:
	explicit MapFunctionBundleList(IFile *owner);
	void ReadFromFile(IFile &file);
	virtual void AddObject(MapFunctionBundle *info);
	MapFunctionBundle *GetFunctionByAddress(IArchitecture *arch, uint64_t address) const;
	bool show_arch_name() const { return show_arch_name_; }
	void set_show_arch_name(bool show_arch_name) { show_arch_name_ = show_arch_name; }
	IFile *owner() const { return owner_; }
	MapFunctionBundle *Add(IArchitecture *arch, MapFunction *func);
private:
	MapFunctionBundle *GetFunctionByHash(const MapFunctionHash &hash) const;
	IFile *owner_;
	std::map<MapFunctionHash, MapFunctionBundle *> map_;
	bool show_arch_name_;
};

#endif
