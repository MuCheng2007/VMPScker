/**
 * Executable imports abstractions.
 * Rust mapping target: mod imports
 */

#ifndef FILES_IMPORTS_H
#define FILES_IMPORTS_H

#include "../../runtime/common.h"
#include "../objects.h"
#include "types.h"

class MapFunction;
class Buffer;
class IArchitecture;
class IImport;
class IImportList;

class IImportFunction : public IObject
{
public:
	virtual uint64_t address() const = 0;
	virtual std::string name() const = 0;
	virtual std::string full_name() const = 0;
	virtual APIType type() const = 0;
	virtual uint32_t options() const = 0;
	virtual CompilationType compilation_type() const = 0;
	virtual MapFunction *map_function() const = 0;
	virtual void set_map_function(MapFunction *map_function) = 0;
	virtual void set_type(APIType type) = 0;
	virtual void include_option(ImportOption option) = 0;
	virtual void exclude_option(ImportOption option) = 0;
	virtual IImport *owner() const = 0;
	virtual IImportFunction *Clone(IImport *owner) const = 0;
	virtual uint32_t GetRuntimeOptions() const = 0;
	virtual uint32_t GetSDKOptions() const = 0;
	virtual void Rebase(uint64_t delta_base) = 0;
	virtual std::string display_name(bool show_ret = true) const = 0;
	virtual OperandSize address_size() const = 0;
};

class IImport : public ObjectList<IImportFunction>
{
public:
	virtual std::string name() const = 0;
	virtual bool is_sdk() const = 0;
	virtual IImportFunction *GetFunctionByAddress(uint64_t address) const = 0;
	virtual uint32_t GetRuntimeOptions() const = 0;
	virtual uint32_t GetSDKOptions() const = 0;
	virtual void Rebase(uint64_t delta_base) = 0;
	virtual	IImportFunction *Add(uint64_t address, APIType type, MapFunction *map_function) = 0;
	virtual	bool CompareName(const std::string &name) const = 0;
	virtual IImport *Clone(IImportList *owner) const = 0;
	virtual IImportList *owner() const = 0;
	virtual bool excluded_from_import_protection() const = 0;
	virtual void set_excluded_from_import_protection(bool value) = 0;
	virtual Data hash() const = 0;
};

class IImportList : public ObjectList<IImport>
{
public:
	virtual IImportFunction *GetFunctionByAddress(uint64_t address) const = 0;
	virtual uint32_t GetRuntimeOptions() const = 0;
	virtual uint32_t GetSDKOptions() const = 0;
	virtual void ReadFromBuffer(Buffer &buffer, IArchitecture &file) = 0;
	virtual void Rebase(uint64_t delta_base) = 0;
	virtual bool has_sdk() const = 0;
	virtual IImport *GetImportByName(const std::string &name) const = 0;
	virtual const ImportInfo *GetSDKInfo(const std::string &name) const = 0;
	virtual IArchitecture *owner() const = 0;
protected:
	virtual IImport *AddSDK() = 0;
};

class BaseImportFunction : public IImportFunction
{
public:
	explicit BaseImportFunction(IImport *owner);
	explicit BaseImportFunction(IImport *owner, const BaseImportFunction &src); 
	~BaseImportFunction();
	virtual IImport *owner() const { return owner_; }
	void set_owner(IImport *value);
	virtual APIType type() const { return type_; }
	virtual void set_type(APIType type) { type_ = type; }
	virtual uint32_t GetRuntimeOptions() const;
	virtual uint32_t GetSDKOptions() const;
	virtual MapFunction *map_function() const { return map_function_; }
	virtual void set_map_function(MapFunction *map_function) { map_function_ = map_function; }
	virtual CompilationType compilation_type() const { return compilation_type_; }
	virtual void set_compilation_type(CompilationType compilation_type) { compilation_type_ = compilation_type; }
	virtual uint32_t options() const { return options_; }
	virtual void include_option(ImportOption option) { options_ |= option; }
	virtual void exclude_option(ImportOption option) { options_ &= ~option; }
	virtual std::string full_name() const;
	virtual OperandSize address_size() const;
private:
	IImport *owner_;
	APIType type_;
	MapFunction *map_function_;
	CompilationType compilation_type_;
	uint32_t options_;
};

class BaseImport : public IImport
{
public:
	explicit BaseImport(IImportList *owner);
	explicit BaseImport(IImportList *owner, const BaseImport &src);
	~BaseImport();
	virtual void clear();
	virtual IImportFunction *GetFunctionByAddress(uint64_t address) const;
	virtual uint32_t GetRuntimeOptions() const;
	virtual uint32_t GetSDKOptions() const;
	virtual void Rebase(uint64_t delta_base);
	virtual bool CompareName(const std::string &name) const;
	virtual void AddObject(IImportFunction *obj);
	virtual IImportList *owner() const { return owner_; }
	virtual bool excluded_from_import_protection() const { return excluded_from_import_protection_; };
	virtual void set_excluded_from_import_protection(bool value);
	virtual Data hash() const;
private:
	IImportList *owner_;
	std::map<uint64_t, IImportFunction *> map_;
	bool excluded_from_import_protection_;
};

class BaseImportList : public IImportList
{
public:
	explicit BaseImportList(IArchitecture *owner);
	explicit BaseImportList(IArchitecture *owner, const BaseImportList &src);
	virtual IImportFunction *GetFunctionByAddress(uint64_t address) const;
	virtual uint32_t GetRuntimeOptions() const;
	virtual uint32_t GetSDKOptions() const;
	virtual void ReadFromBuffer(Buffer &buffer, IArchitecture &file);
	virtual void Rebase(uint64_t delta_base);
	virtual bool has_sdk() const;
	virtual IImport *GetImportByName(const std::string &name) const;
	virtual const ImportInfo *GetSDKInfo(const std::string &name) const;
	virtual IArchitecture *owner() const { return owner_; }
private:
	IArchitecture *owner_;
};

#endif // FILES_IMPORTS_H
