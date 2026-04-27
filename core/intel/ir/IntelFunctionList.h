#ifndef INTEL_FUNCTION_LIST_H
#define INTEL_FUNCTION_LIST_H

#include "../../processors.h"
#include "IntelFunction.h"
#include "IntelSDK.h"

class IArchitecture;
class IntelImport;
class IntelCRCTable;
class IntelLoaderData;
class IntelRuntimeCRCTable;
class IntelVirtualMachineProcessor;
class Watermark;
class MacImportFunction;
struct CompileContext;

class IntelFunctionList : public BaseFunctionList
{
public:
	explicit IntelFunctionList(IArchitecture *owner);
	explicit IntelFunctionList(IArchitecture *owner, const IntelFunctionList &src);
	~IntelFunctionList();
	virtual IntelFunctionList *Clone(IArchitecture *owner) const;
	virtual IntelFunction *Add(const std::string &name, CompilationType compilation_type, uint32_t compilation_options, bool need_compile, Folder *folder);
	IntelFunction *item(size_t index) const;
	IntelFunction *GetFunctionByAddress(uint64_t address) const;
	virtual bool Prepare(const CompileContext &ctx);
	virtual void CompileLinks(const CompileContext &ctx);
	IntelImport *import() const { return import_; }
	virtual IntelCRCTable *crc_table() const { return crc_table_; }
	IntelLoaderData *loader_data() const { return loader_data_; }
	IntelRuntimeCRCTable *runtime_crc_table() const { return runtime_crc_table_; }
	virtual void ReadFromBuffer(Buffer &buffer, IArchitecture &file);
	virtual ValueCryptor *crc_cryptor() const { return crc_cryptor_; }
	virtual IntelFunction *CreateFunction(OperandSize cpu_address_size = osDefault);
	virtual bool GetRuntimeOptions() const;
	IntelVirtualMachineProcessor *AddProcessor(OperandSize cpu_address_size);
protected:
	virtual IntelSDK *AddSDK(OperandSize cpu_address_size);
private:
	IntelImport *AddImport(OperandSize cpu_address_size);
	IntelRuntimeData *AddRuntimeData(OperandSize cpu_address_size);
	IntelCRCTable *AddCRCTable(OperandSize cpu_address_size);
	IntelLoaderData *AddLoaderData(OperandSize cpu_address_size);
	IntelFunction *AddWatermark(OperandSize cpu_address_size, Watermark *watermark, int copy_count);
	IntelRuntimeCRCTable *AddRuntimeCRCTable(OperandSize cpu_address_size);

	ValueCryptor *crc_cryptor_;
	IntelImport *import_;
	IntelCRCTable *crc_table_;
	IntelLoaderData *loader_data_;
	IntelRuntimeCRCTable *runtime_crc_table_;

	// no copy ctr or assignment op
	IntelFunctionList(const IntelFunctionList &);
	IntelFunctionList &operator =(const IntelFunctionList &);
};

class PEIntelFunctionList : public IntelFunctionList
{
public:
	explicit PEIntelFunctionList(IArchitecture *owner);
	explicit PEIntelFunctionList(IArchitecture *owner, const PEIntelFunctionList &src);
	virtual PEIntelFunctionList *Clone(IArchitecture *owner) const;
	virtual bool Prepare(const CompileContext &ctx);
	PEIntelExport *AddExport(OperandSize cpu_address_size);
	virtual void ReadFromBuffer(Buffer &buffer, IArchitecture &file);
protected:
	virtual IntelSDK *AddSDK(OperandSize cpu_address_size);
};

class MacIntelFunctionList : public IntelFunctionList
{
public:
	explicit MacIntelFunctionList(IArchitecture *owner);
	explicit MacIntelFunctionList(IArchitecture *owner, const MacIntelFunctionList &src);
	virtual MacIntelFunctionList *Clone(IArchitecture *owner) const;
	virtual bool Prepare(const CompileContext &ctx);
	virtual bool Compile(const CompileContext &ctx);
protected:
	virtual IntelSDK *AddSDK(OperandSize cpu_address_size);
private:
	std::map<MacImportFunction *, IntelCommand *> relocation_list_;
};

class ELFIntelFunctionList : public IntelFunctionList
{
public:
	explicit ELFIntelFunctionList(IArchitecture *owner);
	explicit ELFIntelFunctionList(IArchitecture *owner, const ELFIntelFunctionList &src);
	virtual ELFIntelFunctionList *Clone(IArchitecture *owner) const;
	virtual void ReadFromBuffer(Buffer &buffer, IArchitecture &file);
protected:
	virtual IntelSDK *AddSDK(OperandSize cpu_address_size);
};

#endif // INTEL_FUNCTION_LIST_H