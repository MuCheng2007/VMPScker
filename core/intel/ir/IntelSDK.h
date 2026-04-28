#ifndef INTEL_SDK_H
#define INTEL_SDK_H

#include "IntelFunction.h"
#include "../../files/utils.h"
#include "../../../runtime/crypto.h"

class IntelSDK : public IntelFunction
{
public:
	explicit IntelSDK(IFunctionList *owner, OperandSize cpu_address_size);
	virtual bool Init(const CompileContext &ctx);
};

class PEIntelSDK : public IntelSDK
{
public:
	explicit PEIntelSDK(IFunctionList *owner, OperandSize cpu_address_size);
	virtual bool Init(const CompileContext &ctx);
};

class MacIntelSDK : public IntelSDK
{
public:
	explicit MacIntelSDK(IFunctionList *owner, OperandSize cpu_address_size);
};

class ELFIntelSDK : public IntelSDK
{
public:
	explicit ELFIntelSDK(IFunctionList *owner, OperandSize cpu_address_size);
};

class PEIntelExport : public IntelFunction
{
public:
	explicit PEIntelExport(IFunctionList *owner, OperandSize cpu_address_size);
	virtual bool Init(const CompileContext &ctx);
	virtual bool Compile(const CompileContext &ctx);
	uint32_t size() const { return size_; }
private:
	uint32_t size_;
};

class PEImportFunction;
class IntelImport : public IntelFunction
{
public:
	explicit IntelImport(IFunctionList *owner, OperandSize cpu_address_size);
	bool Init(const CompileContext &ctx);
	IntelCommand *GetIATCommand(PEImportFunction *import_function) const;
private:
	struct IATInfo {
		PEImportFunction *import_function;
		IntelCommand *command;
		bool from_runtime;
	};
	std::vector<IATInfo> iat_info_list_;
};

class IntelCRCTable : public IntelFunction
{
public:
	explicit IntelCRCTable(IFunctionList *owner, OperandSize cpu_address_size);
	virtual bool Init(const CompileContext &ctx);
	size_t table_size() const { return (count() - 2) * OperandSizeToValue(osDWord); }
	IntelCommand *table_entry() const { return item(0); }
	IntelCommand *size_entry() const { return size_entry_; }
	IntelCommand *hash_entry() const { return hash_entry_; }
private:
	IntelCommand *size_entry_;
	IntelCommand *hash_entry_;
};

class IntelRuntimeData : public IntelFunction
{
public:
	explicit IntelRuntimeData(IFunctionList *owner, OperandSize cpu_address_size);
	virtual bool Init(const CompileContext &ctx);
	virtual size_t WriteToFile(IArchitecture &file);
private:
	RC5Key rc5_key_;
	uint32_t data_key_;
	IntelCommand *strings_entry_;
	uint32_t strings_size_;
	IntelCommand *resources_entry_;
	uint32_t resources_size_;
	IntelCommand *trial_hwid_entry_;
	uint32_t trial_hwid_size_;
	IntelCommand *license_data_entry_;
	uint32_t license_data_size_;
	IntelCommand *files_entry_;
	uint32_t files_size_;
	IntelCommand *registry_entry_;
	uint32_t registry_size_;

	struct CommandCompareHelper {
		bool operator () (const IntelCommand *left, IntelCommand *right) const;
	};
};

class IntelLoaderData : public IntelFunction
{
public:
	explicit IntelLoaderData(IFunctionList *owner, OperandSize cpu_address_size);
	bool Init(const CompileContext &ctx);
};

class IntelWatermark : public IntelFunction
{
public:
	explicit IntelWatermark(IFunctionList *owner, OperandSize cpu_address_size);
	bool Init(const CompileContext &ctx);
};

class IntelRuntimeCRCTable : public IntelFunction
{
public:
	explicit IntelRuntimeCRCTable(IFunctionList *owner, OperandSize cpu_address_size);
	virtual void clear();
	virtual bool Compile(const CompileContext &ctx);
	virtual size_t WriteToFile(IArchitecture &file);
	size_t region_count() const { return region_info_list_.size(); }
private:
	struct RegionInfo {
		uint64_t address;
		uint32_t size;
		bool is_self_crc;

		RegionInfo(uint64_t address_, uint32_t size_, bool is_self_crc_)
			: address(address_), size(size_), is_self_crc(is_self_crc_)
		{
		}
	};
	std::vector<RegionInfo> region_info_list_;
	ValueCryptor *cryptor_;
};

#endif // INTEL_SDK_H