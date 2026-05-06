/**
 * PE Export support.
 */

#ifndef PE_EXPORT_H
#define PE_EXPORT_H

#include "../files/exports.h"
#include "../files/memory.h"

class PEArchitecture;
class PEExportList;
class PEDirectory;

class PEExport : public BaseExport
{
public:
	explicit PEExport(PEExportList *owner, uint64_t address, uint32_t ordinal);
	explicit PEExport(PEExportList *owner, const PEExport &src);
	virtual uint64_t address() const { return address_; }
	virtual std::string name() const { return name_; }
	virtual std::string forwarded_name() const { return forwarded_name_; }
	virtual std::string display_name(bool show_ret = true) const;
	uint32_t ordinal() const { return ordinal_; }
	void set_name(const std::string &name) { name_ = name; }
	void set_forwarded_name(const std::string &forwarded_name) { forwarded_name_ = forwarded_name; }
	virtual PEExport *Clone(IExportList *owner) const;
	/*virtual*/ int CompareWith(const IObject &obj) const;
	void FreeByManager(MemoryManager &manager);
	void ReadFromFile(PEArchitecture &file, uint64_t address_of_name, bool is_forwarded);
	virtual void Rebase(uint64_t delta_base);
private:
	uint64_t address_;
	uint32_t ordinal_;
	uint64_t address_of_name_;
	std::string name_;
	std::string forwarded_name_;
};

class PEExportList : public BaseExportList
{
public:
	explicit PEExportList(PEArchitecture *owner);
	explicit PEExportList(PEArchitecture *owner, const PEExportList &src);
	virtual PEExportList *Clone(PEArchitecture *owner) const;
	virtual std::string name() const { return name_; }
	void set_name(const std::string &name) { name_ = name; }
	uint32_t characteristics() const { return characteristics_; }
	uint32_t time_date_stamp() const { return time_date_stamp_; }
	uint16_t major_version() const { return major_version_; }
	uint16_t minor_version() const { return minor_version_; }
	PEExport *item(size_t index) const;
	void ReadFromFile(PEArchitecture &arch, PEDirectory &dir);
	void FreeByManager(MemoryManager &manager);
	virtual void ReadFromBuffer(Buffer &buffer, IArchitecture &file);
	uint32_t WriteToData(IFunction &data, uint64_t image_base);
	void AddAntidebug();
protected:
	virtual PEExport *Add(uint64_t address) { return Add(address, 0); }
private:
	PEExport *Add(uint64_t address, uint32_t ordinal);
	PEExport *GetExportByOrdinal(uint32_t ordinal);

	uint64_t address_;
	uint64_t name_address_;
	uint32_t characteristics_;
	uint32_t time_date_stamp_;
	uint16_t major_version_;
	uint16_t minor_version_;
	std::string name_;
	uint32_t number_of_functions_;
	uint64_t address_of_functions_;
	uint32_t number_of_names_;
	uint64_t address_of_names_;
	uint64_t address_of_name_ordinals_;

	struct NameInfo {
		uint32_t ordinal_index;
		uint32_t address_of_name;
		bool operator == (uint16_t ordinal_index_) const
		{
			return (ordinal_index == ordinal_index_);
		}
	};

	struct ExportInfo {
		PEExport *export_function;
		ExportInfo(PEExport *export_function_) : export_function(export_function_) {}
		bool operator< (const ExportInfo &obj) const
		{
			return (export_function->name().compare(obj.export_function->name()) < 0);
		}
	};

};

#endif // PE_EXPORT_H
