/**
 * PE SEH Handler support.
 */

#ifndef PE_SEH_HANDLER_H
#define PE_SEH_HANDLER_H

#include "../files.h"

class PEArchitecture;
class PEDirectory;
class PESEHandlerList;
class PELoadConfigDirectory;

class PESEHandler : public BaseSEHandler
{
public:
	explicit PESEHandler(ISEHandlerList *owner, uint64_t address);
	explicit PESEHandler(ISEHandlerList *owner, const PESEHandler &src);
	virtual PESEHandler *Clone(ISEHandlerList *owner) const;
	virtual uint64_t address() const { return address_; }
	virtual void set_address(uint64_t address) { address_ = address; }
	virtual bool is_deleted() const { return deleted_; }
	virtual void set_deleted(bool deleted) { deleted_ = deleted; }
	void Rebase(uint64_t delta_base);
private:
	uint64_t address_;
	bool deleted_;
};

class PESEHandlerList : public BaseSEHandlerList
{
public:
	explicit PESEHandlerList();
	explicit PESEHandlerList(const PESEHandlerList &src);
	virtual PESEHandlerList *Clone() const;
	PESEHandler *item(size_t index) const;
	virtual PESEHandler *Add(uint64_t address);
	void Rebase(uint64_t delta_base);
	void Pack();
};

class PECFGAddressTable;

class PECFGAddress : public IObject
{
public:
	explicit PECFGAddress(PECFGAddressTable *owner, uint64_t address);
	explicit PECFGAddress(PECFGAddressTable *owner, const PECFGAddress &src);
	~PECFGAddress();
	PECFGAddress *Clone(PECFGAddressTable *owner) const;
	void Rebase(uint64_t delta_base);
	uint64_t address() const { return address_; }
	void set_data(std::vector<uint8_t> value) { data_ = value; }
	std::vector<uint8_t> data() const { return data_; }
private:
	PECFGAddressTable *owner_;
	uint64_t address_;
	std::vector<uint8_t> data_;
};

class PECFGAddressTable : public ObjectList<PECFGAddress>
{
public:
	explicit PECFGAddressTable();
	explicit PECFGAddressTable(const PECFGAddressTable &src);
	PECFGAddressTable *Clone() const;
	PECFGAddress *Add(uint64_t address);
	void Rebase(uint64_t delta_base);
};

class PELoadConfigDirectory : public IObject
{
public:
	explicit PELoadConfigDirectory();
	explicit PELoadConfigDirectory(const PELoadConfigDirectory &src);
	~PELoadConfigDirectory();
	virtual PELoadConfigDirectory *Clone() const;
	void ReadFromFile(PEArchitecture &file, PEDirectory &dir);
	size_t WriteToFile(PEArchitecture &file);
	void FreeByManager(MemoryManager &manager);
	void Rebase(uint64_t delta_base);
	uint64_t security_cookie() const { return security_cookie_; }
	void set_security_cookie(uint64_t value) { security_cookie_ = value; }
	uint64_t cfg_check_function() const { return cfg_check_function_; }
	void set_cfg_check_function(uint64_t value) { cfg_check_function_ = value; }
	PESEHandlerList *seh_handler_list() const { return seh_handler_list_; }
	PECFGAddressTable *cfg_address_list() const { return cfg_address_list_; }
	uint64_t seh_table_address() const { return seh_table_address_; }
	uint64_t cfg_table_address() const { return cfg_table_address_; }
private:
	uint64_t seh_table_address_;
	uint64_t security_cookie_;
	uint64_t cfg_table_address_;
	uint64_t cfg_check_function_;
	uint32_t guard_flags_;
	PESEHandlerList *seh_handler_list_;
	PECFGAddressTable *cfg_address_list_;

	// no assignment op
	PELoadConfigDirectory &operator =(const PELoadConfigDirectory &);
};

#endif // PE_SEH_HANDLER_H
