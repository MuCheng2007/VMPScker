/**
 * PE File support.
 */

#ifndef PE_FILE_H
#define PE_FILE_H

#include "../files/architecture.h"
#include "PEArchitecture.h"

class PEFile : public IFile
{
public:
	explicit PEFile(ILog *log = NULL);
	explicit PEFile(const PEFile &src, const char *file_name);
	virtual ~PEFile();
	virtual std::string format_name() const;
	virtual PEFile *Clone(const char *file_name) const;
	virtual bool Compile(CompileOptions &options);
	virtual std::string version() const;
	virtual bool is_executable() const;
	virtual uint32_t disable_options() const;
	bool GetCheckSum(uint32_t *check_sum);
	PEArchitecture *arch_pe() const { return count() > 0 ? dynamic_cast<PEArchitecture *>(item(0)) : NULL; }
	virtual std::string exec_command() const;
protected:
	virtual OpenStatus ReadHeader(uint32_t open_mode);
	bool WriteHeader();
	virtual IFile *runtime() const { return runtime_; };
private:
	PEFile *runtime_;

	// no copy ctr or assignment op
	PEFile(const PEFile &);
	PEFile &operator =(const PEFile &);
};

#endif // PE_FILE_H
