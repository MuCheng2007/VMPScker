#ifndef CORE_H
#define CORE_H

#include "../../runtime/common.h"


class WatermarkManager;
class ProjectTemplateManager;
class LicensingManager;
class FileManager;
class Watermark;
class ProjectTemplate;

enum ProjectOption {
	cpDebugMode             = 0x00000002,
	cpCryptValues           = 0x00000008,
	cpIncludeWatermark      = 0x00000020,
	cpRunnerCRC             = 0x00000040,
	cpEncryptRegs           = 0x00000080,
	cpStripFixups           = 0x00008000,
	cpPack                  = 0x00000100,
	cpImportProtection      = 0x00000200,
	cpCheckDebugger			= 0x00000400,
	cpCheckVirtualMachine	= 0x00000800,
	cpMemoryProtection      = 0x00001000,
	cpResourceProtection    = 0x00010000,
	cpCheckKernelDebugger	= 0x00020000,
	cpStripDebugInfo		= 0x00040000,
	cpClassicVM             = 0x00080000, 

	cpLoaderCRC				= 0x10000000,

	cpEncryptBytecode       = 0x80000000,
	cpVirtualFiles			= 0x08000000,
	cpInternalMemoryProtection = 0x04000000,
	cpLoader				= 0x02000000,
	cpMaximumProtection     = cpCryptValues | cpRunnerCRC | cpEncryptRegs | cpStripDebugInfo,
	cpUserOptionsMask       = 0x00FFFFFF
};

std::string VectorToBase64(const std::vector<uint8_t> &src);

static const VMP_CHAR *default_message[MESSAGE_COUNT] = 
{
	MESSAGE_DEBUGGER_FOUND_STR,
	MESSAGE_VIRTUAL_MACHINE_FOUND_STR,
	MESSAGE_FILE_CORRUPTED_STR,
	MESSAGE_SERIAL_NUMBER_REQUIRED_STR,
	MESSAGE_HWID_MISMATCHED_STR
};

enum VMProtectProductId
{
	VPI_NOT_SPECIFIED,		//0 legacy
	VPI_LITE_WIN_PERSONAL,	//1 VMProtect Lite for Windows (Personal License)
	VPI_LITE_WIN_COMPANY,	//2 VMProtect Lite for Windows (Company License)
	VPI_PROF_WIN_PERSONAL,	//3 VMProtect Professional for Windows (Personal License)
	VPI_PROF_WIN_COMPANY,	//4 VMProtect Professional for Windows (Company License)
	VPI_ULTM_WIN_PERSONAL,	//5 VMProtect Ultimate for Windows (Personal License)
	VPI_ULTM_WIN_COMPANY,	//6 VMProtect Ultimate for Windows (Company License)
	VPI_LITE_OSX_PERSONAL,	//7 VMProtect Lite for Mac OS X (Personal License)
	VPI_LITE_OSX_COMPANY,	//8 VMProtect Lite for Mac OS X (Company License)
	VPI_PROF_OSX_PERSONAL,	//9 VMProtect Professional for Mac OS X (Personal License)
	VPI_PROF_OSX_COMPANY,	//10 VMProtect Professional for Mac OS X (Company License)
	VPI_ULTM_OSX_PERSONAL,	//11 VMProtect Ultimate for Mac OS X (Personal License)
	VPI_ULTM_OSX_COMPANY,	//12 VMProtect Ultimate for Mac OS X (Company License)
	VPI_WLM_PERSONAL,		//13 VMProtect Web License Manager (Personal License)
	VPI_WLM_COMPANY,		//14 VMProtect Web License Manager (Company License)
	VPI_YEAR_PESONAL,		//15 Yearly Subscription Plan (Personal License)
	VPI_YEAR_COMPANY,		//16 Yearly Subscription Plan (Company License)
	VPI_SENS_WIN_PERSONAL,	//17 VMProtect SE for Windows (Personal License)
	VPI_SENS_WIN_COMPANY,	//18 VMProtect SE for Windows (Company License)
	VPI_LITE_LIN_PERSONAL,	//19 VMProtect Lite for Linux (Personal License)
	VPI_LITE_LIN_COMPANY,	//20 VMProtect Lite for Linux (Company License)
	VPI_PROF_LIN_PERSONAL,	//21 VMProtect Professional for Linux (Personal License)
	VPI_PROF_LIN_COMPANY,	//22 VMProtect Professional for Linux (Company License)
	VPI_ULTM_LIN_PERSONAL,	//23 VMProtect Ultimate for Linux (Personal License)
	VPI_ULTM_LIN_COMPANY,	//24 VMProtect Ultimate for Linux (Company License)
	VPI_LITE_PERSONAL = VPI_LITE_WIN_PERSONAL,
	VPI_LITE_COMPANY = VPI_LITE_WIN_COMPANY,
	VPI_PROF_PERSONAL = VPI_PROF_WIN_PERSONAL,
	VPI_PROF_COMPANY = VPI_PROF_WIN_COMPANY,
	VPI_ULTM_PERSONAL = VPI_ULTM_WIN_PERSONAL,
	VPI_ULTM_COMPANY = VPI_ULTM_WIN_COMPANY,
};

#define EDITION "Ultimate"

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define STR_HELPERW(x) L ## #x
#define STRW(x) STR_HELPERW(x)
#define STR_HELPERWQ(x) L ## x
#define STRWQ(x) STR_HELPERWQ(x)


class ILog;
class IFile;
class IArchitecture;

class Core : public IObject
{
public:
	explicit Core(ILog *log = NULL);
	virtual ~Core();
	bool Open(const std::string &file_name, const std::string &user_project_file_name = "", const std::string &user_licensing_params_file_name = "");
	bool Save();
	bool SaveAs(const std::string &file_name);
	void Close();
	bool Compile();

	uint32_t options() const { return options_; }
	std::string vm_section_name() const { return vm_section_name_; }
	std::string watermark_name() const { return watermark_name_; }
	IFile *input_file() const { return input_file_; }
	IFile *output_file() const { return output_file_; }
	ILog *log() const  { return log_; }
	std::string input_file_name() const { return input_file_name_; }
	std::string output_file_name() const { return output_file_name_; }
	void set_options(uint32_t options);
	void include_option(ProjectOption option);
	void exclude_option(ProjectOption option);
	void set_vm_section_name(const std::string &vm_section_name);
	void set_watermark_name(const std::string &watermark_name);
	void set_output_file_name(const std::string &output_file_name);
	std::string message(size_t type) const { return messages_[type]; }
	void set_message(size_t type, const std::string &message);
	std::string hwid() const { return hwid_; }
	void set_hwid(const std::string &hwid);
	LicensingManager *licensing_manager() const { return licensing_manager_; }
	FileManager *file_manager() const { return file_manager_; }
	std::string license_data_file_name() const { return license_data_file_name_; }
	void set_license_data_file_name(const std::string &license_data_file_name);
	std::string activation_server() const;
	void set_activation_server(const std::string &activation_server);
	std::string default_license_data_file_name() const;
	std::string project_path() const;
	void Notify(MessageType type, IObject *sender, const std::string &message = "");
	std::string absolute_output_file_name() const;
	std::string project_file_name() const { return project_file_name_; }
	WatermarkManager *watermark_manager() const { return watermark_manager_; }
	ProjectTemplateManager *template_manager() const { return template_manager_; }

	static const char *copyright() { return "Copyright 2003-2021 VMProtect Software"; }
	static const char *edition() { return "VMProtect " EDITION; }
	static const char *version();
	static const char *build();
	static bool check_license_edition(const VMProtectSerialNumberData &lic);
	IArchitecture *input_architecture() const;
	IArchitecture *output_architecture() const { return output_architecture_; }
	void LoadFromTemplate(const ProjectTemplate &pt);
	void SaveToTemplate(ProjectTemplate &pt);
private:
	HANDLE BeginCompileTransaction();
	void EndCompileTransaction(HANDLE locked_file, bool commit);
	bool LoadFromXML(const char *project_file_name);
	bool LoadFromIni(const char *project_file_name);
	void LoadDefaultFunctions();
	std::string default_output_file_name() const;

	std::string project_file_name_;
	bool modified_;
	IFile *input_file_;
	std::string input_file_name_;
	uint32_t options_;
	uint32_t vm_options_;
	std::string vm_section_name_;
	ProjectTemplateManager *template_manager_;
	std::string output_file_name_;
	std::string watermark_name_;
	std::string messages_[MESSAGE_COUNT];
	IFile *output_file_;
	ILog *log_;
	Watermark *watermark_;
	WatermarkManager *watermark_manager_;

	IArchitecture *output_architecture_;
	std::string hwid_;
	std::string license_data_file_name_;
	LicensingManager *licensing_manager_;
	FileManager *file_manager_;

	// no copy ctr or assignment op
	Core(const Core &);
	Core &operator =(const Core &);
};

#endif
