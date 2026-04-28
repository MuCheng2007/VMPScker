#include "../../runtime/crypto.h"

#include "../objects.h"
#include "../osutils.h"
#include "../streams.h"
#include "../files/architecture.h"
#include "../files/mapping.h"
#include "../files/utils.h"
#include "../processors.h"

#include "../pe/pefile.h"
#include "core.h"

#include "core_utils.h"

#include "license.h"

static std::string GetProjectFileName(std::string &exe_file_name)
{
	std::string file_name_new = exe_file_name + ".vmp";
	std::string file_name_old = os::ChangeFileExt(exe_file_name.c_str(), ".vmp");

	if (os::FileExists(file_name_new.c_str()) || !os::FileExists(file_name_old.c_str()))
		return file_name_new;

	return file_name_old;
}

Core::Core(ILog *log /*=NULL*/)
	: IObject(), log_(log), input_file_(NULL), output_file_(NULL), output_architecture_(NULL),
	options_(0), vm_options_(0)
{
	licensing_manager_ = new LicensingManager(this);
}

Core::~Core() 
{
	Close();

	delete licensing_manager_;
}

std::string Core::default_output_file_name() const
{
	std::string res = input_file_name_;
	std::string ext = os::ExtractFileExt(res.c_str());
	if (ext.empty())
		return res + "_vmp";

	return os::ChangeFileExt(res.c_str(), ".vmp") + ext;
}

std::string Core::default_license_data_file_name() const
{
	return os::ExtractFileName(project_file_name_.c_str());
}

bool Core::Open(const std::string &file_name, const std::string &user_project_file_name, const std::string &user_licensing_params_file_name)
{
	std::string exe_file_name;
	size_t i;

	Close();

	exe_file_name = file_name;
	project_file_name_ = (user_project_file_name.empty()) ? GetProjectFileName(exe_file_name) : user_project_file_name;


	if (!exe_file_name.empty()) {
		if (log_)
			log_->StartProgress(string_format("Loading %s...", os::ExtractFileName(exe_file_name.c_str()).c_str()), 1);

		std::auto_ptr<IFile> file[] = { std::auto_ptr<IFile>(new PEFile(log_))
		};
		std::string open_error;
		for (i = 0; i < _countof(file); i++) {
			open_error.clear();
			OpenStatus status = file[i]->Open(exe_file_name.c_str(), foRead | foCopyToTemp, &open_error);
			if (status == osSuccess) {
				IArchitecture *arch = file[i]->item(0);
				ISection *code_segment = NULL;
				for (size_t j = 0; j < arch->segment_list()->count(); j++) {
					ISection *segment = arch->segment_list()->item(j);
					if (segment->physical_size() && (segment->memory_type() & mtExecutable)) {
						code_segment = segment;
						break;
					}
				}
				if (!code_segment) {
					Notify(mtError, NULL, string_format("File \"%s\" has no code segment", exe_file_name.c_str())); 
					return false;
				}

				delete input_file_;
				input_file_ = file[i].release();
				break;
			} else {
				switch (status) {
				case osOpenError:
					Notify(mtError, NULL, string_format("Cannot open file \"%s\"", exe_file_name.c_str())); 
					break;
				case osInvalidFormat:
					Notify(mtError, NULL, string_format("File \"%s\" has incorrect format", exe_file_name.c_str()) + (!open_error.empty() ? ": " + open_error : ""));
					break;
				case osUnsupportedCPU:
					Notify(mtError, NULL, string_format("File \"%s\" has unsupported processor \"%s\"", exe_file_name.c_str(), file[i]->item(0)->name().c_str())); 
					break;
				case osUnsupportedSubsystem:
					Notify(mtError, NULL, string_format("File \"%s\" has unsupported subsystem", exe_file_name.c_str())); 
					break;
				}
				if (status != osUnknownFormat)
					return false;
			}
		}

		if (!input_file_) {
			Notify(mtError, NULL, string_format("File \"%s\" has unknown format", exe_file_name.c_str())); 
			return false;
		}

		if (input_file_->visible_count() == 0)
			return false;
	}

	// set default values
	options_ = cpMaximumProtection;
	vm_options_ = 0;
	// create random section name
	vm_section_name_ = ".";
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";
	srand(os::GetTickCount());
	for (size_t j = 0; j < 3; j++) {
		vm_section_name_ += alphanum[rand() % (sizeof(alphanum) - 1)];
	}
	for (i = 0; i < _countof(messages_); i++) {
#ifdef VMP_GNU
		messages_[i] = default_message[i];
#else
		messages_[i] = os::ToUTF8(default_message[i]);
#endif
	}

	if (!LoadFromXML(project_file_name_.c_str())) {
		if (input_file_) {
			if (log_)
				log_->StartProgress(string_format("Loading %s...", os::ExtractFileName(project_file_name_.c_str()).c_str()), 0);
			LoadDefaultFunctions();
			if (log_)
				log_->EndProgress();
		}
	}

	if (input_file_name_.empty())
		input_file_name_ = os::SubtractPath(project_path().c_str(), exe_file_name.c_str());

	if (output_file_name_.empty())
		output_file_name_ = default_output_file_name();

	if (!user_licensing_params_file_name.empty())
		license_data_file_name_ = user_licensing_params_file_name;
	if (license_data_file_name_.empty())
		license_data_file_name_ = default_license_data_file_name();

	licensing_manager_->Open(os::CombinePaths(project_path().c_str(), license_data_file_name_.c_str()));

	return true;
}

bool Core::LoadFromXML(const char *project_file_name)
{
	return false;
}

void Core::LoadDefaultFunctions()
{
	if (!input_file_)
		return;

	// add new markers and strings into project
	Folder *parent_folder = NULL;
	for (size_t i = 0; i < input_file_->count(); i++) {
		IArchitecture *arch = input_file_->item(i);
		if (!arch->visible())
			continue;

		for (size_t j = 0; j < arch->map_function_list()->count(); j++) {
			IFunctionList *function_list = arch->function_list();

			MapFunction *map_function = arch->map_function_list()->item(j);
			if ((map_function->type() == otMarker || map_function->type() == otAPIMarker || map_function->type() == otString) 
				&& function_list->GetFunctionByAddress(map_function->address()) == NULL) {
				if (!parent_folder) {
					parent_folder = input_file_->folder_list()->Add("New markers and strings");
					parent_folder->set_read_only(true);
				}
				function_list->AddByAddress(map_function->address(), ctVirtualization, 0, true, parent_folder);
			}
		}
	}
}

bool Core::SaveAs(const std::string &file_name)
{
	std::string old_project_file_name = project_file_name_;
	std::string old_input_file_name = input_file_name_;
	std::string old_output_file_name = output_file_name_;
	std::string old_license_data_file_name = license_data_file_name_;
	std::string new_project_path = os::ExtractFilePath(file_name.c_str());

	input_file_name_ = os::SubtractPath(new_project_path.c_str(), os::CombinePaths(project_path().c_str(), input_file_name().c_str()).c_str());
	output_file_name_ = os::SubtractPath(new_project_path.c_str(), os::CombinePaths(project_path().c_str(), output_file_name().c_str()).c_str());
	license_data_file_name_ = os::SubtractPath(new_project_path.c_str(), os::CombinePaths(project_path().c_str(), license_data_file_name_.c_str()).c_str());
	project_file_name_ = file_name;
	if (!Save()) {
		input_file_name_ = old_input_file_name;
		output_file_name_ = old_output_file_name;
		project_file_name_ = old_project_file_name;
		license_data_file_name_ = old_license_data_file_name;
		return false;
	}

	if (output_file_name_ != old_output_file_name 
		|| license_data_file_name_ != old_license_data_file_name
		)
		Notify(mtChanged, this);
	return true;
}

bool Core::Save()
{
	// XML保存功能已移除
	return true;
}

void Core::Close()
{
	input_file_name_.clear();
	output_file_name_.clear();
	hwid_.clear();
	licensing_manager_->clear();
	license_data_file_name_.clear();
	if (input_file_) {
		delete input_file_;
		input_file_ = NULL;
	}
}

std::string Core::absolute_output_file_name() const
{
	return os::CombinePaths(project_path().c_str(), os::ExpandEnvironmentVariables(output_file_name_.c_str()).c_str());
}

bool Core::Compile()
{
	uint32_t rand_seed = os::GetTickCount();
#ifdef CHECKED
	std::cout << "------------------- Core::Compile " << __LINE__ << " -------------------" << std::endl;
	std::cout << "rand_seed: " << rand_seed << std::endl;
	std::cout << "---------------------------------------------------------" << std::endl;
#endif

	rand_seed = 0;
	OutputDebugStringA(string_format("rand_seed:%d\n", rand_seed).c_str());

	srand(rand_seed);
	
	output_file_ = NULL;
	output_architecture_ = NULL;

	if (!input_file_)
		return true;

	CompileOptions options;

	options.flags = (options_ & cpUserOptionsMask);
	options.flags &= ~input_file_->disable_options();
	if ((options.flags & cpCheckDebugger) == 0)
		options.flags &= ~cpCheckKernelDebugger;

		options.flags |= cpEncryptBytecode;
		if ((options.flags & cpMemoryProtection) == 0)
			options.flags |= cpLoaderCRC;

	options.section_name = vm_section_name_;
	options.vm_flags = vm_options_;
	options.vm_count = 10;
	for (size_t i = 0; i < _countof(options.messages); i++) {
		options.messages[i] = messages_[i];
	}

	options.architecture = &output_architecture_;
	options.hwid = hwid_;
	options.licensing_manager = licensing_manager_;

	if (log_)
		log_->StartProgress(string_format("Compiling..."), 1);

	HANDLE locked_file = BeginCompileTransaction();
	output_file_->set_log(log_);

	bool res;
	try {
		res = output_file_->Compile(options);
	} catch(std::runtime_error &) {
		EndCompileTransaction(locked_file, false);
		throw;
	}

	if (log_) {
		log_->EndProgress();
		log_->set_arch_name("");
	}
	uint32_t output_file_size = static_cast<uint32_t>(output_file_->size()); 
	EndCompileTransaction(locked_file, res);
	if (res) {
		Notify(mtInformation, NULL, string_format(
			"Output file size is %d bytes (%d%%)", 
			output_file_size, 
			static_cast<int>(100.0 * output_file_size / input_file_->size())
			));


	}
	return res;
}

HANDLE Core::BeginCompileTransaction()
{
	HANDLE res = INVALID_HANDLE_VALUE;
	std::string output_file_name = absolute_output_file_name();
	if (os::FileExists(output_file_name.c_str())) {
		res = os::FileCreate(output_file_name.c_str(), fmOpenReadWrite | fmShareDenyWrite);
		if (res == INVALID_HANDLE_VALUE)
			throw std::runtime_error(string_format("Cannot open file \"%s\"", output_file_name.c_str()));

		output_file_name = os::GetTempFilePathNameFor(output_file_name.c_str());
		if (output_file_name.empty())
			throw std::runtime_error(string_format("Cannot create file \"%s\"", "'temporary'"));
	}
	output_file_ = input_file_->Clone(output_file_name.c_str());
	return res;
}

void Core::EndCompileTransaction(HANDLE locked_file, bool commit)
{
	std::string output_file = output_file_->file_name();
	delete output_file_;
	output_file_ = NULL;

	if (locked_file == INVALID_HANDLE_VALUE) {
		//direct compile to new file, no tmp file created
		if (!commit)
			os::FileDelete(output_file.c_str()); //remove new garbage
	} else {
		//compiled to tmp file
		os::FileClose(locked_file);
		if (commit) {
			std::string final_file = absolute_output_file_name();
			os::FileDelete(final_file.c_str(), true);
			if (!os::FileMove(output_file.c_str(), final_file.c_str())) {
				os::FileDelete(output_file.c_str());
				throw std::runtime_error(string_format("Cannot create file \"%s\"", final_file.c_str()));
			}
		} else {
			os::FileDelete(output_file.c_str());
		}
	}
}

void Core::set_options(uint32_t options) 
{ 
	if (options_ != options) {
		options_ = options;
		Notify(mtChanged, this);
	}
}

void Core::include_option(ProjectOption option) 
{ 
	set_options(options_ | option);
}

void Core::exclude_option(ProjectOption option) 
{ 
	set_options(options_ & ~option);
}

void Core::set_vm_section_name(const std::string &vm_section_name)
{ 
	if (vm_section_name_ != vm_section_name) {
		vm_section_name_ = vm_section_name;
		Notify(mtChanged, this);
	}
}

void Core::set_output_file_name(const std::string &output_file_name)
{
	if (output_file_name_ != output_file_name) {
		output_file_name_ = output_file_name.empty() ? default_output_file_name() : output_file_name;
		Notify(mtChanged, this);
	}
}

void Core::set_message(size_t type, const std::string &message)
{
	if (messages_[type] != message) {
		messages_[type] = message;
		Notify(mtChanged, this);
	}
}

void Core::set_hwid(const std::string &hwid)
{
	if (hwid_ != hwid) {
		hwid_ = hwid;
		Notify(mtChanged, this);
	}
}

void Core::set_license_data_file_name(const std::string &license_data_file_name)
{
	if (license_data_file_name_ != license_data_file_name) {
		license_data_file_name_ = license_data_file_name.empty() ? default_license_data_file_name() : license_data_file_name;
		Notify(mtChanged, this);
		licensing_manager_->Open(os::CombinePaths(project_path().c_str(), license_data_file_name_.c_str()));
	}
}

std::string Core::activation_server() const
{
	return licensing_manager_->activation_server();
}

void Core::set_activation_server(const std::string &activation_server)
{
	if (licensing_manager_->activation_server() != activation_server) {
		licensing_manager_->set_activation_server(activation_server);
		Notify(mtChanged, this);
	}
}

std::string Core::project_path() const 
{ 
	return os::ExtractFilePath(project_file_name_.c_str()); 
}

void Core::Notify(MessageType type, IObject *sender, const std::string &message)
{
	if (log_)
		log_->Notify(type, sender, message);
}

IArchitecture * Core::input_architecture() const
{
	return (input_file_ && output_architecture_) ? input_file_->GetArchitectureByType(output_architecture_->type()) : NULL;
}


const char * Core::version()
{
	return "3.5";
}

const char * Core::build()
{
	return STR(VER_BUILD);
}

bool Core::check_license_edition(const VMProtectSerialNumberData &lic)
{
	if (lic.nState != SERIAL_STATE_SUCCESS)
		return false;

	uint8_t productId = (lic.nUserDataLength > 0) ? lic.bUserData[0] : VPI_NOT_SPECIFIED;
	VMProtectProductId allowed[] = {
		VPI_NOT_SPECIFIED, VPI_ULTM_PERSONAL, VPI_ULTM_COMPANY
	};

	for (size_t i = 0; i < _countof(allowed); i++) {
		if (productId == allowed[i])
			return true;
	}
	return false;
}
