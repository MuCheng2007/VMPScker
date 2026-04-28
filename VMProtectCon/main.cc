#include "../core/objects.h"
#include "../core/osutils.h"
#include "../core/streams.h"
#include "../core/files/architecture.h"
#include "../core/core_internal/core.h"

#include "../core/core_internal/license.h"

#include "console.h"
#include "main.h"

#ifdef VMP_GNU
int main(int argc, const char* argv[])
#else

int wmain(int argc, wchar_t* argv[])
#endif
{
	std::vector<std::string> args;
	for (int i = 0; i < argc; i++) {
#ifdef VMP_GNU
		args.push_back(argv[i]);
#else
		args.push_back(os::ToUTF8(argv[i]));
#endif
	}
	return ConsoleApplication(args).Run();
}

/**
 * ConsoleApplication
 */

ConsoleApplication::ConsoleApplication(const std::vector<std::string>& args)
	: args_(args)
{
	log_ << string_format("%s v %s (build %s) %s", Core::edition(), Core::version(), Core::build(), Core::copyright()) << endl;
}

#ifdef ULTIMATE	
static bool checkdate(int y, int m, int d)
{
	if (m < 1 || m > 12)
		return false;

	int max_days;
	if (m == 4 || m == 6 || m == 9 || m == 11)
		max_days = 30;
	else if (m == 2)
		max_days = (((y % 4 == 0) && (y % 100 != 0)) || (y % 400 == 0)) ? 29 : 28;
	else
		max_days = 31;
	return (d >= 1 && d <= max_days);
}
#endif

int ConsoleApplication::Run()
{
#ifdef DEMO
	log_ << "Demo Version" << endl;
#else
	bool is_registered = false;
	{
		VMProtectSerialNumberData serial_data;
		if (VMProtectSetSerialNumber(VMProtectDecryptStringA("SerialNumber")) == SERIAL_STATE_SUCCESS && VMProtectGetSerialNumberData(&serial_data, sizeof(serial_data))) {
			if (Core::check_license_edition(serial_data)) {
				log_ << string_format("Registered To: %s [%s], %s",
				os::ToUTF8(serial_data.wUserName).c_str(), os::ToUTF8(serial_data.wEMail).c_str(), (serial_data.bUserData[0] & 1) ? "Personal License" : "Company License") << endl;
				is_registered = true;
			}
			else {
				VMProtectSetSerialNumber(NULL);
			}
		}
	}
	if (!is_registered) {
		log_ << "Unregistered Version" << endl;
	}
#endif
	log_ << endl;

	if (args_.size() < 2) {
		log_ << string_format("Usage: %s <File> [<Output File>] [-pf <Project File>] [-sf <Script File>]"
#ifdef ULTIMATE
			" [-lf <Licensing Parameters File>]"
			" [-bd <Build Date>]"
#endif
			" [-wm <Watermark>] [-we]",
			os::ExtractFileName(args_[0].c_str()).c_str()
		) << endl;
		return 1;
	}

	std::string input_file_name;
	std::string output_file_name;
	std::string project_file_name;
	std::string script_file_name;
	std::string watermark_name;
#ifdef ULTIMATE
	std::string licensing_params_file_name;
	uint32_t build_date = 0;
#endif
	//std::string invalid_param;
	for (size_t i = 1; i < args_.size(); i++) {
		std::string param = args_[i];
		bool is_last = (i == args_.size() - 1);

		bool invalid_value = false;
		if (param == "-pf") {
			if (is_last)
				invalid_value = true;
			else
				project_file_name = args_[++i];
		}
		else if (param == "-sf") {
			if (is_last)
				invalid_value = true;
			else
				script_file_name = args_[++i];
		}
		else if (param == "-wm") {
			if (is_last)
				invalid_value = true;
			else
				watermark_name = args_[++i];
		}
#ifdef ULTIMATE		
		else if (param == "-lf") {
			if (is_last)
				invalid_value = true;
			else
				licensing_params_file_name = args_[++i];
		}
		else if (param == "-bd") {
			if (is_last)
				invalid_value = true;
			else {
				int y, m, d;
				if (sscanf_s(args_[++i].c_str(), "%04d-%02d-%02d", &y, &m, &d) == 3 && checkdate(y, m, d))
					build_date = (y << 16) + (static_cast<uint8_t>(m) << 8) + static_cast<uint8_t>(d);
				else
					invalid_value = true;
			}
		}
#endif
		else if (param == "-we") {
			log_.set_warnings_as_errors(true);
		}
		else {
			switch (i) {
			case 1:
				input_file_name = param;
				break;
			case 2:
				output_file_name = param;
				break;
			}
		}

		if (invalid_value) {
			log_.Notify(mtError, NULL, string_format("Invalid value of parameter \"%s\"", param.c_str()));
			return 1;
		}
	}

	std::string current_path = os::GetCurrentPath();
	if (!input_file_name.empty())
		input_file_name = os::CombinePaths(current_path.c_str(), input_file_name.c_str());
	if (!project_file_name.empty()) {
		project_file_name = os::CombinePaths(current_path.c_str(), project_file_name.c_str());
		if (!os::FileExists(project_file_name.c_str())) {
			log_.Notify(mtError, NULL, string_format("File \"%s\" not found", project_file_name.c_str()));
			return 1;
		}
	}
#ifdef ULTIMATE
	if (!licensing_params_file_name.empty()) {
		licensing_params_file_name = os::CombinePaths(current_path.c_str(), licensing_params_file_name.c_str());
		if (!os::FileExists(licensing_params_file_name.c_str())) {
			log_.Notify(mtError, NULL, string_format("File \"%s\" not found", licensing_params_file_name.c_str()));
			return 1;
		}
	}
#endif

	Core core(&log_);
	try {
		if (!core.Open(input_file_name, project_file_name
#ifdef ULTIMATE
			, licensing_params_file_name
#endif
		))
			return 1;

		if (!output_file_name.empty())
			core.set_output_file_name(os::CombinePaths(current_path.c_str(), output_file_name.c_str()));



#ifdef ULTIMATE
		if (build_date)
			core.licensing_manager()->set_build_date(build_date);
#endif

		if (!core.Compile())
			return 1;

	}
	catch (abort_error& /*error*/) {
		return 1;
	}
	catch (std::runtime_error& error) {
		if (error.what())
			log_.Notify(mtError, NULL, error.what());
		return 1;
	}

	log_ << endl << "Compiled" << endl;
	return 0;
}