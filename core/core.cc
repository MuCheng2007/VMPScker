#include "../runtime/crypto.h"

#include "objects.h"
#include "osutils.h"
#include "streams.h"
#include "files.h"
#include "processors.h"
#include "inifile.h"
#include "script.h"
#include "pefile.h"
#include "lang.h"
#include "core.h"

#include "core_internal/core_utils.h"
#include "core_internal/watermark.h"
#include "core_internal/project_template.h"

#include "core_internal/license.h"
#include "core_internal/file_manager.h"

static std::string GetProjectFileName(std::string &exe_file_name)
{
	TiXmlDocument doc;
	std::string project_file_name = exe_file_name;

	if (doc.LoadFile(project_file_name.c_str())) {
		TiXmlElement *root_node = doc.FirstChildElement("Document");
		if (root_node) {
			exe_file_name.clear();
			TiXmlElement *protection_node = root_node->FirstChildElement("Protection");
			if (protection_node)
				protection_node->QueryStringAttribute("InputFileName", &exe_file_name);
			if (!exe_file_name.empty())
				exe_file_name = os::CombinePaths(os::ExtractFilePath(project_file_name.c_str()).c_str(), exe_file_name.c_str());
			return project_file_name;
		}
	}

	IniFile ini_file(exe_file_name.c_str());
	if (ini_file.ReadSection("ProjectInfo").size()) {
		exe_file_name = ini_file.ReadString("ProjectInfo", "InputFileName");
		if (!exe_file_name.empty())
			exe_file_name = os::CombinePaths(os::ExtractFilePath(project_file_name.c_str()).c_str(), exe_file_name.c_str());
		return project_file_name;
	}

	std::string file_name_new = exe_file_name + ".vmp";
	std::string file_name_old = os::ChangeFileExt(exe_file_name.c_str(), ".vmp");

	if (os::FileExists(file_name_new.c_str()) || !os::FileExists(file_name_old.c_str()))
		return file_name_new;

	return file_name_old;
}

Core::Core(ILog *log /*=NULL*/)
	: IObject(), log_(log), input_file_(NULL), output_file_(NULL), watermark_(NULL), output_architecture_(NULL),
	options_(0), vm_options_(0)
{
	licensing_manager_ = new LicensingManager(this);
	file_manager_ = new FileManager(this);
	watermark_manager_ = new WatermarkManager(this);
	template_manager_ = new ProjectTemplateManager(this);
	script_ = new Script(this);

	if (settings_file().watermarks_node_created()) {
		// convert old settings file into new format
		std::string ini_file_name = os::CombinePaths(os::GetSysAppDataDirectory().c_str(), "PolyTech/VMProtect/VMProtect.ini");
		if (os::FileExists(ini_file_name.c_str())) {
			watermark_manager_->ReadFromIni(ini_file_name);
			watermark_manager_->SaveToFile(settings_file());
			settings_file().Save();
		}
	} else {
		watermark_manager_->ReadFromFile(settings_file());
	}

	template_manager_->ReadFromFile(settings_file());
}

Core::~Core() 
{
	Close();

	delete script_;
	delete watermark_manager_;
	delete template_manager_;
	delete file_manager_;
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
			log_->StartProgress(string_format("%s %s...", language[lsLoading].c_str(), os::ExtractFileName(exe_file_name.c_str()).c_str()), 1);

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
					Notify(mtError, NULL, string_format(language[lsFileHasNoCodeSegment].c_str(), exe_file_name.c_str())); 
					return false;
				}

				delete input_file_;
				input_file_ = file[i].release();
				break;
			} else {
				switch (status) {
				case osOpenError:
					Notify(mtError, NULL, string_format(language[lsOpenFileError].c_str(), exe_file_name.c_str(), file[i]->format_name().c_str())); 
					break;
				case osInvalidFormat:
					Notify(mtError, NULL, string_format(language[lsFileHasIncorrectFormat].c_str(), exe_file_name.c_str(), file[i]->format_name().c_str()) + (!open_error.empty() ? ": " + open_error : ""));
					break;
				case osUnsupportedCPU:
					Notify(mtError, NULL, string_format(language[lsFileHasUnsupportedProcessor].c_str(), exe_file_name.c_str(), file[i]->item(0)->name().c_str())); 
					break;
				case osUnsupportedSubsystem:
					Notify(mtError, NULL, string_format(language[lsFileHasUnsupportedSubsystem].c_str(), exe_file_name.c_str())); 
					break;
				}
				if (status != osUnknownFormat)
					return false;
			}
		}

		if (!input_file_) {
			Notify(mtError, NULL, string_format(language[lsFileHasUnknownFormat].c_str(), exe_file_name.c_str())); 
			return false;
		}

		if (input_file_->visible_count() == 0)
			return false;
	}

#ifndef ULTIMATE
	if (!input_file_)
		return false;
#endif

	// set default values
	ProjectTemplate *default_template = template_manager_->item(0);
	options_ = default_template->options();
	vm_options_ = 0;
	vm_section_name_ = default_template->vm_section_name();
	for (i = 0; i < _countof(messages_); i++) {
		messages_[i] = default_template->message(i);
	}

	if (!LoadFromXML(project_file_name_.c_str()) && !LoadFromIni(project_file_name_.c_str())) {
		if (input_file_) {
			if (log_)
				log_->StartProgress(string_format("%s %s...", language[lsLoading].c_str(), os::ExtractFileName(project_file_name_.c_str()).c_str()), 0);
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
	TiXmlDocument doc;
	TiXmlElement *root_node, *script_node, *protection_node, *procedures_node, *procedure_node, *objects_node, *object_node,
		*messages_node, *message_node, *folders_node, *folder_node, *ext_command_node;
	size_t i, j;
	CompilationType compilation_type;
	uint64_t func_address, address;
	bool need_compile;
	std::string func_name, arch_name;
	IFunction *function;
	IArchitecture *arch;
	uint32_t compilation_options;
    unsigned int u, version;
	unsigned int func_index;

	if (!doc.LoadFile(project_file_name))
		return false;

	root_node = doc.FirstChildElement("Document");
	if (!root_node)
		return false;

	version = 1;
	root_node->QueryUnsignedAttribute("Version", &version);

	if (input_file_) {
		protection_node = root_node ? root_node->FirstChildElement("Protection") : NULL;
		if (log_) {
			i = 0;
			if (protection_node) {
				procedures_node = protection_node->FirstChildElement("Procedures");
				if (procedures_node) {
					procedure_node = procedures_node->FirstChildElement("Procedure");
					while (procedure_node) {
						i++;
						procedure_node = procedure_node->NextSiblingElement("Procedure");
					}
				}
			}
			log_->StartProgress(string_format("%s %s...", language[lsLoading].c_str(), os::ExtractFileName(project_file_name).c_str()), i);
		}

		if (protection_node) {
			protection_node->QueryStringAttribute("InputFileName", &input_file_name_);
			u = options_;
			protection_node->QueryUnsignedAttribute("Options", &u);
			options_ = u;
			u = 0;
			protection_node->QueryUnsignedAttribute("VMOptions", &u);
			vm_options_ = u;

			if (version < 2) {
				bool check_kernel_debugger = false;
				protection_node->QueryBoolAttribute("CheckKernelDebugger", &check_kernel_debugger);
				if (check_kernel_debugger)
					options_ |= cpCheckKernelDebugger;
			}
			protection_node->QueryStringAttribute("VMCodeSectionName", &vm_section_name_);
			protection_node->QueryStringAttribute("OutputFileName", &output_file_name_);
			protection_node->QueryStringAttribute("WaterMarkName", &watermark_name_);
#ifdef ULTIMATE
			protection_node->QueryStringAttribute("HWID", &hwid_);
			protection_node->QueryStringAttribute("LicenseDataFileName", &license_data_file_name_);
#endif

			messages_node = protection_node->FirstChildElement("Messages");
			if (messages_node) {
				message_node = messages_node->FirstChildElement("Message");
				while (message_node) {
					u = 0;
					message_node->QueryUnsignedAttribute("Id", &u);
					if (u < _countof(messages_)) {
						if (const char *text = message_node->GetText())
							messages_[u] = text;
						else
							messages_[u].clear();
					}
					message_node = message_node->NextSiblingElement(message_node->Value());
				}
			}

			if (version < 2) {
				options_ |= cpStripDebugInfo;
			}

			std::vector<Folder *> folder_list;
			Folder *parent_folder;
			folders_node = protection_node->FirstChildElement("Folders");
			if (folders_node) {
				folder_node = folders_node->FirstChildElement("Folder");
				while (folder_node) {
					u = -1;
					std::string name;
					folder_node->QueryUnsignedAttribute("Parent", &u);
					folder_node->QueryStringAttribute("Name", &name);
					parent_folder = (u < folder_list.size()) ? folder_list[u] : input_file_->folder_list(); 
					folder_list.push_back(parent_folder->Add(name));
					folder_node = folder_node->NextSiblingElement(folder_node->Value());
				}
			}

			procedures_node = protection_node->FirstChildElement("Procedures");
			if (procedures_node) {
				std::vector<uint64_t> address_list;
				procedure_node = procedures_node->FirstChildElement("Procedure");
				while (procedure_node) {
					arch_name.clear();
					procedure_node->QueryStringAttribute("Architecture", &arch_name);
					u = ctVirtualization;
					procedure_node->QueryUnsignedAttribute("CompilationType", &u);
					if (u > 2)
						u = 0;
					compilation_type = static_cast<CompilationType>(u);
					u = 0;
					procedure_node->QueryUnsignedAttribute("Options", &u);
					compilation_options = u;
					need_compile = true;
					procedure_node->QueryBoolAttribute("IncludedInCompilation", &need_compile);
					u = -1;
					procedure_node->QueryUnsignedAttribute("Folder", &u);
					parent_folder = (u < folder_list.size()) ? folder_list[u] : NULL;
					func_name.clear();
					procedure_node->QueryStringAttribute("MapAddress", &func_name);
					func_address = 0;
					func_index = (unsigned int)-1;
					if (func_name.empty()) {
						std::string str;
						procedure_node->QueryStringAttribute("Address", &str);
						func_address = StrToInt64Def(str.c_str(), 0);
					}
					else {
						procedure_node->QueryUnsignedAttribute("Index", &func_index);
					}

					for (i = 0; i < input_file_->count(); i++) {
						arch = input_file_->item(i);
						if (!arch->visible())
							continue;

						struct AddressInfo {
							IArchitecture *arch;
							uint64_t address;
						};

						std::vector<AddressInfo> address_info_list;
						AddressInfo address_info;

						address_info.arch = arch;
						if (func_name.empty()) {
							address_info.address = func_address;
							address_info_list.push_back(address_info);
						} else {
							address_list = arch->map_function_list()->GetAddressListByName(func_name, true);
							for (j = 0; j < address_list.size(); j++) {
								address_info.address = address_list[j];
								address_info_list.push_back(address_info);
							}
						}

						if (!func_name.empty()) {
							if (func_index != (unsigned int)-1) {
								if (func_index < address_info_list.size()) {
									address_info = address_info_list[func_index];
									address_info_list.clear();
									address_info_list.push_back(address_info);
								}
								else {
									address_info_list.clear();
								}
							}
							if (address_list.empty()) {
								function = arch->function_list()->AddUnknown(func_name, compilation_type, compilation_options, need_compile, parent_folder);
								function->set_tag(func_index);
							}
						}

						for (j = 0; j < address_info_list.size(); j++) {
							address_info = address_info_list[j];
							address = address_info.address;
							arch = address_info.arch;
							function = arch->function_list()->AddByAddress(address_info.address, compilation_type, compilation_options, need_compile, parent_folder);
							if (function) {
								u = 0;
								procedure_node->QueryUnsignedAttribute("BreakOffset", &u);
								if (u)
									function->set_break_address(address + u);

								ext_command_node = procedure_node->FirstChildElement("ExtOffset");
								while (ext_command_node) {
									if (const char *str = ext_command_node->GetText())
										function->ext_command_list()->Add(address + strtoul(str, 0, 10));
									ext_command_node = ext_command_node->NextSiblingElement("ExtOffset");
								}
							}
						}
					}

					procedure_node = procedure_node->NextSiblingElement(procedure_node->Value());
					if (log_)
						log_->StepProgress(1ull, true);
				}
			}

   			objects_node = protection_node->FirstChildElement("Objects");
			if (objects_node) {
				std::string name;
				std::string type;
				object_node = objects_node->FirstChildElement("Object");
				while (object_node) {
					arch_name.clear();
					object_node->QueryStringAttribute("Architecture", &arch_name);
					type.clear();
					object_node->QueryStringAttribute("Type", &type);
					name.clear();
					object_node->QueryStringAttribute("Name", &name);
				
					for (i = 0; i < input_file_->count(); i++) {
						arch = input_file_->item(i);
						if (!arch->visible())
							continue;

						if (!arch_name.empty() && arch->name() != arch_name)
							continue;

						if (type == "Segment") {
							if (ISection *segment = arch->segment_list()->GetSectionByName(name)) {
								bool excluded_from_packing = false;
								object_node->QueryBoolAttribute("ExcludedFromPacking", &excluded_from_packing);
								bool excluded_from_memory_protection = false;
								object_node->QueryBoolAttribute("ExcludedFromMemoryProtection", &excluded_from_memory_protection);
								segment->set_excluded_from_packing(excluded_from_packing);
								segment->set_excluded_from_memory_protection(excluded_from_memory_protection);
							}
						} else if (type == "Resource" && arch->resource_list()) {
							if (IResource *resource = arch->resource_list()->GetResourceById(name)) {
								bool excluded_from_packing = false;
								object_node->QueryBoolAttribute("ExcludedFromPacking", &excluded_from_packing);
								resource->set_excluded_from_packing(excluded_from_packing);
							}
						}
						else if (type == "Import") {
							if (IImport *import = arch->import_list()->GetImportByName(name)) {
								bool excluded_from_import_protection = false;
								object_node->QueryBoolAttribute("ExcludedFromImportProtection", &excluded_from_import_protection);
								import->set_excluded_from_import_protection(excluded_from_import_protection);
							}
						}
					}

					object_node = object_node->NextSiblingElement(object_node->Value());
				}
			}
		}

		LoadDefaultFunctions();

		if (log_)
			log_->EndProgress();
	}

	TiXmlElement *files_node = root_node ? root_node->FirstChildElement("DLLBox") : NULL;
	if (files_node) {
		std::vector<FileFolder *> folder_list;
		FileFolder *parent_folder;
		folders_node = files_node->FirstChildElement("Folders");
		if (folders_node) {
			folder_node = folders_node->FirstChildElement("Folder");
			while (folder_node) {
				u = -1;
				std::string name;
				folder_node->QueryUnsignedAttribute("Parent", &u);
				folder_node->QueryStringAttribute("Name", &name);
				parent_folder = (u < folder_list.size()) ? folder_list[u] : file_manager_->folder_list(); 
				folder_list.push_back(parent_folder->Add(name));
				folder_node = folder_node->NextSiblingElement(folder_node->Value());
			}
		}

		need_compile = true;
		files_node->QueryBoolAttribute("IncludedInCompilation", &need_compile);
		file_manager_->set_need_compile(need_compile);

		TiXmlElement *file_node = files_node->FirstChildElement("DLL");
		while (file_node) {
			std::string name;
			std::string file_name;
				
			file_node->QueryStringAttribute("Name", &name);
			file_node->QueryStringAttribute("FileName", &file_name);
			u = -1;
			file_node->QueryUnsignedAttribute("Folder", &u);
			parent_folder = (u < folder_list.size()) ? folder_list[u] : NULL;
			InternalFileAction action = faNone;
			if (version < 2) {
				bool load_at_start = false;
				file_node->QueryBoolAttribute("LoadAtStart", &load_at_start);
				if (load_at_start)
					action = faLoad;
			} else {
				u = 0;
				file_node->QueryUnsignedAttribute("Options", &u);
				if (u & 1)
					action = faLoad;
				else if (u & 2)
					action = faRegister;
				else if (u & 4)
					action = faInstall;
			}
			file_manager_->Add(name, file_name, action, parent_folder);

			file_node = file_node->NextSiblingElement(file_node->Value());
		}
	}

	script_node = root_node ? root_node->FirstChildElement("Script") : NULL;
	if (script_node) {
		need_compile = true;
		script_node->QueryBoolAttribute("IncludedInCompilation", &need_compile);
		script_->set_need_compile(need_compile);

		const char *str = script_node->GetText();
		if (str)
			script_->set_text(std::string(str));
	}

	return true;
}

bool Core::LoadFromIni(const char *project_file_name)
{
	size_t i, c, j, k, u, version;
	std::vector<Folder *> folder_list;
	Folder *parent_folder;
	bool need_compile;
	uint64_t address;
	CompilationType compilation_type;
	uint32_t compilation_options;
	std::string map_address;
	IFunction *function;
	IArchitecture *arch;

	IniFile doc(project_file_name);
	if (doc.ReadSection("ProjectInfo").empty())
		return false;

	if (input_file_) {
		if (log_) {
			i = doc.ReadInt("ProjectInfo", "Count");
			log_->StartProgress(string_format("%s %s...", language[lsLoading].c_str(), os::ExtractFileName(project_file_name).c_str()), i);
		}

		version = doc.ReadInt("ProjectInfo", "Version", 1);
		input_file_name_ = doc.ReadString("ProjectInfo", "InputFileName");
		options_ = doc.ReadInt("ProjectInfo", "Options", options_);
		bool check_kernel_debugger = doc.ReadBool("ProjectInfo", "CheckKernelModeDebugger", false);
		if (check_kernel_debugger)
			options_ |= cpCheckKernelDebugger;
		vm_section_name_ = doc.ReadString("ProjectInfo", "VMCodeSectionName", vm_section_name_.c_str());
		output_file_name_ = doc.ReadString("ProjectInfo", "OutputFileName");
		watermark_name_ = doc.ReadString("ProjectInfo", "WaterMarkName");

		if (version < 2) {
			options_ |= cpStripDebugInfo;
		}

		c = doc.ReadInt("Folders", "Count");
		for (i = 0; i < c; i++) {
			u = doc.ReadInt("Folders", string_format("ParentFolder%d", i).c_str(), -1);
			parent_folder = (u < folder_list.size()) ? folder_list[u] : input_file_->folder_list(); 
			folder_list.push_back(parent_folder->Add(doc.ReadString("Folders", string_format("FolderName%d", i).c_str())));
		}

		c = doc.ReadInt("ProjectInfo", "Count");
		std::vector<uint64_t >address_list;
		for (i = 0; i < c; i++) {
			u = doc.ReadInt("Procedures", string_format("CompilationType%d", i).c_str(), ctVirtualization);
			if (u > 2)
				u = 0;
			compilation_type = static_cast<CompilationType>(u);
			compilation_options = doc.ReadInt("Procedures", string_format("Options%d", i).c_str());
			need_compile = doc.ReadBool("Procedures", string_format("NeedCompile%d", i).c_str());
			u = doc.ReadInt("Procedures", string_format("ParentFolder%d", i).c_str(), -1);
			parent_folder = (u < folder_list.size()) ? folder_list[u] : NULL;
			map_address = doc.ReadString("Procedures", string_format("MapAddress%d", i).c_str());

			for (j = 0; j < input_file_->count(); j++) {
				arch = input_file_->item(j);
				if (!arch->visible())
					continue;

				if (map_address.empty()) {
					address_list.clear();
					address_list.push_back(doc.ReadInt64("Procedures", string_format("Address%d", i).c_str()));
				} else {
					address_list = arch->map_function_list()->GetAddressListByName(map_address, true);
					if (address_list.empty()) {
						function = arch->function_list()->AddUnknown(map_address, compilation_type, compilation_options, need_compile, parent_folder);
						function->set_tag(-1);
					}
				}

				for (k = 0; k < address_list.size(); k++) {
					address = address_list[k];
					function = arch->function_list()->AddByAddress(address, compilation_type, compilation_options, need_compile, parent_folder);
					if (function) {
						u = doc.ReadInt("Procedures", string_format("BreakAddress%d", i).c_str());
						if (u)
							function->set_break_address(address + u);

						size_t e = doc.ReadInt("Procedures", string_format("ExtAddressCount%d", i).c_str());
						for (size_t k = 0; k < e; k++) {
							u = doc.ReadInt(string_format("ExtAddress%d", i).c_str(), string_format("Address%d", k).c_str());
							function->ext_command_list()->Add(address + u);
						}
					}
				}
			}
			if (log_)
				log_->StepProgress(1ull, true);
		}

		LoadDefaultFunctions();

		if (log_)
			log_->EndProgress();
	}

	c = doc.ReadInt("DLLs", "Count");
	for (i = 0; i < c; i++) {
		file_manager_->Add(doc.ReadString("DLLs", string_format("DLLName%d", i).c_str()), 
							doc.ReadString("DLLs", string_format("DLLFileName%d", i).c_str()),
							faNone, NULL);
	}

	std::string script_file_name = os::ChangeFileExt(doc.file_name().c_str(), ".vms");
	if (os::FileExists(script_file_name.c_str()))
		script_->LoadFromFile(script_file_name);

	return true;
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

void Core::LoadFromTemplate(const ProjectTemplate &pt)
{
	set_options(pt.options());
	set_vm_section_name(pt.vm_section_name());
	for (size_t i = 0; i < _countof(messages_); i++) {
		set_message(i, pt.message(i));
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
	if (input_file_) {
		size_t i, j, k;
		TiXmlDocument doc;
		unsigned int old_version;

		if (!doc.LoadFile(project_file_name_.c_str()))
			doc.LinkEndChild(new TiXmlDeclaration("1.0", "UTF-8", ""));

		TiXmlElement *root_node = doc.FirstChildElement("Document");
		if (!root_node) {
			root_node = new TiXmlElement("Document");
			doc.LinkEndChild(root_node);
		}
		old_version = 1;
		root_node->QueryUnsignedAttribute("Version", &old_version);

		root_node->SetAttribute("Version", 2);

		TiXmlElement *protection_node = root_node->FirstChildElement("Protection");
		if (!protection_node) {
			protection_node = new TiXmlElement("Protection");
			root_node->LinkEndChild(protection_node);
		}
		protection_node->SetAttribute("InputFileName", input_file_name_);
		protection_node->SetAttribute("Options", options_);
		protection_node->SetAttribute("VMOptions", vm_options_);
		protection_node->SetAttribute("VMCodeSectionName", vm_section_name_);

		if (!hwid_.empty())
			protection_node->SetAttribute("HWID", hwid_);
		else
			protection_node->RemoveAttribute("HWID");

		if (license_data_file_name_ != default_license_data_file_name()) {
			protection_node->SetAttribute("LicenseDataFileName", license_data_file_name_);
		} else {
			protection_node->RemoveAttribute("LicenseDataFileName");
		}

		if (output_file_name_ != default_output_file_name()) {
			protection_node->SetAttribute("OutputFileName", output_file_name_);
		} else {
			protection_node->RemoveAttribute("OutputFileName");
		}

		if (!watermark_name_.empty()) {
			protection_node->SetAttribute("WaterMarkName", watermark_name_);
		} else {
			protection_node->RemoveAttribute("WaterMarkName");
		}

		TiXmlElement *messages_node = protection_node->FirstChildElement("Messages");
		if (!messages_node) {
			messages_node = new TiXmlElement("Messages");
			protection_node->LinkEndChild(messages_node);
		} else {
			messages_node->Clear();
		}

		for (i = 0; i < _countof(messages_); i++) {
			std::string message = messages_[i];
			if (message != 
#ifdef VMP_GNU
				default_message[i]
#else
				os::ToUTF8(default_message[i])
#endif
				) {
				TiXmlElement *message_node = new TiXmlElement("Message");
				messages_node->LinkEndChild(message_node);
				message_node->SetAttribute("Id", (int)i);
				message_node->LinkEndChild(new TiXmlText(message));
			}
		}

		TiXmlElement *folders_node = protection_node->FirstChildElement("Folders");
		if (!folders_node) {
			folders_node = new TiXmlElement("Folders");
			protection_node->LinkEndChild(folders_node);
		} else {
			folders_node->Clear();
		}
		std::vector<Folder*> folder_list = input_file_->folder_list()->GetFolderList(true);
		for (i = 0; i < folder_list.size(); i++) {
			Folder *folder = folder_list[i];

			TiXmlElement *folder_node = new TiXmlElement("Folder");
			folders_node->LinkEndChild(folder_node);
			folder_node->SetAttribute("Name", folder->name());
			std::vector<Folder*>::const_iterator it = std::find(folder_list.begin(), folder_list.end(), folder->owner());
			if (it != folder_list.end())
				folder_node->SetAttribute("Parent", (int)(it - folder_list.begin()));
		}

		TiXmlElement *procedures_node = protection_node->FirstChildElement("Procedures");
		if (!procedures_node) {
			procedures_node = new TiXmlElement("Procedures");
			protection_node->LinkEndChild(procedures_node);
		} else {
			procedures_node->Clear();
		}
		std::map<Data, std::map<IArchitecture*, std::vector<IFunction*> > > function_map;
		std::map<IFunction*, size_t> function_index;
		size_t arch_count = input_file_->visible_count();
		bool show_arch_name = input_file_->function_list()->show_arch_name();
		for (k = 0; k < input_file_->count(); k++) {
			IArchitecture *arch = input_file_->item(k);
			if (!arch->visible())
				continue;

			for (i = 0; i < arch->function_list()->count(); i++) {
				IFunction *function = arch->function_list()->item(i);
				if (function->name().empty())
					continue;

				Data hash = function->hash();
				std::map<Data, std::map<IArchitecture*, std::vector<IFunction*> > >::iterator it = function_map.find(hash);
				if (it == function_map.end()) {
					function_map[hash][arch].push_back(function);
				} else {
					it->second[arch].push_back(function);
				}
			}
		}

		for (std::map<Data, std::map<IArchitecture*, std::vector<IFunction*> > >::iterator it = function_map.begin(); it != function_map.end(); it++) {
			for (std::map<IArchitecture*, std::vector<IFunction*> >::iterator arch_it = it->second.begin(); arch_it != it->second.end(); arch_it++) {
				IArchitecture *arch = arch_it->first;
				std::vector<uint64_t> address_list;
				for (i = 0; i < arch_it->second.size(); i++) {
					IFunction *function = arch_it->second[i];
					if (i == 0)
						address_list = arch->map_function_list()->GetAddressListByName(function->name(), true);
					if (function->type() == otUnknown) {
						function_index[function] = (function->tag() == 0xff) ? -1 : function->tag();
					} else {
						if (address_list.size() == arch_it->second.size()) {
							function_index[function] = -1;
						} else {
							std::vector<uint64_t>::iterator address_it = std::find(address_list.begin(), address_list.end(), function->address());
							if (address_it != address_list.end())
								function_index[function] = address_it - address_list.begin();
						}
					}
				}
			}
		}

		std::string arch_name;
		size_t first_arch_index = -1;
		for (k = 0; k < input_file_->count(); k++) {
			IArchitecture *arch = input_file_->item(k);
			if (!arch->visible())
				continue;

			if (first_arch_index == NOT_ID)
				first_arch_index = k;

			for (i = 0; i < arch->function_list()->count(); i++) {
				IFunction *function = arch->function_list()->item(i);

				size_t map_index = -1;
				arch_name = arch->name();
				if (!function->name().empty()) {
					std::map<IFunction*, size_t>::iterator index_it = function_index.find(function);
					if (index_it == function_index.end())
						continue;

					map_index = index_it->second;
					std::map<Data, std::map<IArchitecture*, std::vector<IFunction*> > >::iterator it = function_map.find(function->hash());
					if (it != function_map.end()) {
						if (it->second.empty() || it->second[arch].empty())
							continue;

						if (show_arch_name) {
							if (it->second.size() == arch_count && k == first_arch_index) {
								bool is_equal = true;
								std::vector<size_t> source_index_list;
								for (std::map<IArchitecture*, std::vector<IFunction*> >::iterator arch_it = it->second.begin(); arch_it != it->second.end(); arch_it++) {
									std::vector<size_t> index_list;
									for (j = 0; j < it->second[arch].size(); j++) {
										index_it = function_index.find(function);
										if (index_it != function_index.end()) {
											index_list.push_back(index_it->second);
											if (index_it->second == NOT_ID)
												break;
										}
									}
									if (source_index_list.empty())
										source_index_list = index_list;
									else {
										if (source_index_list.size() == index_list.size()) {
											for (j = 0; j < source_index_list.size(); j++) {
												if (std::find(index_list.begin(), index_list.end(), source_index_list[j]) == index_list.end()) {
													is_equal = false;
													break;
												}
											}
										} else 
											is_equal = false;
										if (!is_equal)
											break;
									}
								}

								if (is_equal) {
									it->second.clear();
									arch_name.clear();
								}
							}
						}

						if (map_index == NOT_ID && !it->second.empty())
							it->second[arch].clear();
					}
				}

				TiXmlElement *procedure_node = new TiXmlElement("Procedure");
				procedures_node->LinkEndChild(procedure_node);

				if (show_arch_name && !arch_name.empty())
					procedure_node->SetAttribute("Architecture", arch_name);

				if (function->name().empty()) {
					procedure_node->SetAttribute("Address", string_format("%llu", function->address()));
				} else {
					procedure_node->SetAttribute("MapAddress", function->name());
					if (map_index != NOT_ID)
						procedure_node->SetAttribute("Index", (int)map_index);
				}

				if (!function->need_compile())
					procedure_node->SetAttribute("IncludedInCompilation", function->need_compile());

				procedure_node->SetAttribute("Options", function->compilation_options());

				std::vector<Folder*>::const_iterator it = std::find(folder_list.begin(), folder_list.end(), function->folder());
				if (it != folder_list.end())
					procedure_node->SetAttribute("Folder", (int)(it - folder_list.begin()));

				if (function->compilation_type() != ctVirtualization)
					procedure_node->SetAttribute("CompilationType", function->compilation_type());

				if (function->break_address())
					procedure_node->SetAttribute("BreakOffset", static_cast<int>(function->break_address() - function->address()));

				for (j = 0; j < function->ext_command_list()->count(); j++) {
					TiXmlElement *ext_command_node = new TiXmlElement("ExtOffset");
					procedure_node->LinkEndChild(ext_command_node);
					ext_command_node->LinkEndChild(new TiXmlText(string_format("%d", static_cast<int>(function->ext_command_list()->item(j)->address() - function->address()))));
				}
			}
		}

		TiXmlElement *objects_node = protection_node->FirstChildElement("Objects");
		if (!objects_node) {
			objects_node = new TiXmlElement("Objects");
			protection_node->LinkEndChild(objects_node);
		} else {
			objects_node->Clear();
		}

		std::map<Data, size_t> segment_map;
		std::map<Data, size_t> resource_map;
		std::map<Data, size_t> import_map;
		if (show_arch_name) {
			for (k = 0; k < input_file_->count(); k++) {
				IArchitecture *arch = input_file_->item(k);
				if (!arch->visible())
					continue;

				for (i = 0; i < arch->segment_list()->count(); i++) {
					ISection *segment = arch->segment_list()->item(i);
					if (!segment->excluded_from_packing() && !segment->excluded_from_memory_protection())
						continue;

					Data hash = segment->hash();
					std::map<Data, size_t>::iterator it = segment_map.find(hash);
					if (it == segment_map.end())
						segment_map[hash] = 1;
					else
						it->second++;
				}

				if (arch->resource_list()) {
					std::vector<IResource*> resource_list = arch->resource_list()->GetResourceList();
					for (i = 0; i < resource_list.size(); i++) {
						IResource *resource = resource_list[i];
						if (!resource->excluded_from_packing())
							continue;

						Data hash = resource->hash();
						std::map<Data, size_t>::iterator it = resource_map.find(hash);
						if (it == resource_map.end())
							resource_map[hash] = 1;
						else
							it->second++;
					}
				}

				for (i = 0; i < arch->import_list()->count(); i++) {
					IImport *import = arch->import_list()->item(i);
					if (!import->excluded_from_import_protection())
						continue;

					Data hash = import->hash();
					std::map<Data, size_t>::iterator it = import_map.find(hash);
					if (it == import_map.end())
						import_map[hash] = 1;
					else
						it->second++;
				}
			}
		}

		for (k = 0; k < input_file_->count(); k++) {
			IArchitecture *arch = input_file_->item(k);
			if (!arch->visible())
				continue;

			for (i = 0; i < arch->segment_list()->count(); i++) {
				ISection *segment = arch->segment_list()->item(i);
				if (!segment->excluded_from_packing() && !segment->excluded_from_memory_protection())
					continue;

				if (show_arch_name) {
					arch_name = arch->name();
					std::map<Data, size_t>::iterator it = segment_map.find(segment->hash());
					if (it != segment_map.end()) {
						if (it->second == 0)
							continue;
						if (it->second == arch_count) {
							it->second = 0;
							arch_name.clear();
						}
					}
				}

				TiXmlElement *object_node = new TiXmlElement("Object");
				objects_node->LinkEndChild(object_node);

				if (show_arch_name && !arch_name.empty())
					object_node->SetAttribute("Architecture", arch_name);

				object_node->SetAttribute("Type", "Segment");
				object_node->SetAttribute("Name", segment->name());
				if (segment->excluded_from_packing())
					object_node->SetAttribute("ExcludedFromPacking", segment->excluded_from_packing());
				if (segment->excluded_from_memory_protection())
					object_node->SetAttribute("ExcludedFromMemoryProtection", segment->excluded_from_memory_protection());
			}

			if (arch->resource_list()) {
				std::vector<IResource*> resource_list = arch->resource_list()->GetResourceList();
				for (i = 0; i < resource_list.size(); i++) {
					IResource *resource = resource_list[i];
					if (!resource->excluded_from_packing())
						continue;

					if (show_arch_name) {
						arch_name = arch->name();
						std::map<Data, size_t>::iterator it = resource_map.find(resource->hash());
						if (it != resource_map.end()) {
							if (it->second == 0)
								continue;
							if (it->second == arch_count) {
								it->second = 0;
								arch_name.clear();
							}
						}
					}

					TiXmlElement *object_node = new TiXmlElement("Object");
					objects_node->LinkEndChild(object_node);

					if (show_arch_name && !arch_name.empty())
						object_node->SetAttribute("Architecture", arch_name);

					object_node->SetAttribute("Type", "Resource");
					object_node->SetAttribute("Name", resource->id());
					object_node->SetAttribute("ExcludedFromPacking", resource->excluded_from_packing());
				}
			}

			for (i = 0; i < arch->import_list()->count(); i++) {
				IImport *import = arch->import_list()->item(i);
				if (!import->excluded_from_import_protection())
					continue;

				if (show_arch_name) {
					arch_name = arch->name();
					std::map<Data, size_t>::iterator it = import_map.find(import->hash());
					if (it != import_map.end()) {
						if (it->second == 0)
							continue;
						if (it->second == arch_count) {
							it->second = 0;
							arch_name.clear();
						}
					}
				}

				TiXmlElement *object_node = new TiXmlElement("Object");
				objects_node->LinkEndChild(object_node);

				if (show_arch_name && !arch_name.empty())
					object_node->SetAttribute("Architecture", arch_name);

				object_node->SetAttribute("Type", "Import");
				object_node->SetAttribute("Name", import->name());
				if (import->excluded_from_import_protection())
					object_node->SetAttribute("ExcludedFromImportProtection", import->excluded_from_import_protection());
			}
		}

		{
			TiXmlElement *files_node = root_node->FirstChildElement("DLLBox");
			if (!files_node) {
				files_node = new TiXmlElement("DLLBox");
				root_node->LinkEndChild(files_node);
			} else {
				files_node->Clear();
			}

			folders_node = new TiXmlElement("Folders");
			files_node->LinkEndChild(folders_node);
			std::vector<FileFolder*> folder_list = file_manager_->folder_list()->GetFolderList();
			for (i = 0; i < folder_list.size(); i++) {
				FileFolder *folder = folder_list[i];

				TiXmlElement *folder_node = new TiXmlElement("Folder");
				folders_node->LinkEndChild(folder_node);
				folder_node->SetAttribute("Name", folder->name());
				std::vector<FileFolder*>::const_iterator it = std::find(folder_list.begin(), folder_list.end(), folder->owner());
				if (it != folder_list.end())
					folder_node->SetAttribute("Parent", (int)(it - folder_list.begin()));
			}

			if (!file_manager_->need_compile())
				files_node->SetAttribute("IncludedInCompilation", file_manager_->need_compile());
			else
				files_node->RemoveAttribute("IncludedInCompilation");

			for (i = 0; i < file_manager_->count(); i++) {
				InternalFile *file = file_manager_->item(i);
				TiXmlElement *file_node = new TiXmlElement("DLL");
				files_node->LinkEndChild(file_node);
				file_node->SetAttribute("Name", file->name());
				file_node->SetAttribute("FileName", file->file_name());
				int options;
				switch (file->action()) {
				case faLoad:
					options = 1;
					break;
				case faRegister:
					options = 2;
					break;
				case faInstall:
					options = 4;
					break;
				default:
					options = 0;
					break;
				}
				if (options)
					file_node->SetAttribute("Options", options);
				std::vector<FileFolder*>::const_iterator it = std::find(folder_list.begin(), folder_list.end(), file->folder());
				if (it != folder_list.end())
					file_node->SetAttribute("Folder", (int)(it - folder_list.begin()));
			}
		}

		TiXmlElement *script_node = root_node->FirstChildElement("Script");
		if (!script_node) {
			script_node = new TiXmlElement("Script");
			root_node->LinkEndChild(script_node);
		} else {
			script_node->Clear();
		}
		if (!script_->need_compile())
			script_node->SetAttribute("IncludedInCompilation", script_->need_compile());
		else
			script_node->RemoveAttribute("IncludedInCompilation");

		if (!script_->text().empty())
		{
			std::string st = script_->text();
			st.erase(std::remove(st.begin(), st.end(), '\r'), st.end());
			TiXmlText *stn = new TiXmlText(st);
			stn->SetCDATA(true); //readability improved
			script_node->LinkEndChild(stn);
		}

		if (!doc.SaveFile(project_file_name_.c_str()))
		return false;
	}

	licensing_manager_->Save();

	return true;
}

void Core::Close()
{
	input_file_name_.clear();
	output_file_name_.clear();
	watermark_name_.clear();
	script_->clear();
	script_->set_need_compile(true);
	hwid_.clear();
	licensing_manager_->clear();
	file_manager_->clear();
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
	if (!script_->Compile())
		return false;

	Watermark *watermark = NULL;
	if (!watermark_name_.empty()) {
		watermark = watermark_manager_->GetWatermarkByName(watermark_name_);
		if (!watermark) {
			Notify(mtError, watermark_manager_, string_format(language[lsWatermarkNotFound].c_str(), watermark_name_.c_str()));
			return false;
		}
		if (!watermark->enabled()) {
			Notify(mtError, watermark_manager_, string_format(language[lsWatermarkIsDisabled].c_str(), watermark_name_.c_str()));
			return false;
		}
	}

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


	options.watermark = watermark;
	options.script = script_;
	options.architecture = &output_architecture_;
	options.hwid = hwid_;
	options.licensing_manager = licensing_manager_;
	if (file_manager_->need_compile() && file_manager_->count())
		options.file_manager = file_manager_;

	if (log_)
		log_->StartProgress(string_format("%s...", language[lsCompiling].c_str()), 1);

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
			language[lsOutputFileSize].c_str(), 
			output_file_size, 
			static_cast<int>(100.0 * output_file_size / input_file_->size())
			));

		if (options.script)
			options.script->DoAfterCompilation();
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
			throw std::runtime_error(string_format(language[lsOpenFileError].c_str(), output_file_name.c_str()));

		output_file_name = os::GetTempFilePathNameFor(output_file_name.c_str());
		if (output_file_name.empty())
			throw std::runtime_error(string_format(language[lsCreateFileError].c_str(), "'temporary'"));
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
				throw std::runtime_error(string_format(language[lsCreateFileError].c_str(), final_file.c_str()));
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

void Core::set_watermark_name(const std::string &watermark_name)
{ 
	if (watermark_name_ != watermark_name) {
		watermark_name_ = watermark_name;
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
	if (sender) {
		Watermark *watermark = dynamic_cast<Watermark *>(sender);
		if (watermark) {
			switch (type) {
			case mtAdded:
			case mtChanged:
				watermark->SaveToFile(settings_file());
				break;
			case mtDeleted:
				watermark->DeleteFromFile(settings_file());
				break;
			default:
				// do nothing
				break;
			}
		}
		ProjectTemplate *pt = dynamic_cast<ProjectTemplate *>(sender);
		if (pt) {
			switch (type) {
			case mtAdded:
			case mtChanged:
			case mtDeleted:
				template_manager_->SaveToFile(settings_file());
				break;
			default:
				// do nothing
				break;
			}
		}
	}
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
