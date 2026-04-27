#include "project_template.h"

#include "../lang.h"
#include "../osutils.h"
#include "../files.h"
#include "../inifile.h"
#include "core.h"

extern const VMP_CHAR *default_message[MESSAGE_COUNT];

ProjectTemplateManager::ProjectTemplateManager(Core *owner) : ObjectList<ProjectTemplate>(), owner_(owner)
{
	ProjectTemplate *pt = new ProjectTemplate(this, ProjectTemplate::default_name(), true);
	AddObject(pt);
}

void ProjectTemplateManager::ReadFromFile(SettingsFile &file)
{
	TiXmlElement *node = file.root_node();
	TiXmlElement *templates_node = node->FirstChildElement("Templates");
	if (templates_node) {
		TiXmlElement *template_node = templates_node->FirstChildElement("Template");
		while (template_node) {
			std::string name;
			template_node->QueryStringAttribute("Name", &name);
			ProjectTemplate *pt;
			if (name == ProjectTemplate::default_name())
				pt = item(0);
			else {
				pt = new ProjectTemplate(this, name);
				AddObject(pt);
			}
			pt->ReadFromNode(template_node);
			template_node = template_node->NextSiblingElement();
		}
	}
}

void ProjectTemplateManager::SaveToFile(SettingsFile &file) const
{
	TiXmlElement *node = file.root_node();
	TiXmlElement *templates_node = node->FirstChildElement("Templates");
	if (!templates_node) {
		templates_node = new TiXmlElement("Templates");
		node->LinkEndChild(templates_node);
	} else {
		templates_node->Clear();
	}

	for (size_t i = 0; i < count(); i++) {
		TiXmlElement *template_node = new TiXmlElement("Template");
		templates_node->LinkEndChild(template_node);
		template_node->SetAttribute("Name", item(i)->name());
		item(i)->SaveToNode(template_node);
	}
	file.Save();
}

void ProjectTemplateManager::Add(const std::string &name, const Core &core)
{
	ProjectTemplate *pt = NULL;
	if (name == item(0)->display_name())
		pt = item(0);
	else for (size_t i = 0; i < count(); i++) {
		if (item(i)->name() == name) {
			pt = item(i);
			break;
		}
	}
	if (!pt) {
		pt = new ProjectTemplate(this, name);
		AddObject(pt);
		Notify(mtAdded, pt);
	}
	pt->ReadFromCore(core);
}

void ProjectTemplateManager::Notify(MessageType type, IObject *sender, const std::string &message) const
{
	if (owner_)
		owner_->Notify(type, sender, message);
}

void ProjectTemplateManager::RemoveObject(ProjectTemplate *pt)
{
	ObjectList<ProjectTemplate>::RemoveObject(pt);
	Notify(mtDeleted, pt);
}

ProjectTemplate::ProjectTemplate(ProjectTemplateManager *owner, const std::string &name, bool is_default) 
	: IObject(), owner_(owner), name_(name), options_(0), is_default_(is_default)
{
	Init();
}

ProjectTemplate::~ProjectTemplate()
{
	if (owner_)
		owner_->RemoveObject(this);
}

void ProjectTemplate::ReadFromNode(TiXmlElement *node)
{
	unsigned u = options_;
	node->QueryUnsignedAttribute("Options", &u);
	options_ = u;
	bool check_kernel_debugger = false;
	node->QueryBoolAttribute("CheckKernelDebugger", &check_kernel_debugger);
	if (check_kernel_debugger)
		options_ |= cpCheckKernelDebugger;
	node->QueryStringAttribute("VMCodeSectionName", &vm_section_name_);

	TiXmlElement *messages_node = node->FirstChildElement("Messages");
	if (messages_node) {
		TiXmlElement *message_node = messages_node->FirstChildElement("Message");
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
}

void ProjectTemplate::ReadFromCore(const Core &core)
{
	options_ = core.options();
	vm_section_name_ = core.vm_section_name();
	for (size_t i = 0; i < _countof(messages_); i++) {
		messages_[i] = core.message(i);
	}

	Notify(mtChanged, this);
}

void ProjectTemplate::SaveToNode(TiXmlElement *node) const
{
	node->SetAttribute("Options", options_);
	node->SetAttribute("VMCodeSectionName", vm_section_name_);

	TiXmlElement *messages_node = node->FirstChildElement("Messages");
	if (!messages_node) {
		messages_node = new TiXmlElement("Messages");
		node->LinkEndChild(messages_node);
	} else {
		messages_node->Clear();
	}

	for (size_t i = 0; i < _countof(messages_); i++) {
		const std::string &message = messages_[i];
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
}

void ProjectTemplate::Init()
{
	options_ = cpMaximumProtection;

	// create random section name
	vm_section_name_ = ".";
	size_t i;
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";
	srand(os::GetTickCount());
	for (i = 0; i < 3; i++) {
		vm_section_name_ += alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	for (i = 0; i < _countof(messages_); i++) {
#ifdef VMP_GNU
		messages_[i] = default_message[i];
#else
		messages_[i] = os::ToUTF8(default_message[i]);
#endif
	}
}

void ProjectTemplate::Reset()
{
	Init();
	Notify(mtChanged, this);
}

bool ProjectTemplate::operator==(const ProjectTemplate &other) const
{
	if (options_ != other.options_)
		return false;
	if (vm_section_name_ != other.vm_section_name_)
		return false;
	for (size_t i = 0; i < _countof(messages_); i++)
	{
		if(messages_[i] != other.messages_[i])
			return false;
	}
	return true;
}

std::string ProjectTemplate::display_name() const
{
	return is_default_ ? "(" + language[lsDefault] + ")" : name_;
}

std::string ProjectTemplate::message(size_t idx) const
{
   if (idx >= _countof(messages_))
       throw std::runtime_error("subscript out of range");
   return messages_[idx];
}

void ProjectTemplate::Notify(MessageType type, IObject *sender, const std::string &message /*= ""
*/) const
{
	if (owner_)
		owner_->Notify(type, sender, message);
}

void ProjectTemplate::set_name(const std::string &name)
{
	if (name != name_) {
		name_ = name;
		Notify(mtChanged, this);
	}
}
