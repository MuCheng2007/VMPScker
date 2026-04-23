#ifndef PROJECT_TEMPLATE_H
#define PROJECT_TEMPLATE_H

#include "../../runtime/common.h"
#include "../objects.h"

class Core;
class ProjectTemplateManager;
class SettingsFile;

// ProjectOption enum is defined in core.h

class ProjectTemplate : public IObject
{
public:
	ProjectTemplate(ProjectTemplateManager *owner, const std::string &name, bool is_default = false);
	ProjectTemplate &operator =(const ProjectTemplate &);
	~ProjectTemplate();

	void Reset();
	void ReadFromCore(const Core &core);
	void ReadFromNode(TiXmlElement *node);
	void SaveToNode(TiXmlElement *node) const;

	bool is_default() const { return is_default_; }
	void set_is_default(bool is_default) { is_default_ = is_default; }
	std::string name() const { return name_; }
	std::string display_name() const;
	uint32_t options() const { return options_; }
	std::string vm_section_name() const { return vm_section_name_; }
	std::string message(size_t idx) const;
	void set_name(const std::string &name);
	static std::string default_name() { return "(default)"; }

	virtual void Notify(MessageType type, IObject *sender, const std::string &message = "") const;
	bool operator ==(const ProjectTemplate &other) const;
	bool operator !=(const ProjectTemplate &other) const { return !operator==(other); }
private:
	void Init();
	ProjectTemplateManager *owner_;
	bool is_default_;
	uint32_t options_;
	std::string name_, vm_section_name_;
	std::string messages_[MESSAGE_COUNT];

	// no copy ctr or assignment op
	ProjectTemplate(const ProjectTemplate &);
};

class ProjectTemplateManager : public ObjectList<ProjectTemplate>
{
public:
	ProjectTemplateManager(Core *owner);
	void ReadFromFile(SettingsFile &file);
	void SaveToFile(SettingsFile &file) const;
	void Add(const std::string &name, const Core &core);
	void Notify(MessageType type, IObject *sender, const std::string &message = "") const;
	void RemoveObject(ProjectTemplate *pt);
private:
	Core *owner_;

	// no copy ctr or assignment op
	ProjectTemplateManager(const ProjectTemplateManager &);
	ProjectTemplateManager &operator =(const ProjectTemplateManager &);
};

#endif
