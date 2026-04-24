#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include "../../runtime/common.h"
#include "../objects.h"
#include "../processors.h"

class Core;
class FileManager;
class FileStream;

// LinkType, RuntimeOptions, FILE_LOAD, FILE_REGISTER, FILE_INSTALL are defined in processors.h

class FileFolder : public ObjectList<FileFolder>
{
public:
	explicit FileFolder(FileFolder *owner, const std::string &name);
	explicit FileFolder(FileFolder *owner, const FileFolder &src);
	virtual ~FileFolder();
	FileFolder *Clone(FileFolder *owner) const;
	FileFolder *Add(const std::string &name);
	std::string name() const { return name_; }
	FileFolder *owner() const { return owner_; }
	void set_name(const std::string &name);
	void set_owner(FileFolder *owner);
	virtual void Notify(MessageType type, IObject *sender, const std::string &message = "") const;
	std::string id() const;
	FileFolder *GetFolderById(const std::string &id) const;
	void WriteEntry(IFunction &data);
	void WriteName(IFunction &data, uint64_t image_base, uint32_t key);
	using IObject::CompareWith;
private:
	void changed();
	FileFolder *owner_;
	std::string name_;
	size_t entry_offset_;
};

class FileFolderList : public FileFolder
{
public:
	explicit FileFolderList(FileManager *owner);
	explicit FileFolderList(FileManager *owner, const FileFolderList &src);
	FileFolderList *Clone(FileManager *owner) const;
	std::vector<FileFolder*> GetFolderList() const;
	virtual void Notify(MessageType type, IObject *sender, const std::string &message = "") const;
	FileManager *owner() const { return owner_; }
private:
	FileManager *owner_;
};

enum InternalFileAction {
	faNone,
	faLoad,
	faRegister,
	faInstall
};

class InternalFile : public IObject
{
public:
	InternalFile(FileManager *owner, const std::string &name, const std::string &file_name, InternalFileAction action, FileFolder *folder);
	~InternalFile();
	std::string name() const { return name_; }
	std::string file_name() const { return file_name_; }
	std::string absolute_file_name() const;
	void set_name(const std::string &value);
	void set_file_name(const std::string &value);
	bool Open();
	void Close();
	virtual void WriteEntry(IFunction &func);
	virtual void WriteName(IFunction &func, uint64_t image_base, uint32_t key);
	virtual void WriteData(IFunction &func, uint64_t image_base, uint32_t key);
	void Notify(MessageType type, IObject *sender, const std::string &message = "") const;
	FileManager *owner() const { return owner_; }
	InternalFileAction action() const { return action_; }
	void set_action(InternalFileAction action);
	bool is_server() const { return (action_ == faRegister || action_ == faInstall); }
	FileFolder *folder() const { return folder_; }
	void set_folder(FileFolder *folder);
	size_t id() const;
	FileStream *stream() const { return stream_; }
private:
	FileManager *owner_;
	std::string name_;
	std::string file_name_;
	InternalFileAction action_;
	FileStream *stream_;
	size_t entry_offset_;
	FileFolder *folder_;

	// no copy ctr or assignment op
	InternalFile(const InternalFile &);
	InternalFile &operator =(const InternalFile &);
};

class FileManager : public ObjectList<InternalFile>
{
public:
	FileManager(Core *owner);
	~FileManager();
	virtual void clear();
	bool need_compile() const { return need_compile_; }
	void set_need_compile(bool need_compile);
	InternalFile *Add(const std::string &name, const std::string &file_name, InternalFileAction action, FileFolder *folder);
	bool OpenFiles();
	void CloseFiles();
	void Notify(MessageType type, IObject *sender, const std::string &message = "") const;
	Core *owner() const { return owner_; }
	uint32_t GetRuntimeOptions() const;
	size_t server_count() const;
	FileFolderList *folder_list() const { return folder_list_; }
private:
	Core *owner_;
	bool need_compile_;
	FileFolderList *folder_list_;

	// no copy ctr or assignment op
	FileManager(const FileManager &);
	FileManager &operator =(const FileManager &);
};

#endif
