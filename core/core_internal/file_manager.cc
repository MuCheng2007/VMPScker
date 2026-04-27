#include "file_manager.h"

#include "../lang.h"
#include "../osutils.h"
#include "../streams.h"
#include "../processors.h"

#include "core.h"

#ifdef _WIN32
#include <intrin.h>
// _rotl32 intrinsic might need this on some compiler versions
#ifndef _rotl32
#define _rotl32(x, n) ((x) << (n) | (x) >> (32 - (n)))
#endif
#endif

FileFolder::FileFolder(FileFolder *owner, const std::string &name)
	: ObjectList<FileFolder>(), owner_(owner), name_(name), entry_offset_(0)
{

}

FileFolder::~FileFolder()
{
	clear();
	if (owner_)
		owner_->RemoveObject(this);
	Notify(mtDeleted, this);
}

FileFolder::FileFolder(FileFolder *owner, const FileFolder &src)
	: ObjectList<FileFolder>(src), owner_(owner), entry_offset_(0)
{
	name_ = src.name_;

	for (size_t i = 0; i < src.count(); i++) {
		AddObject(src.item(i)->Clone(this));
	}
}

FileFolder *FileFolder::Clone(FileFolder *owner) const
{
	FileFolder *folder = new FileFolder(owner, *this);
	return folder;
}

FileFolder *FileFolder::Add(const std::string &name)
{
	FileFolder *folder = new FileFolder(this, name);
	AddObject(folder);
	Notify(mtAdded, folder);
	return folder;
}

void FileFolder::changed()
{
	Notify(mtChanged, this);
}

std::string FileFolder::id() const
{
	std::string res;
	const FileFolder *folder = this;
	while (folder->owner_) {
		res = res + string_format("\\%d", folder->owner_->IndexOf(folder));
		folder = folder->owner_;
	}
	return res;
}

void FileFolder::set_name(const std::string &name)
{
	if (name_ != name) {
		name_ = name;
		changed();
	}
}

void FileFolder::set_owner(FileFolder *owner)
{
	if (owner == owner_)
		return;
	if (owner_)
		owner_->RemoveObject(this);
	owner_ = owner;
	if (owner_)
		owner_->AddObject(this);
	changed();
}

void FileFolder::Notify(MessageType type, IObject *sender, const std::string &message) const
{
	if (owner_)
		owner_->Notify(type, sender, message);
}

FileFolder *FileFolder::GetFolderById(const std::string &id) const
{
	if (this->id() == id)
		return (FileFolder *)this;
	for (size_t i = 0; i < count(); i++) {
		FileFolder *res = item(i)->GetFolderById(id);
		if (res)
			return res;
	}
	return NULL;
}

void FileFolder::WriteEntry(IFunction &func)
{
	entry_offset_ = func.count();
	func.AddCommand(osDWord, 0);
	func.AddCommand(osDWord, 0);
	func.AddCommand(osDWord, 0);
	func.AddCommand(osDWord, 0);
}

void FileFolder::WriteName(IFunction &func, uint64_t image_base, uint32_t key)
{
	std::string full_name = name_;
	FileFolder *folder = owner_;
	while (folder && folder->owner()) {
		full_name = folder->name() + '\\' + full_name;
		folder = folder->owner();
	}
	os::unicode_string unicode_name = os::FromUTF8(full_name);
	const os::unicode_char *p = unicode_name.c_str();
	Data str;
	for (size_t i = 0; i < unicode_name.size() + 1; i++) {
		str.PushWord(static_cast<uint16_t>(p[i] ^ (_rotl32(key, static_cast<int>(i)) + i)));
	}
	ICommand *command = func.AddCommand(str);
	command->include_option(roCreateNewBlock);

	CommandLink *link = func.item(entry_offset_)->AddLink(0, ltOffset, command);
	link->set_sub_value(image_base);
}

FileFolderList::FileFolderList(FileManager *owner)
	: FileFolder(NULL, ""), owner_(owner)
{

}

FileFolderList::FileFolderList(FileManager *owner, const FileFolderList & /*src*/)
	: FileFolder(NULL, ""), owner_(owner)
{

}

FileFolderList *FileFolderList::Clone(FileManager *owner) const
{
	FileFolderList *list = new FileFolderList(owner, *this);
	return list;
}

std::vector<FileFolder*> FileFolderList::GetFolderList() const
{
	std::vector<FileFolder*> res;
	FileFolder *folder;
	size_t i, j;

	for (i = 0; i < count(); i++) {
		res.push_back(item(i));
	}
	for (i = 0; i < res.size(); i++) {
		folder = res[i];
		for (j = 0; j < folder->count(); j++) {
			res.push_back(folder->item(j));
		}
	}
	return res;
}

void FileFolderList::Notify(MessageType type, IObject *sender, const std::string &message) const
{
	if (owner_) {
		if (type == mtDeleted) {
			for (size_t i = owner_->count(); i > 0; i--) {
				InternalFile *file = owner_->item(i - 1);
				if (file->folder() == sender)
					delete file;
			}
		}
		owner_->Notify(type, sender, message);
	}
}

InternalFile::InternalFile(FileManager *owner, const std::string &name, const std::string &file_name, InternalFileAction action, FileFolder *folder)
	: owner_(owner), name_(name), file_name_(file_name), action_(action), stream_(NULL), entry_offset_(0), folder_(folder)
{

}

InternalFile::~InternalFile()
{
	Close();
	if (owner_)
		owner_->RemoveObject(this);
	Notify(mtDeleted, this);
}

void InternalFile::set_name(const std::string &value)
{
	if (name_ != value) {
		name_ = value;
		Notify(mtChanged, this);
	}
}

void InternalFile::set_file_name(const std::string &value)
{
	if (file_name_ != value) {
		file_name_ = value;
		Notify(mtChanged, this);
	}
}

void InternalFile::set_action(InternalFileAction action)
{ 
	if (action_ != action) {
		action_ = action;
		Notify(mtChanged, this);
	}
}

void InternalFile::set_folder(FileFolder *folder)
{
	if (folder_ != folder) {
		folder_ = folder;
		Notify(mtChanged, this);
	}
}

size_t InternalFile::id() const 
{ 
	return owner_->IndexOf(this); 
}

void InternalFile::Notify(MessageType type, IObject *sender, const std::string &message) const
{
	if (owner_)
		owner_->Notify(type, sender, message);
}

std::string InternalFile::absolute_file_name() const
{
	std::string project_path = owner_ ? owner_->owner()->project_path() : std::string();
	return os::CombinePaths(project_path.c_str(), os::ExpandEnvironmentVariables(file_name_.c_str()).c_str());
}

bool InternalFile::Open()
{
	Close();
	std::string file_name = absolute_file_name();
	FileStream *stream = new FileStream();
	if (stream->Open(file_name.c_str(), fmOpenRead | fmShareDenyWrite)) {
		stream_ = stream;
	} else {
		delete stream;
		Notify(mtError, this, string_format(language[lsOpenFileError].c_str(), file_name.c_str()));
	}
	return stream_ != NULL;
}

void InternalFile::Close()
{
	if (stream_) {
		delete stream_;
		stream_ = NULL;
	}
}

void InternalFile::WriteEntry(IFunction &func)
{
	entry_offset_ = func.count();
	func.AddCommand(osDWord, 0);
	func.AddCommand(osDWord, 0);
	func.AddCommand(osDWord, stream_->Size());
	uint32_t value;
	switch (action_) {
	case faLoad:
		value = FILE_LOAD;
		break;
	case faRegister:
		value = FILE_REGISTER;
		break;
	case faInstall:
		value = FILE_INSTALL;
		break;
	default:
		value = 0;
		break;
	}
	func.AddCommand(osDWord, value);
}

void InternalFile::WriteName(IFunction &func, uint64_t image_base, uint32_t key)
{
	std::string full_name = name_;
	FileFolder *folder = folder_;
	while (folder && folder->owner()) {
		full_name = folder->name() + '\\' + full_name;
		folder = folder->owner();
	}
	os::unicode_string unicode_name = os::FromUTF8(full_name);
	const os::unicode_char *p = unicode_name.c_str();
	Data str;
	for (size_t i = 0; i < unicode_name.size() + 1; i++) {
		str.PushWord(static_cast<uint16_t>(p[i] ^ (_rotl32(key, static_cast<int>(i)) + i)));
	}
	ICommand *command = func.AddCommand(str);
	command->include_option(roCreateNewBlock);

	CommandLink *link = func.item(entry_offset_)->AddLink(0, ltOffset, command);
	link->set_sub_value(image_base);
}

void InternalFile::WriteData(IFunction &func, uint64_t image_base, uint32_t key)
{
	std::vector<uint8_t> buf;
	buf.resize(static_cast<size_t>(stream_->Size()));
	stream_->Read(&buf[0], buf.size());

	Data d;
	for (size_t i = 0; i < buf.size(); i++) {
		d.PushByte(buf[i] ^ static_cast<uint8_t>(_rotl32(key, static_cast<int>(i)) + i));
	}

	ICommand *command = func.AddCommand(d);
	command->include_option(roCreateNewBlock);

	CommandLink *link = func.item(entry_offset_ + 1)->AddLink(0, ltOffset, command);
	link->set_sub_value(image_base);
}

FileManager::FileManager(Core *owner)
	: ObjectList<InternalFile>(), owner_(owner), need_compile_(true)
{
	folder_list_ = new FileFolderList(this);
}

FileManager::~FileManager()
{
	delete folder_list_;
}

void FileManager::clear()
{
	ObjectList<InternalFile>::clear();
	folder_list_->clear();
}

InternalFile *FileManager::Add(const std::string &name, const std::string &file_name, InternalFileAction action, FileFolder *folder)
{
	InternalFile *file = new InternalFile(this, name, file_name, action, folder);
	AddObject(file);
	Notify(mtAdded, file);
	return file;
}

bool FileManager::OpenFiles()
{
	bool res = true;
	for (size_t i = 0; i < count(); i++) {
		InternalFile *file = item(i);
		if (!file->Open()) {
			res = false;
			break;
		}
	}
	if (!res)
		CloseFiles();
	return res;
}

void FileManager::CloseFiles() 
{
	for (size_t i = 0; i < count(); i++) {
		InternalFile *file = item(i);
		file->Close();
	}
}

void FileManager::Notify(MessageType type, IObject *sender, const std::string &message) const
{
	if (owner_)
		owner_->Notify(type, sender, message);
}

void FileManager::set_need_compile(bool need_compile)
{ 
	if (need_compile_ != need_compile) {
		need_compile_ = need_compile;
		Notify(mtChanged, this);
	}
}

uint32_t FileManager::GetRuntimeOptions() const
{
	if (!count())
		return roNone;

	uint32_t res = roBundler;
	if (server_count())
		res |= roRegistry;
	return res;
}

size_t FileManager::server_count() const
{
	size_t res = 0;
	for (size_t i = 0; i < count(); i++) {
		if (item(i)->is_server())
			res++;
	}
	return res;
}
