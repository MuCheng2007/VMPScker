/**
 * PE File support.
 */

#include "../../runtime/common.h"
#include "../../runtime/crypto.h"
#include "../objects.h"
#include "../osutils.h"
#include "../streams.h"
#include "../files/architecture.h"
#include "../files/utils.h"
#include "PEFile.h"
#include "PEArchitecture.h"
#include "../processors.h"
#include "../core_internal/core.h"

#include "../pdb.h"

#include "../win_runtime32.dll.inc"
#include "../win_runtime64.dll.inc"
#include "../win_runtime32.sys.inc"
#include "../win_runtime64.sys.inc"

/**
 * PEFile
 */

PEFile::PEFile(ILog* log)
	: IFile(log), runtime_(NULL)
{

}

PEFile::PEFile(const PEFile& src, const char* file_name)
	: IFile(src, file_name), runtime_(NULL)
{
	for (size_t i = 0; i < src.count(); i++)
		AddObject(src.item(i)->Clone(this));
}

PEFile::~PEFile()
{
	delete runtime_;
}

OpenStatus PEFile::ReadHeader(uint32_t open_mode)
{
	PEArchitecture* arch = new PEArchitecture(this, 0, size());
	AddObject(arch);
	return arch->ReadFromFile(open_mode);
}

std::string PEFile::format_name() const
{
	return std::string("PE");
}

bool PEFile::WriteHeader()
{
	for (size_t i = 0; i < count(); i++) {
		if (!item(i)->WriteToFile())
			return false;
	}
	return true;
}

PEFile* PEFile::Clone(const char* file_name) const
{
	PEFile* file = new PEFile(*this, file_name);
	return file;
}

bool PEFile::Compile(CompileOptions& options)
{
	const ResourceInfo runtime_info[] = {
		{win_runtime32_dll_file, sizeof(win_runtime32_dll_file), win_runtime32_dll_code},
		{win_runtime64_dll_file, sizeof(win_runtime64_dll_file), win_runtime64_dll_code},
		{win_runtime32_sys_file, sizeof(win_runtime32_sys_file), win_runtime32_sys_code},
		{win_runtime64_sys_file, sizeof(win_runtime64_sys_file), win_runtime64_sys_code},

	};

	size_t index;

	index = (arch_pe()->image_type() == itDriver) ? 2 : 0;

	ResourceInfo info = runtime_info[index + (arch_pe()->cpu_address_size() == osDWord ? 0 : 1)];
	if (info.size > 1) {
		runtime_ = new PEFile(NULL);
		if (!runtime_->OpenResource(info.file, info.size, true) || count() != runtime_->count())
			throw std::runtime_error("Runtime error at OpenResource");

		Buffer buffer(info.code);
		IArchitecture* arch = runtime_->item(runtime_->count() - 1);
		arch->ReadFromBuffer(buffer);
		for (size_t i = 0; i < arch->function_list()->count(); i++) {
			arch->function_list()->item(i)->set_from_runtime(true);
		}
		for (size_t i = 0; i < arch->import_list()->count(); i++) {
			IImport* import = arch->import_list()->item(i);
			for (size_t j = 0; j < import->count(); j++) {
import->item(j)->include_option(ioFromRuntime);
			}
		}
	}

	return IFile::Compile(options);
}

std::string PEFile::version() const
{
	struct VERSION_INFO {
		uint16_t wLength;
		uint16_t wValueLength;
		uint16_t wType;
		uint16_t szKey[1];
	};

	if (count() == 1) {
		IArchitecture* file = item(0);
		IResource* resource = file->resource_list()->GetResourceByType(rtVersionInfo);
		if (resource)
			resource = resource->GetResourceByName("1");
		if (resource && resource->count()) {
			resource = resource->item(0);
			if (resource->size() && file->AddressSeek(resource->address())) {
				uint8_t* data = new uint8_t[resource->size()];
				file->Read(data, resource->size());

				size_t len = 0;
				while (reinterpret_cast<VERSION_INFO*>(data)->szKey[len])
					len++;
				VS_FIXEDFILEINFO* file_info = reinterpret_cast<VS_FIXEDFILEINFO*>(data + AlignValue(offsetof(VERSION_INFO, szKey) + (len + 1) * sizeof(uint16_t), sizeof(uint32_t)));
				std::string res = string_format("%d.%d.%d.%d", static_cast<uint16_t>(file_info->dwFileVersionMS >> 16), static_cast<uint16_t>(file_info->dwFileVersionMS), static_cast<uint16_t>(file_info->dwFileVersionLS >> 16), static_cast<uint16_t>(file_info->dwFileVersionLS));
				delete[] data;

				return res;
			}
		}
	}

	return IFile::version();
}

bool PEFile::is_executable() const
{
	for (size_t i = 0; i < count(); i++) {
		if (item(i)->is_executable())
			return true;
	}
	return false;
}

uint32_t PEFile::disable_options() const
{
	uint32_t res = 0;
	if (count() == 1) {
		PEArchitecture* arch = arch_pe();
		if (arch->segment_alignment() < 0x1000)
			res |= cpPack;
		if (arch->image_type() != itExe)
			res |= cpStripFixups;
		if (arch->image_type() == itDriver) {
			res |= cpResourceProtection;
			res |= cpVirtualFiles;
		}
	}
	else {
		res |= cpStripFixups;
	}
	return res;
}

bool PEFile::GetCheckSum(uint32_t* check_sum)
{
	Flush();
	return os::FileGetCheckSum(file_name(true).c_str(), check_sum);
}

std::string PEFile::exec_command() const
{

	return std::string();
}
