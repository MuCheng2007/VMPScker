#include "objects.h"
#include "inifile.h"
#include "osutils.h"
#include "lang.h"

LangStringList language;

/**
 * Language
 */

Language::Language(LanguageManager *owner, std::string id, const std::string &file_name)
	: IObject(), owner_(owner), id_(id), file_name_(file_name)
{
	name_ = os::GetLocaleName(id_.c_str());
}

Language::~Language()
{
	if (owner_)
		owner_->RemoveObject(this);
}

/**
 * LanguageManager
 */

LanguageManager::LanguageManager()
	: ObjectList<Language>()
{
		InsertObject(0, new Language(this, default_language(), ""));
}



Language *LanguageManager::GetLanguageById(const std::string &id) const
{
	for (size_t i = 0; i < count(); i++) {
		Language *lang = item(i);
		if (lang->id() == id)
			return lang;
	}
	return NULL;
}

/**
 * LangStringList
 */

std::string replace_escape_chars(const char *str)
{
	std::string res;
	while (*str) {
		if (*str == '\\' && *(str + 1) == 'n') {
			res += '\n';
			str++;
		} else {
			res += *str;
		}
		str++;
	}
	return res;
}

LangStringList::LangStringList()
{
	{
		default_values_[lsAbout] = replace_escape_chars(u8"关于");
		default_values_[lsActivationServerNotSpecified] = replace_escape_chars(u8"未指定激活服务器");
		default_values_[lsAdd] = replace_escape_chars(u8"添加");
		default_values_[lsAddFile] = replace_escape_chars(u8"添加文件");
		default_values_[lsAddFolder] = replace_escape_chars(u8"添加文件夹");
		default_values_[lsAddFunction] = replace_escape_chars(u8"添加函数");
		default_values_[lsAddress] = replace_escape_chars(u8"地址");
		default_values_[lsAddressUsedByFunction] = replace_escape_chars(u8"地址已被函数 \"%s\" 使用");
		default_values_[lsAllFiles] = replace_escape_chars(u8"所有文件");
		default_values_[lsAssemblies] = replace_escape_chars(u8"程序集");
		default_values_[lsAutoSaveProject] = replace_escape_chars(u8"编译后自动保存项目");
		default_values_[lsBack] = replace_escape_chars(u8"后退");
		default_values_[lsBlocked] = replace_escape_chars(u8"已阻止");
		default_values_[lsBreakAddress] = replace_escape_chars(u8"函数结束");
		default_values_[lsCalculator] = replace_escape_chars(u8"计算器");
		default_values_[lsCancel] = replace_escape_chars(u8"取消");
		default_values_[lsCaseSensitive] = replace_escape_chars(u8"区分大小写");
		default_values_[lsChanging] = replace_escape_chars(u8"正在更改");
		default_values_[lsClose] = replace_escape_chars(u8"关闭");
		default_values_[lsCode] = replace_escape_chars(u8"代码");
		default_values_[lsContains] = replace_escape_chars(u8"包含");
		default_values_[lsComments] = replace_escape_chars(u8"注释");
		default_values_[lsCommandNotSupported] = replace_escape_chars(u8"不支持的命令 \"%s\"");
		default_values_[lsCompilationLog] = replace_escape_chars(u8"编译日志");
		default_values_[lsCompilationType] = replace_escape_chars(u8"编译类型");
		default_values_[lsCompile] = replace_escape_chars(u8"编译");
		default_values_[lsCompiled] = replace_escape_chars(u8"编译完成");
		default_values_[lsCompiling] = replace_escape_chars(u8"正在编译");
		default_values_[lsConfirmation] = replace_escape_chars(u8"确认");
		default_values_[lsContents] = replace_escape_chars(u8"内容");
		default_values_[lsContinue] = replace_escape_chars(u8"继续");
		default_values_[lsCopy] = replace_escape_chars(u8"复制");
		default_values_[lsCount] = replace_escape_chars(u8"计数");
		default_values_[lsCPU] = replace_escape_chars(u8"CPU");
		default_values_[lsCreateFileError] = replace_escape_chars(u8"无法创建文件 \"%s\"");
		default_values_[lsCreateSegmentError] = replace_escape_chars(u8"文件头中没有足够的空间用于新段");
		default_values_[lsCut] = replace_escape_chars(u8"剪切");
		default_values_[lsDate] = replace_escape_chars(u8"日期");
		default_values_[lsDefault] = replace_escape_chars(u8"默认");
		default_values_[lsDelete] = replace_escape_chars(u8"删除");
		default_values_[lsDeleteFile] = replace_escape_chars(u8"删除文件");
		default_values_[lsDeleteFolder] = replace_escape_chars(u8"删除文件夹");
		default_values_[lsDeleteFunction] = replace_escape_chars(u8"删除函数");
		default_values_[lsDeleting] = replace_escape_chars(u8"正在删除");
		default_values_[lsDetails] = replace_escape_chars(u8"详细信息");
		default_values_[lsDetection] = replace_escape_chars(u8"检测");
		default_values_[lsDirectories] = replace_escape_chars(u8"目录");
		default_values_[lsDump] = replace_escape_chars(u8"转储");
		default_values_[lsEdit] = replace_escape_chars(u8"编辑");
		default_values_[lsError] = replace_escape_chars(u8"错误");
		default_values_[lsExcludedFromCompilation] = replace_escape_chars(u8"从编译中排除");
		default_values_[lsExcludedFromMemoryProtection] = replace_escape_chars(u8"从内存保护中排除");
		default_values_[lsExcludedFromPacking] = replace_escape_chars(u8"从打包中排除");
		default_values_[lsExecutableFiles] = replace_escape_chars(u8"可执行文件");
		default_values_[lsExecute] = replace_escape_chars(u8"执行");
		default_values_[lsExit] = replace_escape_chars(u8"退出");
		default_values_[lsExpirationDate] = replace_escape_chars(u8"到期日期");
		default_values_[lsExport] = replace_escape_chars(u8"导出");
		default_values_[lsExportKeyPair] = replace_escape_chars(u8"导出密钥对");
		default_values_[lsExports] = replace_escape_chars(u8"导出");
		default_values_[lsExternalAddress] = replace_escape_chars(u8"外部地址");
		default_values_[lsFile] = replace_escape_chars(u8"文件");
		default_values_[lsFileCanNotBePacked] = replace_escape_chars(u8"无法打包文件");
		default_values_[lsFileCorrupted] = replace_escape_chars(u8"文件已损坏");
		default_values_[lsFileHasIncorrectFormat] = replace_escape_chars(u8"文件 \"%s\" 的 %s 格式不正确");
		default_values_[lsFileHasNoCodeSegment] = replace_escape_chars(u8"文件 \"%s\" 没有代码段");
		default_values_[lsFileHasUnknownFormat] = replace_escape_chars(u8"文件 \"%s\" 的格式未知");
		default_values_[lsFileHasUnsupportedProcessor] = replace_escape_chars(u8"文件 \"%s\" 使用了不支持的处理器 \"%s\"");
		default_values_[lsFileHasUnsupportedSubsystem] = replace_escape_chars(u8"文件 \"%s\" 使用了不支持的子系统");
		default_values_[lsFileName] = replace_escape_chars(u8"文件名");
		default_values_[lsFileNameNotSpecified] = replace_escape_chars(u8"未指定文件名");
		default_values_[lsFileNotFound] = replace_escape_chars(u8"未找到文件 \"%s\"");
		default_values_[lsFiles] = replace_escape_chars(u8"文件");
		default_values_[lsFlags] = replace_escape_chars(u8"标志");
		default_values_[lsForward] = replace_escape_chars(u8"前进");
		default_values_[lsFreeUpdatesPeriod] = replace_escape_chars(u8"免费更新期限");
		default_values_[lsFunction] = replace_escape_chars(u8"函数");
		default_values_[lsFunctionNotFound] = replace_escape_chars(u8"在对象列表中找不到函数 \"%s\"");
		default_values_[lsFunctions] = replace_escape_chars(u8"函数");
		default_values_[lsFunctionsForProtection] = replace_escape_chars(u8"要保护的函数");
		default_values_[lsGenerate] = replace_escape_chars(u8"生成");
		default_values_[lsGoTo] = replace_escape_chars(u8"转到地址");
		default_values_[lsHardwareID] = replace_escape_chars(u8"硬件 ID");
		default_values_[lsHDD] = replace_escape_chars(u8"硬盘");
		default_values_[lsHelp] = replace_escape_chars(u8"帮助");
		default_values_[lsHomePage] = replace_escape_chars(u8"主页");
		default_values_[lsImport] = replace_escape_chars(u8"导入");
		default_values_[lsImportLicense] = replace_escape_chars(u8"导入许可证");
		default_values_[lsImports] = replace_escape_chars(u8"导入");
		default_values_[lsInformation] = replace_escape_chars(u8"信息");
		default_values_[lsInvalidHWID] = replace_escape_chars(u8"无效的硬件 ID");
		default_values_[lsInvalidParameterValue] = replace_escape_chars(u8"参数 \"%s\" 的值无效");
		default_values_[lsItems] = replace_escape_chars(u8"项");
		default_values_[lsJumpToInternalAddress] = replace_escape_chars(u8"跳转到内部地址：%.8llX");
		default_values_[lsJumpToCommandPart] = replace_escape_chars(u8"跳转到命令的一部分");
		default_values_[lsLanguage] = replace_escape_chars(u8"语言");
		default_values_[lsLoadAtStart] = replace_escape_chars(u8"启动时加载");
		default_values_[lsLoading] = replace_escape_chars(u8"正在加载");
		default_values_[lsLicensingParametersFile] = replace_escape_chars(u8"许可参数文件");
		default_values_[lsLicensingParametersNotInitialized] = replace_escape_chars(u8"许可参数未初始化");
		default_values_[lsMarker] = replace_escape_chars(u8"标记");
		default_values_[lsMarkerExists] = replace_escape_chars(u8"标记 \"%s\" 已存在");
		default_values_[lsMessages] = replace_escape_chars(u8"消息");
		default_values_[lsMinimalFunctionSize] = replace_escape_chars(u8"要编译的函数的最小大小为 5 个字节");
		default_values_[lsMutation] = replace_escape_chars(u8"变异");
		default_values_[lsName] = replace_escape_chars(u8"名称");
		default_values_[lsNext] = replace_escape_chars(u8"下一个");
		default_values_[lsNo] = replace_escape_chars(u8"否");
		default_values_[lsNone] = replace_escape_chars(u8"无");
		default_values_[lsNotEnoughPlace] = replace_escape_chars(u8"没有足够的空间来创建 JMP 命令");
		default_values_[lsOK] = replace_escape_chars(u8"确定");
		default_values_[lsOpen] = replace_escape_chars(u8"打开");
		default_values_[lsOpenFileError] = replace_escape_chars(u8"无法打开文件 \"%s\"");
		default_values_[lsOpenModuleError] = replace_escape_chars(u8"无法打开模块 \"%s\"");
		default_values_[lsOperationCanceledByUser] = replace_escape_chars(u8"操作已由用户取消");
		default_values_[lsOptions] = replace_escape_chars(u8"选项");
		default_values_[lsOutputFile] = replace_escape_chars(u8"输出文件");
		default_values_[lsOutputFileSize] = replace_escape_chars(u8"输出文件大小为 %d 字节 (%d%%)");
		default_values_[lsPackOutputFile] = replace_escape_chars(u8"打包输出文件");
		default_values_[lsParameters] = replace_escape_chars(u8"参数");
		default_values_[lsPaste] = replace_escape_chars(u8"粘贴");
		default_values_[lsLockToSerialNumber] = replace_escape_chars(u8"锁定到序列号");
		default_values_[lsPrevious] = replace_escape_chars(u8"上一个");
		default_values_[lsProject] = replace_escape_chars(u8"项目");
		default_values_[lsProjectFile] = replace_escape_chars(u8"项目文件");
		default_values_[lsProjectFiles] = replace_escape_chars(u8"项目文件");
		default_values_[lsProtection] = replace_escape_chars(u8"保护");
		default_values_[lsRawAddress] = replace_escape_chars(u8"原始地址");
		default_values_[lsRawSize] = replace_escape_chars(u8"原始大小");
		default_values_[lsRecentFiles] = replace_escape_chars(u8"最近的文件");
		default_values_[lsRedo] = replace_escape_chars(u8"重做");
		default_values_[lsReferences] = replace_escape_chars(u8"引用");
		default_values_[lsRename] = replace_escape_chars(u8"重命名");
		default_values_[lsSave] = replace_escape_chars(u8"保存");
		default_values_[lsSaveFileError] = replace_escape_chars(u8"无法保存文件 \"%s\"");
		default_values_[lsSaveProject] = replace_escape_chars(u8"保存项目");
		default_values_[lsSaveProjectAs] = replace_escape_chars(u8"将项目另存为");
		default_values_[lsSaving] = replace_escape_chars(u8"正在保存");
		default_values_[lsSerialNumberTooLong] = replace_escape_chars(u8"序列号太长");
		default_values_[lsSavingStartupCode] = replace_escape_chars(u8"正在保存启动代码");
		default_values_[lsSearch] = replace_escape_chars(u8"搜索");
		default_values_[lsSearchInFile] = replace_escape_chars(u8"在文件中搜索");
		default_values_[lsSearching] = replace_escape_chars(u8"正在搜索");
		default_values_[lsSearchInModule] = replace_escape_chars(u8"在模块中搜索");
		default_values_[lsSearchResult] = replace_escape_chars(u8"搜索结果");
		default_values_[lsSearchResults] = replace_escape_chars(u8"搜索结果");
		default_values_[lsSearchWrapped] = replace_escape_chars(u8"搜索已循环");
		default_values_[lsSegmentCanNotBePacked] = replace_escape_chars(u8"无法打包段 \"%s\"");
		default_values_[lsSegment] = replace_escape_chars(u8"段");
		default_values_[lsSegments] = replace_escape_chars(u8"段");
		default_values_[lsSettings] = replace_escape_chars(u8"设置");
		default_values_[lsSetup] = replace_escape_chars(u8"设置");
		default_values_[lsShowProtectedFunctions] = replace_escape_chars(u8"仅显示受保护的函数");
		default_values_[lsSize] = replace_escape_chars(u8"大小");
		default_values_[lsStart] = replace_escape_chars(u8"开始");
		default_values_[lsString] = replace_escape_chars(u8"字符串");
		default_values_[lsStripDebugInfo] = replace_escape_chars(u8"去除调试信息");
		default_values_[lsStripRelocations] = replace_escape_chars(u8"去除重定位信息（仅限 EXE 文件）");
		default_values_[lsTools] = replace_escape_chars(u8"工具");
		default_values_[lsType] = replace_escape_chars(u8"类型");
		default_values_[lsUltra] = replace_escape_chars(u8"超级");
		default_values_[lsUndo] = replace_escape_chars(u8"撤消");
		default_values_[lsUnknown] = replace_escape_chars(u8"未知");
		default_values_[lsValue] = replace_escape_chars(u8"值");
		default_values_[lsVersion] = replace_escape_chars(u8"版本");
		default_values_[lsVirtualization] = replace_escape_chars(u8"虚拟");
		default_values_[lsWarning] = replace_escape_chars(u8"警告");
		default_values_[lsWatchedFileChange] = replace_escape_chars(u8"文件 \"%s\" 已被其他程序修改。\n是否要重新加载它？");
		default_values_[lsWatermark] = replace_escape_chars(u8"水印");
		default_values_[lsWatermarkIsDisabled] = replace_escape_chars(u8"水印已禁用");
		default_values_[lsWatermarkNotFound] = replace_escape_chars(u8"未找到水印");
		default_values_[lsWelcome] = replace_escape_chars(u8"欢迎使用");
		default_values_[lsYes] = replace_escape_chars(u8"是");
		default_values_[lszhucezhe] = replace_escape_chars(u8"小猫老师");
		default_values_[lsyouxiang] = replace_escape_chars(u8"coke@xm.com");
		default_values_[lsxukezheng] = replace_escape_chars(u8"小猫许可证");
	};
	use_defaults();
}

void LangStringList::use_defaults()
{

	for (size_t j = 0; j < lsCNT; j++) {
		values_[j] = default_values_[j];
	}
}



std::string LangStringList::operator[](LangString id) const
{
	assert(id != lsCNT);
	if (id == lsCNT) 
		return std::string();
	return values_[id];
}