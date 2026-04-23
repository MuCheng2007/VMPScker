# Core文件拆分方案

## 当前文件分析

### 文件规模

* **core.h**: 598行

* **core.cc**: 3605行

### 当前包含的主要组件

1. **工具函数** (core.cc: 16-41)

   * `Base64ToVector`

   * `VectorToBase64`

2. **Watermark相关** (core.cc: 44-393, core.h: 315-375)

   * `Watermark` 类

   * `WatermarkManager` 类

3. **Core主类** (core.cc: 414-1990, core.h: 503-596)

   * 项目文件管理

   * 编译流程控制

   * XML/Ini配置加载保存

4. **License相关** (ULTIMATE版本) (core.cc: 1991-2658, core.h: 87-198)

   * `License` 类

   * `LicensingManager` 类

   * `LicenseInfo` 结构体

5. **FileManager相关** (ULTIMATE版本) (core.cc: 2659-3078, core.h: 200-311)

   * `FileFolder` 类

   * `FileFolderList` 类

   * `InternalFile` 类

   * `FileManager` 类

6. **RSA加密** (core.cc: 3080-3366, core.h: 65-85)

   * `RSA` 类

7. **ProjectTemplate相关** (core.cc: 3368-3605, core.h: 444-496)

   * `ProjectTemplate` 类

   * `ProjectTemplateManager` 类

***

## 拆分方案

### 目标结构

在 `core/` 目录下创建 `core_internal/` 子文件夹，将所有拆分出的文件放到该文件夹中：

```
core/
├── core.h                  # 精简后的主头文件，包含Core类和公共定义
├── core.cc                 # 精简后的主实现文件
└── core_internal/          # 拆分出的内部组件文件夹
    ├── core_utils.h/.cc    # 工具函数 (Base64转换等)
    ├── watermark.h/.cc     # 水印管理
    ├── license.h/.cc       # 许可证管理 (ULTIMATE)
    ├── file_manager.h/.cc  # 文件管理 (ULTIMATE)
    ├── rsa.h/.cc           # RSA加密
    └── project_template.h/.cc  # 项目模板管理
```

***

## 详细拆分步骤

### 步骤1: 创建 core\_utils.h / core\_utils.cc

**core\_internal/core\_utils.h:**

```cpp
#ifndef CORE_UTILS_H
#define CORE_UTILS_H

#include "../../runtime/common.h"

void Base64ToVector(const char *src, size_t src_len, std::vector<uint8_t> &dst);
std::string VectorToBase64(const std::vector<uint8_t> &src);

#endif
```

**core\_internal/core\_utils.cc:**

* 包含 Base64ToVector 和 VectorToBase64 实现

* 包含 crypto.h 依赖

***

### 步骤2: 创建 watermark.h / watermark.cc

**core\_internal/watermark.h:**

```cpp
#ifndef WATERMARK_H
#define WATERMARK_H

#include "../../runtime/common.h"

class WatermarkManager;
class IniFile;
class SettingsFile;

class Watermark : public IObject {
    // ... 原Watermark类定义
};

class WatermarkManager : public ObjectList<Watermark> {
    // ... 原WatermarkManager类定义
};

#endif
```

**core\_internal/watermark.cc:**

* 包含 Watermark 和 WatermarkManager 实现

* 依赖: objects.h, inifile.h, core\_utils.h

***

### 步骤3: 创建 rsa.h / rsa.cc

**core\_internal/rsa.h:**

```cpp
#ifndef RSA_H
#define RSA_H

#include "../../runtime/common.h"

class BigNumber;

class RSA {
public:
    RSA();
    RSA(const std::vector<uint8_t> &public_exp, 
        const std::vector<uint8_t> &private_exp, 
        const std::vector<uint8_t> &modulus);
    ~RSA();
    bool Encrypt(Data &data);
    bool Decrypt(Data &data);
    bool CreateKeyPair(size_t key_length);
    std::vector<uint8_t> public_exp() const;
    std::vector<uint8_t> private_exp() const;
    std::vector<uint8_t> modulus() const;
private:
    BigNumber *private_exp_;
    BigNumber *public_exp_;
    BigNumber *modulus_;
    // no copy
    RSA(const RSA &);
    RSA &operator =(const RSA &);
};

#endif
```

***

### 步骤4: 创建 license.h / license.cc (ULTIMATE)

**core\_internal/license.h:**

```cpp
#ifndef LICENSE_H
#define LICENSE_H

#include "../../runtime/common.h"
#include "rsa.h"

#ifdef ULTIMATE

// 枚举和结构体定义
enum Algorithm { alNone, alRSA };

enum SerialNumberFlags {
    HAS_USER_NAME       = 0x0001,
    HAS_EMAIL           = 0x0002,
    HAS_EXP_DATE        = 0x0004,
    HAS_MAX_BUILD_DATE  = 0x0008,
    HAS_TIME_LIMIT      = 0x0010,
    HAS_HARDWARE_ID     = 0x0020,
    HAS_USER_DATA       = 0x0040,
    SN_FLAGS_PADDING    = 0xFFFF
};

struct LicenseDate {
    uint16_t Year;
    uint8_t Month;
    uint8_t Day;
    LicenseDate(uint32_t value = 0);
    LicenseDate(uint16_t year, uint8_t month, uint8_t day);
    uint32_t value() const;
};

struct LicenseInfo {
    uint32_t Flags;
    std::string CustomerName;
    std::string CustomerEmail;
    LicenseDate ExpireDate;
    std::string HWID;
    uint8_t RunningTimeLimit;
    LicenseDate MaxBuildDate;
    std::string UserData;
    LicenseInfo();
};

// 前向声明
class Core;
class LicensingManager;

class License : public IObject {
    // ... 原License类定义
};

class LicensingManager : public ObjectList<License> {
    // ... 原LicensingManager类定义
};

#endif // ULTIMATE
#endif // LICENSE_H
```

***

### 步骤5: 创建 file\_manager.h / file\_manager.cc (ULTIMATE)

**core\_internal/file\_manager.h:**

```cpp
#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include "../../runtime/common.h"

#ifdef ULTIMATE

// 前向声明
class Core;
class FileManager;
class IFunction;
class FileStream;

class FileFolder : public ObjectList<FileFolder> {
    // ... 原FileFolder类定义
};

class FileFolderList : public FileFolder {
    // ... 原FileFolderList类定义
};

enum InternalFileAction {
    faNone,
    faLoad,
    faRegister,
    faInstall
};

class InternalFile : public IObject {
    // ... 原InternalFile类定义
};

class FileManager : public ObjectList<InternalFile> {
    // ... 原FileManager类定义
};

#endif // ULTIMATE
#endif // FILE_MANAGER_H
```

***

### 步骤6: 创建 project\_template.h / project\_template.cc

**core\_internal/project\_template.h:**

```cpp
#ifndef PROJECT_TEMPLATE_H
#define PROJECT_TEMPLATE_H

#include "../../runtime/common.h"

class Core;
class ProjectTemplateManager;
class SettingsFile;

class ProjectTemplate : public IObject {
    // ... 原ProjectTemplate类定义
};

class ProjectTemplateManager : public ObjectList<ProjectTemplate> {
    // ... 原ProjectTemplateManager类定义
};

#endif
```

***

### 步骤7: 精简 core.h / core.cc

**core.h 精简后:**

```cpp
#ifndef CORE_H
#define CORE_H

#include "../runtime/common.h"
#include "core_internal/core_utils.h"
#include "core_internal/watermark.h"
#include "core_internal/project_template.h"

#ifdef ULTIMATE
#include "core_internal/license.h"
#include "core_internal/file_manager.h"
#endif

// 项目选项枚举
enum ProjectOption {
    cpDebugMode             = 0x00000002,
    cpCryptValues           = 0x00000008,
    cpIncludeWatermark      = 0x00000020,
    cpRunnerCRC             = 0x00000040,
    cpEncryptRegs           = 0x00000080,
    cpStripFixups           = 0x00008000,
    cpPack                  = 0x00000100,
    cpImportProtection      = 0x00000200,
    cpCheckDebugger         = 0x00000400,
    cpCheckVirtualMachine   = 0x00000800,
    cpMemoryProtection      = 0x00001000,
    cpResourceProtection    = 0x00010000,
    cpCheckKernelDebugger   = 0x00020000,
    cpStripDebugInfo        = 0x00040000,
    cpLoaderCRC             = 0x10000000,
#ifndef DEMO
    cpUnregisteredVersion   = 0x40000000,
#endif
    cpEncryptBytecode       = 0x80000000,
    cpVirtualFiles          = 0x08000000,
    cpInternalMemoryProtection = 0x04000000,
    cpLoader                = 0x02000000,
    cpMaximumProtection     = cpCryptValues | cpRunnerCRC | cpEncryptRegs | cpPack | cpImportProtection | cpMemoryProtection | cpResourceProtection | cpStripDebugInfo,
    cpUserOptionsMask       = 0x00FFFFFF
};

// 产品ID枚举
enum VMProtectProductId {
    // ... 原枚举定义
};

// 版本信息宏
#if defined(ULTIMATE)
#define EDITION "Ultimate"
#elif defined(LITE)
#define EDITION "Lite"
#else
#define EDITION "Professional"
#endif

// 前向声明
class Script;
class ILog;
class IFile;
class IArchitecture;

class Core : public IObject {
public:
    explicit Core(ILog *log = NULL);
    virtual ~Core();
    
#ifdef ULTIMATE
    bool Open(const std::string &file_name, 
              const std::string &user_project_file_name = "", 
              const std::string &user_licensing_params_file_name = "");
#else
    bool Open(const std::string &file_name, 
              const std::string &user_project_file_name = "");
#endif
    
    bool Save();
    bool SaveAs(const std::string &file_name);
    void Close();
    bool Compile();

    // Getters
    uint32_t options() const { return options_; }
    std::string vm_section_name() const { return vm_section_name_; }
    std::string watermark_name() const { return watermark_name_; }
    IFile *input_file() const { return input_file_; }
    IFile *output_file() const { return output_file_; }
    ILog *log() const { return log_; }
    std::string input_file_name() const { return input_file_name_; }
    std::string output_file_name() const { return output_file_name_; }
    std::string message(size_t type) const { return messages_[type]; }
    std::string project_file_name() const { return project_file_name_; }
    WatermarkManager *watermark_manager() const { return watermark_manager_; }
    ProjectTemplateManager *template_manager() const { return template_manager_; }
    Script *script() const { return script_; }
    IArchitecture *input_architecture() const;
    IArchitecture *output_architecture() const { return output_architecture_; }
    std::string project_path() const;
    std::string absolute_output_file_name() const;

    // Setters
    void set_options(uint32_t options);
    void include_option(ProjectOption option);
    void exclude_option(ProjectOption option);
    void set_vm_section_name(const std::string &vm_section_name);
    void set_watermark_name(const std::string &watermark_name);
    void set_output_file_name(const std::string &output_file_name);
    void set_message(size_t type, const std::string &message);

#ifdef ULTIMATE
    std::string hwid() const { return hwid_; }
    void set_hwid(const std::string &hwid);
    LicensingManager *licensing_manager() const { return licensing_manager_; }
    FileManager *file_manager() const { return file_manager_; }
    std::string license_data_file_name() const { return license_data_file_name_; }
    void set_license_data_file_name(const std::string &license_data_file_name);
    std::string activation_server() const { return licensing_manager_->activation_server(); }
    void set_activation_server(const std::string &activation_server);
    std::string default_license_data_file_name() const;
#endif

    // 模板相关
    void LoadFromTemplate(const ProjectTemplate &pt);
    void SaveToTemplate(ProjectTemplate &pt);

    // 静态方法
    static const char *copyright() { return "Copyright 2003-2021 VMProtect Software"; }
    static const char *edition() { return "VMProtect " EDITION; }
    static const char *version();
    static const char *build();
    static bool check_license_edition(const VMProtectSerialNumberData &lic);

    // 通知
    void Notify(MessageType type, IObject *sender, const std::string &message = "");

private:
    // 私有方法
    HANDLE BeginCompileTransaction();
    void EndCompileTransaction(HANDLE locked_file, bool commit);
    bool LoadFromXML(const char *project_file_name);
    bool LoadFromIni(const char *project_file_name);
    void LoadDefaultFunctions();
    std::string default_output_file_name() const;

    // 成员变量
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
    Script *script_;
    IArchitecture *output_architecture_;

#ifdef ULTIMATE
    std::string hwid_;
    std::string license_data_file_name_;
    LicensingManager *licensing_manager_;
    FileManager *file_manager_;
#endif

    // 禁止拷贝
    Core(const Core &);
    Core &operator =(const Core &);
};

#endif
```

***

## 依赖关系图

```
core/
├── core.h
│   ├── core_internal/core_utils.h
│   ├── core_internal/watermark.h
│   ├── core_internal/project_template.h
│   ├── core_internal/license.h (ULTIMATE)
│   │   └── core_internal/rsa.h
│   └── core_internal/file_manager.h (ULTIMATE)
├── core.cc
└── core_internal/
    ├── core_utils.h/.cc
    ├── watermark.h/.cc
    ├── rsa.h/.cc
    ├── license.h/.cc (ULTIMATE)
    ├── file_manager.h/.cc (ULTIMATE)
    └── project_template.h/.cc
```

***

## 文件大小预估

| 文件                     | 路径                   | 预估行数        | 说明               |
| ---------------------- | -------------------- | ----------- | ---------------- |
| core.h                 | core/                | \~150       | 精简后的主头文件         |
| core.cc                | core/                | \~1500      | 精简后的主实现文件        |
| core\_utils.h/cc       | core/core\_internal/ | \~50/\~50   | 工具函数             |
| watermark.h/cc         | core/core\_internal/ | \~80/\~350  | 水印管理             |
| rsa.h/cc               | core/core\_internal/ | \~30/\~300  | RSA加密            |
| license.h/cc           | core/core\_internal/ | \~120/\~700 | 许可证管理 (ULTIMATE) |
| file\_manager.h/cc     | core/core\_internal/ | \~120/\~450 | 文件管理 (ULTIMATE)  |
| project\_template.h/cc | core/core\_internal/ | \~60/\~250  | 项目模板             |

***

## 实施建议

### 阶段1: 创建文件夹结构

1. 创建 `core/core_internal/` 文件夹
2. 创建必要的子目录结构

### 阶段2: 提取工具函数

1. 创建 `core_internal/core_utils.h` / `core_internal/core_utils.cc`
2. 移动 Base64ToVector 和 VectorToBase64
3. 更新所有引用 (include 路径改为 `core_internal/xxx.h`)

### 阶段3: 提取独立组件

1. 创建 `core_internal/rsa.h` / `core_internal/rsa.cc` (最独立)
2. 创建 `core_internal/watermark.h` / `core_internal/watermark.cc`
3. 创建 `core_internal/project_template.h` / `core_internal/project_template.cc`

### 阶段4: 提取 ULTIMATE 组件

1. 创建 `core_internal/license.h` / `core_internal/license.cc`
2. 创建 `core_internal/file_manager.h` / `core_internal/file_manager.cc`

### 阶段5: 精简 core

1. 更新 `core.h`，移除已提取的类定义
2. 更新 `core.cc`，移除已提取的实现
3. 添加必要的 `#include "core_internal/xxx.h"`

### 阶段6: 更新编译配置

1. 更新 Makefile 添加新源文件路径
2. 更新 .vcxproj 项目文件

### 阶段7: 验证

1. 确保所有编译配置正常工作
2. 运行测试验证功能完整性

***

## 注意事项

1. **ULTIMATE 宏处理**: 所有 ULTIMATE 相关的代码需要保持在 `#ifdef ULTIMATE` 块中
2. **前向声明**: 使用前置声明减少头文件依赖
3. **循环依赖**: 注意 Core 类与其他类的双向依赖关系
4. **编译配置**: 需要更新 Makefile/VCXProj 文件添加新源文件

