# 修复编译错误计划

## 错误分析

### 1. 类型重定义错误
- `ProjectOption` - 在 core.h 和 project_template.h 中重复定义
- `LinkType` - 在 file_manager.h 和 processors.h 中重复定义
- `RuntimeOptions` - 在 file_manager.h 和 processors.h 中重复定义

### 2. 未定义类型错误
- `Core` - license.cc, file_manager.cc, project_template.cc, watermark.cc 中使用了未定义的 Core
- `BigNumber` - rsa.cc 中使用了未定义的 BigNumber
- `SettingsFile` - project_template.cc 中使用了未定义的 SettingsFile

### 3. 缺少标识符
- `_rotl32` - file_manager.cc 中找不到
- `AlignValue` - license.cc 中找不到
- `DisplayString` - processors.h 中找不到
- `ltCall`, `ltJmp` 等 LinkType 枚举值 - processors.cc 和 script.cc 中找不到

### 4. processors.h 问题
- 缺少 IArchitecture, IRuntimeFunction 等前向声明
- 缺少 CompilationType 定义

## 修复步骤

### 步骤1: 删除重复定义

**project_template.h** - 删除 ProjectOption 枚举定义（它已经在 core.h 中定义）

**file_manager.h** - 删除 LinkType 和 RuntimeOptions 枚举定义（它们已经在 processors.h 中定义）
- 改为包含 processors.h
- 删除 FILE_LOAD, FILE_REGISTER, FILE_INSTALL 宏定义（如果重复）

### 步骤2: 添加缺失的头文件包含

**rsa.cc** - 添加 BigNumber 的完整定义
```cpp
#include "../objects.h"  // 确保这行存在且有效
```

**watermark.cc** - 添加 Core 的前向声明或包含
```cpp
#include "../core.h"  // 或者前向声明 class Core;
```

**license.cc** - 添加缺失的包含
```cpp
#include "../core.h"
#include "../utils.h"  // 用于 AlignValue
```

**file_manager.cc** - 添加缺失的包含
```cpp
#include "../core.h"
#include <intrin.h>  // 用于 _rotl32 (Windows)
```

**project_template.cc** - 添加缺失的包含
```cpp
#include "../core.h"
#include "../files.h"  // 用于 SettingsFile
```

### 步骤3: 修复 processors.h

添加缺失的前向声明和包含：
```cpp
#include "../runtime/common.h"
class IArchitecture;
class IRuntimeFunction;
class Watermark;
class IVirtualMachineList;
// ... 其他前向声明
```

### 步骤4: 确保正确的包含顺序

检查各个文件的包含顺序，确保先包含基础头文件再包含派生头文件。

## 具体修改清单

| 文件 | 修改内容 |
|------|----------|
| project_template.h | 删除 ProjectOption 枚举 |
| file_manager.h | 删除 LinkType/RuntimeOptions 枚举，改为包含 processors.h |
| rsa.cc | 确认包含 objects.h |
| watermark.cc | 添加 #include "../core.h" |
| license.cc | 添加 #include "../core.h" 和 #include "../utils.h" |
| file_manager.cc | 添加 #include "../core.h" 和 #include <intrin.h> |
| project_template.cc | 添加 #include "../core.h" 和 #include "../files.h" |
| processors.h | 添加缺失的前向声明 |
