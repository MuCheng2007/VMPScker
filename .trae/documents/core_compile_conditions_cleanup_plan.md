# Core目录条件编译清理计划（修正版）

## 任务概述
清理core目录下的条件编译代码，具体规则：
1. **`#ifdef ULTIMATE`**：删除条件编译占位符（#ifdef ULTIMATE和#endif），**保留**其中的代码内容
2. **`#ifdef DEMO`**：删除整个代码块（包括内容）
3. **`#ifdef __unix__`**：删除整个代码块（包括内容）
4. **`#ifdef __APPLE__`**：删除整个代码块（包括内容）
5. **`#checked`**：保留（不处理）
6. **`#ifdef VMP_GNU`**：保留（不处理）

## 发现的文件及修改方案

### 1. script.cc
- **位置**: 第3916行
- **内容**: `#ifdef ULTIMATE` ... `#endif` 包含LicensesBinder类相关代码
- **操作**: 删除`#ifdef ULTIMATE`和`#endif`行，保留中间的所有代码内容

### 2. intel.h
- **位置**: 第984行
- **内容**: `#ifdef ULTIMATE` ... `#endif` 包含类成员变量声明
- **操作**: 删除`#ifdef ULTIMATE`和`#endif`行，保留中间的所有代码内容

### 3. intel.cc - 多个位置
1. **第8604行**: `#ifdef ULTIMATE` ... `#endif` - VM命令加密相关代码
2. **第21351行**: `#ifdef ULTIMATE` ... `#endif` - 构造函数初始化列表
3. **第21445行**: `#ifdef ULTIMATE` ... `#endif` - files_entry相关代码
4. **第21574行**: `#ifdef ULTIMATE` ... `#endif` - license_data相关代码
5. **第21591行**: `#ifdef ULTIMATE` ... `#endif` - HWID相关代码
6. **第21691行**: `#ifdef ULTIMATE` ... `#endif` - switch case代码块
7. **第21866行**: `#ifdef ULTIMATE` ... `#endif` - switch case代码块
8. **第21891行**: `#ifdef ULTIMATE` ... `#endif` - if-else代码块
9. **第22313行**: `#ifdef ULTIMATE` ... `#endif` - 延迟导入相关代码
10. **第23189行**: `#ifdef ULTIMATE` ... `#endif` - 延迟导入信息创建
- **操作**: 对每个块，删除`#ifdef ULTIMATE`和`#endif`行，保留中间的所有代码内容

### 4. files.h
1. **第61行**: `#ifdef ULTIMATE` ... `#endif` - 类前向声明
2. **第1183行**: `#ifdef ULTIMATE` ... `#endif` - CompileOptions结构体成员
- **操作**: 删除`#ifdef ULTIMATE`和`#endif`行，保留中间的所有代码内容

### 5. files.cc
1. **第3135行**: `#ifdef ULTIMATE` ... `#endif` - runtime_options设置
   - **操作**: 删除`#ifdef ULTIMATE`和`#endif`行，保留中间的所有代码内容
2. **第3159行**: `#ifdef ULTIMATE` ... `#else` ... `#endif` - 许可证检查代码
   - **操作**: 删除`#ifdef ULTIMATE`及其代码块，删除`#else`和`#endif`，保留#else分支的代码内容

### 6. processors.cc
- **位置**: 第1131行
- **内容**: `#ifndef DEMO` ... `#endif` - 命令合并相关代码
- **操作**: 删除整个代码块（包括#ifndef DEMO、代码内容和#endif）

### 7. osutils.cc - __unix__和__APPLE__代码（完全删除这些块）
1. **第4行**: `#ifdef __APPLE__` ... `#elif defined(__unix__)` ... `#else` ... `#endif` - 头文件包含
   - **操作**: 删除`__APPLE__`和`__unix__`分支，保留#else分支的内容（移除#else和#endif）
2. **第305行**: `#ifdef __APPLE__` ... `#elif defined(__unix__)` ... `#else` ... `#endif` - GetExecutablePath函数
   - **操作**: 删除`__APPLE__`和`__unix__`分支，保留#else分支的内容（移除#else和#endif）
3. **第352行**: `#ifdef __APPLE__` ... `#elif defined(__unix__)` ... `#endif` - FileDelete函数
   - **操作**: 删除整个条件编译块（包括所有分支）
4. **第386行**: `#ifdef __APPLE__` ... `#elif defined (__unix__)` ... `#else` ... `#endif` - FileCopy函数
   - **操作**: 删除`__APPLE__`和`__unix__`分支，保留#else分支的内容（移除#else和#endif）
5. **第728行**: `#ifdef __APPLE__` ... `#elif defined(__unix__)` ... `#else` ... `#endif` - CommandLine函数
   - **操作**: 删除`__APPLE__`和`__unix__`分支，保留#else分支的内容（移除#else和#endif）
6. **第834行**: `#ifdef __APPLE__` ... `#elif defined (__unix__)` ... `#else` ... `#endif` - GetTickCount函数
   - **操作**: 删除`__APPLE__`和`__unix__`分支，保留#else分支的内容（移除#else和#endif）
7. **第1108行**: `#ifdef __APPLE__` ... `#elif defined(__unix__)` ... `#else` ... `#endif` - ProcessOpen函数
   - **操作**: 删除`__APPLE__`和`__unix__`分支，保留#else分支的内容（移除#else和#endif）
8. **第1132行**: `#ifdef __APPLE__` ... `#elif defined(__unix__)` ... `#else` ... `#endif` - ProcessRead函数
   - **操作**: 删除`__APPLE__`和`__unix__`分支，保留#else分支的内容（移除#else和#endif）
9. **第1155行**: `#ifdef __APPLE__` ... `#elif defined(__unix__)` ... `#else` ... `#endif` - ProcessWrite函数
   - **操作**: 删除`__APPLE__`和`__unix__`分支，保留#else分支的内容（移除#else和#endif）
10. **第1197行**: `#ifdef __APPLE__` ... `#elif defined(__unix__)` ... `#else` ... `#endif` - EnumProcesses函数
    - **操作**: 删除`__APPLE__`和`__unix__`分支，保留#else分支的内容（移除#else和#endif）
11. **第1313行**: `#ifdef __unix__` ... `#endif` - ParseMapsLine函数和注释
    - **操作**: 删除整个代码块
12. **第1355行**: `#ifdef __APPLE__` ... `#elif defined(__unix__)` ... `#else` ... `#endif` - EnumModules函数
    - **操作**: 删除`__APPLE__`和`__unix__`分支，保留#else分支的内容（移除#else和#endif）
13. **第1437行**: `#ifdef __APPLE__` ... `#else` ... `#endif` - GetModuleInformation函数
    - **操作**: 删除`__APPLE__`分支，保留#else分支的内容（移除#else和#endif）
14. **第1533行**: `#ifdef __APPLE__` ... `#elif defined(__unix__)` ... `#else` ... `#endif` - GetSysAppDataDirectory函数
    - **操作**: 删除`__APPLE__`和`__unix__`分支，保留#else分支的内容（移除#else和#endif）
15. **第1704行**: `#ifdef __unix__` ... `#endif` - LocaleInfo结构体和数组
    - **操作**: 删除整个代码块
16. **第1764行**: `#ifdef __APPLE__` ... `#elif defined(__unix__)` ... `#else` ... `#endif` - GetLocaleName函数
    - **操作**: 删除`__APPLE__`和`__unix__`分支，保留#else分支的内容（移除#else和#endif）
17. **第1834行**: `#ifdef __APPLE__` ... `#elif defined(__unix__)` ... `#else` ... `#endif` - GetCurrentLocale函数
    - **操作**: 删除`__APPLE__`和`__unix__`分支，保留#else分支的内容（移除#else和#endif）
18. **第2050行**: `#ifdef __APPLE__` ... `#endif` - GetMainExeFileName函数
    - **操作**: 删除整个代码块

### 8. osutils.h
- **位置**: 第99行
- **内容**: `#ifdef __APPLE__` ... `#endif` - GetMainExeFileName声明
- **操作**: 删除整个代码块

### 9. precompiled.h
- **位置**: 第26行
- **内容**: `#ifdef __APPLE__` ... `#else` ... `#endif` - 头文件包含
- **操作**: 删除`__APPLE__`分支，保留#else分支的内容（移除#else和#endif）

### 10. objects.cc
- **位置**: 第7行
- **内容**: `#ifdef __APPLE__` ... `#endif` - _vsnprintf_s宏定义
- **操作**: 删除整个代码块

### 11. files.cc (第2115行)
- **位置**: 第2115行
- **内容**: `#ifdef __APPLE__` ... `#else` ... `#endif` - iterator类型定义
- **操作**: 删除`__APPLE__`分支，保留#else分支的内容（移除#else和#endif）

## 实施步骤

1. 首先修改头文件（intel.h, files.h, osutils.h, precompiled.h）
2. 然后修改源文件（script.cc, intel.cc, files.cc, processors.cc, osutils.cc, objects.cc）
3. 每个文件修改后检查语法正确性

## 注意事项

1. 对于`#ifdef ULTIMATE`：只删除条件编译指令，保留代码内容
2. 对于`#ifdef DEMO`：完全删除代码块
3. 对于`#ifdef __unix__`和`#ifdef __APPLE__`：完全删除代码块，对于多分支结构保留#else分支的Windows代码
4. 确保删除代码后不会留下多余的空行或语法错误
5. 需要特别注意构造函数初始化列表中的修改，确保语法正确
