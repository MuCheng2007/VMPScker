# 移除编译条件计划

## 目标
分析所有版本编译条件，只保留 ULTIMATE 条件下才编译的代码，删除其他条件（如 DEMO、LITE 等）相关的代码。同时删除 Unix/macOS 平台相关代码，只保留 Windows 平台代码。

## 发现的编译条件宏

### 1. ULTIMATE - 保留此条件下的代码
- 这是需要保留的主要版本宏
- 涉及授权管理、文件管理、HWID 等功能

### 2. DEMO - 需要删除
- 演示版特定的代码逻辑
- 运行时库引用（win_runtime32demo.dll.inc 等）
- 简化的功能实现

### 3. LITE - 需要删除
- 简化版特定的代码
- 版本字符串定义
- 授权检查逻辑

### 4. CHECKED - 保留
- 调试/检查模式代码保留

### 5. 平台相关宏 - 处理规则
- `__unix__` - Unix 平台代码 - **删除**
- `__APPLE__` - macOS 平台代码 - **删除**
- `_WIN32` / `_WIN64` - Windows 平台代码 - **保留**
- `VMP_GNU` - GNU 编译器 - **保留**（编译器相关）

### 6. 头文件保护宏 - 保留
- `CORE_H`, `SCRIPT_H`, `LICENSE_H` 等

## 需要修改的文件清单

### core/core.cc
| 行号 | 条件 | 操作 |
|------|------|------|
| 18-21 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 62-65 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 92-95 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 108-113 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 115-119 | `#ifdef ULTIMATE` / `#else` | 保留 ULTIMATE 分支 |
| 187-190 | `#ifndef ULTIMATE` | 删除整个块 |
| 217-224 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 489-543 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 658-665 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 716-718 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 723-725 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 731-733 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 738-740 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 775-786 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 811-816 | `#ifdef VMP_GNU` / `#else` | 保留（编译器相关） |
| 1164-1221 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 1248-1250 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 1262-1267 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 1320-1327 | `#ifndef DEMO` | 保留内容，删除条件 |
| 1332-1337 | `#ifdef DEMO` / `#else` | 保留 #else 分支内容 |
| 1342-1352 | `#ifdef DEMO` / `#else` | 保留 #else 分支内容 |
| 1357-1362 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 1490-1515 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 1581-1587 | `#if defined(ULTIMATE)` / `#elif` / `#else` | 保留 ULTIMATE 分支 |

### core/core.h
| 行号 | 条件 | 操作 |
|------|------|------|
| 9-12 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 31-33 | `#ifndef DEMO` | 保留内容，删除条件 |
| 80-101 | `#ifdef __unix__` / `#elif __APPLE__` / `#else` | 保留 #else 分支 (Windows) |
| 104-110 | `#if defined(ULTIMATE)` / `#elif` / `#else` | 保留 ULTIMATE 分支 |
| 130-134 | `#ifdef ULTIMATE` / `#else` | 保留 ULTIMATE 分支 |
| 156-166 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 208-213 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |

### core/pefile.cc
| 行号 | 条件 | 操作 |
|------|------|------|
| 19-29 | `#ifdef DEMO` / `#else` | 保留 #else 分支内容 |
| 3743-3752 | `#ifdef __unix__` / `#else` | 删除 Unix 代码，保留 #else 分支 |
| 4377-4380 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 5508-5511 | `#ifndef VMP_GNU` | 保留（编译器相关） |

### core/intel.cc
| 行号 | 条件 | 操作 |
|------|------|------|
| 8926-9050 | `#ifdef DEMO` / `#else` | 保留 #else 分支内容 |
| 9015-9050 | `#ifdef DEMO` / `#else` | 保留 #else 分支内容 |
| 17985-17991 | `#ifndef DEMO` | 保留内容，删除条件 |

### core/script.cc
| 行号 | 条件 | 操作 |
|------|------|------|
| 534-562 | `#elif defined(_WIN64)` / `#elif` / `#else` | 保留（平台相关） |
| 3673-3691 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 3816-3830 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 3917-4467 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |

### core/script.h
| 行号 | 条件 | 操作 |
|------|------|------|
| 7-21 | `#ifndef VMP_GNU` / `#ifdef _WIN64` | 保留（平台相关） |
| 735-738 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |
| 748-891 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |

### core/core_internal/license.cc
| 行号 | 条件 | 操作 |
|------|------|------|
| 10-670 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |

### core/core_internal/license.h
| 行号 | 条件 | 操作 |
|------|------|------|
| 8-138 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |

### core/core_internal/file_manager.cc
| 行号 | 条件 | 操作 |
|------|------|------|
| 9-11 | `#ifdef _WIN32` | 保留（平台相关） |
| 13-418 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |

### core/core_internal/file_manager.h
| 行号 | 条件 | 操作 |
|------|------|------|
| 8-125 | `#ifdef ULTIMATE` | 保留，删除条件保留内容 |

### core/core_internal/rsa.cc
| 行号 | 条件 | 操作 |
|------|------|------|
| 90-135 | `#ifdef __APPLE__` / `#elif` / `#else` | 删除 Apple/Unix 代码，保留 #else 分支 |
| 168-210 | `#ifdef CHECKED` | 保留（CHECKED 保留） |

### core/core_internal/project_template.cc
| 行号 | 条件 | 操作 |
|------|------|------|
| 157-192 | `#ifdef VMP_GNU` / `#else` | 保留（编译器相关） |

## 实施步骤

1. **备份原始文件** - 在开始修改前创建备份
2. **按文件逐个处理** - 从最基础的头文件开始
3. **处理 DEMO 条件** - 删除 DEMO 相关代码
4. **处理 LITE 条件** - 删除 LITE 相关代码
5. **处理 ULTIMATE 条件** - 保留代码但删除条件包装
6. **处理平台相关条件** - 删除 Unix/macOS 代码，保留 Windows 代码
7. **验证编译** - 确保修改后的代码可以正常编译

## 注意事项

- CHECKED 宏保留不删除
- `__unix__` 和 `__APPLE__` 平台代码删除，只保留 Windows 代码
- `_WIN32` / `_WIN64` 平台代码保留
- VMP_GNU 是编译器相关宏，保留
- 头文件保护宏需要保留
- 处理 `#ifndef MACRO` 时要特别小心，确保逻辑正确
- 多行条件块要完整处理，包括 `#ifdef`, `#else`, `#elif`, `#endif`
