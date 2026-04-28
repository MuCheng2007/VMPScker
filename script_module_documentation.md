# VMProtect Core - Scripting Module Documentation

## 1. 模块概述 (Overview)
`script.cc` 是 VMProtect C++ 核心与 Lua 脚本引擎之间的**桥接层 (Glue Layer)**。它通过 Lua C API 将内部的 C++ 类和逻辑手动导出给脚本环境，使得用户可以通过脚本自动化保护流程。

## 2. 核心职责 (Core Responsibilities)
- **对象导出 (Object Export)**: 将 C++ 实例包装为 Lua `userdata`。
- **方法绑定 (Method Binding)**: 将 C++ 类成员函数映射为 Lua 表方法。
- **类型转换 (Data Marshaling)**: 处理 `uint64_t`, `std::string`, `Buffer` 等类型在 Lua 堆栈与 C++ 之间的互转。
- **生命周期管理**: 协调 Lua 垃圾回收 (GC) 与 C++ 对象的释放（特别是通过 `delete_object` 辅助函数）。

## 3. 绑定的核心模块 (Bound Modules)
脚本层覆盖了几乎所有的核心功能，主要包括：

### A. 核心与项目 (Core & Project)
- **`Core`**: 导出项目打开、保存、编译、版本信息等。
- **`ProjectOptions`**: 导出虚拟化选项、混淆强度等配置。
- **`Licensing`**: 授权管理系统、水印、硬件 ID 处理。

### B. 文件架构 (File & Architecture)
- **`IFile`**: 文件格式抽象（PE/Mach-O/ELF）。
- **`IArchitecture`**: 具体架构（x86/x64）的访问，包括入口点、镜像基址等。
- **`ISection / ISegment`**: 节区与段的操作。

### C. 代码模型 (Code Model)
- **`IFunction`**: 函数级别操作，包括编译类型设置。
- **`ICommand`**: 指令级别操作，读取/修改机器码。
- **`IntelOperand`**: 指令操作数细节。

### D. 辅助系统
- **`IImport / IExport`**: 导入导出表。
- **`IFixup / IRelocation`**: 重定位与修复逻辑。
- **`MapFile`**: 符号映射文件解析。

## 4. 架构模式 (Architecture Pattern)
该模块采用了经典的 Lua 5.1/5.2 C API 模式：
1. **注册表结构**: 使用 `luaL_Reg` 数组定义每个类的方法名与 C 函数映射。
2. **辅助宏/函数**:
   - `push_object`: 将 C++ 指针包装入 Lua。
   - `check_object`: 从 Lua 堆栈获取并校验 C++ 指针。
   - `register_class`: 创建元表（Metatable）并设置 `__index` 以模拟类继承。
3. **分发逻辑**: 大量手写的静态包装函数，遵循 `获取参数 -> 执行 C++ 调用 -> 返回结果到堆栈` 的流程。

## 5. 迁移与删除说明 (Removal Rationale)
- **现状**: 4700+ 行的手写代码，维护成本极高，容易产生堆栈错误或内存泄漏。
- **目标**: 未来通过 Rust 的 **`mlua`** 库替代。
- **优势**: Rust 可以利用宏（Macros）根据结构体定义**自动生成**这些绑定代码，消除手写胶合层的需求。

---
*注：此文档用于记录 `script.cc` 的功能点，以便在删除该文件后，在 Rust 迁移阶段能够完整还原脚本接口功能。*
