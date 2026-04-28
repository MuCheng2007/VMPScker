# VMProtect GUI - 超级详细技术规格说明书 (Super Detailed Technical Specs)

## 1. 核心架构：响应式数据绑定 (Reactive Data Binding)
GUI 的核心不是简单的界面，而是一套将 C++ 核心对象映射到 UI 控件的**响应式框架**。

### 1.1 Property 系统 (位于 `property_editor.h/cc`)
这是 GUI 的灵魂。它定义了一套多态属性类：
- **基类 `Property`**: 提供名称、提示信息、只读状态和 `createEditor` 虚函数。
- **子类群**:
    - `StringProperty`: 映射到 `QLineEdit`。
    - `BoolProperty`: 映射到 `QCheckBox`。
    - `EnumProperty`: 映射到 `QComboBox`，处理固定选项（如调试器检测模式）。
    - `CompilationTypeProperty`: 特化的枚举，处理“变异/虚拟化/超级”保护模式切换。
    - `FileNameProperty`: 包含文件选择逻辑。
    - `CommandProperty`: 特化的指令显示属性，支持静态文本颜色（如汇编指令的高亮）。

### 1.2 PropertyManager (绑定逻辑)
这是 C++ 核心与 UI 之间的桥梁。
- **工作流**: 
    1. UI 选中一个节点（如函数）。
    2. 触发 `setValue(IFunction *func)`。
    3. `PropertyManager` 遍历该对象的所有属性，通过核心 API 读取值。
    4. **信号槽循环**: 当用户在 UI 中修改属性时，属性对象发射 `valueChanged` 信号，`PropertyManager` 捕获并调用核心对象的 `setter` 方法。
- **具体实现类**:
    - `CorePropertyManager`: 管理全局保护选项、输出路径、水印选择。
    - `FunctionPropertyManager`: 管理特定函数的保护级别、地址和锁定状态。
    - `LicensePropertyManager`: 涉及 RSA 密钥、序列号数据、HWID 逻辑。

## 2. Model-View 系统深度解析 (Models)
为了处理数以万计的函数和庞大的二进制数据，GUI 采用了高效的虚拟模型：

### 2.1 虚拟内存转储 (DumpModel)
- **挑战**: 二进制文件可能有几百 MB，不能全部存入内存模型。
- **方案**: `DumpModel` 是一个“虚”模型。
    - `rowCount()` 根据节区大小动态计算。
    - `data()` 被调用时，才会通过 `file_->read(address, size)` 实时读取字节。
    - 实现了 `addressToIndex` 映射，支持快速跳转。

### 2.2 实时反汇编视图 (DisasmModel)
- **逻辑**: 它持有一个 `IArchitecture` 引用。
- **渲染**: 同样采用按需渲染。当视图请求绘制某一行时，模型调用核心的反汇编引擎解析该地址处的指令，并格式化为 `IntelCommand` 显示。

### 2.3 项目树 (ProjectModel)
- **数据结构**: `ProjectNode` 构成的多叉树。
- **NodeType 映射**: 定义了从 `NODE_ROOT` 到 `NODE_ASSEMBLIES` 的 50 多种节点类型。
- **交互**: 实现了复杂的 MIME 拖拽逻辑，允许用户在 UI 上自由组织函数文件夹，这些改动会实时反映在核心的 `Project` 对象中。

## 3. 通知与日志系统 (Notification Flow)
- **`GUILog` 类**: 这是 `ILog` 接口在 GUI 中的实现。
- **解耦方式**: 
    1. 核心层产生 `MessageType` 消息。
    2. `GUILog` 接收并将其封装为 Qt 信号。
    3. `MainWindow::notify` 槽函数捕获信号。
    4. 更新 `LogModel`，同时根据消息级别（信息/警告/错误）改变状态栏或弹出对话框。

## 4. 关键功能模块的底层实现
### 4.1 授权管理 (Licensing)
- **密钥生成**: 调用 RSA 算法生成密钥对，并同步更新 `CorePropertyManager` 中的十六进制文本显示。
- **序列号**: 解析和生成满足 `VMProtectSetSerialNumber` 要求的二进制块。

### 4.2 脚本编辑器 (Scripting)
- **组件**: 基于 Scintilla 控件。
- **集成**: 提供 Lua 语法高亮、自动缩进和行号显示。
- **交互**: 脚本运行时的输出会重定向到 `LogModel`，且支持点击日志行自动定位到脚本代码。

## 5. 迁移至 Rust 的架构参考
- **状态管理**: 建议在 Rust 中使用 `Observer` 模式或 `Redux-like` 的状态树替代 C++ 混乱的裸指针 (`void *data`) 绑定。
- **UI 框架**: 推荐使用 `iced`, `slint` 或 `egui`，它们原生支持声明式 UI，可以极大简化 `PropertyManager` 的繁琐逻辑。
- **FFI 层**: 使用 `cxx` 或 `autocxx` 来桥接现有的 C++ 核心，直到核心也完成 Rust 迁移。

---
*此文档提供了 GUI 内部运作的完整技术视图，足以支撑在没有任何源码参考的情况下重建其业务逻辑。*
