# VMPScker Rust 项目全文件职责表

## Workspace 根目录

| 文件 | 大小 | 职责说明 |
|------|------|----------|
| `Cargo.toml` | 553B | Workspace 根配置，定义 3 个 crate 成员 (`vmp-core`, `vmp-cli`, `vmp-runtime`) 及共享依赖版本 |
| `Cargo.lock` | 37KB | 依赖版本锁定文件 |
| `rust-toolchain.toml` | 66B | Rust 工具链版本固定 |

---

## Crate 1: `vmp-core` — 核心引擎库

### 顶层文件

| 文件路径 | 大小 | 职责说明 |
|----------|------|----------|
| `vmp-core/Cargo.toml` | 747B | crate 依赖声明（iced-x86, goblin, rand, aes-gcm, rsa, slotmap 等） |
| `vmp-core/src/lib.rs` | 193B | 模块导出中心，pub mod 了 `error`, `pe`, `intel`, `protector`, `vm` |
| `vmp-core/src/error.rs` | 871B | 全局错误类型定义 (`VmpError`)，使用 `thiserror` 派生 |
| `vmp-core/src/protector.rs` | 8.7KB | **保护器主入口**。`VmpProtector` 结构体，编排整体保护流程：加载 PE → 识别 Marker → 提取函数 → 虚拟化/变异 → 重建 PE 输出 |
| `vmp-core/src/test_vm_conversion.rs` | 4.6KB | VM 转换逻辑的单元测试文件 |

---

### `vmp-core/src/pe/` — PE 文件读写与重建子系统 (23 个文件)

这是项目中最成熟、代码量最大的模块，负责 Windows PE 可执行文件的完整解析与重建。

| 文件 | 大小 | 职责说明 |
|------|------|----------|
| `mod.rs` | 2.2KB | PE 模块导出入口 |
| `file.rs` | 3.0KB | PE 文件顶层抽象（打开文件、识别 PE32/PE64） |
| `section.rs` | 4.0KB | PE Section Header 解析（.text, .data, .rdata 等节表读写） |
| `segment.rs` | 5.9KB | 内存段映射（RVA ↔ 文件偏移转换） |
| `import.rs` | 11.6KB | **IAT 导入表解析**（解析 DLL 名、函数名、Thunk 数组） |
| `import_rebuilder.rs` | 14.0KB | **IAT 导入表重建器**（虚拟化后需要重新构造导入描述符） |
| `delay_import.rs` | 2.3KB | 延迟加载导入表解析 |
| `export.rs` | 18.2KB | **导出表解析**（解析导出函数名序号表、ForwarderRVA） |
| `relocation.rs` | 17.4KB | **重定位表解析与重建**（处理 BASE RELOCATION 块，支持 HIGHLOW/DIR64 类型） |
| `exception.rs` | 37.3KB | **异常处理表解析**（x64 `.pdata` Unwind Info、SEH 数据结构完整解析） |
| `debug.rs` | 7.0KB | 调试目录解析（CodeView、PDB 路径提取） |
| `tls.rs` | 13.3KB | TLS 回调表解析与重建 |
| `resource.rs` | 36.4KB | **资源表完整解析器**（递归解析 RESOURCE_DIRECTORY 树、Icon/Version/Manifest 等） |
| `resource_rebuilder.rs` | 18.6KB | **资源表重建器**（在修改 PE 后重新序列化整棵资源树） |
| `load_config.rs` | 8.3KB | Load Config Directory 解析（SafeSEH Handler 表、CFG 数据） |
| `directory.rs` | 4.1KB | 数据目录（Data Directory）的通用读取接口 |
| `map_function.rs` | 60.2KB | **函数映射器**（最大文件！解析符号表、反汇编识别函数边界、构建函数→地址映射） |
| `marker_detector.rs` | 15.9KB | **VMP Marker 检测器**（扫描 PE 中的 VMProtectBegin/End SDK Marker 标记对） |
| `vmp_marker_finder.rs` | 19.8KB | **Marker 搜索引擎**（基于模式匹配的高级 Marker 查找，支持多种 SDK 版本签名） |
| `modify.rs` | 9.2KB | PE 就地修改工具（Patch 节区内容、修改入口点、调整节属性） |
| `rebuilder.rs` | 29.0KB | **PE 完整重建器**（核心！将修改后的所有节区、目录、头部重新序列化为完整 PE 文件） |
| `writer.rs` | 15.1KB | 底层二进制写入器（按对齐写入节区数据、填充 Padding） |
| `utils.rs` | 5.3KB | PE 相关工具函数（对齐计算、RVA 转换、字符串读取） |

---

### `vmp-core/src/intel/` — x86/x64 反汇编与 IR 转换子系统 (10 个文件)

基于 `iced-x86` 构建的指令处理流水线。

| 文件 | 大小 | 职责说明 |
|------|------|----------|
| `mod.rs` | 4.4KB | Intel 模块导出入口，定义公共类型别名 |
| `decoder.rs` | 11.0KB | **反汇编前端**。封装 `iced_x86::Decoder`，将原始字节流解码为 `iced_x86::Instruction` 序列 |
| `encoder.rs` | 134.8KB | **汇编编码器**（巨型文件！将修改后的指令重新编码为机器码字节，处理所有 x86/x64 编码格式） |
| `instruction.rs` | 20.6KB | **指令抽象层**。对 `iced_x86::Instruction` 进行二次封装，添加 Marker、Link 等元数据 |
| `formatter.rs` | 10.5KB | 指令格式化输出（将指令转为可读的汇编文本，用于调试和日志） |
| `basic_block.rs` | 10.7KB | **基本块构建器**。将线性指令流按跳转边界切割为 `BasicBlock` |
| `cfg.rs` | 18.1KB | **控制流图构建器**。在基本块之上建立 CFG 有向图（后继/前驱边、支配树） |
| `function.rs` | 13.2KB | **函数级分析**。以函数为单位管理基本块集合，处理函数调用边界和返回地址 |
| `ir.rs` | 28.9KB | **IR 中间表示定义**。定义 `IrOpcode`, `IrOperand`, `IrRegister`, `IrMemoryOperand`, `IrCondition`, `IrJumpTarget` 等全套 IR 类型枚举 |
| `ir_converter.rs` | 15.0KB | **IR 转换器**。将 `iced_x86::Instruction` 提升 (Lift) 为自定义的 `IrInstruction` |
| `assembler/` | 空目录 | 预留的汇编器模块（尚未实现） |
| `tests/` | 空目录 | 预留的测试模块 |

---

### `vmp-core/src/ir/` — 通用 IR 抽象层 (4 个文件, 均为占位)

| 文件 | 大小 | 职责说明 |
|------|------|----------|
| `mod.rs` | 145B | IR 模块导出入口（占位） |
| `instruction.rs` | 99B | 通用 IR 指令定义（占位，实际 IR 在 `intel/ir.rs` 中） |
| `operand.rs` | 154B | 通用 IR 操作数定义（占位） |
| `function.rs` | 152B | 通用 IR 函数定义（占位） |

---

### `vmp-core/src/crypto/` — 加密子系统 (3 个文件, 均为占位)

| 文件 | 大小 | 职责说明 |
|------|------|----------|
| `mod.rs` | 72B | 加密模块导出入口 |
| `aes.rs` | 68B | AES-GCM 加密封装（占位） |
| `rsa.rs` | 75B | RSA 非对称加密封装（占位） |

---

### `vmp-core/src/pack/` — 打包/压缩子系统 (1 个文件, 占位)

| 文件 | 大小 | 职责说明 |
|------|------|----------|
| `mod.rs` | 19B | 打包模块导出入口（占位） |

---

### `vmp-core/src/project/` — 项目配置管理 (3 个文件)

| 文件 | 大小 | 职责说明 |
|------|------|----------|
| `mod.rs` | 237B | 项目模块导出入口 |
| `config.rs` | 6.8KB | **项目配置解析器**。定义 `.vms` 项目文件的 TOML 结构（保护范围、编译选项、密钥等） |
| `loader.rs` | 1.2KB | 项目文件加载器（从磁盘读取 `.vms` 并反序列化为 Config） |

---

### `vmp-core/src/vm/` — 虚拟机核心 ⚠️ 当前为空（已删除旧代码，等待重建）

| 文件 | 大小 | 职责说明 |
|------|------|----------|
| *(空目录)* | — | 旧代码已删除，将按重构方案分五阶段重建 |

---

### `vmp-core/tests/` — 集成测试 (6 个文件)

| 文件 | 大小 | 职责说明 |
|------|------|----------|
| `pe_test.rs` | 6.2KB | PE 基础解析测试（读取头部、节区） |
| `pe_full_test.rs` | 11.5KB | PE 完整流程测试（解析→修改→重建→验证） |
| `pe_modify_test.rs` | 6.0KB | PE 修改功能测试（Patch 字节、改节属性） |
| `pe_real_file_test.rs` | 16.5KB | 真实 PE 文件测试（使用实际 exe/dll 进行验证） |
| `pe_debug_test.rs` | 3.8KB | PE 调试信息解析测试 |
| `core_cpp_comparison_test.rs` | 15.4KB | **C++ 核心对照测试**（与原版 C++ 引擎输出进行一致性验证） |

---

## Crate 2: `vmp-cli` — 命令行工具

| 文件路径 | 大小 | 职责说明 |
|----------|------|----------|
| `vmp-cli/Cargo.toml` | 591B | CLI crate 依赖声明 |
| `vmp-cli/src/main.rs` | 5.0KB | **CLI 入口点**。解析命令行参数，调用 `vmp-core` 的 `protect_file` 接口 |
| `vmp-cli/src/marker_cmd.rs` | 13.9KB | **Marker 子命令**。扫描 PE 中的 VMP SDK Marker 并输出报告 |
| `vmp-cli/src/vm_test.rs` | 6.2KB | CLI 层面的 VM 功能测试 |

---

## Crate 3: `vmp-runtime` — 运行时保护库 (均为占位)

| 文件路径 | 大小 | 职责说明 |
|----------|------|----------|
| `vmp-runtime/Cargo.toml` | 431B | Runtime crate 依赖声明 |
| `vmp-runtime/src/lib.rs` | 183B | Runtime 模块导出入口 |
| `vmp-runtime/src/anti_debug.rs` | 46B | 反调试检测（占位） |
| `vmp-runtime/src/hooks.rs` | 92B | API Hook 机制（占位） |
| `vmp-runtime/src/hwid.rs` | 50B | 硬件指纹采集（占位） |
| `vmp-runtime/src/licensing.rs` | 102B | 授权验证（占位） |
| `vmp-runtime/src/strings.rs` | 72B | 字符串加密/解密（占位） |

---

## 成熟度总结

| 模块 | 状态 | 说明 |
|------|------|------|
| `pe/` (23 文件, ~337KB) | ✅ **成熟** | PE 解析/重建/Marker 检测完整可用 |
| `intel/` (10 文件, ~267KB) | ✅ **成熟** | 反汇编、IR 提升、CFG 构建完整可用 |
| `project/` (3 文件, ~8KB) | ✅ 可用 | 项目配置加载正常工作 |
| `protector.rs` (8.7KB) | ⚡ 基础可用 | 保护流程编排已搭建，等待 VM 模块接入 |
| `vm/` (空) | ❌ **待重建** | 核心虚拟机模块，将按五阶段方案重写 |
| `crypto/` (占位) | 🔲 占位 | 待实现 AES/RSA 封装 |
| `ir/` (占位) | 🔲 占位 | 通用 IR 层占位，实际 IR 在 intel 子模块 |
| `pack/` (占位) | 🔲 占位 | 待实现打包/压缩 |
| `vmp-runtime` (占位) | 🔲 占位 | 运行时库待实现 |
