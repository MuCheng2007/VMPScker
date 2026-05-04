# VMProtect 项目配置文件 (.vmp) 规范文档

本文档记录了旧版 VMProtect 基于 XML 的项目文件格式，用于指导未来 Rust 版本的配置解析重构。

## 1. 根节点 (Document)
- **Version**: 版本号（通常为 2）。

## 2. 核心保护节点 (Protection)
### 2.1 全局属性
| XML 属性名 | Core 成员变量 | 说明 |
| :--- | :--- | :--- |
| `InputFileName` | `input_file_name_` | 原始待保护二进制文件的相对路径。 |
| `OutputFileName` | `output_file_name_` | 保护后生成的文件的保存路径。 |
| `Options` | `options_` | 全局保护标志位（如调试器检测、内存保护开关）。 |
| `VMOptions` | `vm_options_` | 虚拟机特定的配置（如乱序执行深度）。 |
| `VMCodeSectionName` | `vm_section_name_` | 存放混淆代码的新节区名称（默认 .vmp）。 |
| `HWID` | `hwid_` | 限制程序只能在特定硬件 ID 的机器上运行。 |
| `LicenseDataFileName` | `license_data_file_name_` | 关联的授权配置文件路径。 |

### 2.2 提示消息 (Messages)
节点路径：`Protection -> Messages -> Message`
- **Id**: 消息索引（对应 `Core` 中的枚举，如调试器发现、文件损坏等）。
- **内容**: 用户自定义的弹出文本。

### 2.3 混淆函数配置 (Procedures)
节点路径：`Protection -> Procedures -> Procedure`
每个 `Procedure` 代表一个需要被混淆或虚拟化的函数。
- **MapAddress**: 函数名（来自符号表或 MAP 文件）。
- **Address**: 原始 RVA 地址（当没有函数名时使用）。
- **CompilationType**: 保护模式：
    - `0`: 变异 (Mutation)
    - `1`: 虚拟化 (Virtualization)
    - `2`: 超级虚拟化 (Ultra)
- **Options**: 函数特定的标志位。
- **Index**: 符号索引（处理同名重载函数）。
- **ExtOffset**: 额外入口点（处理跳转表或非标准进入逻辑）。

### 2.4 对象排除 (Objects)
节点路径：`Protection -> Objects -> Object`
用于排除特定段、资源或导入表的保护。
- **Type**: `Segment`, `Resource`, 或 `Import`。
- **Name**: 对象名称。
- **属性**: `ExcludedFromPacking`, `ExcludedFromMemoryProtection` 等。

## 3. 重构建议 (JSON 映射)
在 Rust 中，建议使用 `serde` 库定义如下结构体：

```rust
#[derive(Serialize, Deserialize)]
struct VmpConfig {
    project_version: u32,
    input_file: String,
    output_file: String,
    protection_options: u32,
    sections: Vec<ProtectedFunction>,
    custom_messages: HashMap<u32, String>,
}
```

---
*此文档用于在删除 `core.cc` 中的 XML 解析代码后保持逻辑参考。*
