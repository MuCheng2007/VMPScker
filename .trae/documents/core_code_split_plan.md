# Core 文件夹代码拆分方案

## 当前代码结构分析

### 现有文件统计
- **主目录**: 24 个文件 (12 个 .cc + 12 个 .h)
- **core_internal**: 10 个文件 (5 个 .cc + 5 个 .h)
- **总计**: 34 个文件

### 文件大小分析（按代码量排序）
1. **intel.cc** - 最大文件，包含 Intel x86/x64 指令处理逻辑
2. **pefile.cc** - PE 文件格式处理
3. **core.cc** - 核心逻辑（已部分拆分出 core_internal）
4. **script.cc** - Lua 脚本绑定
5. **files.cc** - 文件操作
6. **processors.cc** - 处理器相关
7. **objects.cc** - 基础对象
8. **streams.cc** - 流操作
9. **packer.cc** - 压缩相关
10. **lang.cc** - 多语言支持
11. **inifile.cc** - INI 文件处理

---

## 拆分方案

### 一、Intel 处理器模块拆分 (intel.cc/intel.h)

当前 **intel.cc** 过大，建议拆分为：

```
core/intel/
├── intel_base.cc/h          - IntelCommand 基础类
├── intel_decoder.cc/h       - 指令解码
├── intel_encoder.cc/h       - 指令编码
├── intel_vm.cc/h            - VM 命令生成
├── intel_obfuscation.cc/h   - 混淆处理
├── intel_compile.cc/h       - 编译逻辑
└── intel_utils.cc/h         - 工具函数
```

**依赖关系**:
- intel_base 无依赖
- intel_decoder/encoder 依赖 intel_base
- intel_vm 依赖 intel_base + decoder
- intel_obfuscation 依赖 intel_base + vm
- intel_compile 依赖所有其他模块

---

### 二、PE 文件模块拆分 (pefile.cc/pefile.h)

```
core/pe/
├── pe_base.cc/h             - PE 基础结构
├── pe_segment.cc/h          - 段/节处理
├── pe_import.cc/h           - 导入表处理
├── pe_export.cc/h           - 导出表处理
├── pe_resource.cc/h         - 资源处理
├── pe_reloc.cc/h            - 重定位处理
├── pe_tls.cc/h              - TLS 处理
├── pe_loadconfig.cc/h       - 加载配置
├── pe_runtime.cc/h          - 运行时库嵌入
└── pe_compile.cc/h          - 编译逻辑
```

**依赖关系**:
- pe_base 无依赖
- 其他模块都依赖 pe_base
- pe_compile 依赖所有其他模块

---

### 三、Script 模块拆分 (script.cc/script.h)

```
core/script/
├── script_base.cc/h         - Lua 基础绑定
├── script_core.cc/h         - Core 类绑定
├── script_licenses.cc/h     - 许可证绑定
├── script_files.cc/h        - 文件管理绑定
├── script_watermarks.cc/h   - 水印绑定
├── script_project.cc/h      - 项目选项绑定
└── script_utils.cc/h        - 脚本工具函数
```

**依赖关系**:
- script_base 无依赖
- 其他绑定模块依赖 script_base
- script_core 依赖其他所有绑定模块

---

### 四、Files 模块拆分 (files.cc/files.h)

```
core/file/
├── file_base.cc/h           - 文件基础类
├── file_operation.cc/h      - 文件操作
├── file_function.cc/h       - 函数管理
├── file_folder.cc/h         - 文件夹管理
├── file_import.cc/h         - 导入处理
├── file_map.cc/h            - MAP 文件处理
├── file_export.cc/h         - 导出处理
└── file_utils.cc/h          - 文件工具
```

---

### 五、Processors 模块拆分 (processors.cc/processors.h)

```
core/processor/
├── proc_base.cc/h           - 处理器基础
├── proc_address.cc/h        - 地址范围处理
├── proc_link.cc/h           - 链接处理
├── proc_cryptor.cc/h        - 加密器
├── proc_command.cc/h        - 命令处理
├── proc_function.cc/h       - 函数处理
├── proc_block.cc/h          - 代码块处理
└── proc_utils.cc/h          - 工具函数
```

---

### 六、Streams 模块拆分 (streams.cc/streams.h)

```
core/stream/
├── stream_base.cc/h         - 流基础类
├── stream_memory.cc/h       - 内存流
├── stream_file.cc/h         - 文件流
├── stream_buffer.cc/h       - 缓冲流
└── stream_utils.cc/h        - 流工具
```

---

### 七、Objects 模块拆分 (objects.cc/objects.h)

```
core/object/
├── object_base.cc/h         - 对象基础
├── object_list.cc/h         - 列表对象
├── object_addressable.cc/h  - 可寻址对象
├── object_named.cc/h        - 命名对象
└── object_utils.cc/h        - 对象工具
```

---

## 实施步骤

### 第一阶段：基础模块拆分（低风险）
1. **streams** → stream/ 目录
2. **objects** → object/ 目录
3. **packer** → 保持现状（已较小）
4. **inifile** → 保持现状（已较小）
5. **lang** → 保持现状（已较小）

### 第二阶段：核心模块拆分（中风险）
1. **processors** → processor/ 目录
2. **files** → file/ 目录
3. **script** → script/ 目录

### 第三阶段：大型模块拆分（高风险）
1. **pefile** → pe/ 目录
2. **intel** → intel/ 目录

### 第四阶段：整理 core_internal
1. 将 watermark 移至 core/watermark/
2. 将 license 移至 core/license/
3. 将 file_manager 移至 core/file/
4. 将 project_template 移至 core/template/
5. 保留 core_internal 仅用于工具类

---

## 依赖关系图

```
                    ┌─────────────┐
                    │   runtime   │
                    └──────┬──────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
   ┌─────────┐       ┌─────────┐       ┌─────────┐
   │ objects │◄─────►│ streams │◄─────►│ osutils │
   └────┬────┘       └────┬────┘       └─────────┘
        │                 │
        ▼                 ▼
   ┌─────────┐       ┌─────────┐
   │ packer  │       │ processors
   └─────────┘       └────┬────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
   ┌─────────┐      ┌─────────┐      ┌─────────┐
   │  files  │◄────►│  intel  │◄────►│ pefile  │
   └────┬────┘      └─────────┘      └────┬────┘
        │                                 │
        └────────────────┬────────────────┘
                         │
                         ▼
                   ┌─────────┐
                   │  core   │
                   └────┬────┘
                        │
                        ▼
                   ┌─────────┐
                   │ script  │
                   └─────────┘
```

---

## 文件命名规范

1. **模块目录**: 使用单数名词（如 `intel/` 而非 `intels/`）
2. **文件命名**: `模块名_功能.cc/h`
3. **类命名**: 保持原命名风格（如 `IntelCommand`）
4. **头文件保护**: `MODULE_FILENAME_H`

---

## 注意事项

1. **循环依赖**: 需要仔细处理 objects 和 processors 之间的依赖
2. **前向声明**: 大量使用前向声明减少头文件依赖
3. **预编译头**: 更新 precompiled.h 包含新的头文件路径
4. **构建系统**: 需要更新 CMake/Makefile 添加新的源文件
5. **测试**: 每拆分一个模块后立即编译测试
