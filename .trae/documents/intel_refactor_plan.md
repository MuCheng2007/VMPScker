# Intel 模块拆分计划

## 目标
将 `core/intel.h` 和 `core/intel.cc` 中的代码拆分为一个独立的 `intel/` 文件夹，按照功能模块进行组织。

## 当前状态
- `core/intel.h` - 包含所有 Intel 相关的类定义 (~1568 行)
- `core/intel.cc` - 包含所有 Intel 相关的实现 (~894KB)

## 目标结构

```
core/
├── intel/                           # 新的 Intel 模块目录
│   ├── ir/                          # 中间表示层 (Instruction Representation)
│   │   ├── IntelCommandType.h       # 仅存放枚举 (cmAdd, cmMov 等)
│   │   ├── IntelOperand.h/.cc       # 负责操作数解析 (寄存器/内存/立即数)
│   │   ├── IntelCommand.h/.cc       # 负责单条指令的中间表示
│   │   └── IntelCommandInfo.h/.cc   # 负责指令属性和元数据
│   ├── vm/                          # 虚拟机核心调度层
│   │   ├── IntelVirtualMachine.h/.cc      # 单个虚拟机实例的运行时抽象
│   │   ├── IntelVirtualMachineList.h/.cc  # 多虚拟机实例池管理
│   │   └── Handlers.h/.cc                 # (可选) 专门存放生成的 Handler 逻辑
│   └── crypto/                      # 密码学组件层
│       ├── OpcodeCryptor.h/.cc      # Opcode 的滚动解密抽象
│       └── ValueCryptor.h/.cc       # 常数和地址的加密解密
└── (intel.h 和 intel.cc 将被删除，代码按需分配到各子模块)
```

## 详细拆分方案

### 1. ir/IntelCommandType.h
**内容**: 从 intel.h 第 4-138 行提取
- `enum IntelCommandType` - 指令类型枚举
- `static const char *intel_command_name[]` - 指令名称数组
- `enum IntelFlags` - 标志位枚举
- `enum IntelRegistr` - 寄存器枚举
- `enum IntelSegment` - 段寄存器枚举
- `enum IntelRexFlags` - REX 前缀标志

### 2. ir/IntelOperand.h/.cc
**内容**: 从 intel.h 第 322-421 行提取
- `struct IntelOperand` - 操作数结构体
  - 成员变量: value, fixup, relocation, type, size, registr, base_registr, scale_registr, value_pos, address_size, value_size, show_size, is_large_value
  - 方法: Clear(), effective_base_segment(), encode(), decode(), operator==, operator!=
- 构造函数实现在 .cc 文件中

### 3. ir/IntelCommand.h/.cc
**内容**: 从 intel.h 第 532-689 行提取
- `class IntelCommand` - 指令类
  - 继承自 BaseCommand
  - 包含指令解析、汇编、虚拟化相关方法
  - 操作数管理 (operand_ 数组)
  - VM 命令生成
- 相关实现在 .cc 文件中

### 4. ir/IntelCommandInfo.h/.cc
**内容**: 从 intel.h 第 518-528 行提取
- `class IntelCommandInfoList` - 指令信息列表
  - 继承自 CommandInfoList
  - 管理指令的访问类型、操作数信息
- 实现在 .cc 文件中

### 5. vm/IntelVirtualMachine.h/.cc
**内容**: 从 intel.h 第 1497-1547 行提取
- `class IntelVirtualMachine` - 虚拟机类
  - 继承自 BaseVirtualMachine
  - 管理 VM 的初始化、编译、命令处理
  - 包含寄存器顺序、操作码列表、加密器等
- 实现在 .cc 文件中

### 6. vm/IntelVirtualMachineList.h/.cc
**内容**: 从 intel.h 第 1549-1566 行提取
- `class IntelVirtualMachineList` - 虚拟机列表
  - 继承自 IVirtualMachineList
  - 管理多个 VM 实例
  - CRC 管理
- 实现在 .cc 文件中

### 7. vm/IntelVirtualMachineProcessor.h/.cc
**内容**: 从 intel.h 第 1483-1493 行提取
- `class IntelVirtualMachineProcessor` - VM 处理器
  - 继承自 IntelFunction
  - 处理 VM 的混淆和异常处理
- 实现在 .cc 文件中

### 8. crypto/OpcodeCryptor.h/.cc
**内容**: 从 processors.h 第 452-463 行提取并扩展
- `class OpcodeCryptor` - 操作码加密器
  - 继承自 ValueCryptor
  - 专门用于操作码的滚动解密
- 实现在 .cc 文件中

### 9. crypto/ValueCryptor.h/.cc
**内容**: 从 processors.h 第 412-450 行提取并扩展
- `class ValueCommand` - 值命令
- `class ValueCryptor` - 值加密器
  - 用于常数和地址的加密解密
- 实现在 .cc 文件中

### 10. ir/IntelFunction.h/.cc (额外)
**内容**: 从 intel.h 第 723-793 行提取
- `class IntelFunction` - Intel 函数类
  - 继承自 BaseFunction
  - 管理函数级别的指令列表
  - 包含 SEH 处理、编译、链接等功能
- 大量相关实现在 .cc 文件中

### 11. ir/IntelFunctionList.h/.cc (额外)
**内容**: 从 intel.h 第 1035-1088 行提取
- `class IntelFunctionList` - Intel 函数列表
  - 继承自 BaseFunctionList
  - 管理平台相关的函数管理
- `class PEIntelFunctionList` - PE 格式专用
- `class MacIntelFunctionList` - Mac 格式专用
- `class ELFIntelFunctionList` - ELF 格式专用
- 实现在 .cc 文件中

### 12. vm/IntelVMCommand.h/.cc (额外)
**内容**: 从 intel.h 第 426-491 行提取
- `class IntelVMCommand` - VM 命令类
  - 继承自 BaseVMCommand
  - 表示虚拟机中的单条命令
  - 包含加密、链接、转储等功能
- 实现在 .cc 文件中

### 13. crypto/SectionCryptor.h/.cc (额外)
**内容**: 从 intel.h 第 693-714 行提取
- `class SectionCryptor` - 段加密器
- `class SectionCryptorList` - 段加密器列表
- 用于代码段的加密保护
- 实现在 .cc 文件中

### 14. ir/IntelOpcodeInfo.h/.cc (额外)
**内容**: 从 intel.h 第 1391-1434 行提取
- `class IntelOpcodeInfo` - 操作码信息
- `class IntelOpcodeList` - 操作码列表
- 管理 VM 操作码的元数据
- 实现在 .cc 文件中

### 15. ir/IntelObfuscation.h/.cc (额外)
**内容**: 从 intel.h 第 872-892 行提取
- `class IntelObfuscation` - 混淆类
  - 代码混淆功能
- 实现在 .cc 文件中

### 16. ir/IntelStack.h/.cc (额外)
**内容**: 从 intel.h 第 795-870 行提取
- `class IntelStackValue` - 栈值
- `class IntelStack` - 栈
- `class IntelRegistrValue` - 寄存器值
- `class IntelFlagsValue` - 标志值
- `class IntelRegistrStorage` - 寄存器存储
- 用于数据流分析
- 实现在 .cc 文件中

### 17. ir/IntelLoader.h/.cc (额外)
**内容**: 从 intel.h 第 1090-1389 行提取
- `class BaseIntelLoader` - 基础加载器
- `class PEIntelLoader` - PE 加载器
- `class MacIntelLoader` - Mac 加载器
- `class ELFIntelLoader` - ELF 加载器
- 平台特定的加载逻辑
- 实现在 .cc 文件中

### 18. ir/IntelSDK.h/.cc (额外)
**内容**: 从 intel.h 第 914-938 行提取
- `class IntelSDK` - SDK 支持
- `class PEIntelSDK` - PE SDK
- `class MacIntelSDK` - Mac SDK
- `class ELFIntelSDK` - ELF SDK
- SDK 相关功能
- 实现在 .cc 文件中

### 19. ir/IntelMisc.h/.cc (额外)
**内容**: 其他辅助类和结构
- `struct DisasmContext` - 反汇编上下文
- `struct AsmContext` - 汇编上下文
- `class IntelRegistrList` - 寄存器列表
- `class IntelFileHelper` - 文件辅助
- 其他辅助功能
- 实现在 .cc 文件中

## 依赖关系

### 头文件包含顺序
```
IntelCommandType.h (最基础，无依赖)
    ↓
IntelOperand.h (依赖 IntelCommandType.h)
    ↓
IntelCommandInfo.h (依赖 IntelOperand.h)
    ↓
IntelCommand.h (依赖以上所有)
    ↓
IntelFunction.h (依赖 IntelCommand.h)
    ↓
IntelFunctionList.h (依赖 IntelFunction.h)
    ↓
IntelVMCommand.h (依赖 IntelCommand.h)
    ↓
ValueCryptor.h (独立，但 processors.h 已定义)
    ↓
OpcodeCryptor.h (依赖 ValueCryptor.h)
    ↓
SectionCryptor.h (依赖 OpcodeCryptor.h)
    ↓
IntelVirtualMachine.h (依赖以上大部分)
    ↓
IntelVirtualMachineList.h (依赖 IntelVirtualMachine.h)
```

## 实施步骤

### 阶段 1: 创建基础文件
1. 创建目录结构 `core/intel/ir`, `core/intel/vm`, `core/intel/crypto`
2. 创建 `IntelCommandType.h` - 提取所有枚举
3. 创建 `IntelOperand.h/.cc` - 提取操作数相关
4. 更新 `core/intel.h` - 包含新头文件

### 阶段 2: 创建 IR 层
5. 创建 `IntelCommandInfo.h/.cc`
6. 创建 `IntelCommand.h/.cc`
7. 创建 `IntelVMCommand.h/.cc`
8. 创建 `IntelFunction.h/.cc`
9. 创建 `IntelFunctionList.h/.cc`

### 阶段 3: 创建 Crypto 层
10. 创建 `ValueCryptor.h/.cc`
11. 创建 `OpcodeCryptor.h/.cc`
12. 创建 `SectionCryptor.h/.cc`

### 阶段 4: 创建 VM 层
13. 创建 `IntelVirtualMachine.h/.cc`
14. 创建 `IntelVirtualMachineList.h/.cc`
15. 创建 `IntelVirtualMachineProcessor.h/.cc`

### 阶段 5: 创建辅助文件
16. 创建 `IntelStack.h/.cc`
17. 创建 `IntelObfuscation.h/.cc`
18. 创建 `IntelOpcodeInfo.h/.cc`
19. 创建 `IntelLoader.h/.cc`
20. 创建 `IntelSDK.h/.cc`
21. 创建 `IntelMisc.h/.cc`

### 阶段 6: 更新构建系统
22. 更新 Visual Studio 项目文件 (.vcxproj)
23. 更新 Makefile 文件
24. 确保所有文件正确编译

### 阶段 7: 清理和引用更新
25. 删除原始的 `core/intel.h` 和 `core/intel.cc`
26. 更新所有引用 intel.h 的文件，按需包含特定子模块头文件

## 引用更新策略

原来包含 `#include "intel.h"` 的文件需要按需更新为包含具体的子模块头文件：

### 示例更新映射

| 原引用 | 按需替换为 |
|--------|-----------|
| `#include "intel.h"` (使用指令类型) | `#include "intel/ir/IntelCommandType.h"` |
| `#include "intel.h"` (使用操作数) | `#include "intel/ir/IntelOperand.h"` |
| `#include "intel.h"` (使用指令) | `#include "intel/ir/IntelCommand.h"` |
| `#include "intel.h"` (使用函数) | `#include "intel/ir/IntelFunction.h"` |
| `#include "intel.h"` (使用VM) | `#include "intel/vm/IntelVirtualMachine.h"` |
| `#include "intel.h"` (使用加密) | `#include "intel/crypto/ValueCryptor.h"` |

### 需要更新的文件清单

需要通过搜索找到所有包含 `intel.h` 的文件，并逐一分析其依赖：
- `core/*.cc` 文件
- `VMProtect/*.cc` 文件
- `VMProtectCon/*.cc` 文件
- `runtime/*.cc` 文件
- 其他可能引用的文件

## 风险评估

1. **编译时间增加**: 头文件拆分可能导致编译时间略微增加，但现代编译器的预编译头可以缓解
2. **循环依赖**: 需要仔细处理类之间的前向声明
3. **构建系统更新**: 需要更新所有平台的构建配置

## 验证清单

- [ ] 所有新文件创建完成
- [ ] 所有代码正确迁移
- [ ] 所有引用 intel.h 的文件更新为按需包含
- [ ] 原始的 intel.h 和 intel.cc 已删除
- [ ] 项目编译成功
- [ ] 所有功能测试通过
