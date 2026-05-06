# VMProtect Core Refactoring: Advanced Native Engine Walkthrough

我们刚刚完成了一场底层架构的“大换血”。这篇文档总结了我们将 VMProtect 核心引擎从**“缓慢且易受攻击的 C++ 解释器模式”**彻底重构为**“高性能、纯原生、AOT 代码生成的 Rust 引擎”**的全过程。

## 架构痛点与重构动机

在重构前，项目包含了一个名为 `src/vm/` 的臃肿模块，其内部使用了一个名为 `NativeVMContext` 的庞大结构体来模拟 CPU 寄存器，并在宿主 Rust 语言层面上通过巨大的 `match opcode` 循环来执行虚拟机指令（例如 `context.rax = context.rax + context.rbx`）。

> [!WARNING]
> 这是一种**致命的错误架构**，原因如下：
> 1. **性能毁灭**：频繁的语言层切换导致严重的性能开销。
> 2. **标志位失真**：宿主语言（Rust/C++）层面模拟的算术运算**无法完美还原原生 CPU 的 EFLAGS 状态**（包括进位、溢出、符号、辅助进位等），这会导致被保护的程序运行产生不可预知的 Bug。
> 3. **极易被破解**：集中式的 Dispatcher 循环（大 Switch-Case）是符号执行和反汇编器最容易识别和打破的“软肋”。

## 全新架构设计 (基于 `vtAdvanced`)

我们严格对齐了 C++ 源码中的 `vtAdvanced`（高级虚拟机）架构，移除了所有的模拟层代码，采用了 **"Threaded Code (内联调度)"** 和 **"Native Execution (原生执行)"** 模型。

### 1. `src/vm/arch.rs`: 核心映射引擎
保护强度的核心在于**随机化**。
- **四重特殊寄存器**：定义了 `VSP` (虚拟栈)、`VIP` (虚拟指令指针)、`VJMP` (动态分发基址) 和 `VCRYPT` (流解密密钥)。
- **动态映射**：在每次保护时，引擎会将这些特殊寄存器以及通用的 `R0-R15` 随机分配给真实的物理硬件寄存器 (如 `R14`, `RSI` 等)。
- **滚动加密流**：为每个被保护的函数生成独一无二的加密流水线组合 (如先 `Sub` 再 `Rol` 再 `Xor`)。

### 2. `src/vm/interpreter.rs`: 内联调度宏
彻底抛弃了 `switch-case`，取而代之的是一段直接粘贴在每个微指令末尾的原生汇编宏 (`generate_next_instruction_fetch`)：
```assembly
mov al, byte ptr [VIP]    ; 获取被加密的字节码
xor rax, VCRYPT           ; 使用动态密钥解密
add VCRYPT, rax           ; 更新下一轮的密钥 (Rolling Key)
inc VIP                   ; 指针推移
shl rax, 3                
add rax, VJMP             ; 加上 Handler 数组基址计算偏移
mov rax, qword ptr [rax]  
mov qword ptr [rsp], rax  ; 覆盖栈顶
ret                       ; 出栈直接飞跃到下一个真实 Handler
```
> [!TIP]
> 这种执行流没有任何规律可循，并且因为 `ret` 导致的间接跳转，几乎可以瘫痪所有静态分析工具的 CFG（控制流图）构建。

### 3. `src/vm/handlers.rs`: 完美的微指令
在这里，我们利用 `iced-x86` 的宏直接生成原生机器码。
**原生 EFLAGS 同步**：
比如在加法 (`vAdd`) 中，我们直接在机器层面执行 `add rax, rcx`，并在下一微秒立刻执行 `pushfq`，将真实的、包含了硬件运算奥秘的标志位直接捕获到虚拟栈上。

> [!IMPORTANT] Check Stack 动态栈扩容机制
> 这是复刻 C++ 逻辑时最精妙的一环：当虚拟栈 (`VSP`) 不断向下生长，即将撞击真实的宿主栈底 (`RSP`) 时，引擎将触发 `generate_check_stack`。它会**强行将真实物理栈向下推移**，并将整个执行上下文完整地搬迁过去，为虚拟机提供近乎无尽的安全栈空间，杜绝了 Stack Overflow 崩溃的可能！

### 4. `src/vm/compiler.rs`: 字节码编译器
将最上游 `decoder.rs` 生成的标准 x86 汇编（IR），智能“降级 (Lowering)”为我们的微指令组合。
例如，一条简单的 `SUB EAX, EBX` 会被编译器拆解为加密的字节流，对应：
1. `vPushReg (EBX映射的槽位)`
2. `vPushReg (EAX映射的槽位)`
3. `vSub`
4. `vPopReg (EAX映射的槽位)`
在这个过程中，生成的每一个字节码都会经过 `encrypt_byte` 的流加密混淆。

## 最终集成：`protector.rs`
最终，所有模块在 `protector.rs` 会师。输入一个需要保护的 PE 文件，引擎将会：
1. 生成唯一的 `ArchConfig` 和加密密钥。
2. 驱动 `Compiler` 把函数编译成一团乱码的二进制数组。
3. 驱动 `Interpreter` 和 `Handlers` 生成执行这团乱码的专属原生外壳 (Shellcode)。

目前所有的生成管道已成功连接，并通过了 `cargo build` 编译！接下来的路线，将是真正的 PE 节区注入和入口点 (OEP) 劫持。
