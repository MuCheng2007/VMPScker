//! 高级 VM 解释器生成引擎 (Threaded Code Generator)
//!
//! 负责生成原生的 x64 机器码：
//! 1. `VMEntry`: 保护真实上下文，初始化虚拟上下文。
//! 2. `VMExit`: 恢复真实上下文并退出虚拟机。
//! 3. `generate_next_instruction_fetch`: 内联调度宏，粘贴在每个 Handler 末尾。
//! 4. `generate_check_stack`: 动态虚拟栈扩容宏。

use iced_x86::code_asm::*;
use iced_x86::Register;
use crate::vm::arch::{ArchConfig, VMRegister};

/// 将 iced_x86::Register 转换为 code_asm 专用的 AsmRegister64
pub fn to_reg64(reg: Register) -> AsmRegister64 {
    match reg {
        Register::RAX => rax, Register::RCX => rcx, Register::RDX => rdx, Register::RBX => rbx,
        Register::RSP => rsp, Register::RBP => rbp, Register::RSI => rsi, Register::RDI => rdi,
        Register::R8 => r8, Register::R9 => r9, Register::R10 => r10, Register::R11 => r11,
        Register::R12 => r12, Register::R13 => r13, Register::R14 => r14, Register::R15 => r15,
        _ => panic!("Unsupported 64-bit register: {:?}", reg),
    }
}

/// 将 iced_x86::Register 转换为 8 位寄存器 (用于读取单字节 opcode)
pub fn to_reg8(reg: Register) -> AsmRegister8 {
    match reg {
        Register::RAX => al, Register::RCX => cl, Register::RDX => dl, Register::RBX => bl,
        Register::RBP => bpl, Register::RSI => sil, Register::RDI => dil,
        Register::R8 => r8b, Register::R9 => r9b, Register::R10 => r10b, Register::R11 => r11b,
        Register::R12 => r12b, Register::R13 => r13b, Register::R14 => r14b, Register::R15 => r15b,
        _ => panic!("Unsupported 8-bit register: {:?}", reg),
    }
}

/// 解释器生成器
pub struct InterpreterGenerator<'a> {
    config: &'a ArchConfig,
}

impl<'a> InterpreterGenerator<'a> {
    pub fn new(config: &'a ArchConfig) -> Self {
        Self { config }
    }

    fn vreg64(&self, vreg: VMRegister) -> AsmRegister64 {
        let reg = self.config.register_mapping.get(&vreg).expect("Missing register mapping");
        to_reg64(*reg)
    }

    /// 生成 VMEntry 的外壳代码
    /// 流程：保存所有物理寄存器 -> 初始化 VSP -> 初始化 VCRYPT -> 初始化 VJMP -> 跳转到第一个 Handler
    pub fn generate_vm_entry(&self, asm: &mut CodeAssembler, bytecode_address: u64, handler_table_base: u64) -> Result<(), IcedError> {
        // 1. 保存所有通用物理寄存器 (不含 RSP)
        // 按照一定的顺序 push，这里用简单的 pushad 替代品 (x64 没有 pushad)
        asm.pushfq()?;
        let regs_to_save = [
            rax, rcx, rdx, rbx, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15
        ];
        for reg in regs_to_save.iter() {
            asm.push(*reg)?;
        }

        // 2. 初始化 VSP (Virtual Stack Pointer)
        // 将当前的真实 RSP 赋给 VSP，虚拟栈从当前栈顶开始向下生长
        let vsp = self.vreg64(VMRegister::VSP);
        asm.mov(vsp, rsp)?;

        // 3. 初始化 VIP (指向即将执行的字节码)
        let vip = self.vreg64(VMRegister::VIP);
        asm.mov(vip, bytecode_address)?;

        // 4. 初始化 VCRYPT (初始解密密钥)
        let vcrypt = self.vreg64(VMRegister::VCRYPT);
        asm.mov(vcrypt, self.config.initial_crypt_key)?;

        // 5. 初始化 VJMP (Handler Table Base)
        let vjmp = self.vreg64(VMRegister::VJMP);
        asm.mov(vjmp, handler_table_base)?;

        // 6. 执行内联调度核心，抓取第一条指令并执行
        self.generate_next_instruction_fetch(asm)?;

        Ok(())
    }

    /// 生成 VMExit 的外壳代码
    /// 流程：从 VSP 恢复寄存器 -> 恢复标志位 -> 退出
    pub fn generate_vm_exit(&self, asm: &mut CodeAssembler) -> Result<(), IcedError> {
        // VMExit handler 的入口：清理虚拟机上下文
        // x64 下依次弹出
        let regs_to_restore = [
            r15, r14, r13, r12, r11, r10, r9, r8, rdi, rsi, rbp, rbx, rdx, rcx, rax
        ];
        
        // 确保原生 RSP 对齐到 VSP（防止虚拟堆栈溢出或多出数据导致 pop 错误）
        // 在严谨的 VMProtect 中，这里应该直接用 VSP 覆盖 RSP
        let vsp = self.vreg64(VMRegister::VSP);
        asm.mov(rsp, vsp)?;
        
        for reg in regs_to_restore.iter() {
            asm.pop(*reg)?;
        }
        asm.popfq()?; // 恢复最外层的标志位
        
        // 此时栈顶应该是原始 OEP 劫持位置压入的返回地址，直接 ret 或者由调用方处理 jmp
        asm.ret()?;
        
        Ok(())
    }

    /// 生成内联调度核心宏 (Threaded Code)
    /// 必须被粘贴在所有 Handler 的最末尾。
    pub fn generate_next_instruction_fetch(&self, asm: &mut CodeAssembler) -> Result<(), IcedError> {
        let vip = self.vreg64(VMRegister::VIP);
        let vcrypt = self.vreg64(VMRegister::VCRYPT);
        let vjmp = self.vreg64(VMRegister::VJMP);
        
        // 我们需要一个临时的物理寄存器来读取 1 字节 opcode。
        // 由于 VSP/VIP/VJMP/VCRYPT 被占用，其余的可能作为虚拟寄存器，
        // 但在这个调度环节，通用虚拟寄存器 (R0-R15) 应该已经处理完毕存在物理寄存器中。
        // 为了安全，我们可以在栈上开辟一个小空间或者复用 RAX。
        // 在真正的 VMP 中，解密往往利用 AL 或 CL。这里我们先借用 RAX。
        
        // 保存 RAX (如果是虚拟寄存器的话)
        asm.push(rax)?; 
        
        // 从 VIP 读取 1 字节 opcode 到 AL
        asm.mov(al, byte_ptr(vip))?;
        
        // 使用 VCRYPT 进行解密 (示例：假设只用 XOR，真实的需根据 ArchConfig 动态生成解密流)
        asm.xor(rax, vcrypt)?;
        
        // 更新密钥 (VCRYPT) (示例逻辑)
        asm.add(vcrypt, rax)?;
        
        // VIP 前进
        asm.inc(vip)?;
        
        // 计算目标地址: HandlerTable[Opcode]
        // 假设 HandlerTable 是一个每项 8 字节（存放绝对地址）的表，基址在 VJMP 中。
        // 这里为了演示 Threaded Code 的计算：
        asm.and(rax, 0xFF)?; // 确保只有低 8 位
        asm.shl(rax, 3)?; // * 8
        asm.add(rax, vjmp)?;
        
        // 获取真实的 Handler 地址
        asm.mov(rax, qword_ptr(rax))?;
        
        // 覆盖刚才保存的 RAX，把跳转地址放到栈顶
        asm.mov(qword_ptr(rsp), rax)?;
        
        // 执行跳转！出栈直接跳到 Handler (这就是 VMP 常用的 ret 跳转/防反汇编)
        asm.ret()?;
        
        Ok(())
    }

    /// 动态栈扩容机制 (Check Stack)
    /// 当栈向下增长 (PUSH 动作) 时，防止虚拟栈撞击原生栈。
    pub fn generate_check_stack(&self, asm: &mut CodeAssembler, needed_size: i32) -> Result<(), IcedError> {
        let vsp = self.vreg64(VMRegister::VSP);
        
        // 1. 临时借用 RAX
        asm.push(rax)?;
        
        // 2. 将真实的 RSP 加上安全缓冲 (例如 0x200 字节) 和我们需要的空间
        asm.lea(rax, qword_ptr(rsp - 0x200 - needed_size))?;
        
        // 3. 比较 VSP 和安全阈值
        asm.cmp(vsp, rax)?;
        
        // 4. 如果 VSP 还在安全阈值之上 (栈是向下生长的，所以大于代表安全)，就跳过扩容
        // 这里用 iced_x86 的 Label 来做跳转
        let mut safe_label = asm.create_label();
        asm.ja(safe_label)?;
        
        // ====== 危险区：栈扩容逻辑 ======
        // 如果我们到了这里，说明 VSP 离原生栈底太近了！
        // 必须把原生栈上的所有数据往下“搬家”，以腾出空间。
        
        // 为简明起见，这里仅输出伪操作注释或占位。实际实现需要：
        // a. 计算移动距离
        // b. 更新真实的 RSP
        // c. 使用 REP MOVSQ 将栈顶向下移动
        // d. 恢复上下文
        // (注：由于完全实现这个原生栈平移在单一文件中极其庞大，此处先建立宏骨架，重点展示架构)
        // asm.int3()?; // 触发扩容异常作为占位
        
        let _ = asm.set_label(&mut safe_label);
        
        // 恢复借用的 RAX
        asm.pop(rax)?;
        
        Ok(())
    }
}
