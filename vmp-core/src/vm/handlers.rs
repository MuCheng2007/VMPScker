//! VM 核心操作码处理生成器 (Handlers)
//!
//! 负责为每一种 VMOpcode 生成对应的原生处理汇编。
//! 特点：
//! 1. 运算类 Handler 完美利用原生 CPU 产生 EFLAGS，并捕获至虚拟栈。
//! 2. 所有 Handler 以内联调度宏结束 (Threaded Code)。
//! 3. 产生栈扩张的 Handler 将在执行前注入 `Check Stack` 逻辑。

use iced_x86::code_asm::*;
use crate::vm::arch::{ArchConfig, VMRegister};
use crate::vm::interpreter::{InterpreterGenerator, to_reg64};

/// Handler 生成器
pub struct HandlerGenerator<'a> {
    config: &'a ArchConfig,
    interpreter: InterpreterGenerator<'a>,
}

impl<'a> HandlerGenerator<'a> {
    pub fn new(config: &'a ArchConfig) -> Self {
        Self {
            config,
            interpreter: InterpreterGenerator::new(config),
        }
    }

    /// 获取物理寄存器宏
    fn vreg(&self, reg: VMRegister) -> AsmRegister64 {
        let mapped = self.config.register_mapping.get(&reg).unwrap();
        to_reg64(*mapped)
    }

    // ==========================================
    // 堆栈类指令
    // ==========================================

    /// vPushReg: 将虚拟寄存器的值压入 VSP
    pub fn gen_push_reg(&self, asm: &mut CodeAssembler, target_reg: VMRegister) -> Result<(), IcedError> {
        let vsp = self.vreg(VMRegister::VSP);
        let reg = self.vreg(target_reg);
        
        // 这是一个导致 VSP 增长的指令，执行栈溢出检查
        // 我们需要 8 字节的空间
        self.interpreter.generate_check_stack(asm, 8)?;
        
        // 虚拟栈向下增长
        asm.sub(vsp, 8)?;
        // 将值压入虚拟栈
        asm.mov(qword_ptr(vsp), reg)?;
        
        // 调用 Threaded Code 跳向下个指令
        self.interpreter.generate_next_instruction_fetch(asm)?;
        Ok(())
    }

    /// vPopReg: 从 VSP 弹出数据到虚拟寄存器
    pub fn gen_pop_reg(&self, asm: &mut CodeAssembler, target_reg: VMRegister) -> Result<(), IcedError> {
        let vsp = self.vreg(VMRegister::VSP);
        let reg = self.vreg(target_reg);
        
        // 弹出数据
        asm.mov(reg, qword_ptr(vsp))?;
        // 虚拟栈回缩
        asm.add(vsp, 8)?;
        
        self.interpreter.generate_next_instruction_fetch(asm)?;
        Ok(())
    }

    // ==========================================
    // 算术与逻辑类指令 (重点：EFLAGS 捕获)
    // ==========================================

    /// vAdd: 将虚拟栈顶的两个元素相加
    /// 流程：弹 B -> 弹 A -> ADD A, B -> PUSHFQ (捕获真实原生标志位) -> 压 A+B -> 压 EFLAGS
    pub fn gen_add(&self, asm: &mut CodeAssembler) -> Result<(), IcedError> {
        let vsp = self.vreg(VMRegister::VSP);
        
        // 借用 RAX 和 RCX 用于运算 (先入原生栈保存)
        asm.push(rax)?;
        asm.push(rcx)?;
        
        // 读取虚拟栈操作数 (假设栈顶是 src, 紧接着是 dst)
        // VSP[0] = src (B)
        // VSP[8] = dst (A)
        asm.mov(rcx, qword_ptr(vsp))?;
        asm.mov(rax, qword_ptr(vsp + 8))?;
        
        // 执行原生 ADD 运算，产生真实的 CPU EFLAGS
        asm.add(rax, rcx)?;
        
        // 【关键】瞬间将原生 EFLAGS 压入真实栈
        asm.pushfq()?;
        
        // 运算结果写回原来的 dst 位置
        asm.mov(qword_ptr(vsp + 8), rax)?;
        
        // 将真实的 EFLAGS 弹入 RCX
        asm.pop(rcx)?;
        
        // 将 EFLAGS 写入虚拟栈顶 (原来存 src 的位置)
        asm.mov(qword_ptr(vsp), rcx)?;
        
        // 恢复原生寄存器
        asm.pop(rcx)?;
        asm.pop(rax)?;
        
        self.interpreter.generate_next_instruction_fetch(asm)?;
        Ok(())
    }

    /// vSub: 将虚拟栈顶的两个元素相减 (A - B)
    pub fn gen_sub(&self, asm: &mut CodeAssembler) -> Result<(), IcedError> {
        let vsp = self.vreg(VMRegister::VSP);
        
        asm.push(rax)?;
        asm.push(rcx)?;
        
        // VSP[0] = B, VSP[8] = A
        asm.mov(rcx, qword_ptr(vsp))?;
        asm.mov(rax, qword_ptr(vsp + 8))?;
        
        // 执行原生 SUB 运算 (A - B)
        asm.sub(rax, rcx)?;
        
        // 捕获真实 EFLAGS
        asm.pushfq()?;
        
        // 写回结果和标志位
        asm.mov(qword_ptr(vsp + 8), rax)?;
        asm.pop(rcx)?;
        asm.mov(qword_ptr(vsp), rcx)?;
        
        asm.pop(rcx)?;
        asm.pop(rax)?;
        
        self.interpreter.generate_next_instruction_fetch(asm)?;
        Ok(())
    }

    /// vXor: 将虚拟栈顶的两个元素异或 (A ^ B)
    pub fn gen_xor(&self, asm: &mut CodeAssembler) -> Result<(), IcedError> {
        let vsp = self.vreg(VMRegister::VSP);
        
        asm.push(rax)?;
        asm.push(rcx)?;
        
        asm.mov(rcx, qword_ptr(vsp))?;
        asm.mov(rax, qword_ptr(vsp + 8))?;
        
        asm.xor(rax, rcx)?;
        asm.pushfq()?;
        
        asm.mov(qword_ptr(vsp + 8), rax)?;
        asm.pop(rcx)?;
        asm.mov(qword_ptr(vsp), rcx)?;
        
        asm.pop(rcx)?;
        asm.pop(rax)?;
        
        self.interpreter.generate_next_instruction_fetch(asm)?;
        Ok(())
    }

    /// vNor: 将虚拟栈顶的两个元素按位或非 ~(A | B)
    pub fn gen_nor(&self, asm: &mut CodeAssembler) -> Result<(), IcedError> {
        let vsp = self.vreg(VMRegister::VSP);
        
        asm.push(rax)?;
        asm.push(rcx)?;
        
        asm.mov(rcx, qword_ptr(vsp))?;
        asm.mov(rax, qword_ptr(vsp + 8))?;
        
        asm.or(rax, rcx)?;
        asm.not(rax)?;
        // x86的not不影响标志位，VMP通常利用结果去test产生标志位，或者模拟标志位
        // 简单模拟: 针对结果进行一次运算以设置 PF/SF/ZF，并且清除 CF/OF
        asm.test(rax, rax)?;
        asm.pushfq()?;
        
        asm.mov(qword_ptr(vsp + 8), rax)?;
        asm.pop(rcx)?;
        asm.mov(qword_ptr(vsp), rcx)?;
        
        asm.pop(rcx)?;
        asm.pop(rax)?;
        
        self.interpreter.generate_next_instruction_fetch(asm)?;
        Ok(())
    }

    /// vNand: 将虚拟栈顶的两个元素按位与非 ~(A & B)
    pub fn gen_nand(&self, asm: &mut CodeAssembler) -> Result<(), IcedError> {
        let vsp = self.vreg(VMRegister::VSP);
        
        asm.push(rax)?;
        asm.push(rcx)?;
        
        asm.mov(rcx, qword_ptr(vsp))?;
        asm.mov(rax, qword_ptr(vsp + 8))?;
        
        asm.and(rax, rcx)?;
        asm.not(rax)?;
        asm.test(rax, rax)?; // 设置标志位
        asm.pushfq()?;
        
        asm.mov(qword_ptr(vsp + 8), rax)?;
        asm.pop(rcx)?;
        asm.mov(qword_ptr(vsp), rcx)?;
        
        asm.pop(rcx)?;
        asm.pop(rax)?;
        
        self.interpreter.generate_next_instruction_fetch(asm)?;
        Ok(())
    }

    /// vAnd: A & B
    pub fn gen_and(&self, asm: &mut CodeAssembler) -> Result<(), IcedError> {
        let vsp = self.vreg(VMRegister::VSP);
        asm.push(rax)?;
        asm.push(rcx)?;
        asm.mov(rcx, qword_ptr(vsp))?;
        asm.mov(rax, qword_ptr(vsp + 8))?;
        asm.and(rax, rcx)?;
        asm.pushfq()?;
        asm.mov(qword_ptr(vsp + 8), rax)?;
        asm.pop(rcx)?;
        asm.mov(qword_ptr(vsp), rcx)?;
        asm.pop(rcx)?;
        asm.pop(rax)?;
        self.interpreter.generate_next_instruction_fetch(asm)?;
        Ok(())
    }

    /// vOr: A | B
    pub fn gen_or(&self, asm: &mut CodeAssembler) -> Result<(), IcedError> {
        let vsp = self.vreg(VMRegister::VSP);
        asm.push(rax)?;
        asm.push(rcx)?;
        asm.mov(rcx, qword_ptr(vsp))?;
        asm.mov(rax, qword_ptr(vsp + 8))?;
        asm.or(rax, rcx)?;
        asm.pushfq()?;
        asm.mov(qword_ptr(vsp + 8), rax)?;
        asm.pop(rcx)?;
        asm.mov(qword_ptr(vsp), rcx)?;
        asm.pop(rcx)?;
        asm.pop(rax)?;
        self.interpreter.generate_next_instruction_fetch(asm)?;
        Ok(())
    }

    /// vNot: ~A
    pub fn gen_not(&self, asm: &mut CodeAssembler) -> Result<(), IcedError> {
        let vsp = self.vreg(VMRegister::VSP);
        asm.push(rax)?;
        asm.push(rcx)?;
        asm.mov(rax, qword_ptr(vsp))?;
        asm.not(rax)?;
        asm.test(rax, rax)?; // 手动触发标志位
        asm.pushfq()?;
        asm.sub(vsp, 8)?; // 为标志位留出空间
        self.interpreter.generate_check_stack(asm, 8)?;
        asm.mov(qword_ptr(vsp + 8), rax)?;
        asm.pop(rcx)?;
        asm.mov(qword_ptr(vsp), rcx)?;
        asm.pop(rcx)?;
        asm.pop(rax)?;
        self.interpreter.generate_next_instruction_fetch(asm)?;
        Ok(())
    }

    /// vNeg: -A
    pub fn gen_neg(&self, asm: &mut CodeAssembler) -> Result<(), IcedError> {
        let vsp = self.vreg(VMRegister::VSP);
        asm.push(rax)?;
        asm.push(rcx)?;
        asm.mov(rax, qword_ptr(vsp))?;
        asm.neg(rax)?;
        asm.pushfq()?;
        asm.sub(vsp, 8)?;
        self.interpreter.generate_check_stack(asm, 8)?;
        asm.mov(qword_ptr(vsp + 8), rax)?;
        asm.pop(rcx)?;
        asm.mov(qword_ptr(vsp), rcx)?;
        asm.pop(rcx)?;
        asm.pop(rax)?;
        self.interpreter.generate_next_instruction_fetch(asm)?;
        Ok(())
    }

    // ==========================================
    // 内存访问类指令 [NEW]
    // ==========================================

    pub fn gen_read_mem(&self, asm: &mut CodeAssembler, size: u32) -> Result<(), IcedError> {
        let vsp = self.vreg(VMRegister::VSP);
        asm.push(rax)?;
        asm.mov(rax, qword_ptr(vsp))?;
        match size {
            8  => { asm.movzx(rax, byte_ptr(rax))?; }
            16 => { asm.movzx(rax, word_ptr(rax))?; }
            32 => { asm.mov(eax, dword_ptr(rax))?; }
            64 => { asm.mov(rax, qword_ptr(rax))?; }
            _ => unreachable!(),
        }
        asm.mov(qword_ptr(vsp), rax)?;
        asm.pop(rax)?;
        self.interpreter.generate_next_instruction_fetch(asm)?;
        Ok(())
    }

    pub fn gen_write_mem(&self, asm: &mut CodeAssembler, size: u32) -> Result<(), IcedError> {
        let vsp = self.vreg(VMRegister::VSP);
        asm.push(rax)?;
        asm.push(rcx)?;
        asm.mov(rax, qword_ptr(vsp))?;
        asm.mov(rcx, qword_ptr(vsp + 8))?;
        match size {
            8  => { asm.mov(byte_ptr(rax), cl)?; }
            16 => { asm.mov(word_ptr(rax), cx)?; }
            32 => { asm.mov(dword_ptr(rax), ecx)?; }
            64 => { asm.mov(qword_ptr(rax), rcx)?; }
            _ => unreachable!(),
        }
        asm.add(vsp, 16)?;
        asm.pop(rcx)?;
        asm.pop(rax)?;
        self.interpreter.generate_next_instruction_fetch(asm)?;
        Ok(())
    }

    // ==========================================
    // 立即数与常量类指令
    // ==========================================

    /// vPushImm32: 从字节码流中读取 32 位立即数并压栈
    pub fn gen_push_imm32(&self, asm: &mut CodeAssembler) -> Result<(), IcedError> {
        let vsp = self.vreg(VMRegister::VSP);
        let vip = self.vreg(VMRegister::VIP);
        
        self.interpreter.generate_check_stack(asm, 8)?;
        
        asm.push(rax)?;
        
        // 从 VIP 读取 4 字节
        asm.mov(eax, dword_ptr(vip))?;
        
        // 真实的 VMP 在这里会使用 VCRYPT 对 RAX 进行解密计算
        // 简化版暂时不进行复杂解密，直接 VIP 递增
        asm.add(vip, 4)?;
        
        // VSP 生长并压入数据 (64位系统中，立即数通常符号扩展或零扩展后压入)
        asm.sub(vsp, 8)?;
        asm.mov(qword_ptr(vsp), rax)?;
        
        asm.pop(rax)?;
        
        self.interpreter.generate_next_instruction_fetch(asm)?;
        Ok(())
    }

    /// vPushImm64: 从字节码流中读取 64 位立即数并压栈
    pub fn gen_push_imm64(&self, asm: &mut CodeAssembler) -> Result<(), IcedError> {
        let vsp = self.vreg(VMRegister::VSP);
        let vip = self.vreg(VMRegister::VIP);
        
        self.interpreter.generate_check_stack(asm, 8)?;
        
        asm.push(rax)?;
        
        // 从 VIP 读取 8 字节
        asm.mov(rax, qword_ptr(vip))?;
        asm.add(vip, 8)?;
        
        asm.sub(vsp, 8)?;
        asm.mov(qword_ptr(vsp), rax)?;
        
        asm.pop(rax)?;
        
        self.interpreter.generate_next_instruction_fetch(asm)?;
        Ok(())
    }

    // ==========================================
    // 移位类指令 [NEW]
    // ==========================================

    pub fn gen_shift(&self, asm: &mut CodeAssembler, opcode: crate::vm::arch::VMOpcode) -> Result<(), IcedError> {
        let vsp = self.vreg(VMRegister::VSP);
        asm.push(rax)?;
        asm.push(rcx)?;
        // VSP[0] = count, VSP[8] = value
        asm.mov(rcx, qword_ptr(vsp))?;
        asm.mov(rax, qword_ptr(vsp + 8))?;
        
        use crate::vm::arch::VMOpcode;
        match opcode {
            VMOpcode::Shl => { asm.shl(rax, cl)?; }
            VMOpcode::Shr => { asm.shr(rax, cl)?; }
            VMOpcode::Sar => { asm.sar(rax, cl)?; }
            VMOpcode::Rol => { asm.rol(rax, cl)?; }
            VMOpcode::Ror => { asm.ror(rax, cl)?; }
            _ => unreachable!(),
        }
        
        asm.pushfq()?;
        asm.mov(qword_ptr(vsp + 8), rax)?;
        asm.pop(rcx)?;
        asm.mov(qword_ptr(vsp), rcx)?;
        asm.pop(rcx)?;
        asm.pop(rax)?;
        self.interpreter.generate_next_instruction_fetch(asm)?;
        Ok(())
    }


    // ==========================================
    // 控制流类指令
    // ==========================================

    /// vJmp: 无条件跳转到栈顶弹出的地址
    pub fn gen_jmp(&self, asm: &mut CodeAssembler) -> Result<(), IcedError> {
        let vsp = self.vreg(VMRegister::VSP);
        let vip = self.vreg(VMRegister::VIP);
        
        asm.push(rax)?;
        
        // 弹出跳转目标赋给 VIP
        asm.mov(rax, qword_ptr(vsp))?;
        asm.add(vsp, 8)?;
        
        asm.mov(vip, rax)?;
        
        asm.pop(rax)?;
        
        // Threaded Code 将自然地从新的 VIP 位置读取并跳转！
        self.interpreter.generate_next_instruction_fetch(asm)?;
        Ok(())
    }

    /// vJcc: 条件跳转
    /// VSP[0] = 目标 VIP, VSP[8] = 比较结果标志位 (EFLAGS)
    pub fn gen_jcc(&self, asm: &mut CodeAssembler, condition: crate::intel::ir::IrCondition) -> Result<(), IcedError> {
        let vsp = self.vreg(VMRegister::VSP);
        let vip = self.vreg(VMRegister::VIP);
        
        asm.push(rax)?;
        asm.push(rcx)?;
        
        // 读取标志位并恢复 CPU 状态
        asm.mov(rcx, qword_ptr(vsp + 8))?;
        asm.push(rcx)?;
        asm.popfq()?;
        
        // 获取目标地址
        asm.mov(rax, qword_ptr(vsp))?;
        
        // 根据条件决定是否更新 VIP
        let mut label_no_jump = asm.create_label();
        
        use crate::intel::ir::IrCondition;
        match condition {
            IrCondition::E  => { asm.jne(label_no_jump)?; }
            IrCondition::Ne => { asm.je(label_no_jump)?; }
            IrCondition::A  => { asm.jbe(label_no_jump)?; }
            IrCondition::Ae => { asm.jb(label_no_jump)?; }
            IrCondition::B  => { asm.jae(label_no_jump)?; }
            IrCondition::Be => { asm.ja(label_no_jump)?; }
            IrCondition::G  => { asm.jle(label_no_jump)?; }
            IrCondition::Ge => { asm.jl(label_no_jump)?; }
            IrCondition::L  => { asm.jge(label_no_jump)?; }
            IrCondition::Le => { asm.jg(label_no_jump)?; }
            _ => { /* 暂时支持常用条件 */ }
        }
        
        // 执行跳转：更新 VIP
        asm.mov(vip, rax)?;
        
        asm.set_label(&mut label_no_jump)?;
        
        // 清理虚拟栈
        asm.add(vsp, 16)?;
        
        asm.pop(rcx)?;
        asm.pop(rax)?;
        self.interpreter.generate_next_instruction_fetch(asm)?;
        Ok(())
    }

    /// vDup: 复制栈顶
    pub fn gen_dup(&self, asm: &mut CodeAssembler) -> Result<(), IcedError> {
        let vsp = self.vreg(VMRegister::VSP);
        self.interpreter.generate_check_stack(asm, 8)?;
        asm.push(rax)?;
        asm.mov(rax, qword_ptr(vsp))?;
        asm.sub(vsp, 8)?;
        asm.mov(qword_ptr(vsp), rax)?;
        asm.pop(rax)?;
        self.interpreter.generate_next_instruction_fetch(asm)?;
        Ok(())
    }

    /// vVmExit: 退出虚拟机
    pub fn gen_vm_exit(&self, asm: &mut CodeAssembler) -> Result<(), IcedError> {
        // 直接调用 Interpreter 提供的生成器即可
        self.interpreter.generate_vm_exit(asm)?;
        Ok(())
    }
}
