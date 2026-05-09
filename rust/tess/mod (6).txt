//! 核心微指令 Handler 生成器

pub mod control;
pub mod stack;
pub mod math;

use crate::vm::arch::ArchConfig;
use crate::vm::opcode::VmOpcode;
use iced_x86::code_asm::*;
use iced_x86::IcedError;

// ========== Handler 注册表 ==========

pub struct HandlerEntry {
    pub opcode: VmOpcode,
    pub has_operand: bool,
    pub operand_size: u8,
    pub category: HandlerCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerCategory {
    Control,
    Stack,
    Arith,
    Logic,
    Memory,
}

pub struct HandlerRegistry {
    pub entries: Vec<HandlerEntry>,
}

impl HandlerRegistry {
    pub fn register_all() -> Self {
        Self {
            entries: vec![
                HandlerEntry {
                    opcode: VmOpcode::VNop,
                    has_operand: false,
                    operand_size: 0,
                    category: HandlerCategory::Stack,
                },
                HandlerEntry {
                    opcode: VmOpcode::VExit,
                    has_operand: false,
                    operand_size: 0,
                    category: HandlerCategory::Control,
                },
                HandlerEntry {
                    opcode: VmOpcode::VExec,
                    has_operand: false,
                    operand_size: 0,
                    category: HandlerCategory::Control,
                },
                HandlerEntry {
                    opcode: VmOpcode::VPushImm32(0),
                    has_operand: true,
                    operand_size: 4,
                    category: HandlerCategory::Stack,
                },
                HandlerEntry {
                    opcode: VmOpcode::VPushImm64(0),
                    has_operand: true,
                    operand_size: 8,
                    category: HandlerCategory::Stack,
                },
                HandlerEntry {
                    opcode: VmOpcode::VPushReg(0),
                    has_operand: true,
                    operand_size: 1,
                    category: HandlerCategory::Stack,
                },
                HandlerEntry {
                    opcode: VmOpcode::VPopReg(0),
                    has_operand: true,
                    operand_size: 1,
                    category: HandlerCategory::Stack,
                },
            ],
        }
    }

    pub fn generate(gen: &mut HandlerGenerator, opcode: &VmOpcode) -> Result<(usize, usize), IcedError> {
        match opcode {
            VmOpcode::VNop => stack::gen_vnop(gen),
            VmOpcode::VExit => control::gen_vexit(gen),
            VmOpcode::VExec => control::gen_vexec(gen),
            VmOpcode::VPushImm32(_) => stack::gen_vpush_imm32(gen),
            VmOpcode::VPushImm64(_) => stack::gen_vpush_imm64(gen),
            VmOpcode::VPushReg(_) => stack::gen_vpush_reg(gen),
            VmOpcode::VPopReg(_) => stack::gen_vpop_reg(gen),
            _ => control::gen_vexit(gen), // 未实现的 opcode → VExit (安全回退)
        }
    }
}

// ========== Handler 生成器上下文 ==========

pub struct HandlerGenerator<'a> {
    pub asm: &'a mut CodeAssembler,
    pub arch: &'a ArchConfig,
    pub save_area_va: u64,
    pub reentry_va: u64,
    pub return_va: u64,
}

impl<'a> HandlerGenerator<'a> {
    pub fn new(asm: &'a mut CodeAssembler, arch: &'a ArchConfig) -> Self {
        Self { asm, arch, save_area_va: 0, reentry_va: 0, return_va: 0 }
    }

    #[allow(dead_code)]
    pub fn reg_save_base(&self) -> i64 {
        self.save_area_va as i64 + 40
    }

    #[allow(dead_code)]
    pub fn load_reg_save_base(&mut self, reg: AsmRegister64) -> Result<(), IcedError> {
        self.asm.mov(reg, self.save_area_va)?;
        self.asm.add(reg, 40_i32)?;
        Ok(())
    }

    pub fn to_32(reg: AsmRegister64) -> AsmRegister32 {
        let r: iced_x86::Register = reg.into();
        match r {
            iced_x86::Register::RAX => eax,
            iced_x86::Register::RCX => ecx,
            iced_x86::Register::RDX => edx,
            iced_x86::Register::RBX => ebx,
            iced_x86::Register::RSP => esp,
            iced_x86::Register::RBP => ebp,
            iced_x86::Register::RSI => esi,
            iced_x86::Register::RDI => edi,
            iced_x86::Register::R8  => r8d,
            iced_x86::Register::R9  => r9d,
            iced_x86::Register::R10 => r10d,
            iced_x86::Register::R11 => r11d,
            iced_x86::Register::R12 => r12d,
            iced_x86::Register::R13 => r13d,
            iced_x86::Register::R14 => r14d,
            iced_x86::Register::R15 => r15d,
            _ => eax,
        }
    }

    #[allow(dead_code)]
    pub fn to_8(reg: AsmRegister64) -> AsmRegister8 {
        let r: iced_x86::Register = reg.into();
        match r {
            iced_x86::Register::RAX => al,
            iced_x86::Register::RCX => cl,
            iced_x86::Register::RDX => dl,
            iced_x86::Register::RBX => bl,
            iced_x86::Register::RSP => spl,
            iced_x86::Register::RBP => bpl,
            iced_x86::Register::RSI => sil,
            iced_x86::Register::RDI => dil,
            iced_x86::Register::R8  => r8b,
            iced_x86::Register::R9  => r9b,
            iced_x86::Register::R10 => r10b,
            iced_x86::Register::R11 => r11b,
            iced_x86::Register::R12 => r12b,
            iced_x86::Register::R13 => r13b,
            iced_x86::Register::R14 => r14b,
            iced_x86::Register::R15 => r15b,
            _ => al,
        }
    }

    pub fn vpop(&mut self, target_reg: AsmRegister64) -> Result<(), IcedError> {
        let vsp = self.arch.context.vsp;
        self.asm.mov(target_reg, qword_ptr(vsp))?;
        self.asm.add(vsp, 8_i32)?;
        Ok(())
    }

    pub fn vpush(&mut self, src_reg: AsmRegister64) -> Result<(), IcedError> {
        let vsp = self.arch.context.vsp;
        self.asm.sub(vsp, 8_i32)?;
        self.asm.mov(qword_ptr(vsp), src_reg)?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn save_native_regs(&mut self) -> Result<(), IcedError> {
        let ctx = &self.arch.context;
        self.asm.push(rbp)?;
        self.asm.mov(rbp, self.save_area_va)?;

        self.asm.mov(qword_ptr(rbp + 40 + 14 * 8), rax)?;

        self.asm.pushfq()?;
        self.asm.pop(rax)?;
        self.asm.mov(qword_ptr(rbp + 40 + 15 * 8), rax)?;

        self.asm.mov(qword_ptr(rbp + 40 + 13 * 8), rcx)?;
        self.asm.mov(qword_ptr(rbp + 40 + 12 * 8), rdx)?;
        self.asm.mov(qword_ptr(rbp + 40 + 11 * 8), rbx)?;
        self.asm.mov(qword_ptr(rbp + 40 + 9 * 8), rsi)?;
        self.asm.mov(qword_ptr(rbp + 40 + 8 * 8), rdi)?;
        self.asm.mov(qword_ptr(rbp + 40 + 7 * 8), r8)?;
        self.asm.mov(qword_ptr(rbp + 40 + 6 * 8), r9)?;
        self.asm.mov(qword_ptr(rbp + 40 + 5 * 8), r10)?;
        self.asm.mov(qword_ptr(rbp + 40 + 4 * 8), r11)?;
        self.asm.mov(qword_ptr(rbp + 40 + 3 * 8), r12)?;
        self.asm.mov(qword_ptr(rbp + 40 + 2 * 8), r13)?;
        self.asm.mov(qword_ptr(rbp + 40 + 1 * 8), r14)?;
        self.asm.mov(qword_ptr(rbp + 40 + 0 * 8), r15)?;

        self.asm.pop(rcx)?;
        self.asm.mov(qword_ptr(rbp + 40 + 10 * 8), rcx)?;

        self.asm.mov(qword_ptr(rbp + 40 + 16 * 8), rsp)?;

        Ok(())
    }

    pub fn restore_native_and_ret(&mut self) -> Result<(), IcedError> {
        self.asm.mov(r15, self.save_area_va)?;

        self.asm.mov(r14, qword_ptr(r15 + 40 + 1 * 8))?;
        self.asm.mov(r13, qword_ptr(r15 + 40 + 2 * 8))?;
        self.asm.mov(r12, qword_ptr(r15 + 40 + 3 * 8))?;
        self.asm.mov(r11, qword_ptr(r15 + 40 + 4 * 8))?;
        self.asm.mov(r10, qword_ptr(r15 + 40 + 5 * 8))?;
        self.asm.mov(r9, qword_ptr(r15 + 40 + 6 * 8))?;
        self.asm.mov(r8, qword_ptr(r15 + 40 + 7 * 8))?;
        self.asm.mov(rdi, qword_ptr(r15 + 40 + 8 * 8))?;
        self.asm.mov(rsi, qword_ptr(r15 + 40 + 9 * 8))?;
        self.asm.mov(rbp, qword_ptr(r15 + 40 + 10 * 8))?;
        self.asm.mov(rbx, qword_ptr(r15 + 40 + 11 * 8))?;
        self.asm.mov(rdx, qword_ptr(r15 + 40 + 12 * 8))?;
        self.asm.mov(rcx, qword_ptr(r15 + 40 + 13 * 8))?;
        self.asm.mov(rax, qword_ptr(r15 + 40 + 14 * 8))?;

        self.asm.push(qword_ptr(r15 + 40 + 15 * 8))?;
        self.asm.popfq()?;

        self.asm.mov(rsp, qword_ptr(r15 + 24))?;
        self.asm.mov(r15, qword_ptr(r15 + 40 + 0 * 8))?;
        self.asm.ret()?;

        Ok(())
    }
}
