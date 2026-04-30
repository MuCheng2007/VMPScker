//! 指令包装模块
//!
//! 包装 iced_x86::Instruction，添加 VMProtect 特定的元数据。

use iced_x86::{Instruction as IcedInstruction, OpKind, Register as IcedRegister};

/// 指令分类
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionCategory {
    /// 无操作
    Nop,
    /// 数据传输（mov, push, pop, lea 等）
    DataTransfer,
    /// 算术运算（add, sub, mul, div 等）
    Arithmetic,
    /// 逻辑运算（and, or, xor, not 等）
    Logical,
    /// 比较和测试（cmp, test）
    Compare,
    /// 无条件跳转（jmp）
    UnconditionalJump,
    /// 条件跳转（je, jne, ja 等）
    ConditionalJump,
    /// 调用（call）
    Call,
    /// 返回（ret）
    Return,
    /// 条件移动（cmov）
    ConditionalMove,
    /// 系统指令（syscall, sysret, int 等）
    System,
    /// 字符串操作（movs, cmps, scas 等）
    String,
    /// 位操作（bt, bts, btr 等）
    Bit,
    /// 浮点运算
    FloatingPoint,
    /// SIMD 指令（SSE, AVX 等）
    Simd,
    /// 其他/未知
    Other,
}

impl InstructionCategory {
    /// 是否控制流指令
    pub fn is_control_flow(&self) -> bool {
        matches!(
            self,
            InstructionCategory::UnconditionalJump
                | InstructionCategory::ConditionalJump
                | InstructionCategory::Call
                | InstructionCategory::Return
        )
    }

    /// 是否条件指令
    pub fn is_conditional(&self) -> bool {
        matches!(
            self,
            InstructionCategory::ConditionalJump | InstructionCategory::ConditionalMove
        )
    }
}

/// 指令信息
#[derive(Debug, Clone)]
pub struct InstructionInfo {
    /// 指令长度（字节）
    pub len: u8,
    /// 指令地址（IP）
    pub ip: u64,
    /// 下一条指令地址
    pub next_ip: u64,
    /// 指令分类
    pub category: InstructionCategory,
    /// 操作码助记符
    pub mnemonic: String,
    /// 操作数数量
    pub op_count: u8,
    /// 是否读取内存
    pub reads_memory: bool,
    /// 是否写入内存
    pub writes_memory: bool,
    /// 读取的寄存器
    pub read_registers: Vec<IcedRegister>,
    /// 写入的寄存器
    pub written_registers: Vec<IcedRegister>,
    /// 栈指针操作（正值表示弹出，负值表示压入）
    pub stack_pointer_delta: i32,
}

/// 指令包装结构
#[derive(Debug, Clone)]
pub struct Instruction {
    /// 原始 iced-x86 指令
    iced: IcedInstruction,
    /// 指令地址
    ip: u64,
    /// 指令信息（延迟计算）
    info: Option<InstructionInfo>,
}

impl Instruction {
    /// 从 iced-x86 指令创建
    pub fn from_iced(iced: IcedInstruction, ip: u64) -> Self {
        Self {
            iced,
            ip,
            info: None,
        }
    }

    /// 获取原始 iced-x86 指令
    pub fn iced(&self) -> &IcedInstruction {
        &self.iced
    }

    /// 获取指令地址
    pub fn ip(&self) -> u64 {
        self.ip
    }

    /// 获取指令长度
    pub fn len(&self) -> u8 {
        self.iced.len() as u8
    }

    /// 获取下一条指令地址
    pub fn next_ip(&self) -> u64 {
        self.ip + self.len() as u64
    }

    /// 获取助记符
    pub fn mnemonic(&self) -> String {
        format!("{:?}", self.iced.mnemonic()).to_lowercase()
    }

    /// 获取指令分类
    pub fn category(&self) -> InstructionCategory {
        use iced_x86::Mnemonic;
        match self.iced.mnemonic() {
            Mnemonic::Nop => InstructionCategory::Nop,
            Mnemonic::Mov | Mnemonic::Push | Mnemonic::Pop | Mnemonic::Lea | Mnemonic::Xchg => {
                InstructionCategory::DataTransfer
            }
            Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::Mul
            | Mnemonic::Imul
            | Mnemonic::Div
            | Mnemonic::Idiv
            | Mnemonic::Inc
            | Mnemonic::Dec
            | Mnemonic::Neg
            | Mnemonic::Adc
            | Mnemonic::Sbb => InstructionCategory::Arithmetic,
            Mnemonic::And | Mnemonic::Or | Mnemonic::Xor | Mnemonic::Not => {
                InstructionCategory::Logical
            }
            Mnemonic::Cmp | Mnemonic::Test => InstructionCategory::Compare,
            Mnemonic::Jmp => InstructionCategory::UnconditionalJump,
            Mnemonic::Je
            | Mnemonic::Jne
            | Mnemonic::Ja
            | Mnemonic::Jae
            | Mnemonic::Jb
            | Mnemonic::Jbe
            | Mnemonic::Jg
            | Mnemonic::Jge
            | Mnemonic::Jl
            | Mnemonic::Jle
            | Mnemonic::Jo
            | Mnemonic::Jno
            | Mnemonic::Js
            | Mnemonic::Jns
            | Mnemonic::Jp
            | Mnemonic::Jnp
            | Mnemonic::Jcxz
            | Mnemonic::Jecxz
            | Mnemonic::Jrcxz => InstructionCategory::ConditionalJump,
            Mnemonic::Call => InstructionCategory::Call,
            Mnemonic::Ret | Mnemonic::Retf => InstructionCategory::Return,
            Mnemonic::Cmovae
            | Mnemonic::Cmova
            | Mnemonic::Cmovbe
            | Mnemonic::Cmovb
            | Mnemonic::Cmove
            | Mnemonic::Cmovge
            | Mnemonic::Cmovg
            | Mnemonic::Cmovle
            | Mnemonic::Cmovl
            | Mnemonic::Cmovne
            | Mnemonic::Cmovno
            | Mnemonic::Cmovnp
            | Mnemonic::Cmovns
            | Mnemonic::Cmovo
            | Mnemonic::Cmovp
            | Mnemonic::Cmovs => InstructionCategory::ConditionalMove,
            Mnemonic::Syscall
            | Mnemonic::Sysret
            | Mnemonic::Int
            | Mnemonic::Into
            | Mnemonic::Iret
            | Mnemonic::Iretd
            | Mnemonic::Iretq
            | Mnemonic::Cli
            | Mnemonic::Sti
            | Mnemonic::Hlt => InstructionCategory::System,
            Mnemonic::Movsb
            | Mnemonic::Movsw
            | Mnemonic::Movsd
            | Mnemonic::Movsq
            | Mnemonic::Cmpsb
            | Mnemonic::Cmpsw
            | Mnemonic::Cmpsd
            | Mnemonic::Cmpsq
            | Mnemonic::Scasb
            | Mnemonic::Scasw
            | Mnemonic::Scasd
            | Mnemonic::Scasq
            | Mnemonic::Lodsb
            | Mnemonic::Lodsw
            | Mnemonic::Lodsd
            | Mnemonic::Lodsq
            | Mnemonic::Stosb
            | Mnemonic::Stosw
            | Mnemonic::Stosd
            | Mnemonic::Stosq => InstructionCategory::String,
            Mnemonic::Bt
            | Mnemonic::Btc
            | Mnemonic::Btr
            | Mnemonic::Bts
            | Mnemonic::Bsf
            | Mnemonic::Bsr
            | Mnemonic::Bswap => InstructionCategory::Bit,
            Mnemonic::Addss
            | Mnemonic::Subss
            | Mnemonic::Mulss
            | Mnemonic::Divss
            | Mnemonic::Addsd
            | Mnemonic::Subsd
            | Mnemonic::Mulsd
            | Mnemonic::Divsd
            | Mnemonic::Sqrtss
            | Mnemonic::Sqrtsd => InstructionCategory::FloatingPoint,
            _ => {
                // 检查是否是 SIMD 指令
                let mnemonic_str = format!("{:?}", self.iced.mnemonic()).to_lowercase();
                if mnemonic_str.contains("xmm")
                    || mnemonic_str.contains("ymm")
                    || mnemonic_str.contains("sse")
                    || mnemonic_str.contains("avx")
                    || mnemonic_str.contains("movd")
                    || mnemonic_str.contains("movq")
                    || mnemonic_str.contains("movaps")
                    || mnemonic_str.contains("movups")
                    || mnemonic_str.contains("movdqa")
                    || mnemonic_str.contains("movdqu")
                {
                    InstructionCategory::Simd
                } else {
                    InstructionCategory::Other
                }
            }
        }
    }

    /// 获取操作数数量
    pub fn op_count(&self) -> u32 {
        self.iced.op_count()
    }

    /// 获取指定操作数的类型
    pub fn op_kind(&self, index: u32) -> OpKind {
        self.iced.op_kind(index)
    }

    /// 获取立即数（如果操作数是指令）
    pub fn immediate(&self, index: u32) -> Option<u64> {
        if self.iced.op_kind(index) == OpKind::Immediate8 {
            Some(self.iced.immediate8() as u64)
        } else if self.iced.op_kind(index) == OpKind::Immediate16 {
            Some(self.iced.immediate16() as u64)
        } else if self.iced.op_kind(index) == OpKind::Immediate32 {
            Some(self.iced.immediate32() as u64)
        } else if self.iced.op_kind(index) == OpKind::Immediate64 {
            Some(self.iced.immediate64())
        } else {
            None
        }
    }

    /// 获取内存操作数信息
    pub fn memory_operand(&self) -> Option<MemoryOperandInfo> {
        // 检查是否有内存操作数
        let has_memory = (0..self.op_count()).any(|i| {
            self.iced.op_kind(i) == OpKind::Memory
        });
        
        if !has_memory {
            return None;
        }

        Some(MemoryOperandInfo {
            base: self.iced.memory_base(),
            index: self.iced.memory_index(),
            scale: self.iced.memory_index_scale(),
            displacement: self.iced.memory_displacement64(),
            size: self.iced.memory_size(),
        })
    }

    /// 获取分支目标地址（如果是跳转或调用）
    pub fn branch_target(&self) -> Option<u64> {
        if self.is_jump() || self.is_call() {
            // 对于近跳转/调用，目标地址是 IP + 相对偏移
            if self.iced.op_count() > 0 && self.iced.op_kind(0) == OpKind::NearBranch64 {
                Some(self.iced.near_branch_target())
            } else {
                None
            }
        } else {
            None
        }
    }

    /// 是否是控制流指令
    pub fn is_control_flow(&self) -> bool {
        self.category().is_control_flow()
    }

    /// 是否是无条件跳转
    pub fn is_unconditional_jump(&self) -> bool {
        self.category() == InstructionCategory::UnconditionalJump
    }

    /// 是否是条件跳转
    pub fn is_conditional_jump(&self) -> bool {
        self.category() == InstructionCategory::ConditionalJump
    }

    /// 是否是跳转指令
    pub fn is_jump(&self) -> bool {
        matches!(
            self.category(),
            InstructionCategory::UnconditionalJump | InstructionCategory::ConditionalJump
        )
    }

    /// 是否是调用指令
    pub fn is_call(&self) -> bool {
        self.category() == InstructionCategory::Call
    }

    /// 是否是返回指令
    pub fn is_return(&self) -> bool {
        self.category() == InstructionCategory::Return
    }

    /// 是否读取内存
    pub fn reads_memory(&self) -> bool {
        // 使用指令信息工厂来获取内存访问信息
        // 简化实现：检查指令类别
        use iced_x86::FlowControl;
        match self.iced.flow_control() {
            FlowControl::Next | FlowControl::Call | FlowControl::ConditionalBranch |
            FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => {
                // 检查是否有内存操作数
                (0..self.op_count()).any(|i| {
                    self.iced.op_kind(i) == OpKind::Memory
                })
            }
            _ => false,
        }
    }

    /// 是否写入内存
    pub fn writes_memory(&self) -> bool {
        // 简化实现：根据指令类型判断
        use iced_x86::Mnemonic;
        match self.iced.mnemonic() {
            Mnemonic::Mov | Mnemonic::Push | Mnemonic::Pop |
            Mnemonic::Xchg | Mnemonic::Add | Mnemonic::Sub |
            Mnemonic::And | Mnemonic::Or | Mnemonic::Xor => {
                (0..self.op_count()).any(|i| {
                    self.iced.op_kind(i) == OpKind::Memory
                })
            }
            _ => false,
        }
    }

    /// 获取读取的寄存器列表
    pub fn read_registers(&self) -> Vec<IcedRegister> {
        let mut regs = Vec::new();
        for i in 0..self.op_count() {
            let op_kind = self.iced.op_kind(i);
            match op_kind {
                OpKind::Register => {
                    let reg = self.iced.op_register(i);
                    regs.push(reg);
                }
                OpKind::Memory => {
                    // 内存操作数可能使用基址和索引寄存器
                    let base = self.iced.memory_base();
                    if base != IcedRegister::None {
                        regs.push(base);
                    }
                    let index = self.iced.memory_index();
                    if index != IcedRegister::None {
                        regs.push(index);
                    }
                }
                _ => {}
            }
        }
        regs
    }

    /// 获取写入的寄存器列表
    pub fn written_registers(&self) -> Vec<IcedRegister> {
        let mut regs = Vec::new();
        // 简化实现：根据指令类型判断
        use iced_x86::Mnemonic;
        match self.iced.mnemonic() {
            Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx |
            Mnemonic::Lea | Mnemonic::Add | Mnemonic::Sub |
            Mnemonic::And | Mnemonic::Or | Mnemonic::Xor |
            Mnemonic::Shl | Mnemonic::Shr | Mnemonic::Sar |
            Mnemonic::Inc | Mnemonic::Dec | Mnemonic::Neg |
            Mnemonic::Pop => {
                if self.op_count() > 0 && self.iced.op_kind(0) == OpKind::Register {
                    regs.push(self.iced.op_register(0));
                }
            }
            _ => {}
        }
        regs
    }

    /// 获取栈指针变化量
    pub fn stack_pointer_delta(&self) -> i32 {
        use iced_x86::Mnemonic;
        match self.iced.mnemonic() {
            Mnemonic::Push => -8,
            Mnemonic::Pop => 8,
            Mnemonic::Pusha | Mnemonic::Pushad => -16,
            Mnemonic::Popa | Mnemonic::Popad => 16,
            Mnemonic::Pushfq | Mnemonic::Pushfd | Mnemonic::Pushf => -8,
            Mnemonic::Popfq | Mnemonic::Popfd | Mnemonic::Popf => 8,
            Mnemonic::Call => -8,
            Mnemonic::Ret | Mnemonic::Retf => {
                // ret 可能带有立即数参数
                if self.iced.op_count() > 0 {
                    self.iced.immediate16() as i32
                } else {
                    8
                }
            }
            Mnemonic::Enter => {
                // enter 指令复杂，需要特殊处理
                0
            }
            Mnemonic::Leave => 0,
            _ => 0,
        }
    }

    /// 获取指令信息（延迟计算并缓存）
    pub fn info(&mut self) -> &InstructionInfo {
        if self.info.is_none() {
            self.info = Some(self.compute_info());
        }
        self.info.as_ref().unwrap()
    }

    fn compute_info(&self) -> InstructionInfo {
        InstructionInfo {
            len: self.len(),
            ip: self.ip(),
            next_ip: self.next_ip(),
            category: self.category(),
            mnemonic: self.mnemonic(),
            op_count: self.op_count() as u8,
            reads_memory: self.reads_memory(),
            writes_memory: self.writes_memory(),
            read_registers: self.read_registers(),
            written_registers: self.written_registers(),
            stack_pointer_delta: self.stack_pointer_delta(),
        }
    }
}

/// 内存操作数信息
#[derive(Debug, Clone)]
pub struct MemoryOperandInfo {
    pub base: IcedRegister,
    pub index: IcedRegister,
    pub scale: u32,
    pub displacement: u64,
    pub size: iced_x86::MemorySize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::decoder::decode_single;
    use crate::intel::DisassemblyMode;

    #[test]
    fn test_nop_instruction() {
        let data = vec![0x90];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();

        assert_eq!(insn.mnemonic(), "nop");
        assert_eq!(insn.category(), InstructionCategory::Nop);
        assert_eq!(insn.len(), 1);
        assert!(!insn.is_control_flow());
    }

    #[test]
    fn test_mov_instruction() {
        // mov rax, rbx
        let data = vec![0x48, 0x89, 0xD8];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();

        assert_eq!(insn.mnemonic(), "mov");
        assert_eq!(insn.category(), InstructionCategory::DataTransfer);
        assert_eq!(insn.op_count(), 2);
    }

    #[test]
    fn test_call_instruction() {
        // call 0x1234
        let data = vec![0xE8, 0x2F, 0x12, 0x00, 0x00];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();

        assert_eq!(insn.mnemonic(), "call");
        assert!(insn.is_call());
        assert!(insn.is_control_flow());
        assert!(!insn.is_jump());
    }

    #[test]
    fn test_jmp_instruction() {
        // jmp short
        let data = vec![0xEB, 0x05];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();

        assert_eq!(insn.mnemonic(), "jmp");
        assert!(insn.is_jump());
        assert!(insn.is_unconditional_jump());
        assert!(!insn.is_conditional_jump());
    }

    #[test]
    fn test_conditional_jmp() {
        // je short
        let data = vec![0x74, 0x05];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();

        assert_eq!(insn.mnemonic(), "je");
        assert!(insn.is_jump());
        assert!(insn.is_conditional_jump());
        assert!(!insn.is_unconditional_jump());
    }

    #[test]
    fn test_ret_instruction() {
        // ret
        let data = vec![0xC3];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();

        assert_eq!(insn.mnemonic(), "ret");
        assert!(insn.is_return());
        assert!(insn.is_control_flow());
    }

    #[test]
    fn test_push_stack_delta() {
        // push rax
        let data = vec![0x50];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();

        assert_eq!(insn.mnemonic(), "push");
        assert_eq!(insn.stack_pointer_delta(), -8);
    }

    #[test]
    fn test_pop_stack_delta() {
        // pop rax
        let data = vec![0x58];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();

        assert_eq!(insn.mnemonic(), "pop");
        assert_eq!(insn.stack_pointer_delta(), 8);
    }

    #[test]
    fn test_branch_target() {
        // jmp 0x1005 (EB 03)
        let data = vec![0xEB, 0x03];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();

        assert_eq!(insn.branch_target(), Some(0x1005));
    }

    #[test]
    fn test_next_ip() {
        // mov rax, rbx (3 bytes)
        let data = vec![0x48, 0x89, 0xD8];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();

        assert_eq!(insn.ip(), 0x1000);
        assert_eq!(insn.next_ip(), 0x1003);
    }

    #[test]
    fn test_instruction_category_is_control_flow() {
        assert!(InstructionCategory::UnconditionalJump.is_control_flow());
        assert!(InstructionCategory::ConditionalJump.is_control_flow());
        assert!(InstructionCategory::Call.is_control_flow());
        assert!(InstructionCategory::Return.is_control_flow());
        assert!(!InstructionCategory::Nop.is_control_flow());
        assert!(!InstructionCategory::Arithmetic.is_control_flow());
    }
}
