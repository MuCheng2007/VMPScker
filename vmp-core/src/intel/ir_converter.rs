//! IR 转换器模块
//!
//! 将 iced-x86 指令转换为 VMProtect IR。

use super::{
    DisassemblyMode, DisassemblyResult, Instruction, InstructionCategory,
    IrImmediate, IrInstruction, IrMemoryOperand, IrOperand, IrRegister,
};
use super::ir::{IrCondition, IrJumpTarget};
use crate::error::Result;
use iced_x86::{ConditionCode, Mnemonic, OpKind, Register as IcedRegister};

/// IR 转换器
pub struct IrConverter {
    mode: DisassemblyMode,
    label_counter: u32,
}

impl IrConverter {
    /// 创建新的 IR 转换器
    pub fn new(mode: DisassemblyMode) -> Self {
        Self {
            mode,
            label_counter: 0,
        }
    }

    /// 转换单条指令
    pub fn convert(&mut self, instruction: &Instruction) -> Result<Vec<IrInstruction>> {
        let mut result = Vec::new();
        
        // 添加注释显示原始指令
        let comment = format!("{:X}: {:?}", instruction.ip(), instruction.iced().mnemonic());
        result.push(IrInstruction::Comment { text: comment });

        let ir_insn = match instruction.category() {
            InstructionCategory::Nop => self.convert_nop(instruction),
            InstructionCategory::DataTransfer => self.convert_data_transfer(instruction),
            InstructionCategory::Arithmetic => self.convert_arithmetic(instruction),
            InstructionCategory::Logical => self.convert_logical(instruction),
            InstructionCategory::Compare => self.convert_compare(instruction),
            InstructionCategory::UnconditionalJump => self.convert_unconditional_jump(instruction),
            InstructionCategory::ConditionalJump => self.convert_conditional_jump(instruction),
            InstructionCategory::Call => self.convert_call(instruction),
            InstructionCategory::Return => self.convert_return(instruction),
            InstructionCategory::ConditionalMove => self.convert_conditional_move(instruction),
            InstructionCategory::Shift => self.convert_shift(instruction),
            InstructionCategory::Bit => self.convert_bit(instruction),
            InstructionCategory::Flags => self.convert_flags(instruction),
            InstructionCategory::System => self.convert_system(instruction),
            _ => self.convert_generic(instruction),
        };

        match ir_insn {
            Ok(ir) => {
                if let Some(insn) = ir {
                    result.push(insn);
                }
            }
            Err(e) => {
                // 转换失败时添加未实现注释
                result.push(IrInstruction::Comment {
                    text: format!("UNIMPLEMENTED: {:?}", instruction.iced().mnemonic()),
                });
            }
        }

        Ok(result)
    }

    /// 转换多条指令
    pub fn convert_instructions(&self, instructions: &[Instruction]) -> Result<Vec<IrInstruction>> {
        let mut result = Vec::new();
        let mut converter = IrConverter::new(self.mode);

        for instruction in instructions {
            let ir = converter.convert(instruction)?;
            result.extend(ir);
        }

        Ok(result)
    }

    /// 转换 nop 指令
    fn convert_nop(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrInstruction>> {
        Ok(Some(IrInstruction::Nop))
    }

    /// 转换数据传输指令
    fn convert_data_transfer(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrInstruction>> {
        use iced_x86::Mnemonic;
        
        match instruction.iced().mnemonic() {
            Mnemonic::Mov => {
                let dst = self.convert_operand(instruction, 0)?;
                let src = self.convert_operand(instruction, 1)?;
                Ok(Some(IrInstruction::Mov { dst, src }))
            }
            Mnemonic::Push => {
                let src = self.convert_operand(instruction, 0)?;
                Ok(Some(IrInstruction::Push { src }))
            }
            Mnemonic::Pop => {
                let dst = self.convert_operand(instruction, 0)?;
                Ok(Some(IrInstruction::Pop { dst }))
            }
            Mnemonic::Lea => {
                let dst = self.convert_register(instruction.iced().op_register(0))?;
                let src = self.convert_memory_operand(instruction.iced())?;
                Ok(Some(IrInstruction::Lea { dst, src }))
            }
            Mnemonic::Xchg => {
                let op1 = self.convert_operand(instruction, 0)?;
                let op2 = self.convert_operand(instruction, 1)?;
                Ok(Some(IrInstruction::Xchg { op1, op2 }))
            }
            _ => Ok(None),
        }
    }

    /// 转换算术指令
    fn convert_arithmetic(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrInstruction>> {
        use iced_x86::Mnemonic;
        
        match instruction.iced().mnemonic() {
            Mnemonic::Add => {
                let dst = self.convert_operand(instruction, 0)?;
                let src = self.convert_operand(instruction, 1)?;
                Ok(Some(IrInstruction::Add { dst, src }))
            }
            Mnemonic::Sub => {
                let dst = self.convert_operand(instruction, 0)?;
                let src = self.convert_operand(instruction, 1)?;
                Ok(Some(IrInstruction::Sub { dst, src }))
            }
            Mnemonic::Inc => {
                let op = self.convert_operand(instruction, 0)?;
                Ok(Some(IrInstruction::Inc { op }))
            }
            Mnemonic::Dec => {
                let op = self.convert_operand(instruction, 0)?;
                Ok(Some(IrInstruction::Dec { op }))
            }
            Mnemonic::Neg => {
                let op = self.convert_operand(instruction, 0)?;
                Ok(Some(IrInstruction::Neg { op }))
            }
            Mnemonic::Imul => {
                let op_count = instruction.op_count();
                if op_count == 1 {
                    // 单操作数 imul
                    let src = self.convert_operand(instruction, 0)?;
                    Ok(Some(IrInstruction::Imul {
                        dst: None,
                        src1: src,
                        src2: None,
                    }))
                } else if op_count == 2 {
                    // 双操作数 imul
                    let dst = self.convert_operand(instruction, 0)?;
                    let src = self.convert_operand(instruction, 1)?;
                    Ok(Some(IrInstruction::Imul {
                        dst: Some(dst),
                        src1: src,
                        src2: None,
                    }))
                } else {
                    // 三操作数 imul
                    let dst = self.convert_operand(instruction, 0)?;
                    let src1 = self.convert_operand(instruction, 1)?;
                    let src2 = self.convert_operand(instruction, 2)?;
                    Ok(Some(IrInstruction::Imul {
                        dst: Some(dst),
                        src1,
                        src2: Some(src2),
                    }))
                }
            }
            Mnemonic::Mul => {
                // 无符号乘法 - 单操作数形式
                let src = self.convert_operand(instruction, 0)?;
                Ok(Some(IrInstruction::Mul { src }))
            }
            Mnemonic::Div => {
                // 无符号除法 - 单操作数形式
                let src = self.convert_operand(instruction, 0)?;
                Ok(Some(IrInstruction::Div { src }))
            }
            Mnemonic::Idiv => {
                // 有符号除法 - 单操作数形式
                let src = self.convert_operand(instruction, 0)?;
                Ok(Some(IrInstruction::Idiv { src }))
            }
            _ => Ok(None),
        }
    }

    /// 转换逻辑指令
    fn convert_logical(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrInstruction>> {
        use iced_x86::Mnemonic;
        
        match instruction.iced().mnemonic() {
            Mnemonic::And => {
                let dst = self.convert_operand(instruction, 0)?;
                let src = self.convert_operand(instruction, 1)?;
                Ok(Some(IrInstruction::And { dst, src }))
            }
            Mnemonic::Or => {
                let dst = self.convert_operand(instruction, 0)?;
                let src = self.convert_operand(instruction, 1)?;
                Ok(Some(IrInstruction::Or { dst, src }))
            }
            Mnemonic::Xor => {
                let dst = self.convert_operand(instruction, 0)?;
                let src = self.convert_operand(instruction, 1)?;
                Ok(Some(IrInstruction::Xor { dst, src }))
            }
            Mnemonic::Not => {
                let op = self.convert_operand(instruction, 0)?;
                Ok(Some(IrInstruction::Not { op }))
            }
            Mnemonic::Test => {
                let op1 = self.convert_operand(instruction, 0)?;
                let op2 = self.convert_operand(instruction, 1)?;
                Ok(Some(IrInstruction::Test { op1, op2 }))
            }
            _ => Ok(None),
        }
    }

    /// 转换比较指令
    fn convert_compare(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrInstruction>> {
        use iced_x86::Mnemonic;
        
        match instruction.iced().mnemonic() {
            Mnemonic::Cmp => {
                let op1 = self.convert_operand(instruction, 0)?;
                let op2 = self.convert_operand(instruction, 1)?;
                Ok(Some(IrInstruction::Cmp { op1, op2 }))
            }
            Mnemonic::Test => {
                let op1 = self.convert_operand(instruction, 0)?;
                let op2 = self.convert_operand(instruction, 1)?;
                Ok(Some(IrInstruction::Test { op1, op2 }))
            }
            _ => Ok(None),
        }
    }

    /// 转换无条件跳转
    fn convert_unconditional_jump(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrInstruction>> {
        let target = if let Some(addr) = instruction.branch_target() {
            IrJumpTarget::Direct(addr)
        } else {
            // 间接跳转
            let op = self.convert_operand(instruction, 0)?;
            match op {
                IrOperand::Register(r) => IrJumpTarget::Register(r),
                IrOperand::Memory(m) => IrJumpTarget::Memory(m),
                _ => return Err(super::DisassemblyError::IrConversionError(
                    "Invalid jump target".to_string()
                )),
            }
        };
        
        Ok(Some(IrInstruction::Jmp { target }))
    }

    /// 转换条件跳转
    fn convert_conditional_jump(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrInstruction>> {
        let condition = self.convert_condition_code(instruction.iced().condition_code());
        
        let target = if let Some(addr) = instruction.branch_target() {
            IrJumpTarget::Direct(addr)
        } else {
            return Err(super::DisassemblyError::IrConversionError(
                "Conditional jump with indirect target not supported".to_string()
            ));
        };
        
        Ok(Some(IrInstruction::Jcc { condition, target }))
    }

    /// 转换调用指令
    fn convert_call(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrInstruction>> {
        let target = if let Some(addr) = instruction.branch_target() {
            IrJumpTarget::Direct(addr)
        } else {
            // 间接调用
            let op = self.convert_operand(instruction, 0)?;
            match op {
                IrOperand::Register(r) => IrJumpTarget::Register(r),
                IrOperand::Memory(m) => IrJumpTarget::Memory(m),
                _ => return Err(super::DisassemblyError::IrConversionError(
                    "Invalid call target".to_string()
                )),
            }
        };
        
        Ok(Some(IrInstruction::Call { target }))
    }

    /// 转换返回指令
    fn convert_return(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrInstruction>> {
        use iced_x86::Mnemonic;
        
        let pop_bytes = if instruction.iced().mnemonic() == Mnemonic::Ret && instruction.op_count() > 0 {
            Some(instruction.iced().immediate16())
        } else {
            None
        };
        
        Ok(Some(IrInstruction::Ret { pop_bytes }))
    }

    /// 转换条件移动
    fn convert_conditional_move(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrInstruction>> {
        let condition = self.convert_condition_code(instruction.iced().condition_code());
        let dst = self.convert_register(instruction.iced().op_register(0))?;
        let src = self.convert_operand(instruction, 1)?;
        
        Ok(Some(IrInstruction::Cmov { condition, dst, src }))
    }

    /// 转换移位指令
    fn convert_shift(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrInstruction>> {
        use iced_x86::Mnemonic;

        // 获取操作数
        let dst = self.convert_operand(instruction, 0)?;
        let count = if instruction.op_count() > 1 {
            self.convert_operand(instruction, 1)?
        } else {
            // 单操作数形式，使用 1 作为默认计数
            IrOperand::Immediate(IrImmediate::U8(1))
        };

        match instruction.iced().mnemonic() {
            Mnemonic::Shl => Ok(Some(IrInstruction::Shl { dst, count })),
            Mnemonic::Shr => Ok(Some(IrInstruction::Shr { dst, count })),
            Mnemonic::Sar => Ok(Some(IrInstruction::Sar { dst, count })),
            Mnemonic::Rol => Ok(Some(IrInstruction::Rol { dst, count })),
            Mnemonic::Ror => Ok(Some(IrInstruction::Ror { dst, count })),
            _ => Ok(None),
        }
    }

    /// 转换位操作指令
    fn convert_bit(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrInstruction>> {
        use iced_x86::Mnemonic;

        match instruction.iced().mnemonic() {
            Mnemonic::Bt => {
                let base = self.convert_operand(instruction, 0)?;
                let offset = self.convert_operand(instruction, 1)?;
                Ok(Some(IrInstruction::Bt { base, offset }))
            }
            Mnemonic::Bts => {
                let base = self.convert_operand(instruction, 0)?;
                let offset = self.convert_operand(instruction, 1)?;
                Ok(Some(IrInstruction::Bts { base, offset }))
            }
            Mnemonic::Btr => {
                let base = self.convert_operand(instruction, 0)?;
                let offset = self.convert_operand(instruction, 1)?;
                Ok(Some(IrInstruction::Btr { base, offset }))
            }
            Mnemonic::Bsf => {
                let dst = self.convert_register(instruction.iced().op_register(0))?;
                let src = self.convert_operand(instruction, 1)?;
                Ok(Some(IrInstruction::Bsf { dst, src }))
            }
            Mnemonic::Bsr => {
                let dst = self.convert_register(instruction.iced().op_register(0))?;
                let src = self.convert_operand(instruction, 1)?;
                Ok(Some(IrInstruction::Bsr { dst, src }))
            }
            _ => Ok(None),
        }
    }

    /// 转换标志操作指令
    fn convert_flags(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrInstruction>> {
        use iced_x86::Mnemonic;

        match instruction.iced().mnemonic() {
            Mnemonic::Pushf | Mnemonic::Pushfd | Mnemonic::Pushfq => Ok(Some(IrInstruction::Pushf)),
            Mnemonic::Popf | Mnemonic::Popfd | Mnemonic::Popfq => Ok(Some(IrInstruction::Popf)),
            Mnemonic::Lahf => Ok(Some(IrInstruction::Lahf)),
            Mnemonic::Sahf => Ok(Some(IrInstruction::Sahf)),
            Mnemonic::Cld => Ok(Some(IrInstruction::Cld)),
            Mnemonic::Std => Ok(Some(IrInstruction::Std)),
            Mnemonic::Clc => Ok(Some(IrInstruction::Clc)),
            Mnemonic::Stc => Ok(Some(IrInstruction::Stc)),
            _ => Ok(None),
        }
    }

    /// 转换系统指令
    fn convert_system(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrInstruction>> {
        use iced_x86::Mnemonic;

        match instruction.iced().mnemonic() {
            Mnemonic::Syscall => Ok(Some(IrInstruction::Syscall)),
            Mnemonic::Sysret => Ok(Some(IrInstruction::Sysret)),
            Mnemonic::Int => {
                let vector = instruction.iced().immediate8();
                Ok(Some(IrInstruction::Int { vector }))
            }
            Mnemonic::Int3 => Ok(Some(IrInstruction::Int3)),
            Mnemonic::Ud2 => Ok(Some(IrInstruction::Ud2)),
            _ => Ok(None),
        }
    }

    /// 通用转换（对于未特殊处理的指令）
    fn convert_generic(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrInstruction>> {
        Ok(None)
    }

    /// 转换操作数
    fn convert_operand(&self, instruction: &Instruction, index: u32) -> DisassemblyResult<IrOperand> {
        let iced = instruction.iced();
        let op_kind = iced.op_kind(index);
        
        match op_kind {
            OpKind::Register => {
                let reg = iced.op_register(index);
                Ok(IrOperand::Register(self.convert_register(reg)?))
            }
            OpKind::Immediate8 => Ok(IrOperand::Immediate(IrImmediate::U8(iced.immediate8()))),
            OpKind::Immediate16 => Ok(IrOperand::Immediate(IrImmediate::U16(iced.immediate16()))),
            OpKind::Immediate32 => Ok(IrOperand::Immediate(IrImmediate::U32(iced.immediate32()))),
            OpKind::Immediate64 => Ok(IrOperand::Immediate(IrImmediate::U64(iced.immediate64()))),
            OpKind::Immediate8to16 => Ok(IrOperand::Immediate(IrImmediate::I16(iced.immediate8to16()))),
            OpKind::Immediate8to32 => Ok(IrOperand::Immediate(IrImmediate::I32(iced.immediate8to32()))),
            OpKind::Immediate8to64 => Ok(IrOperand::Immediate(IrImmediate::I64(iced.immediate8to64()))),
            OpKind::Immediate32to64 => Ok(IrOperand::Immediate(IrImmediate::I64(iced.immediate32to64()))),
            OpKind::Memory => {
                let mem = self.convert_memory_operand(iced)?;
                Ok(IrOperand::Memory(mem))
            }
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                // 分支目标作为立即数
                Ok(IrOperand::Immediate(IrImmediate::U64(iced.near_branch_target())))
            }
            _ => Err(super::DisassemblyError::IrConversionError(
                format!("Unsupported operand kind: {:?}", op_kind)
            )),
        }
    }

    /// 转换寄存器
    fn convert_register(&self, reg: IcedRegister) -> DisassemblyResult<IrRegister> {
        use iced_x86::Register;
        
        let ir_reg = match reg {
            // 8-bit
            Register::AL => IrRegister::Al,
            Register::CL => IrRegister::Cl,
            Register::DL => IrRegister::Dl,
            Register::BL => IrRegister::Bl,
            Register::AH => IrRegister::Ah,
            Register::CH => IrRegister::Ch,
            Register::DH => IrRegister::Dh,
            Register::BH => IrRegister::Bh,
            Register::R8L => IrRegister::R8b,
            Register::R9L => IrRegister::R9b,
            Register::R10L => IrRegister::R10b,
            Register::R11L => IrRegister::R11b,
            Register::R12L => IrRegister::R12b,
            Register::R13L => IrRegister::R13b,
            Register::R14L => IrRegister::R14b,
            Register::R15L => IrRegister::R15b,
            
            // 16-bit
            Register::AX => IrRegister::Ax,
            Register::CX => IrRegister::Cx,
            Register::DX => IrRegister::Dx,
            Register::BX => IrRegister::Bx,
            Register::SP => IrRegister::Sp,
            Register::BP => IrRegister::Bp,
            Register::SI => IrRegister::Si,
            Register::DI => IrRegister::Di,
            Register::R8W => IrRegister::R8w,
            Register::R9W => IrRegister::R9w,
            Register::R10W => IrRegister::R10w,
            Register::R11W => IrRegister::R11w,
            Register::R12W => IrRegister::R12w,
            Register::R13W => IrRegister::R13w,
            Register::R14W => IrRegister::R14w,
            Register::R15W => IrRegister::R15w,
            
            // 32-bit
            Register::EAX => IrRegister::Eax,
            Register::ECX => IrRegister::Ecx,
            Register::EDX => IrRegister::Edx,
            Register::EBX => IrRegister::Ebx,
            Register::ESP => IrRegister::Esp,
            Register::EBP => IrRegister::Ebp,
            Register::ESI => IrRegister::Esi,
            Register::EDI => IrRegister::Edi,
            Register::R8D => IrRegister::R8d,
            Register::R9D => IrRegister::R9d,
            Register::R10D => IrRegister::R10d,
            Register::R11D => IrRegister::R11d,
            Register::R12D => IrRegister::R12d,
            Register::R13D => IrRegister::R13d,
            Register::R14D => IrRegister::R14d,
            Register::R15D => IrRegister::R15d,
            
            // 64-bit
            Register::RAX => IrRegister::Rax,
            Register::RCX => IrRegister::Rcx,
            Register::RDX => IrRegister::Rdx,
            Register::RBX => IrRegister::Rbx,
            Register::RSP => IrRegister::Rsp,
            Register::RBP => IrRegister::Rbp,
            Register::RSI => IrRegister::Rsi,
            Register::RDI => IrRegister::Rdi,
            Register::R8 => IrRegister::R8,
            Register::R9 => IrRegister::R9,
            Register::R10 => IrRegister::R10,
            Register::R11 => IrRegister::R11,
            Register::R12 => IrRegister::R12,
            Register::R13 => IrRegister::R13,
            Register::R14 => IrRegister::R14,
            Register::R15 => IrRegister::R15,
            Register::RIP => IrRegister::Rip,
            
            // Segment registers
            Register::ES => IrRegister::Es,
            Register::CS => IrRegister::Cs,
            Register::SS => IrRegister::Ss,
            Register::DS => IrRegister::Ds,
            Register::FS => IrRegister::Fs,
            Register::GS => IrRegister::Gs,
            
            _ => return Err(super::DisassemblyError::IrConversionError(
                format!("Unsupported register: {:?}", reg)
            )),
        };
        
        Ok(ir_reg)
    }

    /// 转换内存操作数
    fn convert_memory_operand(&self, iced: &iced_x86::Instruction) -> DisassemblyResult<IrMemoryOperand> {
        let base = if iced.memory_base() != IcedRegister::None {
            Some(self.convert_register(iced.memory_base())?)
        } else {
            None
        };
        
        let index = if iced.memory_index() != IcedRegister::None {
            Some(self.convert_register(iced.memory_index())?)
        } else {
            None
        };
        
        let scale = iced.memory_index_scale();
        let displacement = iced.memory_displacement64() as i64;
        
        // 确定内存访问大小
        let size_bits = match iced.memory_size() {
            iced_x86::MemorySize::UInt8 => 8,
            iced_x86::MemorySize::UInt16 => 16,
            iced_x86::MemorySize::UInt32 => 32,
            iced_x86::MemorySize::UInt64 => 64,
            iced_x86::MemorySize::Int8 => 8,
            iced_x86::MemorySize::Int16 => 16,
            iced_x86::MemorySize::Int32 => 32,
            iced_x86::MemorySize::Int64 => 64,
            _ => 64, // 默认 64 位
        };
        
        Ok(IrMemoryOperand {
            segment: None, // 简化处理，暂时不考虑段寄存器
            base,
            index,
            scale,
            displacement,
            size_bits,
        })
    }

    /// 转换条件码
    fn convert_condition_code(&self, cc: ConditionCode) -> IrCondition {
        use iced_x86::ConditionCode;
        match cc {
            ConditionCode::e => IrCondition::E,
            ConditionCode::ne => IrCondition::Ne,
            ConditionCode::g => IrCondition::G,
            ConditionCode::ge => IrCondition::Ge,
            ConditionCode::l => IrCondition::L,
            ConditionCode::le => IrCondition::Le,
            ConditionCode::a => IrCondition::A,
            ConditionCode::ae => IrCondition::Ae,
            ConditionCode::b => IrCondition::B,
            ConditionCode::be => IrCondition::Be,
            ConditionCode::o => IrCondition::O,
            ConditionCode::no => IrCondition::No,
            ConditionCode::s => IrCondition::S,
            ConditionCode::ns => IrCondition::Ns,
            ConditionCode::p => IrCondition::P,
            ConditionCode::np => IrCondition::Np,
            _ => IrCondition::E, // 默认情况
        }
    }

    /// 生成新标签
    fn new_label(&mut self) -> u32 {
        let label = self.label_counter;
        self.label_counter += 1;
        label
    }
}

impl Default for IrConverter {
    fn default() -> Self {
        Self::new(DisassemblyMode::Mode64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::decoder::decode_single;
    use crate::intel::DisassemblyMode;

    #[test]
    fn test_convert_nop() {
        let data = vec![0x90];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Nop)));
    }

    #[test]
    fn test_convert_mov() {
        // mov rax, rbx
        let data = vec![0x48, 0x89, 0xD8];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Mov { .. })));
    }

    #[test]
    fn test_convert_push_pop() {
        // push rax
        let data = vec![0x50];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Push { .. })));

        // pop rbx
        let data = vec![0x5B];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Pop { .. })));
    }

    #[test]
    fn test_convert_arithmetic() {
        // add rax, rbx
        let data = vec![0x48, 0x01, 0xD8];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Add { .. })));
    }

    #[test]
    fn test_convert_jmp() {
        // jmp short
        let data = vec![0xEB, 0x05];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Jmp { .. })));
    }

    #[test]
    fn test_convert_call() {
        // call rel32
        let data = vec![0xE8, 0x00, 0x00, 0x00, 0x00];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Call { .. })));
    }

    #[test]
    fn test_convert_ret() {
        // ret
        let data = vec![0xC3];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Ret { .. })));
    }

    #[test]
    fn test_convert_multiple() {
        // nop; mov rax, rbx; add rax, rcx
        let data = vec![0x90, 0x48, 0x89, 0xD8, 0x48, 0x01, 0xC8];
        let mut decoder = crate::intel::decoder::Decoder::new(
            crate::intel::decoder::DecoderConfig::new(DisassemblyMode::Mode64, 0x1000)
        );
        let instructions = decoder.decode_all(&data).unwrap();
        let converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert_instructions(&instructions).unwrap();

        assert!(!ir.is_empty());
    }

    #[test]
    fn test_register_conversion() {
        let converter = IrConverter::new(DisassemblyMode::Mode64);
        
        let ir_reg = converter.convert_register(IcedRegister::RAX).unwrap();
        assert_eq!(ir_reg, IrRegister::Rax);
        
        let ir_reg = converter.convert_register(IcedRegister::EAX).unwrap();
        assert_eq!(ir_reg, IrRegister::Eax);
        
        let ir_reg = converter.convert_register(IcedRegister::AL).unwrap();
        assert_eq!(ir_reg, IrRegister::Al);
    }

    #[test]
    fn test_condition_code_conversion() {
        let converter = IrConverter::new(DisassemblyMode::Mode64);
        
        assert_eq!(converter.convert_condition_code(ConditionCode::e), IrCondition::E);
        assert_eq!(converter.convert_condition_code(ConditionCode::ne), IrCondition::Ne);
        assert_eq!(converter.convert_condition_code(ConditionCode::g), IrCondition::G);
        assert_eq!(converter.convert_condition_code(ConditionCode::l), IrCondition::L);
    }

    // ========== 新增测试：乘除法指令 ==========
    #[test]
    fn test_convert_mul() {
        // mul rax (48 F7 E0)
        let data = vec![0x48, 0xF7, 0xE0];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Mul { .. })));
    }

    #[test]
    fn test_convert_div() {
        // div rbx (48 F7 F3)
        let data = vec![0x48, 0xF7, 0xF3];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Div { .. })));
    }

    #[test]
    fn test_convert_idiv() {
        // idiv rcx (48 F7 F9)
        let data = vec![0x48, 0xF7, 0xF9];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Idiv { .. })));
    }

    // ========== 新增测试：移位指令 ==========
    #[test]
    fn test_convert_shl() {
        // shl rax, 1 (48 D1 E0)
        let data = vec![0x48, 0xD1, 0xE0];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Shl { .. })));
    }

    #[test]
    fn test_convert_shr() {
        // shr rax, 1 (48 D1 E8)
        let data = vec![0x48, 0xD1, 0xE8];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Shr { .. })));
    }

    #[test]
    fn test_convert_sar() {
        // sar rax, 4 (48 C1 F8 04)
        let data = vec![0x48, 0xC1, 0xF8, 0x04];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Sar { .. })));
    }

    #[test]
    fn test_convert_rol() {
        // rol eax, 5 (C1 C0 05)
        let data = vec![0xC1, 0xC0, 0x05];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Rol { .. })));
    }

    #[test]
    fn test_convert_ror() {
        // ror eax, 3 (C1 C8 03)
        let data = vec![0xC1, 0xC8, 0x03];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Ror { .. })));
    }

    // ========== 新增测试：位操作指令 ==========
    #[test]
    fn test_convert_bt() {
        // bt rax, rbx (48 0F A3 D8)
        let data = vec![0x48, 0x0F, 0xA3, 0xD8];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Bt { .. })));
    }

    #[test]
    fn test_convert_bts() {
        // bts rax, rbx (48 0F AB D8)
        let data = vec![0x48, 0x0F, 0xAB, 0xD8];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Bts { .. })));
    }

    #[test]
    fn test_convert_btr() {
        // btr rax, rbx (48 0F B3 D8)
        let data = vec![0x48, 0x0F, 0xB3, 0xD8];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Btr { .. })));
    }

    #[test]
    fn test_convert_bsf() {
        // bsf rax, rbx (48 0F BC C3)
        let data = vec![0x48, 0x0F, 0xBC, 0xC3];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Bsf { .. })));
    }

    #[test]
    fn test_convert_bsr() {
        // bsr rax, rbx (48 0F BD C3)
        let data = vec![0x48, 0x0F, 0xBD, 0xC3];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Bsr { .. })));
    }

    // ========== 新增测试：标志操作指令 ==========
    #[test]
    fn test_convert_pushf() {
        // pushf (9C)
        let data = vec![0x9C];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Pushf)));
    }

    #[test]
    fn test_convert_popf() {
        // popf (9D)
        let data = vec![0x9D];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Popf)));
    }

    #[test]
    fn test_convert_lahf() {
        // lahf (9F)
        let data = vec![0x9F];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Lahf)));
    }

    #[test]
    fn test_convert_sahf() {
        // sahf (9E)
        let data = vec![0x9E];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Sahf)));
    }

    #[test]
    fn test_convert_cld() {
        // cld (FC)
        let data = vec![0xFC];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Cld)));
    }

    #[test]
    fn test_convert_std() {
        // std (FD)
        let data = vec![0xFD];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Std)));
    }

    // ========== 新增测试：系统指令 ==========
    #[test]
    fn test_convert_syscall() {
        // syscall (0F 05)
        let data = vec![0x0F, 0x05];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Syscall)));
    }

    #[test]
    fn test_convert_int3() {
        // int3 (CC)
        let data = vec![0xCC];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut converter = IrConverter::new(DisassemblyMode::Mode64);
        let ir = converter.convert(&insn).unwrap();

        assert!(ir.iter().any(|i| matches!(i, IrInstruction::Int3)));
    }
}
