//! IR 转换器模块
//!
//! 将 iced-x86 指令转换为 VMProtect IR。

use super::{
    DisassemblyMode, DisassemblyResult, Instruction, InstructionCategory,
    IrImmediate, IrInstruction, IrMemoryOperand, IrOperand, IrRegister,
};
use super::ir::{IrCondition, IrJumpTarget, IrOpcode};
use crate::error::Result;
use iced_x86::{ConditionCode, Mnemonic, OpKind, Register as IcedRegister};

/// IR 转换器
pub struct IrConverter {
    mode: DisassemblyMode,
    #[allow(dead_code)]
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
        let ip = instruction.ip();
        
        // 添加注释显示原始指令
        let comment = format!("{:X}: {:?}", ip, instruction.iced().mnemonic());
        result.push(IrInstruction::new(ip, IrOpcode::Comment { text: comment }));

        let ir_opcode = match instruction.category() {
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

        match ir_opcode {
            Ok(op) => {
                if let Some(opcode) = op {
                    result.push(IrInstruction::new(ip, opcode));
                }
            }
            Err(_e) => {
                // 转换失败时添加未实现注释
                result.push(IrInstruction::new(ip, IrOpcode::Comment {
                    text: format!("UNIMPLEMENTED: {:?}", instruction.iced().mnemonic()),
                }));
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

    fn convert_nop(&self, _instruction: &Instruction) -> DisassemblyResult<Option<IrOpcode>> {
        Ok(Some(IrOpcode::Nop))
    }

    fn convert_data_transfer(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrOpcode>> {
        match instruction.iced().mnemonic() {
            Mnemonic::Mov => {
                let dst = self.convert_operand(instruction, 0)?;
                let src = self.convert_operand(instruction, 1)?;
                Ok(Some(IrOpcode::Mov { dst, src }))
            }
            Mnemonic::Push => {
                let src = self.convert_operand(instruction, 0)?;
                Ok(Some(IrOpcode::Push { src }))
            }
            Mnemonic::Pop => {
                let dst = self.convert_operand(instruction, 0)?;
                Ok(Some(IrOpcode::Pop { dst }))
            }
            Mnemonic::Lea => {
                let dst = self.convert_register(instruction.iced().op_register(0))?;
                let src = self.convert_memory_operand(instruction, 1)?;
                Ok(Some(IrOpcode::Lea { dst, src }))
            }
            _ => self.convert_generic(instruction),
        }
    }

    fn convert_arithmetic(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrOpcode>> {
        match instruction.iced().mnemonic() {
            Mnemonic::Add => {
                let dst = self.convert_operand(instruction, 0)?;
                let src = self.convert_operand(instruction, 1)?;
                Ok(Some(IrOpcode::Add { dst, src }))
            }
            Mnemonic::Sub => {
                let dst = self.convert_operand(instruction, 0)?;
                let src = self.convert_operand(instruction, 1)?;
                Ok(Some(IrOpcode::Sub { dst, src }))
            }
            Mnemonic::Inc => {
                let op = self.convert_operand(instruction, 0)?;
                Ok(Some(IrOpcode::Inc { op }))
            }
            Mnemonic::Dec => {
                let op = self.convert_operand(instruction, 0)?;
                Ok(Some(IrOpcode::Dec { op }))
            }
            Mnemonic::Neg => {
                let op = self.convert_operand(instruction, 0)?;
                Ok(Some(IrOpcode::Neg { op }))
            }
            Mnemonic::Imul => {
                let op_count = instruction.op_count();
                if op_count == 1 {
                    let src = self.convert_operand(instruction, 0)?;
                    Ok(Some(IrOpcode::Imul { dst: None, src1: src, src2: None }))
                } else if op_count == 2 {
                    let dst = self.convert_operand(instruction, 0)?;
                    let src = self.convert_operand(instruction, 1)?;
                    Ok(Some(IrOpcode::Imul { dst: Some(dst.clone()), src1: dst, src2: Some(src) }))
                } else {
                    let dst = self.convert_operand(instruction, 0)?;
                    let src1 = self.convert_operand(instruction, 1)?;
                    let src2 = self.convert_operand(instruction, 2)?;
                    Ok(Some(IrOpcode::Imul { dst: Some(dst), src1, src2: Some(src2) }))
                }
            }
            _ => self.convert_generic(instruction),
        }
    }

    fn convert_logical(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrOpcode>> {
        match instruction.iced().mnemonic() {
            Mnemonic::And => {
                let dst = self.convert_operand(instruction, 0)?;
                let src = self.convert_operand(instruction, 1)?;
                Ok(Some(IrOpcode::And { dst, src }))
            }
            Mnemonic::Or => {
                let dst = self.convert_operand(instruction, 0)?;
                let src = self.convert_operand(instruction, 1)?;
                Ok(Some(IrOpcode::Or { dst, src }))
            }
            Mnemonic::Xor => {
                let dst = self.convert_operand(instruction, 0)?;
                let src = self.convert_operand(instruction, 1)?;
                Ok(Some(IrOpcode::Xor { dst, src }))
            }
            Mnemonic::Not => {
                let op = self.convert_operand(instruction, 0)?;
                Ok(Some(IrOpcode::Not { op }))
            }
            _ => self.convert_generic(instruction),
        }
    }

    fn convert_compare(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrOpcode>> {
        match instruction.iced().mnemonic() {
            Mnemonic::Cmp => {
                let op1 = self.convert_operand(instruction, 0)?;
                let op2 = self.convert_operand(instruction, 1)?;
                Ok(Some(IrOpcode::Cmp { op1, op2 }))
            }
            Mnemonic::Test => {
                let op1 = self.convert_operand(instruction, 0)?;
                let op2 = self.convert_operand(instruction, 1)?;
                Ok(Some(IrOpcode::Test { op1, op2 }))
            }
            _ => self.convert_generic(instruction),
        }
    }

    fn convert_unconditional_jump(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrOpcode>> {
        let target = if let Some(addr) = instruction.branch_target() {
            IrJumpTarget::Direct(addr)
        } else {
            let op = self.convert_operand(instruction, 0)?;
            match op {
                IrOperand::Register(r) => IrJumpTarget::Register(r),
                IrOperand::Memory(m) => IrJumpTarget::Memory(m),
                _ => return Err(crate::intel::DisassemblyError::IrConversionError("Invalid jump target".to_string())),
            }
        };
        Ok(Some(IrOpcode::Jmp { target }))
    }

    fn convert_conditional_jump(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrOpcode>> {
        let condition = self.convert_condition_code(instruction.iced().condition_code());
        let target = if let Some(addr) = instruction.branch_target() {
            IrJumpTarget::Direct(addr)
        } else {
            return Err(crate::intel::DisassemblyError::IrConversionError("Conditional jump with indirect target not supported".to_string()));
        };
        Ok(Some(IrOpcode::Jcc { condition, target }))
    }

    fn convert_call(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrOpcode>> {
        let target = if let Some(addr) = instruction.branch_target() {
            IrJumpTarget::Direct(addr)
        } else {
            let op = self.convert_operand(instruction, 0)?;
            match op {
                IrOperand::Register(r) => IrJumpTarget::Register(r),
                IrOperand::Memory(m) => IrJumpTarget::Memory(m),
                _ => return Err(crate::intel::DisassemblyError::IrConversionError("Invalid call target".to_string())),
            }
        };
        Ok(Some(IrOpcode::Call { target }))
    }

    fn convert_return(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrOpcode>> {
        let pop_bytes = if instruction.op_count() > 0 {
            Some(instruction.iced().immediate16() as u16)
        } else {
            None
        };
        Ok(Some(IrOpcode::Ret { pop_bytes }))
    }

    fn convert_conditional_move(&self, _instruction: &Instruction) -> DisassemblyResult<Option<IrOpcode>> {
        Ok(None)
    }

    fn convert_shift(&self, instruction: &Instruction) -> DisassemblyResult<Option<IrOpcode>> {
        let dst = self.convert_operand(instruction, 0)?;
        let count = self.convert_operand(instruction, 1)?;
        match instruction.iced().mnemonic() {
            Mnemonic::Shl => Ok(Some(IrOpcode::Shl { dst, count })),
            Mnemonic::Shr => Ok(Some(IrOpcode::Shr { dst, count })),
            Mnemonic::Sar => Ok(Some(IrOpcode::Sar { dst, count })),
            _ => Ok(None),
        }
    }

    fn convert_bit(&self, _instruction: &Instruction) -> DisassemblyResult<Option<IrOpcode>> { Ok(None) }
    fn convert_flags(&self, _instruction: &Instruction) -> DisassemblyResult<Option<IrOpcode>> { Ok(None) }
    fn convert_system(&self, _instruction: &Instruction) -> DisassemblyResult<Option<IrOpcode>> { Ok(None) }
    fn convert_generic(&self, _instruction: &Instruction) -> DisassemblyResult<Option<IrOpcode>> { Ok(None) }

    fn convert_operand(&self, instruction: &Instruction, op_index: u32) -> DisassemblyResult<IrOperand> {
        let iced = instruction.iced();
        match iced.op_kind(op_index) {
            OpKind::Register => Ok(IrOperand::Register(self.convert_register(iced.op_register(op_index))?)),
            OpKind::Immediate8 | OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64 => Ok(IrOperand::Immediate(IrImmediate::U8(iced.immediate8()))),
            OpKind::Immediate16 => Ok(IrOperand::Immediate(IrImmediate::U16(iced.immediate16()))),
            OpKind::Immediate32 | OpKind::Immediate32to64 => Ok(IrOperand::Immediate(IrImmediate::U32(iced.immediate32()))),
            OpKind::Immediate64 => Ok(IrOperand::Immediate(IrImmediate::U64(iced.immediate64()))),
            OpKind::Memory => Ok(IrOperand::Memory(self.convert_memory_operand(instruction, op_index)?)),
            _ => Err(crate::intel::DisassemblyError::IrConversionError(format!("Unsupported operand kind: {:?}", iced.op_kind(op_index)))),
        }
    }

    fn convert_register(&self, reg: IcedRegister) -> DisassemblyResult<IrRegister> {
        match reg {
            IcedRegister::RAX | IcedRegister::EAX | IcedRegister::AX | IcedRegister::AL => Ok(IrRegister::Rax),
            IcedRegister::RCX | IcedRegister::ECX | IcedRegister::CX | IcedRegister::CL => Ok(IrRegister::Rcx),
            IcedRegister::RDX | IcedRegister::EDX | IcedRegister::DX | IcedRegister::DL => Ok(IrRegister::Rdx),
            IcedRegister::RBX | IcedRegister::EBX | IcedRegister::BX | IcedRegister::BL => Ok(IrRegister::Rbx),
            IcedRegister::RSP | IcedRegister::ESP | IcedRegister::SP | IcedRegister::SPL => Ok(IrRegister::Rsp),
            IcedRegister::RBP | IcedRegister::EBP | IcedRegister::BP | IcedRegister::BPL => Ok(IrRegister::Rbp),
            IcedRegister::RSI | IcedRegister::ESI | IcedRegister::SI | IcedRegister::SIL => Ok(IrRegister::Rsi),
            IcedRegister::RDI | IcedRegister::EDI | IcedRegister::DI | IcedRegister::DIL => Ok(IrRegister::Rdi),
            IcedRegister::R8 | IcedRegister::R8D | IcedRegister::R8W | IcedRegister::R8L => Ok(IrRegister::R8),
            IcedRegister::R9 | IcedRegister::R9D | IcedRegister::R9W | IcedRegister::R9L => Ok(IrRegister::R9),
            _ => Ok(IrRegister::Rax),
        }
    }

    fn convert_memory_operand(&self, instruction: &Instruction, _op_index: u32) -> DisassemblyResult<IrMemoryOperand> {
        let iced = instruction.iced();
        Ok(IrMemoryOperand {
            base: if iced.memory_base() != IcedRegister::None { Some(self.convert_register(iced.memory_base())?) } else { None },
            index: if iced.memory_index() != IcedRegister::None { Some(self.convert_register(iced.memory_index())?) } else { None },
            scale: iced.memory_index_scale() as u32,
            displacement: iced.memory_displacement64() as i64,
            size_bits: (iced.memory_size().size() * 8) as u32,
            segment: None,
        })
    }

    fn convert_condition_code(&self, cc: ConditionCode) -> IrCondition {
        match cc {
            ConditionCode::e => IrCondition::E,
            ConditionCode::ne => IrCondition::Ne,
            ConditionCode::b => IrCondition::B,
            ConditionCode::be => IrCondition::Be,
            ConditionCode::a => IrCondition::A,
            ConditionCode::ae => IrCondition::Ae,
            ConditionCode::l => IrCondition::L,
            ConditionCode::le => IrCondition::Le,
            ConditionCode::g => IrCondition::G,
            ConditionCode::ge => IrCondition::Ge,
            _ => IrCondition::E,
        }
    }
}
