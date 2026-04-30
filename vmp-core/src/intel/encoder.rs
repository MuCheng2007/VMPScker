//! 编码器模块
//!
//! 将 VMProtect IR 指令编码为 x86/x64 机器码。
//! 使用 iced-x86 库提供高性能的编码功能。

use super::{
    DisassemblyMode, DisassemblyError, DisassemblyResult,
    ir::{IrInstruction, IrOperand, IrRegister, IrMemoryOperand, IrImmediate, IrCondition, IrJumpTarget}
};
use iced_x86::{Instruction as IcedInstruction, Register as IcedRegister, Code, ConditionCode};
use std::collections::HashMap;

/// 编码器配置
#[derive(Debug, Clone)]
pub struct EncoderConfig {
    /// 编码模式
    pub mode: DisassemblyMode,
    /// 基础地址
    pub base_address: u64,
    /// 默认地址大小（0表示使用模式默认值）
    pub address_size: u32,
    /// 默认操作数大小（0表示使用模式默认值）
    pub operand_size: u32,
}

impl EncoderConfig {
    /// 创建新的配置
    pub fn new(mode: DisassemblyMode, base_address: u64) -> Self {
        Self {
            mode,
            base_address,
            address_size: 0,
            operand_size: 0,
        }
    }

    /// 设置地址大小
    pub fn with_address_size(mut self, size: u32) -> Self {
        self.address_size = size;
        self
    }

    /// 设置操作数大小
    pub fn with_operand_size(mut self, size: u32) -> Self {
        self.operand_size = size;
        self
    }

    /// 获取有效的地址大小
    pub fn effective_address_size(&self) -> u32 {
        if self.address_size > 0 {
            self.address_size
        } else {
            self.mode.bits()
        }
    }

    /// 获取有效的操作数大小
    pub fn effective_operand_size(&self) -> u32 {
        if self.operand_size > 0 {
            self.operand_size
        } else {
            self.mode.bits()
        }
    }
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self {
            mode: DisassemblyMode::Mode64,
            base_address: 0,
            address_size: 0,
            operand_size: 0,
        }
    }
}

/// 编码后的指令
#[derive(Debug, Clone)]
pub struct EncodedInstruction {
    /// 机器码字节序列
    pub bytes: Vec<u8>,
    /// 指令长度
    pub len: u8,
    /// 指令地址
    pub address: u64,
    /// 指令类型
    pub instruction_type: String,
}

impl EncodedInstruction {
    /// 创建新的编码结果
    pub fn new(bytes: Vec<u8>, address: u64, instruction_type: impl Into<String>) -> Self {
        let len = bytes.len() as u8;
        Self {
            bytes,
            len,
            address,
            instruction_type: instruction_type.into(),
        }
    }
}

/// 标签信息
#[derive(Debug, Clone)]
struct LabelInfo {
    /// 标签 ID
    id: u32,
    /// 标签地址（编码后确定）
    address: Option<u64>,
}

/// 待回填的跳转信息
#[derive(Debug, Clone)]
struct PendingJump {
    /// 跳转指令在输出中的位置
    position: usize,
    /// 跳转指令长度
    instruction_len: u8,
    /// 跳转指令地址
    instruction_address: u64,
    /// 目标标签 ID
    target_label: u32,
    /// 是否是短跳转
    is_short: bool,
}

/// 编码器
pub struct Encoder {
    config: EncoderConfig,
    /// 当前指令指针
    current_ip: u64,
    /// 标签映射表
    labels: HashMap<u32, LabelInfo>,
    /// 待回填的跳转列表
    pending_jumps: Vec<PendingJump>,
    /// 输出缓冲区
    output: Vec<u8>,
}

impl Encoder {
    /// 创建新的编码器
    pub fn new(config: EncoderConfig) -> Self {
        let current_ip = config.base_address;
        Self {
            config,
            current_ip,
            labels: HashMap::new(),
            pending_jumps: Vec::new(),
            output: Vec::new(),
        }
    }

    /// 获取配置
    pub fn config(&self) -> &EncoderConfig {
        &self.config
    }

    /// 获取当前指令指针
    pub fn current_ip(&self) -> u64 {
        self.current_ip
    }

    /// 编码单条指令
    pub fn encode(&mut self, instruction: &IrInstruction) -> DisassemblyResult<EncodedInstruction> {
        let start_ip = self.current_ip;
        let start_pos = self.output.len();

        match instruction {
            IrInstruction::Nop => self.encode_nop(),
            IrInstruction::Mov { dst, src } => self.encode_mov(dst, src),
            IrInstruction::Push { src } => self.encode_push(src),
            IrInstruction::Pop { dst } => self.encode_pop(dst),
            IrInstruction::Lea { dst, src } => self.encode_lea(dst, src),
            IrInstruction::Xchg { op1, op2 } => self.encode_xchg(op1, op2),
            IrInstruction::Cmov { condition, dst, src } => self.encode_cmov(*condition, dst, src),
            IrInstruction::Add { dst, src } => self.encode_add(dst, src),
            IrInstruction::Sub { dst, src } => self.encode_sub(dst, src),
            IrInstruction::Inc { op } => self.encode_inc(op),
            IrInstruction::Dec { op } => self.encode_dec(op),
            IrInstruction::Neg { op } => self.encode_neg(op),
            IrInstruction::Mul { src } => self.encode_mul(src),
            IrInstruction::Imul { dst, src1, src2 } => self.encode_imul(dst.as_ref(), src1, src2.as_ref()),
            IrInstruction::Div { src } => self.encode_div(src),
            IrInstruction::Idiv { src } => self.encode_idiv(src),
            IrInstruction::Cmp { op1, op2 } => self.encode_cmp(op1, op2),
            IrInstruction::And { dst, src } => self.encode_and(dst, src),
            IrInstruction::Or { dst, src } => self.encode_or(dst, src),
            IrInstruction::Xor { dst, src } => self.encode_xor(dst, src),
            IrInstruction::Not { op } => self.encode_not(op),
            IrInstruction::Test { op1, op2 } => self.encode_test(op1, op2),
            IrInstruction::Shl { dst, count } => self.encode_shl(dst, count),
            IrInstruction::Shr { dst, count } => self.encode_shr(dst, count),
            IrInstruction::Sar { dst, count } => self.encode_sar(dst, count),
            IrInstruction::Rol { dst, count } => self.encode_rol(dst, count),
            IrInstruction::Ror { dst, count } => self.encode_ror(dst, count),
            IrInstruction::Bt { base, offset } => self.encode_bt(base, offset),
            IrInstruction::Bts { base, offset } => self.encode_bts(base, offset),
            IrInstruction::Btr { base, offset } => self.encode_btr(base, offset),
            IrInstruction::Bsf { dst, src } => self.encode_bsf(dst, src),
            IrInstruction::Bsr { dst, src } => self.encode_bsr(dst, src),
            IrInstruction::Jmp { target } => self.encode_jmp(target),
            IrInstruction::Jcc { condition, target } => self.encode_jcc(*condition, target),
            IrInstruction::Call { target } => self.encode_call(target),
            IrInstruction::Ret { pop_bytes } => self.encode_ret(*pop_bytes),
            IrInstruction::Syscall => self.encode_syscall(),
            IrInstruction::Sysret => self.encode_sysret(),
            IrInstruction::Int { vector } => self.encode_int(*vector),
            IrInstruction::Int3 => self.encode_int3(),
            IrInstruction::Ud2 => self.encode_ud2(),
            IrInstruction::Pushf => self.encode_pushf(),
            IrInstruction::Popf => self.encode_popf(),
            IrInstruction::Lahf => self.encode_lahf(),
            IrInstruction::Sahf => self.encode_sahf(),
            IrInstruction::Cld => self.encode_cld(),
            IrInstruction::Std => self.encode_std(),
            IrInstruction::Clc => self.encode_clc(),
            IrInstruction::Stc => self.encode_stc(),
            IrInstruction::Label { id } => {
                self.bind_label(*id);
                Ok(())
            }
            IrInstruction::Comment { .. } => Ok(()), // 注释不产生机器码
        }?;

        let end_pos = self.output.len();
        let bytes = self.output[start_pos..end_pos].to_vec();
        let len = bytes.len() as u8;

        let result = EncodedInstruction {
            bytes,
            len,
            address: start_ip,
            instruction_type: format!("{:?}", instruction).split_whitespace().next().unwrap_or("Unknown").to_string(),
        };

        self.current_ip += len as u64;

        Ok(result)
    }

    /// 编码多条指令
    pub fn encode_all(&mut self, instructions: &[IrInstruction]) -> DisassemblyResult<Vec<EncodedInstruction>> {
        let mut results = Vec::new();

        // 第一遍：收集标签位置
        self.collect_labels(instructions)?;

        // 第二遍：编码指令
        for instruction in instructions {
            let encoded = self.encode(instruction)?;
            results.push(encoded);
        }

        // 回填跳转偏移
        self.resolve_jumps()?;

        Ok(results)
    }

    /// 获取编码后的字节序列
    pub fn get_bytes(&self) -> &[u8] {
        &self.output
    }

    /// 获取编码后的字节序列（克隆）
    pub fn into_bytes(self) -> Vec<u8> {
        self.output
    }

    /// 收集标签位置
    fn collect_labels(&mut self, instructions: &[IrInstruction]) -> DisassemblyResult<()> {
        let mut ip = self.config.base_address;

        for instruction in instructions {
            if let IrInstruction::Label { id } = instruction {
                self.labels.insert(*id, LabelInfo {
                    id: *id,
                    address: Some(ip),
                });
            } else {
                // 估算指令长度（简化处理）
                ip += self.estimate_instruction_size(instruction)? as u64;
            }
        }

        Ok(())
    }

    /// 估算指令大小（用于第一遍扫描）
    fn estimate_instruction_size(&self, instruction: &IrInstruction) -> DisassemblyResult<u8> {
        // 简化估算，实际实现中可能需要更精确的计算
        let size = match instruction {
            IrInstruction::Nop => 1,
            IrInstruction::Push { src } => match src {
                IrOperand::Register(_) => 1,
                IrOperand::Immediate(imm) => {
                    match imm {
                        IrImmediate::U8(_) | IrImmediate::I8(_) => 2,
                        _ => 5,
                    }
                }
                IrOperand::Memory(_) => 7,
            },
            IrInstruction::Pop { dst } => match dst {
                IrOperand::Register(_) => 1,
                IrOperand::Memory(_) => 7,
                _ => 1,
            },
            IrInstruction::Jmp { .. } => 5,
            IrInstruction::Jcc { .. } => 6,
            IrInstruction::Call { .. } => 5,
            IrInstruction::Ret { pop_bytes } => {
                if pop_bytes.is_some() { 3 } else { 1 }
            }
            _ => 7, // 默认估算
        };
        Ok(size)
    }

    /// 绑定标签到当前地址
    fn bind_label(&mut self, id: u32) {
        self.labels.insert(id, LabelInfo {
            id,
            address: Some(self.current_ip),
        });
    }

    /// 解析跳转目标地址
    fn resolve_jump_target(&self, target: &IrJumpTarget) -> DisassemblyResult<u64> {
        match target {
            IrJumpTarget::Direct(addr) => Ok(*addr),
            IrJumpTarget::Relative(offset) => {
                Ok((self.current_ip as i64 + offset) as u64)
            }
            IrJumpTarget::Label(label_id) => {
                self.labels.get(label_id)
                    .and_then(|info| info.address)
                    .ok_or_else(|| DisassemblyError::IrConversionError(
                        format!("Undefined label: {}", label_id)
                    ))
            }
            _ => Err(DisassemblyError::IrConversionError(
                "Unsupported jump target type".to_string()
            )),
        }
    }

    /// 回填所有待处理的跳转
    fn resolve_jumps(&mut self) -> DisassemblyResult<()> {
        for pending in &self.pending_jumps {
            let target_addr = self.labels.get(&pending.target_label)
                .and_then(|info| info.address)
                .ok_or_else(|| DisassemblyError::IrConversionError(
                    format!("Undefined label: {}", pending.target_label)
                ))?;

            let instruction_end = pending.instruction_address + pending.instruction_len as u64;
            let offset = target_addr as i64 - instruction_end as i64;

            // 回填偏移到输出缓冲区
            let offset_pos = pending.position;
            if pending.is_short && offset >= -128 && offset <= 127 {
                self.output[offset_pos] = offset as i8 as u8;
            } else if !pending.is_short {
                let offset_bytes = (offset as i32).to_le_bytes();
                self.output[offset_pos..offset_pos + 4].copy_from_slice(&offset_bytes);
            } else {
                return Err(DisassemblyError::IrConversionError(
                    "Jump offset out of range for short jump".to_string()
                ));
            }
        }

        self.pending_jumps.clear();
        Ok(())
    }

    /// 将 IR 寄存器转换为 iced 寄存器
    fn convert_register(&self, reg: &IrRegister) -> DisassemblyResult<IcedRegister> {
        use IrRegister::*;
        
        let iced_reg = match reg {
            // 8-bit
            Al => IcedRegister::AL,
            Cl => IcedRegister::CL,
            Dl => IcedRegister::DL,
            Bl => IcedRegister::BL,
            Ah => IcedRegister::AH,
            Ch => IcedRegister::CH,
            Dh => IcedRegister::DH,
            Bh => IcedRegister::BH,
            // x86-64 low byte registers
            Spl => IcedRegister::SPL,
            Bpl => IcedRegister::BPL,
            Sil => IcedRegister::SIL,
            Dil => IcedRegister::DIL,
            R8b => IcedRegister::R8L,
            R9b => IcedRegister::R9L,
            R10b => IcedRegister::R10L,
            R11b => IcedRegister::R11L,
            R12b => IcedRegister::R12L,
            R13b => IcedRegister::R13L,
            R14b => IcedRegister::R14L,
            R15b => IcedRegister::R15L,
            
            // 16-bit
            Ax => IcedRegister::AX,
            Cx => IcedRegister::CX,
            Dx => IcedRegister::DX,
            Bx => IcedRegister::BX,
            Sp => IcedRegister::SP,
            Bp => IcedRegister::BP,
            Si => IcedRegister::SI,
            Di => IcedRegister::DI,
            R8w => IcedRegister::R8W,
            R9w => IcedRegister::R9W,
            R10w => IcedRegister::R10W,
            R11w => IcedRegister::R11W,
            R12w => IcedRegister::R12W,
            R13w => IcedRegister::R13W,
            R14w => IcedRegister::R14W,
            R15w => IcedRegister::R15W,
            
            // 32-bit
            Eax => IcedRegister::EAX,
            Ecx => IcedRegister::ECX,
            Edx => IcedRegister::EDX,
            Ebx => IcedRegister::EBX,
            Esp => IcedRegister::ESP,
            Ebp => IcedRegister::EBP,
            Esi => IcedRegister::ESI,
            Edi => IcedRegister::EDI,
            R8d => IcedRegister::R8D,
            R9d => IcedRegister::R9D,
            R10d => IcedRegister::R10D,
            R11d => IcedRegister::R11D,
            R12d => IcedRegister::R12D,
            R13d => IcedRegister::R13D,
            R14d => IcedRegister::R14D,
            R15d => IcedRegister::R15D,
            
            // 64-bit
            Rax => IcedRegister::RAX,
            Rcx => IcedRegister::RCX,
            Rdx => IcedRegister::RDX,
            Rbx => IcedRegister::RBX,
            Rsp => IcedRegister::RSP,
            Rbp => IcedRegister::RBP,
            Rsi => IcedRegister::RSI,
            Rdi => IcedRegister::RDI,
            R8 => IcedRegister::R8,
            R9 => IcedRegister::R9,
            R10 => IcedRegister::R10,
            R11 => IcedRegister::R11,
            R12 => IcedRegister::R12,
            R13 => IcedRegister::R13,
            R14 => IcedRegister::R14,
            R15 => IcedRegister::R15,
            Rip => IcedRegister::RIP,
            
            // Segment registers
            Es => IcedRegister::ES,
            Cs => IcedRegister::CS,
            Ss => IcedRegister::SS,
            Ds => IcedRegister::DS,
            Fs => IcedRegister::FS,
            Gs => IcedRegister::GS,
            
            // Flags - 这些不是通用寄存器，不能直接编码
            Eflags | Rflags => return Err(DisassemblyError::IrConversionError(
                "EFLAGS/RFLAGS cannot be directly encoded as a register operand".to_string()
            )),
        };
        
        Ok(iced_reg)
    }

    /// 将 IR 条件码转换为 iced 条件码
    fn convert_condition(&self, condition: IrCondition) -> ConditionCode {
        match condition {
            IrCondition::E => ConditionCode::e,
            IrCondition::Ne => ConditionCode::ne,
            IrCondition::G => ConditionCode::g,
            IrCondition::Ge => ConditionCode::ge,
            IrCondition::L => ConditionCode::l,
            IrCondition::Le => ConditionCode::le,
            IrCondition::A => ConditionCode::a,
            IrCondition::Ae => ConditionCode::ae,
            IrCondition::B => ConditionCode::b,
            IrCondition::Be => ConditionCode::be,
            IrCondition::O => ConditionCode::o,
            IrCondition::No => ConditionCode::no,
            IrCondition::S => ConditionCode::s,
            IrCondition::Ns => ConditionCode::ns,
            IrCondition::P => ConditionCode::p,
            IrCondition::Np => ConditionCode::np,
            _ => ConditionCode::e,
        }
    }

    /// 获取立即数值作为 i64
    fn immediate_to_i64(&self, imm: &IrImmediate) -> i64 {
        match imm {
            IrImmediate::U8(v) => *v as i64,
            IrImmediate::U16(v) => *v as i64,
            IrImmediate::U32(v) => *v as i64,
            IrImmediate::U64(v) => *v as i64,
            IrImmediate::I8(v) => *v as i64,
            IrImmediate::I16(v) => *v as i64,
            IrImmediate::I32(v) => *v as i64,
            IrImmediate::I64(v) => *v,
        }
    }

    /// 获取立即数值作为 u64
    fn immediate_to_u64(&self, imm: &IrImmediate) -> u64 {
        match imm {
            IrImmediate::U8(v) => *v as u64,
            IrImmediate::U16(v) => *v as u64,
            IrImmediate::U32(v) => *v as u64,
            IrImmediate::U64(v) => *v,
            IrImmediate::I8(v) => *v as u64,
            IrImmediate::I16(v) => *v as u64,
            IrImmediate::I32(v) => *v as u64,
            IrImmediate::I64(v) => *v as u64,
        }
    }

    /// 编码 nop 指令
    fn encode_nop(&mut self) -> DisassemblyResult<()> {
        self.output.push(0x90);
        Ok(())
    }

    /// 编码 mov 指令
    fn encode_mov(&mut self, dst: &IrOperand, src: &IrOperand) -> DisassemblyResult<()> {
        match (dst, src) {
            // mov reg, reg
            (IrOperand::Register(dst_reg), IrOperand::Register(src_reg)) => {
                self.encode_mov_reg_reg(dst_reg, src_reg)
            }
            // mov reg, imm
            (IrOperand::Register(dst_reg), IrOperand::Immediate(imm)) => {
                self.encode_mov_reg_imm(dst_reg, imm)
            }
            // mov reg, mem
            (IrOperand::Register(dst_reg), IrOperand::Memory(mem)) => {
                self.encode_mov_reg_mem(dst_reg, mem)
            }
            // mov mem, reg
            (IrOperand::Memory(mem), IrOperand::Register(src_reg)) => {
                self.encode_mov_mem_reg(mem, src_reg)
            }
            // mov mem, imm
            (IrOperand::Memory(mem), IrOperand::Immediate(imm)) => {
                self.encode_mov_mem_imm(mem, imm)
            }
            _ => Err(DisassemblyError::IrConversionError(
                "Unsupported mov operand combination".to_string()
            )),
        }
    }

    /// 编码 mov reg, reg
    fn encode_mov_reg_reg(&mut self, dst: &IrRegister, src: &IrRegister) -> DisassemblyResult<()> {
        let dst_iced = self.convert_register(dst)?;
        let src_iced = self.convert_register(src)?;
        
        // 使用原始字节编码 mov reg, reg
        // REX.W (0x48) + 0x89 + ModR/M
        let rex = if dst_iced.is_gpr64() || src_iced.is_gpr64() {
            let mut rex = 0x48;
            if dst_iced.number() >= 8 {
                rex |= 0x01;
            }
            if src_iced.number() >= 8 {
                rex |= 0x04;
            }
            Some(rex)
        } else if dst_iced.number() >= 8 || src_iced.number() >= 8 {
            let mut rex = 0x40;
            if dst_iced.number() >= 8 {
                rex |= 0x01;
            }
            if src_iced.number() >= 8 {
                rex |= 0x04;
            }
            Some(rex)
        } else {
            None
        };

        let dst_num = (dst_iced.number() & 7) as u8;
        let src_num = (src_iced.number() & 7) as u8;
        let modrm = 0xC0 | (src_num << 3) | dst_num;

        if let Some(rex_byte) = rex {
            self.output.push(rex_byte);
        }
        self.output.push(0x89);
        self.output.push(modrm);

        Ok(())
    }

    /// 编码 mov reg, imm
    fn encode_mov_reg_imm(&mut self, dst: &IrRegister, imm: &IrImmediate) -> DisassemblyResult<()> {
        let dst_iced = self.convert_register(dst)?;
        let imm_val = self.immediate_to_u64(imm);

        if dst_iced.is_gpr64() {
            // 64位寄存器
            if imm_val <= u32::MAX as u64 {
                // 可以使用 32位立即数 (零扩展)
                let dst_num = (dst_iced.number() & 7) as u8;
                let is_extended = dst_iced.number() >= 8;
                
                // REX.W + C7 /0 id
                if is_extended {
                    self.output.push(0x49); // REX.W + REX.B
                } else {
                    self.output.push(0x48); // REX.W
                }
                self.output.push(0xC7);
                self.output.push(0xC0 | dst_num);
                self.output.extend_from_slice(&(imm_val as u32).to_le_bytes());
            } else {
                // 需要 64位立即数 - 使用 MOV r64, imm64
                let dst_num = (dst_iced.number() & 7) as u8;
                let is_extended = dst_iced.number() >= 8;
                
                // REX.W + B8+rd io
                if is_extended {
                    self.output.push(0x49); // REX.W + REX.B
                } else {
                    self.output.push(0x48); // REX.W
                }
                self.output.push(0xB8 | dst_num);
                self.output.extend_from_slice(&imm_val.to_le_bytes());
            }
        } else if dst_iced.is_gpr32() {
            // 32位寄存器
            let dst_num = (dst_iced.number() & 7) as u8;
            let is_extended = dst_iced.number() >= 8;
            
            if is_extended {
                self.output.push(0x41); // REX.B
            }
            self.output.push(0xB8 | dst_num);
            self.output.extend_from_slice(&(imm_val as u32).to_le_bytes());
        } else if dst_iced.is_gpr16() {
            // 16位寄存器
            self.output.push(0x66); // 操作数大小前缀
            let dst_num = (dst_iced.number() & 7) as u8;
            let is_extended = dst_iced.number() >= 8;
            
            if is_extended {
                self.output.push(0x41); // REX.B
            }
            self.output.push(0xB8 | dst_num);
            self.output.extend_from_slice(&(imm_val as u16).to_le_bytes());
        } else if dst_iced.is_gpr8() {
            // 8位寄存器
            let dst_num = (dst_iced.number() & 7) as u8;
            let is_extended = dst_iced.number() >= 8;
            let needs_spl = matches!(dst, IrRegister::Spl | IrRegister::Bpl | IrRegister::Sil | IrRegister::Dil);
            
            if is_extended || needs_spl {
                let mut rex = 0x40;
                if is_extended {
                    rex |= 0x01;
                }
                self.output.push(rex);
            }
            self.output.push(0xB0 | dst_num);
            self.output.push(imm_val as u8);
        } else {
            return Err(DisassemblyError::IrConversionError(
                "Unsupported register for mov imm".to_string()
            ));
        }

        Ok(())
    }

    /// 编码 mov reg, mem
    fn encode_mov_reg_mem(&mut self, dst: &IrRegister, mem: &IrMemoryOperand) -> DisassemblyResult<()> {
        let dst_iced = self.convert_register(dst)?;
        
        // 简化实现 - 仅支持简单基址寻址
        if let Some(base_reg) = &mem.base {
            let base_iced = self.convert_register(base_reg)?;
            
            if dst_iced.is_gpr64() {
                // REX.W + 8B /r
                let dst_num = (dst_iced.number() & 7) as u8;
                let base_num = (base_iced.number() & 7) as u8;
                let dst_extended = dst_iced.number() >= 8;
                let base_extended = base_iced.number() >= 8;
                
                let mut rex = 0x48;
                if dst_extended {
                    rex |= 0x04;
                }
                if base_extended {
                    rex |= 0x01;
                }
                
                self.output.push(rex);
                self.output.push(0x8B);
                
                if mem.displacement == 0 {
                    // [base]
                    let modrm = (dst_num << 3) | base_num;
                    self.output.push(modrm);
                } else if mem.displacement >= -128 && mem.displacement <= 127 {
                    // [base + disp8]
                    let modrm = 0x40 | (dst_num << 3) | base_num;
                    self.output.push(modrm);
                    self.output.push(mem.displacement as i8 as u8);
                } else {
                    // [base + disp32]
                    let modrm = 0x80 | (dst_num << 3) | base_num;
                    self.output.push(modrm);
                    self.output.extend_from_slice(&(mem.displacement as i32).to_le_bytes());
                }
            } else if dst_iced.is_gpr32() {
                // 32-bit: 8B /r
                let dst_num = (dst_iced.number() & 7) as u8;
                let base_num = (base_iced.number() & 7) as u8;
                let dst_extended = dst_iced.number() >= 8;
                let base_extended = base_iced.number() >= 8;
                
                if dst_extended || base_extended {
                    let mut rex = 0x40;
                    if dst_extended {
                        rex |= 0x04;
                    }
                    if base_extended {
                        rex |= 0x01;
                    }
                    self.output.push(rex);
                }
                
                self.output.push(0x8B);
                
                if mem.displacement == 0 {
                    let modrm = (dst_num << 3) | base_num;
                    self.output.push(modrm);
                } else if mem.displacement >= -128 && mem.displacement <= 127 {
                    let modrm = 0x40 | (dst_num << 3) | base_num;
                    self.output.push(modrm);
                    self.output.push(mem.displacement as i8 as u8);
                } else {
                    let modrm = 0x80 | (dst_num << 3) | base_num;
                    self.output.push(modrm);
                    self.output.extend_from_slice(&(mem.displacement as i32).to_le_bytes());
                }
            } else {
                return Err(DisassemblyError::IrConversionError(
                    "Unsupported register size for mov from mem".to_string()
                ));
            }
        } else {
            return Err(DisassemblyError::IrConversionError(
                "Memory operand without base not supported yet".to_string()
            ));
        }

        Ok(())
    }

    /// 编码 mov mem, reg
    fn encode_mov_mem_reg(&mut self, mem: &IrMemoryOperand, src: &IrRegister) -> DisassemblyResult<()> {
        let src_iced = self.convert_register(src)?;
        
        if let Some(base_reg) = &mem.base {
            let base_iced = self.convert_register(base_reg)?;
            
            if src_iced.is_gpr64() {
                // REX.W + 89 /r
                let src_num = (src_iced.number() & 7) as u8;
                let base_num = (base_iced.number() & 7) as u8;
                let src_extended = src_iced.number() >= 8;
                let base_extended = base_iced.number() >= 8;
                
                let mut rex = 0x48;
                if src_extended {
                    rex |= 0x04;
                }
                if base_extended {
                    rex |= 0x01;
                }
                
                self.output.push(rex);
                self.output.push(0x89);
                
                if mem.displacement == 0 {
                    let modrm = (src_num << 3) | base_num;
                    self.output.push(modrm);
                } else if mem.displacement >= -128 && mem.displacement <= 127 {
                    let modrm = 0x40 | (src_num << 3) | base_num;
                    self.output.push(modrm);
                    self.output.push(mem.displacement as i8 as u8);
                } else {
                    let modrm = 0x80 | (src_num << 3) | base_num;
                    self.output.push(modrm);
                    self.output.extend_from_slice(&(mem.displacement as i32).to_le_bytes());
                }
            } else if src_iced.is_gpr32() {
                // 89 /r
                let src_num = (src_iced.number() & 7) as u8;
                let base_num = (base_iced.number() & 7) as u8;
                let src_extended = src_iced.number() >= 8;
                let base_extended = base_iced.number() >= 8;
                
                if src_extended || base_extended {
                    let mut rex = 0x40;
                    if src_extended {
                        rex |= 0x04;
                    }
                    if base_extended {
                        rex |= 0x01;
                    }
                    self.output.push(rex);
                }
                
                self.output.push(0x89);
                
                if mem.displacement == 0 {
                    let modrm = (src_num << 3) | base_num;
                    self.output.push(modrm);
                } else if mem.displacement >= -128 && mem.displacement <= 127 {
                    let modrm = 0x40 | (src_num << 3) | base_num;
                    self.output.push(modrm);
                    self.output.push(mem.displacement as i8 as u8);
                } else {
                    let modrm = 0x80 | (src_num << 3) | base_num;
                    self.output.push(modrm);
                    self.output.extend_from_slice(&(mem.displacement as i32).to_le_bytes());
                }
            } else {
                return Err(DisassemblyError::IrConversionError(
                    "Unsupported register size for mov to mem".to_string()
                ));
            }
        } else {
            return Err(DisassemblyError::IrConversionError(
                "Memory operand without base not supported yet".to_string()
            ));
        }

        Ok(())
    }

    /// 编码 mov mem, imm
    fn encode_mov_mem_imm(&mut self, mem: &IrMemoryOperand, imm: &IrImmediate) -> DisassemblyResult<()> {
        let imm_val = self.immediate_to_u64(imm);
        
        if let Some(base_reg) = &mem.base {
            let base_iced = self.convert_register(base_reg)?;
            let base_num = (base_iced.number() & 7) as u8;
            let base_extended = base_iced.number() >= 8;
            
            match mem.size_bits {
                32 => {
                    // C7 /0 id
                    if base_extended {
                        self.output.push(0x41); // REX.B
                    }
                    self.output.push(0xC7);
                    
                    if mem.displacement == 0 {
                        self.output.push(0x00 | base_num);
                    } else if mem.displacement >= -128 && mem.displacement <= 127 {
                        self.output.push(0x40 | base_num);
                        self.output.push(mem.displacement as i8 as u8);
                    } else {
                        self.output.push(0x80 | base_num);
                        self.output.extend_from_slice(&(mem.displacement as i32).to_le_bytes());
                    }
                    
                    self.output.extend_from_slice(&(imm_val as u32).to_le_bytes());
                }
                64 => {
                    // REX.W + C7 /0 id (符号扩展)
                    let mut rex = 0x48;
                    if base_extended {
                        rex |= 0x01;
                    }
                    self.output.push(rex);
                    self.output.push(0xC7);
                    
                    if mem.displacement == 0 {
                        self.output.push(0x00 | base_num);
                    } else if mem.displacement >= -128 && mem.displacement <= 127 {
                        self.output.push(0x40 | base_num);
                        self.output.push(mem.displacement as i8 as u8);
                    } else {
                        self.output.push(0x80 | base_num);
                        self.output.extend_from_slice(&(mem.displacement as i32).to_le_bytes());
                    }
                    
                    self.output.extend_from_slice(&(imm_val as u32).to_le_bytes());
                }
                _ => {
                    return Err(DisassemblyError::IrConversionError(
                        "Unsupported memory size for mov imm".to_string()
                    ));
                }
            }
        } else {
            return Err(DisassemblyError::IrConversionError(
                "Memory operand without base not supported yet".to_string()
            ));
        }

        Ok(())
    }

    /// 编码 push 指令
    fn encode_push(&mut self, src: &IrOperand) -> DisassemblyResult<()> {
        match src {
            IrOperand::Register(reg) => {
                let iced_reg = self.convert_register(reg)?;
                
                if iced_reg.is_gpr64() {
                    let reg_num = (iced_reg.number() & 7) as u8;
                    let is_extended = iced_reg.number() >= 8;
                    
                    if is_extended {
                        // REX.B + 50+rd
                        self.output.push(0x41);
                        self.output.push(0x50 | reg_num);
                    } else {
                        // 50+rd
                        self.output.push(0x50 | reg_num);
                    }
                } else if iced_reg.is_gpr16() {
                    // 66 50+rw
                    self.output.push(0x66);
                    let reg_num = (iced_reg.number() & 7) as u8;
                    let is_extended = iced_reg.number() >= 8;
                    
                    if is_extended {
                        self.output.push(0x41);
                    }
                    self.output.push(0x50 | reg_num);
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Unsupported register for push".to_string()
                    ));
                }
            }
            IrOperand::Immediate(imm) => {
                let imm_val = self.immediate_to_i64(imm);
                
                if imm_val >= -128 && imm_val <= 127 {
                    // 6A ib
                    self.output.push(0x6A);
                    self.output.push(imm_val as i8 as u8);
                } else if imm_val >= i32::MIN as i64 && imm_val <= i32::MAX as i64 {
                    // 68 id
                    self.output.push(0x68);
                    self.output.extend_from_slice(&(imm_val as i32).to_le_bytes());
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Push immediate too large".to_string()
                    ));
                }
            }
            IrOperand::Memory(mem) => {
                if let Some(base_reg) = &mem.base {
                    let base_iced = self.convert_register(base_reg)?;
                    let base_num = (base_iced.number() & 7) as u8;
                    let base_extended = base_iced.number() >= 8;
                    
                    // FF /6
                    if base_extended {
                        self.output.push(0x41);
                    }
                    self.output.push(0xFF);
                    
                    if mem.displacement == 0 {
                        self.output.push(0x30 | base_num);
                    } else if mem.displacement >= -128 && mem.displacement <= 127 {
                        self.output.push(0x70 | base_num);
                        self.output.push(mem.displacement as i8 as u8);
                    } else {
                        self.output.push(0xB0 | base_num);
                        self.output.extend_from_slice(&(mem.displacement as i32).to_le_bytes());
                    }
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Push memory without base not supported".to_string()
                    ));
                }
            }
        }

        Ok(())
    }

    /// 编码 pop 指令
    fn encode_pop(&mut self, dst: &IrOperand) -> DisassemblyResult<()> {
        match dst {
            IrOperand::Register(reg) => {
                let iced_reg = self.convert_register(reg)?;
                
                if iced_reg.is_gpr64() {
                    let reg_num = (iced_reg.number() & 7) as u8;
                    let is_extended = iced_reg.number() >= 8;
                    
                    if is_extended {
                        self.output.push(0x41);
                        self.output.push(0x58 | reg_num);
                    } else {
                        self.output.push(0x58 | reg_num);
                    }
                } else if iced_reg.is_gpr16() {
                    self.output.push(0x66);
                    let reg_num = (iced_reg.number() & 7) as u8;
                    let is_extended = iced_reg.number() >= 8;
                    
                    if is_extended {
                        self.output.push(0x41);
                    }
                    self.output.push(0x58 | reg_num);
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Unsupported register for pop".to_string()
                    ));
                }
            }
            IrOperand::Memory(mem) => {
                if let Some(base_reg) = &mem.base {
                    let base_iced = self.convert_register(base_reg)?;
                    let base_num = (base_iced.number() & 7) as u8;
                    let base_extended = base_iced.number() >= 8;
                    
                    if base_extended {
                        self.output.push(0x41);
                    }
                    self.output.push(0x8F);
                    
                    if mem.displacement == 0 {
                        self.output.push(0x00 | base_num);
                    } else if mem.displacement >= -128 && mem.displacement <= 127 {
                        self.output.push(0x40 | base_num);
                        self.output.push(mem.displacement as i8 as u8);
                    } else {
                        self.output.push(0x80 | base_num);
                        self.output.extend_from_slice(&(mem.displacement as i32).to_le_bytes());
                    }
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Pop memory without base not supported".to_string()
                    ));
                }
            }
            _ => return Err(DisassemblyError::IrConversionError(
                "Unsupported pop operand".to_string()
            )),
        }

        Ok(())
    }

    /// 编码 lea 指令
    fn encode_lea(&mut self, dst: &IrRegister, src: &IrMemoryOperand) -> DisassemblyResult<()> {
        let dst_iced = self.convert_register(dst)?;
        
        if !dst_iced.is_gpr64() && !dst_iced.is_gpr32() {
            return Err(DisassemblyError::IrConversionError(
                "Lea destination must be a general purpose register".to_string()
            ));
        }

        if let Some(base_reg) = &src.base {
            let base_iced = self.convert_register(base_reg)?;
            let dst_num = (dst_iced.number() & 7) as u8;
            let base_num = (base_iced.number() & 7) as u8;
            let dst_extended = dst_iced.number() >= 8;
            let base_extended = base_iced.number() >= 8;

            if dst_iced.is_gpr64() {
                // REX.W + 8D /r
                let mut rex = 0x48;
                if dst_extended {
                    rex |= 0x04;
                }
                if base_extended {
                    rex |= 0x01;
                }
                self.output.push(rex);
            } else {
                // 8D /r
                if dst_extended || base_extended {
                    let mut rex = 0x40;
                    if dst_extended {
                        rex |= 0x04;
                    }
                    if base_extended {
                        rex |= 0x01;
                    }
                    self.output.push(rex);
                }
            }

            self.output.push(0x8D);

            if src.displacement == 0 {
                let modrm = (dst_num << 3) | base_num;
                self.output.push(modrm);
            } else if src.displacement >= -128 && src.displacement <= 127 {
                let modrm = 0x40 | (dst_num << 3) | base_num;
                self.output.push(modrm);
                self.output.push(src.displacement as i8 as u8);
            } else {
                let modrm = 0x80 | (dst_num << 3) | base_num;
                self.output.push(modrm);
                self.output.extend_from_slice(&(src.displacement as i32).to_le_bytes());
            }
        } else {
            return Err(DisassemblyError::IrConversionError(
                "Lea without base not supported yet".to_string()
            ));
        }

        Ok(())
    }

    /// 编码 xchg 指令
    fn encode_xchg(&mut self, op1: &IrOperand, op2: &IrOperand) -> DisassemblyResult<()> {
        match (op1, op2) {
            (IrOperand::Register(reg1), IrOperand::Register(reg2)) => {
                let r1 = self.convert_register(reg1)?;
                let r2 = self.convert_register(reg2)?;

                if r1.is_gpr64() && r2.is_gpr64() {
                    // REX.W + 87 /r
                    let r1_num = (r1.number() & 7) as u8;
                    let r2_num = (r2.number() & 7) as u8;
                    let r1_extended = r1.number() >= 8;
                    let r2_extended = r2.number() >= 8;

                    let mut rex = 0x48;
                    if r1_extended {
                        rex |= 0x04;
                    }
                    if r2_extended {
                        rex |= 0x01;
                    }
                    self.output.push(rex);
                    self.output.push(0x87);
                    self.output.push(0xC0 | (r1_num << 3) | r2_num);
                } else if r1.is_gpr32() && r2.is_gpr32() {
                    let r1_num = (r1.number() & 7) as u8;
                    let r2_num = (r2.number() & 7) as u8;
                    let r1_extended = r1.number() >= 8;
                    let r2_extended = r2.number() >= 8;

                    if r1_extended || r2_extended {
                        let mut rex = 0x40;
                        if r1_extended {
                            rex |= 0x04;
                        }
                        if r2_extended {
                            rex |= 0x01;
                        }
                        self.output.push(rex);
                    }
                    self.output.push(0x87);
                    self.output.push(0xC0 | (r1_num << 3) | r2_num);
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Unsupported xchg registers".to_string()
                    ));
                }
            }
            _ => return Err(DisassemblyError::IrConversionError(
                "Unsupported xchg operands".to_string()
            )),
        }

        Ok(())
    }

    /// 编码 cmov 指令
    fn encode_cmov(&mut self, condition: IrCondition, dst: &IrRegister, src: &IrOperand) -> DisassemblyResult<()> {
        let dst_iced = self.convert_register(dst)?;
        
        if !dst_iced.is_gpr64() && !dst_iced.is_gpr32() {
            return Err(DisassemblyError::IrConversionError(
                "Cmov destination must be a general purpose register".to_string()
            ));
        }

        let dst_num = (dst_iced.number() & 7) as u8;
        let dst_extended = dst_iced.number() >= 8;

        // 条件码到操作码的映射 (0F 40+cc /r for 32-bit, 0F 40+cc /r with REX.W for 64-bit)
        let cc = match condition {
            IrCondition::E => 0x44,   // cmove/cmova
            IrCondition::Ne => 0x45,  // cmovne/cmovnz
            IrCondition::G => 0x4F,   // cmovg
            IrCondition::Ge => 0x4D,  // cmovge
            IrCondition::L => 0x4C,   // cmovl
            IrCondition::Le => 0x4E,  // cmovle
            IrCondition::A => 0x47,   // cmova
            IrCondition::Ae => 0x43,  // cmovae
            IrCondition::B => 0x42,   // cmovb
            IrCondition::Be => 0x46,  // cmovbe
            IrCondition::O => 0x40,   // cmovo
            IrCondition::No => 0x41,  // cmovno
            IrCondition::S => 0x48,   // cmovs
            IrCondition::Ns => 0x49,  // cmovns
            IrCondition::P => 0x4A,   // cmovp
            IrCondition::Np => 0x4B,  // cmovnp
            _ => return Err(DisassemblyError::IrConversionError("Unsupported cmov condition".to_string())),
        };

        match src {
            IrOperand::Register(src_reg) => {
                let src_iced = self.convert_register(src_reg)?;
                let src_num = (src_iced.number() & 7) as u8;
                let src_extended = src_iced.number() >= 8;

                if dst_iced.is_gpr64() {
                    let mut rex = 0x48;
                    if dst_extended {
                        rex |= 0x04;
                    }
                    if src_extended {
                        rex |= 0x01;
                    }
                    self.output.push(rex);
                } else {
                    if dst_extended || src_extended {
                        let mut rex = 0x40;
                        if dst_extended {
                            rex |= 0x04;
                        }
                        if src_extended {
                            rex |= 0x01;
                        }
                        self.output.push(rex);
                    }
                }

                self.output.push(0x0F);
                self.output.push(cc);
                self.output.push(0xC0 | (dst_num << 3) | src_num);
            }
            IrOperand::Memory(mem) => {
                if let Some(base_reg) = &mem.base {
                    let base_iced = self.convert_register(base_reg)?;
                    let base_num = (base_iced.number() & 7) as u8;
                    let base_extended = base_iced.number() >= 8;

                    if dst_iced.is_gpr64() {
                        let mut rex = 0x48;
                        if dst_extended {
                            rex |= 0x04;
                        }
                        if base_extended {
                            rex |= 0x01;
                        }
                        self.output.push(rex);
                    } else {
                        if dst_extended || base_extended {
                            let mut rex = 0x40;
                            if dst_extended {
                                rex |= 0x04;
                            }
                            if base_extended {
                                rex |= 0x01;
                            }
                            self.output.push(rex);
                        }
                    }

                    self.output.push(0x0F);
                    self.output.push(cc);

                    if mem.displacement == 0 {
                        self.output.push((dst_num << 3) | base_num);
                    } else if mem.displacement >= -128 && mem.displacement <= 127 {
                        self.output.push(0x40 | (dst_num << 3) | base_num);
                        self.output.push(mem.displacement as i8 as u8);
                    } else {
                        self.output.push(0x80 | (dst_num << 3) | base_num);
                        self.output.extend_from_slice(&(mem.displacement as i32).to_le_bytes());
                    }
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Cmov from memory without base not supported".to_string()
                    ));
                }
            }
            _ => return Err(DisassemblyError::IrConversionError("Unsupported cmov source".to_string())),
        }

        Ok(())
    }

    /// 编码 add 指令
    fn encode_add(&mut self, dst: &IrOperand, src: &IrOperand) -> DisassemblyResult<()> {
        self.encode_alu(dst, src, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x80, 0x81, 0x83, 0)
    }

    /// 编码 sub 指令
    fn encode_sub(&mut self, dst: &IrOperand, src: &IrOperand) -> DisassemblyResult<()> {
        self.encode_alu(dst, src, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x80, 0x81, 0x83, 5)
    }

    /// 编码 and 指令
    fn encode_and(&mut self, dst: &IrOperand, src: &IrOperand) -> DisassemblyResult<()> {
        self.encode_alu(dst, src, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x80, 0x81, 0x83, 4)
    }

    /// 编码 or 指令
    fn encode_or(&mut self, dst: &IrOperand, src: &IrOperand) -> DisassemblyResult<()> {
        self.encode_alu(dst, src, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x80, 0x81, 0x83, 1)
    }

    /// 编码 xor 指令
    fn encode_xor(&mut self, dst: &IrOperand, src: &IrOperand) -> DisassemblyResult<()> {
        self.encode_alu(dst, src, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x80, 0x81, 0x83, 6)
    }

    /// 编码 cmp 指令
    fn encode_cmp(&mut self, op1: &IrOperand, op2: &IrOperand) -> DisassemblyResult<()> {
        self.encode_alu(op1, op2, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x80, 0x81, 0x83, 7)
    }

    /// 通用 ALU 指令编码
    fn encode_alu(
        &mut self,
        dst: &IrOperand,
        src: &IrOperand,
        rm8_r8: u8, rm_r: u8, r_rm8: u8, r_rm: u8,
        al_imm8: u8, ax_imm: u8,
        rm8_imm8_op: u8, rm_imm_op: u8, rm_imm8_op: u8,
        ext_op: u8,
    ) -> DisassemblyResult<()> {
        match (dst, src) {
            // reg, reg
            (IrOperand::Register(dst_reg), IrOperand::Register(src_reg)) => {
                let dst_iced = self.convert_register(dst_reg)?;
                let src_iced = self.convert_register(src_reg)?;

                if dst_iced.is_gpr8() && src_iced.is_gpr8() {
                    let dst_num = (dst_iced.number() & 7) as u8;
                    let src_num = (src_iced.number() & 7) as u8;
                    let dst_extended = dst_iced.number() >= 8;
                    let src_extended = src_iced.number() >= 8;
                    let needs_spl = matches!(dst_reg, IrRegister::Spl | IrRegister::Bpl | IrRegister::Sil | IrRegister::Dil);

                    if dst_extended || src_extended || needs_spl {
                        let mut rex = 0x40;
                        if dst_extended {
                            rex |= 0x04;
                        }
                        if src_extended {
                            rex |= 0x01;
                        }
                        self.output.push(rex);
                    }
                    self.output.push(rm8_r8);
                    self.output.push(0xC0 | (src_num << 3) | dst_num);
                } else if dst_iced.is_gpr64() && src_iced.is_gpr64() {
                    let dst_num = (dst_iced.number() & 7) as u8;
                    let src_num = (src_iced.number() & 7) as u8;
                    let dst_extended = dst_iced.number() >= 8;
                    let src_extended = src_iced.number() >= 8;

                    let mut rex = 0x48;
                    if dst_extended {
                        rex |= 0x01;
                    }
                    if src_extended {
                        rex |= 0x04;
                    }
                    self.output.push(rex);
                    self.output.push(rm_r);
                    self.output.push(0xC0 | (src_num << 3) | dst_num);
                } else if dst_iced.is_gpr32() && src_iced.is_gpr32() {
                    let dst_num = (dst_iced.number() & 7) as u8;
                    let src_num = (src_iced.number() & 7) as u8;
                    let dst_extended = dst_iced.number() >= 8;
                    let src_extended = src_iced.number() >= 8;

                    if dst_extended || src_extended {
                        let mut rex = 0x40;
                        if dst_extended {
                            rex |= 0x01;
                        }
                        if src_extended {
                            rex |= 0x04;
                        }
                        self.output.push(rex);
                    }
                    self.output.push(rm_r);
                    self.output.push(0xC0 | (src_num << 3) | dst_num);
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "ALU register size mismatch".to_string()
                    ));
                }
            }
            // reg, imm
            (IrOperand::Register(dst_reg), IrOperand::Immediate(imm)) => {
                let dst_iced = self.convert_register(dst_reg)?;
                let imm_val = self.immediate_to_i64(imm);
                let dst_num = (dst_iced.number() & 7) as u8;
                let dst_extended = dst_iced.number() >= 8;

                if dst_iced.is_gpr64() {
                    if imm_val >= -128 && imm_val <= 127 {
                        // REX.W + 83 /ext id
                        let mut rex = 0x48;
                        if dst_extended {
                            rex |= 0x01;
                        }
                        self.output.push(rex);
                        self.output.push(rm_imm8_op);
                        self.output.push(0xC0 | (ext_op << 3) | dst_num);
                        self.output.push(imm_val as i8 as u8);
                    } else {
                        // REX.W + 81 /ext id
                        let mut rex = 0x48;
                        if dst_extended {
                            rex |= 0x01;
                        }
                        self.output.push(rex);
                        self.output.push(rm_imm_op);
                        self.output.push(0xC0 | (ext_op << 3) | dst_num);
                        self.output.extend_from_slice(&(imm_val as i32).to_le_bytes());
                    }
                } else if dst_iced.is_gpr32() {
                    if imm_val >= -128 && imm_val <= 127 {
                        if dst_extended {
                            self.output.push(0x41);
                        }
                        self.output.push(rm_imm8_op);
                        self.output.push(0xC0 | (ext_op << 3) | dst_num);
                        self.output.push(imm_val as i8 as u8);
                    } else {
                        if dst_extended {
                            self.output.push(0x41);
                        }
                        self.output.push(rm_imm_op);
                        self.output.push(0xC0 | (ext_op << 3) | dst_num);
                        self.output.extend_from_slice(&(imm_val as i32).to_le_bytes());
                    }
                } else if dst_iced.is_gpr8() {
                    let needs_spl = matches!(dst_reg, IrRegister::Spl | IrRegister::Bpl | IrRegister::Sil | IrRegister::Dil);
                    if dst_extended || needs_spl {
                        let mut rex = 0x40;
                        if dst_extended {
                            rex |= 0x04;
                        }
                        self.output.push(rex);
                    }
                    self.output.push(rm8_imm8_op);
                    self.output.push(0xC0 | (ext_op << 3) | dst_num);
                    self.output.push(imm_val as u8);
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Unsupported register for ALU imm".to_string()
                    ));
                }
            }
            // reg, mem
            (IrOperand::Register(dst_reg), IrOperand::Memory(mem)) => {
                let dst_iced = self.convert_register(dst_reg)?;
                
                if let Some(base_reg) = &mem.base {
                    let base_iced = self.convert_register(base_reg)?;
                    let dst_num = (dst_iced.number() & 7) as u8;
                    let base_num = (base_iced.number() & 7) as u8;
                    let dst_extended = dst_iced.number() >= 8;
                    let base_extended = base_iced.number() >= 8;

                    if dst_iced.is_gpr64() {
                        let mut rex = 0x48;
                        if dst_extended {
                            rex |= 0x04;
                        }
                        if base_extended {
                            rex |= 0x01;
                        }
                        self.output.push(rex);
                        self.output.push(r_rm);
                    } else if dst_iced.is_gpr32() {
                        if dst_extended || base_extended {
                            let mut rex = 0x40;
                            if dst_extended {
                                rex |= 0x04;
                            }
                            if base_extended {
                                rex |= 0x01;
                            }
                            self.output.push(rex);
                        }
                        self.output.push(r_rm);
                    } else if dst_iced.is_gpr8() {
                        let needs_spl = matches!(dst_reg, IrRegister::Spl | IrRegister::Bpl | IrRegister::Sil | IrRegister::Dil);
                        if dst_extended || base_extended || needs_spl {
                            let mut rex = 0x40;
                            if dst_extended {
                                rex |= 0x04;
                            }
                            if base_extended {
                                rex |= 0x01;
                            }
                            self.output.push(rex);
                        }
                        self.output.push(r_rm8);
                    } else {
                        return Err(DisassemblyError::IrConversionError(
                            "Unsupported register size".to_string()
                        ));
                    }

                    if mem.displacement == 0 {
                        self.output.push((dst_num << 3) | base_num);
                    } else if mem.displacement >= -128 && mem.displacement <= 127 {
                        self.output.push(0x40 | (dst_num << 3) | base_num);
                        self.output.push(mem.displacement as i8 as u8);
                    } else {
                        self.output.push(0x80 | (dst_num << 3) | base_num);
                        self.output.extend_from_slice(&(mem.displacement as i32).to_le_bytes());
                    }
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Memory without base not supported".to_string()
                    ));
                }
            }
            // mem, reg
            (IrOperand::Memory(mem), IrOperand::Register(src_reg)) => {
                let src_iced = self.convert_register(src_reg)?;
                
                if let Some(base_reg) = &mem.base {
                    let base_iced = self.convert_register(base_reg)?;
                    let src_num = (src_iced.number() & 7) as u8;
                    let base_num = (base_iced.number() & 7) as u8;
                    let src_extended = src_iced.number() >= 8;
                    let base_extended = base_iced.number() >= 8;

                    if src_iced.is_gpr64() {
                        let mut rex = 0x48;
                        if src_extended {
                            rex |= 0x04;
                        }
                        if base_extended {
                            rex |= 0x01;
                        }
                        self.output.push(rex);
                        self.output.push(rm_r);
                    } else if src_iced.is_gpr32() {
                        if src_extended || base_extended {
                            let mut rex = 0x40;
                            if src_extended {
                                rex |= 0x04;
                            }
                            if base_extended {
                                rex |= 0x01;
                            }
                            self.output.push(rex);
                        }
                        self.output.push(rm_r);
                    } else if src_iced.is_gpr8() {
                        if src_extended || base_extended {
                            let mut rex = 0x40;
                            if src_extended {
                                rex |= 0x04;
                            }
                            if base_extended {
                                rex |= 0x01;
                            }
                            self.output.push(rex);
                        }
                        self.output.push(rm8_r8);
                    } else {
                        return Err(DisassemblyError::IrConversionError(
                            "Unsupported register size".to_string()
                        ));
                    }

                    if mem.displacement == 0 {
                        self.output.push((src_num << 3) | base_num);
                    } else if mem.displacement >= -128 && mem.displacement <= 127 {
                        self.output.push(0x40 | (src_num << 3) | base_num);
                        self.output.push(mem.displacement as i8 as u8);
                    } else {
                        self.output.push(0x80 | (src_num << 3) | base_num);
                        self.output.extend_from_slice(&(mem.displacement as i32).to_le_bytes());
                    }
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Memory without base not supported".to_string()
                    ));
                }
            }
            // mem, imm
            (IrOperand::Memory(mem), IrOperand::Immediate(imm)) => {
                let imm_val = self.immediate_to_i64(imm);
                
                if let Some(base_reg) = &mem.base {
                    let base_iced = self.convert_register(base_reg)?;
                    let base_num = (base_iced.number() & 7) as u8;
                    let base_extended = base_iced.number() >= 8;

                    match mem.size_bits {
                        64 => {
                            if imm_val >= -128 && imm_val <= 127 {
                                let mut rex = 0x48;
                                if base_extended {
                                    rex |= 0x01;
                                }
                                self.output.push(rex);
                                self.output.push(rm_imm8_op);
                            } else {
                                let mut rex = 0x48;
                                if base_extended {
                                    rex |= 0x01;
                                }
                                self.output.push(rex);
                                self.output.push(rm_imm_op);
                            }
                        }
                        32 => {
                            if base_extended {
                                self.output.push(0x41);
                            }
                            if imm_val >= -128 && imm_val <= 127 {
                                self.output.push(rm_imm8_op);
                            } else {
                                self.output.push(rm_imm_op);
                            }
                        }
                        8 => {
                            if base_extended {
                                self.output.push(0x41);
                            }
                            self.output.push(rm8_imm8_op);
                        }
                        _ => return Err(DisassemblyError::IrConversionError(
                            "Unsupported memory size".to_string()
                        )),
                    }

                    if mem.displacement == 0 {
                        self.output.push((ext_op << 3) | base_num);
                    } else if mem.displacement >= -128 && mem.displacement <= 127 {
                        self.output.push(0x40 | (ext_op << 3) | base_num);
                        self.output.push(mem.displacement as i8 as u8);
                    } else {
                        self.output.push(0x80 | (ext_op << 3) | base_num);
                        self.output.extend_from_slice(&(mem.displacement as i32).to_le_bytes());
                    }

                    if imm_val >= -128 && imm_val <= 127 {
                        self.output.push(imm_val as i8 as u8);
                    } else {
                        self.output.extend_from_slice(&(imm_val as i32).to_le_bytes());
                    }
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Memory without base not supported".to_string()
                    ));
                }
            }
            _ => return Err(DisassemblyError::IrConversionError(
                "Unsupported ALU operand combination".to_string()
            )),
        }

        Ok(())
    }

    /// 编码 inc 指令
    fn encode_inc(&mut self, op: &IrOperand) -> DisassemblyResult<()> {
        self.encode_inc_dec_neg(op, 0xFF, 0x40, 0)
    }

    /// 编码 dec 指令
    fn encode_dec(&mut self, op: &IrOperand) -> DisassemblyResult<()> {
        self.encode_inc_dec_neg(op, 0xFF, 0x48, 1)
    }

    /// 编码 neg 指令
    fn encode_neg(&mut self, op: &IrOperand) -> DisassemblyResult<()> {
        self.encode_inc_dec_neg(op, 0xF6, 0xF7, 3)
    }

    /// 编码 not 指令
    fn encode_not(&mut self, op: &IrOperand) -> DisassemblyResult<()> {
        self.encode_inc_dec_neg(op, 0xF6, 0xF7, 2)
    }

    /// 通用 inc/dec/neg/not 指令编码
    fn encode_inc_dec_neg(&mut self, op: &IrOperand, op8: u8, op_sized: u8, ext: u8) -> DisassemblyResult<()> {
        match op {
            IrOperand::Register(reg) => {
                let iced_reg = self.convert_register(reg)?;
                let reg_num = (iced_reg.number() & 7) as u8;
                let reg_extended = iced_reg.number() >= 8;

                if iced_reg.is_gpr8() {
                    let needs_spl = matches!(reg, IrRegister::Spl | IrRegister::Bpl | IrRegister::Sil | IrRegister::Dil);
                    if reg_extended || needs_spl {
                        let mut rex = 0x40;
                        if reg_extended {
                            rex |= 0x04;
                        }
                        self.output.push(rex);
                    }
                    self.output.push(op8);
                    self.output.push(0xC0 | (ext << 3) | reg_num);
                } else if iced_reg.is_gpr64() {
                    let mut rex = 0x48;
                    if reg_extended {
                        rex |= 0x01;
                    }
                    self.output.push(rex);
                    self.output.push(op_sized);
                    self.output.push(0xC0 | (ext << 3) | reg_num);
                } else if iced_reg.is_gpr32() {
                    if reg_extended {
                        self.output.push(0x41);
                    }
                    self.output.push(op_sized);
                    self.output.push(0xC0 | (ext << 3) | reg_num);
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Unsupported register for inc/dec/neg/not".to_string()
                    ));
                }
            }
            IrOperand::Memory(mem) => {
                if let Some(base_reg) = &mem.base {
                    let base_iced = self.convert_register(base_reg)?;
                    let base_num = (base_iced.number() & 7) as u8;
                    let base_extended = base_iced.number() >= 8;

                    match mem.size_bits {
                        8 => {
                            if base_extended {
                                self.output.push(0x41);
                            }
                            self.output.push(op8);
                        }
                        64 => {
                            let mut rex = 0x48;
                            if base_extended {
                                rex |= 0x01;
                            }
                            self.output.push(rex);
                            self.output.push(op_sized);
                        }
                        32 => {
                            if base_extended {
                                self.output.push(0x41);
                            }
                            self.output.push(op_sized);
                        }
                        _ => return Err(DisassemblyError::IrConversionError(
                            "Unsupported memory size".to_string()
                        )),
                    }

                    if mem.displacement == 0 {
                        self.output.push((ext << 3) | base_num);
                    } else if mem.displacement >= -128 && mem.displacement <= 127 {
                        self.output.push(0x40 | (ext << 3) | base_num);
                        self.output.push(mem.displacement as i8 as u8);
                    } else {
                        self.output.push(0x80 | (ext << 3) | base_num);
                        self.output.extend_from_slice(&(mem.displacement as i32).to_le_bytes());
                    }
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Memory without base not supported".to_string()
                    ));
                }
            }
            _ => return Err(DisassemblyError::IrConversionError(
                "Unsupported operand for inc/dec/neg/not".to_string()
            )),
        }

        Ok(())
    }

    /// 编码 test 指令
    fn encode_test(&mut self, op1: &IrOperand, op2: &IrOperand) -> DisassemblyResult<()> {
        // test 使用与 ALU 类似的编码，但操作码不同
        match (op1, op2) {
            (IrOperand::Register(dst_reg), IrOperand::Register(src_reg)) => {
                let dst_iced = self.convert_register(dst_reg)?;
                let src_iced = self.convert_register(src_reg)?;

                if dst_iced.is_gpr64() && src_iced.is_gpr64() {
                    let dst_num = (dst_iced.number() & 7) as u8;
                    let src_num = (src_iced.number() & 7) as u8;
                    let dst_extended = dst_iced.number() >= 8;
                    let src_extended = src_iced.number() >= 8;

                    let mut rex = 0x48;
                    if dst_extended {
                        rex |= 0x01;
                    }
                    if src_extended {
                        rex |= 0x04;
                    }
                    self.output.push(rex);
                    self.output.push(0x85);
                    self.output.push(0xC0 | (src_num << 3) | dst_num);
                } else if dst_iced.is_gpr32() && src_iced.is_gpr32() {
                    let dst_num = (dst_iced.number() & 7) as u8;
                    let src_num = (src_iced.number() & 7) as u8;
                    let dst_extended = dst_iced.number() >= 8;
                    let src_extended = src_iced.number() >= 8;

                    if dst_extended || src_extended {
                        let mut rex = 0x40;
                        if dst_extended {
                            rex |= 0x01;
                        }
                        if src_extended {
                            rex |= 0x04;
                        }
                        self.output.push(rex);
                    }
                    self.output.push(0x85);
                    self.output.push(0xC0 | (src_num << 3) | dst_num);
                } else if dst_iced.is_gpr8() && src_iced.is_gpr8() {
                    let dst_num = (dst_iced.number() & 7) as u8;
                    let src_num = (src_iced.number() & 7) as u8;
                    let dst_extended = dst_iced.number() >= 8;
                    let src_extended = src_iced.number() >= 8;
                    let needs_spl = matches!(dst_reg, IrRegister::Spl | IrRegister::Bpl | IrRegister::Sil | IrRegister::Dil);

                    if dst_extended || src_extended || needs_spl {
                        let mut rex = 0x40;
                        if dst_extended {
                            rex |= 0x04;
                        }
                        if src_extended {
                            rex |= 0x01;
                        }
                        self.output.push(rex);
                    }
                    self.output.push(0x84);
                    self.output.push(0xC0 | (src_num << 3) | dst_num);
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Test register size mismatch".to_string()
                    ));
                }
            }
            (IrOperand::Register(dst_reg), IrOperand::Immediate(imm)) => {
                let dst_iced = self.convert_register(dst_reg)?;
                let imm_val = self.immediate_to_u64(imm);
                let dst_num = (dst_iced.number() & 7) as u8;
                let dst_extended = dst_iced.number() >= 8;

                if dst_iced.is_gpr64() {
                    let mut rex = 0x48;
                    if dst_extended {
                        rex |= 0x01;
                    }
                    self.output.push(rex);
                    self.output.push(0xF7);
                    self.output.push(0xC0 | dst_num);
                    self.output.extend_from_slice(&(imm_val as u32).to_le_bytes());
                } else if dst_iced.is_gpr32() {
                    if dst_extended {
                        self.output.push(0x41);
                    }
                    self.output.push(0xF7);
                    self.output.push(0xC0 | dst_num);
                    self.output.extend_from_slice(&(imm_val as u32).to_le_bytes());
                } else if dst_iced.is_gpr8() {
                    let needs_spl = matches!(dst_reg, IrRegister::Spl | IrRegister::Bpl | IrRegister::Sil | IrRegister::Dil);
                    if dst_extended || needs_spl {
                        let mut rex = 0x40;
                        if dst_extended {
                            rex |= 0x04;
                        }
                        self.output.push(rex);
                    }
                    self.output.push(0xF6);
                    self.output.push(0xC0 | dst_num);
                    self.output.push(imm_val as u8);
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Unsupported register for test".to_string()
                    ));
                }
            }
            _ => return Err(DisassemblyError::IrConversionError(
                "Unsupported test operands".to_string()
            )),
        }

        Ok(())
    }

    /// 编码 mul 指令
    fn encode_mul(&mut self, src: &IrOperand) -> DisassemblyResult<()> {
        self.encode_mul_div(src, 0xF6, 0xF7, 4)
    }

    /// 编码 imul 指令
    fn encode_imul(&mut self, dst: Option<&IrOperand>, src1: &IrOperand, src2: Option<&IrOperand>) -> DisassemblyResult<()> {
        use iced_x86::Instruction;

        match (dst, src2) {
            // 单操作数形式
            (None, None) => {
                self.encode_mul_div(src1, 0xF6, 0xF7, 5)
            }
            // 双操作数形式
            (Some(dst), None) => {
                match (dst, src1) {
                    (IrOperand::Register(dst_reg), IrOperand::Register(src_reg)) => {
                        let dst_iced = self.convert_register(dst_reg)?;
                        let src_iced = self.convert_register(src_reg)?;
                        
                        let dst_num = (dst_iced.number() & 7) as u8;
                        let src_num = (src_iced.number() & 7) as u8;
                        let dst_extended = dst_iced.number() >= 8;
                        let src_extended = src_iced.number() >= 8;

                        if dst_iced.is_gpr64() {
                            let mut rex = 0x48;
                            if dst_extended {
                                rex |= 0x04;
                            }
                            if src_extended {
                                rex |= 0x01;
                            }
                            self.output.push(rex);
                            self.output.push(0x0F);
                            self.output.push(0xAF);
                            self.output.push(0xC0 | (dst_num << 3) | src_num);
                        } else if dst_iced.is_gpr32() {
                            if dst_extended || src_extended {
                                let mut rex = 0x40;
                                if dst_extended {
                                    rex |= 0x04;
                                }
                                if src_extended {
                                    rex |= 0x01;
                                }
                                self.output.push(rex);
                            }
                            self.output.push(0x0F);
                            self.output.push(0xAF);
                            self.output.push(0xC0 | (dst_num << 3) | src_num);
                        } else {
                            return Err(DisassemblyError::IrConversionError(
                                "Unsupported register size for imul".to_string()
                            ));
                        }
                        Ok(())
                    }
                    _ => Err(DisassemblyError::IrConversionError(
                        "Unsupported imul operands".to_string()
                    )),
                }
            }
            // 三操作数形式
            (Some(dst), Some(src2_imm)) => {
                match (dst, src1, src2_imm) {
                    (IrOperand::Register(dst_reg), IrOperand::Register(src_reg), IrOperand::Immediate(imm)) => {
                        let dst_iced = self.convert_register(dst_reg)?;
                        let src_iced = self.convert_register(src_reg)?;
                        let imm_val = self.immediate_to_i64(imm);
                        
                        let dst_num = (dst_iced.number() & 7) as u8;
                        let src_num = (src_iced.number() & 7) as u8;
                        let dst_extended = dst_iced.number() >= 8;
                        let src_extended = src_iced.number() >= 8;

                        if dst_iced.is_gpr64() {
                            let mut rex = 0x48;
                            if dst_extended {
                                rex |= 0x04;
                            }
                            if src_extended {
                                rex |= 0x01;
                            }
                            self.output.push(rex);
                            
                            if imm_val >= -128 && imm_val <= 127 {
                                self.output.push(0x6B);
                                self.output.push(0xC0 | (dst_num << 3) | src_num);
                                self.output.push(imm_val as i8 as u8);
                            } else {
                                self.output.push(0x69);
                                self.output.push(0xC0 | (dst_num << 3) | src_num);
                                self.output.extend_from_slice(&(imm_val as i32).to_le_bytes());
                            }
                        } else if dst_iced.is_gpr32() {
                            if dst_extended || src_extended {
                                let mut rex = 0x40;
                                if dst_extended {
                                    rex |= 0x04;
                                }
                                if src_extended {
                                    rex |= 0x01;
                                }
                                self.output.push(rex);
                            }
                            
                            if imm_val >= -128 && imm_val <= 127 {
                                self.output.push(0x6B);
                                self.output.push(0xC0 | (dst_num << 3) | src_num);
                                self.output.push(imm_val as i8 as u8);
                            } else {
                                self.output.push(0x69);
                                self.output.push(0xC0 | (dst_num << 3) | src_num);
                                self.output.extend_from_slice(&(imm_val as i32).to_le_bytes());
                            }
                        } else {
                            return Err(DisassemblyError::IrConversionError(
                                "Unsupported register size for imul".to_string()
                            ));
                        }
                        Ok(())
                    }
                    _ => Err(DisassemblyError::IrConversionError(
                        "Unsupported imul operands".to_string()
                    )),
                }
            }
            // 处理 (None, Some(_)) 情况 - 这不应该发生，但如果发生则返回错误
            (None, Some(_)) => Err(DisassemblyError::IrConversionError(
                "Invalid imul operand combination: dst is None but src2 is Some".to_string()
            )),
        }
    }

    /// 编码 div 指令
    fn encode_div(&mut self, src: &IrOperand) -> DisassemblyResult<()> {
        self.encode_mul_div(src, 0xF6, 0xF7, 6)
    }

    /// 编码 idiv 指令
    fn encode_idiv(&mut self, src: &IrOperand) -> DisassemblyResult<()> {
        self.encode_mul_div(src, 0xF6, 0xF7, 7)
    }

    /// 通用乘除法指令编码
    fn encode_mul_div(&mut self, src: &IrOperand, op8: u8, op: u8, ext: u8) -> DisassemblyResult<()> {
        match src {
            IrOperand::Register(reg) => {
                let iced_reg = self.convert_register(reg)?;
                let reg_num = (iced_reg.number() & 7) as u8;
                let reg_extended = iced_reg.number() >= 8;

                if iced_reg.is_gpr8() {
                    let needs_spl = matches!(reg, IrRegister::Spl | IrRegister::Bpl | IrRegister::Sil | IrRegister::Dil);
                    if reg_extended || needs_spl {
                        let mut rex = 0x40;
                        if reg_extended {
                            rex |= 0x04;
                        }
                        self.output.push(rex);
                    }
                    self.output.push(op8);
                    self.output.push(0xC0 | (ext << 3) | reg_num);
                } else if iced_reg.is_gpr64() {
                    let mut rex = 0x48;
                    if reg_extended {
                        rex |= 0x01;
                    }
                    self.output.push(rex);
                    self.output.push(op);
                    self.output.push(0xC0 | (ext << 3) | reg_num);
                } else if iced_reg.is_gpr32() {
                    if reg_extended {
                        self.output.push(0x41);
                    }
                    self.output.push(op);
                    self.output.push(0xC0 | (ext << 3) | reg_num);
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Unsupported register for mul/div".to_string()
                    ));
                }
            }
            IrOperand::Memory(mem) => {
                if let Some(base_reg) = &mem.base {
                    let base_iced = self.convert_register(base_reg)?;
                    let base_num = (base_iced.number() & 7) as u8;
                    let base_extended = base_iced.number() >= 8;

                    match mem.size_bits {
                        8 => {
                            if base_extended {
                                self.output.push(0x41);
                            }
                            self.output.push(op8);
                        }
                        64 => {
                            let mut rex = 0x48;
                            if base_extended {
                                rex |= 0x01;
                            }
                            self.output.push(rex);
                            self.output.push(op);
                        }
                        32 => {
                            if base_extended {
                                self.output.push(0x41);
                            }
                            self.output.push(op);
                        }
                        _ => return Err(DisassemblyError::IrConversionError(
                            "Unsupported memory size".to_string()
                        )),
                    }

                    if mem.displacement == 0 {
                        self.output.push((ext << 3) | base_num);
                    } else if mem.displacement >= -128 && mem.displacement <= 127 {
                        self.output.push(0x40 | (ext << 3) | base_num);
                        self.output.push(mem.displacement as i8 as u8);
                    } else {
                        self.output.push(0x80 | (ext << 3) | base_num);
                        self.output.extend_from_slice(&(mem.displacement as i32).to_le_bytes());
                    }
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Memory without base not supported".to_string()
                    ));
                }
            }
            _ => return Err(DisassemblyError::IrConversionError(
                "Unsupported operand for mul/div".to_string()
            )),
        }

        Ok(())
    }

    /// 编码 shl 指令
    fn encode_shl(&mut self, dst: &IrOperand, count: &IrOperand) -> DisassemblyResult<()> {
        self.encode_shift(dst, count, 4)
    }

    /// 编码 shr 指令
    fn encode_shr(&mut self, dst: &IrOperand, count: &IrOperand) -> DisassemblyResult<()> {
        self.encode_shift(dst, count, 5)
    }

    /// 编码 sar 指令
    fn encode_sar(&mut self, dst: &IrOperand, count: &IrOperand) -> DisassemblyResult<()> {
        self.encode_shift(dst, count, 7)
    }

    /// 编码 rol 指令
    fn encode_rol(&mut self, dst: &IrOperand, count: &IrOperand) -> DisassemblyResult<()> {
        self.encode_shift(dst, count, 0)
    }

    /// 编码 ror 指令
    fn encode_ror(&mut self, dst: &IrOperand, count: &IrOperand) -> DisassemblyResult<()> {
        self.encode_shift(dst, count, 1)
    }

    /// 通用移位指令编码
    fn encode_shift(&mut self, dst: &IrOperand, count: &IrOperand, ext: u8) -> DisassemblyResult<()> {
        // 确定计数类型
        let (is_cl, count_val) = match count {
            IrOperand::Register(reg) => {
                if *reg == IrRegister::Cl {
                    (true, 0)
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Shift count must be CL or immediate".to_string()
                    ));
                }
            }
            IrOperand::Immediate(imm) => {
                let val = self.immediate_to_i64(imm);
                (false, val)
            }
            _ => return Err(DisassemblyError::IrConversionError("Invalid shift count".to_string())),
        };

        match dst {
            IrOperand::Register(reg) => {
                let iced_reg = self.convert_register(reg)?;
                let reg_num = (iced_reg.number() & 7) as u8;
                let reg_extended = iced_reg.number() >= 8;

                if iced_reg.is_gpr8() {
                    let needs_spl = matches!(reg, IrRegister::Spl | IrRegister::Bpl | IrRegister::Sil | IrRegister::Dil);
                    if reg_extended || needs_spl {
                        let mut rex = 0x40;
                        if reg_extended {
                            rex |= 0x04;
                        }
                        self.output.push(rex);
                    }

                    if is_cl {
                        self.output.push(0xD2);
                        self.output.push(0xC0 | (ext << 3) | reg_num);
                    } else if count_val == 1 {
                        self.output.push(0xD0);
                        self.output.push(0xC0 | (ext << 3) | reg_num);
                    } else {
                        self.output.push(0xC0);
                        self.output.push(0xC0 | (ext << 3) | reg_num);
                        self.output.push(count_val as u8);
                    }
                } else if iced_reg.is_gpr64() {
                    let mut rex = 0x48;
                    if reg_extended {
                        rex |= 0x01;
                    }
                    self.output.push(rex);

                    if is_cl {
                        self.output.push(0xD3);
                        self.output.push(0xC0 | (ext << 3) | reg_num);
                    } else if count_val == 1 {
                        self.output.push(0xD1);
                        self.output.push(0xC0 | (ext << 3) | reg_num);
                    } else {
                        self.output.push(0xC1);
                        self.output.push(0xC0 | (ext << 3) | reg_num);
                        self.output.push(count_val as u8);
                    }
                } else if iced_reg.is_gpr32() {
                    if reg_extended {
                        self.output.push(0x41);
                    }

                    if is_cl {
                        self.output.push(0xD3);
                        self.output.push(0xC0 | (ext << 3) | reg_num);
                    } else if count_val == 1 {
                        self.output.push(0xD1);
                        self.output.push(0xC0 | (ext << 3) | reg_num);
                    } else {
                        self.output.push(0xC1);
                        self.output.push(0xC0 | (ext << 3) | reg_num);
                        self.output.push(count_val as u8);
                    }
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Unsupported register for shift".to_string()
                    ));
                }
            }
            IrOperand::Memory(mem) => {
                if let Some(base_reg) = &mem.base {
                    let base_iced = self.convert_register(base_reg)?;
                    let base_num = (base_iced.number() & 7) as u8;
                    let base_extended = base_iced.number() >= 8;

                    match mem.size_bits {
                        8 => {
                            if base_extended {
                                self.output.push(0x41);
                            }

                            if is_cl {
                                self.output.push(0xD2);
                            } else if count_val == 1 {
                                self.output.push(0xD0);
                            } else {
                                self.output.push(0xC0);
                            }
                        }
                        64 => {
                            let mut rex = 0x48;
                            if base_extended {
                                rex |= 0x01;
                            }
                            self.output.push(rex);

                            if is_cl {
                                self.output.push(0xD3);
                            } else if count_val == 1 {
                                self.output.push(0xD1);
                            } else {
                                self.output.push(0xC1);
                            }
                        }
                        32 => {
                            if base_extended {
                                self.output.push(0x41);
                            }

                            if is_cl {
                                self.output.push(0xD3);
                            } else if count_val == 1 {
                                self.output.push(0xD1);
                            } else {
                                self.output.push(0xC1);
                            }
                        }
                        _ => return Err(DisassemblyError::IrConversionError(
                            "Unsupported memory size".to_string()
                        )),
                    }

                    if mem.displacement == 0 {
                        self.output.push((ext << 3) | base_num);
                    } else if mem.displacement >= -128 && mem.displacement <= 127 {
                        self.output.push(0x40 | (ext << 3) | base_num);
                        self.output.push(mem.displacement as i8 as u8);
                    } else {
                        self.output.push(0x80 | (ext << 3) | base_num);
                        self.output.extend_from_slice(&(mem.displacement as i32).to_le_bytes());
                    }

                    if !is_cl && count_val != 1 {
                        self.output.push(count_val as u8);
                    }
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Memory without base not supported".to_string()
                    ));
                }
            }
            _ => return Err(DisassemblyError::IrConversionError(
                "Unsupported operand for shift".to_string()
            )),
        }

        Ok(())
    }

    /// 编码 bt 指令
    fn encode_bt(&mut self, base: &IrOperand, offset: &IrOperand) -> DisassemblyResult<()> {
        self.encode_bit_test(base, offset, 4)
    }

    /// 编码 bts 指令
    fn encode_bts(&mut self, base: &IrOperand, offset: &IrOperand) -> DisassemblyResult<()> {
        self.encode_bit_test(base, offset, 5)
    }

    /// 编码 btr 指令
    fn encode_btr(&mut self, base: &IrOperand, offset: &IrOperand) -> DisassemblyResult<()> {
        self.encode_bit_test(base, offset, 6)
    }

    /// 通用位测试指令编码
    fn encode_bit_test(&mut self, base: &IrOperand, offset: &IrOperand, ext: u8) -> DisassemblyResult<()> {
        match (base, offset) {
            // base 是寄存器，offset 是寄存器
            (IrOperand::Register(base_reg), IrOperand::Register(offset_reg)) => {
                let base_iced = self.convert_register(base_reg)?;
                let offset_iced = self.convert_register(offset_reg)?;

                if !base_iced.is_gpr64() && !base_iced.is_gpr32() && !base_iced.is_gpr16() {
                    return Err(DisassemblyError::IrConversionError(
                        "BT base must be 16/32/64-bit register".to_string()
                    ));
                }

                let base_num = (base_iced.number() & 7) as u8;
                let offset_num = (offset_iced.number() & 7) as u8;
                let base_extended = base_iced.number() >= 8;
                let offset_extended = offset_iced.number() >= 8;

                if base_iced.is_gpr64() {
                    let mut rex = 0x48;
                    if offset_extended {
                        rex |= 0x04;
                    }
                    if base_extended {
                        rex |= 0x01;
                    }
                    self.output.push(rex);
                } else if base_iced.is_gpr32() {
                    if offset_extended || base_extended {
                        let mut rex = 0x40;
                        if offset_extended {
                            rex |= 0x04;
                        }
                        if base_extended {
                            rex |= 0x01;
                        }
                        self.output.push(rex);
                    }
                } else {
                    // 16-bit
                    self.output.push(0x66);
                    if offset_extended || base_extended {
                        let mut rex = 0x40;
                        if offset_extended {
                            rex |= 0x04;
                        }
                        if base_extended {
                            rex |= 0x01;
                        }
                        self.output.push(rex);
                    }
                }

                self.output.push(0x0F);
                self.output.push(0xA3 + (ext - 4) * 8);
                self.output.push(0xC0 | (offset_num << 3) | base_num);
            }
            // base 是寄存器，offset 是立即数
            (IrOperand::Register(base_reg), IrOperand::Immediate(imm)) => {
                let base_iced = self.convert_register(base_reg)?;
                let imm_val = self.immediate_to_i64(imm);

                if !base_iced.is_gpr64() && !base_iced.is_gpr32() && !base_iced.is_gpr16() {
                    return Err(DisassemblyError::IrConversionError(
                        "BT base must be 16/32/64-bit register".to_string()
                    ));
                }

                let base_num = (base_iced.number() & 7) as u8;
                let base_extended = base_iced.number() >= 8;

                if base_iced.is_gpr64() {
                    let mut rex = 0x48;
                    if base_extended {
                        rex |= 0x01;
                    }
                    self.output.push(rex);
                } else if base_iced.is_gpr32() {
                    if base_extended {
                        self.output.push(0x41);
                    }
                } else {
                    self.output.push(0x66);
                    if base_extended {
                        self.output.push(0x41);
                    }
                }

                self.output.push(0x0F);
                self.output.push(0xBA);
                self.output.push(0xC0 | (ext << 3) | base_num);
                self.output.push(imm_val as u8);
            }
            _ => return Err(DisassemblyError::IrConversionError(
                "Unsupported BT operands".to_string()
            )),
        }

        Ok(())
    }

    /// 编码 bsf 指令
    fn encode_bsf(&mut self, dst: &IrRegister, src: &IrOperand) -> DisassemblyResult<()> {
        self.encode_bit_scan(dst, src, 0xBC)
    }

    /// 编码 bsr 指令
    fn encode_bsr(&mut self, dst: &IrRegister, src: &IrOperand) -> DisassemblyResult<()> {
        self.encode_bit_scan(dst, src, 0xBD)
    }

    /// 通用位扫描指令编码
    fn encode_bit_scan(&mut self, dst: &IrRegister, src: &IrOperand, opcode: u8) -> DisassemblyResult<()> {
        let dst_iced = self.convert_register(dst)?;

        if !dst_iced.is_gpr64() && !dst_iced.is_gpr32() && !dst_iced.is_gpr16() {
            return Err(DisassemblyError::IrConversionError(
                "BSF/BSR destination must be 16/32/64-bit register".to_string()
            ));
        }

        let dst_num = (dst_iced.number() & 7) as u8;
        let dst_extended = dst_iced.number() >= 8;

        match src {
            IrOperand::Register(src_reg) => {
                let src_iced = self.convert_register(src_reg)?;
                let src_num = (src_iced.number() & 7) as u8;
                let src_extended = src_iced.number() >= 8;

                if dst_iced.is_gpr64() {
                    let mut rex = 0x48;
                    if dst_extended {
                        rex |= 0x04;
                    }
                    if src_extended {
                        rex |= 0x01;
                    }
                    self.output.push(rex);
                } else if dst_iced.is_gpr32() {
                    if dst_extended || src_extended {
                        let mut rex = 0x40;
                        if dst_extended {
                            rex |= 0x04;
                        }
                        if src_extended {
                            rex |= 0x01;
                        }
                        self.output.push(rex);
                    }
                } else {
                    self.output.push(0x66);
                    if dst_extended || src_extended {
                        let mut rex = 0x40;
                        if dst_extended {
                            rex |= 0x04;
                        }
                        if src_extended {
                            rex |= 0x01;
                        }
                        self.output.push(rex);
                    }
                }

                self.output.push(0x0F);
                self.output.push(opcode);
                self.output.push(0xC0 | (dst_num << 3) | src_num);
            }
            IrOperand::Memory(mem) => {
                if let Some(base_reg) = &mem.base {
                    let base_iced = self.convert_register(base_reg)?;
                    let base_num = (base_iced.number() & 7) as u8;
                    let base_extended = base_iced.number() >= 8;

                    if dst_iced.is_gpr64() {
                        let mut rex = 0x48;
                        if dst_extended {
                            rex |= 0x04;
                        }
                        if base_extended {
                            rex |= 0x01;
                        }
                        self.output.push(rex);
                    } else if dst_iced.is_gpr32() {
                        if dst_extended || base_extended {
                            let mut rex = 0x40;
                            if dst_extended {
                                rex |= 0x04;
                            }
                            if base_extended {
                                rex |= 0x01;
                            }
                            self.output.push(rex);
                        }
                    } else {
                        self.output.push(0x66);
                        if dst_extended || base_extended {
                            let mut rex = 0x40;
                            if dst_extended {
                                rex |= 0x04;
                            }
                            if base_extended {
                                rex |= 0x01;
                            }
                            self.output.push(rex);
                        }
                    }

                    self.output.push(0x0F);
                    self.output.push(opcode);

                    if mem.displacement == 0 {
                        self.output.push((dst_num << 3) | base_num);
                    } else if mem.displacement >= -128 && mem.displacement <= 127 {
                        self.output.push(0x40 | (dst_num << 3) | base_num);
                        self.output.push(mem.displacement as i8 as u8);
                    } else {
                        self.output.push(0x80 | (dst_num << 3) | base_num);
                        self.output.extend_from_slice(&(mem.displacement as i32).to_le_bytes());
                    }
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Memory without base not supported".to_string()
                    ));
                }
            }
            _ => return Err(DisassemblyError::IrConversionError(
                "Unsupported BSF/BSR source".to_string()
            )),
        }

        Ok(())
    }

    /// 编码 jmp 指令
    fn encode_jmp(&mut self, target: &IrJumpTarget) -> DisassemblyResult<()> {
        match target {
            IrJumpTarget::Direct(addr) => {
                let offset = *addr as i64 - (self.current_ip + 5) as i64;

                if offset >= -128 && offset <= 127 {
                    // EB cb (short jump)
                    self.output.push(0xEB);
                    self.output.push(offset as i8 as u8);
                } else {
                    // E9 cd (near jump)
                    self.output.push(0xE9);
                    self.output.extend_from_slice(&(offset as i32).to_le_bytes());
                }
            }
            IrJumpTarget::Relative(offset) => {
                let target_addr = (self.current_ip as i64 + offset) as u64;
                let rel_offset = target_addr as i64 - (self.current_ip + 5) as i64;

                if rel_offset >= -128 && rel_offset <= 127 {
                    self.output.push(0xEB);
                    self.output.push(rel_offset as i8 as u8);
                } else {
                    self.output.push(0xE9);
                    self.output.extend_from_slice(&(rel_offset as i32).to_le_bytes());
                }
            }
            IrJumpTarget::Register(reg) => {
                let iced_reg = self.convert_register(reg)?;
                let reg_num = (iced_reg.number() & 7) as u8;
                let reg_extended = iced_reg.number() >= 8;

                if iced_reg.is_gpr64() {
                    if reg_extended {
                        self.output.push(0x41);
                    }
                    self.output.push(0xFF);
                    self.output.push(0xE0 | reg_num);
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Jmp register must be 64-bit".to_string()
                    ));
                }
            }
            IrJumpTarget::Memory(mem) => {
                if let Some(base_reg) = &mem.base {
                    let base_iced = self.convert_register(base_reg)?;
                    let base_num = (base_iced.number() & 7) as u8;
                    let base_extended = base_iced.number() >= 8;

                    if base_extended {
                        self.output.push(0x41);
                    }
                    self.output.push(0xFF);

                    if mem.displacement == 0 {
                        self.output.push(0x20 | base_num);
                    } else if mem.displacement >= -128 && mem.displacement <= 127 {
                        self.output.push(0x60 | base_num);
                        self.output.push(mem.displacement as i8 as u8);
                    } else {
                        self.output.push(0xA0 | base_num);
                        self.output.extend_from_slice(&(mem.displacement as i32).to_le_bytes());
                    }
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Jmp memory without base not supported".to_string()
                    ));
                }
            }
            IrJumpTarget::Label(label_id) => {
                // 记录待回填的跳转
                let start_pos = self.output.len();

                // 先编码为近跳转（5字节），后面再回填
                self.output.push(0xE9);
                self.output.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // 占位符

                self.pending_jumps.push(PendingJump {
                    position: start_pos + 1, // 跳过操作码字节
                    instruction_len: 5,
                    instruction_address: self.current_ip,
                    target_label: *label_id,
                    is_short: false,
                });
            }
        }

        Ok(())
    }

    /// 编码 jcc 指令
    fn encode_jcc(&mut self, condition: IrCondition, target: &IrJumpTarget) -> DisassemblyResult<()> {
        // 条件码到操作码的映射
        let cc = match condition {
            IrCondition::E => 0x84,   // je/jz
            IrCondition::Ne => 0x85,  // jne/jnz
            IrCondition::G => 0x8F,   // jg
            IrCondition::Ge => 0x8D,  // jge
            IrCondition::L => 0x8C,   // jl
            IrCondition::Le => 0x8E,  // jle
            IrCondition::A => 0x87,   // ja
            IrCondition::Ae => 0x83,  // jae
            IrCondition::B => 0x82,   // jb
            IrCondition::Be => 0x86,  // jbe
            IrCondition::O => 0x80,   // jo
            IrCondition::No => 0x81,  // jno
            IrCondition::S => 0x88,   // js
            IrCondition::Ns => 0x89,  // jns
            IrCondition::P => 0x8A,   // jp
            IrCondition::Np => 0x8B,  // jnp
            _ => return Err(DisassemblyError::IrConversionError("Unsupported condition".to_string())),
        };

        match target {
            IrJumpTarget::Direct(addr) => {
                let offset = *addr as i64 - (self.current_ip + 6) as i64;

                if offset >= -128 && offset <= 127 {
                    // 0F 80+cc cb (short)
                    self.output.push(0x0F);
                    self.output.push(cc);
                    self.output.push(offset as i8 as u8);
                } else {
                    // 0F 80+cc cd (near)
                    self.output.push(0x0F);
                    self.output.push(cc);
                    self.output.extend_from_slice(&(offset as i32).to_le_bytes());
                }
            }
            IrJumpTarget::Relative(offset) => {
                let target_addr = (self.current_ip as i64 + offset) as u64;
                let rel_offset = target_addr as i64 - (self.current_ip + 6) as i64;

                if rel_offset >= -128 && rel_offset <= 127 {
                    self.output.push(0x0F);
                    self.output.push(cc);
                    self.output.push(rel_offset as i8 as u8);
                } else {
                    self.output.push(0x0F);
                    self.output.push(cc);
                    self.output.extend_from_slice(&(rel_offset as i32).to_le_bytes());
                }
            }
            IrJumpTarget::Label(label_id) => {
                let start_pos = self.output.len();

                // 先编码为近跳转（6字节）
                self.output.push(0x0F);
                self.output.push(cc);
                self.output.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // 占位符

                self.pending_jumps.push(PendingJump {
                    position: start_pos + 2, // 跳过操作码字节（0F + 条件码）
                    instruction_len: 6,
                    instruction_address: self.current_ip,
                    target_label: *label_id,
                    is_short: false,
                });
            }
            _ => return Err(DisassemblyError::IrConversionError("Unsupported jcc target".to_string())),
        }

        Ok(())
    }

    /// 编码 call 指令
    fn encode_call(&mut self, target: &IrJumpTarget) -> DisassemblyResult<()> {
        match target {
            IrJumpTarget::Direct(addr) => {
                let offset = *addr as i64 - (self.current_ip + 5) as i64;
                self.output.push(0xE8);
                self.output.extend_from_slice(&(offset as i32).to_le_bytes());
            }
            IrJumpTarget::Relative(offset) => {
                let target_addr = (self.current_ip as i64 + offset) as u64;
                let rel_offset = target_addr as i64 - (self.current_ip + 5) as i64;
                self.output.push(0xE8);
                self.output.extend_from_slice(&(rel_offset as i32).to_le_bytes());
            }
            IrJumpTarget::Register(reg) => {
                let iced_reg = self.convert_register(reg)?;
                let reg_num = (iced_reg.number() & 7) as u8;
                let reg_extended = iced_reg.number() >= 8;

                if iced_reg.is_gpr64() {
                    if reg_extended {
                        self.output.push(0x41);
                    }
                    self.output.push(0xFF);
                    self.output.push(0xD0 | reg_num);
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Call register must be 64-bit".to_string()
                    ));
                }
            }
            IrJumpTarget::Memory(mem) => {
                if let Some(base_reg) = &mem.base {
                    let base_iced = self.convert_register(base_reg)?;
                    let base_num = (base_iced.number() & 7) as u8;
                    let base_extended = base_iced.number() >= 8;

                    if base_extended {
                        self.output.push(0x41);
                    }
                    self.output.push(0xFF);

                    if mem.displacement == 0 {
                        self.output.push(0x10 | base_num);
                    } else if mem.displacement >= -128 && mem.displacement <= 127 {
                        self.output.push(0x50 | base_num);
                        self.output.push(mem.displacement as i8 as u8);
                    } else {
                        self.output.push(0x90 | base_num);
                        self.output.extend_from_slice(&(mem.displacement as i32).to_le_bytes());
                    }
                } else {
                    return Err(DisassemblyError::IrConversionError(
                        "Call memory without base not supported".to_string()
                    ));
                }
            }
            IrJumpTarget::Label(label_id) => {
                let start_pos = self.output.len();

                self.output.push(0xE8);
                self.output.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // 占位符

                self.pending_jumps.push(PendingJump {
                    position: start_pos + 1,
                    instruction_len: 5,
                    instruction_address: self.current_ip,
                    target_label: *label_id,
                    is_short: false,
                });
            }
        }

        Ok(())
    }

    /// 编码 ret 指令
    fn encode_ret(&mut self, pop_bytes: Option<u16>) -> DisassemblyResult<()> {
        if let Some(bytes) = pop_bytes {
            self.output.push(0xC2);
            self.output.extend_from_slice(&bytes.to_le_bytes());
        } else {
            self.output.push(0xC3);
        }
        Ok(())
    }

    /// 编码 syscall 指令
    fn encode_syscall(&mut self) -> DisassemblyResult<()> {
        self.output.push(0x0F);
        self.output.push(0x05);
        Ok(())
    }

    /// 编码 sysret 指令
    fn encode_sysret(&mut self) -> DisassemblyResult<()> {
        self.output.push(0x0F);
        self.output.push(0x07);
        Ok(())
    }

    /// 编码 int 指令
    fn encode_int(&mut self, vector: u8) -> DisassemblyResult<()> {
        self.output.push(0xCD);
        self.output.push(vector);
        Ok(())
    }

    /// 编码 int3 指令
    fn encode_int3(&mut self) -> DisassemblyResult<()> {
        self.output.push(0xCC);
        Ok(())
    }

    /// 编码 ud2 指令
    fn encode_ud2(&mut self) -> DisassemblyResult<()> {
        self.output.push(0x0F);
        self.output.push(0x0B);
        Ok(())
    }

    /// 编码 pushf 指令
    fn encode_pushf(&mut self) -> DisassemblyResult<()> {
        match self.config.mode.bits() {
            64 => self.output.push(0x9C), // pushfq
            32 => self.output.push(0x9C), // pushfd
            _ => self.output.push(0x9C),  // pushf
        }
        Ok(())
    }

    /// 编码 popf 指令
    fn encode_popf(&mut self) -> DisassemblyResult<()> {
        match self.config.mode.bits() {
            64 => self.output.push(0x9D), // popfq
            32 => self.output.push(0x9D), // popfd
            _ => self.output.push(0x9D),  // popf
        }
        Ok(())
    }

    /// 编码 lahf 指令
    fn encode_lahf(&mut self) -> DisassemblyResult<()> {
        self.output.push(0x9F);
        Ok(())
    }

    /// 编码 sahf 指令
    fn encode_sahf(&mut self) -> DisassemblyResult<()> {
        self.output.push(0x9E);
        Ok(())
    }

    /// 编码 cld 指令
    fn encode_cld(&mut self) -> DisassemblyResult<()> {
        self.output.push(0xFC);
        Ok(())
    }

    /// 编码 std 指令
    fn encode_std(&mut self) -> DisassemblyResult<()> {
        self.output.push(0xFD);
        Ok(())
    }

    /// 编码 clc 指令
    fn encode_clc(&mut self) -> DisassemblyResult<()> {
        self.output.push(0xF8);
        Ok(())
    }

    /// 编码 stc 指令
    fn encode_stc(&mut self) -> DisassemblyResult<()> {
        self.output.push(0xF9);
        Ok(())
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new(EncoderConfig::default())
    }
}

/// 编码单条 IR 指令的便捷函数
pub fn encode_single(instruction: &IrInstruction, mode: DisassemblyMode, base_address: u64) -> DisassemblyResult<EncodedInstruction> {
    let config = EncoderConfig::new(mode, base_address);
    let mut encoder = Encoder::new(config);
    encoder.encode(instruction)
}

/// 编码多条 IR 指令的便捷函数
pub fn encode_all(instructions: &[IrInstruction], mode: DisassemblyMode, base_address: u64) -> DisassemblyResult<Vec<EncodedInstruction>> {
    let config = EncoderConfig::new(mode, base_address);
    let mut encoder = Encoder::new(config);
    encoder.encode_all(instructions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoder_config() {
        let config = EncoderConfig::new(DisassemblyMode::Mode64, 0x1000)
            .with_address_size(64)
            .with_operand_size(64);
        
        assert_eq!(config.mode, DisassemblyMode::Mode64);
        assert_eq!(config.base_address, 0x1000);
        assert_eq!(config.effective_address_size(), 64);
        assert_eq!(config.effective_operand_size(), 64);
    }

    #[test]
    fn test_encode_nop() {
        let insn = IrInstruction::Nop;
        let result = encode_single(&insn, DisassemblyMode::Mode64, 0x1000).unwrap();
        
        assert_eq!(result.bytes, vec![0x90]);
        assert_eq!(result.len, 1);
    }

    #[test]
    fn test_encode_mov_reg_reg() {
        let insn = IrInstruction::Mov {
            dst: IrOperand::Register(IrRegister::Rax),
            src: IrOperand::Register(IrRegister::Rbx),
        };
        let result = encode_single(&insn, DisassemblyMode::Mode64, 0x1000).unwrap();
        
        assert!(!result.bytes.is_empty());
    }

    #[test]
    fn test_encode_push_reg() {
        let insn = IrInstruction::Push {
            src: IrOperand::Register(IrRegister::Rax),
        };
        let result = encode_single(&insn, DisassemblyMode::Mode64, 0x1000).unwrap();
        
        assert!(!result.bytes.is_empty());
    }

    #[test]
    fn test_encode_pop_reg() {
        let insn = IrInstruction::Pop {
            dst: IrOperand::Register(IrRegister::Rax),
        };
        let result = encode_single(&insn, DisassemblyMode::Mode64, 0x1000).unwrap();
        
        assert!(!result.bytes.is_empty());
    }

    #[test]
    fn test_encode_ret() {
        let insn = IrInstruction::Ret { pop_bytes: None };
        let result = encode_single(&insn, DisassemblyMode::Mode64, 0x1000).unwrap();
        
        assert!(!result.bytes.is_empty());
    }

    #[test]
    fn test_encode_int3() {
        let insn = IrInstruction::Int3;
        let result = encode_single(&insn, DisassemblyMode::Mode64, 0x1000).unwrap();
        
        assert_eq!(result.bytes, vec![0xCC]);
    }

    #[test]
    fn test_encode_nop_sequence() {
        let instructions = vec![
            IrInstruction::Nop,
            IrInstruction::Nop,
            IrInstruction::Nop,
        ];
        let results = encode_all(&instructions, DisassemblyMode::Mode64, 0x1000).unwrap();
        
        assert_eq!(results.len(), 3);
        for result in results {
            assert_eq!(result.bytes, vec![0x90]);
        }
    }

    /// 测试解码-编码循环一致性
    /// 将机器码解码为 IR，再编码回机器码，验证是否一致
    #[test]
    fn test_decode_encode_roundtrip() {
        use crate::intel::{disassemble_to_ir, encode_ir};
        
        // 测试简单的指令序列
        // mov rax, rbx (0x48 0x89 0xD8)
        // nop (0x90)
        // ret (0xC3)
        let original_bytes = vec![
            0x48, 0x89, 0xD8,  // mov rax, rbx
            0x90,              // nop
            0xC3,              // ret
        ];
        
        let base_addr = 0x1000u64;
        
        // 解码为 IR
        let ir_instructions = disassemble_to_ir(&original_bytes, DisassemblyMode::Mode64, base_addr)
            .expect("Failed to disassemble");
        
        assert!(!ir_instructions.is_empty(), "Should have decoded some instructions");
        
        // 编码回机器码
        let encoded_bytes = encode_ir(&ir_instructions, DisassemblyMode::Mode64, base_addr)
            .expect("Failed to encode");
        
        // 验证编码后的字节与原始字节一致
        assert_eq!(encoded_bytes, original_bytes, 
            "Encoded bytes should match original. Original: {:02X?}, Encoded: {:02X?}", 
            original_bytes, encoded_bytes);
    }

    /// 测试更多指令的解码-编码循环
    #[test]
    fn test_decode_encode_roundtrip_more_instructions() {
        use crate::intel::{disassemble_to_ir, encode_ir};
        
        // 测试更多指令
        // push rax (0x50)
        // pop rax (0x58)
        // mov rax, 0x12345678 (0x48 0xC7 0xC0 0x78 0x56 0x34 0x12)
        // add rax, rbx (0x48 0x01 0xD8)
        let original_bytes = vec![
            0x50,                                      // push rax
            0x58,                                      // pop rax
            0x48, 0xC7, 0xC0, 0x78, 0x56, 0x34, 0x12, // mov rax, 0x12345678
            0x48, 0x01, 0xD8,                          // add rax, rbx
        ];
        
        let base_addr = 0x1000u64;
        
        // 解码为 IR
        let ir_instructions = disassemble_to_ir(&original_bytes, DisassemblyMode::Mode64, base_addr)
            .expect("Failed to disassemble");
        
        assert!(!ir_instructions.is_empty(), "Should have decoded some instructions");
        
        // 编码回机器码
        let encoded_bytes = encode_ir(&ir_instructions, DisassemblyMode::Mode64, base_addr)
            .expect("Failed to encode");
        
        // 验证编码后的字节与原始字节一致
        assert_eq!(encoded_bytes, original_bytes,
            "Encoded bytes should match original.\nOriginal: {:02X?}\nEncoded:  {:02X?}",
            original_bytes, encoded_bytes);
    }

    /// 测试带立即数的指令
    #[test]
    fn test_decode_encode_immediate_instructions() {
        use crate::intel::{disassemble_to_ir, encode_ir};
        
        // mov eax, 1 (0xB8 0x01 0x00 0x00 0x00)
        // mov rax, 0x123456789ABCDEF0 (0x48 0xB8 0xF0 0xDE 0xBC 0x9A 0x78 0x56 0x34 0x12)
        let original_bytes = vec![
            0xB8, 0x01, 0x00, 0x00, 0x00,              // mov eax, 1
            0x48, 0xB8, 0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12, // mov rax, 0x123456789ABCDEF0
        ];
        
        let base_addr = 0x1000u64;
        
        // 解码为 IR
        let ir_instructions = disassemble_to_ir(&original_bytes, DisassemblyMode::Mode64, base_addr)
            .expect("Failed to disassemble");
        
        assert!(!ir_instructions.is_empty(), "Should have decoded some instructions");
        
        // 编码回机器码
        let encoded_bytes = encode_ir(&ir_instructions, DisassemblyMode::Mode64, base_addr)
            .expect("Failed to encode");
        
        // 验证编码后的字节与原始字节一致
        assert_eq!(encoded_bytes, original_bytes,
            "Encoded bytes should match original.\nOriginal: {:02X?}\nEncoded:  {:02X?}",
            original_bytes, encoded_bytes);
    }
}
