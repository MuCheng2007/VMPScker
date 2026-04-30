//! Intel x86/x64 反汇编和 IR 模块
//!
//! 使用 iced-x86 库提供高性能的反汇编功能，并构建 VMProtect 特定的 IR 层。

pub mod decoder;
pub mod instruction;
pub mod formatter;
pub mod ir;
pub mod ir_converter;
pub mod basic_block;
pub mod function;
pub mod cfg;

pub use decoder::{Decoder, DecoderConfig};
pub use instruction::{Instruction, InstructionInfo, InstructionCategory};
pub use formatter::{Formatter, FormatterOptions};
pub use ir::{IrInstruction, IrOperand, IrRegister, IrMemoryOperand, IrImmediate};
pub use ir_converter::IrConverter;
pub use basic_block::{BasicBlock, BasicBlockId};
pub use function::{Function, FunctionAnalyzer};
pub use cfg::{ControlFlowGraph, CfgBuilder};

use crate::error::{Result, VmpError};

/// 反汇编模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisassemblyMode {
    /// 16 位实模式
    Mode16,
    /// 32 位保护模式
    Mode32,
    /// 64 位长模式
    Mode64,
}

impl DisassemblyMode {
    /// 获取对应的位宽
    pub fn bits(&self) -> u32 {
        match self {
            DisassemblyMode::Mode16 => 16,
            DisassemblyMode::Mode32 => 32,
            DisassemblyMode::Mode64 => 64,
        }
    }

    /// 获取默认的代码段地址大小
    pub fn default_code_segment_size(&self) -> u32 {
        match self {
            DisassemblyMode::Mode16 => 16,
            DisassemblyMode::Mode32 => 32,
            DisassemblyMode::Mode64 => 64,
        }
    }

    /// 获取默认的栈地址大小
    pub fn default_stack_address_size(&self) -> u32 {
        match self {
            DisassemblyMode::Mode16 => 16,
            DisassemblyMode::Mode32 => 32,
            DisassemblyMode::Mode64 => 64,
        }
    }
}

impl From<DisassemblyMode> for u32 {
    fn from(mode: DisassemblyMode) -> Self {
        mode.bits()
    }
}

/// 反汇编错误类型
#[derive(Debug, thiserror::Error)]
pub enum DisassemblyError {
    #[error("无效的指令编码: {0}")]
    InvalidInstruction(String),
    #[error("不支持的指令: {0}")]
    UnsupportedInstruction(String),
    #[error("解码错误: {0}")]
    DecodeError(String),
    #[error("IR 转换错误: {0}")]
    IrConversionError(String),
    #[error("控制流分析错误: {0}")]
    CfgError(String),
}

impl From<DisassemblyError> for VmpError {
    fn from(e: DisassemblyError) -> Self {
        VmpError::Disassembly(e.to_string())
    }
}

/// 反汇编结果
pub type DisassemblyResult<T> = std::result::Result<T, DisassemblyError>;

/// 将字节数组反汇编为指令列表
pub fn disassemble(data: &[u8], mode: DisassemblyMode, base_address: u64) -> Result<Vec<Instruction>> {
    let config = DecoderConfig::new(mode, base_address);
    let mut decoder = Decoder::new(config);
    decoder.decode_all(data)
}

/// 将字节数组反汇编并转换为 IR
pub fn disassemble_to_ir(data: &[u8], mode: DisassemblyMode, base_address: u64) -> Result<Vec<ir::IrInstruction>> {
    let instructions = disassemble(data, mode, base_address)?;
    let converter = IrConverter::new(mode);
    converter.convert_instructions(&instructions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassembly_mode() {
        assert_eq!(DisassemblyMode::Mode16.bits(), 16);
        assert_eq!(DisassemblyMode::Mode32.bits(), 32);
        assert_eq!(DisassemblyMode::Mode64.bits(), 64);
    }

    #[test]
    fn test_disassemble_simple() {
        // nop
        let data = vec![0x90];
        let instructions = disassemble(&data, DisassemblyMode::Mode64, 0x1000).unwrap();
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].mnemonic(), "nop");
    }

    #[test]
    fn test_disassemble_mov() {
        // mov rax, rbx
        let data = vec![0x48, 0x89, 0xD8];
        let instructions = disassemble(&data, DisassemblyMode::Mode64, 0x1000).unwrap();
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].mnemonic(), "mov");
    }
}
