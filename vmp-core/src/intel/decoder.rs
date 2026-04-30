//! 反汇编器模块
//!
//! 使用 iced-x86 提供高性能的反汇编功能。

use super::{DisassemblyMode, DisassemblyResult, Instruction};
use crate::error::Result;

/// 反汇编器配置
#[derive(Debug, Clone)]
pub struct DecoderConfig {
    /// 反汇编模式
    pub mode: DisassemblyMode,
    /// 基地址
    pub base_address: u64,
    /// 最大指令数量（0表示无限制）
    pub max_instructions: usize,
    /// 是否验证指令有效性
    pub validate_instructions: bool,
}

impl DecoderConfig {
    /// 创建新的配置
    pub fn new(mode: DisassemblyMode, base_address: u64) -> Self {
        Self {
            mode,
            base_address,
            max_instructions: 0,
            validate_instructions: true,
        }
    }

    /// 设置最大指令数量
    pub fn with_max_instructions(mut self, max: usize) -> Self {
        self.max_instructions = max;
        self
    }

    /// 禁用指令验证
    pub fn without_validation(mut self) -> Self {
        self.validate_instructions = false;
        self
    }
}

impl Default for DecoderConfig {
    fn default() -> Self {
        Self {
            mode: DisassemblyMode::Mode64,
            base_address: 0,
            max_instructions: 0,
            validate_instructions: true,
        }
    }
}

/// 反汇编器
pub struct Decoder {
    config: DecoderConfig,
}

impl Decoder {
    /// 创建新的反汇编器
    pub fn new(config: DecoderConfig) -> Self {
        Self { config }
    }

    /// 解码单个指令
    pub fn decode_one(&self, data: &[u8], ip: u64) -> Result<Option<Instruction>> {
        if data.is_empty() {
            return Ok(None);
        }

        let mut decoder = self.create_iced_decoder(data, ip);
        
        if decoder.can_decode() {
            let iced_insn = decoder.decode();
            if iced_insn.code() != iced_x86::Code::INVALID {
                return Ok(Some(Instruction::from_iced(iced_insn, ip)));
            }
        }
        
        Ok(None)
    }

    /// 解码所有指令
    pub fn decode_all(&mut self, data: &[u8]) -> Result<Vec<Instruction>> {
        let mut instructions = Vec::new();
        let mut offset = 0u64;
        let base = self.config.base_address;

        let mut decoder = self.create_iced_decoder(data, base);

        while decoder.can_decode() {
            // 检查最大指令数量限制
            if self.config.max_instructions > 0 && instructions.len() >= self.config.max_instructions {
                break;
            }

            let ip = decoder.ip();
            let iced_insn = decoder.decode();

            // 检查是否是无效指令
            if iced_insn.code() == iced_x86::Code::INVALID {
                break;
            }

            let instruction = Instruction::from_iced(iced_insn, ip);
            instructions.push(instruction);
            offset += iced_insn.len() as u64;
        }

        Ok(instructions)
    }

    /// 解码指定地址范围的指令
    pub fn decode_range(&mut self, data: &[u8], start_offset: u64, end_offset: u64) -> Result<Vec<Instruction>> {
        if start_offset >= data.len() as u64 || start_offset >= end_offset {
            return Ok(Vec::new());
        }

        let end = end_offset.min(data.len() as u64) as usize;
        let slice = &data[start_offset as usize..end];
        let base = self.config.base_address + start_offset;

        let mut temp_decoder = Self::new(DecoderConfig::new(self.config.mode, base));
        temp_decoder.decode_all(slice)
    }

    /// 获取配置
    pub fn config(&self) -> &DecoderConfig {
        &self.config
    }

    /// 创建 iced-x86 解码器
    fn create_iced_decoder<'a>(&self, data: &'a [u8], ip: u64) -> iced_x86::Decoder<'a> {
        let bitness = match self.config.mode {
            DisassemblyMode::Mode16 => 16,
            DisassemblyMode::Mode32 => 32,
            DisassemblyMode::Mode64 => 64,
        };

        iced_x86::Decoder::with_ip(bitness, data, ip, iced_x86::DecoderOptions::NONE)
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new(DecoderConfig::default())
    }
}

/// 快速反汇编辅助函数
pub fn decode_single(data: &[u8], mode: DisassemblyMode, ip: u64) -> Result<Option<Instruction>> {
    let decoder = Decoder::new(DecoderConfig::new(mode, ip));
    decoder.decode_one(data, ip)
}

/// 解码指令列表
pub fn decode_instructions(data: &[u8], mode: DisassemblyMode, base_address: u64) -> Result<Vec<Instruction>> {
    let config = DecoderConfig::new(mode, base_address);
    let mut decoder = Decoder::new(config);
    decoder.decode_all(data)
}

/// 反汇编代码块直到遇到控制流指令
pub fn decode_basic_block(data: &[u8], mode: DisassemblyMode, base_address: u64) -> Result<Vec<Instruction>> {
    let config = DecoderConfig::new(mode, base_address);
    let mut decoder = Decoder::new(config);
    let mut instructions = Vec::new();

    let mut iced_decoder = match mode {
        DisassemblyMode::Mode16 => iced_x86::Decoder::new(16, data, iced_x86::DecoderOptions::NONE),
        DisassemblyMode::Mode32 => iced_x86::Decoder::new(32, data, iced_x86::DecoderOptions::NONE),
        DisassemblyMode::Mode64 => iced_x86::Decoder::new(64, data, iced_x86::DecoderOptions::NONE),
    };
    iced_decoder.set_ip(base_address);

    while iced_decoder.can_decode() {
        let ip = iced_decoder.ip();
        let iced_insn = iced_decoder.decode();

        if iced_insn.code() == iced_x86::Code::INVALID {
            break;
        }

        let instruction = Instruction::from_iced(iced_insn, ip);
        let is_control_flow = instruction.is_control_flow();
        instructions.push(instruction);

        // 遇到控制流指令就停止
        if is_control_flow {
            break;
        }
    }

    Ok(instructions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decoder_config() {
        let config = DecoderConfig::new(DisassemblyMode::Mode64, 0x1000)
            .with_max_instructions(100)
            .without_validation();

        assert_eq!(config.mode, DisassemblyMode::Mode64);
        assert_eq!(config.base_address, 0x1000);
        assert_eq!(config.max_instructions, 100);
        assert!(!config.validate_instructions);
    }

    #[test]
    fn test_decode_nop() {
        let data = vec![0x90]; // nop
        let mut decoder = Decoder::new(DecoderConfig::new(DisassemblyMode::Mode64, 0x1000));
        let instructions = decoder.decode_all(&data).unwrap();

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].mnemonic(), "nop");
        assert_eq!(instructions[0].len(), 1);
    }

    #[test]
    fn test_decode_mov() {
        // mov rax, rbx (48 89 D8)
        let data = vec![0x48, 0x89, 0xD8];
        let mut decoder = Decoder::new(DecoderConfig::new(DisassemblyMode::Mode64, 0x1000));
        let instructions = decoder.decode_all(&data).unwrap();

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].mnemonic(), "mov");
        assert_eq!(instructions[0].len(), 3);
    }

    #[test]
    fn test_decode_multiple() {
        // nop; nop; nop
        let data = vec![0x90, 0x90, 0x90];
        let mut decoder = Decoder::new(DecoderConfig::new(DisassemblyMode::Mode64, 0x1000));
        let instructions = decoder.decode_all(&data).unwrap();

        assert_eq!(instructions.len(), 3);
        for insn in &instructions {
            assert_eq!(insn.mnemonic(), "nop");
        }
    }

    #[test]
    fn test_decode_call() {
        // call 0x1234 (E8 2F 12 00 00)
        let data = vec![0xE8, 0x2F, 0x12, 0x00, 0x00];
        let mut decoder = Decoder::new(DecoderConfig::new(DisassemblyMode::Mode64, 0x1000));
        let instructions = decoder.decode_all(&data).unwrap();

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].mnemonic(), "call");
        assert!(instructions[0].is_call());
    }

    #[test]
    fn test_decode_jmp() {
        // jmp short (EB 05)
        let data = vec![0xEB, 0x05];
        let mut decoder = Decoder::new(DecoderConfig::new(DisassemblyMode::Mode64, 0x1000));
        let instructions = decoder.decode_all(&data).unwrap();

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].mnemonic(), "jmp");
        assert!(instructions[0].is_jump());
        assert!(instructions[0].is_unconditional_jump());
    }

    #[test]
    fn test_decode_conditional_jmp() {
        // je short (74 05)
        let data = vec![0x74, 0x05];
        let mut decoder = Decoder::new(DecoderConfig::new(DisassemblyMode::Mode64, 0x1000));
        let instructions = decoder.decode_all(&data).unwrap();

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].mnemonic(), "je");
        assert!(instructions[0].is_jump());
        assert!(instructions[0].is_conditional_jump());
    }

    #[test]
    fn test_decode_basic_block() {
        // mov rax, rbx; nop; call 0x1234
        let data = vec![0x48, 0x89, 0xD8, 0x90, 0xE8, 0x2F, 0x12, 0x00, 0x00];
        let instructions = decode_basic_block(&data, DisassemblyMode::Mode64, 0x1000).unwrap();

        assert_eq!(instructions.len(), 3);
        assert_eq!(instructions[0].mnemonic(), "mov");
        assert_eq!(instructions[1].mnemonic(), "nop");
        assert_eq!(instructions[2].mnemonic(), "call");
    }

    #[test]
    fn test_decode_32bit() {
        // mov eax, ebx (89 D8)
        let data = vec![0x89, 0xD8];
        let mut decoder = Decoder::new(DecoderConfig::new(DisassemblyMode::Mode32, 0x1000));
        let instructions = decoder.decode_all(&data).unwrap();

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].mnemonic(), "mov");
    }

    #[test]
    fn test_decode_range() {
        // nop; nop; nop; nop
        let data = vec![0x90, 0x90, 0x90, 0x90];
        let mut decoder = Decoder::new(DecoderConfig::new(DisassemblyMode::Mode64, 0x1000));
        let instructions = decoder.decode_range(&data, 1, 3).unwrap();

        assert_eq!(instructions.len(), 2);
    }

    #[test]
    fn test_decode_single() {
        // push rax (50)
        let data = vec![0x50];
        let result = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap().mnemonic(), "push");
    }

    #[test]
    fn test_empty_data() {
        let data: Vec<u8> = vec![];
        let mut decoder = Decoder::new(DecoderConfig::new(DisassemblyMode::Mode64, 0x1000));
        let instructions = decoder.decode_all(&data).unwrap();

        assert!(instructions.is_empty());
    }

    #[test]
    fn test_max_instructions() {
        // 10 nops
        let data = vec![0x90; 10];
        let config = DecoderConfig::new(DisassemblyMode::Mode64, 0x1000)
            .with_max_instructions(5);
        let mut decoder = Decoder::new(config);
        let instructions = decoder.decode_all(&data).unwrap();

        assert_eq!(instructions.len(), 5);
    }
}
