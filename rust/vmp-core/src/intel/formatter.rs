//! 格式化器模块
//!
//! 提供指令的格式化输出功能，支持 Intel 和 NASM 语法。

use super::Instruction;
use iced_x86::Formatter as IcedFormatter;
use iced_x86::IntelFormatter;
use iced_x86::NasmFormatter;
use iced_x86::FormatterOutput;
use iced_x86::FormatterTextKind;
use std::fmt::Write;

/// 格式化器语法风格
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatterStyle {
    /// Intel 语法（默认）
    Intel,
    /// NASM 语法
    Nasm,
}

/// 格式化器选项
#[derive(Debug, Clone)]
pub struct FormatterOptions {
    /// 语法风格
    pub style: FormatterStyle,
    /// 是否显示地址
    pub show_address: bool,
    /// 是否显示字节码
    pub show_bytes: bool,
    /// 是否显示操作数大小
    pub show_operand_size: bool,
    /// 地址格式（十六进制前缀）
    pub hex_prefix: String,
    /// 数字格式（十六进制后缀）
    pub hex_suffix: String,
    /// 数字前导零
    pub leading_zeros: bool,
}

impl Default for FormatterOptions {
    fn default() -> Self {
        Self {
            style: FormatterStyle::Intel,
            show_address: true,
            show_bytes: false,
            show_operand_size: false,
            hex_prefix: String::new(),
            hex_suffix: String::new(),
            leading_zeros: false,
        }
    }
}

impl FormatterOptions {
    /// 创建默认选项
    pub fn new() -> Self {
        Self::default()
    }

    /// 使用 Intel 语法
    pub fn intel() -> Self {
        Self {
            style: FormatterStyle::Intel,
            ..Default::default()
        }
    }

    /// 使用 NASM 语法
    pub fn nasm() -> Self {
        Self {
            style: FormatterStyle::Nasm,
            ..Default::default()
        }
    }

    /// 显示地址
    pub fn with_address(mut self, show: bool) -> Self {
        self.show_address = show;
        self
    }

    /// 显示字节码
    pub fn with_bytes(mut self, show: bool) -> Self {
        self.show_bytes = show;
        self
    }

    /// 显示操作数大小
    pub fn with_operand_size(mut self, show: bool) -> Self {
        self.show_operand_size = show;
        self
    }
}

/// 指令格式化器
pub struct Formatter {
    options: FormatterOptions,
    intel_formatter: IntelFormatter,
    nasm_formatter: NasmFormatter,
}

impl Formatter {
    /// 创建新的格式化器
    pub fn new(options: FormatterOptions) -> Self {
        Self {
            options,
            intel_formatter: IntelFormatter::new(),
            nasm_formatter: NasmFormatter::new(),
        }
    }

    /// 使用默认选项创建
    pub fn default_intel() -> Self {
        Self::new(FormatterOptions::intel())
    }

    /// 使用 NASM 语法创建
    pub fn default_nasm() -> Self {
        Self::new(FormatterOptions::nasm())
    }

    /// 格式化单条指令
    pub fn format(&mut self, instruction: &Instruction) -> String {
        let mut output = StringOutput::new();
        
        // 格式化地址部分
        if self.options.show_address {
            let addr = instruction.ip();
            if self.options.leading_zeros {
                write!(output.inner(), "{:016X}: ", addr).unwrap();
            } else {
                write!(output.inner(), "{:X}: ", addr).unwrap();
            }
        }

        // 格式化字节码部分
        if self.options.show_bytes {
            let bytes = self.get_instruction_bytes(instruction);
            for byte in &bytes {
                write!(output.inner(), "{:02X} ", byte).unwrap();
            }
            // 补齐字节码列
            for _ in bytes.len()..12 {
                write!(output.inner(), "   ").unwrap();
            }
        }

        // 格式化指令
        let iced_insn = instruction.iced();
        match self.options.style {
            FormatterStyle::Intel => {
                self.intel_formatter.format(iced_insn, &mut output);
            }
            FormatterStyle::Nasm => {
                self.nasm_formatter.format(iced_insn, &mut output);
            }
        }

        output.into_string()
    }

    /// 格式化多条指令
    pub fn format_instructions(&mut self, instructions: &[Instruction]) -> String {
        let mut result = String::new();
        for instruction in instructions {
            result.push_str(&self.format(instruction));
            result.push('\n');
        }
        result
    }

    /// 格式化指令为字符串（不包含地址和字节码）
    pub fn format_instruction_only(&mut self, instruction: &Instruction) -> String {
        let mut output = StringOutput::new();
        let iced_insn = instruction.iced();
        
        match self.options.style {
            FormatterStyle::Intel => {
                self.intel_formatter.format(iced_insn, &mut output);
            }
            FormatterStyle::Nasm => {
                self.nasm_formatter.format(iced_insn, &mut output);
            }
        }
        
        output.into_string()
    }

    /// 获取助记符
    pub fn format_mnemonic(&self, instruction: &Instruction) -> String {
        instruction.mnemonic()
    }

    /// 获取操作数字符串
    pub fn format_operands(&mut self, instruction: &Instruction) -> String {
        let full = self.format_instruction_only(instruction);
        let mnemonic = self.format_mnemonic(instruction);
        
        // 从完整指令字符串中提取操作数部分
        if let Some(pos) = full.find(&mnemonic) {
            let after_mnemonic = &full[pos + mnemonic.len()..];
            after_mnemonic.trim().to_string()
        } else {
            String::new()
        }
    }

    /// 获取指令字节码
    fn get_instruction_bytes(&self, instruction: &Instruction) -> Vec<u8> {
        // 从 iced 指令获取原始字节
        let len = instruction.len() as usize;
        let ip = instruction.ip();
        
        // 注意：这里我们无法直接从 Instruction 获取原始字节
        // 实际实现中需要在解码时保存原始字节
        Vec::new()
    }

    /// 获取选项
    pub fn options(&self) -> &FormatterOptions {
        &self.options
    }
}

impl Default for Formatter {
    fn default() -> Self {
        Self::default_intel()
    }
}

/// 字符串输出实现
struct StringOutput {
    buffer: String,
}

impl StringOutput {
    fn new() -> Self {
        Self {
            buffer: String::new(),
        }
    }

    fn inner(&mut self) -> &mut String {
        &mut self.buffer
    }

    fn into_string(self) -> String {
        self.buffer
    }
}

impl FormatterOutput for StringOutput {
    fn write(&mut self, text: &str, _kind: FormatterTextKind) {
        self.buffer.push_str(text);
    }
}

/// 快速格式化函数
pub fn format_instruction(instruction: &Instruction) -> String {
    Formatter::default_intel().format(instruction)
}

/// 使用 NASM 语法格式化
pub fn format_instruction_nasm(instruction: &Instruction) -> String {
    Formatter::default_nasm().format(instruction)
}

/// 格式化多条指令
pub fn format_instructions(instructions: &[Instruction]) -> String {
    Formatter::default_intel().format_instructions(instructions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::decoder::decode_single;
    use crate::intel::DisassemblyMode;

    #[test]
    fn test_format_nop() {
        let data = vec![0x90];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut formatter = Formatter::default_intel();
        let formatted = formatter.format_instruction_only(&insn);

        assert!(formatted.contains("nop"));
    }

    #[test]
    fn test_format_mov() {
        // mov rax, rbx
        let data = vec![0x48, 0x89, 0xD8];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut formatter = Formatter::default_intel();
        let formatted = formatter.format_instruction_only(&insn);

        assert!(formatted.contains("mov"));
        assert!(formatted.contains("rax"));
        assert!(formatted.contains("rbx"));
    }

    #[test]
    fn test_format_with_address() {
        let data = vec![0x90];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut formatter = Formatter::new(FormatterOptions::intel().with_address(true));
        let formatted = formatter.format(&insn);

        assert!(formatted.contains("1000"));
        assert!(formatted.contains("nop"));
    }

    #[test]
    fn test_formatter_options() {
        let opts = FormatterOptions::intel()
            .with_address(true)
            .with_bytes(true)
            .with_operand_size(true);

        assert!(opts.show_address);
        assert!(opts.show_bytes);
        assert!(opts.show_operand_size);
        assert_eq!(opts.style, FormatterStyle::Intel);
    }

    #[test]
    fn test_nasm_formatter() {
        // mov rax, rbx
        let data = vec![0x48, 0x89, 0xD8];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let mut formatter = Formatter::default_nasm();
        let formatted = formatter.format_instruction_only(&insn);

        assert!(formatted.contains("mov"));
    }

    #[test]
    fn test_format_multiple() {
        // nop; nop
        let data = vec![0x90, 0x90];
        let mut decoder = crate::intel::decoder::Decoder::new(
            crate::intel::decoder::DecoderConfig::new(DisassemblyMode::Mode64, 0x1000)
        );
        let instructions = decoder.decode_all(&data).unwrap();
        let mut formatter = Formatter::default_intel();
        let formatted = formatter.format_instructions(&instructions);

        assert!(formatted.contains("nop"));
        assert!(formatted.lines().count() >= 2);
    }

    #[test]
    fn test_format_mnemonic() {
        let data = vec![0x90];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let formatter = Formatter::default_intel();
        let mnemonic = formatter.format_mnemonic(&insn);

        assert_eq!(mnemonic, "nop");
    }

    #[test]
    fn test_quick_format() {
        let data = vec![0x48, 0x89, 0xD8];
        let insn = decode_single(&data, DisassemblyMode::Mode64, 0x1000).unwrap().unwrap();
        let formatted = format_instruction(&insn);

        assert!(!formatted.is_empty());
        assert!(formatted.contains("mov"));
    }
}
