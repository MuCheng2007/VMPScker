//! VMP 保护器
//!
//! 提供 VMProtect 保护流程。

use crate::error::{Result, VmpError};
use crate::intel::{disassemble_to_ir, DisassemblyMode};
use crate::intel::ir::IrInstruction;
use crate::pe::file::PeFile;
use std::path::Path;

/// 保护配置
#[derive(Debug, Clone)]
pub struct ProtectConfig {
    pub mode: DisassemblyMode,
}

impl Default for ProtectConfig {
    fn default() -> Self {
        Self {
            mode: DisassemblyMode::Mode64,
        }
    }
}

/// 保护范围
#[derive(Debug, Clone)]
pub enum ProtectRange {
    FullSection(String),
}

/// 保护结果
#[derive(Debug, Clone)]
pub struct ProtectResult {
    pub protected_instructions: usize,
}

/// VMP 保护器
pub struct VmpProtector {
    config: ProtectConfig,
}

impl VmpProtector {
    pub fn new() -> Self {
        Self::with_config(ProtectConfig::default())
    }

    pub fn with_config(config: ProtectConfig) -> Self {
        Self { config }
    }

    pub fn protect_file<P: AsRef<Path>>(
        &self,
        input_path: P,
        _output_path: P,
        ranges: Vec<ProtectRange>,
    ) -> Result<ProtectResult> {
        let pe_file = PeFile::load(&input_path)?;
        let code_bytes = self.extract_code(&pe_file, &ranges)?;
        let ir_instructions = self.bytes_to_ir(&code_bytes)?;

        // TODO: 插入纯代码生成式的 VM 编译器与解释器生成逻辑

        Ok(ProtectResult {
            protected_instructions: ir_instructions.len(),
        })
    }

    pub fn protect_data(
        &self,
        pe_data: &[u8],
        ranges: Vec<ProtectRange>,
    ) -> Result<(Vec<u8>, ProtectResult)> {
        // TODO: 实现内存级保护
        Err(VmpError::vm_error("Not implemented yet".to_string()))
    }

    fn extract_code(&self, pe_file: &PeFile, ranges: &[ProtectRange]) -> Result<Vec<u8>> {
        let mut code_bytes = Vec::new();
        for range in ranges {
            match range {
                ProtectRange::FullSection(name) => {
                    if let Some(pe) = pe_file.pe() {
                        for section in &pe.sections {
                            let section_name = String::from_utf8_lossy(&section.name)
                                .trim_end_matches('\0')
                                .to_string();
                            if section_name == *name {
                                let rva = section.virtual_address as u64;
                                let size = section.virtual_size as usize;
                                if let Some(bytes) = pe_file.read_at_rva(rva, size) {
                                    code_bytes.extend_from_slice(bytes);
                                }
                                break;
                            }
                        }
                    }
                }
                _ => return Err(VmpError::vm_error("Range type not implemented".to_string())),
            }
        }
        Ok(code_bytes)
    }

    fn bytes_to_ir(&self, code_bytes: &[u8]) -> Result<Vec<IrInstruction>> {
        disassemble_to_ir(code_bytes, self.config.mode, 0x401000)
            .map_err(|e| VmpError::vm_error(format!("Disassembly failed: {:?}", e)))
    }
}

impl Default for VmpProtector {
    fn default() -> Self {
        Self::new()
    }
}

pub fn protect_file<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
    ranges: Vec<ProtectRange>,
) -> Result<ProtectResult> {
    let protector = VmpProtector::new();
    protector.protect_file(input_path, output_path, ranges)
}

pub fn protect_data(
    pe_data: &[u8],
    ranges: Vec<ProtectRange>,
) -> Result<(Vec<u8>, ProtectResult)> {
    let protector = VmpProtector::new();
    protector.protect_data(pe_data, ranges)
}
