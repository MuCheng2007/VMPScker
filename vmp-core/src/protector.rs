//! VMP 保护器
//!
//! 提供 VMProtect 保护流程。
//! 仅加密 VM 标记保护的区域，OEP 保持不变。

use crate::error::{Result, VmpError};
use crate::intel::{disassemble_to_ir, DisassemblyMode};
use crate::pe::file::PeFile;
use crate::pe::vmp_marker_finder::{VmpMarkerFinder, VmpMarkerType};
use crate::pe::rebuilder::{PeRebuilder, NewSection};
use crate::pipeline::node::InstNode;
use crate::pipeline::lowering::LoweringPass;
use crate::vm::arch::ArchConfig;
use crate::vm::compiler::BytecodeCompiler;
use crate::vm::opcode::VmOpcode;
use crate::vm::assembler::VmPayload;
use std::path::Path;

fn align_up(value: u64, alignment: u64) -> u64 {
    ((value + alignment - 1) / alignment) * alignment
}

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
    pub vm_ir_count: usize,
    pub bytecode_size: usize,
    pub payload_size: usize,
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
        output_path: P,
        _ranges: Vec<ProtectRange>,
    ) -> Result<ProtectResult> {
        let pe_file = PeFile::load(&input_path)?;
        let image_base = pe_file.image_base();

        // 1. 查找 VMP 标记
        let finder = VmpMarkerFinder::with_mode(self.config.mode);
        let pairs = finder.find_marker_pairs(&pe_file)?;

        let virt_pair = pairs.iter().find(|p| {
            p.begin.marker_type == VmpMarkerType::Virtualization
                || p.begin.marker_type == VmpMarkerType::Begin
                || p.begin.marker_type == VmpMarkerType::Ultra
        });

        let (code_bytes, code_start, code_end) = match virt_pair {
            Some(pair) => {
                let code_bytes = finder.read_protected_code(&pe_file, pair)?;
                if code_bytes.is_empty() {
                    return Err(VmpError::vm_error("Empty protected code block".to_string()));
                }
                (code_bytes, pair.code_start, pair.code_end)
            }
            None => {
                return Err(VmpError::vm_error(
                    "No VMProtect markers found. Add VMProtectBeginVirtualization/VMProtectEnd markers to your code.".to_string()
                ));
            }
        };

        // 2. 反汇编并降级为 VM IR
        let ir_instructions = disassemble_to_ir(&code_bytes, self.config.mode, code_start)
            .map_err(|e| VmpError::vm_error(format!("Disassembly failed: {:?}", e)))?;

        let mut nodes: Vec<InstNode> = ir_instructions
            .into_iter()
            .map(|ir| InstNode {
                rva: ir.rva,
                native_inst: None,
                x86_ir: Some(ir),
                liveness: Default::default(),
                vm_ir: Vec::new(),
                is_junk: false,
            })
            .collect();

        LoweringPass::run_with_range_and_base(&mut nodes, code_start, code_end, image_base);

        let mut all_vm_ir = Vec::new();
        for node in &nodes {
            all_vm_ir.extend_from_slice(&node.vm_ir);
        }
        all_vm_ir.push(VmOpcode::VExit);

        // 3. 编译字节码
        let arch_config = ArchConfig::new_random();
        let compiler = BytecodeCompiler::new(&arch_config);
        let bytecode = compiler.compile_block(&all_vm_ir);

        // 4. 构建 VM 载荷
        let section_alignment = 0x1000u64;
        let new_section_rva = if let Some(pe) = pe_file.pe() {
            if let Some(last_sec) = pe.sections.last() {
                let end = last_sec.virtual_address as u64 + last_sec.virtual_size as u64;
                align_up(end, section_alignment)
            } else {
                0x10000
            }
        } else {
            0x10000
        };

        let new_section_va = image_base + new_section_rva;
        let return_va = image_base + code_end;

        let vm_payload = VmPayload::build(&arch_config, &bytecode, new_section_va, return_va)
            .map_err(|e| VmpError::vm_error(format!("VM payload build failed: {:?}", e)))?;

        // 5. 重建 PE（不修改入口点）
        let mut rebuilder = PeRebuilder::new(pe_file);
        let vmp_section = NewSection::new(".vmp0", vm_payload.binary_data.clone())
            .as_code()
            .with_characteristics(0xE0000060);
        rebuilder.add_section(vmp_section);

        let mut new_pe_bytes = rebuilder.rebuild()?;

        // 6. 修补被保护区域起始位置为 jmp VM_Entry
        let new_pe = PeFile::new(new_pe_bytes.clone())?;
        let vm_entry_rva = new_section_rva + vm_payload.entry_offset as u64;
        let code_start_offset = new_pe
            .rva_to_offset(code_start)
            .ok_or_else(|| VmpError::vm_error("Cannot locate code_start in rebuilt PE"))?
            as usize;

        let patch_va = image_base + code_start;
        let target_va = image_base + vm_entry_rva;
        let rel_offset = (target_va as i64) - (patch_va as i64) - 5;

        if rel_offset < i32::MIN as i64 || rel_offset > i32::MAX as i64 {
            return Err(VmpError::vm_error("Jump offset exceeds 32-bit range".to_string()));
        }

        new_pe_bytes[code_start_offset] = 0xE9;
        new_pe_bytes[code_start_offset + 1..code_start_offset + 5]
            .copy_from_slice(&(rel_offset as i32).to_le_bytes());

        let patch_end = code_start_offset + 5;
        let code_end_offset = new_pe
            .rva_to_offset(code_end)
            .ok_or_else(|| VmpError::vm_error("Cannot locate code_end in rebuilt PE"))?
            as usize;
        let clear_end = code_end_offset.min(new_pe_bytes.len());
        if patch_end < clear_end {
            for byte in &mut new_pe_bytes[patch_end..clear_end] {
                *byte = 0x90;
            }
        }

        // 7. 写入文件
        std::fs::write(output_path, new_pe_bytes)?;

        Ok(ProtectResult {
            protected_instructions: nodes.len(),
            vm_ir_count: all_vm_ir.len(),
            bytecode_size: bytecode.len(),
            payload_size: vm_payload.binary_data.len(),
        })
    }

    pub fn protect_data(
        &self,
        _pe_data: &[u8],
        _ranges: Vec<ProtectRange>,
    ) -> Result<(Vec<u8>, ProtectResult)> {
        Err(VmpError::vm_error("Not implemented yet".to_string()))
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
