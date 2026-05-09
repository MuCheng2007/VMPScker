//! VMP 保护器
//!
//! 提供 VMProtect 保护流程。
//! 仅加密 VM 标记保护的区域，OEP 保持不变。

use crate::error::{Result, VmpError};
use crate::intel::{disassemble, disassemble_to_ir, DisassemblyMode};
use crate::pe::file::PeFile;
use crate::pe::vmp_marker_finder::{VmpMarkerFinder, VmpMarkerType};
use crate::pe::rebuilder::{PeRebuilder, NewSection};
use crate::pipeline::node::InstNode;
use crate::pipeline::lowering::LoweringPass;
use crate::vm::arch::ArchConfig;
use crate::vm::compiler::BytecodeCompiler;
use crate::vm::opcode::VmOpcode;
use crate::vm::ir::VmInstruction;
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

        // Select the first matching pair.
        // The marker pairs are in address order. With LIFO stack pairing,
        // the first pair typically corresponds to the outermost function (main).
        // Note: the JMP-aware finder may produce additional pairs for inner functions,
        // but main's pair remains first because its Begin marker has the lowest address.
        let virt_pair = pairs.iter().find(|p| {
            p.begin.marker_type == VmpMarkerType::Virtualization
                || p.begin.marker_type == VmpMarkerType::Begin
                || p.begin.marker_type == VmpMarkerType::Ultra
        });

        let (code_bytes, code_start, code_end, begin_call_rva, end_call_rva) = match virt_pair {
            Some(pair) => {
                let code_bytes = finder.read_protected_code(&pe_file, pair)?;
                if code_bytes.is_empty() {
                    return Err(VmpError::vm_error("Empty protected code block".to_string()));
                }
                (code_bytes, pair.code_start, pair.code_end, pair.begin.call_rva, pair.end.call_rva)
            }
            None => {
                return Err(VmpError::vm_error(
                    "No VMProtect markers found. Add VMProtectBeginVirtualization/VMProtectEnd markers to your code.".to_string()
                ));
            }
        };

        // 2. 反汇编并降级为 VM IR
        eprintln!("[DEBUG protect] image_base=0x{:X}, code_start=0x{:X}, code_end=0x{:X}, code_bytes.len()=0x{:X}", image_base, code_start, code_end, code_bytes.len());
        let ir_instructions = disassemble_to_ir(&code_bytes, self.config.mode, code_start)
            .map_err(|e| VmpError::vm_error(format!("Disassembly failed: {:?}", e)))?;
        let raw_instructions = disassemble(&code_bytes, self.config.mode, code_start)
            .map_err(|e| VmpError::vm_error(format!("Disassembly failed: {:?}", e)))?;

        // Build RVA → native_inst map for correct pairing (IR converter emits Comment
        // pseudo-instructions that share RVAs with real IR opcodes)
        let native_by_rva: std::collections::HashMap<u64, iced_x86::Instruction> = raw_instructions
            .iter()
            .map(|inst| (inst.ip(), inst.iced().clone()))
            .collect();

        let mut nodes: Vec<InstNode> = Vec::new();
        for ir_inst in &ir_instructions {
            // Skip Comment pseudo-instructions — they are annotations, not executable IR
            if matches!(&ir_inst.opcode, crate::intel::ir::IrOpcode::Comment { .. }) {
                continue;
            }
            let native_inst = native_by_rva.get(&ir_inst.rva).cloned();
            nodes.push(InstNode {
                rva: ir_inst.rva,
                native_inst,
                x86_ir: Some(ir_inst.clone()),
                liveness: Default::default(),
                vm_ir: Vec::new(),
                is_junk: false,
            });
        }

        // 3. 计算返回地址 (VM 退出后的目标)
        let end_call_size = finder.get_call_instruction_size(&pe_file, end_call_rva).unwrap_or(5);
        let return_va = image_base + code_end + end_call_size;

        // 4. 执行降级操作，将 x86 指令映射为 VM IR 或 Island
        LoweringPass::run_with_range_and_base(&mut nodes, code_start, code_end, image_base);

        let mut all_vm_ir: Vec<VmInstruction> = Vec::new();
        for node in &nodes {
            all_vm_ir.extend_from_slice(&node.vm_ir);
        }

        // 最终退出序列：手动把 return_va 推入虚拟栈，然后触发 VExit
        // VExit 从虚拟栈弹出返回地址并跳转过去
        all_vm_ir.push(VmInstruction::new(VmOpcode::VPushImm64(return_va)));
        all_vm_ir.push(VmInstruction::new(VmOpcode::VExit));

        // Debug: print all VM IR opcodes
        eprintln!("[VM] Total VM IR count: {}", all_vm_ir.len());
        for (i, ir) in all_vm_ir.iter().enumerate() {
            eprintln!("[VM]   [{:3}] {:?}", i, ir);
        }

        // 5. 编译字节码
        let arch_config = ArchConfig::new_default();
        let compiler = BytecodeCompiler::new();
        let (bytecode, islands) = compiler.compile_block(&all_vm_ir);

        // 6. 构建 VM 载荷
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

        let vm_payload = VmPayload::build(&arch_config, &bytecode, &islands, new_section_va, return_va, image_base)
            .map_err(|e| VmpError::vm_error(format!("VM payload build failed: {:?}", e)))?;

        // 7. 重建 PE（不修改入口点）
        let mut rebuilder = PeRebuilder::new(pe_file);
        let vmp_section = NewSection::new(".vmp0", vm_payload.binary_data.clone())
            .as_code()
            .with_characteristics(0xE0000060);
        rebuilder.add_section(vmp_section);

        let mut new_pe_bytes = rebuilder.rebuild()?;

        // 8. 修补 BEGIN 标记的 CALL：call [IAT] → jmp VM_Entry
        //    原始: FF 15 xx xx xx xx (6字节 IAT call)
        //    替换: E9 xx xx xx xx 90 (5字节 direct jmp + 1字节 NOP)
        //    使用 JMP 而非 CALL：避免在原生栈上压入返回地址，
        //    确保 Native Fallback 中执行的原生代码看到的 RSP 与保护前完全一致。
        let new_pe = PeFile::new(new_pe_bytes.clone())?;
        let vm_entry_rva = new_section_rva + vm_payload.entry_offset as u64;

        let begin_call_offset = new_pe
            .rva_to_offset(begin_call_rva)
            .ok_or_else(|| VmpError::vm_error("Cannot locate begin CALL in rebuilt PE"))?
            as usize;

        let patch_va = image_base + begin_call_rva;
        let target_va = image_base + vm_entry_rva;
        let rel_offset = (target_va as i64) - (patch_va as i64) - 5;

        if rel_offset < i32::MIN as i64 || rel_offset > i32::MAX as i64 {
            return Err(VmpError::vm_error("Jump offset exceeds 32-bit range".to_string()));
        }

        new_pe_bytes[begin_call_offset] = 0xE9;
        new_pe_bytes[begin_call_offset + 1..begin_call_offset + 5]
            .copy_from_slice(&(rel_offset as i32).to_le_bytes());
        if begin_call_offset + 5 < new_pe_bytes.len() {
            new_pe_bytes[begin_call_offset + 5] = 0x90; // NOP the 6th byte
        }
        eprintln!("[VM] Patched CALL at 0x{:X}: jmp VM_Entry 0x{:X}", begin_call_rva, target_va);

        // 9. 修补 .pdata：零化覆盖被保护代码范围的 RUNTIME_FUNCTION 条目
        // 否则 Windows 栈展开会使用失效的 unwind 信息导致崩溃
        {
            let new_pe2 = PeFile::new(new_pe_bytes.clone())?;
            if let Some(ref pe2) = new_pe2.pe() {
                if let Some(optional_header) = pe2.header.optional_header {
                    let dirs = &optional_header.data_directories.data_directories;
                    // 索引 3 = Exception Directory (.pdata)
                    if let Some(Some((_, exception_dir))) = dirs.get(3) {
                        let pdata_rva = exception_dir.virtual_address as u64;
                        let pdata_size = exception_dir.size as u64;
                        if let Some(pdata_file_offset) = new_pe2.rva_to_offset(pdata_rva) {
                            let entry_size: u64 = 12; // RUNTIME_FUNCTION for x64
                            let count = pdata_size / entry_size;
                            for i in 0..count {
                                let entry_off = pdata_file_offset as usize + (i * entry_size) as usize;
                                if entry_off + 12 > new_pe_bytes.len() { break; }
                                let begin = u32::from_le_bytes([
                                    new_pe_bytes[entry_off], new_pe_bytes[entry_off+1],
                                    new_pe_bytes[entry_off+2], new_pe_bytes[entry_off+3],
                                ]);
                                let end = u32::from_le_bytes([
                                    new_pe_bytes[entry_off+4], new_pe_bytes[entry_off+5],
                                    new_pe_bytes[entry_off+6], new_pe_bytes[entry_off+7],
                                ]);
                                // 如果该 RUNTIME_FUNCTION 覆盖了被保护代码范围，零化它
                                if begin < code_end as u32 && end > code_start as u32 {
                                    eprintln!("[VM] Zeroing .pdata entry #{i}: 0x{begin:X}..0x{end:X} (overlaps protected range 0x{code_start:X}..0x{code_end:X})");
                                    for b in &mut new_pe_bytes[entry_off..entry_off+12] {
                                        *b = 0;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 10. 写入文件
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
