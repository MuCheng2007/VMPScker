//! VMP 保护器
//!
//! 提供 VMProtect 保护流程。

use crate::error::{Result, VmpError};
use crate::intel::{disassemble_to_ir, DisassemblyMode};
use crate::intel::ir::IrInstruction;
use crate::pe::file::PeFile;
use crate::vm::arch::{ArchConfig, VMOpcode, VMRegister};
use crate::vm::compiler::VmCompiler;
use crate::vm::cfg::ControlFlowGraph;
use crate::vm::interpreter::InterpreterGenerator;
use crate::vm::handlers::HandlerGenerator;
use crate::pe::rebuilder::{PeRebuilder, NewSection, RebuildConfig};
use iced_x86::code_asm::CodeAssembler;
use std::path::Path;

fn align_up(value: u32, alignment: u32) -> u32 {
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
        ranges: Vec<ProtectRange>,
    ) -> Result<ProtectResult> {
        let pe_file = PeFile::load(&input_path)?;
        let code_bytes = self.extract_code(&pe_file, &ranges)?;
        let ir_instructions = self.bytes_to_ir(&code_bytes)?;

        // 1. 初始化高级架构配置 (随机寄存器映射、指令映射、加密序列)
        let arch_config = ArchConfig::new_random();

        // 2. 构建 CFG 并编译到加密字节码
        let entry_rva = ir_instructions.first().map(|i| i.rva).unwrap_or(0);
        let cfg = ControlFlowGraph::from_ir(&ir_instructions, entry_rva);
        let compiler = VmCompiler::new(&arch_config);
        let bytecode = compiler.compile_cfg(&cfg);

        // 3. 准备代码生成器
        let mut asm = CodeAssembler::new(if pe_file.is_64bit() { 64 } else { 32 }).unwrap();
        let interpreter_gen = InterpreterGenerator::new(&arch_config);
        let handler_gen = HandlerGenerator::new(&arch_config);

        // 4. 动态计算 .vmp0 节区的 RVA 和基址
        let section_alignment = 0x1000;
        let mut new_section_rva = 0;
        if let Some(pe) = pe_file.pe() {
            if let Some(last_sec) = pe.sections.last() {
                new_section_rva = align_up(last_sec.virtual_address as u32 + last_sec.virtual_size, section_alignment);
            }
        }
        if new_section_rva == 0 {
            new_section_rva = 0x10000; // Fallback
        }
        
        let vmp_section_base = pe_file.image_base() + new_section_rva as u64; 
        
        // 我们将 Payload 划分为: [ Interpreter/Handlers 机器码 ] [ HandlerTable ] [ Bytecode ]
        // 先假设机器码大小不超过 0x1000 字节
        let handler_table_offset = 0x1000;
        let bytecode_offset = 0x2000;
        
        let handler_table_base = vmp_section_base + handler_table_offset; 
        let bytecode_address = vmp_section_base + bytecode_offset; 

        // 5. 生成 VMEntry (入口)，并将源 OEP 劫持到这里
        interpreter_gen.generate_vm_entry(&mut asm, bytecode_address, handler_table_base)
            .map_err(|e| VmpError::vm_error(format!("VMEntry generation failed: {:?}", e)))?;

        // 6. 生成核心微指令 Handlers
        handler_gen.gen_push_reg(&mut asm, VMRegister::R0).unwrap();
        handler_gen.gen_pop_reg(&mut asm, VMRegister::R0).unwrap();
        handler_gen.gen_add(&mut asm).unwrap();
        handler_gen.gen_sub(&mut asm).unwrap();
        handler_gen.gen_nor(&mut asm).unwrap();
        handler_gen.gen_nand(&mut asm).unwrap();
        handler_gen.gen_xor(&mut asm).unwrap();
        handler_gen.gen_push_imm32(&mut asm).unwrap();
        handler_gen.gen_push_imm64(&mut asm).unwrap();
        handler_gen.gen_jmp(&mut asm).unwrap();
        handler_gen.gen_vm_exit(&mut asm).unwrap();

        // 7. 生成 VMExit
        interpreter_gen.generate_vm_exit(&mut asm).unwrap();

        // 8. 汇编出最终的机器码 Payload
        let assembled_bytes = asm.assemble(vmp_section_base)
            .map_err(|e| VmpError::vm_error(format!("Assembly failed: {:?}", e)))?;

        // 9. 组装 .vmp0 节区数据
        let mut vmp0_data = vec![0u8; bytecode_offset as usize + bytecode.len()];
        
        // 9.1 写入原生机器码 (Interpreter + Handlers)
        vmp0_data[..assembled_bytes.len()].copy_from_slice(&assembled_bytes);
        
        // 9.2 写入 Handler Table (简化版，在正式版中需要从 asm 提取真实 handler 偏移)
        // 这里只是占位，真实的 Handler Table 必须基于 asm.assemble 后各个 gen_xxx 的实际地址来构建
        
        // 9.3 写入加密字节码
        vmp0_data[bytecode_offset as usize..bytecode_offset as usize + bytecode.len()].copy_from_slice(&bytecode);

        // 10. 使用 PeRebuilder 注入并生成新 PE
        let mut rebuilder = PeRebuilder::new(pe_file);
        
        // 创建 .vmp0 节区 (代码属性)
        let vmp_section = NewSection::new(".vmp0", vmp0_data)
            .as_code()
            .with_characteristics(0xE0000060); // 执行/读/写，包含代码和数据
            
        rebuilder.add_section(vmp_section);
        
        // 劫持 OEP 到我们的 VMEntry
        rebuilder.set_entry_point(new_section_rva as u64);
        
        let new_pe_bytes = rebuilder.rebuild()?;
        
        // 写入到文件
        std::fs::write(output_path, new_pe_bytes)?;
        
        println!("====== VMProtect Compilation Success ======");
        println!("ArchConfig Initial Key: {:#x}", arch_config.initial_crypt_key);
        println!("Compiled Bytecode Size: {} bytes", bytecode.len());
        println!("Generated Interpreter Shellcode Size: {} bytes", assembled_bytes.len());
        println!("New OEP: {:#x}", new_section_rva);
        println!("===========================================");

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
