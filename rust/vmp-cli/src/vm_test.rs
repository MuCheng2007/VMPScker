use vmp_core::pe::file::PeFile;
use vmp_core::pe::vmp_marker_finder::{VmpMarkerFinder, VmpMarkerType};
use vmp_core::intel::{disassemble_to_ir, DisassemblyMode};
use vmp_core::vm::arch::ArchConfig;
use vmp_core::vm::compiler::BytecodeCompiler;
use vmp_core::vm::ir::VmInstruction;
use vmp_core::vm::opcode::VmOpcode;
use vmp_core::vm::assembler::VmPayload;
use vmp_core::pipeline::node::InstNode;
use vmp_core::pipeline::lowering::LoweringPass;
use vmp_core::pe::rebuilder::{PeRebuilder, NewSection};
use std::path::PathBuf;

/// 运行 VM 转换测试
pub fn run_test(input: PathBuf, mode_str: String) -> Result<(), Box<dyn std::error::Error>> {
    let disasm_mode = match mode_str.as_str() {
        "16" => DisassemblyMode::Mode16,
        "32" => DisassemblyMode::Mode32,
        "64" => DisassemblyMode::Mode64,
        _ => DisassemblyMode::Mode64,
    };

    println!("正在加载 PE 文件: {:?}", input);
    let pe_file = PeFile::load(&input)?;
    
    // 1. 探测标记
    println!("正在探测虚拟化标记...");
    let finder = VmpMarkerFinder::with_mode(disasm_mode);
    let pairs = finder.find_marker_pairs(&pe_file)?;
    
    // 过滤出虚拟化标记
    let virt_pairs: Vec<_> = pairs.iter()
        .filter(|p| p.begin.marker_type == VmpMarkerType::Virtualization || 
                    p.begin.marker_type == VmpMarkerType::Begin)
        .collect();

    if virt_pairs.is_empty() {
        println!("未找到虚拟化标记，尝试运行内置测试用例...");
        
        // 构造一个测试代码: mov rax, 1; add rax, 2; ret
        let mut test_code = vec![0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00]; // mov rax, 1
        test_code.extend_from_slice(&[0x48, 0x83, 0xC0, 0x02]);           // add rax, 2
        test_code.extend_from_slice(&[0xC3]);                             // ret
        
        test_advanced_vm_pipeline(&pe_file, &test_code, 0x1000, disasm_mode)?;
        return Ok(());
    }
    
    println!("找到 {} 个标记对\n", virt_pairs.len());
    
    println!("\n=== VM 架构初始化 (简化明文版) ===");

    for (i, pair) in virt_pairs.iter().enumerate() {
        println!("\n=== 测试虚拟化标记 #{} ===", i + 1);
        println!("Begin RVA: 0x{:08X}", pair.begin.call_rva);
        println!("Code Range: 0x{:08X} - 0x{:08X} ({} bytes)",
            pair.code_start, pair.code_end, pair.code_end - pair.code_start);

        // 提取标记范围内的代码
        let code_bytes = finder.read_protected_code(&pe_file, pair)?;
        if !code_bytes.is_empty() {
            test_advanced_vm_pipeline(&pe_file, &code_bytes, pair.code_start, disasm_mode)?;
        } else {
            println!("  跳过空代码块");
        }
    }

    Ok(())
}

fn test_advanced_vm_pipeline(_pe_file: &PeFile, code_bytes: &[u8], base_rva: u64, mode: DisassemblyMode) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n【阶段 1】反汇编原始机器码");
    let ir_instructions = disassemble_to_ir(code_bytes, mode, base_rva)?;
    println!("  解码指令数: {} 条", ir_instructions.len());

    println!("\n【阶段 2】编译至明文 VM 字节码");
    let compiler = BytecodeCompiler::new();

    // 创建简单的 VM IR 序列用于测试
    let mut vm_ir = Vec::new();
    vm_ir.push(VmInstruction::new(VmOpcode::VPushImm32(0x12345678)));
    vm_ir.push(VmInstruction::new(VmOpcode::VPushImm32(0x87654321)));
    vm_ir.push(VmInstruction::new(VmOpcode::VAdd));
    vm_ir.push(VmInstruction::new(VmOpcode::VNand));
    vm_ir.push(VmInstruction::new(VmOpcode::VExit));

    let (bytecode, _) = compiler.compile_block(&vm_ir);
    println!("  生成字节码大小: {} bytes", bytecode.len());
    println!("  字节码前16字节: {:02X?}", &bytecode[..bytecode.len().min(16)]);

    Ok(())
}

/// 运行导入表加密测试
pub fn run_import_encryption_test(input: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    println!("正在加载 PE 文件: {:?}", input);
    let pe_file = PeFile::load(&input)?;
    
    if let Some(pe) = pe_file.pe() {
        println!("PE file loaded successfully");
        println!("Machine: {:04X}", pe.header.coff_header.machine);
        println!("Number of sections: {}", pe.sections.len());
        
        println!("\n=== VM 架构 (简化明文版) ===");

        // 检查导入表
        if let Some(optional_header) = pe.header.optional_header {
            let data_dirs = &optional_header.data_directories;
            println!("\nData directories count: {}", data_dirs.data_directories.len());
            
            // 导入表是第2个数据目录（索引1）
            let import_dir_index = 1;
            if let Some(Some((_, import_dir))) = data_dirs.data_directories.get(import_dir_index) {
                println!("Import directory found:");
                println!("  Virtual Address: {:08X}", import_dir.virtual_address);
                println!("  Size: {:08X}", import_dir.size);
                
                // 尝试解析导入表
                use goblin::pe::import::ImportData;
                let file_data = pe_file.data();
                let file_alignment = optional_header.windows_fields.file_alignment;
                let is_64bit = pe.header.coff_header.machine == goblin::pe::header::COFF_MACHINE_X86_64;
                
                println!("\nFile alignment: {}", file_alignment);
                println!("Is 64-bit: {}", is_64bit);
                
                let import_result = if is_64bit {
                    ImportData::parse::<u64>(file_data, *import_dir, &pe.sections, file_alignment)
                } else {
                    ImportData::parse::<u32>(file_data, *import_dir, &pe.sections, file_alignment)
                };
                
                match import_result {
                    Ok(import_data) => {
                        println!("\nImport data parsed successfully");
                        println!("Number of import entries: {}", import_data.import_data.len());
                        
                        for entry in &import_data.import_data {
                            let dll_name = entry.name.to_string();
                            println!("\n  DLL: {}", dll_name);
                            
                            if dll_name.to_lowercase().contains("vmprotect") {
                                println!("    *** VMP DLL FOUND! ***");
                                let iat_rva = entry.import_directory_entry.import_address_table_rva;
                                println!("    IAT RVA: {:08X}", iat_rva);
                                
                                if let Some(ref lookup_table) = entry.import_lookup_table {
                                    println!("    Number of functions: {}", lookup_table.len());
                                    
                                    // 创建字节码编译器
                                    let compiler = BytecodeCompiler::new();
                                    
                                    for (i, lookup_entry) in lookup_table.iter().enumerate() {
                                        match lookup_entry {
                                            goblin::pe::import::SyntheticImportLookupTableEntry::HintNameTableRVA((_, hint_entry)) => {
                                                let func_name = hint_entry.name.to_string();
                                                let thunk_rva = iat_rva as u64 + (i * 8) as u64;
                                                println!("      [{}] {} @ {:08X}", i, func_name, thunk_rva);
                                                
                                                // 对函数名进行虚拟标记加密
                                                println!("        -> 加密虚拟标记...");
                                                
                                                // 将函数名转换为字节码序列（模拟）
                                                let mut vm_ir = Vec::new();
                                                
                                                // 为每个字符创建 PushImm 指令
                                                for (j, byte) in func_name.bytes().enumerate() {
                                                    vm_ir.push(VmInstruction::new(VmOpcode::VPushImm32(byte as u32)));
                                                    
                                                    // 每4个字节执行一次 XOR 混淆
                                                    if j % 4 == 3 {
                                                        vm_ir.push(VmInstruction::new(VmOpcode::VXor));
                                                    }
                                                }
                                                
                                                // 添加结束标记
                                                vm_ir.push(VmInstruction::new(VmOpcode::VPushImm32(0xDEADBEEF)));
                                                vm_ir.push(VmInstruction::new(VmOpcode::VNand));
                                                
                                                // 编译为字节码
                                                let (encrypted_bytecode, _islands) = compiler.compile_block(&vm_ir);

                                                println!("        -> 原始长度: {} 字节", func_name.len());
                                                println!("        -> 字节码长度: {} 字节", encrypted_bytecode.len());
                                                println!("        -> 字节码数据 (前16字节): {:02X?}",
                                                    &encrypted_bytecode[..encrypted_bytecode.len().min(16)]);

                                                println!("        -> RVA: {:08X}", thunk_rva);
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                        
                        println!("\n=== 虚拟标记编译完成 ===");
                    }
                    Err(e) => {
                        println!("Failed to parse import data: {:?}", e);
                    }
                }
            } else {
                println!("No import directory found");
            }
        }
    }
    
    Ok(())
}

/// 加密 VMProtectBeginVirtualization 标记内的代码并写入 PE 文件
/// 仅加密 VM 标记保护的区域，OEP 保持不变
pub fn encrypt_and_write_pe(input: PathBuf, output: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== VMProtect 代码虚拟化加密工具 ===");
    println!("输入文件: {:?}", input);
    println!("输出文件: {:?}", output);

    // 1. 加载 PE 文件
    println!("\n[1/7] 加载 PE 文件...");
    let pe_file = PeFile::load(&input)?;

    let oep = pe_file.entry_point();
    println!("  原始入口点 (OEP): 0x{:08X}", oep);

    // 2. 查找 VMProtectBeginVirtualization 标记
    println!("[2/7] 查找虚拟化标记...");
    
    // 检测架构
    let is_64bit = if let Some(pe) = pe_file.pe() {
        pe.header.coff_header.machine == goblin::pe::header::COFF_MACHINE_X86_64
    } else {
        true
    };
    let mode = if is_64bit { DisassemblyMode::Mode64 } else { DisassemblyMode::Mode32 };
    println!("  检测到架构: {}", if is_64bit { "x64" } else { "x86" });

    let finder = VmpMarkerFinder::with_mode(mode);
    let pairs = finder.find_marker_pairs(&pe_file)?;

    let virt_pair = pairs.iter()
        .find(|p| {
            p.begin.marker_type == VmpMarkerType::Virtualization ||
            p.begin.marker_type == VmpMarkerType::Begin
        });

    let (code_bytes, code_start, code_end, end_call_rva, begin_call_rva) = match virt_pair {
        Some(pair) => {
            println!("  找到标记:");
            println!("    Begin RVA: 0x{:08X}", pair.begin.call_rva);
            println!("    End RVA: 0x{:08X}", pair.end.call_rva);
            println!("    Code Range: 0x{:08X} - 0x{:08X} ({} bytes)",
                pair.code_start, pair.code_end, pair.code_end - pair.code_start);

            let code_bytes = finder.read_protected_code(&pe_file, pair)?;
            if code_bytes.is_empty() {
                return Err("Empty code block".into());
            }
            println!("  提取代码大小: {} 字节", code_bytes.len());
            (code_bytes, pair.code_start, pair.code_end, pair.end.call_rva, pair.begin.call_rva)
        }
        None => {
            println!("  未找到虚拟化标记！OEP 不加密，跳过保护。");
            println!("  提示：请在源代码中添加 VMProtectBeginVirtualization/VMProtectEnd 标记。");
            return Ok(());
        }
    };

    // 3. 反汇编 → IR → 降级 → 编译字节码
    println!("\n[3/7] 编译 VM 字节码 (逐指令)...");

    let image_base = pe_file.image_base();

    let x86_ir = vmp_core::intel::disassemble_to_ir(&code_bytes, mode, code_start)?;
    let raw_instructions = vmp_core::intel::disassemble(&code_bytes, mode, code_start)?;

    // 创建 pipeline 节点 (每个 x86 指令一个)
    let mut nodes: Vec<InstNode> = Vec::new();
    for (i, ir_inst) in x86_ir.iter().enumerate() {
        if i < raw_instructions.len() {
            nodes.push(InstNode::new(ir_inst.rva, *raw_instructions[i].iced(), ir_inst.clone()));
        }
    }
    println!("  解码指令数: {} 条", nodes.len());

    // 运行降级通道: matched → VM bytecode, unmatched → island (VPushImm64 + VExec)
    LoweringPass::run_with_range_and_base(
        &mut nodes, code_start, code_end, image_base,
    );

    // 收集所有 VM IR + 末尾 VExit
    let mut all_vm_ir: Vec<VmInstruction> = Vec::new();
    for node in &nodes {
        let matched = !node.vm_ir.is_empty();
        all_vm_ir.extend(node.vm_ir.clone());
        if !matched {
            println!("    [unmatched] RVA {:08X} -> island VExec", node.rva);
        }
    }
    all_vm_ir.push(VmInstruction::new(VmOpcode::VExit));

    println!("  VM IR 指令数: {} 条 (+VExit)", all_vm_ir.len() - 1);

    let arch_config = ArchConfig::new_default();
    let compiler = BytecodeCompiler::new();
    let (bytecode, islands) = compiler.compile_block(&all_vm_ir);
    println!("  字节码大小: {} 字节, 孤岛数: {}", bytecode.len(), islands.len());

    // 4. 计算新节区 RVA 并构建 VM 载荷
    println!("\n[4/7] 构建 VM 载荷...");
    let section_alignment = 0x1000u64;

    let new_section_rva = if let Some(pe) = pe_file.pe() {
        if let Some(last_sec) = pe.sections.last() {
            let end = last_sec.virtual_address as u64 + last_sec.virtual_size as u64;
            (end + section_alignment - 1) / section_alignment * section_alignment
        } else {
            0x10000
        }
    } else {
        0x10000
    };

    let new_section_va = image_base + new_section_rva;

    // 跳过 END 标记的 call 指令 (通常 5-6 字节)
    let end_call_size = finder.get_call_instruction_size(&pe_file, end_call_rva)
        .unwrap_or(5);
    let return_va = image_base + code_end + end_call_size;
    println!("  .vmp0 VA: 0x{:016X}", new_section_va);
    println!("  VM 返回地址: 0x{:016X} (code_end + {})", return_va, end_call_size);

    let vm_payload = VmPayload::build(&arch_config, &bytecode, &islands, new_section_va, return_va, image_base)?;
    println!("  VM 载荷大小: {} 字节", vm_payload.binary_data.len());
    println!("  VM Entry 偏移: 0x{:08X}", vm_payload.entry_offset);

    // 5. 重建 PE 文件（不修改入口点）
    println!("\n[5/7] 重建 PE 文件...");
    let mut rebuilder = PeRebuilder::new(pe_file);

    let vmp_section = NewSection::new(".vmp0", vm_payload.binary_data.clone())
        .as_code()
        .with_characteristics(0xE0000060);
    rebuilder.add_section(vmp_section);

    let mut new_pe_bytes = rebuilder.rebuild()?;

    // 6. 修补 BEGIN 标记的 CALL：替换为 call VM_Entry
    //    原始: FF 15 xx xx xx xx (6字节 IAT call)
    //    替换: E8 xx xx xx xx 90 (5字节 direct call + 1字节 NOP)
    //    注意：不破坏被保护区域代码，保持 .text 原样以便 VExec 原地执行
    println!("[6/7] 修补 BEGIN 标记跳转...");
    let vm_entry_rva = new_section_rva + vm_payload.entry_offset as u64;
    println!("  VM Entry RVA: 0x{:08X}", vm_entry_rva);

    let new_pe = PeFile::new(new_pe_bytes.clone())?;

    let begin_call_offset = new_pe.rva_to_offset(begin_call_rva)
        .ok_or("Cannot locate begin call in rebuilt PE")? as usize;

    let patch_va = image_base + begin_call_rva;
    let target_va = image_base + vm_entry_rva;
    let rel_offset = (target_va as i64) - (patch_va as i64) - 5;

    if rel_offset >= i32::MIN as i64 && rel_offset <= i32::MAX as i64 {
        new_pe_bytes[begin_call_offset] = 0xE8;
        new_pe_bytes[begin_call_offset + 1..begin_call_offset + 5]
            .copy_from_slice(&(rel_offset as i32).to_le_bytes());
        if begin_call_offset + 5 < new_pe_bytes.len() {
            new_pe_bytes[begin_call_offset + 5] = 0x90; // NOP the 6th byte
        }
        println!("  已修补: call @ 0x{:08X} -> call VM_Entry @ 0x{:016X}", begin_call_rva, target_va);
    } else {
        return Err("Jump offset exceeds 32-bit range".into());
    }

    // 写入文件
    std::fs::write(&output, &new_pe_bytes)?;
    println!("  已写入: {:?}", output);

    println!("\n=== 加密完成 ===");
    println!("被保护区域: 0x{:08X} - 0x{:08X}", code_start, code_end);
    println!("VM 区域 RVA: 0x{:08X} ({} 字节)", new_section_rva, vm_payload.binary_data.len());
    println!("OEP 保持不变: 0x{:08X}", oep);
    println!("VM 返回地址: 0x{:08X}", code_end);

    Ok(())
}
