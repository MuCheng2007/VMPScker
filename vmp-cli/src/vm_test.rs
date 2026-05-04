use vmp_core::pe::file::PeFile;
use vmp_core::pe::vmp_marker_finder::{VmpMarkerFinder, VmpMarkerType};
use vmp_core::intel::{disassemble_to_ir, DisassemblyMode};
use vmp_core::vm::arch::ArchConfig;
use vmp_core::vm::compiler::BytecodeCompiler;
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
    
    // 初始化加密架构
    let arch_config = ArchConfig::new_random();
    println!("\n=== VMProtect 加密架构初始化 ===");
    println!("Initial Key: {:08X}", arch_config.initial_crypt_key);
    
    // 显示加密链
    println!("\n=== 加密链配置 ===");
    for (i, op) in arch_config.opcode_cryptor.ops.iter().enumerate() {
        println!("  [{}] {:?}", i, op);
    }
    
    for (i, pair) in virt_pairs.iter().enumerate() {
        println!("\n=== 测试虚拟化标记 #{} ===", i + 1);
        println!("Begin RVA: 0x{:08X}", pair.begin.call_rva);
        println!("Code Range: 0x{:08X} - 0x{:08X} ({} bytes)", 
            pair.code_start, pair.code_end, pair.code_end - pair.code_start);
        
        // 提取标记范围内的代码
        let code_bytes = finder.read_protected_code(&pe_file, pair)?;
        if !code_bytes.is_empty() {
            test_advanced_vm_pipeline(&pe_file, &code_bytes, pair.code_start, disasm_mode)?;
            
            // 对标记进行虚拟标记加密
            println!("\n=== 虚拟标记加密 ===");
            encrypt_virtual_markers(&arch_config, pair.code_start, pair.code_end);
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

    println!("\n【阶段 2】初始化 ArchConfig 架构");
    let arch_config = ArchConfig::new_random();
    println!("  Initial Crypt Key: {:#X}", arch_config.initial_crypt_key);

    println!("\n【阶段 3】编译至加密 VM 字节码");
    let compiler = BytecodeCompiler::new(&arch_config);
    
    // 创建简单的 VM IR 序列用于测试
    let mut vm_ir = Vec::new();
    vm_ir.push(VmOpcode::VPushImm32(0x12345678));
    vm_ir.push(VmOpcode::VPushImm32(0x87654321));
    vm_ir.push(VmOpcode::VAdd);
    vm_ir.push(VmOpcode::VNand);
    vm_ir.push(VmOpcode::VExit);
    
    let bytecode = compiler.compile_block(&vm_ir);
    println!("  生成字节码大小: {} bytes", bytecode.len());
    println!("  字节码前16字节: {:02X?}", &bytecode[..bytecode.len().min(16)]);
    
    Ok(())
}

/// 对虚拟标记进行加密
fn encrypt_virtual_markers(arch: &ArchConfig, code_start: u64, code_end: u64) {
    println!("  加密范围: 0x{:08X} - 0x{:08X}", code_start, code_end);
    
    let compiler = BytecodeCompiler::new(arch);
    let mut vm_ir = Vec::new();
    
    // 将地址转换为字节码序列
    let start_low = code_start as u32;
    let start_high = (code_start >> 32) as u32;
    let end_low = code_end as u32;
    let end_high = (code_end >> 32) as u32;
    
    // 构建加密序列
    vm_ir.push(VmOpcode::VPushImm32(start_low));
    vm_ir.push(VmOpcode::VPushImm32(start_high));
    vm_ir.push(VmOpcode::VXor);
    vm_ir.push(VmOpcode::VPushImm32(end_low));
    vm_ir.push(VmOpcode::VPushImm32(end_high));
    vm_ir.push(VmOpcode::VXor);
    vm_ir.push(VmOpcode::VNand);
    vm_ir.push(VmOpcode::VPushImm32(arch.initial_crypt_key));
    vm_ir.push(VmOpcode::VXor);
    vm_ir.push(VmOpcode::VExit);
    
    let encrypted = compiler.compile_block(&vm_ir);
    
    println!("  原始标记大小: {} 字节", (code_end - code_start) as usize);
    println!("  加密后大小: {} 字节", encrypted.len());
    println!("  加密数据: {:02X?}", &encrypted[..encrypted.len().min(32)]);
    
    // 使用加密链对地址进行额外加密
    let encrypted_start = arch.opcode_cryptor.encrypt(start_low, arch.initial_crypt_key);
    let encrypted_end = arch.opcode_cryptor.encrypt(end_low, encrypted_start);
    
    println!("  加密后的起始地址: {:08X}", encrypted_start);
    println!("  加密后的结束地址: {:08X}", encrypted_end);
}

/// 运行导入表加密测试
pub fn run_import_encryption_test(input: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    println!("正在加载 PE 文件: {:?}", input);
    let pe_file = PeFile::load(&input)?;
    
    if let Some(pe) = pe_file.pe() {
        println!("PE file loaded successfully");
        println!("Machine: {:04X}", pe.header.coff_header.machine);
        println!("Number of sections: {}", pe.sections.len());
        
        // 初始化加密架构
        let arch_config = ArchConfig::new_random();
        println!("\n=== VMProtect 加密架构初始化 ===");
        println!("Initial Key: {:08X}", arch_config.initial_crypt_key);
        
        // 显示加密链
        println!("\n=== 加密链配置 ===");
        for (i, op) in arch_config.opcode_cryptor.ops.iter().enumerate() {
            println!("  [{}] {:?}", i, op);
        }
        
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
                                    let compiler = BytecodeCompiler::new(&arch_config);
                                    
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
                                                    vm_ir.push(VmOpcode::VPushImm32(byte as u32));
                                                    
                                                    // 每4个字节执行一次 XOR 混淆
                                                    if j % 4 == 3 {
                                                        vm_ir.push(VmOpcode::VXor);
                                                    }
                                                }
                                                
                                                // 添加结束标记
                                                vm_ir.push(VmOpcode::VPushImm32(0xDEADBEEF));
                                                vm_ir.push(VmOpcode::VNand);
                                                
                                                // 编译为加密字节码
                                                let encrypted_bytecode = compiler.compile_block(&vm_ir);
                                                
                                                println!("        -> 原始长度: {} 字节", func_name.len());
                                                println!("        -> 加密后长度: {} 字节", encrypted_bytecode.len());
                                                println!("        -> 加密数据 (前16字节): {:02X?}", 
                                                    &encrypted_bytecode[..encrypted_bytecode.len().min(16)]);
                                                
                                                // 使用加密链对 RVA 进行加密
                                                let encrypted_rva = arch_config.opcode_cryptor.encrypt(
                                                    thunk_rva as u32, 
                                                    arch_config.initial_crypt_key
                                                );
                                                println!("        -> 原始 RVA: {:08X}", thunk_rva);
                                                println!("        -> 加密 RVA: {:08X}", encrypted_rva);
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                        
                        println!("\n=== 虚拟标记加密完成 ===");
                        println!("所有 VMP 导入函数已使用滚动密钥加密");
                        println!("加密密钥流: {:08X} -> ...", arch_config.initial_crypt_key);
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
    let finder = VmpMarkerFinder::with_mode(DisassemblyMode::Mode64);
    let pairs = finder.find_marker_pairs(&pe_file)?;

    let virt_pair = pairs.iter()
        .find(|p| {
            p.begin.marker_type == VmpMarkerType::Virtualization ||
            p.begin.marker_type == VmpMarkerType::Begin
        });

    let (code_bytes, code_start, code_end) = match virt_pair {
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
            (code_bytes, pair.code_start, pair.code_end)
        }
        None => {
            println!("  未找到虚拟化标记！OEP 不加密，跳过保护。");
            println!("  提示：请在源代码中添加 VMProtectBeginVirtualization/VMProtectEnd 标记。");
            return Ok(());
        }
    };

    // 3. 反汇编并降级为 VM IR
    println!("\n[3/7] 反汇编并降级为 VM IR...");
    let ir_instructions = disassemble_to_ir(&code_bytes, DisassemblyMode::Mode64, code_start)?;
    println!("  反汇编指令数: {} 条", ir_instructions.len());

    let mut nodes: Vec<InstNode> = ir_instructions.into_iter()
        .map(|ir| InstNode {
            rva: ir.rva,
            native_inst: None,
            x86_ir: Some(ir),
            liveness: Default::default(),
            vm_ir: Vec::new(),
            is_junk: false,
        })
        .collect();

    LoweringPass::run_with_range(&mut nodes, code_start, code_end);

    let mut all_vm_ir = Vec::new();
    for node in &nodes {
        all_vm_ir.extend_from_slice(&node.vm_ir);
    }
    all_vm_ir.push(VmOpcode::VExit);

    println!("  VM IR 指令数: {} 条", all_vm_ir.len());

    // 4. 初始化架构并编译字节码
    println!("\n[4/7] 编译 VM 字节码...");
    let arch_config = ArchConfig::new_random();
    println!("  Initial Key: {:08X}", arch_config.initial_crypt_key);

    let compiler = BytecodeCompiler::new(&arch_config);
    let bytecode = compiler.compile_block(&all_vm_ir);
    println!("  字节码大小: {} 字节", bytecode.len());

    // 5. 计算新节区 RVA 并构建 VM 载荷
    println!("\n[5/7] 构建 VM 载荷...");
    let section_alignment = 0x1000u64;
    let image_base = pe_file.image_base();

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
    // VM 退出后跳转到被保护代码之后的下一条指令（不是 OEP）
    let return_va = image_base + code_end;
    println!("  .vmp0 VA: 0x{:016X}", new_section_va);
    println!("  VM 返回地址: 0x{:016X} (code_end)", return_va);

    let vm_payload = VmPayload::build(&arch_config, &bytecode, new_section_va, return_va)?;
    println!("  VM 载荷大小: {} 字节", vm_payload.binary_data.len());
    println!("  VM Entry 偏移: 0x{:08X}", vm_payload.entry_offset);

    // 6. 重建 PE 文件（不修改入口点）
    println!("\n[6/7] 重建 PE 文件...");
    let mut rebuilder = PeRebuilder::new(pe_file);

    let vmp_section = NewSection::new(".vmp0", vm_payload.binary_data.clone())
        .as_code()
        .with_characteristics(0xE0000060);
    rebuilder.add_section(vmp_section);
    // 注意：不调用 set_entry_point，保持原始 OEP

    let mut new_pe_bytes = rebuilder.rebuild()?;

    // 7. 在新 PE 中修补被保护区域的起始位置：替换为 jmp VM_Entry
    println!("[7/7] 修补被保护区域跳转...");
    let vm_entry_rva = new_section_rva + vm_payload.entry_offset as u64;
    println!("  VM Entry RVA: 0x{:08X}", vm_entry_rva);

    // 重新加载新 PE 来获取正确的节区映射
    let new_pe = PeFile::new(new_pe_bytes.clone())?;
    let code_start_offset = new_pe.rva_to_offset(code_start)
        .ok_or("Cannot locate code_start in rebuilt PE")? as usize;

    // 计算相对偏移: target - (patch_addr + 5)
    // patch_addr = image_base + code_start
    // target = image_base + vm_entry_rva
    let patch_va = image_base + code_start;
    let target_va = image_base + vm_entry_rva;
    let rel_offset = (target_va as i64) - (patch_va as i64) - 5;

    if rel_offset >= i32::MIN as i64 && rel_offset <= i32::MAX as i64 {
        // 修补: E9 xx xx xx xx (near relative jmp)
        new_pe_bytes[code_start_offset] = 0xE9;
        new_pe_bytes[code_start_offset + 1..code_start_offset + 5]
            .copy_from_slice(&(rel_offset as i32).to_le_bytes());
        // NOP 填充剩余的原始代码区域（防止 CPU 执行到原始代码）
        let patch_end = code_start_offset + 5;
        let code_end_offset = new_pe.rva_to_offset(code_end)
            .ok_or("Cannot locate code_end in rebuilt PE")? as usize;
        let clear_end = code_end_offset.min(new_pe_bytes.len());
        if patch_end < clear_end {
            for byte in &mut new_pe_bytes[patch_end..clear_end] {
                *byte = 0x90;
            }
        }
        println!("  已修补: 0x{:08X} -> jmp 0x{:016X}", code_start, target_va);
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
    println!("滚动密钥: {:08X}", arch_config.initial_crypt_key);

    Ok(())
}
