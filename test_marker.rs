use vmp_core::pe::file::PeFile;
use vmp_core::vm::arch::{ArchConfig, CryptoChain, CryptoOp};
use vmp_core::vm::compiler::BytecodeCompiler;
use vmp_core::vm::opcode::VmOpcode;
use std::collections::HashMap;

fn main() {
    let pe_file = PeFile::load(r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1.exe").unwrap();
    
    if let Some(pe) = pe_file.pe() {
        println!("PE file loaded successfully");
        println!("Machine: {:04X}", pe.header.coff_header.machine);
        println!("Number of sections: {}", pe.sections.len());
        
        // 初始化加密架构
        let arch_config = ArchConfig::new_random();
        println!("\n=== VMProtect 加密架构初始化 ===");
        println!("Initial Key: {:08X}", arch_config.initial_crypt_key);
        println!("VIP Register: {:?}", arch_config.context.vip);
        println!("VSP Register: {:?}", arch_config.context.vsp);
        println!("VKEY Register: {:?}", arch_config.context.vkey);
        
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
}
