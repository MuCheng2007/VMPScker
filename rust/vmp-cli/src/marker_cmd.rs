//! 标记检测命令

use clap::{Parser, Subcommand};
use tracing::{info, error};
use std::path::PathBuf;
use vmp_core::pe::{PeFile, VmpMarkerFinder};
use vmp_core::intel::DisassemblyMode;

#[derive(Parser, Debug)]
pub struct MarkerArgs {
    #[command(subcommand)]
    pub command: MarkerCommands,
}

#[derive(Subcommand, Debug)]
pub enum MarkerCommands {
    /// 检测 PE 文件中的所有 VMP 标记
    #[command(name = "detect")]
    Detect {
        /// 输入 PE 文件
        #[arg(short = 'i', long = "input")]
        input: PathBuf,

        /// 架构模式 (32 或 64)
        #[arg(short = 'm', long = "mode", default_value = "64")]
        mode: String,

        /// 显示保护的汇编代码
        #[arg(short = 'd', long = "disasm")]
        disasm: bool,
    },

    /// 分析标记对
    #[command(name = "pairs")]
    Pairs {
        /// 输入 PE 文件
        #[arg(short = 'i', long = "input")]
        input: PathBuf,

        /// 显示保护的汇编代码
        #[arg(short = 'd', long = "disasm")]
        disasm: bool,
    },

    /// 调试导入表
    #[command(name = "debug")]
    Debug {
        /// 输入 PE 文件
        #[arg(short = 'i', long = "input")]
        input: PathBuf,
    },

    /// 显示虚拟化标记的汇编代码
    #[command(name = "virtualization")]
    Virtualization {
        /// 输入 PE 文件
        #[arg(short = 'i', long = "input")]
        input: PathBuf,

        /// 架构模式 (32 或 64)
        #[arg(short = 'm', long = "mode", default_value = "64")]
        mode: String,
    },
}

pub fn handle_marker_command(args: MarkerArgs) -> Result<(), Box<dyn std::error::Error>> {
    match args.command {
        MarkerCommands::Detect { input, mode, disasm } => {
            detect_markers(input, mode, disasm)
        }
        MarkerCommands::Pairs { input, disasm } => {
            detect_pairs(input, disasm)
        }
        MarkerCommands::Debug { input } => {
            debug_imports(input)
        }
        MarkerCommands::Virtualization { input, mode } => {
            show_virtualization_asm(input, mode)
        }
    }
}

fn detect_markers(input: PathBuf, mode: String, _disasm: bool) -> Result<(), Box<dyn std::error::Error>> {
    info!("加载 PE 文件: {:?}", input);
    let pe_file = PeFile::load(&input)?;

    let disasm_mode = match mode.as_str() {
        "32" => DisassemblyMode::Mode32,
        "64" => DisassemblyMode::Mode64,
        _ => {
            error!("无效的模式: {}. 使用 '32' 或 '64'", mode);
            return Err("无效的模式".into());
        }
    };

    let finder = VmpMarkerFinder::with_mode(disasm_mode);
    
    // 调试：检查导入表
    println!("\n调试信息：检查导入表...");
    if let Some(pe) = pe_file.pe() {
        if let Some(optional_header) = pe.header.optional_header {
            let data_dirs = &optional_header.data_directories;
            if let Some(Some((_, import_dir))) = data_dirs.data_directories.get(1) {
                use goblin::pe::import::ImportData;
                let file_data = pe_file.data();
                let file_alignment = optional_header.windows_fields.file_alignment;
                let is_64bit = pe.header.coff_header.machine == goblin::pe::header::COFF_MACHINE_X86_64;
                let import_result = if is_64bit {
                    ImportData::parse::<u64>(file_data, *import_dir, &pe.sections, file_alignment)
                } else {
                    ImportData::parse::<u32>(file_data, *import_dir, &pe.sections, file_alignment)
                };
                
                if let Ok(import_data) = import_result {
                    let mut vmp_count = 0;
                    for entry in &import_data.import_data {
                        if entry.name.to_string().to_lowercase().contains("vmprotect") {
                            vmp_count += 1;
                            println!("  找到 VMP DLL: {}", entry.name);
                            if let Some(ref lookup_table) = entry.import_lookup_table {
                                for (i, lookup_entry) in lookup_table.iter().enumerate() {
                                    match lookup_entry {
                                        goblin::pe::import::SyntheticImportLookupTableEntry::HintNameTableRVA((_, hint_entry)) => {
                                            let iat_rva = entry.import_directory_entry.import_address_table_rva;
                                            let thunk_rva = iat_rva as u64 + (i * 8) as u64;
                                            println!("    - {} @ {:08X}", hint_entry.name, thunk_rva);
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                    if vmp_count == 0 {
                        println!("  未找到 VMP DLL");
                    }
                }
            }
        }
    }
    
    let markers = finder.find_markers(&pe_file)?;

    if markers.is_empty() {
        info!("未检测到 VMP 标记");
        return Ok(());
    }

    info!("检测到 {} 个 VMP 标记:\n", markers.len());
    println!("{:<6} {:<12} {:<16} {:<25} {}",
        "序号", "文件偏移", "RVA", "类型", "函数名");
    println!("{}", "-".repeat(90));

    for (i, marker) in markers.iter().enumerate() {
        println!("{:<6} 0x{:08X}   0x{:08X}   {:<25} {}",
            i + 1,
            marker.call_file_offset,
            marker.call_rva,
            marker.marker_type.to_string(),
            marker.function_name
        );
    }

    Ok(())
}

fn debug_imports(input: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    info!("调试导入表: {:?}", input);
    let pe_file = PeFile::load(&input)?;
    
    if let Some(pe) = pe_file.pe() {
        println!("PE file loaded successfully");
        println!("Machine: {:04X}", pe.header.coff_header.machine);
        println!("Number of sections: {}", pe.sections.len());
        
        // 打印所有节的信息
        println!("\nSections:");
        for section in &pe.sections {
            let name = String::from_utf8_lossy(&section.name).trim_end_matches('\0').to_string();
            println!("  {} - RVA: {:08X}, Size: {:08X}, Raw: {:08X}",
                name, section.virtual_address, section.virtual_size, section.pointer_to_raw_data);
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
                                    for (i, lookup_entry) in lookup_table.iter().enumerate() {
                                        match lookup_entry {
                                            goblin::pe::import::SyntheticImportLookupTableEntry::HintNameTableRVA((_, hint_entry)) => {
                                                let func_name = hint_entry.name.to_string();
                                                let thunk_rva = iat_rva as u64 + (i * 8) as u64;
                                                println!("      [{}] {} @ {:08X}", i, func_name, thunk_rva);
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
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

fn show_virtualization_asm(input: PathBuf, mode: String) -> Result<(), Box<dyn std::error::Error>> {
    info!("加载 PE 文件: {:?}", input);
    let pe_file = PeFile::load(&input)?;

    let disasm_mode = match mode.as_str() {
        "32" => DisassemblyMode::Mode32,
        "64" => DisassemblyMode::Mode64,
        _ => {
            error!("无效的模式: {}. 使用 '32' 或 '64'", mode);
            return Err("无效的模式".into());
        }
    };

    let finder = VmpMarkerFinder::with_mode(disasm_mode);
    let virt_markers = finder.find_virtualization_markers(&pe_file)?;

    if virt_markers.is_empty() {
        info!("未检测到虚拟化标记 (VMProtectBeginVirtualization)");
        return Ok(());
    }

    info!("检测到 {} 个虚拟化标记:\n", virt_markers.len());

    for (i, (pair, asm)) in virt_markers.iter().enumerate() {
        println!("\n=== 虚拟化标记 #{} ===", i + 1);
        println!("Begin 标记:");
        println!("  文件偏移: 0x{:08X}", pair.begin.call_file_offset);
        println!("  RVA:      0x{:08X}", pair.begin.call_rva);
        println!("  函数名:   {}", pair.begin.function_name);

        println!("\nEnd 标记:");
        println!("  文件偏移: 0x{:08X}", pair.end.call_file_offset);
        println!("  RVA:      0x{:08X}", pair.end.call_rva);
        println!("  函数名:   {}", pair.end.function_name);

        println!("\n保护的代码:");
        println!("  起始 RVA: 0x{:08X}", pair.code_start);
        println!("  结束 RVA: 0x{:08X}", pair.code_end);
        let code_size = pair.code_end - pair.code_start;
        println!("  大小:     {} 字节", code_size);

        println!("\n  汇编代码:");
        for line in asm.lines() {
            println!("    {}", line);
        }

        println!("{}", "-".repeat(60));
    }

    Ok(())
}

fn detect_pairs(input: PathBuf, disasm: bool) -> Result<(), Box<dyn std::error::Error>> {
    info!("加载 PE 文件: {:?}", input);
    let pe_file = PeFile::load(&input)?;

    let finder = VmpMarkerFinder::new();
    let pairs = finder.find_marker_pairs(&pe_file)?;

    if pairs.is_empty() {
        info!("未检测到完整的标记对 (Begin + End)");
        return Ok(());
    }

    info!("检测到 {} 个标记对:\n", pairs.len());

    for (i, pair) in pairs.iter().enumerate() {
        println!("\n=== 标记对 #{} ===", i + 1);
        println!("Begin 标记:");
        println!("  文件偏移: 0x{:08X}", pair.begin.call_file_offset);
        println!("  RVA:      0x{:08X}", pair.begin.call_rva);
        println!("  类型:     {}", pair.begin.marker_type);
        println!("  函数名:   {}", pair.begin.function_name);

        println!("\nEnd 标记:");
        println!("  文件偏移: 0x{:08X}", pair.end.call_file_offset);
        println!("  RVA:      0x{:08X}", pair.end.call_rva);
        println!("  函数名:   {}", pair.end.function_name);

        println!("\n保护的代码:");
        println!("  起始 RVA: 0x{:08X}", pair.code_start);
        println!("  结束 RVA: 0x{:08X}", pair.code_end);
        let code_size = pair.code_end - pair.code_start;
        println!("  大小:     {} 字节", code_size);

        if disasm && code_size > 0 && code_size < 10000 {
            println!("\n  汇编代码:");
            match finder.disassemble_protected_code(&pe_file, pair) {
                Ok(asm) => {
                    for line in asm.lines() {
                        println!("    {}", line);
                    }
                }
                Err(e) => {
                    println!("    反汇编失败: {:?}", e);
                }
            }
        }

        println!("{}", "-".repeat(60));
    }

    Ok(())
}
