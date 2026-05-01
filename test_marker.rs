use vmp_core::pe::file::PeFile;

fn main() {
    let pe_file = PeFile::load(r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1.exe").unwrap();
    
    if let Some(pe) = pe_file.pe() {
        println!("PE file loaded successfully");
        println!("Machine: {:04X}", pe.header.coff_header.machine);
        println!("Number of sections: {}", pe.sections.len());
        
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
}
