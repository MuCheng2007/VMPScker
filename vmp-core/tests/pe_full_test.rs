use std::fs;
use vmp_core::pe::*;

#[test]
fn test_directory_parsing() {
    let path = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1.exe";
    let pe_file = PeFile::load(path).expect("Failed to load PE file");
    
    println!("\n=== Data Directory Test ===");
    
    if let Some(_pe) = pe_file.pe() {
        let optional_header_offset = pe_file.get_optional_header_offset();
        let is_64bit = pe_file.is_64bit();
        
        let num_dirs_offset = if is_64bit { 108 } else { 92 };
        let dirs_offset = optional_header_offset + num_dirs_offset;
        
        let num_dirs = u32::from_le_bytes([
            pe_file.data()[dirs_offset],
            pe_file.data()[dirs_offset + 1],
            pe_file.data()[dirs_offset + 2],
            pe_file.data()[dirs_offset + 3],
        ]);
        
        println!("Number of directories: {}", num_dirs);
        
        let dir_data = &pe_file.data()[dirs_offset + 4..dirs_offset + 4 + num_dirs as usize * 8];
        let dir_list = DirectoryList::from_data(dir_data, num_dirs as usize);
        
        for entry in dir_list.valid_entries() {
            println!("  {}: VA=0x{:08X}, Size=0x{:08X}", 
                entry.directory_type.name(),
                entry.virtual_address,
                entry.size
            );
        }
    }
}

#[test]
fn test_segment_parsing() {
    let path = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1.exe";
    let pe_file = PeFile::load(path).expect("Failed to load PE file");
    
    println!("\n=== Segment Test ===");
    
    if let Some(_pe) = pe_file.pe() {
        let section_table_offset = utils::get_section_table_offset(pe_file.data()).unwrap();
        let num_sections = utils::get_section_count(pe_file.data()).unwrap();
        
        let section_data = &pe_file.data()[section_table_offset..section_table_offset + num_sections as usize * 40];
        let segments = SegmentList::from_data(section_data, num_sections as usize);
        
        println!("Number of segments: {}", segments.len());
        
        for (i, segment) in segments.iter().enumerate() {
            println!("  [{}] {}", i, segment.name);
            println!("      VA: 0x{:08X}, VS: 0x{:08X}", segment.virtual_address, segment.virtual_size);
            println!("      RA: 0x{:08X}, RS: 0x{:08X}", segment.raw_address, segment.raw_size);
            println!("      Code: {}, Data: {}, Exec: {}, Read: {}, Write: {}",
                segment.is_code(),
                segment.is_initialized_data(),
                segment.is_executable(),
                segment.is_readable(),
                segment.is_writable()
            );
        }
    }
}

#[test]
fn test_debug_directory() {
    let path = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1.exe";
    let pe_file = PeFile::load(path).expect("Failed to load PE file");
    
    println!("\n=== Debug Directory Test ===");
    
    if let Some(_pe) = pe_file.pe() {
        let optional_header_offset = pe_file.get_optional_header_offset();
        let is_64bit = pe_file.is_64bit();
        
        let num_dirs_offset = if is_64bit { 108 } else { 92 };
        let dirs_offset = optional_header_offset + num_dirs_offset;
        let debug_dir_offset = dirs_offset + 4 + 6 * 8; // Debug directory is index 6
        
        let debug_rva = u32::from_le_bytes([
            pe_file.data()[debug_dir_offset],
            pe_file.data()[debug_dir_offset + 1],
            pe_file.data()[debug_dir_offset + 2],
            pe_file.data()[debug_dir_offset + 3],
        ]);
        let debug_size = u32::from_le_bytes([
            pe_file.data()[debug_dir_offset + 4],
            pe_file.data()[debug_dir_offset + 5],
            pe_file.data()[debug_dir_offset + 6],
            pe_file.data()[debug_dir_offset + 7],
        ]);
        
        println!("Debug Directory RVA: 0x{:08X}, Size: {}", debug_rva, debug_size);
        
        if debug_rva != 0 && debug_size > 0 {
            if let Some(debug_offset) = pe_file.rva_to_offset(debug_rva as u64) {
                let debug_data = &pe_file.data()[debug_offset as usize..debug_offset as usize + debug_size as usize];
                let debug_dir = DebugDirectory::from_data(debug_data);
                
                println!("Number of debug entries: {}", debug_dir.len());
                
                for entry in debug_dir.iter() {
                    println!("  Type: {}, RVA: 0x{:08X}, Size: {}",
                        entry.debug_type.name(),
                        entry.address_of_raw_data,
                        entry.size_of_data
                    );
                }
            }
        }
    }
}

#[test]
fn test_exception_directory() {
    let path = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1.exe";
    let pe_file = PeFile::load(path).expect("Failed to load PE file");
    
    println!("\n=== Exception Directory Test ===");
    
    if let Some(_pe) = pe_file.pe() {
        let optional_header_offset = pe_file.get_optional_header_offset();
        let is_64bit = pe_file.is_64bit();
        
        let num_dirs_offset = if is_64bit { 108 } else { 92 };
        let dirs_offset = optional_header_offset + num_dirs_offset;
        let exception_dir_offset = dirs_offset + 4 + 3 * 8; // Exception directory is index 3
        
        let exception_rva = u32::from_le_bytes([
            pe_file.data()[exception_dir_offset],
            pe_file.data()[exception_dir_offset + 1],
            pe_file.data()[exception_dir_offset + 2],
            pe_file.data()[exception_dir_offset + 3],
        ]);
        let exception_size = u32::from_le_bytes([
            pe_file.data()[exception_dir_offset + 4],
            pe_file.data()[exception_dir_offset + 5],
            pe_file.data()[exception_dir_offset + 6],
            pe_file.data()[exception_dir_offset + 7],
        ]);
        
        println!("Exception Directory RVA: 0x{:08X}, Size: {}", exception_rva, exception_size);
        
        if exception_rva != 0 && exception_size > 0 {
            if let Some(exception_offset) = pe_file.rva_to_offset(exception_rva as u64) {
                let exception_data = &pe_file.data()[exception_offset as usize..exception_offset as usize + exception_size as usize];
                let runtime_funcs = RuntimeFunctionList::parse(exception_data, exception_size, is_64bit);
                
                println!("Number of runtime functions: {}", runtime_funcs.len());
                
                for (i, func) in runtime_funcs.iter().take(5).enumerate() {
                    println!("  [{}] Begin: 0x{:08X}, End: 0x{:08X}, Unwind RVA: 0x{:08X}",
                        i,
                        func.begin_address,
                        func.end_address,
                        func.unwind_info_rva
                    );
                }
            }
        }
    }
}

#[test]
fn test_pe_writer() {
    println!("\n=== PE Writer Test ===");
    
    let mut writer = PeWriter::create_empty(true);
    
    // Add .text section
    let text_segment = Segment::new(
        ".text",
        0x1000,
        0x1000,
        0x400,
        0x200,
        0x60000020 // CODE | EXECUTE | READ
    );
    writer.add_segment(&text_segment).expect("Failed to add .text section");
    
    // Add .data section
    let data_segment = Segment::new(
        ".data",
        0x2000,
        0x1000,
        0x600,
        0x200,
        0xC0000040 // INITIALIZED_DATA | READ | WRITE
    );
    writer.add_segment(&data_segment).expect("Failed to add .data section");
    
    // Set entry point
    writer.set_entry_point(0x1000);
    
    // Update checksum
    let checksum = writer.update_checksum();
    println!("PE Checksum: 0x{:08X}", checksum);
    
    // Save to file
    let output_path = r"E:\VMPScker\bin\64\Ultimate\test_created.exe";
    fs::write(output_path, writer.data()).expect("Failed to write PE file");
    
    println!("Created PE file: {}", output_path);
    println!("  Size: {} bytes", writer.data().len());
    
    // Verify by loading
    let loaded = PeFile::load(output_path).expect("Failed to load created PE");
    println!("  Verification: Loaded successfully!");
    println!("  Is 64-bit: {}", loaded.is_64bit());
    println!("  Entry Point: 0x{:08X}", loaded.entry_point());
}

#[test]
fn test_full_pe_operations() {
    let input_path = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1.exe";
    let output_path = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1_full_test.exe";
    
    println!("\n=== Full PE Operations Test ===");
    
    // 1. Load original PE
    let pe_file = PeFile::load(input_path).expect("Failed to load PE");
    println!("1. Loaded original PE");
    
    // 2. Parse all structures
    let is_64bit = pe_file.is_64bit();
    let image_base = pe_file.image_base();
    let entry_point = pe_file.entry_point();
    
    println!("   Is 64-bit: {}", is_64bit);
    println!("   Image Base: 0x{:016X}", image_base);
    println!("   Entry Point: 0x{:08X}", entry_point);
    
    // 3. Get all sections
    if let Some(pe) = pe_file.pe() {
        println!("   Sections: {}", pe.sections.len());
        
        // 4. Get imports
        if let Some(ref import_data) = pe.import_data {
            let imports = ImportList::from_goblin(import_data);
            println!("   Imports: {} DLLs", imports.len());
        }
        
        // 5. Get exports
        if let Some(ref export_data) = pe.export_data {
            println!("   Exports: {} functions", export_data.export_address_table.len());
        }
    }
    
    // 6. Modify PE
    let data = fs::read(input_path).expect("Failed to read PE file");
    let mut modifier = PeModifier::new(data, is_64bit);
    
    // Add a new section
    let new_section_va = modifier.add_section(".vmp0", 0x1000, 0x60000020)
        .expect("Failed to add section");
    println!("2. Added new section at VA: 0x{:08X}", new_section_va);
    
    // Rename a section
    modifier.rename_section(".vmp0", ".vmp1")
        .expect("Failed to rename section");
    println!("3. Renamed section .vmp0 -> .vmp1");
    
    // Strip debug info
    modifier.strip_debug_info()
        .expect("Failed to strip debug info");
    println!("4. Stripped debug info");
    
    // Update checksum
    let checksum = modifier.update_checksum()
        .expect("Failed to update checksum");
    println!("5. Updated checksum: 0x{:08X}", checksum);
    
    // 7. Save modified PE
    fs::write(output_path, modifier.data())
        .expect("Failed to write modified PE");
    println!("6. Saved modified PE to: {}", output_path);
    
    // 8. Verify modified PE
    let modified = PeFile::load(output_path)
        .expect("Failed to load modified PE");
    println!("7. Verification: Modified PE loaded successfully!");
    
    // Verify section count increased
    if let Some(pe) = modified.pe() {
        println!("   New section count: {}", pe.sections.len());
    }
    
    println!("\n✓ All operations completed successfully!");
}

// Helper trait for PeFile
trait PeFileExt {
    fn get_optional_header_offset(&self) -> usize;
}

impl PeFileExt for PeFile {
    fn get_optional_header_offset(&self) -> usize {
        let pe_offset = u32::from_le_bytes([
            self.data()[0x3C], self.data()[0x3D],
            self.data()[0x3E], self.data()[0x3F],
        ]) as usize;
        pe_offset + 4 + 20 // PE + COFF Header (20 bytes)
    }
}
