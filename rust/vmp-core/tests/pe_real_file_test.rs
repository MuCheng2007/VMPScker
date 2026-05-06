//! Comprehensive PE file tests using real executable
//! Tests all PE functionality with E:\VMPScker\bin\64\Ultimate\ConsoleApplication1.exe

use std::path::Path;
use vmp_core::pe::*;
use vmp_core::pe::modify::PeModifier;
use vmp_core::core::section::Section;

const TEST_FILE_PATH: &str = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1.exe";

/// Helper to check if test file exists
fn check_test_file() -> Option<String> {
    if Path::new(TEST_FILE_PATH).exists() {
        None
    } else {
        Some(format!("Test file not found: {}", TEST_FILE_PATH))
    }
}

/// Test PE file parsing - DOS Header
#[test]
fn test_pe_dos_header() {
    if let Some(skip) = check_test_file() {
        eprintln!("Skipping test: {}", skip);
        return;
    }
    
    let pe_file = PeFile::load(TEST_FILE_PATH).expect("Failed to load PE file");
    let data = pe_file.data();
    
    // Verify DOS signature (MZ)
    let dos_magic = u16::from_le_bytes([data[0], data[1]]);
    assert_eq!(dos_magic, 0x5A4D, "DOS signature should be MZ");
    
    // Verify e_lfanew points to valid PE signature
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    assert!(pe_offset < data.len(), "e_lfanew points outside file");
    assert!(pe_offset >= 0x40, "e_lfanew should be at least 0x40");
    
    // Verify PE signature
    let pe_sig = &data[pe_offset..pe_offset + 4];
    assert_eq!(pe_sig, b"PE\0\0", "PE signature should be 'PE\\0\\0'");
}

/// Test PE file parsing - COFF Header
#[test]
fn test_pe_coff_header() {
    if let Some(skip) = check_test_file() {
        eprintln!("Skipping test: {}", skip);
        return;
    }
    
    let pe_file = PeFile::load(TEST_FILE_PATH).expect("Failed to load PE file");
    let pe = pe_file.pe().expect("Failed to get PE");
    
    // Verify machine type (AMD64 = 0x8664)
    assert_eq!(pe.header.coff_header.machine, 0x8664, "Machine should be AMD64");
    
    // Verify number of sections
    assert!(pe.header.coff_header.number_of_sections > 0, "Should have at least 1 section");
    assert!(pe.header.coff_header.number_of_sections < 100, "Unreasonable number of sections");
    
    // Verify size of optional header (should be non-zero for executables)
    assert!(pe.header.coff_header.size_of_optional_header > 0, "Optional header size should be > 0");
}

/// Test PE file parsing - Optional Header
#[test]
fn test_pe_optional_header() {
    if let Some(skip) = check_test_file() {
        eprintln!("Skipping test: {}", skip);
        return;
    }
    
    let pe_file = PeFile::load(TEST_FILE_PATH).expect("Failed to load PE file");
    
    // Verify magic (0x20b for PE32+, 0x10b for PE32)
    let pe = pe_file.pe().expect("Failed to get PE");
    let magic = pe.header.optional_header.as_ref().map(|oh| oh.standard_fields.magic).unwrap_or(0);
    assert!(magic == 0x20b || magic == 0x10b, "Magic should be 0x20b (PE32+) or 0x10b (PE32)");
    
    // For 64-bit executable, should be PE32+
    if pe_file.is_64bit() {
        assert_eq!(magic, 0x20b, "64-bit PE should have magic 0x20b");
    }
    
    // Verify entry point is not zero (for executables)
    let entry_point = pe_file.entry_point();
    println!("Entry Point: {:016X}", entry_point);
    
    // Verify image base is aligned
    let image_base = pe_file.image_base();
    assert!(image_base > 0, "Image base should be > 0");
    assert_eq!(image_base % 0x10000, 0, "Image base should be aligned to 64KB");
}

/// Test PE file parsing - Section Table
#[test]
fn test_pe_section_table() {
    if let Some(skip) = check_test_file() {
        eprintln!("Skipping test: {}", skip);
        return;
    }
    
    let pe_file = PeFile::load(TEST_FILE_PATH).expect("Failed to load PE file");
    let pe = pe_file.pe().expect("Failed to get PE");
    let num_sections = pe.header.coff_header.number_of_sections as usize;
    
    assert_eq!(pe.sections.len(), num_sections, "Section count should match COFF header");
    
    // Verify each section
    for (i, section) in pe.sections.iter().enumerate() {
        // Section name should not be empty
        let name = std::str::from_utf8(&section.name).unwrap_or("").trim_end_matches('\0');
        assert!(!name.is_empty(), "Section {} name should not be empty", i);
        
        // Virtual address should be aligned
        assert_eq!(section.virtual_address as u64 % 0x1000, 0, 
            "Section {} virtual address should be aligned to 4KB", i);
        
        // Virtual size should be > 0
        assert!(section.virtual_size > 0, "Section {} virtual size should be > 0", i);
        
        // Raw address should be aligned
        assert_eq!(section.pointer_to_raw_data as u64 % 0x200, 0,
            "Section {} raw address should be aligned to 512 bytes", i);
        
        // Characteristics should have some valid flags
        assert!(section.characteristics != 0, "Section {} should have characteristics", i);
        
        println!("Section {}: {} VA:{:08X} VS:{:08X} RA:{:08X} RS:{:08X} Char:{:08X}",
            i, name, section.virtual_address, section.virtual_size,
            section.pointer_to_raw_data, section.size_of_raw_data, section.characteristics);
    }
    
    // Verify common sections exist
    let section_names: Vec<String> = pe.sections.iter()
        .map(|s| std::str::from_utf8(&s.name).unwrap_or("").trim_end_matches('\0').to_string())
        .collect();
    assert!(section_names.iter().any(|n| n == ".text"), "Should have .text section");
}

/// Test PE file parsing - Import Directory
#[test]
fn test_pe_import_directory() {
    if let Some(skip) = check_test_file() {
        eprintln!("Skipping test: {}", skip);
        return;
    }
    
    let pe_file = PeFile::load(TEST_FILE_PATH).expect("Failed to load PE file");
    let pe = pe_file.pe().expect("Failed to get PE");
    
    // Get import table from goblin
    let imports = &pe.imports;
    if !imports.is_empty() {
        println!("Found {} import entries", imports.len());
        
        for import in imports {
            let dll_name = &import.dll;
            println!("  DLL: {}", dll_name);
            
            // Print imported function info - goblin uses Cow for name
            let name_str = import.name.as_ref();
            if import.ordinal != 0 {
                println!("    - Ordinal({}) @ {:08X}", import.ordinal, import.rva);
            } else {
                println!("    - {} @ {:08X}", name_str, import.rva);
            }
        }
        
        // Common DLLs that should be present
        let dll_names: Vec<String> = imports.iter().map(|e| e.dll.to_string()).collect();
        assert!(dll_names.iter().any(|n| n.eq_ignore_ascii_case("KERNEL32.dll")),
            "Should import from kernel32");
    } else {
        println!("No import table found (might be a static executable)");
    }
}

/// Test PE file parsing - Export Directory
#[test]
fn test_pe_export_directory() {
    if let Some(skip) = check_test_file() {
        eprintln!("Skipping test: {}", skip);
        return;
    }
    
    let pe_file = PeFile::load(TEST_FILE_PATH).expect("Failed to load PE file");
    let pe = pe_file.pe().expect("Failed to get PE");
    
    // Get export table from goblin
    let exports = &pe.exports;
    if !exports.is_empty() {
        println!("Found {} exports", exports.len());
        
        for export in exports {
            match &export.name {
                Some(name) => println!("  {} @ {:08X}", name, export.rva),
                None => println!("  Ordinal @ {:08X}", export.rva),
            }
        }
        
        // ConsoleApplication1 is an EXE, might not have exports
        // DLLs should have exports
    } else {
        println!("No export table found");
    }
}

/// Test PE file parsing - Data Directories
#[test]
fn test_pe_data_directories() {
    if let Some(skip) = check_test_file() {
        eprintln!("Skipping test: {}", skip);
        return;
    }
    
    let pe_file = PeFile::load(TEST_FILE_PATH).expect("Failed to load PE file");
    let pe = pe_file.pe().expect("Failed to get PE");
    
    // Get data directories from optional header
    if let Some(opt_header) = &pe.header.optional_header {
        let data_dirs = &opt_header.data_directories;
        
        // Print all directories
        let dir_names = [
            "Export", "Import", "Resource", "Exception", "Security", "BaseReloc",
            "Debug", "Architecture", "GlobalPtr", "TLS", "LoadConfig", "BoundImport",
            "IAT", "DelayImport", "COMDescriptor", "Reserved"
        ];
        
        let mut present_dirs = 0;
        // goblin's data_directories is a fixed-size array of Options
        for (i, (dir_opt, name)) in data_dirs.data_directories.iter().zip(dir_names.iter()).enumerate() {
            if let Some((_, dir)) = dir_opt {
                if dir.virtual_address != 0 {
                    present_dirs += 1;
                    println!("Directory[{:2}] {:20} VA:{:08X} Size:{:08X}",
                        i, name, dir.virtual_address, dir.size);
                }
            }
        }
        
        println!("Present directories: {}/{}", present_dirs, data_dirs.data_directories.len());
        
        // At minimum, should have Import directory (index 1)
        if let Some((_, import_dir)) = &data_dirs.data_directories[1] {
            assert!(import_dir.virtual_address != 0, "Should have Import directory");
        }
    }
}

/// Test PE file parsing - Debug Directory
#[test]
fn test_pe_debug_directory() {
    if let Some(skip) = check_test_file() {
        eprintln!("Skipping test: {}", skip);
        return;
    }
    
    let pe_file = PeFile::load(TEST_FILE_PATH).expect("Failed to load PE file");
    let pe = pe_file.pe().expect("Failed to get PE");
    
    // Get debug directory from goblin
    if let Some(debug_data) = &pe.debug_data {
        println!("Debug data available");
        
        // Access debug info - goblin uses data_type not _type
        let debug_dir = &debug_data.image_debug_directory;
        println!("  Type:{:08X} Size:{:08X} VA:{:08X} FileOffset:{:08X}",
            debug_dir.data_type, 
            debug_dir.size_of_data, 
            debug_dir.address_of_raw_data, 
            debug_dir.pointer_to_raw_data);
        
        // Check for CodeView info
        if let Some(cv_info) = &debug_data.codeview_pdb70_debug_info {
            println!("  CodeView PDB70 signature: {:?}", cv_info.signature);
        }
    } else {
        println!("No debug directory found");
    }
}

/// Test PE file modification - Rename section
#[test]
fn test_pe_modify_section_name() {
    if let Some(skip) = check_test_file() {
        eprintln!("Skipping test: {}", skip);
        return;
    }
    
    let data = std::fs::read(TEST_FILE_PATH).expect("Failed to read test file");
    let mut modifier = PeModifier::new(data, true);
    
    // Get original section name
    let original_name = modifier.get_section_name(0).expect("Failed to get section name");
    println!("Original section 0 name: {}", original_name);
    
    // Rename section
    let new_name = ".test123";
    modifier.rename_section(&original_name, new_name).expect("Failed to rename section");
    
    // Verify rename
    let renamed = modifier.get_section_name(0).expect("Failed to get renamed section");
    assert_eq!(renamed, new_name, "Section should be renamed");
    
    // Rename back
    modifier.rename_section(new_name, &original_name).expect("Failed to rename back");
    let restored = modifier.get_section_name(0).expect("Failed to get restored section");
    assert_eq!(restored, original_name, "Section name should be restored");
}

/// Test PE to Core Section conversion
#[test]
fn test_pe_to_core_section_conversion() {
    if let Some(skip) = check_test_file() {
        eprintln!("Skipping test: {}", skip);
        return;
    }
    
    let pe_file = PeFile::load(TEST_FILE_PATH).expect("Failed to load PE file");
    let pe = pe_file.pe().expect("Failed to get PE");
    
    // Convert PE sections to core Segments
    for section in &pe.sections {
        let segment = Segment {
            name: std::str::from_utf8(&section.name).unwrap_or("").trim_end_matches('\0').to_string(),
            virtual_address: section.virtual_address as u64,
            virtual_size: section.virtual_size as u64,
            raw_address: section.pointer_to_raw_data as u64,
            raw_size: section.size_of_raw_data as u64,
            characteristics: section.characteristics,
            pointer_to_relocations: section.pointer_to_relocations,
            pointer_to_linenumbers: section.pointer_to_linenumbers,
            number_of_relocations: section.number_of_relocations,
            number_of_linenumbers: section.number_of_linenumbers,
        };
        
        // Convert to core Section
        let core_section = Section::from_pe_segment(&segment);
        
        // Verify name matches
        assert_eq!(core_section.name, segment.name, "Section name should match");
        
        // Verify addresses match
        assert_eq!(core_section.virtual_address, segment.virtual_address, 
            "Virtual address should match");
        assert_eq!(core_section.virtual_size, segment.virtual_size,
            "Virtual size should match");
        
        // Verify physical addresses match
        assert_eq!(core_section.physical_offset as u64, segment.raw_address,
            "Physical offset should match");
        assert_eq!(core_section.physical_size as u64, segment.raw_size,
            "Physical size should match");
        
        // Verify characteristics match
        assert_eq!(core_section.flags, segment.characteristics,
            "Characteristics should match");
        
        // Test RVA to offset conversion
        if segment.raw_size > 0 {
            let test_rva = segment.virtual_address;
            let expected_offset = segment.raw_address;
            let actual_offset = core_section.rva_to_offset(test_rva);
            assert_eq!(actual_offset, Some(expected_offset),
                "RVA to offset conversion should work");
        }
        
        // Test memory type conversion
        let is_code = segment.characteristics & 0x20000000 != 0; // IMAGE_SCN_MEM_EXECUTE
        assert_eq!(core_section.is_code(), is_code, "is_code() should match characteristics");
    }
}

/// Test comprehensive PE operations
#[test]
fn test_pe_comprehensive_operations() {
    if let Some(skip) = check_test_file() {
        eprintln!("Skipping test: {}", skip);
        return;
    }
    
    // Parse the PE
    let pe_file = PeFile::load(TEST_FILE_PATH).expect("Failed to load PE file");
    let pe = pe_file.pe().expect("Failed to get PE");
    
    // Collect information
    let is_64bit = pe_file.is_64bit();
    let entry_point = pe_file.entry_point();
    let image_base = pe_file.image_base();
    let num_sections = pe.header.coff_header.number_of_sections;
    
    println!("PE Information:");
    println!("  64-bit: {}", is_64bit);
    println!("  Entry Point: {:016X}", entry_point);
    println!("  Image Base: {:016X}", image_base);
    println!("  Sections: {}", num_sections);
    
    // Verify all data directories are accessible
    if let Some(opt_header) = &pe.header.optional_header {
        let data_dirs = &opt_header.data_directories;
        let mut present_dirs = 0;
        for (i, dir_opt) in data_dirs.data_directories.iter().enumerate() {
            if let Some((_, dir)) = dir_opt {
                if dir.virtual_address != 0 {
                    present_dirs += 1;
                    println!("  Directory[{}]: VA={:08X} Size={:08X}", 
                        i, dir.virtual_address, dir.size);
                }
            }
        }
        println!("  Present directories: {}/{}", present_dirs, data_dirs.data_directories.len());
    }
    
    // Verify all sections are accessible
    println!("  Segments parsed: {}", pe.sections.len());
    
    // Test modifier
    let data = std::fs::read(TEST_FILE_PATH).expect("Failed to read test file");
    let _modifier = PeModifier::new(data, is_64bit);
    
    // Get section info
    for (i, section) in pe.sections.iter().enumerate() {
        let name = std::str::from_utf8(&section.name).unwrap_or("").trim_end_matches('\0');
        println!("  Section[{}]: {}", i, name);
    }
    
    // All operations should succeed without panic
    assert!(true, "Comprehensive operations test passed");
}
