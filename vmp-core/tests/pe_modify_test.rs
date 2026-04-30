use std::fs;
use vmp_core::pe::{PeFile, PeModifier};

#[test]
fn test_rename_section() {
    let input_path = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1.exe";
    let output_path = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1_renamed.exe";
    
    println!("\n=== Section Rename Test ===");
    
    let data = fs::read(input_path).expect("Failed to read PE file");
    let is_64bit = vmp_core::pe::utils::is_64bit(&data).unwrap_or(false);
    
    println!("Original PE: {} bytes, 64-bit: {}", data.len(), is_64bit);
    
    let mut modifier = PeModifier::new(data, is_64bit);
    
    println!("\nOriginal section names:");
    for i in 0..6 {
        match modifier.get_section_name(i) {
            Ok(name) => println!("  [{}] {}", i, name),
            Err(e) => println!("  [{}] Error: {:?}", i, e),
        }
    }
    
    println!("\nRenaming .text -> .code...");
    modifier.rename_section(".text", ".code").expect("Failed to rename section");
    
    println!("Renaming .rdata -> .rsrc...");
    modifier.rename_section(".rdata", ".rsrc").expect("Failed to rename section");
    
    println!("\nUpdated section names:");
    for i in 0..6 {
        match modifier.get_section_name(i) {
            Ok(name) => println!("  [{}] {}", i, name),
            Err(e) => println!("  [{}] Error: {:?}", i, e),
        }
    }
    
    fs::write(output_path, modifier.data()).expect("Failed to write modified PE");
    println!("\nModified PE saved to: {}", output_path);
    
    println!("\nVerifying by loading modified PE...");
    let modified_pe = PeFile::load(output_path).expect("Failed to load modified PE");
    
    if let Some(pe) = modified_pe.pe() {
        println!("Modified PE loaded successfully!");
        println!("  Number of sections: {}", pe.sections.len());
        
        println!("\nSection names from modified PE:");
        for (i, section) in pe.sections.iter().enumerate() {
            let name = String::from_utf8_lossy(&section.name)
                .trim_end_matches('\0')
                .to_string();
            println!("  [{}] {}", i, name);
        }
        
        let first_section_name = String::from_utf8_lossy(&pe.sections[0].name)
            .trim_end_matches('\0')
            .to_string();
        assert_eq!(first_section_name, ".code", "First section should be renamed to .code");
        
        let second_section_name = String::from_utf8_lossy(&pe.sections[1].name)
            .trim_end_matches('\0')
            .to_string();
        assert_eq!(second_section_name, ".rsrc", "Second section should be renamed to .rsrc");
        
        println!("\n✓ Section rename verification passed!");
    }
}

#[test]
fn test_add_section_and_rename() {
    let input_path = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1.exe";
    let output_path = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1_add_and_rename.exe";
    
    println!("\n=== Add Section and Rename Test ===");
    
    let data = fs::read(input_path).expect("Failed to read PE file");
    let is_64bit = vmp_core::pe::utils::is_64bit(&data).unwrap_or(false);
    
    let mut modifier = PeModifier::new(data, is_64bit);
    
    println!("Adding new section .vmp...");
    let section_va = modifier.add_section(".vmp", 0x1000, 0x60000020)
        .expect("Failed to add section");
    println!("  New section VA: 0x{:X}", section_va);
    
    let section_count = vmp_core::pe::utils::get_section_count(modifier.data())
        .expect("Failed to get section count");
    println!("  Total sections after add: {}", section_count);
    
    println!("\nRenaming added section .vmp -> .vmp2...");
    modifier.rename_section(".vmp", ".vmp2").expect("Failed to rename section");
    
    fs::write(output_path, modifier.data()).expect("Failed to write modified PE");
    println!("\nModified PE saved to: {}", output_path);
    
    println!("\nVerifying...");
    let modified_pe = PeFile::load(output_path).expect("Failed to load modified PE");
    
    if let Some(pe) = modified_pe.pe() {
        println!("  Number of sections: {}", pe.sections.len());
        
        let last_section = &pe.sections[pe.sections.len() - 1];
        let last_section_name = String::from_utf8_lossy(&last_section.name)
            .trim_end_matches('\0')
            .to_string();
        
        println!("  Last section name: {}", last_section_name);
        assert_eq!(last_section_name, ".vmp2", "Last section should be renamed to .vmp2");
        
        println!("\n✓ Add and rename verification passed!");
    }
}

#[test]
fn test_rename_nonexistent_section() {
    let input_path = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1.exe";
    
    println!("\n=== Rename Non-existent Section Test ===");
    
    let data = fs::read(input_path).expect("Failed to read PE file");
    let is_64bit = vmp_core::pe::utils::is_64bit(&data).unwrap_or(false);
    
    let mut modifier = PeModifier::new(data, is_64bit);
    
    println!("Trying to rename non-existent section .nonexistent...");
    match modifier.rename_section(".nonexistent", ".newname") {
        Ok(_) => panic!("Should have failed"),
        Err(e) => {
            println!("  Expected error: {:?}", e);
            println!("  ✓ Error handling works correctly!");
        }
    }
}

#[test]
fn test_section_name_too_long() {
    let input_path = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1.exe";
    
    println!("\n=== Section Name Too Long Test ===");
    
    let data = fs::read(input_path).expect("Failed to read PE file");
    let is_64bit = vmp_core::pe::utils::is_64bit(&data).unwrap_or(false);
    
    let mut modifier = PeModifier::new(data, is_64bit);
    
    println!("Trying to rename with name longer than 8 chars...");
    match modifier.rename_section(".text", ".verylongname") {
        Ok(_) => panic!("Should have failed"),
        Err(e) => {
            println!("  Expected error: {:?}", e);
            println!("  ✓ Length validation works correctly!");
        }
    }
}
