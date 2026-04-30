use std::fs;

#[test]
fn debug_pe_structure() {
    let path = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1.exe";
    let data = fs::read(path).expect("Failed to read PE file");
    
    println!("File size: {} bytes", data.len());
    
    println!("DOS Header:");
    println!("  Magic: {:02X} {:02X}", data[0], data[1]);
    
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    println!("  PE Offset: 0x{:X}", pe_offset);
    
    println!("PE Signature:");
    println!("  {:02X} {:02X} {:02X} {:02X}", 
        data[pe_offset], data[pe_offset + 1], 
        data[pe_offset + 2], data[pe_offset + 3]);
    
    let coff_header_offset = pe_offset + 4;
    println!("\nCOFF Header (offset 0x{:X}):", coff_header_offset);
    
    let machine = u16::from_le_bytes([data[coff_header_offset], data[coff_header_offset + 1]]);
    println!("  Machine: 0x{:X}", machine);
    
    let num_sections = u16::from_le_bytes([data[coff_header_offset + 2], data[coff_header_offset + 3]]);
    println!("  Number of Sections: {}", num_sections);
    
    let time_date_stamp = u32::from_le_bytes([
        data[coff_header_offset + 4], data[coff_header_offset + 5],
        data[coff_header_offset + 6], data[coff_header_offset + 7]
    ]);
    println!("  Time Date Stamp: 0x{:X}", time_date_stamp);
    
    let size_of_optional_header = u16::from_le_bytes([
        data[coff_header_offset + 16], data[coff_header_offset + 17]
    ]);
    println!("  Size of Optional Header: {}", size_of_optional_header);
    
    let characteristics = u16::from_le_bytes([
        data[coff_header_offset + 18], data[coff_header_offset + 19]
    ]);
    println!("  Characteristics: 0x{:X}", characteristics);
    
    let optional_header_offset = coff_header_offset + 24;
    println!("\nOptional Header (offset 0x{:X}):", optional_header_offset);
    
    println!("  Raw bytes at offset: {:02X} {:02X}", 
        data[optional_header_offset], data[optional_header_offset + 1]);
    
    let magic = u16::from_le_bytes([data[optional_header_offset], data[optional_header_offset + 1]]);
    println!("  Magic: 0x{:X}", magic);
    
    match magic {
        0x10b => println!("  -> 32-bit PE"),
        0x20b => println!("  -> 64-bit PE+"),
        _ => println!("  -> Unknown"),
    }
    
    let section_table_offset = optional_header_offset + size_of_optional_header as usize;
    println!("\nSection Table (offset 0x{:X}):", section_table_offset);
    
    for i in 0..num_sections.min(6) {
        let section_offset = section_table_offset + i as usize * 40;
        println!("  Section {} at offset 0x{:X}:", i, section_offset);
        println!("    Raw bytes: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
            data[section_offset], data[section_offset + 1],
            data[section_offset + 2], data[section_offset + 3],
            data[section_offset + 4], data[section_offset + 5],
            data[section_offset + 6], data[section_offset + 7]);
        
        let name_bytes = &data[section_offset..section_offset + 8];
        let name = String::from_utf8_lossy(name_bytes)
            .trim_end_matches('\0')
            .to_string();
        println!("    Name: '{}'", name);
    }
    
    println!("\n=== Testing utils functions ===");
    println!("is_pe: {}", vmp_core::pe::utils::is_pe(&data));
    println!("is_64bit: {:?}", vmp_core::pe::utils::is_64bit(&data));
    println!("get_section_count: {:?}", vmp_core::pe::utils::get_section_count(&data));
    println!("get_section_table_offset: {:?}", vmp_core::pe::utils::get_section_table_offset(&data));
    
    for i in 0..6 {
        println!("get_section_name({}): {:?}", i, vmp_core::pe::utils::get_section_name(&data, i));
    }
}
