pub fn rva_to_offset(sections: &[crate::pe::section::Section], rva: u64) -> Option<u64> {
    for section in sections {
        if section.contains_rva(rva) {
            return section.rva_to_offset(rva);
        }
    }
    None
}

pub fn offset_to_rva(sections: &[crate::pe::section::Section], offset: u64) -> Option<u64> {
    for section in sections {
        if section.contains_offset(offset) {
            return section.offset_to_rva(offset);
        }
    }
    None
}

pub fn align_up(value: u64, alignment: u64) -> u64 {
    ((value + alignment - 1) / alignment) * alignment
}

pub fn align_down(value: u64, alignment: u64) -> u64 {
    (value / alignment) * alignment
}

pub fn is_pe(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    
    if data[0] != b'M' || data[1] != b'Z' {
        return false;
    }
    
    if data.len() < 64 {
        return false;
    }
    
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    
    if pe_offset + 4 > data.len() {
        return false;
    }
    
    data[pe_offset] == b'P' && data[pe_offset + 1] == b'E'
}

pub fn is_64bit(data: &[u8]) -> Option<bool> {
    if !is_pe(data) {
        return None;
    }
    
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    // COFF Header is 20 bytes (not 24)
    let optional_header_offset = pe_offset + 4 + 20;
    
    if optional_header_offset + 2 > data.len() {
        return None;
    }
    
    let magic = u16::from_le_bytes([data[optional_header_offset], data[optional_header_offset + 1]]);
    
    match magic {
        0x10b => Some(false),
        0x20b => Some(true),
        _ => None,
    }
}

pub fn get_image_base(data: &[u8]) -> Option<u64> {
    if !is_pe(data) {
        return None;
    }
    
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    let optional_header_offset = pe_offset + 4 + 20;
    
    let is_64bit = is_64bit(data)?;
    
    if is_64bit {
        // ImageBase is at offset 24 in Optional Header for 64-bit
        if optional_header_offset + 24 + 8 > data.len() {
            return None;
        }
        Some(u64::from_le_bytes([
            data[optional_header_offset + 24],
            data[optional_header_offset + 25],
            data[optional_header_offset + 26],
            data[optional_header_offset + 27],
            data[optional_header_offset + 28],
            data[optional_header_offset + 29],
            data[optional_header_offset + 30],
            data[optional_header_offset + 31],
        ]))
    } else {
        // ImageBase is at offset 28 in Optional Header for 32-bit
        if optional_header_offset + 28 + 4 > data.len() {
            return None;
        }
        Some(u32::from_le_bytes([
            data[optional_header_offset + 28],
            data[optional_header_offset + 29],
            data[optional_header_offset + 30],
            data[optional_header_offset + 31],
        ]) as u64)
    }
}

pub fn get_entry_point(data: &[u8]) -> Option<u64> {
    if !is_pe(data) {
        return None;
    }
    
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    let optional_header_offset = pe_offset + 4 + 20;
    
    // AddressOfEntryPoint is at offset 16 in Optional Header
    if optional_header_offset + 16 + 4 > data.len() {
        return None;
    }
    
    Some(u32::from_le_bytes([
        data[optional_header_offset + 16],
        data[optional_header_offset + 17],
        data[optional_header_offset + 18],
        data[optional_header_offset + 19],
    ]) as u64)
}

pub fn get_section_count(data: &[u8]) -> Option<u16> {
    if !is_pe(data) {
        return None;
    }
    
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    // NumberOfSections is at offset 2 in COFF Header
    let num_sections_offset = pe_offset + 4 + 2;
    
    if num_sections_offset + 2 > data.len() {
        return None;
    }
    
    Some(u16::from_le_bytes([
        data[num_sections_offset],
        data[num_sections_offset + 1],
    ]))
}

pub fn get_section_table_offset(data: &[u8]) -> Option<usize> {
    if !is_pe(data) {
        return None;
    }
    
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    let coff_header_offset = pe_offset + 4;
    // COFF Header is 20 bytes
    let optional_header_offset = coff_header_offset + 20;
    
    // SizeOfOptionalHeader is at offset 16 in COFF Header
    let size_of_optional_header = u16::from_le_bytes([
        data[coff_header_offset + 16],
        data[coff_header_offset + 17],
    ]);
    
    Some(optional_header_offset + size_of_optional_header as usize)
}

pub fn get_section_name(data: &[u8], index: usize) -> Option<String> {
    let section_table_offset = get_section_table_offset(data)?;
    let num_sections = get_section_count(data)?;
    
    if index >= num_sections as usize {
        return None;
    }
    
    let section_offset = section_table_offset + index * 40;
    let name_bytes = &data[section_offset..section_offset + 8];
    let name = String::from_utf8_lossy(name_bytes)
        .trim_end_matches('\0')
        .to_string();
    
    Some(name)
}
