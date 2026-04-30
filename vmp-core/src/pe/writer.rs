use crate::error::{Result, VmpError};
use crate::pe::segment::Segment;

pub struct PeWriter {
    data: Vec<u8>,
    is_64bit: bool,
}

impl PeWriter {
    pub fn new(data: Vec<u8>, is_64bit: bool) -> Self {
        Self { data, is_64bit }
    }

    pub fn create_empty(is_64bit: bool) -> Self {
        let mut data = vec![0u8; 0x400];
        
        // DOS Header
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C] = 0x80; // PE offset
        
        // PE Signature
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0;
        data[0x83] = 0;
        
        // COFF Header
        let coff_offset = 0x84;
        data[coff_offset] = if is_64bit { 0x64 } else { 0x4C }; // Machine (AMD64 or i386)
        data[coff_offset + 1] = if is_64bit { 0x86 } else { 0x01 };
        data[coff_offset + 2] = 0; // NumberOfSections (0 for now)
        data[coff_offset + 3] = 0;
        
        // TimeDateStamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        data[coff_offset + 4..coff_offset + 8].copy_from_slice(&timestamp.to_le_bytes());
        
        // PointerToSymbolTable = 0
        data[coff_offset + 8..coff_offset + 12].copy_from_slice(&[0, 0, 0, 0]);
        // NumberOfSymbols = 0
        data[coff_offset + 12..coff_offset + 16].copy_from_slice(&[0, 0, 0, 0]);
        
        // SizeOfOptionalHeader
        let optional_header_size: u16 = if is_64bit { 240 } else { 224 };
        data[coff_offset + 16..coff_offset + 18].copy_from_slice(&optional_header_size.to_le_bytes());
        
        // Characteristics
        let characteristics: u16 = 0x1022; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | 32BIT_MACHINE
        data[coff_offset + 18..coff_offset + 20].copy_from_slice(&characteristics.to_le_bytes());
        
        // Optional Header
        let optional_offset = coff_offset + 20;
        let magic: u16 = if is_64bit { 0x20b } else { 0x10b };
        data[optional_offset..optional_offset + 2].copy_from_slice(&magic.to_le_bytes());
        
        // MajorLinkerVersion, MinorLinkerVersion
        data[optional_offset + 2] = 14;
        data[optional_offset + 3] = 0;
        
        // SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData = 0 (for now)
        data[optional_offset + 4..optional_offset + 16].copy_from_slice(&[0; 12]);
        
        // AddressOfEntryPoint = 0
        data[optional_offset + 16..optional_offset + 20].copy_from_slice(&[0; 4]);
        
        // BaseOfCode = 0x1000
        data[optional_offset + 20..optional_offset + 24].copy_from_slice(&0x1000u32.to_le_bytes());
        
        if is_64bit {
            // ImageBase (64-bit)
            data[optional_offset + 24..optional_offset + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
            
            // SectionAlignment, FileAlignment
            data[optional_offset + 32..optional_offset + 36].copy_from_slice(&0x1000u32.to_le_bytes());
            data[optional_offset + 36..optional_offset + 40].copy_from_slice(&0x200u32.to_le_bytes());
            
            // MajorOperatingSystemVersion, MinorOperatingSystemVersion
            data[optional_offset + 40] = 6;
            data[optional_offset + 41] = 0;
            
            // MajorImageVersion, MinorImageVersion
            data[optional_offset + 42] = 0;
            data[optional_offset + 43] = 0;
            
            // MajorSubsystemVersion, MinorSubsystemVersion
            data[optional_offset + 44] = 6;
            data[optional_offset + 45] = 0;
            
            // Win32VersionValue = 0
            data[optional_offset + 46..optional_offset + 50].copy_from_slice(&[0; 4]);
            
            // SizeOfImage = 0x2000 (minimum)
            data[optional_offset + 56..optional_offset + 60].copy_from_slice(&0x2000u32.to_le_bytes());
            
            // SizeOfHeaders = 0x400
            data[optional_offset + 60..optional_offset + 64].copy_from_slice(&0x400u32.to_le_bytes());
            
            // CheckSum = 0
            data[optional_offset + 64..optional_offset + 68].copy_from_slice(&[0; 4]);
            
            // Subsystem = WINDOWS_CUI (3)
            data[optional_offset + 68..optional_offset + 70].copy_from_slice(&3u16.to_le_bytes());
            
            // DllCharacteristics
            data[optional_offset + 70..optional_offset + 72].copy_from_slice(&0x8160u16.to_le_bytes());
            
            // SizeOfStackReserve, SizeOfStackCommit
            data[optional_offset + 72..optional_offset + 80].copy_from_slice(&0x100000u64.to_le_bytes());
            data[optional_offset + 80..optional_offset + 88].copy_from_slice(&0x1000u64.to_le_bytes());
            
            // SizeOfHeapReserve, SizeOfHeapCommit
            data[optional_offset + 88..optional_offset + 96].copy_from_slice(&0x100000u64.to_le_bytes());
            data[optional_offset + 96..optional_offset + 104].copy_from_slice(&0x1000u64.to_le_bytes());
            
            // LoaderFlags = 0
            data[optional_offset + 104..optional_offset + 108].copy_from_slice(&[0; 4]);
            
            // NumberOfRvaAndSizes = 16
            data[optional_offset + 108..optional_offset + 112].copy_from_slice(&16u32.to_le_bytes());
        } else {
            // BaseOfData (32-bit only)
            data[optional_offset + 28..optional_offset + 32].copy_from_slice(&0x2000u32.to_le_bytes());
            
            // ImageBase (32-bit)
            data[optional_offset + 28..optional_offset + 32].copy_from_slice(&0x10000000u32.to_le_bytes());
            
            // SectionAlignment, FileAlignment
            data[optional_offset + 32..optional_offset + 36].copy_from_slice(&0x1000u32.to_le_bytes());
            data[optional_offset + 36..optional_offset + 40].copy_from_slice(&0x200u32.to_le_bytes());
            
            // MajorOperatingSystemVersion, MinorOperatingSystemVersion
            data[optional_offset + 40] = 6;
            data[optional_offset + 41] = 0;
            
            // MajorImageVersion, MinorImageVersion
            data[optional_offset + 42] = 0;
            data[optional_offset + 43] = 0;
            
            // MajorSubsystemVersion, MinorSubsystemVersion
            data[optional_offset + 44] = 6;
            data[optional_offset + 45] = 0;
            
            // Win32VersionValue = 0
            data[optional_offset + 46..optional_offset + 50].copy_from_slice(&[0; 4]);
            
            // SizeOfImage = 0x2000 (minimum)
            data[optional_offset + 56..optional_offset + 60].copy_from_slice(&0x2000u32.to_le_bytes());
            
            // SizeOfHeaders = 0x400
            data[optional_offset + 60..optional_offset + 64].copy_from_slice(&0x400u32.to_le_bytes());
            
            // CheckSum = 0
            data[optional_offset + 64..optional_offset + 68].copy_from_slice(&[0; 4]);
            
            // Subsystem = WINDOWS_CUI (3)
            data[optional_offset + 68..optional_offset + 70].copy_from_slice(&3u16.to_le_bytes());
            
            // DllCharacteristics
            data[optional_offset + 70..optional_offset + 72].copy_from_slice(&0x8540u16.to_le_bytes());
            
            // SizeOfStackReserve, SizeOfStackCommit
            data[optional_offset + 72..optional_offset + 76].copy_from_slice(&0x100000u32.to_le_bytes());
            data[optional_offset + 76..optional_offset + 80].copy_from_slice(&0x1000u32.to_le_bytes());
            
            // SizeOfHeapReserve, SizeOfHeapCommit
            data[optional_offset + 80..optional_offset + 84].copy_from_slice(&0x100000u32.to_le_bytes());
            data[optional_offset + 84..optional_offset + 88].copy_from_slice(&0x1000u32.to_le_bytes());
            
            // LoaderFlags = 0
            data[optional_offset + 88..optional_offset + 92].copy_from_slice(&[0; 4]);
            
            // NumberOfRvaAndSizes = 16
            data[optional_offset + 92..optional_offset + 96].copy_from_slice(&16u32.to_le_bytes());
        }
        
        Self { data, is_64bit }
    }

    pub fn add_segment(&mut self, segment: &Segment) -> Result<()> {
        if segment.name.len() > 8 {
            return Err(VmpError::InvalidOperation(
                "Section name too long (max 8 chars)".to_string()
            ));
        }

        let pe_offset = u32::from_le_bytes([self.data[0x3C], self.data[0x3D], self.data[0x3E], self.data[0x3F]]) as usize;
        let coff_offset = pe_offset + 4;
        let num_sections = u16::from_le_bytes([self.data[coff_offset + 2], self.data[coff_offset + 3]]);
        
        let optional_header_size = u16::from_le_bytes([self.data[coff_offset + 16], self.data[coff_offset + 17]]);
        let section_table_offset = coff_offset + 20 + optional_header_size as usize;
        
        let new_section_index = num_sections as usize;
        let new_section_offset = section_table_offset + new_section_index * 40;
        
        // Resize if needed
        if new_section_offset + 40 > self.data.len() {
            self.data.resize(new_section_offset + 40, 0);
        }
        
        // Write section header
        let mut name_bytes = [0u8; 8];
        name_bytes[..segment.name.len()].copy_from_slice(segment.name.as_bytes());
        self.data[new_section_offset..new_section_offset + 8].copy_from_slice(&name_bytes);
        
        self.data[new_section_offset + 8..new_section_offset + 12].copy_from_slice(&(segment.virtual_size as u32).to_le_bytes());
        self.data[new_section_offset + 12..new_section_offset + 16].copy_from_slice(&(segment.virtual_address as u32).to_le_bytes());
        self.data[new_section_offset + 16..new_section_offset + 20].copy_from_slice(&(segment.raw_size as u32).to_le_bytes());
        self.data[new_section_offset + 20..new_section_offset + 24].copy_from_slice(&(segment.raw_address as u32).to_le_bytes());
        self.data[new_section_offset + 24..new_section_offset + 28].copy_from_slice(&segment.pointer_to_relocations.to_le_bytes());
        self.data[new_section_offset + 28..new_section_offset + 32].copy_from_slice(&segment.pointer_to_linenumbers.to_le_bytes());
        self.data[new_section_offset + 32..new_section_offset + 34].copy_from_slice(&segment.number_of_relocations.to_le_bytes());
        self.data[new_section_offset + 34..new_section_offset + 36].copy_from_slice(&segment.number_of_linenumbers.to_le_bytes());
        self.data[new_section_offset + 36..new_section_offset + 40].copy_from_slice(&segment.characteristics.to_le_bytes());
        
        // Update number of sections
        self.data[coff_offset + 2..coff_offset + 4].copy_from_slice(&(num_sections + 1).to_le_bytes());
        
        // Update SizeOfImage
        let optional_offset = coff_offset + 20;
        let image_size_offset = if self.is_64bit { optional_offset + 56 } else { optional_offset + 56 };
        let current_image_size = u32::from_le_bytes([
            self.data[image_size_offset],
            self.data[image_size_offset + 1],
            self.data[image_size_offset + 2],
            self.data[image_size_offset + 3],
        ]);
        let new_image_size = std::cmp::max(
            current_image_size,
            (segment.virtual_address + segment.virtual_size) as u32
        );
        self.data[image_size_offset..image_size_offset + 4].copy_from_slice(&new_image_size.to_le_bytes());
        
        Ok(())
    }

    pub fn set_entry_point(&mut self, rva: u32) {
        let pe_offset = u32::from_le_bytes([self.data[0x3C], self.data[0x3D], self.data[0x3E], self.data[0x3F]]) as usize;
        let coff_offset = pe_offset + 4;
        let optional_offset = coff_offset + 20;
        let entry_point_offset = optional_offset + 16;
        
        self.data[entry_point_offset..entry_point_offset + 4].copy_from_slice(&rva.to_le_bytes());
    }

    pub fn set_image_base(&mut self, image_base: u64) {
        let pe_offset = u32::from_le_bytes([self.data[0x3C], self.data[0x3D], self.data[0x3E], self.data[0x3F]]) as usize;
        let coff_offset = pe_offset + 4;
        let optional_offset = coff_offset + 20;
        
        if self.is_64bit {
            let image_base_offset = optional_offset + 24;
            self.data[image_base_offset..image_base_offset + 8].copy_from_slice(&image_base.to_le_bytes());
        } else {
            let image_base_offset = optional_offset + 28;
            self.data[image_base_offset..image_base_offset + 4].copy_from_slice(&(image_base as u32).to_le_bytes());
        }
    }

    pub fn set_directory(&mut self, index: usize, rva: u32, size: u32) {
        if index >= 16 {
            return;
        }
        
        let pe_offset = u32::from_le_bytes([self.data[0x3C], self.data[0x3D], self.data[0x3E], self.data[0x3F]]) as usize;
        let coff_offset = pe_offset + 4;
        let optional_offset = coff_offset + 20;
        
        let num_dirs_offset = if self.is_64bit { optional_offset + 108 } else { optional_offset + 92 };
        let dir_offset = num_dirs_offset + 4 + index * 8;
        
        if dir_offset + 8 <= self.data.len() {
            self.data[dir_offset..dir_offset + 4].copy_from_slice(&rva.to_le_bytes());
            self.data[dir_offset + 4..dir_offset + 8].copy_from_slice(&size.to_le_bytes());
        }
    }

    pub fn update_checksum(&mut self) -> u32 {
        let pe_offset = u32::from_le_bytes([self.data[0x3C], self.data[0x3D], self.data[0x3E], self.data[0x3F]]) as usize;
        let coff_offset = pe_offset + 4;
        let optional_offset = coff_offset + 20;
        let checksum_offset = if self.is_64bit { optional_offset + 64 } else { optional_offset + 64 };
        
        // Clear checksum first
        self.data[checksum_offset..checksum_offset + 4].copy_from_slice(&[0; 4]);
        
        let checksum = self.calculate_checksum();
        self.data[checksum_offset..checksum_offset + 4].copy_from_slice(&checksum.to_le_bytes());
        
        checksum
    }

    pub fn write_data(&mut self, offset: usize, data: &[u8]) {
        if offset + data.len() > self.data.len() {
            self.data.resize(offset + data.len(), 0);
        }
        self.data[offset..offset + data.len()].copy_from_slice(data);
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    fn calculate_checksum(&self) -> u32 {
        let mut checksum: u64 = 0;
        let len = self.data.len() as u64;

        for i in (0..self.data.len()).step_by(2) {
            if i + 1 < self.data.len() {
                let word = u16::from_le_bytes([self.data[i], self.data[i + 1]]) as u64;
                checksum += word;
                if checksum > 0xFFFFFFFF {
                    checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32);
                }
            }
        }

        checksum = (checksum & 0xFFFF) + (checksum >> 16);
        checksum = checksum + (len >> 1);

        checksum as u32
    }
}
