use crate::error::{Result, VmpError};

pub struct PeModifier {
    data: Vec<u8>,
    is_64bit: bool,
    section_alignment: u32,
    file_alignment: u32,
}

impl PeModifier {
    pub fn new(data: Vec<u8>, is_64bit: bool) -> Self {
        Self {
            data,
            is_64bit,
            section_alignment: 0x1000,
            file_alignment: 0x200,
        }
    }

    fn get_pe_offset(&self) -> usize {
        u32::from_le_bytes([
            self.data[0x3C], self.data[0x3D],
            self.data[0x3E], self.data[0x3F],
        ]) as usize
    }

    fn get_coff_header_offset(&self) -> usize {
        self.get_pe_offset() + 4
    }

    fn get_optional_header_offset(&self) -> usize {
        // COFF Header is 20 bytes
        self.get_coff_header_offset() + 20
    }

    fn get_section_table_offset(&self) -> usize {
        let coff_header_offset = self.get_coff_header_offset();
        // SizeOfOptionalHeader is at offset 16 in COFF Header
        let size_of_optional_header = u16::from_le_bytes([
            self.data[coff_header_offset + 16],
            self.data[coff_header_offset + 17],
        ]);
        self.get_optional_header_offset() + size_of_optional_header as usize
    }

    fn get_num_sections(&self) -> u16 {
        let coff_header_offset = self.get_coff_header_offset();
        // NumberOfSections is at offset 2 in COFF Header
        u16::from_le_bytes([
            self.data[coff_header_offset + 2],
            self.data[coff_header_offset + 3],
        ])
    }

    pub fn add_section(&mut self, name: &str, size: u32, characteristics: u32) -> Result<u64> {
        if name.len() > 8 {
            return Err(VmpError::InvalidOperation(
                "Section name too long (max 8 chars)".to_string()
            ));
        }

        let num_sections = self.get_num_sections();
        let section_table_offset = self.get_section_table_offset();

        let new_section_index = num_sections as usize;
        let new_section_entry_offset = section_table_offset + new_section_index * 40;

        let last_section_raw_end = if num_sections > 0 {
            let last_section_offset = section_table_offset + (num_sections as usize - 1) * 40;
            let raw_addr = u32::from_le_bytes([
                self.data[last_section_offset + 20],
                self.data[last_section_offset + 21],
                self.data[last_section_offset + 22],
                self.data[last_section_offset + 23],
            ]);
            let raw_size = u32::from_le_bytes([
                self.data[last_section_offset + 16],
                self.data[last_section_offset + 17],
                self.data[last_section_offset + 18],
                self.data[last_section_offset + 19],
            ]);
            raw_addr + raw_size
        } else {
            section_table_offset as u32 + 40
        };

        let aligned_raw_end = self.align_up(last_section_raw_end, self.file_alignment);
        let virtual_size = self.align_up(size, self.section_alignment);

        let optional_header_offset = self.get_optional_header_offset();
        let image_size_offset = if self.is_64bit {
            optional_header_offset + 88
        } else {
            optional_header_offset + 80
        };

        let last_section_virt_end = if num_sections > 0 {
            let last_section_offset = section_table_offset + (num_sections as usize - 1) * 40;
            let virt_addr = u32::from_le_bytes([
                self.data[last_section_offset + 12],
                self.data[last_section_offset + 13],
                self.data[last_section_offset + 14],
                self.data[last_section_offset + 15],
            ]);
            let virt_size = u32::from_le_bytes([
                self.data[last_section_offset + 8],
                self.data[last_section_offset + 9],
                self.data[last_section_offset + 10],
                self.data[last_section_offset + 11],
            ]);
            virt_addr + virt_size
        } else {
            self.section_alignment
        };

        let new_virt_addr = self.align_up(last_section_virt_end, self.section_alignment);

        if new_section_entry_offset + 40 > self.data.len() {
            self.data.resize(new_section_entry_offset + 40, 0);
        }

        let mut name_bytes = [0u8; 8];
        name_bytes[..name.len()].copy_from_slice(name.as_bytes());
        self.data[new_section_entry_offset..new_section_entry_offset + 8]
            .copy_from_slice(&name_bytes);

        self.write_u32(new_section_entry_offset + 8, size);
        self.write_u32(new_section_entry_offset + 12, new_virt_addr);
        self.write_u32(new_section_entry_offset + 16, self.align_up(size, self.file_alignment));
        self.write_u32(new_section_entry_offset + 20, aligned_raw_end);
        self.write_u32(new_section_entry_offset + 36, characteristics);

        let coff_header_offset = self.get_coff_header_offset();
        self.write_u16(coff_header_offset + 2, num_sections + 1);

        let new_image_size = new_virt_addr + virtual_size;
        self.write_u32(image_size_offset, new_image_size);

        let new_data_size = aligned_raw_end as usize + self.align_up(size, self.file_alignment) as usize;
        if new_data_size > self.data.len() {
            self.data.resize(new_data_size, 0);
        }

        Ok(new_virt_addr as u64)
    }

    pub fn rename_section(&mut self, old_name: &str, new_name: &str) -> Result<()> {
        if new_name.len() > 8 {
            return Err(VmpError::InvalidOperation(
                "Section name too long (max 8 chars)".to_string()
            ));
        }

        let num_sections = self.get_num_sections();
        let section_table_offset = self.get_section_table_offset();

        for i in 0..num_sections {
            let section_offset = section_table_offset + i as usize * 40;
            let name_bytes = &self.data[section_offset..section_offset + 8];
            let name = String::from_utf8_lossy(name_bytes)
                .trim_end_matches('\0')
                .to_string();

            if name == old_name {
                let mut new_name_bytes = [0u8; 8];
                new_name_bytes[..new_name.len()].copy_from_slice(new_name.as_bytes());
                self.data[section_offset..section_offset + 8]
                    .copy_from_slice(&new_name_bytes);
                return Ok(());
            }
        }

        Err(VmpError::NotFound(format!("Section '{}' not found", old_name)))
    }

    pub fn get_section_name(&self, index: usize) -> Result<String> {
        let num_sections = self.get_num_sections();

        if index >= num_sections as usize {
            return Err(VmpError::IndexOutOfRange);
        }

        let section_table_offset = self.get_section_table_offset();
        let section_offset = section_table_offset + index * 40;
        let name_bytes = &self.data[section_offset..section_offset + 8];
        let name = String::from_utf8_lossy(name_bytes)
            .trim_end_matches('\0')
            .to_string();

        Ok(name)
    }

    pub fn strip_debug_info(&mut self) -> Result<()> {
        let optional_header_offset = self.get_optional_header_offset();

        let num_data_dirs_offset = if self.is_64bit {
            optional_header_offset + 108
        } else {
            optional_header_offset + 92
        };

        let debug_dir_index = 6;
        let debug_dir_entry_offset = num_data_dirs_offset + 4 + debug_dir_index * 8;

        self.write_u32(debug_dir_entry_offset, 0);
        self.write_u32(debug_dir_entry_offset + 4, 0);

        Ok(())
    }

    pub fn update_checksum(&mut self) -> Result<u32> {
        let optional_header_offset = self.get_optional_header_offset();

        let checksum_offset = if self.is_64bit {
            optional_header_offset + 88
        } else {
            optional_header_offset + 80
        };

        self.write_u32(checksum_offset, 0);

        let checksum = self.calculate_checksum();
        self.write_u32(checksum_offset, checksum);

        Ok(checksum)
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    fn align_up(&self, value: u32, alignment: u32) -> u32 {
        ((value + alignment - 1) / alignment) * alignment
    }

    fn write_u16(&mut self, offset: usize, value: u16) {
        self.data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(&mut self, offset: usize, value: u32) {
        self.data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
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
