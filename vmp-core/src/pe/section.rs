pub struct Section {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_address: u64,
    pub raw_size: u64,
    pub characteristics: u32,
}

impl Section {
    pub fn new(
        name: impl Into<String>,
        virtual_address: u64,
        virtual_size: u64,
        raw_address: u64,
        raw_size: u64,
        characteristics: u32,
    ) -> Self {
        Self {
            name: name.into(),
            virtual_address,
            virtual_size,
            raw_address,
            raw_size,
            characteristics,
        }
    }

    pub fn is_code(&self) -> bool {
        (self.characteristics & 0x20000000) != 0
    }

    pub fn is_initialized_data(&self) -> bool {
        (self.characteristics & 0x40000000) != 0
    }

    pub fn is_uninitialized_data(&self) -> bool {
        (self.characteristics & 0x80000000) != 0
    }

    pub fn is_readable(&self) -> bool {
        (self.characteristics & 0x40000000) != 0
    }

    pub fn is_writable(&self) -> bool {
        (self.characteristics & 0x80000000) != 0
    }

    pub fn is_executable(&self) -> bool {
        (self.characteristics & 0x20000000) != 0
    }

    pub fn contains_rva(&self, rva: u64) -> bool {
        rva >= self.virtual_address && rva < self.virtual_address + self.virtual_size
    }

    pub fn contains_offset(&self, offset: u64) -> bool {
        offset >= self.raw_address && offset < self.raw_address + self.raw_size
    }

    pub fn rva_to_offset(&self, rva: u64) -> Option<u64> {
        if self.contains_rva(rva) {
            Some(self.raw_address + (rva - self.virtual_address))
        } else {
            None
        }
    }

    pub fn offset_to_rva(&self, offset: u64) -> Option<u64> {
        if self.contains_offset(offset) {
            Some(self.virtual_address + (offset - self.raw_address))
        } else {
            None
        }
    }
}

pub struct SectionList {
    sections: Vec<Section>,
}

impl SectionList {
    pub fn new() -> Self {
        Self {
            sections: Vec::new(),
        }
    }

    pub fn from_goblin(sections: &[goblin::pe::section_table::SectionTable]) -> Self {
        let sections = sections
            .iter()
            .map(|s| {
                let name = String::from_utf8_lossy(&s.name)
                    .trim_end_matches('\0')
                    .to_string();
                Section::new(
                    name,
                    s.virtual_address as u64,
                    s.virtual_size as u64,
                    s.pointer_to_raw_data as u64,
                    s.size_of_raw_data as u64,
                    s.characteristics,
                )
            })
            .collect();
        Self { sections }
    }

    pub fn len(&self) -> usize {
        self.sections.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sections.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&Section> {
        self.sections.get(index)
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut Section> {
        self.sections.get_mut(index)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter()
    }

    pub fn find_by_name(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    pub fn find_by_rva(&self, rva: u64) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains_rva(rva))
    }

    pub fn find_by_offset(&self, offset: u64) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains_offset(offset))
    }

    pub fn add(&mut self, section: Section) {
        self.sections.push(section);
    }

    pub fn code_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(|s| s.is_code())
    }

    pub fn data_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(|s| s.is_initialized_data())
    }
}

impl Default for SectionList {
    fn default() -> Self {
        Self::new()
    }
}
