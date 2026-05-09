pub struct Segment {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_address: u64,
    pub raw_size: u64,
    pub characteristics: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
}

impl Segment {
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
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
        }
    }

    pub fn from_section_table(data: &[u8]) -> Option<Self> {
        if data.len() < 40 {
            return None;
        }

        let name = String::from_utf8_lossy(&data[0..8])
            .trim_end_matches('\0')
            .to_string();
        let virtual_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as u64;
        let virtual_address = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as u64;
        let raw_size = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as u64;
        let raw_address = u32::from_le_bytes([data[20], data[21], data[22], data[23]]) as u64;
        let pointer_to_relocations = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
        let pointer_to_linenumbers = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
        let number_of_relocations = u16::from_le_bytes([data[32], data[33]]);
        let number_of_linenumbers = u16::from_le_bytes([data[34], data[35]]);
        let characteristics = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);

        Some(Self {
            name,
            virtual_address,
            virtual_size,
            raw_address,
            raw_size,
            characteristics,
            pointer_to_relocations,
            pointer_to_linenumbers,
            number_of_relocations,
            number_of_linenumbers,
        })
    }

    pub fn is_code(&self) -> bool {
        (self.characteristics & 0x00000020) != 0
    }

    pub fn is_initialized_data(&self) -> bool {
        (self.characteristics & 0x00000040) != 0
    }

    pub fn is_uninitialized_data(&self) -> bool {
        (self.characteristics & 0x00000080) != 0
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

    pub fn is_shareable(&self) -> bool {
        (self.characteristics & 0x10000000) != 0
    }

    pub fn is_discardable(&self) -> bool {
        (self.characteristics & 0x02000000) != 0
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

    pub fn alignment(&self) -> u32 {
        ((self.characteristics >> 20) & 0xF) * 0x1000
    }
}

pub struct SegmentList {
    segments: Vec<Segment>,
}

impl SegmentList {
    pub fn new() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    pub fn from_data(data: &[u8], count: usize) -> Self {
        let mut segments = Vec::with_capacity(count);

        for i in 0..count {
            let offset = i * 40;
            if offset + 40 > data.len() {
                break;
            }

            if let Some(segment) = Segment::from_section_table(&data[offset..offset + 40]) {
                segments.push(segment);
            }
        }

        Self { segments }
    }

    pub fn len(&self) -> usize {
        self.segments.len()
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&Segment> {
        self.segments.get(index)
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut Segment> {
        self.segments.get_mut(index)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Segment> {
        self.segments.iter()
    }

    pub fn find_by_name(&self, name: &str) -> Option<&Segment> {
        self.segments.iter().find(|s| s.name == name)
    }

    pub fn find_by_rva(&self, rva: u64) -> Option<&Segment> {
        self.segments.iter().find(|s| s.contains_rva(rva))
    }

    pub fn find_by_offset(&self, offset: u64) -> Option<&Segment> {
        self.segments.iter().find(|s| s.contains_offset(offset))
    }

    pub fn add(&mut self, segment: Segment) {
        self.segments.push(segment);
    }

    pub fn code_segments(&self) -> impl Iterator<Item = &Segment> {
        self.segments.iter().filter(|s| s.is_code())
    }

    pub fn data_segments(&self) -> impl Iterator<Item = &Segment> {
        self.segments.iter().filter(|s| s.is_initialized_data())
    }

    pub fn get_section_by_address(&self, address: u64) -> Option<&Segment> {
        self.find_by_rva(address)
    }
}

impl Default for SegmentList {
    fn default() -> Self {
        Self::new()
    }
}
