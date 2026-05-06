#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum DirectoryType {
    Export = 0,
    Import = 1,
    Resource = 2,
    Exception = 3,
    Security = 4,
    BaseReloc = 5,
    Debug = 6,
    Architecture = 7,
    GlobalPtr = 8,
    TLS = 9,
    LoadConfig = 10,
    BoundImport = 11,
    IAT = 12,
    DelayImport = 13,
    COMDescriptor = 14,
}

impl DirectoryType {
    pub fn from_usize(value: usize) -> Option<Self> {
        match value {
            0 => Some(Self::Export),
            1 => Some(Self::Import),
            2 => Some(Self::Resource),
            3 => Some(Self::Exception),
            4 => Some(Self::Security),
            5 => Some(Self::BaseReloc),
            6 => Some(Self::Debug),
            7 => Some(Self::Architecture),
            8 => Some(Self::GlobalPtr),
            9 => Some(Self::TLS),
            10 => Some(Self::LoadConfig),
            11 => Some(Self::BoundImport),
            12 => Some(Self::IAT),
            13 => Some(Self::DelayImport),
            14 => Some(Self::COMDescriptor),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Export => "Export",
            Self::Import => "Import",
            Self::Resource => "Resource",
            Self::Exception => "Exception",
            Self::Security => "Security",
            Self::BaseReloc => "BaseReloc",
            Self::Debug => "Debug",
            Self::Architecture => "Architecture",
            Self::GlobalPtr => "GlobalPtr",
            Self::TLS => "TLS",
            Self::LoadConfig => "LoadConfig",
            Self::BoundImport => "BoundImport",
            Self::IAT => "IAT",
            Self::DelayImport => "DelayImport",
            Self::COMDescriptor => "COMDescriptor",
        }
    }
}

pub struct DirectoryEntry {
    pub directory_type: DirectoryType,
    pub virtual_address: u32,
    pub size: u32,
}

impl DirectoryEntry {
    pub fn new(directory_type: DirectoryType, virtual_address: u32, size: u32) -> Self {
        Self {
            directory_type,
            virtual_address,
            size,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.virtual_address != 0 && self.size != 0
    }
}

pub struct DirectoryList {
    entries: Vec<DirectoryEntry>,
}

impl DirectoryList {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn from_data(data: &[u8], count: usize) -> Self {
        let mut entries = Vec::with_capacity(count);

        for i in 0..count {
            if i * 8 + 8 > data.len() {
                break;
            }

            let offset = i * 8;
            let virtual_address = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let size = u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);

            if let Some(dir_type) = DirectoryType::from_usize(i) {
                entries.push(DirectoryEntry::new(dir_type, virtual_address, size));
            }
        }

        Self { entries }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&DirectoryEntry> {
        self.entries.get(index)
    }

    pub fn get_by_type(&self, dir_type: DirectoryType) -> Option<&DirectoryEntry> {
        self.entries.iter().find(|e| e.directory_type == dir_type)
    }

    pub fn iter(&self) -> impl Iterator<Item = &DirectoryEntry> {
        self.entries.iter()
    }

    pub fn valid_entries(&self) -> impl Iterator<Item = &DirectoryEntry> {
        self.entries.iter().filter(|e| e.is_valid())
    }

    pub fn add(&mut self, entry: DirectoryEntry) {
        self.entries.push(entry);
    }
}

impl Default for DirectoryList {
    fn default() -> Self {
        Self::new()
    }
}
