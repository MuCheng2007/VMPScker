#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DebugType {
    Unknown = 0,
    Coff = 1,
    CodeView = 2,
    Fpo = 3,
    Misc = 4,
    Exception = 5,
    Fixup = 6,
    OmapToSrc = 7,
    OmapFromSrc = 8,
    Borland = 9,
    Reserved10 = 10,
    Clsid = 11,
    VcFeature = 12,
    Pogo = 13,
    Iltcg = 14,
    Mpx = 15,
    Repro = 16,
}

impl DebugType {
    pub fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::Coff,
            2 => Self::CodeView,
            3 => Self::Fpo,
            4 => Self::Misc,
            5 => Self::Exception,
            6 => Self::Fixup,
            7 => Self::OmapToSrc,
            8 => Self::OmapFromSrc,
            9 => Self::Borland,
            10 => Self::Reserved10,
            11 => Self::Clsid,
            12 => Self::VcFeature,
            13 => Self::Pogo,
            14 => Self::Iltcg,
            15 => Self::Mpx,
            16 => Self::Repro,
            _ => Self::Unknown,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Coff => "COFF",
            Self::CodeView => "CodeView",
            Self::Fpo => "FPO",
            Self::Misc => "Misc",
            Self::Exception => "Exception",
            Self::Fixup => "Fixup",
            Self::OmapToSrc => "OmapToSrc",
            Self::OmapFromSrc => "OmapFromSrc",
            Self::Borland => "Borland",
            Self::Reserved10 => "Reserved10",
            Self::Clsid => "CLSID",
            Self::VcFeature => "VCFeature",
            Self::Pogo => "POGO",
            Self::Iltcg => "ILTCG",
            Self::Mpx => "MPX",
            Self::Repro => "Repro",
        }
    }
}

pub struct DebugEntry {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub debug_type: DebugType,
    pub size_of_data: u32,
    pub address_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
}

impl DebugEntry {
    pub fn from_data(data: &[u8]) -> Option<Self> {
        if data.len() < 28 {
            return None;
        }

        let characteristics = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let time_date_stamp = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let major_version = u16::from_le_bytes([data[8], data[9]]);
        let minor_version = u16::from_le_bytes([data[10], data[11]]);
        let debug_type_val = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let size_of_data = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let address_of_raw_data = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        let pointer_to_raw_data = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);

        Some(Self {
            characteristics,
            time_date_stamp,
            major_version,
            minor_version,
            debug_type: DebugType::from_u32(debug_type_val),
            size_of_data,
            address_of_raw_data,
            pointer_to_raw_data,
        })
    }

    pub fn is_codeview(&self) -> bool {
        self.debug_type == DebugType::CodeView
    }
}

pub struct CodeViewInfo {
    pub signature: [u8; 4],
    pub guid: [u8; 16],
    pub age: u32,
    pub pdb_file_name: String,
}

impl CodeViewInfo {
    pub const PDB70_SIGNATURE: [u8; 4] = *b"RSDS";
    pub const PDB20_SIGNATURE: [u8; 4] = *b"NB10";

    pub fn from_data(data: &[u8]) -> Option<Self> {
        if data.len() < 24 {
            return None;
        }

        let signature = [data[0], data[1], data[2], data[3]];

        if signature == Self::PDB70_SIGNATURE {
            if data.len() < 24 {
                return None;
            }
            let guid = [
                data[4], data[5], data[6], data[7],
                data[8], data[9], data[10], data[11],
                data[12], data[13], data[14], data[15],
                data[16], data[17], data[18], data[19],
            ];
            let age = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
            let pdb_file_name = String::from_utf8_lossy(&data[24..])
                .trim_end_matches('\0')
                .to_string();

            Some(Self {
                signature,
                guid,
                age,
                pdb_file_name,
            })
        } else if signature == Self::PDB20_SIGNATURE {
            // NB10 format (older)
            let guid = [0u8; 16];
            let age = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
            let pdb_file_name = String::from_utf8_lossy(&data[16..])
                .trim_end_matches('\0')
                .to_string();

            Some(Self {
                signature,
                guid,
                age,
                pdb_file_name,
            })
        } else {
            None
        }
    }

    pub fn is_pdb70(&self) -> bool {
        self.signature == Self::PDB70_SIGNATURE
    }

    pub fn is_pdb20(&self) -> bool {
        self.signature == Self::PDB20_SIGNATURE
    }
}

pub struct DebugDirectory {
    entries: Vec<DebugEntry>,
    codeview_info: Option<CodeViewInfo>,
}

impl DebugDirectory {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            codeview_info: None,
        }
    }

    pub fn from_data(data: &[u8]) -> Self {
        let mut entries = Vec::new();
        let entry_count = data.len() / 28;

        for i in 0..entry_count {
            let offset = i * 28;
            if offset + 28 > data.len() {
                break;
            }

            if let Some(entry) = DebugEntry::from_data(&data[offset..offset + 28]) {
                entries.push(entry);
            }
        }

        Self {
            entries,
            codeview_info: None,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&DebugEntry> {
        self.entries.get(index)
    }

    pub fn iter(&self) -> impl Iterator<Item = &DebugEntry> {
        self.entries.iter()
    }

    pub fn find_by_type(&self, debug_type: DebugType) -> Option<&DebugEntry> {
        self.entries.iter().find(|e| e.debug_type == debug_type)
    }

    pub fn codeview_entry(&self) -> Option<&DebugEntry> {
        self.find_by_type(DebugType::CodeView)
    }

    pub fn set_codeview_info(&mut self, info: CodeViewInfo) {
        self.codeview_info = Some(info);
    }

    pub fn codeview_info(&self) -> Option<&CodeViewInfo> {
        self.codeview_info.as_ref()
    }

    pub fn pdb_file_name(&self) -> Option<&str> {
        self.codeview_info.as_ref().map(|info| info.pdb_file_name.as_str())
    }

    pub fn add(&mut self, entry: DebugEntry) {
        self.entries.push(entry);
    }
}

impl Default for DebugDirectory {
    fn default() -> Self {
        Self::new()
    }
}
