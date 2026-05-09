pub struct LoadConfigDirectory32 {
    pub size: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub global_flags_clear: u32,
    pub global_flags_set: u32,
    pub critical_section_default_timeout: u32,
    pub de_commit_free_block_threshold: u32,
    pub de_commit_total_free_threshold: u32,
    pub lock_prefix_table: u32,
    pub maximum_allocation_size: u32,
    pub virtual_memory_threshold: u32,
    pub process_heap_flags: u32,
    pub process_affinity_mask: u32,
    pub csd_version: u16,
    pub dependent_load_flags: u16,
    pub edit_list: u32,
    pub security_cookie: u32,
    pub se_handler_table: u32,
    pub se_handler_count: u32,
    pub guard_cf_check_function_pointer: u32,
    pub guard_cf_dispatch_function_pointer: u32,
    pub guard_cf_function_table: u32,
    pub guard_cf_function_count: u32,
    pub guard_flags: u32,
}

impl LoadConfigDirectory32 {
    pub fn from_data(data: &[u8]) -> Option<Self> {
        if data.len() < 64 {
            return None;
        }

        Some(Self {
            size: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            time_date_stamp: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            major_version: u16::from_le_bytes([data[8], data[9]]),
            minor_version: u16::from_le_bytes([data[10], data[11]]),
            global_flags_clear: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            global_flags_set: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            critical_section_default_timeout: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            de_commit_free_block_threshold: u32::from_le_bytes([data[24], data[25], data[26], data[27]]),
            de_commit_total_free_threshold: u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
            lock_prefix_table: u32::from_le_bytes([data[32], data[33], data[34], data[35]]),
            maximum_allocation_size: u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
            virtual_memory_threshold: u32::from_le_bytes([data[40], data[41], data[42], data[43]]),
            process_heap_flags: u32::from_le_bytes([data[44], data[45], data[46], data[47]]),
            process_affinity_mask: u32::from_le_bytes([data[48], data[49], data[50], data[51]]),
            csd_version: u16::from_le_bytes([data[52], data[53]]),
            dependent_load_flags: u16::from_le_bytes([data[54], data[55]]),
            edit_list: u32::from_le_bytes([data[56], data[57], data[58], data[59]]),
            security_cookie: u32::from_le_bytes([data[60], data[61], data[62], data[63]]),
            se_handler_table: u32::from_le_bytes([data[64], data[65], data[66], data[67]]),
            se_handler_count: u32::from_le_bytes([data[68], data[69], data[70], data[71]]),
            guard_cf_check_function_pointer: u32::from_le_bytes([data[72], data[73], data[74], data[75]]),
            guard_cf_dispatch_function_pointer: u32::from_le_bytes([data[76], data[77], data[78], data[79]]),
            guard_cf_function_table: u32::from_le_bytes([data[80], data[81], data[82], data[83]]),
            guard_cf_function_count: u32::from_le_bytes([data[84], data[85], data[86], data[87]]),
            guard_flags: u32::from_le_bytes([data[88], data[89], data[90], data[91]]),
        })
    }

    pub fn has_guard_cf(&self) -> bool {
        (self.guard_flags & 0x00000100) != 0
    }
}

pub struct LoadConfigDirectory64 {
    pub size: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub global_flags_clear: u32,
    pub global_flags_set: u32,
    pub critical_section_default_timeout: u32,
    pub de_commit_free_block_threshold: u64,
    pub de_commit_total_free_threshold: u64,
    pub lock_prefix_table: u64,
    pub maximum_allocation_size: u64,
    pub virtual_memory_threshold: u64,
    pub process_affinity_mask: u64,
    pub process_heap_flags: u32,
    pub csd_version: u16,
    pub dependent_load_flags: u16,
    pub edit_list: u64,
    pub security_cookie: u64,
    pub se_handler_table: u64,
    pub se_handler_count: u64,
    pub guard_cf_check_function_pointer: u64,
    pub guard_cf_dispatch_function_pointer: u64,
    pub guard_cf_function_table: u64,
    pub guard_cf_function_count: u64,
    pub guard_flags: u32,
}

impl LoadConfigDirectory64 {
    pub fn from_data(data: &[u8]) -> Option<Self> {
        if data.len() < 112 {
            return None;
        }

        Some(Self {
            size: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            time_date_stamp: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            major_version: u16::from_le_bytes([data[8], data[9]]),
            minor_version: u16::from_le_bytes([data[10], data[11]]),
            global_flags_clear: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            global_flags_set: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            critical_section_default_timeout: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            de_commit_free_block_threshold: u64::from_le_bytes([data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31]]),
            de_commit_total_free_threshold: u64::from_le_bytes([data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39]]),
            lock_prefix_table: u64::from_le_bytes([data[40], data[41], data[42], data[43], data[44], data[45], data[46], data[47]]),
            maximum_allocation_size: u64::from_le_bytes([data[48], data[49], data[50], data[51], data[52], data[53], data[54], data[55]]),
            virtual_memory_threshold: u64::from_le_bytes([data[56], data[57], data[58], data[59], data[60], data[61], data[62], data[63]]),
            process_affinity_mask: u64::from_le_bytes([data[64], data[65], data[66], data[67], data[68], data[69], data[70], data[71]]),
            process_heap_flags: u32::from_le_bytes([data[72], data[73], data[74], data[75]]),
            csd_version: u16::from_le_bytes([data[76], data[77]]),
            dependent_load_flags: u16::from_le_bytes([data[78], data[79]]),
            edit_list: u64::from_le_bytes([data[80], data[81], data[82], data[83], data[84], data[85], data[86], data[87]]),
            security_cookie: u64::from_le_bytes([data[88], data[89], data[90], data[91], data[92], data[93], data[94], data[95]]),
            se_handler_table: u64::from_le_bytes([data[96], data[97], data[98], data[99], data[100], data[101], data[102], data[103]]),
            se_handler_count: u64::from_le_bytes([data[104], data[105], data[106], data[107], data[108], data[109], data[110], data[111]]),
            guard_cf_check_function_pointer: u64::from_le_bytes([data[112], data[113], data[114], data[115], data[116], data[117], data[118], data[119]]),
            guard_cf_dispatch_function_pointer: u64::from_le_bytes([data[120], data[121], data[122], data[123], data[124], data[125], data[126], data[127]]),
            guard_cf_function_table: u64::from_le_bytes([data[128], data[129], data[130], data[131], data[132], data[133], data[134], data[135]]),
            guard_cf_function_count: u64::from_le_bytes([data[136], data[137], data[138], data[139], data[140], data[141], data[142], data[143]]),
            guard_flags: u32::from_le_bytes([data[144], data[145], data[146], data[147]]),
        })
    }

    pub fn has_guard_cf(&self) -> bool {
        (self.guard_flags & 0x00000100) != 0
    }
}

pub enum LoadConfigDirectory {
    Config32(LoadConfigDirectory32),
    Config64(LoadConfigDirectory64),
}

impl LoadConfigDirectory {
    pub fn from_data(data: &[u8], is_64bit: bool) -> Option<Self> {
        if is_64bit {
            LoadConfigDirectory64::from_data(data).map(Self::Config64)
        } else {
            LoadConfigDirectory32::from_data(data).map(Self::Config32)
        }
    }

    pub fn has_guard_cf(&self) -> bool {
        match self {
            Self::Config32(cfg) => cfg.has_guard_cf(),
            Self::Config64(cfg) => cfg.has_guard_cf(),
        }
    }

    pub fn security_cookie(&self) -> u64 {
        match self {
            Self::Config32(cfg) => cfg.security_cookie as u64,
            Self::Config64(cfg) => cfg.security_cookie,
        }
    }
}
