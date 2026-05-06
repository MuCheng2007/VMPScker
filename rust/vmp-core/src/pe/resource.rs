//! PE 资源目录处理
//!
//! 支持解析和重建 PE 文件中的资源目录。

use crate::error::{Result, VmpError};

/// 资源类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ResourceType {
    Cursor = 1,
    Bitmap = 2,
    Icon = 3,
    Menu = 4,
    Dialog = 5,
    StringTable = 6,
    FontDir = 7,
    Font = 8,
    Accelerators = 9,
    RcData = 10,
    MessageTable = 11,
    GroupCursor = 12,
    GroupIcon = 14,
    VersionInfo = 16,
    DlgInclude = 17,
    PlugPlay = 19,
    Vxd = 20,
    AniCursor = 21,
    AniIcon = 22,
    Html = 23,
    Manifest = 24,
    DialogInit = 240,
    Toolbar = 241,
    Unknown = 0,
}

impl ResourceType {
    pub fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::Cursor,
            2 => Self::Bitmap,
            3 => Self::Icon,
            4 => Self::Menu,
            5 => Self::Dialog,
            6 => Self::StringTable,
            7 => Self::FontDir,
            8 => Self::Font,
            9 => Self::Accelerators,
            10 => Self::RcData,
            11 => Self::MessageTable,
            12 => Self::GroupCursor,
            14 => Self::GroupIcon,
            16 => Self::VersionInfo,
            17 => Self::DlgInclude,
            19 => Self::PlugPlay,
            20 => Self::Vxd,
            21 => Self::AniCursor,
            22 => Self::AniIcon,
            23 => Self::Html,
            24 => Self::Manifest,
            240 => Self::DialogInit,
            241 => Self::Toolbar,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cursor => "Cursor",
            Self::Bitmap => "Bitmap",
            Self::Icon => "Icon",
            Self::Menu => "Menu",
            Self::Dialog => "Dialog",
            Self::StringTable => "StringTable",
            Self::FontDir => "FontDir",
            Self::Font => "Font",
            Self::Accelerators => "Accelerators",
            Self::RcData => "RcData",
            Self::MessageTable => "MessageTable",
            Self::GroupCursor => "GroupCursor",
            Self::GroupIcon => "GroupIcon",
            Self::VersionInfo => "VersionInfo",
            Self::DlgInclude => "DlgInclude",
            Self::PlugPlay => "PlugPlay",
            Self::Vxd => "Vxd",
            Self::AniCursor => "AniCursor",
            Self::AniIcon => "AniIcon",
            Self::Html => "Html",
            Self::Manifest => "Manifest",
            Self::DialogInit => "DialogInit",
            Self::Toolbar => "Toolbar",
            Self::Unknown => "Unknown",
        }
    }
}

/// 资源目录条目名称（可以是 ID 或字符串）
#[derive(Debug, Clone)]
pub enum ResourceName {
    Id(u32),
    Name(String),
}

impl ResourceName {
    pub fn as_id(&self) -> Option<u32> {
        match self {
            Self::Id(id) => Some(*id),
            _ => None,
        }
    }

    pub fn as_name(&self) -> Option<&str> {
        match self {
            Self::Name(name) => Some(name),
            _ => None,
        }
    }

    pub fn is_id(&self) -> bool {
        matches!(self, Self::Id(_))
    }

    pub fn is_name(&self) -> bool {
        matches!(self, Self::Name(_))
    }
}

/// 资源数据条目
#[derive(Debug, Clone)]
pub struct ResourceDataEntry {
    pub data_rva: u32,
    pub size: u32,
    pub code_page: u32,
    pub reserved: u32,
}

impl ResourceDataEntry {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }

        Some(Self {
            data_rva: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            size: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            code_page: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            reserved: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        })
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&self.data_rva.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.size.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.code_page.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.reserved.to_le_bytes());
        bytes
    }
}

/// 资源条目
#[derive(Debug, Clone)]
pub enum ResourceEntry {
    /// 数据条目（叶子节点）
    Data(ResourceDataEntry),
    /// 子目录
    Directory(ResourceDirectory),
}

/// 资源目录
#[derive(Debug, Clone)]
pub struct ResourceDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: ResourceName,
    pub entries: Vec<(ResourceName, ResourceEntry)>,
}

impl ResourceDirectory {
    pub fn new(name: ResourceName) -> Self {
        Self {
            characteristics: 0,
            time_date_stamp: 0,
            major_version: 0,
            minor_version: 0,
            name,
            entries: Vec::new(),
        }
    }

    /// 从 PE 数据解析资源目录
    pub fn parse(data: &[u8], rva: u32, base_rva: u32) -> Result<Self> {
        let offset = (rva - base_rva) as usize;
        if offset + 16 > data.len() {
            return Err(VmpError::InvalidData("Resource directory too small".to_string()));
        }

        let characteristics = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        let time_date_stamp = u32::from_le_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]);
        let major_version = u16::from_le_bytes([data[offset + 8], data[offset + 9]]);
        let minor_version = u16::from_le_bytes([data[offset + 10], data[offset + 11]]);
        let number_of_named_entries = u16::from_le_bytes([data[offset + 12], data[offset + 13]]);
        let number_of_id_entries = u16::from_le_bytes([data[offset + 14], data[offset + 15]]);

        let mut dir = Self {
            characteristics,
            time_date_stamp,
            major_version,
            minor_version,
            name: ResourceName::Id(0),
            entries: Vec::new(),
        };

        let mut entry_offset = offset + 16;

        // 解析命名条目
        for _ in 0..number_of_named_entries {
            if entry_offset + 8 > data.len() {
                break;
            }
            let name_offset = u32::from_le_bytes([data[entry_offset], data[entry_offset + 1], data[entry_offset + 2], data[entry_offset + 3]]);
            let data_offset = u32::from_le_bytes([data[entry_offset + 4], data[entry_offset + 5], data[entry_offset + 6], data[entry_offset + 7]]);
            
            let name = Self::parse_name(data, name_offset, base_rva)?;
            let entry = Self::parse_entry(data, data_offset, base_rva)?;
            
            dir.entries.push((name, entry));
            entry_offset += 8;
        }

        // 解析 ID 条目
        for _ in 0..number_of_id_entries {
            if entry_offset + 8 > data.len() {
                break;
            }
            let name_id = u32::from_le_bytes([data[entry_offset], data[entry_offset + 1], data[entry_offset + 2], data[entry_offset + 3]]);
            let data_offset = u32::from_le_bytes([data[entry_offset + 4], data[entry_offset + 5], data[entry_offset + 6], data[entry_offset + 7]]);
            
            let name = ResourceName::Id(name_id);
            let entry = Self::parse_entry(data, data_offset, base_rva)?;
            
            dir.entries.push((name, entry));
            entry_offset += 8;
        }

        Ok(dir)
    }

    /// 解析名称
    fn parse_name(data: &[u8], name_offset: u32, base_rva: u32) -> Result<ResourceName> {
        let offset = ((name_offset & 0x7FFFFFFF) - base_rva) as usize;
        if offset + 2 > data.len() {
            return Err(VmpError::InvalidData("Resource name too small".to_string()));
        }

        let length = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        if offset + 2 + length * 2 > data.len() {
            return Err(VmpError::InvalidData("Resource name length exceeds data".to_string()));
        }

        let name = String::from_utf16_lossy(
            &(0..length)
                .map(|i| u16::from_le_bytes([data[offset + 2 + i * 2], data[offset + 3 + i * 2]]))
                .collect::<Vec<_>>()
        );

        Ok(ResourceName::Name(name))
    }

    /// 解析条目
    fn parse_entry(data: &[u8], entry_offset: u32, base_rva: u32) -> Result<ResourceEntry> {
        if (entry_offset & 0x80000000) != 0 {
            // 子目录
            let subdir_rva = entry_offset & 0x7FFFFFFF;
            let dir = Self::parse(data, subdir_rva, base_rva)?;
            Ok(ResourceEntry::Directory(dir))
        } else {
            // 数据条目
            let data_entry_offset = (entry_offset - base_rva) as usize;
            if data_entry_offset + 16 > data.len() {
                return Err(VmpError::InvalidData("Resource data entry too small".to_string()));
            }
            
            let data_entry = ResourceDataEntry::from_bytes(&data[data_entry_offset..data_entry_offset + 16])
                .ok_or_else(|| VmpError::InvalidData("Failed to parse resource data entry".to_string()))?;
            
            Ok(ResourceEntry::Data(data_entry))
        }
    }

    /// 查找条目
    pub fn find_entry(&self, name: &ResourceName) -> Option<&ResourceEntry> {
        self.entries.iter()
            .find(|(n, _)| match (n, name) {
                (ResourceName::Id(a), ResourceName::Id(b)) => a == b,
                (ResourceName::Name(a), ResourceName::Name(b)) => a == b,
                _ => false,
            })
            .map(|(_, e)| e)
    }

    /// 获取所有数据条目（递归）
    pub fn get_all_data_entries(&self, path: Vec<ResourceName>) -> Vec<(Vec<ResourceName>, &ResourceDataEntry)> {
        let mut result = Vec::new();

        for (name, entry) in &self.entries {
            let mut new_path = path.clone();
            new_path.push(name.clone());

            match entry {
                ResourceEntry::Data(data) => {
                    result.push((new_path, data));
                }
                ResourceEntry::Directory(dir) => {
                    result.extend(dir.get_all_data_entries(new_path));
                }
            }
        }

        result
    }

    /// 计算目录大小
    pub fn calculate_size(&self) -> usize {
        let header_size = 16; // 目录头部
        let entry_size = 8; // 每个条目 8 字节
        let mut total_size = header_size + self.entries.len() * entry_size;

        for (_, entry) in &self.entries {
            match entry {
                ResourceEntry::Data(_) => {
                    total_size += 16; // 数据条目大小
                }
                ResourceEntry::Directory(dir) => {
                    total_size += dir.calculate_size();
                }
            }
        }

        total_size
    }

    /// 计算完整重建所需的总大小
    /// 
    /// 返回：(目录表大小, 名称表大小, 数据条目表大小, 数据大小)
    pub fn calculate_rebuild_size(&self) -> (usize, usize, usize, usize) {
        let mut dir_size = 16; // 根目录头部
        let mut name_table_size = 0;
        let mut data_entry_table_size = 0;
        let mut data_size = 0;

        self.calculate_rebuild_size_recursive(
            &mut dir_size,
            &mut name_table_size,
            &mut data_entry_table_size,
            &mut data_size,
        );

        (dir_size, name_table_size, data_entry_table_size, data_size)
    }

    fn calculate_rebuild_size_recursive(
        &self,
        dir_size: &mut usize,
        name_table_size: &mut usize,
        data_entry_table_size: &mut usize,
        data_size: &mut usize,
    ) {
        // 当前目录的条目
        *dir_size += self.entries.len() * 8;

        for (name, entry) in &self.entries {
            // 名称条目
            if let ResourceName::Name(n) = name {
                // 2字节长度 + Unicode字符串（每个字符2字节）
                *name_table_size += 2 + n.len() * 2;
                // 对齐到4字节
                *name_table_size = (*name_table_size + 3) & !3;
            }

            match entry {
                ResourceEntry::Data(data_entry) => {
                    *data_entry_table_size += 16; // IMAGE_RESOURCE_DATA_ENTRY大小
                    *data_size += data_entry.size as usize;
                    // 数据对齐到4字节
                    *data_size = (*data_size + 3) & !3;
                }
                ResourceEntry::Directory(subdir) => {
                    subdir.calculate_rebuild_size_recursive(
                        dir_size,
                        name_table_size,
                        data_entry_table_size,
                        data_size,
                    );
                }
            }
        }
    }

    /// 写入目录头部到数据缓冲区
    /// 
    /// # Arguments
    /// * `data` - 目标数据缓冲区
    /// * `name_entries` - 命名条目数量
    /// * `id_entries` - ID条目数量
    pub fn write_header(&self, data: &mut Vec<u8>, name_entries: u16, id_entries: u16) {
        // Characteristics
        data.extend_from_slice(&self.characteristics.to_le_bytes());
        // TimeDateStamp
        data.extend_from_slice(&self.time_date_stamp.to_le_bytes());
        // MajorVersion
        data.extend_from_slice(&self.major_version.to_le_bytes());
        // MinorVersion
        data.extend_from_slice(&self.minor_version.to_le_bytes());
        // NumberOfNamedEntries
        data.extend_from_slice(&name_entries.to_le_bytes());
        // NumberOfIdEntries
        data.extend_from_slice(&id_entries.to_le_bytes());
    }

    /// 写入目录条目到数据缓冲区
    /// 
    /// # Arguments
    /// * `data` - 目标数据缓冲区
    /// * `name_offset` - 名称偏移（高位置1表示使用名称表）
    /// * `data_offset` - 数据偏移（高位置1表示子目录）
    pub fn write_entry(&self, data: &mut Vec<u8>, name_offset: u32, data_offset: u32) {
        data.extend_from_slice(&name_offset.to_le_bytes());
        data.extend_from_slice(&data_offset.to_le_bytes());
    }

    /// 写入名称条目到数据缓冲区
    /// 
    /// # Arguments
    /// * `data` - 目标数据缓冲区
    /// * `name` - 资源名称
    /// * `offset` - 当前名称表偏移（相对于资源节起始）
    /// 
    /// 返回写入后的新偏移
    pub fn write_name(data: &mut Vec<u8>, name: &ResourceName, offset: u32) -> u32 {
        if let ResourceName::Name(n) = name {
            let length = n.len() as u16;
            data.extend_from_slice(&length.to_le_bytes());
            for c in n.encode_utf16() {
                data.extend_from_slice(&c.to_le_bytes());
            }
            // 对齐到4字节
            while data.len() % 4 != 0 {
                data.push(0);
            }
        }
        data.len() as u32
    }

    /// 写入数据条目到数据缓冲区
    /// 
    /// # Arguments
    /// * `data` - 目标数据缓冲区
    /// * `data_entry` - 数据条目
    pub fn write_data_entry(data: &mut Vec<u8>, data_entry: &ResourceDataEntry) {
        data.extend_from_slice(&data_entry.data_rva.to_le_bytes());
        data.extend_from_slice(&data_entry.size.to_le_bytes());
        data.extend_from_slice(&data_entry.code_page.to_le_bytes());
        data.extend_from_slice(&data_entry.reserved.to_le_bytes());
    }

    /// 完整重建资源目录
    /// 
    /// # Arguments
    /// * `section_data` - 原始节区数据（用于复制资源数据）
    /// * `base_rva` - 资源节基址RVA
    /// * `section_va` - 资源节虚拟地址
    /// 
    /// 返回重建后的资源目录数据
    pub fn rebuild(&self, section_data: &[u8], base_rva: u32, section_va: u64) -> Result<Vec<u8>> {
        // 计算各部分大小
        let (dir_size, name_table_size, data_entry_size, data_size) = self.calculate_rebuild_size();

        // 预留目录表空间
        let dir_table_offset = 0;
        let name_table_base = dir_table_offset + dir_size;
        let data_entry_table_base = name_table_base + name_table_size;
        let data_table_base = data_entry_table_base + data_entry_size;

        // 扩展结果向量
        let mut result = Vec::with_capacity(data_table_base + data_size);
        result.resize(data_table_base + data_size, 0);

        // 使用可变偏移量
        let mut name_table_offset = name_table_base;
        let mut data_entry_offset = data_entry_table_base;
        let mut data_table_offset = data_table_base;

        // 递归重建
        self.rebuild_recursive(
            &mut result,
            section_data,
            base_rva,
            section_va,
            dir_table_offset,
            name_table_base,
            data_entry_table_base,
            data_table_base,
            &mut name_table_offset,
            &mut data_entry_offset,
            &mut data_table_offset,
        )?;

        Ok(result)
    }

    fn rebuild_recursive(
        &self,
        result: &mut Vec<u8>,
        section_data: &[u8],
        base_rva: u32,
        section_va: u64,
        dir_offset: usize,
        name_table_base: usize,
        data_entry_base: usize,
        data_table_base: usize,
        name_table_offset: &mut usize,
        data_entry_offset: &mut usize,
        data_table_offset: &mut usize,
    ) -> Result<()> {
        // 分离命名条目和ID条目
        let named_entries: Vec<_> = self.entries.iter()
            .filter(|(name, _)| matches!(name, ResourceName::Name(_)))
            .collect();
        let id_entries: Vec<_> = self.entries.iter()
            .filter(|(name, _)| matches!(name, ResourceName::Id(_)))
            .collect();

        // 写入目录头部
        let mut header = Vec::new();
        self.write_header(&mut header, named_entries.len() as u16, id_entries.len() as u16);
        result[dir_offset..dir_offset + 16].copy_from_slice(&header);

        let mut entry_offset = dir_offset + 16;

        // 写入命名条目
        for (name, entry) in named_entries {
            let name_offset = *name_table_offset - name_table_base;
            let name_rva = (name_table_base + name_offset) as u32 | 0x80000000;

            // 写入名称到名称表
            if let ResourceName::Name(n) = name {
                let length = n.len() as u16;
                result[*name_table_offset..*name_table_offset + 2].copy_from_slice(&length.to_le_bytes());
                *name_table_offset += 2;
                for c in n.encode_utf16() {
                    result[*name_table_offset..*name_table_offset + 2].copy_from_slice(&c.to_le_bytes());
                    *name_table_offset += 2;
                }
                // 对齐到4字节
                while *name_table_offset % 4 != 0 {
                    result[*name_table_offset] = 0;
                    *name_table_offset += 1;
                }
            }

            // 写入条目
            match entry {
                ResourceEntry::Data(data_entry) => {
                    Self::write_data_entry_to_result(
                        result,
                        section_data,
                        data_entry,
                        base_rva,
                        section_va,
                        data_entry_base,
                        data_table_base,
                        name_rva,
                        entry_offset,
                        data_entry_offset,
                        data_table_offset,
                    );
                    entry_offset += 8;
                }
                ResourceEntry::Directory(subdir) => {
                    let subdir_offset = entry_offset + 8; // 子目录紧跟在当前条目后
                    let subdir_rva = (subdir_offset as u32) | 0x80000000;

                    // 写入目录条目（指向子目录）
                    result[entry_offset..entry_offset + 4].copy_from_slice(&name_rva.to_le_bytes());
                    result[entry_offset + 4..entry_offset + 8].copy_from_slice(&subdir_rva.to_le_bytes());
                    entry_offset += 8;

                    // 递归重建子目录
                    subdir.rebuild_recursive(
                        result,
                        section_data,
                        base_rva,
                        section_va,
                        subdir_offset,
                        name_table_base,
                        data_entry_base,
                        data_table_base,
                        name_table_offset,
                        data_entry_offset,
                        data_table_offset,
                    )?;
                }
            }
        }

        // 写入ID条目
        for (name, entry) in id_entries {
            let name_id = match name {
                ResourceName::Id(id) => *id,
                _ => 0,
            };

            match entry {
                ResourceEntry::Data(data_entry) => {
                    Self::write_data_entry_to_result(
                        result,
                        section_data,
                        data_entry,
                        base_rva,
                        section_va,
                        data_entry_base,
                        data_table_base,
                        name_id,
                        entry_offset,
                        data_entry_offset,
                        data_table_offset,
                    );
                    entry_offset += 8;
                }
                ResourceEntry::Directory(subdir) => {
                    let subdir_offset = entry_offset + 8;
                    let subdir_rva = (subdir_offset as u32) | 0x80000000;

                    // 写入目录条目
                    result[entry_offset..entry_offset + 4].copy_from_slice(&name_id.to_le_bytes());
                    result[entry_offset + 4..entry_offset + 8].copy_from_slice(&subdir_rva.to_le_bytes());
                    entry_offset += 8;

                    // 递归重建子目录
                    subdir.rebuild_recursive(
                        result,
                        section_data,
                        base_rva,
                        section_va,
                        subdir_offset,
                        name_table_base,
                        data_entry_base,
                        data_table_base,
                        name_table_offset,
                        data_entry_offset,
                        data_table_offset,
                    )?;
                }
            }
        }

        Ok(())
    }

    fn write_data_entry_to_result(
        result: &mut Vec<u8>,
        section_data: &[u8],
        data_entry: &ResourceDataEntry,
        base_rva: u32,
        section_va: u64,
        data_entry_base: usize,
        data_table_base: usize,
        name_value: u32,
        entry_offset: usize,
        data_entry_offset: &mut usize,
        data_table_offset: &mut usize,
    ) {
        let current_data_entry_offset = *data_entry_offset;
        let current_data_offset = *data_table_offset;
        let data_entry_rva = (data_entry_base + current_data_entry_offset - data_entry_base) as u32;

        // 复制数据
        let src_offset = (data_entry.data_rva - base_rva) as usize;
        let dst_offset = current_data_offset;
        if src_offset + data_entry.size as usize <= section_data.len() {
            result[dst_offset..dst_offset + data_entry.size as usize]
                .copy_from_slice(&section_data[src_offset..src_offset + data_entry.size as usize]);
        }

        // 更新数据条目RVA
        let new_data_rva = (section_va + data_table_base as u64 + dst_offset as u64) as u32;

        // 写入数据条目
        let mut de_data = Vec::new();
        Self::write_data_entry(&mut de_data, &ResourceDataEntry {
            data_rva: new_data_rva,
            size: data_entry.size,
            code_page: data_entry.code_page,
            reserved: data_entry.reserved,
        });
        result[current_data_entry_offset..current_data_entry_offset + 16].copy_from_slice(&de_data);

        *data_entry_offset += 16;
        *data_table_offset += data_entry.size as usize;
        // 对齐数据表
        while *data_table_offset % 4 != 0 {
            *data_table_offset += 1;
        }

        // 写入目录条目（指向数据条目）
        result[entry_offset..entry_offset + 4].copy_from_slice(&name_value.to_le_bytes());
        result[entry_offset + 4..entry_offset + 8].copy_from_slice(&data_entry_rva.to_le_bytes());
    }

    /// 添加条目
    pub fn add_entry(&mut self, name: ResourceName, entry: ResourceEntry) {
        self.entries.push((name, entry));
    }

    /// 添加子目录
    pub fn add_directory(&mut self, name: ResourceName, dir: ResourceDirectory) {
        self.entries.push((name, ResourceEntry::Directory(dir)));
    }

    /// 添加数据条目
    pub fn add_data(&mut self, name: ResourceName, data_entry: ResourceDataEntry) {
        self.entries.push((name, ResourceEntry::Data(data_entry)));
    }

    /// 获取条目数量
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// 获取命名条目数量
    pub fn named_entry_count(&self) -> usize {
        self.entries.iter()
            .filter(|(name, _)| matches!(name, ResourceName::Name(_)))
            .count()
    }

    /// 获取ID条目数量
    pub fn id_entry_count(&self) -> usize {
        self.entries.iter()
            .filter(|(name, _)| matches!(name, ResourceName::Id(_)))
            .count()
    }
}

/// 资源
#[derive(Debug, Clone)]
pub struct Resource {
    pub id: u32,
    pub name: Option<String>,
    pub resource_type: ResourceType,
    pub data: Vec<u8>,
    pub code_page: u32,
}

impl Resource {
    pub fn new(id: u32, resource_type: ResourceType, data: Vec<u8>) -> Self {
        Self {
            id,
            name: None,
            resource_type,
            data,
            code_page: 0,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn display_name(&self) -> String {
        match &self.name {
            Some(name) => name.clone(),
            None => format!("{}/{}", self.resource_type.as_str(), self.id),
        }
    }
}

/// 资源列表
#[derive(Debug, Clone)]
pub struct ResourceList {
    resources: Vec<Resource>,
}

impl ResourceList {
    pub fn new() -> Self {
        Self {
            resources: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.resources.len()
    }

    pub fn is_empty(&self) -> bool {
        self.resources.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&Resource> {
        self.resources.get(index)
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut Resource> {
        self.resources.get_mut(index)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Resource> {
        self.resources.iter()
    }

    pub fn find_by_id(&self, id: u32) -> Option<&Resource> {
        self.resources.iter().find(|r| r.id == id)
    }

    pub fn find_by_type(&self, resource_type: ResourceType) -> impl Iterator<Item = &Resource> {
        self.resources.iter().filter(move |r| r.resource_type == resource_type)
    }

    pub fn find_by_name(&self, name: &str) -> Option<&Resource> {
        self.resources.iter().find(|r| {
            r.name.as_ref().map(|n| n == name).unwrap_or(false)
        })
    }

    pub fn add(&mut self, resource: Resource) {
        self.resources.push(resource);
    }

    pub fn remove(&mut self, index: usize) -> Option<Resource> {
        if index < self.resources.len() {
            Some(self.resources.remove(index))
        } else {
            None
        }
    }

    pub fn icons(&self) -> impl Iterator<Item = &Resource> {
        self.find_by_type(ResourceType::Icon)
    }

    pub fn bitmaps(&self) -> impl Iterator<Item = &Resource> {
        self.find_by_type(ResourceType::Bitmap)
    }

    pub fn manifests(&self) -> impl Iterator<Item = &Resource> {
        self.find_by_type(ResourceType::Manifest)
    }

    pub fn version_info(&self) -> impl Iterator<Item = &Resource> {
        self.find_by_type(ResourceType::VersionInfo)
    }

    /// 从资源目录构建资源列表
    pub fn from_directory(dir: &ResourceDirectory, section_data: &[u8], base_rva: u32) -> Self {
        let mut list = Self::new();
        let entries = dir.get_all_data_entries(Vec::new());

        for (path, data_entry) in entries {
            if let Some(ResourceName::Id(type_id)) = path.first() {
                let resource_type = ResourceType::from_u32(*type_id);
                let id = path.get(1).and_then(|n| n.as_id()).unwrap_or(0);
                
                // 读取实际数据
                let data_offset = (data_entry.data_rva - base_rva) as usize;
                let data = if data_offset + data_entry.size as usize <= section_data.len() {
                    section_data[data_offset..data_offset + data_entry.size as usize].to_vec()
                } else {
                    Vec::new()
                };

                let resource = Resource {
                    id,
                    name: None,
                    resource_type,
                    data,
                    code_page: data_entry.code_page,
                };
                list.add(resource);
            }
        }

        list
    }

    /// 重建资源列表为目录结构
    /// 
    /// 将扁平的资源列表转换为层次化的资源目录结构
    pub fn rebuild_as_directory(&self) -> ResourceDirectory {
        let mut root = ResourceDirectory::new(ResourceName::Id(0));

        for resource in &self.resources {
            // 获取或创建类型目录
            let type_id = resource.resource_type as u32;
            let type_name = ResourceName::Id(type_id);
            
            // 查找或创建类型目录
            let type_dir_exists = root.find_entry(&type_name).is_some();
            
            if !type_dir_exists {
                // 创建新的类型目录
                let new_dir = ResourceDirectory::new(type_name.clone());
                root.add_directory(type_name.clone(), new_dir);
            }

            // 获取类型目录的可变引用
            let type_dir_index = root.entries.iter()
                .position(|(name, _)| {
                    if let ResourceName::Id(id) = name {
                        *id == type_id
                    } else {
                        false
                    }
                });

            if let Some(index) = type_dir_index {
                if let (_, ResourceEntry::Directory(type_dir)) = &mut root.entries[index] {
                    // 创建资源ID目录或数据条目
                    let res_id_name = ResourceName::Id(resource.id);
                    
                    // 创建数据条目
                    let data_entry = ResourceDataEntry {
                        data_rva: 0, // 将在重建时更新
                        size: resource.data.len() as u32,
                        code_page: resource.code_page,
                        reserved: 0,
                    };
                    
                    type_dir.add_data(res_id_name, data_entry);
                }
            }
        }

        root
    }

    /// 计算资源总大小
    pub fn total_size(&self) -> usize {
        self.resources.iter()
            .map(|r| r.data.len())
            .sum()
    }

    /// 获取所有资源类型
    pub fn resource_types(&self) -> Vec<ResourceType> {
        let mut types: Vec<ResourceType> = self.resources.iter()
            .map(|r| r.resource_type)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        types.sort_by_key(|t| *t as u32);
        types
    }

    /// 按类型分组
    pub fn group_by_type(&self) -> std::collections::HashMap<ResourceType, Vec<&Resource>> {
        let mut map = std::collections::HashMap::new();
        for resource in &self.resources {
            map.entry(resource.resource_type)
                .or_insert_with(Vec::new)
                .push(resource);
        }
        map
    }

    /// 清除所有资源
    pub fn clear(&mut self) {
        self.resources.clear();
    }

    /// 批量添加资源
    pub fn add_batch(&mut self, resources: Vec<Resource>) {
        self.resources.extend(resources);
    }

    /// 获取资源统计信息
    pub fn statistics(&self) -> ResourceStatistics {
        let mut stats = ResourceStatistics::default();
        stats.total_count = self.resources.len();
        stats.total_size = self.total_size();
        
        for resource in &self.resources {
            match resource.resource_type {
                ResourceType::Icon => stats.icon_count += 1,
                ResourceType::Bitmap => stats.bitmap_count += 1,
                ResourceType::Cursor => stats.cursor_count += 1,
                ResourceType::Manifest => stats.manifest_count += 1,
                ResourceType::VersionInfo => stats.version_info_count += 1,
                ResourceType::Dialog => stats.dialog_count += 1,
                ResourceType::StringTable => stats.string_table_count += 1,
                ResourceType::Menu => stats.menu_count += 1,
                ResourceType::RcData => stats.rcdata_count += 1,
                _ => stats.other_count += 1,
            }
        }
        
        stats
    }
}

/// 资源统计信息
#[derive(Debug, Default, Clone)]
pub struct ResourceStatistics {
    pub total_count: usize,
    pub total_size: usize,
    pub icon_count: usize,
    pub bitmap_count: usize,
    pub cursor_count: usize,
    pub manifest_count: usize,
    pub version_info_count: usize,
    pub dialog_count: usize,
    pub string_table_count: usize,
    pub menu_count: usize,
    pub rcdata_count: usize,
    pub other_count: usize,
}

impl Default for ResourceList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_type_from_u32() {
        assert_eq!(ResourceType::from_u32(1), ResourceType::Cursor);
        assert_eq!(ResourceType::from_u32(3), ResourceType::Icon);
        assert_eq!(ResourceType::from_u32(24), ResourceType::Manifest);
        assert_eq!(ResourceType::from_u32(999), ResourceType::Unknown);
    }

    #[test]
    fn test_resource_name() {
        let id_name = ResourceName::Id(42);
        assert_eq!(id_name.as_id(), Some(42));
        assert_eq!(id_name.as_name(), None);
        assert!(id_name.is_id());

        let str_name = ResourceName::Name("Test".to_string());
        assert_eq!(str_name.as_id(), None);
        assert_eq!(str_name.as_name(), Some("Test"));
        assert!(str_name.is_name());
    }

    #[test]
    fn test_resource_data_entry() {
        let data = [0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 
                    0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let entry = ResourceDataEntry::from_bytes(&data).unwrap();
        assert_eq!(entry.data_rva, 0x10);
        assert_eq!(entry.size, 0x20);
        assert_eq!(entry.code_page, 0x400);
        assert_eq!(entry.reserved, 0);
    }

    #[test]
    fn test_resource_list() {
        let mut list = ResourceList::new();
        list.add(Resource::new(1, ResourceType::Icon, vec![1, 2, 3]));
        list.add(Resource::new(2, ResourceType::Bitmap, vec![4, 5, 6]));
        list.add(Resource::new(3, ResourceType::Icon, vec![7, 8, 9]));

        assert_eq!(list.len(), 3);
        assert_eq!(list.icons().count(), 2);
        assert_eq!(list.bitmaps().count(), 1);
        
        let icon = list.find_by_id(1).unwrap();
        assert_eq!(icon.resource_type, ResourceType::Icon);
    }

    #[test]
    fn test_resource_directory() {
        let dir = ResourceDirectory::new(ResourceName::Id(0));
        assert_eq!(dir.entries.len(), 0);
        assert_eq!(dir.calculate_size(), 16); // 只有头部
    }
}
