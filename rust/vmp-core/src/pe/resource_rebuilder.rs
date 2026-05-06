//! PE 资源目录重建器
//!
//! 支持完整重建 PE 文件中的资源目录，包括目录表、名称表、数据条目表和数据表。

use crate::error::{Result, VmpError};
use crate::pe::resource::{ResourceDirectory, ResourceEntry, ResourceName, ResourceDataEntry};

/// 资源重建配置
#[derive(Debug, Clone)]
pub struct ResourceRebuildConfig {
    /// 资源节基址RVA
    pub base_rva: u32,
    /// 对齐要求
    pub alignment: u32,
    /// 是否压缩资源
    pub pack_resources: bool,
    /// 资源节虚拟地址
    pub section_va: u64,
}

impl Default for ResourceRebuildConfig {
    fn default() -> Self {
        Self {
            base_rva: 0,
            alignment: 4,
            pack_resources: false,
            section_va: 0,
        }
    }
}

impl ResourceRebuildConfig {
    pub fn new(base_rva: u32, section_va: u64) -> Self {
        Self {
            base_rva,
            alignment: 4,
            pack_resources: false,
            section_va,
        }
    }

    pub fn with_alignment(mut self, alignment: u32) -> Self {
        self.alignment = alignment;
        self
    }

    pub fn with_pack_resources(mut self, pack: bool) -> Self {
        self.pack_resources = pack;
        self
    }
}

/// 资源布局信息
#[derive(Debug, Clone)]
pub struct ResourceLayout {
    /// 目录表偏移
    pub directory_table_offset: usize,
    /// 目录表大小
    pub directory_table_size: usize,
    /// 名称表偏移
    pub name_table_offset: usize,
    /// 名称表大小
    pub name_table_size: usize,
    /// 数据条目表偏移
    pub data_entry_table_offset: usize,
    /// 数据条目表大小
    pub data_entry_table_size: usize,
    /// 数据表偏移
    pub data_table_offset: usize,
    /// 数据表大小
    pub data_table_size: usize,
    /// 总大小
    pub total_size: usize,
}

impl ResourceLayout {
    pub fn new() -> Self {
        Self {
            directory_table_offset: 0,
            directory_table_size: 0,
            name_table_offset: 0,
            name_table_size: 0,
            data_entry_table_offset: 0,
            data_entry_table_size: 0,
            data_table_offset: 0,
            data_table_size: 0,
            total_size: 0,
        }
    }

    /// 验证布局有效性
    pub fn validate(&self) -> Result<()> {
        if self.directory_table_offset != 0 {
            return Err(VmpError::InvalidData("Directory table must start at offset 0".to_string()));
        }
        if self.name_table_offset < self.directory_table_offset + self.directory_table_size {
            return Err(VmpError::InvalidData("Name table overlaps with directory table".to_string()));
        }
        if self.data_entry_table_offset < self.name_table_offset + self.name_table_size {
            return Err(VmpError::InvalidData("Data entry table overlaps with name table".to_string()));
        }
        if self.data_table_offset < self.data_entry_table_offset + self.data_entry_table_size {
            return Err(VmpError::InvalidData("Data table overlaps with data entry table".to_string()));
        }
        if self.total_size < self.data_table_offset + self.data_table_size {
            return Err(VmpError::InvalidData("Total size is smaller than required".to_string()));
        }
        Ok(())
    }
}

impl Default for ResourceLayout {
    fn default() -> Self {
        Self::new()
    }
}

/// 资源重建器
pub struct ResourceRebuilder {
    config: ResourceRebuildConfig,
    directories: Vec<ResourceDirectory>,
}

impl ResourceRebuilder {
    /// 创建新的资源重建器
    pub fn new(config: ResourceRebuildConfig) -> Self {
        Self {
            config,
            directories: Vec::new(),
        }
    }

    /// 添加资源目录
    pub fn add_directory(&mut self, dir: ResourceDirectory) {
        self.directories.push(dir);
    }

    /// 计算布局
    pub fn calculate_layout(&self) -> ResourceLayout {
        let mut layout = ResourceLayout::new();

        // 计算各部分大小
        let mut dir_size = 0usize;
        let mut name_table_size = 0usize;
        let mut data_entry_table_size = 0usize;
        let mut data_table_size = 0usize;

        for dir in &self.directories {
            let (d, n, de, dt) = dir.calculate_rebuild_size();
            dir_size += d;
            name_table_size += n;
            data_entry_table_size += de;
            data_table_size += dt;
        }

        // 对齐
        let align = self.config.alignment as usize;
        name_table_size = (name_table_size + align - 1) & !(align - 1);
        data_entry_table_size = (data_entry_table_size + align - 1) & !(align - 1);
        data_table_size = (data_table_size + align - 1) & !(align - 1);

        // 设置布局
        layout.directory_table_offset = 0;
        layout.directory_table_size = dir_size;
        layout.name_table_offset = dir_size;
        layout.name_table_size = name_table_size;
        layout.data_entry_table_offset = layout.name_table_offset + name_table_size;
        layout.data_entry_table_size = data_entry_table_size;
        layout.data_table_offset = layout.data_entry_table_offset + data_entry_table_size;
        layout.data_table_size = data_table_size;
        layout.total_size = layout.data_table_offset + data_table_size;

        layout
    }

    /// 重建所有资源
    /// 
    /// # Arguments
    /// * `original_data` - 原始资源节数据
    /// 
    /// 返回重建后的资源数据
    pub fn rebuild(&self, original_data: &[u8]) -> Result<Vec<u8>> {
        if self.directories.is_empty() {
            return Ok(Vec::new());
        }

        let layout = self.calculate_layout();
        layout.validate()?;

        // 重建每个目录
        let mut result = Vec::with_capacity(layout.total_size);
        result.resize(layout.total_size, 0);

        let mut dir_offset = layout.directory_table_offset;
        let mut name_offset = layout.name_table_offset;
        let mut data_entry_offset = layout.data_entry_table_offset;
        let mut data_offset = layout.data_table_offset;

        for dir in &self.directories {
            self.rebuild_directory(
                dir,
                &mut result,
                original_data,
                &mut dir_offset,
                &mut name_offset,
                &mut data_entry_offset,
                &mut data_offset,
            )?;
        }

        Ok(result)
    }

    fn rebuild_directory(
        &self,
        dir: &ResourceDirectory,
        result: &mut [u8],
        original_data: &[u8],
        dir_offset: &mut usize,
        name_offset: &mut usize,
        data_entry_offset: &mut usize,
        data_offset: &mut usize,
    ) -> Result<()> {
        // 分离命名条目和ID条目
        let named_entries: Vec<_> = dir.entries.iter()
            .filter(|(name, _)| matches!(name, ResourceName::Name(_)))
            .collect();
        let id_entries: Vec<_> = dir.entries.iter()
            .filter(|(name, _)| matches!(name, ResourceName::Id(_)))
            .collect();

        let current_dir_offset = *dir_offset;

        // 写入目录头部
        result[current_dir_offset..current_dir_offset + 4].copy_from_slice(&dir.characteristics.to_le_bytes());
        result[current_dir_offset + 4..current_dir_offset + 8].copy_from_slice(&dir.time_date_stamp.to_le_bytes());
        result[current_dir_offset + 8..current_dir_offset + 10].copy_from_slice(&dir.major_version.to_le_bytes());
        result[current_dir_offset + 10..current_dir_offset + 12].copy_from_slice(&dir.minor_version.to_le_bytes());
        result[current_dir_offset + 12..current_dir_offset + 14].copy_from_slice(&(named_entries.len() as u16).to_le_bytes());
        result[current_dir_offset + 14..current_dir_offset + 16].copy_from_slice(&(id_entries.len() as u16).to_le_bytes());

        *dir_offset += 16;
        let mut entry_offset = current_dir_offset + 16;

        // 写入命名条目
        for (name, entry) in named_entries {
            let name_table_offset = *name_offset;
            let name_rva = (name_table_offset as u32) | 0x80000000;

            // 写入名称到名称表
            if let ResourceName::Name(n) = name {
                let length = n.len() as u16;
                result[name_table_offset..name_table_offset + 2].copy_from_slice(&length.to_le_bytes());
                for (i, c) in n.encode_utf16().enumerate() {
                    result[name_table_offset + 2 + i * 2..name_table_offset + 2 + i * 2 + 2]
                        .copy_from_slice(&c.to_le_bytes());
                }
                *name_offset += 2 + n.len() * 2;
                // 对齐
                let align = self.config.alignment as usize;
                *name_offset = (*name_offset + align - 1) & !(align - 1);
            }

            // 写入条目
            match entry {
                ResourceEntry::Data(data_entry) => {
                    self.write_data_entry(
                        result,
                        original_data,
                        data_entry,
                        name_rva,
                        entry_offset,
                        data_entry_offset,
                        data_offset,
                    )?;
                    entry_offset += 8;
                }
                ResourceEntry::Directory(subdir) => {
                    let subdir_offset = *dir_offset;
                    let subdir_rva = (subdir_offset as u32) | 0x80000000;

                    // 写入目录条目
                    result[entry_offset..entry_offset + 4].copy_from_slice(&name_rva.to_le_bytes());
                    result[entry_offset + 4..entry_offset + 8].copy_from_slice(&subdir_rva.to_le_bytes());
                    entry_offset += 8;

                    // 递归重建子目录
                    self.rebuild_directory(
                        subdir,
                        result,
                        original_data,
                        dir_offset,
                        name_offset,
                        data_entry_offset,
                        data_offset,
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
                    self.write_data_entry(
                        result,
                        original_data,
                        data_entry,
                        name_id,
                        entry_offset,
                        data_entry_offset,
                        data_offset,
                    )?;
                    entry_offset += 8;
                }
                ResourceEntry::Directory(subdir) => {
                    let subdir_offset = *dir_offset;
                    let subdir_rva = (subdir_offset as u32) | 0x80000000;

                    // 写入目录条目
                    result[entry_offset..entry_offset + 4].copy_from_slice(&name_id.to_le_bytes());
                    result[entry_offset + 4..entry_offset + 8].copy_from_slice(&subdir_rva.to_le_bytes());
                    entry_offset += 8;

                    // 递归重建子目录
                    self.rebuild_directory(
                        subdir,
                        result,
                        original_data,
                        dir_offset,
                        name_offset,
                        data_entry_offset,
                        data_offset,
                    )?;
                }
            }
        }

        Ok(())
    }

    fn write_data_entry(
        &self,
        result: &mut [u8],
        original_data: &[u8],
        data_entry: &ResourceDataEntry,
        name_value: u32,
        entry_offset: usize,
        data_entry_offset: &mut usize,
        data_offset: &mut usize,
    ) -> Result<()> {
        let current_data_entry_offset = *data_entry_offset;
        let current_data_offset = *data_offset;

        // 复制数据
        let src_offset = (data_entry.data_rva - self.config.base_rva) as usize;
        let size = data_entry.size as usize;

        if src_offset + size <= original_data.len() {
            result[current_data_offset..current_data_offset + size]
                .copy_from_slice(&original_data[src_offset..src_offset + size]);
        }

        // 更新数据RVA
        let new_data_rva = (self.config.section_va + current_data_offset as u64) as u32;

        // 写入数据条目
        result[current_data_entry_offset..current_data_entry_offset + 4]
            .copy_from_slice(&new_data_rva.to_le_bytes());
        result[current_data_entry_offset + 4..current_data_entry_offset + 8]
            .copy_from_slice(&data_entry.size.to_le_bytes());
        result[current_data_entry_offset + 8..current_data_entry_offset + 12]
            .copy_from_slice(&data_entry.code_page.to_le_bytes());
        result[current_data_entry_offset + 12..current_data_entry_offset + 16]
            .copy_from_slice(&data_entry.reserved.to_le_bytes());

        // 写入目录条目（指向数据条目）
        let data_entry_rva = current_data_entry_offset as u32;
        result[entry_offset..entry_offset + 4].copy_from_slice(&name_value.to_le_bytes());
        result[entry_offset + 4..entry_offset + 8].copy_from_slice(&data_entry_rva.to_le_bytes());

        *data_entry_offset += 16;
        *data_offset += size;

        // 对齐
        let align = self.config.alignment as usize;
        *data_offset = (*data_offset + align - 1) & !(align - 1);

        Ok(())
    }

    /// 获取配置
    pub fn config(&self) -> &ResourceRebuildConfig {
        &self.config
    }

    /// 获取目录数量
    pub fn directory_count(&self) -> usize {
        self.directories.len()
    }

    /// 清空所有目录
    pub fn clear(&mut self) {
        self.directories.clear();
    }
}

/// 资源压缩器
pub struct ResourceCompressor;

impl ResourceCompressor {
    /// 压缩资源数据（使用LZMA）
    pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
        // 简化的压缩实现 - 实际应使用LZMA或其他压缩算法
        // 这里使用简单的RLE压缩作为示例
        let mut compressed = Vec::new();
        compressed.extend_from_slice(&(data.len() as u32).to_le_bytes()); // 原始大小

        if data.is_empty() {
            return Ok(compressed);
        }

        let mut i = 0;
        while i < data.len() {
            let byte = data[i];
            let mut count: u8 = 1;

            while i + (count as usize) < data.len()
                && count < 255
                && data[i + (count as usize)] == byte
            {
                count = count + 1;
            }

            if count >= 4 {
                // RLE编码
                compressed.push(0x00); // RLE标记
                compressed.push(count);
                compressed.push(byte);
                i += count as usize;
            } else {
                // 原始数据
                compressed.push(byte);
                i += 1;
            }
        }

        Ok(compressed)
    }

    /// 解压资源数据
    pub fn decompress(data: &[u8], original_size: usize) -> Result<Vec<u8>> {
        if data.len() < 4 {
            return Err(VmpError::InvalidData("Compressed data too small".to_string()));
        }

        let stored_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if stored_size != original_size {
            return Err(VmpError::InvalidData("Size mismatch in compressed data".to_string()));
        }

        let mut decompressed = Vec::with_capacity(original_size);
        let mut i = 4;

        while i < data.len() && decompressed.len() < original_size {
            if data[i] == 0x00 && i + 2 < data.len() {
                // RLE解码
                let count = data[i + 1] as usize;
                let byte = data[i + 2];
                for _ in 0..count {
                    decompressed.push(byte);
                }
                i += 3;
            } else {
                // 原始数据
                decompressed.push(data[i]);
                i += 1;
            }
        }

        if decompressed.len() != original_size {
            return Err(VmpError::InvalidData("Decompressed size mismatch".to_string()));
        }

        Ok(decompressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_layout() {
        let layout = ResourceLayout {
            directory_table_offset: 0,
            directory_table_size: 100,
            name_table_offset: 100,
            name_table_size: 50,
            data_entry_table_offset: 150,
            data_entry_table_size: 32,
            data_table_offset: 182,
            data_table_size: 200,
            total_size: 382,
        };

        assert!(layout.validate().is_ok());
    }

    #[test]
    fn test_resource_layout_invalid() {
        let layout = ResourceLayout {
            directory_table_offset: 10, // 错误：应该从0开始
            directory_table_size: 100,
            name_table_offset: 100,
            name_table_size: 50,
            data_entry_table_offset: 150,
            data_entry_table_size: 32,
            data_table_offset: 182,
            data_table_size: 200,
            total_size: 382,
        };

        assert!(layout.validate().is_err());
    }

    #[test]
    fn test_resource_rebuilder() {
        let config = ResourceRebuildConfig::new(0x1000, 0x10000);
        let rebuilder = ResourceRebuilder::new(config);

        assert_eq!(rebuilder.directory_count(), 0);
    }

    #[test]
    fn test_resource_compressor() {
        let data = vec![0xAA; 100]; // 100个相同的字节
        let compressed = ResourceCompressor::compress(&data).unwrap();
        let decompressed = ResourceCompressor::decompress(&compressed, 100).unwrap();

        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_resource_compressor_mixed() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        data.extend_from_slice(&[0xFF; 50]); // 50个0xFF
        data.extend_from_slice(&[0x05, 0x06]);

        let compressed = ResourceCompressor::compress(&data).unwrap();
        let decompressed = ResourceCompressor::decompress(&compressed, data.len()).unwrap();

        assert_eq!(decompressed, data);
    }
}
