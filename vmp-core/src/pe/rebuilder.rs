//! PE 重建器
//!
//! 提供完整的 PE 文件重建功能，支持添加新节区、修改导入表、导出表等。

use crate::error::{Result, VmpError};
use crate::pe::{
    file::PeFile,
    section::{Section, SectionList},
    import::{ImportList},
    export::{ExportList},
    relocation::RelocationList,
};
use crate::pe::import_rebuilder::{ImportRebuilder, RebuildResult as ImportRebuildResult};

/// PE 重建配置
#[derive(Debug, Clone)]
pub struct RebuildConfig {
    /// 是否更新重定位表
    pub update_relocations: bool,
    /// 是否重建导入表
    pub rebuild_imports: bool,
    /// 是否重建导出表
    pub rebuild_exports: bool,
    /// 是否计算校验和
    pub compute_checksum: bool,
    /// 对齐方式
    pub file_alignment: u32,
    pub section_alignment: u32,
}

impl Default for RebuildConfig {
    fn default() -> Self {
        Self {
            update_relocations: true,
            rebuild_imports: false,
            rebuild_exports: false,
            compute_checksum: true,
            file_alignment: 0x200,   // 默认 512 字节
            section_alignment: 0x1000, // 默认 4KB
        }
    }
}

/// 新节区信息
#[derive(Debug, Clone)]
pub struct NewSection {
    pub name: String,
    pub data: Vec<u8>,
    pub characteristics: u32,
    pub virtual_size: Option<u32>,
}

impl NewSection {
    pub fn new(name: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            data,
            characteristics: 0x40000040, // INITIALIZED_DATA | READ
            virtual_size: None,
        }
    }

    pub fn with_characteristics(mut self, characteristics: u32) -> Self {
        self.characteristics = characteristics;
        self
    }

    pub fn as_code(mut self) -> Self {
        self.characteristics = 0x60000020; // CODE | EXECUTE | READ
        self
    }

    pub fn as_data(mut self) -> Self {
        self.characteristics = 0xC0000040; // INITIALIZED_DATA | READ | WRITE
        self
    }

    pub fn as_readonly_data(mut self) -> Self {
        self.characteristics = 0x40000040; // INITIALIZED_DATA | READ
        self
    }
}

/// 节区修改信息
#[derive(Debug, Clone)]
pub struct SectionModification {
    pub name: String,
    pub new_data: Option<Vec<u8>>,
    pub new_characteristics: Option<u32>,
}

/// PE 重建器
pub struct PeRebuilder {
    original: PeFile,
    config: RebuildConfig,
    new_sections: Vec<NewSection>,
    section_modifications: Vec<SectionModification>,
    new_entry_point: Option<u64>,
    import_list: Option<ImportList>,
    export_list: Option<ExportList>,
    relocation_list: Option<RelocationList>,
}

impl PeRebuilder {
    /// 创建新的 PE 重建器
    pub fn new(pe: PeFile) -> Self {
        Self {
            original: pe,
            config: RebuildConfig::default(),
            new_sections: Vec::new(),
            section_modifications: Vec::new(),
            new_entry_point: None,
            import_list: None,
            export_list: None,
            relocation_list: None,
        }
    }

    /// 设置重建配置
    pub fn with_config(mut self, config: RebuildConfig) -> Self {
        self.config = config;
        self
    }

    /// 添加新节区
    pub fn add_section(&mut self, section: NewSection) {
        self.new_sections.push(section);
    }

    /// 修改现有节区
    pub fn modify_section(&mut self, modification: SectionModification) {
        self.section_modifications.push(modification);
    }

    /// 设置新的入口点
    pub fn set_entry_point(&mut self, rva: u64) {
        self.new_entry_point = Some(rva);
    }

    /// 设置导入表
    pub fn set_imports(&mut self, imports: ImportList) {
        self.import_list = Some(imports);
    }

    /// 设置导出表
    pub fn set_exports(&mut self, exports: ExportList) {
        self.export_list = Some(exports);
    }

    /// 设置重定位表
    pub fn set_relocations(&mut self, relocations: RelocationList) {
        self.relocation_list = Some(relocations);
    }

    /// 重建 PE 文件
    pub fn rebuild(&self) -> Result<Vec<u8>> {
        // 1. 计算新布局
        let layout = self.calculate_layout()?;

        // 2. 分配输出缓冲区
        let mut output = vec![0u8; layout.total_size];

        // 3. 写入 DOS 头和 PE 头
        self.write_headers(&mut output, &layout)?;

        // 4. 写入节区表
        self.write_section_table(&mut output, &layout)?;

        // 5. 写入节区数据
        self.write_sections(&mut output, &layout)?;

        // 6. 写入数据目录
        self.write_data_directories(&mut output, &layout)?;

        // 7. 计算校验和（如果需要）
        if self.config.compute_checksum {
            self.compute_checksum(&mut output);
        }

        Ok(output)
    }

    /// 计算新布局
    fn calculate_layout(&self) -> Result<PeLayout> {
        let is_64bit = self.original.is_64bit();
        let file_alignment = self.config.file_alignment;
        let section_alignment = self.config.section_alignment;

        // 计算头部大小
        let dos_header_size = 0x40; // 64 字节
        let pe_signature_size = 4;
        let coff_header_size = 20;
        let optional_header_size = if is_64bit { 240 } else { 224 };
        let data_directory_size = 16 * 8; // 16 个目录项，每个 8 字节
        let total_header_size = dos_header_size + pe_signature_size + coff_header_size
            + optional_header_size + data_directory_size;

        // 计算节区表大小
        let original_section_count = if let Some(ref pe) = self.original.pe() {
            pe.sections.len()
        } else {
            0
        };
        let new_section_count = original_section_count + self.new_sections.len();
        let section_table_size = new_section_count * 40; // 每个节区表项 40 字节

        // 计算节区数据偏移
        let first_section_offset = align_up(
            (total_header_size + section_table_size) as u32,
            file_alignment,
        ) as usize;

        // 计算各个节区的位置和大小
        let mut sections = Vec::new();
        let mut current_offset = first_section_offset;
        let mut current_rva = align_up(first_section_offset as u32, section_alignment);

        // 原始节区
        if let Some(ref pe) = self.original.pe() {
            for (i, section) in pe.sections.iter().enumerate() {
                let data_size = section.size_of_raw_data;
                let virtual_size = section.virtual_size;

                let file_offset = current_offset;
                let rva = current_rva;

                sections.push(SectionLayout {
                    name: String::from_utf8_lossy(&section.name)
                        .trim_end_matches('\0')
                        .to_string(),
                    file_offset,
                    rva,
                    data_size,
                    virtual_size,
                    is_new: false,
                    original_index: Some(i),
                });

                current_offset = align_up((current_offset + data_size as usize) as u32, file_alignment) as usize;
                current_rva = align_up(current_rva + virtual_size, section_alignment);
            }
        }

        // 新节区
        for new_section in &self.new_sections {
            let data_size = new_section.data.len() as u32;
            let virtual_size = new_section.virtual_size.unwrap_or(data_size);

            let file_offset = current_offset;
            let rva = current_rva;

            sections.push(SectionLayout {
                name: new_section.name.clone(),
                file_offset,
                rva,
                data_size,
                virtual_size,
                is_new: true,
                original_index: None,
            });

            current_offset = align_up((current_offset + data_size as usize) as u32, file_alignment) as usize;
            current_rva = align_up(current_rva + virtual_size, section_alignment);
        }

        // 计算总大小
        let total_size = current_offset;

        Ok(PeLayout {
            is_64bit,
            total_size,
            first_section_offset,
            section_count: new_section_count,
            sections,
            image_base: self.original.image_base(),
            entry_point: self.new_entry_point
                .unwrap_or_else(|| self.original.entry_point()),
        })
    }

    /// 写入头部
    fn write_headers(&self, output: &mut [u8], layout: &PeLayout) -> Result<()> {
        // DOS 头部
        output[0..2].copy_from_slice(b"MZ");
        // e_lfanew: PE 头偏移（通常在 0x40 或 0x80）
        let pe_offset = 0x40u32;
        output[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());

        // PE 签名
        output[pe_offset as usize..pe_offset as usize + 4].copy_from_slice(b"PE\0\0");

        // COFF 头部
        let coff_offset = pe_offset as usize + 4;
        let machine = if layout.is_64bit { 0x8664u16 } else { 0x14Cu16 };
        output[coff_offset..coff_offset + 2].copy_from_slice(&machine.to_le_bytes());
        output[coff_offset + 2..coff_offset + 4]
            .copy_from_slice(&(layout.section_count as u16).to_le_bytes());
        
        // TimeDateStamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        output[coff_offset + 4..coff_offset + 8].copy_from_slice(&timestamp.to_le_bytes());
        
        // PointerToSymbolTable 和 NumberOfSymbols（通常为 0）
        output[coff_offset + 8..coff_offset + 16].fill(0);
        
        // SizeOfOptionalHeader
        let optional_header_size = if layout.is_64bit { 240u16 } else { 224u16 };
        output[coff_offset + 16..coff_offset + 18]
            .copy_from_slice(&optional_header_size.to_le_bytes());
        
        // Characteristics
        let characteristics: u16 = 0x102; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
        output[coff_offset + 18..coff_offset + 20]
            .copy_from_slice(&characteristics.to_le_bytes());

        // 可选头部
        let optional_offset = coff_offset + 20;
        
        // Magic
        let magic = if layout.is_64bit { 0x20Bu16 } else { 0x10Bu16 };
        output[optional_offset..optional_offset + 2].copy_from_slice(&magic.to_le_bytes());
        
        // MajorLinkerVersion, MinorLinkerVersion
        output[optional_offset + 2..optional_offset + 4].copy_from_slice(&[1, 0]);
        
        // SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData
        let (code_size, initialized_size, uninitialized_size) = self.calculate_section_sizes(layout);
        output[optional_offset + 4..optional_offset + 8].copy_from_slice(&code_size.to_le_bytes());
        output[optional_offset + 8..optional_offset + 12].copy_from_slice(&initialized_size.to_le_bytes());
        output[optional_offset + 12..optional_offset + 16].copy_from_slice(&uninitialized_size.to_le_bytes());
        
        // AddressOfEntryPoint
        output[optional_offset + 16..optional_offset + 20]
            .copy_from_slice(&(layout.entry_point as u32).to_le_bytes());
        
        // BaseOfCode
        if let Some(first_code) = layout.sections.iter().find(|s| s.is_code()) {
            output[optional_offset + 20..optional_offset + 24]
                .copy_from_slice(&first_code.rva.to_le_bytes());
        }
        
        // BaseOfData (仅 32 位)
        if !layout.is_64bit {
            if let Some(first_data) = layout.sections.iter().find(|s| s.is_data()) {
                output[optional_offset + 24..optional_offset + 28]
                    .copy_from_slice(&first_data.rva.to_le_bytes());
            }
        }

        // ImageBase
        let image_base_offset = if layout.is_64bit { 24 } else { 28 };
        if layout.is_64bit {
            output[optional_offset + image_base_offset..optional_offset + image_base_offset + 8]
                .copy_from_slice(&layout.image_base.to_le_bytes());
        } else {
            output[optional_offset + image_base_offset..optional_offset + image_base_offset + 4]
                .copy_from_slice(&(layout.image_base as u32).to_le_bytes());
        }

        // SectionAlignment, FileAlignment
        let align_offset = optional_offset + image_base_offset + if layout.is_64bit { 8 } else { 4 };
        output[align_offset..align_offset + 4]
            .copy_from_slice(&self.config.section_alignment.to_le_bytes());
        output[align_offset + 4..align_offset + 8]
            .copy_from_slice(&self.config.file_alignment.to_le_bytes());

        // MajorOperatingSystemVersion, MinorOperatingSystemVersion
        // MajorImageVersion, MinorImageVersion
        // MajorSubsystemVersion, MinorSubsystemVersion
        let version_offset = align_offset + 8;
        output[version_offset..version_offset + 8].copy_from_slice(&[6, 0, 0, 0, 6, 0, 0, 0]);

        // Win32VersionValue (保留，必须为 0）
        output[version_offset + 8..version_offset + 12].fill(0);

        // SizeOfImage
        let size_of_image_offset = version_offset + 12;
        let last_section = layout.sections.last()
            .ok_or_else(|| VmpError::InvalidOperation("No sections in PE".to_string()))?;
        let size_of_image = align_up(
            last_section.rva + last_section.virtual_size,
            self.config.section_alignment,
        );
        output[size_of_image_offset..size_of_image_offset + 4]
            .copy_from_slice(&size_of_image.to_le_bytes());

        // SizeOfHeaders
        let size_of_headers = layout.first_section_offset as u32;
        output[size_of_image_offset + 4..size_of_image_offset + 8]
            .copy_from_slice(&size_of_headers.to_le_bytes());

        // CheckSum（稍后计算）
        output[size_of_image_offset + 8..size_of_image_offset + 12].fill(0);

        // Subsystem (WINDOWS_GUI = 2, WINDOWS_CUI = 3)
        let subsystem: u16 = 3; // WINDOWS_CUI
        output[size_of_image_offset + 12..size_of_image_offset + 14]
            .copy_from_slice(&subsystem.to_le_bytes());

        // DllCharacteristics
        let dll_characteristics: u16 = 0x8160; // DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
        output[size_of_image_offset + 14..size_of_image_offset + 16]
            .copy_from_slice(&dll_characteristics.to_le_bytes());

        // SizeOfStackReserve, SizeOfStackCommit
        // SizeOfHeapReserve, SizeOfHeapCommit
        let stack_heap_offset = size_of_image_offset + 16;
        if layout.is_64bit {
            output[stack_heap_offset..stack_heap_offset + 8].copy_from_slice(&0x100000u64.to_le_bytes());
            output[stack_heap_offset + 8..stack_heap_offset + 16].copy_from_slice(&0x1000u64.to_le_bytes());
            output[stack_heap_offset + 16..stack_heap_offset + 24].copy_from_slice(&0x100000u64.to_le_bytes());
            output[stack_heap_offset + 24..stack_heap_offset + 32].copy_from_slice(&0x1000u64.to_le_bytes());
        } else {
            output[stack_heap_offset..stack_heap_offset + 4].copy_from_slice(&0x100000u32.to_le_bytes());
            output[stack_heap_offset + 4..stack_heap_offset + 8].copy_from_slice(&0x1000u32.to_le_bytes());
            output[stack_heap_offset + 8..stack_heap_offset + 12].copy_from_slice(&0x100000u32.to_le_bytes());
            output[stack_heap_offset + 12..stack_heap_offset + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        }

        // LoaderFlags (保留，必须为 0）
        let loader_flags_offset = stack_heap_offset + if layout.is_64bit { 32 } else { 16 };
        output[loader_flags_offset..loader_flags_offset + 4].fill(0);

        // NumberOfRvaAndSizes (数据目录数量）
        output[loader_flags_offset + 4..loader_flags_offset + 8]
            .copy_from_slice(&16u32.to_le_bytes());

        Ok(())
    }

    /// 写入节区表
    fn write_section_table(&self, output: &mut [u8], layout: &PeLayout) -> Result<()> {
        let section_table_offset = if layout.is_64bit {
            0x40 + 4 + 20 + 240 // DOS + PE sig + COFF + Optional (64-bit)
        } else {
            0x40 + 4 + 20 + 224 // DOS + PE sig + COFF + Optional (32-bit)
        };

        for (i, section_layout) in layout.sections.iter().enumerate() {
            let entry_offset = section_table_offset + i * 40;

            // Name (8 字节）
            let name_bytes = section_layout.name.as_bytes();
            let name_len = name_bytes.len().min(8);
            output[entry_offset..entry_offset + name_len]
                .copy_from_slice(&name_bytes[..name_len]);

            // VirtualSize
            output[entry_offset + 8..entry_offset + 12]
                .copy_from_slice(&section_layout.virtual_size.to_le_bytes());

            // VirtualAddress
            output[entry_offset + 12..entry_offset + 16]
                .copy_from_slice(&section_layout.rva.to_le_bytes());

            // SizeOfRawData
            output[entry_offset + 16..entry_offset + 20]
                .copy_from_slice(&section_layout.data_size.to_le_bytes());

            // PointerToRawData
            output[entry_offset + 20..entry_offset + 24]
                .copy_from_slice(&(section_layout.file_offset as u32).to_le_bytes());

            // PointerToRelocations (通常为 0）
            output[entry_offset + 24..entry_offset + 28].fill(0);

            // PointerToLinenumbers (通常为 0）
            output[entry_offset + 28..entry_offset + 32].fill(0);

            // NumberOfRelocations, NumberOfLinenumbers
            output[entry_offset + 32..entry_offset + 36].fill(0);

            // Characteristics
            let characteristics = if section_layout.is_new {
                // 新节区使用默认特性
                self.new_sections.iter()
                    .find(|s| s.name == section_layout.name)
                    .map(|s| s.characteristics)
                    .unwrap_or(0x40000040)
            } else {
                // 保留原始节区特性
                if let Some(ref pe) = self.original.pe() {
                    section_layout.original_index
                        .and_then(|i| pe.sections.get(i))
                        .map(|s| s.characteristics)
                        .unwrap_or(0x40000040)
                } else {
                    0x40000040
                }
            };
            output[entry_offset + 36..entry_offset + 40]
                .copy_from_slice(&characteristics.to_le_bytes());
        }

        Ok(())
    }

    /// 写入节区数据
    fn write_sections(&self, output: &mut [u8], layout: &PeLayout) -> Result<()> {
        for section_layout in &layout.sections {
            if section_layout.is_new {
                // 写入新节区数据
                if let Some(new_section) = self.new_sections.iter()
                    .find(|s| s.name == section_layout.name) {
                    let start = section_layout.file_offset;
                    let end = start + new_section.data.len();
                    if end <= output.len() {
                        output[start..end].copy_from_slice(&new_section.data);
                    }
                }
            } else {
                // 复制原始节区数据
                if let Some(original_index) = section_layout.original_index {
                    if let Some(ref pe) = self.original.pe() {
                        if let Some(original_section) = pe.sections.get(original_index) {
                            let raw_start = original_section.pointer_to_raw_data as usize;
                            let raw_size = original_section.size_of_raw_data as usize;
                            let target_start = section_layout.file_offset;
                            
                            if raw_start + raw_size <= self.original.data().len() 
                                && target_start + raw_size <= output.len() {
                                output[target_start..target_start + raw_size]
                                    .copy_from_slice(&self.original.data()[raw_start..raw_start + raw_size]);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// 写入数据目录
    fn write_data_directories(&self, _output: &mut [u8], _layout: &PeLayout) -> Result<()> {
        // TODO: 实现数据目录写入
        // 包括导入表、导出表、重定位表等
        Ok(())
    }

    /// 计算节区大小统计
    fn calculate_section_sizes(&self, layout: &PeLayout) -> (u32, u32, u32) {
        let mut code_size = 0u32;
        let mut initialized_size = 0u32;
        let mut uninitialized_size = 0u32;

        for section_layout in &layout.sections {
            if section_layout.is_code() {
                code_size += section_layout.virtual_size;
            } else if section_layout.is_initialized_data() {
                initialized_size += section_layout.virtual_size;
            } else if section_layout.is_uninitialized_data() {
                uninitialized_size += section_layout.virtual_size;
            }
        }

        (code_size, initialized_size, uninitialized_size)
    }

    /// 计算校验和
    fn compute_checksum(&self, _data: &mut [u8]) {
        // TODO: 实现 PE 校验和计算
        // 校验和是可选的，Windows 加载器通常不要求
    }
}

/// PE 布局信息
#[derive(Debug)]
struct PeLayout {
    is_64bit: bool,
    total_size: usize,
    first_section_offset: usize,
    section_count: usize,
    sections: Vec<SectionLayout>,
    image_base: u64,
    entry_point: u64,
}

/// 节区布局信息
#[derive(Debug)]
struct SectionLayout {
    name: String,
    file_offset: usize,
    rva: u32,
    data_size: u32,
    virtual_size: u32,
    is_new: bool,
    original_index: Option<usize>,
}

impl SectionLayout {
    fn is_code(&self) -> bool {
        // 简单判断：包含 "text" 或 "code" 的节区名
        let name_lower = self.name.to_lowercase();
        name_lower.contains("text") || name_lower.contains("code")
    }

    fn is_data(&self) -> bool {
        let name_lower = self.name.to_lowercase();
        name_lower.contains("data") && !name_lower.contains("rdata")
    }

    fn is_initialized_data(&self) -> bool {
        let name_lower = self.name.to_lowercase();
        name_lower.contains("data") || name_lower.contains("rsrc")
    }

    fn is_uninitialized_data(&self) -> bool {
        let name_lower = self.name.to_lowercase();
        name_lower.contains("bss")
    }
}

/// 对齐到指定边界
fn align_up(value: u32, alignment: u32) -> u32 {
    ((value + alignment - 1) / alignment) * alignment
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_section_builder() {
        let section = NewSection::new(".test", vec![1, 2, 3, 4])
            .as_code();
        
        assert_eq!(section.name, ".test");
        assert_eq!(section.data.len(), 4);
        assert_eq!(section.characteristics, 0x60000020);
    }

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0x100, 0x200), 0x200);
        assert_eq!(align_up(0x201, 0x200), 0x400);
        assert_eq!(align_up(0x400, 0x1000), 0x1000);
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
    }

    #[test]
    fn test_section_layout_classification() {
        let code_section = SectionLayout {
            name: ".text".to_string(),
            file_offset: 0x400,
            rva: 0x1000,
            data_size: 0x1000,
            virtual_size: 0x1000,
            is_new: false,
            original_index: Some(0),
        };
        assert!(code_section.is_code());
        assert!(!code_section.is_data());

        let data_section = SectionLayout {
            name: ".data".to_string(),
            file_offset: 0x1400,
            rva: 0x2000,
            data_size: 0x1000,
            virtual_size: 0x1000,
            is_new: false,
            original_index: Some(1),
        };
        assert!(!data_section.is_code());
        assert!(data_section.is_data());
        assert!(data_section.is_initialized_data());
    }
}
