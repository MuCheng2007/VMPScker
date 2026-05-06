//! 导入表重建器
//!
//! 将 ImportList 重建为 PE 文件中的导入表结构。

use crate::error::{Result, VmpError};
use crate::pe::import::{Import, ImportFunction, ImportList};

/// 导入表重建结果
#[derive(Debug)]
pub struct RebuildResult {
    /// 完整的导入表数据
    pub data: Vec<u8>,
    /// 导入目录 RVA
    pub import_directory_rva: u32,
    /// 导入目录大小（字节）
    pub import_directory_size: u32,
    /// IAT RVA
    pub iat_rva: u32,
    /// IAT 大小
    pub iat_size: u32,
}

/// 导入表重建器
pub struct ImportRebuilder {
    imports: ImportList,
}

/// 导入目录条目（IMAGE_IMPORT_DESCRIPTOR）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImportDirectoryEntry {
    original_first_thunk: u32,  // ILT RVA
    time_date_stamp: u32,
    forwarder_chain: u32,
    name_rva: u32,
    first_thunk: u32,           // IAT RVA
}

impl ImportDirectoryEntry {
    fn to_bytes(&self) -> [u8; 20] {
        let mut bytes = [0u8; 20];
        bytes[0..4].copy_from_slice(&self.original_first_thunk.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.time_date_stamp.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.forwarder_chain.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.name_rva.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.first_thunk.to_le_bytes());
        bytes
    }
}

/// 名称表条目（Hint/Name 表）
#[derive(Debug)]
struct NameTableEntry {
    hint: u16,
    name: String,
    rva: u32,
}

impl ImportRebuilder {
    /// 创建新的导入表重建器
    pub fn new(imports: ImportList) -> Self {
        Self { imports }
    }

    /// 重建导入表
    ///
    /// # 参数
    /// - `target_rva`: 导入表将被放置的 RVA
    /// - `is_64bit`: 是否为 64 位 PE
    ///
    /// # 返回
    /// 重建结果，包含数据和目录信息
    pub fn rebuild(&self, target_rva: u32, is_64bit: bool) -> Result<RebuildResult> {
        if self.imports.is_empty() {
            return Err(VmpError::InvalidOperation(
                "Cannot rebuild empty import list".to_string()
            ));
        }

        // 计算各部分大小和布局
        let num_imports = self.imports.len();
        let directory_size = (num_imports + 1) * 20; // +1 for NULL terminator

        // 计算 ILT/IAT 大小
        let mut total_functions = 0;
        for import in self.imports.iter() {
            total_functions += import.functions.len();
        }
        let entry_size = if is_64bit { 8 } else { 4 };
        let ilt_iat_size = (total_functions + num_imports) * entry_size; // +num_imports for NULL entries

        // 计算名称表大小
        let name_entries = self.build_name_table_entries();
        let name_table_size = self.calculate_name_table_size(&name_entries);

        // 计算总大小
        let total_size = directory_size + ilt_iat_size * 2 + name_table_size;

        // 分配数据缓冲区
        let mut data = vec![0u8; total_size];

        // 布局：
        // [导入目录表][ILT][IAT][名称表]
        let directory_offset = 0;
        let ilt_offset = directory_offset + directory_size;
        let iat_offset = ilt_offset + ilt_iat_size;
        let name_table_offset = iat_offset + ilt_iat_size;

        // 写入名称表并获取名称 RVA 映射
        let name_rva_map = self.write_name_table(
            &mut data[name_table_offset..],
            &name_entries,
            target_rva + name_table_offset as u32,
        )?;

        // 写入 ILT 和 IAT
        let (ilt_rvas, iat_rvas) = self.write_ilt_iat(
            &mut data,
            ilt_offset,
            iat_offset,
            target_rva + ilt_offset as u32,
            target_rva + iat_offset as u32,
            is_64bit,
            &name_rva_map,
        )?;

        // 写入导入目录表
        self.write_directory_table(
            &mut data[directory_offset..ilt_offset],
            target_rva + directory_offset as u32,
            &ilt_rvas,
            &iat_rvas,
            &name_rva_map,
        )?;

        Ok(RebuildResult {
            data,
            import_directory_rva: target_rva,
            import_directory_size: directory_size as u32,
            iat_rva: target_rva + iat_offset as u32,
            iat_size: ilt_iat_size as u32,
        })
    }

    /// 构建名称表条目列表
    fn build_name_table_entries(&self) -> Vec<(String, Vec<NameTableEntry>)> {
        let mut result = Vec::new();

        for import in self.imports.iter() {
            let mut entries = Vec::new();
            for func in &import.functions {
                if let Some(name) = &func.name {
                    entries.push(NameTableEntry {
                        hint: func.hint,
                        name: name.clone(),
                        rva: 0, // 将在写入时设置
                    });
                }
            }
            result.push((import.dll_name.clone(), entries));
        }

        result
    }

    /// 计算名称表总大小
    fn calculate_name_table_size(&self, entries: &[(String, Vec<NameTableEntry>)]) -> usize {
        let mut size = 0;
        for (dll_name, func_entries) in entries {
            // DLL 名称（以 NULL 结尾）
            size += dll_name.len() + 1;

            // 函数名称条目
            for entry in func_entries {
                // Hint (2字节) + 名称 + NULL
                size += 2 + entry.name.len() + 1;
                // 对齐到偶数边界
                if size % 2 != 0 {
                    size += 1;
                }
            }
        }
        size
    }

    /// 写入名称表
    fn write_name_table(
        &self,
        data: &mut [u8],
        entries: &[(String, Vec<NameTableEntry>)],
        base_rva: u32,
    ) -> Result<std::collections::HashMap<String, u32>> {
        let mut rva_map = std::collections::HashMap::new();
        let mut offset = 0usize;

        for (dll_name, func_entries) in entries {
            // 写入 DLL 名称
            let dll_name_bytes = dll_name.as_bytes();
            data[offset..offset + dll_name_bytes.len()].copy_from_slice(dll_name_bytes);
            data[offset + dll_name_bytes.len()] = 0; // NULL terminator
            rva_map.insert(format!("dll:{}", dll_name), base_rva + offset as u32);
            offset += dll_name_bytes.len() + 1;

            // 写入函数名称条目
            for entry in func_entries {
                // Hint
                data[offset..offset + 2].copy_from_slice(&entry.hint.to_le_bytes());
                offset += 2;

                // 名称
                let name_bytes = entry.name.as_bytes();
                data[offset..offset + name_bytes.len()].copy_from_slice(name_bytes);
                data[offset + name_bytes.len()] = 0; // NULL terminator
                rva_map.insert(
                    format!("{}:{}", dll_name, entry.name),
                    base_rva + offset as u32 - 2, // RVA 指向 Hint 开始
                );
                offset += name_bytes.len() + 1;

                // 对齐到偶数边界
                if offset % 2 != 0 {
                    data[offset] = 0;
                    offset += 1;
                }
            }
        }

        Ok(rva_map)
    }

    /// 写入 ILT 和 IAT
    fn write_ilt_iat(
        &self,
        data: &mut [u8],
        ilt_offset: usize,
        iat_offset: usize,
        ilt_base_rva: u32,
        iat_base_rva: u32,
        is_64bit: bool,
        name_rva_map: &std::collections::HashMap<String, u32>,
    ) -> Result<(Vec<u32>, Vec<u32>)> {
        let mut ilt_rvas = Vec::new();
        let mut iat_rvas = Vec::new();
        let mut current_ilt_offset = ilt_offset;
        let mut current_iat_offset = iat_offset;

        for import in self.imports.iter() {
            // 记录此导入的 ILT/IAT RVA
            ilt_rvas.push(ilt_base_rva + (current_ilt_offset - ilt_offset) as u32);
            iat_rvas.push(iat_base_rva + (current_iat_offset - iat_offset) as u32);

            for func in &import.functions {
                let entry_value = if func.is_by_ordinal() {
                    // 按序号导入
                    let ordinal = func.ordinal.unwrap_or(0);
                    if is_64bit {
                        0x8000000000000000 | (ordinal as u64)
                    } else {
                        0x80000000 | (ordinal as u32) as u64
                    }
                } else {
                    // 按名称导入
                    let key = format!("{}:{}", import.dll_name, func.name.as_ref().unwrap());
                    let name_rva = name_rva_map.get(&key).copied().unwrap_or(0);
                    name_rva as u64
                };

                // 写入 ILT 条目
                if is_64bit {
                    data[current_ilt_offset..current_ilt_offset + 8]
                        .copy_from_slice(&entry_value.to_le_bytes());
                    current_ilt_offset += 8;
                } else {
                    data[current_ilt_offset..current_ilt_offset + 4]
                        .copy_from_slice(&(entry_value as u32).to_le_bytes());
                    current_ilt_offset += 4;
                }

                // 写入 IAT 条目（初始为0，将在加载时由 Windows 加载器填充）
                if is_64bit {
                    data[current_iat_offset..current_iat_offset + 8].copy_from_slice(&[0u8; 8]);
                    current_iat_offset += 8;
                } else {
                    data[current_iat_offset..current_iat_offset + 4].copy_from_slice(&[0u8; 4]);
                    current_iat_offset += 4;
                }
            }

            // 写入 NULL 条目（表结束标记）
            if is_64bit {
                data[current_ilt_offset..current_ilt_offset + 8].copy_from_slice(&[0u8; 8]);
                data[current_iat_offset..current_iat_offset + 8].copy_from_slice(&[0u8; 8]);
                current_ilt_offset += 8;
                current_iat_offset += 8;
            } else {
                data[current_ilt_offset..current_ilt_offset + 4].copy_from_slice(&[0u8; 4]);
                data[current_iat_offset..current_iat_offset + 4].copy_from_slice(&[0u8; 4]);
                current_ilt_offset += 4;
                current_iat_offset += 4;
            }
        }

        Ok((ilt_rvas, iat_rvas))
    }

    /// 写入导入目录表
    fn write_directory_table(
        &self,
        data: &mut [u8],
        directory_base_rva: u32,
        ilt_rvas: &[u32],
        iat_rvas: &[u32],
        name_rva_map: &std::collections::HashMap<String, u32>,
    ) -> Result<()> {
        let mut offset = 0usize;

        for (i, import) in self.imports.iter().enumerate() {
            let dll_name_key = format!("dll:{}", import.dll_name);
            let name_rva = name_rva_map.get(&dll_name_key).copied().unwrap_or(0);

            let entry = ImportDirectoryEntry {
                original_first_thunk: ilt_rvas[i],
                time_date_stamp: 0,
                forwarder_chain: 0,
                name_rva,
                first_thunk: iat_rvas[i],
            };

            data[offset..offset + 20].copy_from_slice(&entry.to_bytes());
            offset += 20;
        }

        // 写入 NULL 条目（结束标记）
        data[offset..offset + 20].copy_from_slice(&[0u8; 20]);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::import::{Import, ImportFunction, ImportList};

    fn create_test_imports() -> ImportList {
        let mut list = ImportList::new();

        let mut kernel32 = Import::new("kernel32.dll");
        kernel32.add_function(ImportFunction::by_name("CreateFileA", 0, 1));
        kernel32.add_function(ImportFunction::by_name("ReadFile", 0, 2));
        list.add(kernel32);

        let mut user32 = Import::new("user32.dll");
        user32.add_function(ImportFunction::by_name("MessageBoxA", 0, 3));
        list.add(user32);

        list
    }

    #[test]
    fn test_import_rebuilder_new() {
        let imports = create_test_imports();
        let rebuilder = ImportRebuilder::new(imports);
        assert!(!rebuilder.imports.is_empty());
    }

    #[test]
    fn test_import_rebuilder_rebuild_64bit() {
        let imports = create_test_imports();
        let rebuilder = ImportRebuilder::new(imports);

        let result = rebuilder.rebuild(0x10000, true);
        assert!(result.is_ok());

        let rebuild = result.unwrap();
        assert!(!rebuild.data.is_empty());
        assert_eq!(rebuild.import_directory_rva, 0x10000);
        assert!(rebuild.import_directory_size > 0);
        assert!(rebuild.iat_size > 0);
    }

    #[test]
    fn test_import_rebuilder_rebuild_32bit() {
        let imports = create_test_imports();
        let rebuilder = ImportRebuilder::new(imports);

        let result = rebuilder.rebuild(0x10000, false);
        assert!(result.is_ok());

        let rebuild = result.unwrap();
        assert!(!rebuild.data.is_empty());
    }

    #[test]
    fn test_import_directory_entry_to_bytes() {
        let entry = ImportDirectoryEntry {
            original_first_thunk: 0x1000,
            time_date_stamp: 0,
            forwarder_chain: 0,
            name_rva: 0x2000,
            first_thunk: 0x3000,
        };

        let bytes = entry.to_bytes();
        assert_eq!(bytes.len(), 20);
        assert_eq!(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]), 0x1000);
        assert_eq!(u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]), 0x2000);
        assert_eq!(u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]), 0x3000);
    }

    #[test]
    fn test_empty_import_list_fails() {
        let imports = ImportList::new();
        let rebuilder = ImportRebuilder::new(imports);

        let result = rebuilder.rebuild(0x10000, true);
        assert!(result.is_err());
    }
}
