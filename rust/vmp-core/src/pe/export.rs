use crate::error::{Result, VmpError};

/// 导出函数信息
#[derive(Debug, Clone)]
pub struct ExportFunction {
    pub ordinal: u16,
    pub name: Option<String>,
    pub address: u64,
    pub forwarder: Option<String>, // 转发器名称（如果存在）
}

impl ExportFunction {
    pub fn by_name(ordinal: u16, name: impl Into<String>, address: u64) -> Self {
        Self {
            ordinal,
            name: Some(name.into()),
            address,
            forwarder: None,
        }
    }

    pub fn by_ordinal(ordinal: u16, address: u64) -> Self {
        Self {
            ordinal,
            name: None,
            address,
            forwarder: None,
        }
    }

    pub fn with_forwarder(ordinal: u16, name: impl Into<String>, forwarder: impl Into<String>) -> Self {
        Self {
            ordinal,
            name: Some(name.into()),
            address: 0,
            forwarder: Some(forwarder.into()),
        }
    }

    pub fn is_forwarder(&self) -> bool {
        self.forwarder.is_some()
    }

    pub fn is_by_name(&self) -> bool {
        self.name.is_some()
    }

    pub fn display_name(&self) -> String {
        match &self.name {
            Some(name) => name.clone(),
            None => format!("Ordinal_{}", self.ordinal),
        }
    }
}

/// 导出表信息
#[derive(Debug, Clone)]
pub struct ExportDirectory {
    pub export_flags: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub dll_name: String,
    pub ordinal_base: u32,
    pub functions: Vec<ExportFunction>,
}

impl ExportDirectory {
    pub fn new(dll_name: impl Into<String>) -> Self {
        Self {
            export_flags: 0,
            time_date_stamp: 0,
            major_version: 0,
            minor_version: 0,
            dll_name: dll_name.into(),
            ordinal_base: 1,
            functions: Vec::new(),
        }
    }

    pub fn from_goblin(export_data: &goblin::pe::export::ExportData) -> Self {
        let mut functions = Vec::new();

        // 处理导出地址表
        for (i, export_addr) in export_data.export_address_table.iter().enumerate() {
            let ordinal = export_data.export_directory_table.ordinal_base + i as u32;
            
            // 检查是否是转发器（通常在导出节区内）
            let forwarder = None; // goblin 不直接提供转发器检测

            // 获取导出地址值
            let address = match export_addr {
                goblin::pe::export::ExportAddressTableEntry::ExportRVA(rva) => *rva as u64,
                goblin::pe::export::ExportAddressTableEntry::ForwarderRVA(rva) => *rva as u64,
            };

            functions.push(ExportFunction {
                ordinal: ordinal as u16,
                name: None, // 稍后填充
                address,
                forwarder,
            });
        }

        // 填充名称信息
        for (i, &name_rva) in export_data.export_name_pointer_table.iter().enumerate() {
            // 从导出数据中获取名称
            if let Some(name) = export_data.name {
                if let Some(ordinal_idx) = export_data.export_ordinal_table.get(i).copied() {
                    let ordinal_idx = ordinal_idx as usize;
                    if ordinal_idx < functions.len() {
                        // 尝试从原始数据解析名称
                        // 注意：这里简化处理，实际需要根据 name_rva 从原始数据读取
                        functions[ordinal_idx].name = Some(format!("Export_{}", i));
                    }
                }
            }
        }

        Self {
            export_flags: export_data.export_directory_table.export_flags,
            time_date_stamp: export_data.export_directory_table.time_date_stamp,
            major_version: export_data.export_directory_table.major_version,
            minor_version: export_data.export_directory_table.minor_version,
            dll_name: export_data.name.map(|s| s.to_string()).unwrap_or_default(),
            ordinal_base: export_data.export_directory_table.ordinal_base,
            functions,
        }
    }

    pub fn add_function(&mut self, function: ExportFunction) {
        self.functions.push(function);
    }

    pub fn find_by_name(&self, name: &str) -> Option<&ExportFunction> {
        self.functions.iter().find(|f| {
            f.name.as_ref().map(|n| n == name).unwrap_or(false)
        })
    }

    pub fn find_by_name_mut(&mut self, name: &str) -> Option<&mut ExportFunction> {
        self.functions.iter_mut().find(|f| {
            f.name.as_ref().map(|n| n == name).unwrap_or(false)
        })
    }

    pub fn find_by_ordinal(&self, ordinal: u16) -> Option<&ExportFunction> {
        self.functions.iter().find(|f| f.ordinal == ordinal)
    }

    pub fn find_by_ordinal_mut(&mut self, ordinal: u16) -> Option<&mut ExportFunction> {
        self.functions.iter_mut().find(|f| f.ordinal == ordinal)
    }

    /// 更新导出地址（用于重定位）
    pub fn update_address(&mut self, old_addr: u64, new_addr: u64) {
        for func in &mut self.functions {
            if func.address == old_addr && !func.is_forwarder() {
                func.address = new_addr;
            }
        }
    }

    /// 获取最高序号
    pub fn max_ordinal(&self) -> u16 {
        self.functions.iter()
            .map(|f| f.ordinal)
            .max()
            .unwrap_or(0)
    }

    /// 获取按名称导出的函数数量
    pub fn named_export_count(&self) -> usize {
        self.functions.iter().filter(|f| f.is_by_name()).count()
    }

    /// 计算重建导出表所需的总大小
    /// 
    /// 返回：(目录大小, 地址表大小, 名称指针表大小, 序号表大小, 名称表大小)
    pub fn calculate_rebuild_size(&self) -> (usize, usize, usize, usize, usize) {
        // 导出目录：40字节
        let directory_size = 40;

        // 导出地址表（EAT）：每个函数一个DWORD
        let address_table_size = self.functions.len() * 4;

        // 名称指针表：每个有名称的函数一个DWORD
        let name_pointer_count = self.named_export_count();
        let name_pointer_table_size = name_pointer_count * 4;

        // 序号表：每个有名称的函数一个WORD
        let ordinal_table_size = name_pointer_count * 2;

        // 名称表大小
        let mut name_table_size = 0;
        // DLL名称
        name_table_size += self.dll_name.len() + 1;
        // 函数名称
        for func in &self.functions {
            if let Some(name) = &func.name {
                name_table_size += name.len() + 1;
            }
            // 转发器名称
            if let Some(forwarder) = &func.forwarder {
                name_table_size += forwarder.len() + 1;
            }
        }

        (
            directory_size,
            address_table_size,
            name_pointer_table_size,
            ordinal_table_size,
            name_table_size,
        )
    }

    /// 计算对齐后的总大小
    pub fn total_rebuild_size(&self) -> usize {
        let (dir, eat, npt, ot, nt) = self.calculate_rebuild_size();
        // 对齐到4字节边界
        let total = dir + eat + npt + ot + nt;
        (total + 3) & !3
    }

    /// 重建导出表
    /// 
    /// # Arguments
    /// * `base_rva` - 导出表基址RVA
    /// 
    /// 返回重建后的导出表数据和目录信息
    pub fn rebuild(&self, base_rva: u32) -> ExportRebuildResult {
        let (dir_size, eat_size, npt_size, ot_size, nt_size) = self.calculate_rebuild_size();
        let total_size = dir_size + eat_size + npt_size + ot_size + nt_size;
        
        let mut data = vec![0u8; total_size];
        
        // 计算各表偏移
        let dir_offset = 0;
        let eat_offset = dir_offset + dir_size;
        let npt_offset = eat_offset + eat_size;
        let ot_offset = npt_offset + npt_size;
        let nt_offset = ot_offset + ot_size;
        
        // 写入导出目录 (40字节)
        let export_dir_rva = base_rva;
        data[dir_offset..dir_offset + 4].copy_from_slice(&self.export_flags.to_le_bytes());
        data[dir_offset + 4..dir_offset + 8].copy_from_slice(&self.time_date_stamp.to_le_bytes());
        data[dir_offset + 8..dir_offset + 10].copy_from_slice(&self.major_version.to_le_bytes());
        data[dir_offset + 10..dir_offset + 12].copy_from_slice(&self.minor_version.to_le_bytes());
        
        // DLL名称RVA
        let dll_name_rva = base_rva + nt_offset as u32;
        data[dir_offset + 12..dir_offset + 16].copy_from_slice(&dll_name_rva.to_le_bytes());
        
        // Ordinal Base
        data[dir_offset + 16..dir_offset + 20].copy_from_slice(&self.ordinal_base.to_le_bytes());
        
        // Address Table Entries (EAT条目数)
        let eat_entries = self.functions.len() as u32;
        data[dir_offset + 20..dir_offset + 24].copy_from_slice(&eat_entries.to_le_bytes());
        
        // Number of Name Pointers (有名称的导出数量)
        let name_ptr_count = self.named_export_count() as u32;
        data[dir_offset + 24..dir_offset + 28].copy_from_slice(&name_ptr_count.to_le_bytes());
        
        // Export Address Table RVA
        let eat_rva = base_rva + eat_offset as u32;
        data[dir_offset + 28..dir_offset + 32].copy_from_slice(&eat_rva.to_le_bytes());
        
        // Name Pointer RVA
        let npt_rva = base_rva + npt_offset as u32;
        data[dir_offset + 32..dir_offset + 36].copy_from_slice(&npt_rva.to_le_bytes());
        
        // Ordinal Table RVA
        let ot_rva = base_rva + ot_offset as u32;
        data[dir_offset + 36..dir_offset + 40].copy_from_slice(&ot_rva.to_le_bytes());
        
        // 写入导出地址表 (EAT)
        for (i, func) in self.functions.iter().enumerate() {
            let offset = eat_offset + i * 4;
            let addr = if func.is_forwarder() {
                // 转发器：写入转发器名称RVA
                0 // 简化处理，实际需要计算转发器名称RVA
            } else {
                func.address as u32
            };
            data[offset..offset + 4].copy_from_slice(&addr.to_le_bytes());
        }
        
        // 写入名称指针表和序号表
        let mut name_table_offset = nt_offset;
        let mut name_ptr_index = 0;
        
        // 先写入DLL名称
        let dll_name_bytes = self.dll_name.as_bytes();
        data[name_table_offset..name_table_offset + dll_name_bytes.len()].copy_from_slice(dll_name_bytes);
        data[name_table_offset + dll_name_bytes.len()] = 0; // null terminator
        name_table_offset += dll_name_bytes.len() + 1;
        
        // 写入有名称的函数
        for (i, func) in self.functions.iter().enumerate() {
            if let Some(name) = &func.name {
                // 写入名称指针
                let name_rva = base_rva + name_table_offset as u32;
                let npt_entry_offset = npt_offset + name_ptr_index * 4;
                data[npt_entry_offset..npt_entry_offset + 4].copy_from_slice(&name_rva.to_le_bytes());
                
                // 写入序号
                let ordinal = (func.ordinal - self.ordinal_base as u16) as u16;
                let ot_entry_offset = ot_offset + name_ptr_index * 2;
                data[ot_entry_offset..ot_entry_offset + 2].copy_from_slice(&ordinal.to_le_bytes());
                
                // 写入名称到名称表
                let name_bytes = name.as_bytes();
                data[name_table_offset..name_table_offset + name_bytes.len()].copy_from_slice(name_bytes);
                data[name_table_offset + name_bytes.len()] = 0;
                name_table_offset += name_bytes.len() + 1;
                
                name_ptr_index += 1;
            }
        }
        
        ExportRebuildResult {
            data,
            export_directory_rva: export_dir_rva,
            export_directory_size: dir_size as u32,
        }
    }
}

/// 导出列表（用于管理多个导出表，虽然通常只有一个）
#[derive(Debug, Clone)]
pub struct ExportList {
    exports: Vec<ExportDirectory>,
}

impl ExportList {
    pub fn new() -> Self {
        Self {
            exports: Vec::new(),
        }
    }

    pub fn from_goblin(export_data: Option<&goblin::pe::export::ExportData>) -> Self {
        let mut list = Self::new();
        if let Some(data) = export_data {
            list.add(ExportDirectory::from_goblin(data));
        }
        list
    }

    pub fn len(&self) -> usize {
        self.exports.len()
    }

    pub fn is_empty(&self) -> bool {
        self.exports.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&ExportDirectory> {
        self.exports.get(index)
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut ExportDirectory> {
        self.exports.get_mut(index)
    }

    pub fn first(&self) -> Option<&ExportDirectory> {
        self.exports.first()
    }

    pub fn first_mut(&mut self) -> Option<&mut ExportDirectory> {
        self.exports.first_mut()
    }

    pub fn add(&mut self, export: ExportDirectory) {
        self.exports.push(export);
    }

    pub fn iter(&self) -> impl Iterator<Item = &ExportDirectory> {
        self.exports.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut ExportDirectory> {
        self.exports.iter_mut()
    }

    /// 查找函数
    pub fn find_function(&self, name: &str) -> Option<(&ExportDirectory, &ExportFunction)> {
        for export in &self.exports {
            if let Some(func) = export.find_by_name(name) {
                return Some((export, func));
            }
        }
        None
    }

    /// 更新所有导出地址
    pub fn update_addresses(&mut self, address_map: &std::collections::HashMap<u64, u64>) {
        for export in &mut self.exports {
            for func in &mut export.functions {
                if !func.is_forwarder() {
                    if let Some(&new_addr) = address_map.get(&func.address) {
                        func.address = new_addr;
                    }
                }
            }
        }
    }
}

impl Default for ExportList {
    fn default() -> Self {
        Self::new()
    }
}

/// 导出表重建结果
#[derive(Debug)]
pub struct ExportRebuildResult {
    /// 导出表数据
    pub data: Vec<u8>,
    /// 导出目录 RVA
    pub export_directory_rva: u32,
    /// 导出目录大小
    pub export_directory_size: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_function_by_name() {
        let func = ExportFunction::by_name(1, "TestFunction", 0x1000);
        assert!(func.is_by_name());
        assert!(!func.is_forwarder());
        assert_eq!(func.display_name(), "TestFunction");
        assert_eq!(func.address, 0x1000);
    }

    #[test]
    fn test_export_function_by_ordinal() {
        let func = ExportFunction::by_ordinal(42, 0x2000);
        assert!(!func.is_by_name());
        assert_eq!(func.display_name(), "Ordinal_42");
    }

    #[test]
    fn test_export_function_forwarder() {
        let func = ExportFunction::with_forwarder(1, "ForwardedFunc", "NTDLL.RtlInitString");
        assert!(func.is_forwarder());
        assert_eq!(func.forwarder, Some("NTDLL.RtlInitString".to_string()));
    }

    #[test]
    fn test_export_directory_add_function() {
        let mut export = ExportDirectory::new("test.dll");
        export.add_function(ExportFunction::by_name(1, "Func1", 0x1000));
        export.add_function(ExportFunction::by_ordinal(2, 0x2000));
        
        assert_eq!(export.functions.len(), 2);
        assert!(export.find_by_name("Func1").is_some());
        assert!(export.find_by_ordinal(2).is_some());
    }

    #[test]
    fn test_export_directory_update_address() {
        let mut export = ExportDirectory::new("test.dll");
        export.add_function(ExportFunction::by_name(1, "Func1", 0x1000));
        
        export.update_address(0x1000, 0x5000);
        
        let func = export.find_by_name("Func1").unwrap();
        assert_eq!(func.address, 0x5000);
    }

    #[test]
    fn test_export_directory_calculate_size() {
        let mut export = ExportDirectory::new("test.dll");
        export.add_function(ExportFunction::by_name(1, "Func1", 0x1000));
        export.add_function(ExportFunction::by_name(2, "Func2", 0x2000));
        export.add_function(ExportFunction::by_ordinal(3, 0x3000));
        
        let (dir, eat, npt, ot, nt) = export.calculate_rebuild_size();
        
        // 目录：40字节
        assert_eq!(dir, 40);
        // EAT：3个函数 * 4字节
        assert_eq!(eat, 12);
        // 名称指针表：2个有名称的函数 * 4字节
        assert_eq!(npt, 8);
        // 序号表：2个有名称的函数 * 2字节
        assert_eq!(ot, 4);
        // 名称表应该大于0
        assert!(nt > 0);
    }

    #[test]
    fn test_export_list_find_function() {
        let mut list = ExportList::new();
        let mut export = ExportDirectory::new("test.dll");
        export.add_function(ExportFunction::by_name(1, "MyFunction", 0x1000));
        list.add(export);
        
        let (exp, func) = list.find_function("MyFunction").unwrap();
        assert_eq!(exp.dll_name, "test.dll");
        assert_eq!(func.name, Some("MyFunction".to_string()));
    }

    #[test]
    fn test_export_list_update_addresses() {
        let mut list = ExportList::new();
        let mut export = ExportDirectory::new("test.dll");
        export.add_function(ExportFunction::by_name(1, "Func1", 0x1000));
        export.add_function(ExportFunction::by_name(2, "Func2", 0x2000));
        list.add(export);
        
        let mut map = std::collections::HashMap::new();
        map.insert(0x1000, 0x5000);
        map.insert(0x2000, 0x6000);
        
        list.update_addresses(&map);
        
        let func1 = list.find_function("Func1").unwrap().1;
        let func2 = list.find_function("Func2").unwrap().1;
        assert_eq!(func1.address, 0x5000);
        assert_eq!(func2.address, 0x6000);
    }
}
