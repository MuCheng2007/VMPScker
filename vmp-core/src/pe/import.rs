use crate::error::{Result, VmpError};

/// 导入函数信息
#[derive(Debug, Clone)]
pub struct ImportFunction {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub address: u64,
    pub hint: u16,
}

impl ImportFunction {
    pub fn by_name(name: impl Into<String>, address: u64, hint: u16) -> Self {
        Self {
            name: Some(name.into()),
            ordinal: None,
            address,
            hint,
        }
    }

    pub fn by_ordinal(ordinal: u16, address: u64) -> Self {
        Self {
            name: None,
            ordinal: Some(ordinal),
            address,
            hint: 0,
        }
    }

    pub fn is_by_name(&self) -> bool {
        self.name.is_some()
    }

    pub fn is_by_ordinal(&self) -> bool {
        self.ordinal.is_some()
    }

    pub fn display_name(&self) -> String {
        match &self.name {
            Some(name) => name.clone(),
            None => format!("Ordinal_{}", self.ordinal.unwrap_or(0)),
        }
    }

    /// 获取导入查找表条目值（64位）
    pub fn lookup_table_entry_64(&self) -> u64 {
        if let Some(ordinal) = self.ordinal {
            // 按序号导入：高位为1，低16位为序号
            0x8000000000000000 | (ordinal as u64)
        } else {
            // 按名称导入：存储的是Hint/Name表的RVA
            self.address
        }
    }

    /// 获取导入查找表条目值（32位）
    pub fn lookup_table_entry_32(&self) -> u32 {
        if let Some(ordinal) = self.ordinal {
            // 按序号导入：高位为1，低16位为序号
            0x80000000 | (ordinal as u32)
        } else {
            // 按名称导入
            self.address as u32
        }
    }
}

/// DLL导入信息
#[derive(Debug, Clone)]
pub struct Import {
    pub dll_name: String,
    pub functions: Vec<ImportFunction>,
    pub import_lookup_table_rva: u32,
    pub import_address_table_rva: u32,
}

impl Import {
    pub fn new(dll_name: impl Into<String>) -> Self {
        Self {
            dll_name: dll_name.into(),
            functions: Vec::new(),
            import_lookup_table_rva: 0,
            import_address_table_rva: 0,
        }
    }

    pub fn add_function(&mut self, function: ImportFunction) {
        self.functions.push(function);
    }

    pub fn find_function(&self, name: &str) -> Option<&ImportFunction> {
        self.functions.iter().find(|f| {
            f.name.as_ref().map(|n| n == name).unwrap_or(false)
        })
    }

    pub fn find_function_by_ordinal(&self, ordinal: u16) -> Option<&ImportFunction> {
        self.functions.iter().find(|f| f.ordinal == Some(ordinal))
    }

    /// 计算此导入所需的ILT/IAT大小（字节）
    pub fn table_size(&self, is_64bit: bool) -> usize {
        // 每个函数一个条目，加上结尾的NULL条目
        let entry_size = if is_64bit { 8 } else { 4 };
        (self.functions.len() + 1) * entry_size
    }
}

/// 导入列表
#[derive(Debug, Clone)]
pub struct ImportList {
    imports: Vec<Import>,
}

impl ImportList {
    pub fn new() -> Self {
        Self {
            imports: Vec::new(),
        }
    }

    pub fn from_goblin(import_data: &goblin::pe::import::ImportData) -> Self {
        let mut list = Self::new();

        for entry in &import_data.import_data {
            let mut import = Import::new(entry.name.to_string());
            import.import_lookup_table_rva = entry.import_directory_entry.import_lookup_table_rva;
            import.import_address_table_rva = entry.import_directory_entry.import_address_table_rva;

            if let Some(ref lookup_table) = entry.import_lookup_table {
                for lookup_entry in lookup_table {
                    let import_func = match lookup_entry {
                        goblin::pe::import::SyntheticImportLookupTableEntry::OrdinalNumber(ord) => {
                            ImportFunction::by_ordinal(*ord, 0)
                        }
                        goblin::pe::import::SyntheticImportLookupTableEntry::HintNameTableRVA((rva, hint_entry)) => {
                            ImportFunction {
                                name: Some(hint_entry.name.to_string()),
                                ordinal: None,
                                address: *rva as u64,
                                hint: hint_entry.hint,
                            }
                        }
                    };
                    import.add_function(import_func);
                }
            }

            list.add(import);
        }

        list
    }

    pub fn len(&self) -> usize {
        self.imports.len()
    }

    pub fn is_empty(&self) -> bool {
        self.imports.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&Import> {
        self.imports.get(index)
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut Import> {
        self.imports.get_mut(index)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Import> {
        self.imports.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Import> {
        self.imports.iter_mut()
    }

    pub fn find_by_dll(&self, dll_name: &str) -> Option<&Import> {
        self.imports.iter().find(|i| {
            i.dll_name.to_lowercase() == dll_name.to_lowercase()
        })
    }

    pub fn find_by_dll_mut(&mut self, dll_name: &str) -> Option<&mut Import> {
        self.imports.iter_mut().find(|i| {
            i.dll_name.to_lowercase() == dll_name.to_lowercase()
        })
    }

    pub fn find_function(&self, dll_name: &str, func_name: &str) -> Option<&ImportFunction> {
        self.find_by_dll(dll_name)
            .and_then(|imp| imp.find_function(func_name))
    }

    pub fn add(&mut self, import: Import) {
        self.imports.push(import);
    }

    /// 添加新的导入函数
    pub fn add_function(&mut self, dll_name: &str, func_name: &str) -> Result<()> {
        let import = self.find_by_dll_mut(dll_name)
            .ok_or_else(|| VmpError::NotFound(format!("DLL '{}' not found", dll_name)))?;
        
        import.add_function(ImportFunction::by_name(func_name, 0, 0));
        Ok(())
    }

    /// 创建新的DLL导入项
    pub fn create_import(&mut self, dll_name: impl Into<String>) -> &mut Import {
        let import = Import::new(dll_name);
        self.add(import);
        let index = self.imports.len() - 1;
        &mut self.imports[index]
    }

    pub fn all_functions(&self) -> impl Iterator<Item = (&Import, &ImportFunction)> {
        self.imports.iter().flat_map(|imp| {
            imp.functions.iter().map(move |func| (imp, func))
        })
    }

    /// 计算重建导入表所需的总大小
    /// 
    /// 返回：(目录表大小, ILT总大小, IAT总大小, 名称表总大小)
    pub fn calculate_rebuild_size(&self, is_64bit: bool) -> (usize, usize, usize, usize) {
        // 导入目录表：每个导入一个条目（20字节），加上结尾的NULL条目
        let directory_size = (self.imports.len() + 1) * 20;
        
        // ILT和IAT大小
        let mut ilt_size = 0;
        let mut iat_size = 0;
        for import in &self.imports {
            let table_size = import.table_size(is_64bit);
            ilt_size += table_size;
            iat_size += table_size;
        }
        
        // 名称表大小：每个按名称导入的函数需要一个Hint/Name条目
        let mut name_table_size = 0;
        for import in &self.imports {
            // DLL名称（以NULL结尾）
            name_table_size += import.dll_name.len() + 1;
            
            for func in &import.functions {
                if func.is_by_name() {
                    // Hint (2字节) + 名称 + NULL结尾
                    name_table_size += 2 + func.name.as_ref().map(|n| n.len()).unwrap_or(0) + 1;
                    // 对齐到偶数地址
                    if name_table_size % 2 != 0 {
                        name_table_size += 1;
                    }
                }
            }
        }
        
        (directory_size, ilt_size, iat_size, name_table_size)
    }

    /// 获取所有按名称导入的函数数量
    pub fn named_import_count(&self) -> usize {
        self.all_functions()
            .filter(|(_, func)| func.is_by_name())
            .count()
    }

    /// 获取所有按序号导入的函数数量
    pub fn ordinal_import_count(&self) -> usize {
        self.all_functions()
            .filter(|(_, func)| func.is_by_ordinal())
            .count()
    }
}

impl Default for ImportList {
    fn default() -> Self {
        Self::new()
    }
}

/// 重建结果
#[derive(Debug)]
pub struct ImportRebuildResult {
    /// 导入表数据
    pub data: Vec<u8>,
    /// 导入目录 RVA
    pub import_directory_rva: u32,
    /// 导入目录大小
    pub import_directory_size: u32,
    /// IAT RVA（用于数据目录）
    pub iat_rva: u32,
    /// IAT 大小
    pub iat_size: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_function_by_name() {
        let func = ImportFunction::by_name("TestFunction", 0x1000, 5);
        assert!(func.is_by_name());
        assert!(!func.is_by_ordinal());
        assert_eq!(func.display_name(), "TestFunction");
        assert_eq!(func.hint, 5);
    }

    #[test]
    fn test_import_function_by_ordinal() {
        let func = ImportFunction::by_ordinal(42, 0);
        assert!(!func.is_by_name());
        assert!(func.is_by_ordinal());
        assert_eq!(func.display_name(), "Ordinal_42");
    }

    #[test]
    fn test_import_add_function() {
        let mut import = Import::new("kernel32.dll");
        import.add_function(ImportFunction::by_name("CreateFileA", 0, 0));
        import.add_function(ImportFunction::by_ordinal(10, 0));
        
        assert_eq!(import.functions.len(), 2);
        assert!(import.find_function("CreateFileA").is_some());
        assert!(import.find_function_by_ordinal(10).is_some());
    }

    #[test]
    fn test_import_list_calculate_size() {
        let mut list = ImportList::new();
        
        let mut import1 = Import::new("kernel32.dll");
        import1.add_function(ImportFunction::by_name("CreateFileA", 0, 0));
        import1.add_function(ImportFunction::by_name("ReadFile", 0, 0));
        list.add(import1);
        
        let mut import2 = Import::new("user32.dll");
        import2.add_function(ImportFunction::by_name("MessageBoxA", 0, 0));
        list.add(import2);
        
        let (dir_size, ilt_size, iat_size, name_size) = list.calculate_rebuild_size(true);
        
        // 目录表：(2个导入 + 1个NULL) * 20字节
        assert_eq!(dir_size, 60);
        
        // ILT/IAT：每个导入 (函数数 + 1) * 8字节
        // kernel32: (2+1)*8 = 24, user32: (1+1)*8 = 16, 总计 = 40
        assert_eq!(ilt_size, 40);
        assert_eq!(iat_size, 40);
        
        // 名称表应该大于0
        assert!(name_size > 0);
    }

    #[test]
    fn test_lookup_table_entry_64() {
        let func_name = ImportFunction::by_name("Test", 0x1234, 0);
        assert_eq!(func_name.lookup_table_entry_64(), 0x1234);
        
        let func_ord = ImportFunction::by_ordinal(42, 0);
        assert_eq!(func_ord.lookup_table_entry_64(), 0x800000000000002A);
    }

    #[test]
    fn test_lookup_table_entry_32() {
        let func_name = ImportFunction::by_name("Test", 0x1234, 0);
        assert_eq!(func_name.lookup_table_entry_32(), 0x1234);
        
        let func_ord = ImportFunction::by_ordinal(42, 0);
        assert_eq!(func_ord.lookup_table_entry_32(), 0x8000002A);
    }
}
