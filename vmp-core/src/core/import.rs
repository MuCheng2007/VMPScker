//! Executable imports management
//! Translated from core/files/imports.h/cc

use crate::core::types::{ApiType, ImportOptions, CompilationType, RuntimeOptions, CompileFlags, get_sdk_info, get_api_runtime_options, get_api_sdk_options};
use crate::core::refs::ReferenceList;
use std::collections::HashMap;

/// Import function entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportFunction {
    /// Import address (IAT entry)
    pub address: u64,
    /// Function name
    pub name: String,
    /// API type (for SDK imports)
    pub api_type: Option<ApiType>,
    /// Import options
    pub options: ImportOptions,
    /// Compilation type (for SDK markers)
    pub compilation_type: CompilationType,
    /// Map function reference
    pub map_function: Option<usize>,
    /// Reference list (who references this import)
    pub reference_list: ReferenceList,
}

impl ImportFunction {
    /// Create a new import function
    pub fn new(address: u64, name: impl Into<String>) -> Self {
        Self {
            address,
            name: name.into(),
            api_type: None,
            options: ImportOptions::NONE,
            compilation_type: CompilationType::None,
            map_function: None,
            reference_list: ReferenceList::new(),
        }
    }

    /// Create from SDK info
    pub fn from_sdk(address: u64, name: &str) -> Option<Self> {
        let sdk_info = get_sdk_info(name)?;
        let mut func = Self::new(address, name);
        func.api_type = Some(sdk_info.api_type);
        func.options = sdk_info.options;
        func.compilation_type = sdk_info.compilation_type;
        Some(func)
    }

    /// Get full name (DLL!Function)
    pub fn full_name(&self, dll_name: &str) -> String {
        if dll_name.is_empty() {
            self.name.clone()
        } else {
            format!("{}!{}", dll_name, self.name)
        }
    }

    /// Get display name
    pub fn display_name(&self, show_return: bool) -> String {
        // Simplified - could include return type info
        if show_return {
            self.name.clone()
        } else {
            self.name.clone()
        }
    }

    /// Include an option
    pub fn include_option(&mut self, option: ImportOptions) {
        self.options.insert(option);
    }

    /// Exclude an option
    pub fn exclude_option(&mut self, option: ImportOptions) {
        self.options.remove(option);
    }

    /// Check if has option
    pub fn has_option(&self, option: ImportOptions) -> bool {
        self.options.contains(option)
    }

    /// Check if this is an SDK import
    pub fn is_sdk(&self) -> bool {
        self.api_type.is_some()
    }

    /// Get runtime options for this import
    pub fn get_runtime_options(&self) -> RuntimeOptions {
        self.api_type.map(get_api_runtime_options).unwrap_or(RuntimeOptions::NONE)
    }

    /// Get SDK options for this import
    pub fn get_sdk_options(&self) -> CompileFlags {
        self.api_type.map(get_api_sdk_options).unwrap_or(CompileFlags::NONE)
    }

    /// Set API type
    pub fn set_api_type(&mut self, api_type: ApiType) {
        self.api_type = Some(api_type);
    }

    /// Set compilation type
    pub fn set_compilation_type(&mut self, comp_type: CompilationType) {
        self.compilation_type = comp_type;
    }

    /// Set map function reference
    pub fn set_map_function(&mut self, map_func: usize) {
        self.map_function = Some(map_func);
    }

    /// Rebase address
    pub fn rebase(&mut self, delta: u64) {
        self.address = self.address.wrapping_add(delta);
        self.reference_list.rebase(delta);
    }

    /// Create a rebased copy
    pub fn rebased(&self, delta: u64) -> Self {
        let mut copy = self.clone();
        copy.rebase(delta);
        copy
    }
}

impl Default for ImportFunction {
    fn default() -> Self {
        Self {
            address: 0,
            name: String::new(),
            api_type: None,
            options: ImportOptions::NONE,
            compilation_type: CompilationType::None,
            map_function: None,
            reference_list: ReferenceList::new(),
        }
    }
}

/// Import entry (DLL with its functions)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    /// DLL name
    pub dll_name: String,
    /// Functions imported from this DLL
    pub functions: Vec<ImportFunction>,
    /// Whether this is the SDK import
    pub is_sdk: bool,
    /// Excluded from import protection
    pub excluded_from_protection: bool,
}

impl Import {
    /// Create a new import entry
    pub fn new(dll_name: impl Into<String>) -> Self {
        Self {
            dll_name: dll_name.into(),
            functions: Vec::new(),
            is_sdk: false,
            excluded_from_protection: false,
        }
    }

    /// Create SDK import entry
    pub fn new_sdk() -> Self {
        let mut import = Self::new("VMProtectSDK");
        import.is_sdk = true;
        import
    }

    /// Add a function
    pub fn add_function(&mut self, function: ImportFunction) -> &ImportFunction {
        self.functions.push(function);
        self.functions.last().unwrap()
    }

    /// Add a function by name
    pub fn add(&mut self, address: u64, name: impl Into<String>) -> &ImportFunction {
        self.add_function(ImportFunction::new(address, name))
    }

    /// Add SDK function
    pub fn add_sdk_function(&mut self, address: u64, name: &str) -> Option<&ImportFunction> {
        let func = ImportFunction::from_sdk(address, name)?;
        self.add_function(func);
        self.functions.last()
    }

    /// Find function by address
    pub fn find_by_address(&self, address: u64) -> Option<&ImportFunction> {
        self.functions.iter().find(|f| f.address == address)
    }

    /// Find function by address (mutable)
    pub fn find_by_address_mut(&mut self, address: u64) -> Option<&mut ImportFunction> {
        self.functions.iter_mut().find(|f| f.address == address)
    }

    /// Find function by name
    pub fn find_by_name(&self, name: &str) -> Option<&ImportFunction> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Find function by name (mutable)
    pub fn find_by_name_mut(&mut self, name: &str) -> Option<&mut ImportFunction> {
        self.functions.iter_mut().find(|f| f.name == name)
    }

    /// Get number of functions
    pub fn len(&self) -> usize {
        self.functions.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    /// Compare DLL name (case-insensitive)
    pub fn compare_name(&self, name: &str) -> bool {
        self.dll_name.eq_ignore_ascii_case(name)
    }

    /// Get aggregate runtime options
    pub fn get_runtime_options(&self) -> RuntimeOptions {
        self.functions.iter().fold(RuntimeOptions::NONE, |acc, f| {
            acc | f.get_runtime_options()
        })
    }

    /// Get aggregate SDK options
    pub fn get_sdk_options(&self) -> CompileFlags {
        self.functions.iter().fold(CompileFlags::NONE, |acc, f| {
            acc | f.get_sdk_options()
        })
    }

    /// Rebase all functions
    pub fn rebase(&mut self, delta: u64) {
        for func in &mut self.functions {
            func.rebase(delta);
        }
    }

    /// Calculate hash for comparison
    pub fn hash(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        self.dll_name.hash(&mut hasher);
        self.excluded_from_protection.hash(&mut hasher);
        hasher.finish()
    }
}

impl Default for Import {
    fn default() -> Self {
        Self {
            dll_name: String::new(),
            functions: Vec::new(),
            is_sdk: false,
            excluded_from_protection: false,
        }
    }
}

/// List of imports
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportList {
    imports: Vec<Import>,
    address_map: HashMap<u64, (usize, usize)>, // address -> (import_idx, func_idx)
}

impl ImportList {
    /// Create a new empty import list
    pub fn new() -> Self {
        Self {
            imports: Vec::new(),
            address_map: HashMap::new(),
        }
    }

    /// Create with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            imports: Vec::with_capacity(capacity),
            address_map: HashMap::with_capacity(capacity * 4), // Estimate 4 funcs per import
        }
    }

    /// Add an import entry
    pub fn add(&mut self, import: Import) -> &Import {
        let idx = self.imports.len();
        self.imports.push(import);
        self.rebuild_map();
        &self.imports[idx]
    }

    /// Add SDK import
    pub fn add_sdk(&mut self) -> &Import {
        let sdk = Import::new_sdk();
        self.add(sdk)
    }

    /// Get import by index
    pub fn get(&self, index: usize) -> Option<&Import> {
        self.imports.get(index)
    }

    /// Get mutable import by index
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Import> {
        self.imports.get_mut(index)
    }

    /// Find function by address
    pub fn find_function_by_address(&self, address: u64) -> Option<&ImportFunction> {
        self.address_map.get(&address).and_then(|&(imp_idx, func_idx)| {
            self.imports.get(imp_idx).and_then(|imp| imp.functions.get(func_idx))
        })
    }

    /// Find function by address (mutable)
    pub fn find_function_by_address_mut(&mut self, address: u64) -> Option<&mut ImportFunction> {
        if let Some(&(imp_idx, func_idx)) = self.address_map.get(&address) {
            self.imports.get_mut(imp_idx).and_then(|imp| imp.functions.get_mut(func_idx))
        } else {
            None
        }
    }

    /// Find import by DLL name
    pub fn find_by_name(&self, name: &str) -> Option<&Import> {
        self.imports.iter().find(|imp| imp.compare_name(name))
    }

    /// Find import by DLL name (mutable)
    pub fn find_by_name_mut(&mut self, name: &str) -> Option<&mut Import> {
        self.imports.iter_mut().find(|imp| imp.compare_name(name))
    }

    /// Check if has SDK import
    pub fn has_sdk(&self) -> bool {
        self.imports.iter().any(|imp| imp.is_sdk)
    }

    /// Get SDK import
    pub fn get_sdk(&self) -> Option<&Import> {
        self.imports.iter().find(|imp| imp.is_sdk)
    }

    /// Get SDK import (mutable)
    pub fn get_sdk_mut(&mut self) -> Option<&mut Import> {
        self.imports.iter_mut().find(|imp| imp.is_sdk)
    }

    /// Get aggregate runtime options
    pub fn get_runtime_options(&self) -> RuntimeOptions {
        self.imports.iter().fold(RuntimeOptions::NONE, |acc, imp| {
            acc | imp.get_runtime_options()
        })
    }

    /// Get aggregate SDK options
    pub fn get_sdk_options(&self) -> CompileFlags {
        self.imports.iter().fold(CompileFlags::NONE, |acc, imp| {
            acc | imp.get_sdk_options()
        })
    }

    /// Get number of imports
    pub fn len(&self) -> usize {
        self.imports.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.imports.is_empty()
    }

    /// Clear all imports
    pub fn clear(&mut self) {
        self.imports.clear();
        self.address_map.clear();
    }

    /// Rebase all imports
    pub fn rebase(&mut self, delta: u64) {
        for import in &mut self.imports {
            import.rebase(delta);
        }
        self.rebuild_map();
    }

    /// Rebuild address map
    fn rebuild_map(&mut self) {
        self.address_map.clear();
        for (imp_idx, import) in self.imports.iter().enumerate() {
            for (func_idx, func) in import.functions.iter().enumerate() {
                self.address_map.insert(func.address, (imp_idx, func_idx));
            }
        }
    }

    /// Get all imports
    pub fn imports(&self) -> &[Import] {
        &self.imports
    }

    /// Get mutable imports
    pub fn imports_mut(&mut self) -> &mut Vec<Import> {
        &mut self.imports
    }

    /// Iterate over imports
    pub fn iter(&self) -> std::slice::Iter<Import> {
        self.imports.iter()
    }

    /// Iterate mutably over imports
    pub fn iter_mut(&mut self) -> std::slice::IterMut<Import> {
        self.imports.iter_mut()
    }

    /// Iterate over all functions across all imports
    pub fn iter_functions(&self) -> impl Iterator<Item = &ImportFunction> {
        self.imports.iter().flat_map(|imp| imp.functions.iter())
    }

    /// Get total function count
    pub fn total_functions(&self) -> usize {
        self.imports.iter().map(|imp| imp.functions.len()).sum()
    }

    /// Merge another import list
    pub fn merge(&mut self, other: &ImportList) {
        for import in &other.imports {
            self.add(import.clone());
        }
    }

    /// Remove import by name
    pub fn remove_by_name(&mut self, name: &str) -> bool {
        if let Some(pos) = self.imports.iter().position(|imp| imp.compare_name(name)) {
            self.imports.remove(pos);
            self.rebuild_map();
            true
        } else {
            false
        }
    }
}

impl IntoIterator for ImportList {
    type Item = Import;
    type IntoIter = std::vec::IntoIter<Import>;

    fn into_iter(self) -> Self::IntoIter {
        self.imports.into_iter()
    }
}

impl<'a> IntoIterator for &'a ImportList {
    type Item = &'a Import;
    type IntoIter = std::slice::Iter<'a, Import>;

    fn into_iter(self) -> Self::IntoIter {
        self.imports.iter()
    }
}

impl<'a> IntoIterator for &'a mut ImportList {
    type Item = &'a mut Import;
    type IntoIter = std::slice::IterMut<'a, Import>;

    fn into_iter(self) -> Self::IntoIter {
        self.imports.iter_mut()
    }
}

impl Extend<Import> for ImportList {
    fn extend<T: IntoIterator<Item = Import>>(&mut self, iter: T) {
        for import in iter {
            self.add(import);
        }
    }
}

impl FromIterator<Import> for ImportList {
    fn from_iter<I: IntoIterator<Item = Import>>(iter: I) -> Self {
        let mut list = Self::new();
        list.extend(iter);
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_function_new() {
        let func = ImportFunction::new(0x1000, "TestFunction");
        assert_eq!(func.address, 0x1000);
        assert_eq!(func.name, "TestFunction");
    }

    #[test]
    fn test_import_function_from_sdk() {
        let func = ImportFunction::from_sdk(0x1000, "VMProtectBegin");
        assert!(func.is_some());
        let func = func.unwrap();
        assert_eq!(func.api_type, Some(ApiType::Begin));
    }

    #[test]
    fn test_import_function_full_name() {
        let func = ImportFunction::new(0x1000, "TestFunction");
        assert_eq!(func.full_name("kernel32.dll"), "kernel32.dll!TestFunction");
        assert_eq!(func.full_name(""), "TestFunction");
    }

    #[test]
    fn test_import_function_runtime_options() {
        let func = ImportFunction::from_sdk(0x1000, "VMProtectSetSerialNumber").unwrap();
        let opts = func.get_runtime_options();
        assert!(opts.contains(RuntimeOptions::KEY));
    }

    #[test]
    fn test_import_new() {
        let import = Import::new("kernel32.dll");
        assert_eq!(import.dll_name, "kernel32.dll");
        assert!(!import.is_sdk);
    }

    #[test]
    fn test_import_new_sdk() {
        let import = Import::new_sdk();
        assert!(import.is_sdk);
    }

    #[test]
    fn test_import_add_function() {
        let mut import = Import::new("kernel32.dll");
        import.add(0x1000, "LoadLibraryA");
        import.add(0x1004, "GetProcAddress");
        
        assert_eq!(import.len(), 2);
    }

    #[test]
    fn test_import_find_by_address() {
        let mut import = Import::new("kernel32.dll");
        import.add(0x1000, "LoadLibraryA");
        import.add(0x1004, "GetProcAddress");
        
        let found = import.find_by_address(0x1000);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "LoadLibraryA");
    }

    #[test]
    fn test_import_compare_name() {
        let import = Import::new("KERNEL32.DLL");
        assert!(import.compare_name("kernel32.dll"));
        assert!(import.compare_name("KERNEL32.dll"));
        assert!(!import.compare_name("user32.dll"));
    }

    #[test]
    fn test_import_list_add() {
        let mut list = ImportList::new();
        list.add(Import::new("kernel32.dll"));
        list.add(Import::new("user32.dll"));
        
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_import_list_find_function_by_address() {
        let mut list = ImportList::new();
        let mut import = Import::new("kernel32.dll");
        import.add(0x1000, "LoadLibraryA");
        list.add(import);
        
        let found = list.find_function_by_address(0x1000);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "LoadLibraryA");
    }

    #[test]
    fn test_import_list_find_by_name() {
        let mut list = ImportList::new();
        list.add(Import::new("kernel32.dll"));
        list.add(Import::new("user32.dll"));
        
        let found = list.find_by_name("KERNEL32.dll");
        assert!(found.is_some());
    }

    #[test]
    fn test_import_list_has_sdk() {
        let mut list = ImportList::new();
        assert!(!list.has_sdk());
        
        list.add(Import::new_sdk());
        assert!(list.has_sdk());
    }

    #[test]
    fn test_import_list_rebase() {
        let mut list = ImportList::new();
        let mut import = Import::new("kernel32.dll");
        import.add(0x1000, "LoadLibraryA");
        list.add(import);
        
        list.rebase(0x100);
        
        let found = list.find_function_by_address(0x1100);
        assert!(found.is_some());
    }

    #[test]
    fn test_import_list_total_functions() {
        let mut list = ImportList::new();
        let mut import1 = Import::new("kernel32.dll");
        import1.add(0x1000, "Func1");
        import1.add(0x1004, "Func2");
        list.add(import1);
        
        let mut import2 = Import::new("user32.dll");
        import2.add(0x2000, "Func3");
        list.add(import2);
        
        assert_eq!(list.total_functions(), 3);
    }
}
