//! Executable exports management
//! Translated from core/files/exports.h/cc

use crate::core::types::{ApiType, OperandSize};
use std::collections::HashMap;

/// Export entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    /// Export address
    pub address: u64,
    /// Export name
    pub name: String,
    /// Forwarded name (if forwarded export)
    pub forwarded_name: Option<String>,
    /// API type (for SDK exports)
    pub api_type: Option<ApiType>,
    /// Ordinal number (if exported by ordinal)
    pub ordinal: Option<u16>,
}

impl Export {
    /// Create a new export
    pub fn new(address: u64, name: impl Into<String>) -> Self {
        Self {
            address,
            name: name.into(),
            forwarded_name: None,
            api_type: None,
            ordinal: None,
        }
    }

    /// Create a forwarded export
    pub fn forwarded(address: u64, name: impl Into<String>, forwarded: impl Into<String>) -> Self {
        Self {
            address,
            name: name.into(),
            forwarded_name: Some(forwarded.into()),
            api_type: None,
            ordinal: None,
        }
    }

    /// Create export by ordinal
    pub fn by_ordinal(address: u64, ordinal: u16) -> Self {
        Self {
            address,
            name: format!("Ordinal_{}", ordinal),
            forwarded_name: None,
            api_type: None,
            ordinal: Some(ordinal),
        }
    }

    /// Get display name
    pub fn display_name(&self, show_return: bool) -> String {
        // Simplified - could include return type
        if show_return {
            self.name.clone()
        } else {
            self.name.clone()
        }
    }

    /// Check if this is a forwarded export
    pub fn is_forwarded(&self) -> bool {
        self.forwarded_name.is_some()
    }

    /// Check if this is an ordinal export
    pub fn is_ordinal(&self) -> bool {
        self.ordinal.is_some()
    }

    /// Set API type
    pub fn set_api_type(&mut self, api_type: ApiType) {
        self.api_type = Some(api_type);
    }

    /// Rebase address
    pub fn rebase(&mut self, delta: u64) {
        self.address = self.address.wrapping_add(delta);
    }

    /// Create a rebased copy
    pub fn rebased(&self, delta: u64) -> Self {
        let mut copy = self.clone();
        copy.rebase(delta);
        copy
    }

    /// Check if equal to another export
    pub fn is_equal(&self, other: &Export) -> bool {
        self.address == other.address
            && self.name == other.name
            && self.forwarded_name == other.forwarded_name
    }
}

impl Default for Export {
    fn default() -> Self {
        Self {
            address: 0,
            name: String::new(),
            forwarded_name: None,
            api_type: None,
            ordinal: None,
        }
    }
}

/// Export list for a module
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportList {
    /// Module name (DLL name)
    pub module_name: String,
    /// Export entries
    exports: Vec<Export>,
    /// Address to index map
    address_map: HashMap<u64, usize>,
    /// Name to index map
    name_map: HashMap<String, usize>,
}

impl ExportList {
    /// Create a new empty export list
    pub fn new() -> Self {
        Self {
            module_name: String::new(),
            exports: Vec::new(),
            address_map: HashMap::new(),
            name_map: HashMap::new(),
        }
    }

    /// Create with module name
    pub fn with_name(name: impl Into<String>) -> Self {
        Self {
            module_name: name.into(),
            exports: Vec::new(),
            address_map: HashMap::new(),
            name_map: HashMap::new(),
        }
    }

    /// Create with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            module_name: String::new(),
            exports: Vec::with_capacity(capacity),
            address_map: HashMap::with_capacity(capacity),
            name_map: HashMap::with_capacity(capacity),
        }
    }

    /// Add an export
    pub fn add(&mut self, export: Export) -> &Export {
        let idx = self.exports.len();
        let address = export.address;
        let name = export.name.clone();
        
        self.exports.push(export);
        self.address_map.insert(address, idx);
        self.name_map.insert(name, idx);
        
        &self.exports[idx]
    }

    /// Add a simple export
    pub fn add_simple(&mut self, address: u64, name: impl Into<String>) -> &Export {
        self.add(Export::new(address, name))
    }

    /// Get export by index
    pub fn get(&self, index: usize) -> Option<&Export> {
        self.exports.get(index)
    }

    /// Get mutable export by index
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Export> {
        self.exports.get_mut(index)
    }

    /// Find export by address
    pub fn find_by_address(&self, address: u64) -> Option<&Export> {
        self.address_map.get(&address).and_then(|&idx| self.exports.get(idx))
    }

    /// Find export by address (mutable)
    pub fn find_by_address_mut(&mut self, address: u64) -> Option<&mut Export> {
        self.address_map.get(&address).copied().and_then(move |idx| self.exports.get_mut(idx))
    }

    /// Find export by name
    pub fn find_by_name(&self, name: &str) -> Option<&Export> {
        self.name_map.get(name).and_then(|&idx| self.exports.get(idx))
    }

    /// Find export by name (mutable)
    pub fn find_by_name_mut(&mut self, name: &str) -> Option<&mut Export> {
        self.name_map.get(name).copied().and_then(move |idx| self.exports.get_mut(idx))
    }

    /// Find export by API type
    pub fn find_by_api_type(&self, api_type: ApiType) -> Option<&Export> {
        self.exports.iter().find(|e| e.api_type == Some(api_type))
    }

    /// Get address by API type
    pub fn get_address_by_type(&self, api_type: ApiType) -> Option<u64> {
        self.find_by_api_type(api_type).map(|e| e.address)
    }

    /// Get number of exports
    pub fn len(&self) -> usize {
        self.exports.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.exports.is_empty()
    }

    /// Clear all exports
    pub fn clear(&mut self) {
        self.exports.clear();
        self.address_map.clear();
        self.name_map.clear();
    }

    /// Rebase all exports
    pub fn rebase(&mut self, delta: u64) {
        // Clear maps since addresses will change
        self.address_map.clear();
        
        for (idx, export) in self.exports.iter_mut().enumerate() {
            export.rebase(delta);
            self.address_map.insert(export.address, idx);
        }
    }

    /// Get all exports
    pub fn exports(&self) -> &[Export] {
        &self.exports
    }

    /// Get mutable exports
    pub fn exports_mut(&mut self) -> &mut Vec<Export> {
        &mut self.exports
    }

    /// Iterate over exports
    pub fn iter(&self) -> std::slice::Iter<Export> {
        self.exports.iter()
    }

    /// Iterate mutably over exports
    pub fn iter_mut(&mut self) -> std::slice::IterMut<Export> {
        self.exports.iter_mut()
    }

    /// Get forwarded exports
    pub fn forwarded_exports(&self) -> Vec<&Export> {
        self.exports.iter().filter(|e| e.is_forwarded()).collect()
    }

    /// Get ordinal exports
    pub fn ordinal_exports(&self) -> Vec<&Export> {
        self.exports.iter().filter(|e| e.is_ordinal()).collect()
    }

    /// Get addresses as a vector
    pub fn addresses(&self) -> Vec<u64> {
        self.exports.iter().map(|e| e.address).collect()
    }

    /// Get names as a vector
    pub fn names(&self) -> Vec<&str> {
        self.exports.iter().map(|e| e.name.as_str()).collect()
    }

    /// Check if equal to another export list
    pub fn is_equal(&self, other: &ExportList) -> bool {
        if self.module_name != other.module_name || self.exports.len() != other.exports.len() {
            return false;
        }

        for (a, b) in self.exports.iter().zip(other.exports.iter()) {
            if !a.is_equal(b) {
                return false;
            }
        }

        true
    }

    /// Merge another export list
    pub fn merge(&mut self, other: &ExportList) {
        for export in &other.exports {
            if !self.address_map.contains_key(&export.address) {
                self.add(export.clone());
            }
        }
    }

    /// Remove export by address
    pub fn remove_by_address(&mut self, address: u64) -> bool {
        if let Some(&idx) = self.address_map.get(&address) {
            let name = self.exports[idx].name.clone();
            self.exports.remove(idx);
            self.address_map.remove(&address);
            self.name_map.remove(&name);
            
            // Rebuild maps since indices shifted
            self.address_map.clear();
            self.name_map.clear();
            for (i, export) in self.exports.iter().enumerate() {
                self.address_map.insert(export.address, i);
                self.name_map.insert(export.name.clone(), i);
            }
            true
        } else {
            false
        }
    }

    /// Remove export by name
    pub fn remove_by_name(&mut self, name: &str) -> bool {
        if let Some(&idx) = self.name_map.get(name) {
            let address = self.exports[idx].address;
            self.exports.remove(idx);
            self.address_map.remove(&address);
            self.name_map.remove(name);
            
            // Rebuild maps
            self.address_map.clear();
            self.name_map.clear();
            for (i, export) in self.exports.iter().enumerate() {
                self.address_map.insert(export.address, i);
                self.name_map.insert(export.name.clone(), i);
            }
            true
        } else {
            false
        }
    }

    /// Sort exports by address
    pub fn sort_by_address(&mut self) {
        self.exports.sort_by_key(|e| e.address);
        // Rebuild maps
        self.address_map.clear();
        self.name_map.clear();
        for (idx, export) in self.exports.iter().enumerate() {
            self.address_map.insert(export.address, idx);
            self.name_map.insert(export.name.clone(), idx);
        }
    }

    /// Sort exports by name
    pub fn sort_by_name(&mut self) {
        self.exports.sort_by(|a, b| a.name.cmp(&b.name));
        // Rebuild maps
        self.address_map.clear();
        self.name_map.clear();
        for (idx, export) in self.exports.iter().enumerate() {
            self.address_map.insert(export.address, idx);
            self.name_map.insert(export.name.clone(), idx);
        }
    }

    /// Get address size based on addresses
    pub fn address_size(&self) -> OperandSize {
        let max_addr = self.exports.iter().map(|e| e.address).max().unwrap_or(0);
        if max_addr > u32::MAX as u64 {
            OperandSize::QWord
        } else {
            OperandSize::DWord
        }
    }
}

impl IntoIterator for ExportList {
    type Item = Export;
    type IntoIter = std::vec::IntoIter<Export>;

    fn into_iter(self) -> Self::IntoIter {
        self.exports.into_iter()
    }
}

impl<'a> IntoIterator for &'a ExportList {
    type Item = &'a Export;
    type IntoIter = std::slice::Iter<'a, Export>;

    fn into_iter(self) -> Self::IntoIter {
        self.exports.iter()
    }
}

impl<'a> IntoIterator for &'a mut ExportList {
    type Item = &'a mut Export;
    type IntoIter = std::slice::IterMut<'a, Export>;

    fn into_iter(self) -> Self::IntoIter {
        self.exports.iter_mut()
    }
}

impl Extend<Export> for ExportList {
    fn extend<T: IntoIterator<Item = Export>>(&mut self, iter: T) {
        for export in iter {
            self.add(export);
        }
    }
}

impl FromIterator<Export> for ExportList {
    fn from_iter<I: IntoIterator<Item = Export>>(iter: I) -> Self {
        let mut list = Self::new();
        list.extend(iter);
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_new() {
        let export = Export::new(0x1000, "TestExport");
        assert_eq!(export.address, 0x1000);
        assert_eq!(export.name, "TestExport");
        assert!(!export.is_forwarded());
    }

    #[test]
    fn test_export_forwarded() {
        let export = Export::forwarded(0x1000, "Forwarder", "OTHERDLL.Function");
        assert!(export.is_forwarded());
        assert_eq!(export.forwarded_name, Some("OTHERDLL.Function".to_string()));
    }

    #[test]
    fn test_export_by_ordinal() {
        let export = Export::by_ordinal(0x1000, 42);
        assert!(export.is_ordinal());
        assert_eq!(export.ordinal, Some(42));
        assert_eq!(export.name, "Ordinal_42");
    }

    #[test]
    fn test_export_rebase() {
        let mut export = Export::new(0x1000, "Test");
        export.rebase(0x100);
        assert_eq!(export.address, 0x1100);
    }

    #[test]
    fn test_export_list_new() {
        let list = ExportList::new();
        assert!(list.is_empty());
    }

    #[test]
    fn test_export_list_add() {
        let mut list = ExportList::new();
        list.add(Export::new(0x1000, "Export1"));
        list.add(Export::new(0x2000, "Export2"));
        
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_export_list_find_by_address() {
        let mut list = ExportList::new();
        list.add(Export::new(0x1000, "Export1"));
        list.add(Export::new(0x2000, "Export2"));
        
        let found = list.find_by_address(0x1000);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "Export1");
    }

    #[test]
    fn test_export_list_find_by_name() {
        let mut list = ExportList::new();
        list.add(Export::new(0x1000, "Export1"));
        list.add(Export::new(0x2000, "Export2"));
        
        let found = list.find_by_name("Export2");
        assert!(found.is_some());
        assert_eq!(found.unwrap().address, 0x2000);
    }

    #[test]
    fn test_export_list_find_by_api_type() {
        let mut list = ExportList::new();
        let mut export = Export::new(0x1000, "VMProtectBegin");
        export.set_api_type(ApiType::Begin);
        list.add(export);
        
        let found = list.find_by_api_type(ApiType::Begin);
        assert!(found.is_some());
    }

    #[test]
    fn test_export_list_get_address_by_type() {
        let mut list = ExportList::new();
        let mut export = Export::new(0x1000, "VMProtectBegin");
        export.set_api_type(ApiType::Begin);
        list.add(export);
        
        assert_eq!(list.get_address_by_type(ApiType::Begin), Some(0x1000));
        assert_eq!(list.get_address_by_type(ApiType::End), None);
    }

    #[test]
    fn test_export_list_rebase() {
        let mut list = ExportList::new();
        list.add(Export::new(0x1000, "Export1"));
        list.add(Export::new(0x2000, "Export2"));
        
        list.rebase(0x100);
        
        assert!(list.find_by_address(0x1100).is_some());
        assert!(list.find_by_address(0x2100).is_some());
    }

    #[test]
    fn test_export_list_forwarded_exports() {
        let mut list = ExportList::new();
        list.add(Export::new(0x1000, "NormalExport"));
        list.add(Export::forwarded(0x2000, "ForwardedExport", "OTHERDLL.Func"));
        
        let forwarded = list.forwarded_exports();
        assert_eq!(forwarded.len(), 1);
        assert_eq!(forwarded[0].name, "ForwardedExport");
    }

    #[test]
    fn test_export_list_is_equal() {
        let mut list1 = ExportList::new();
        list1.add(Export::new(0x1000, "Export1"));
        
        let mut list2 = ExportList::new();
        list2.add(Export::new(0x1000, "Export1"));
        
        assert!(list1.is_equal(&list2));
        
        list2.add(Export::new(0x2000, "Export2"));
        assert!(!list1.is_equal(&list2));
    }

    #[test]
    fn test_export_list_remove_by_address() {
        let mut list = ExportList::new();
        list.add(Export::new(0x1000, "Export1"));
        list.add(Export::new(0x2000, "Export2"));
        
        assert!(list.remove_by_address(0x1000));
        assert_eq!(list.len(), 1);
        assert!(!list.remove_by_address(0x9999));
    }

    #[test]
    fn test_export_list_sort_by_address() {
        let mut list = ExportList::new();
        list.add(Export::new(0x3000, "Export3"));
        list.add(Export::new(0x1000, "Export1"));
        list.add(Export::new(0x2000, "Export2"));
        
        list.sort_by_address();
        
        assert_eq!(list.get(0).unwrap().address, 0x1000);
        assert_eq!(list.get(1).unwrap().address, 0x2000);
        assert_eq!(list.get(2).unwrap().address, 0x3000);
    }
}
