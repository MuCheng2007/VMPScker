//! Compiler internal helper functions
//! Translated from core/files/compiler_func.h/cc

use crate::core::types::{CompilerFunctionType, CompilerFunctionOptions, ApiType, RuntimeOptions, CompileFlags};
use std::collections::BTreeMap;

/// Compiler-generated helper function entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilerFunction {
    /// Function address
    pub address: u64,
    /// Function type
    pub func_type: CompilerFunctionType,
    /// Associated values (context-dependent)
    pub values: Vec<u64>,
    /// Function options
    pub options: CompilerFunctionOptions,
}

impl CompilerFunction {
    /// Create a new compiler function
    pub fn new(address: u64, func_type: CompilerFunctionType) -> Self {
        Self {
            address,
            func_type,
            values: Vec::new(),
            options: CompilerFunctionOptions::NONE,
        }
    }

    /// Add a value
    pub fn add_value(&mut self, value: u64) {
        self.values.push(value);
    }

    /// Get value at index
    pub fn get_value(&self, index: usize) -> Option<u64> {
        self.values.get(index).copied()
    }

    /// Get value at index (default to 0)
    pub fn value_or_default(&self, index: usize) -> u64 {
        self.get_value(index).unwrap_or(0)
    }

    /// Include an option
    pub fn include_option(&mut self, option: CompilerFunctionOptions) {
        self.options.insert(option);
    }

    /// Exclude an option
    pub fn exclude_option(&mut self, option: CompilerFunctionOptions) {
        self.options.remove(option);
    }

    /// Check if has option
    pub fn has_option(&self, option: CompilerFunctionOptions) -> bool {
        self.options.contains(option)
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

    /// Get runtime options based on function type and values
    pub fn get_runtime_options(&self) -> RuntimeOptions {
        if self.func_type == CompilerFunctionType::DllFunctionCall && self.has_option(CompilerFunctionOptions::USED) {
            if let Some(api_value) = self.get_value(0) {
                let api_type = unsafe { std::mem::transmute((api_value & 0xff) as u8) };
                return crate::core::types::get_api_runtime_options(api_type);
            }
        }
        RuntimeOptions::NONE
    }

    /// Get SDK options (compile flags) based on function type and values
    pub fn get_sdk_options(&self) -> CompileFlags {
        if self.func_type == CompilerFunctionType::DllFunctionCall && self.has_option(CompilerFunctionOptions::USED) {
            if let Some(api_value) = self.get_value(0) {
                let api_type = unsafe { std::mem::transmute((api_value & 0xff) as u8) };
                return crate::core::types::get_api_sdk_options(api_type);
            }
        }
        CompileFlags::NONE
    }
}

impl Default for CompilerFunction {
    fn default() -> Self {
        Self {
            address: 0,
            func_type: CompilerFunctionType::None,
            values: Vec::new(),
            options: CompilerFunctionOptions::NONE,
        }
    }
}

/// List of compiler functions
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompilerFunctionList {
    functions: Vec<CompilerFunction>,
    address_map: BTreeMap<u64, usize>, // Sorted map for efficient lookup
}

impl CompilerFunctionList {
    /// Create a new empty list
    pub fn new() -> Self {
        Self {
            functions: Vec::new(),
            address_map: BTreeMap::new(),
        }
    }

    /// Create with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            functions: Vec::with_capacity(capacity),
            address_map: BTreeMap::new(),
        }
    }

    /// Add a function
    pub fn add(&mut self, func_type: CompilerFunctionType, address: u64) -> &CompilerFunction {
        let idx = self.functions.len();
        self.functions.push(CompilerFunction::new(address, func_type));
        self.address_map.insert(address, idx);
        &self.functions[idx]
    }

    /// Add a function object
    pub fn add_function(&mut self, function: CompilerFunction) -> &CompilerFunction {
        let idx = self.functions.len();
        let address = function.address;
        self.functions.push(function);
        self.address_map.insert(address, idx);
        &self.functions[idx]
    }

    /// Get function by index
    pub fn get(&self, index: usize) -> Option<&CompilerFunction> {
        self.functions.get(index)
    }

    /// Get mutable function by index
    pub fn get_mut(&mut self, index: usize) -> Option<&mut CompilerFunction> {
        self.functions.get_mut(index)
    }

    /// Find function by exact address
    pub fn find_by_address(&self, address: u64) -> Option<&CompilerFunction> {
        self.address_map.get(&address).and_then(|&idx| self.functions.get(idx))
    }

    /// Find function by exact address (mutable)
    pub fn find_by_address_mut(&mut self, address: u64) -> Option<&mut CompilerFunction> {
        self.address_map.get(&address).copied().and_then(move |idx| self.functions.get_mut(idx))
    }

    /// Find function at or before address (nearest lower or equal)
    pub fn find_by_lower_address(&self, address: u64) -> Option<&CompilerFunction> {
        // Get the last entry with key <= address
        self.address_map
            .range(..=address)
            .next_back()
            .and_then(|(&addr, &idx)| self.functions.get(idx).filter(|_| addr <= address))
    }

    /// Get register base value at address
    /// Looks backward for cfBaseRegister entries
    pub fn get_register_value(&self, address: u64, register: u64) -> Option<u64> {
        // Iterate backward from address
        for (&func_addr, &idx) in self.address_map.range(..=address).rev() {
            let func = &self.functions[idx];
            if func.func_type == CompilerFunctionType::BaseRegister {
                if func.value_or_default(0) == register {
                    return Some(func_addr + func.value_or_default(1));
                }
                break; // Found base register entry but for different register
            }
        }
        None
    }

    /// Get aggregate runtime options from all functions
    pub fn get_runtime_options(&self) -> RuntimeOptions {
        self.functions.iter().fold(RuntimeOptions::NONE, |acc, f| {
            acc | f.get_runtime_options()
        })
    }

    /// Get aggregate SDK options from all functions
    pub fn get_sdk_options(&self) -> CompileFlags {
        self.functions.iter().fold(CompileFlags::NONE, |acc, f| {
            acc | f.get_sdk_options()
        })
    }

    /// Get number of functions
    pub fn len(&self) -> usize {
        self.functions.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    /// Clear all functions
    pub fn clear(&mut self) {
        self.functions.clear();
        self.address_map.clear();
    }

    /// Rebase all functions
    pub fn rebase(&mut self, delta: u64) {
        for func in &mut self.functions {
            func.rebase(delta);
        }
        // Rebuild the map since addresses changed
        self.address_map.clear();
        for (idx, func) in self.functions.iter().enumerate() {
            self.address_map.insert(func.address, idx);
        }
    }

    /// Get all functions
    pub fn functions(&self) -> &[CompilerFunction] {
        &self.functions
    }

    /// Get mutable functions
    pub fn functions_mut(&mut self) -> &mut Vec<CompilerFunction> {
        &mut self.functions
    }

    /// Iterate over functions
    pub fn iter(&self) -> std::slice::Iter<CompilerFunction> {
        self.functions.iter()
    }

    /// Iterate mutably over functions
    pub fn iter_mut(&mut self) -> std::slice::IterMut<CompilerFunction> {
        self.functions.iter_mut()
    }

    /// Find functions by type
    pub fn find_by_type(&self, func_type: CompilerFunctionType) -> Vec<&CompilerFunction> {
        self.functions.iter().filter(|f| f.func_type == func_type).collect()
    }

    /// Remove function at address
    pub fn remove_by_address(&mut self, address: u64) -> bool {
        if let Some(&idx) = self.address_map.get(&address) {
            self.functions.remove(idx);
            // Rebuild map since indices shifted
            self.address_map.clear();
            for (i, func) in self.functions.iter().enumerate() {
                self.address_map.insert(func.address, i);
            }
            true
        } else {
            false
        }
    }

    /// Get addresses as a vector
    pub fn addresses(&self) -> Vec<u64> {
        self.functions.iter().map(|f| f.address).collect()
    }

    /// Merge another function list into this one
    pub fn merge(&mut self, other: &CompilerFunctionList) {
        for func in &other.functions {
            if !self.address_map.contains_key(&func.address) {
                self.add_function(func.clone());
            }
        }
    }

    /// Sort functions by address
    pub fn sort_by_address(&mut self) {
        self.functions.sort_by_key(|f| f.address);
        // Rebuild map
        self.address_map.clear();
        for (idx, func) in self.functions.iter().enumerate() {
            self.address_map.insert(func.address, idx);
        }
    }
}

impl IntoIterator for CompilerFunctionList {
    type Item = CompilerFunction;
    type IntoIter = std::vec::IntoIter<CompilerFunction>;

    fn into_iter(self) -> Self::IntoIter {
        self.functions.into_iter()
    }
}

impl<'a> IntoIterator for &'a CompilerFunctionList {
    type Item = &'a CompilerFunction;
    type IntoIter = std::slice::Iter<'a, CompilerFunction>;

    fn into_iter(self) -> Self::IntoIter {
        self.functions.iter()
    }
}

impl<'a> IntoIterator for &'a mut CompilerFunctionList {
    type Item = &'a mut CompilerFunction;
    type IntoIter = std::slice::IterMut<'a, CompilerFunction>;

    fn into_iter(self) -> Self::IntoIter {
        self.functions.iter_mut()
    }
}

impl Extend<CompilerFunction> for CompilerFunctionList {
    fn extend<T: IntoIterator<Item = CompilerFunction>>(&mut self, iter: T) {
        for func in iter {
            self.add_function(func);
        }
    }
}

impl FromIterator<CompilerFunction> for CompilerFunctionList {
    fn from_iter<I: IntoIterator<Item = CompilerFunction>>(iter: I) -> Self {
        let mut list = Self::new();
        list.extend(iter);
        list
    }
}

/// Builder for constructing compiler function lists
pub struct CompilerFunctionListBuilder {
    functions: Vec<CompilerFunction>,
}

impl CompilerFunctionListBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self { functions: Vec::new() }
    }

    /// Add a function
    pub fn add(mut self, func_type: CompilerFunctionType, address: u64) -> Self {
        self.functions.push(CompilerFunction::new(address, func_type));
        self
    }

    /// Add with values
    pub fn add_with_values(mut self, func_type: CompilerFunctionType, address: u64, values: &[u64]) -> Self {
        let mut func = CompilerFunction::new(address, func_type);
        for &v in values {
            func.add_value(v);
        }
        self.functions.push(func);
        self
    }

    /// Build the list
    pub fn build(self) -> CompilerFunctionList {
        let mut list = CompilerFunctionList::with_capacity(self.functions.len());
        for func in self.functions {
            list.add_function(func);
        }
        list
    }
}

impl Default for CompilerFunctionListBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compiler_function_new() {
        let func = CompilerFunction::new(0x1000, CompilerFunctionType::BaseRegister);
        assert_eq!(func.address, 0x1000);
        assert_eq!(func.func_type, CompilerFunctionType::BaseRegister);
    }

    #[test]
    fn test_compiler_function_values() {
        let mut func = CompilerFunction::new(0x1000, CompilerFunctionType::DllFunctionCall);
        func.add_value(0x1234);
        func.add_value(0x5678);
        
        assert_eq!(func.get_value(0), Some(0x1234));
        assert_eq!(func.get_value(1), Some(0x5678));
        assert_eq!(func.get_value(2), None);
        assert_eq!(func.value_or_default(2), 0);
    }

    #[test]
    fn test_compiler_function_options() {
        let mut func = CompilerFunction::new(0x1000, CompilerFunctionType::DllFunctionCall);
        func.include_option(CompilerFunctionOptions::USED);
        
        assert!(func.has_option(CompilerFunctionOptions::USED));
        assert!(!func.has_option(CompilerFunctionOptions::NO_RETURN));
    }

    #[test]
    fn test_compiler_function_rebase() {
        let mut func = CompilerFunction::new(0x1000, CompilerFunctionType::BaseRegister);
        func.rebase(0x100);
        assert_eq!(func.address, 0x1100);
    }

    #[test]
    fn test_compiler_function_list_add() {
        let mut list = CompilerFunctionList::new();
        list.add(CompilerFunctionType::BaseRegister, 0x1000);
        list.add(CompilerFunctionType::DllFunctionCall, 0x2000);
        
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_compiler_function_list_find_by_address() {
        let mut list = CompilerFunctionList::new();
        list.add(CompilerFunctionType::BaseRegister, 0x1000);
        list.add(CompilerFunctionType::DllFunctionCall, 0x2000);
        
        let found = list.find_by_address(0x1000);
        assert!(found.is_some());
        assert_eq!(found.unwrap().func_type, CompilerFunctionType::BaseRegister);
    }

    #[test]
    fn test_compiler_function_list_find_by_lower_address() {
        let mut list = CompilerFunctionList::new();
        list.add(CompilerFunctionType::BaseRegister, 0x1000);
        list.add(CompilerFunctionType::DllFunctionCall, 0x2000);
        
        let found = list.find_by_lower_address(0x1500);
        assert!(found.is_some());
        assert_eq!(found.unwrap().address, 0x1000);
        
        let found = list.find_by_lower_address(0x2500);
        assert!(found.is_some());
        assert_eq!(found.unwrap().address, 0x2000);
    }

    #[test]
    fn test_get_register_value() {
        let mut list = CompilerFunctionList::new();
        let mut func = CompilerFunction::new(0x1000, CompilerFunctionType::BaseRegister);
        func.add_value(0); // Register 0 (e.g., EAX)
        func.add_value(0x100); // Offset
        list.add_function(func);
        
        let value = list.get_register_value(0x1500, 0);
        assert_eq!(value, Some(0x1100)); // 0x1000 + 0x100
    }

    #[test]
    fn test_compiler_function_list_rebase() {
        let mut list = CompilerFunctionList::new();
        list.add(CompilerFunctionType::BaseRegister, 0x1000);
        list.add(CompilerFunctionType::DllFunctionCall, 0x2000);
        
        list.rebase(0x100);
        
        assert!(list.find_by_address(0x1100).is_some());
        assert!(list.find_by_address(0x2100).is_some());
    }

    #[test]
    fn test_find_by_type() {
        let mut list = CompilerFunctionList::new();
        list.add(CompilerFunctionType::BaseRegister, 0x1000);
        list.add(CompilerFunctionType::BaseRegister, 0x2000);
        list.add(CompilerFunctionType::DllFunctionCall, 0x3000);
        
        let base_regs = list.find_by_type(CompilerFunctionType::BaseRegister);
        assert_eq!(base_regs.len(), 2);
    }

    #[test]
    fn test_builder() {
        let list = CompilerFunctionListBuilder::new()
            .add(CompilerFunctionType::BaseRegister, 0x1000)
            .add_with_values(CompilerFunctionType::DllFunctionCall, 0x2000, &[0x1234, 0x5678])
            .build();
        
        assert_eq!(list.len(), 2);
        let func = list.find_by_address(0x2000).unwrap();
        assert_eq!(func.value_or_default(0), 0x1234);
    }
}
