//! Executable fixups (position-dependent code) management
//! Translated from core/files/fixups.h/cc

use crate::core::types::{FixupType, OperandSize};
use std::collections::{BTreeMap, HashMap};

/// Fixup entry for position-dependent code
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fixup {
    /// Fixup address
    pub address: u64,
    /// Fixup type
    pub fixup_type: FixupType,
    /// Operand size
    pub size: OperandSize,
    /// Deleted flag
    pub deleted: bool,
}

impl Fixup {
    /// Create a new fixup
    pub fn new(address: u64, fixup_type: FixupType, size: OperandSize) -> Self {
        Self {
            address,
            fixup_type,
            size,
            deleted: false,
        }
    }

    /// Get size in bytes
    pub fn size_in_bytes(&self) -> usize {
        self.size.size_in_bytes()
    }

    /// Get next address after this fixup
    pub fn next_address(&self) -> u64 {
        self.address + self.size.size_in_bytes() as u64
    }

    /// Apply fixup to data
    pub fn apply(&self, data: &mut [u8], old_base: u64, new_base: u64) -> Result<(), String> {
        let offset = self.address as usize;
        let size = self.size.size_in_bytes();
        
        if offset + size > data.len() {
            return Err(format!("Fixup address 0x{:X} out of bounds", self.address));
        }

        let delta = new_base as i64 - old_base as i64;
        
        match self.fixup_type {
            FixupType::Absolute => {
                let value = self.parse_value(&data[offset..offset + size])?;
                let new_value = (value as i64 + delta) as u64;
                self.write_value(&mut data[offset..offset + size], new_value)?;
            }
            FixupType::HighLow => {
                let value = self.parse_value(&data[offset..offset + size])?;
                let new_value = (value as i64 + delta) as u64;
                self.write_value(&mut data[offset..offset + size], new_value)?;
            }
            FixupType::Dir64 => {
                let value = self.parse_value(&data[offset..offset + size])?;
                let new_value = (value as i64 + delta) as u64;
                self.write_value(&mut data[offset..offset + size], new_value)?;
            }
            _ => {
                // Other types not yet implemented
                return Err(format!("Fixup type {:?} not implemented", self.fixup_type));
            }
        }

        Ok(())
    }

    /// Parse value from data
    pub fn parse_value(&self, data: &[u8]) -> Result<u64, String> {
        match self.size {
            OperandSize::Byte => {
                if data.len() < 1 {
                    return Err("Not enough data for byte".to_string());
                }
                Ok(data[0] as u64)
            }
            OperandSize::Word => {
                if data.len() < 2 {
                    return Err("Not enough data for word".to_string());
                }
                Ok(u16::from_le_bytes([data[0], data[1]]) as u64)
            }
            OperandSize::DWord => {
                if data.len() < 4 {
                    return Err("Not enough data for dword".to_string());
                }
                Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64)
            }
            OperandSize::QWord => {
                if data.len() < 8 {
                    return Err("Not enough data for qword".to_string());
                }
                Ok(u64::from_le_bytes([
                    data[0], data[1], data[2], data[3],
                    data[4], data[5], data[6], data[7]
                ]))
            }
            _ => Err(format!("Unsupported operand size: {:?}", self.size)),
        }
    }

    /// Write value to data
    pub fn write_value(&self, data: &mut [u8], value: u64) -> Result<(), String> {
        match self.size {
            OperandSize::Byte => {
                if data.len() < 1 {
                    return Err("Not enough data for byte".to_string());
                }
                data[0] = value as u8;
            }
            OperandSize::Word => {
                if data.len() < 2 {
                    return Err("Not enough data for word".to_string());
                }
                let bytes = (value as u16).to_le_bytes();
                data[0] = bytes[0];
                data[1] = bytes[1];
            }
            OperandSize::DWord => {
                if data.len() < 4 {
                    return Err("Not enough data for dword".to_string());
                }
                let bytes = (value as u32).to_le_bytes();
                data[0] = bytes[0];
                data[1] = bytes[1];
                data[2] = bytes[2];
                data[3] = bytes[3];
            }
            OperandSize::QWord => {
                if data.len() < 8 {
                    return Err("Not enough data for qword".to_string());
                }
                let bytes = value.to_le_bytes();
                data[0] = bytes[0];
                data[1] = bytes[1];
                data[2] = bytes[2];
                data[3] = bytes[3];
                data[4] = bytes[4];
                data[5] = bytes[5];
                data[6] = bytes[6];
                data[7] = bytes[7];
            }
            _ => return Err(format!("Unsupported operand size: {:?}", self.size)),
        }
        Ok(())
    }

    /// Clone this fixup
    pub fn clone_fixup(&self) -> Self {
        Self {
            address: self.address,
            fixup_type: self.fixup_type,
            size: self.size,
            deleted: self.deleted,
        }
    }

    /// Check if this fixup overlaps with another
    pub fn overlaps(&self, other: &Fixup) -> bool {
        let self_end = self.next_address();
        let other_end = other.next_address();
        self.address < other_end && other.address < self_end
    }

    /// Get fixup description
    pub fn description(&self) -> String {
        format!(
            "Fixup at 0x{:X}: {:?} (size: {:?})",
            self.address, self.fixup_type, self.size
        )
    }

    /// Mark as deleted
    pub fn mark_deleted(&mut self) {
        self.deleted = true;
    }

    /// Check if deleted
    pub fn is_deleted(&self) -> bool {
        self.deleted
    }

    /// Rebase address
    pub fn rebase(&mut self, delta: u64) {
        self.address = self.address.wrapping_add(delta);
    }

    /// Create a rebased copy
    pub fn rebased(&self, delta: u64) -> Self {
        let mut copy = *self;
        copy.rebase(delta);
        copy
    }
}

impl Default for Fixup {
    fn default() -> Self {
        Self {
            address: 0,
            fixup_type: FixupType::Unknown,
            size: OperandSize::DWord,
            deleted: false,
        }
    }
}

/// List of fixups
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FixupList {
    fixups: Vec<Fixup>,
    address_map: BTreeMap<u64, usize>,
}

impl FixupList {
    /// Create a new empty fixup list
    pub fn new() -> Self {
        Self {
            fixups: Vec::new(),
            address_map: BTreeMap::new(),
        }
    }

    /// Create with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            fixups: Vec::with_capacity(capacity),
            address_map: BTreeMap::new(),
        }
    }

    /// Add a fixup
    pub fn add(&mut self, fixup: Fixup) -> &Fixup {
        let idx = self.fixups.len();
        let address = fixup.address;
        self.fixups.push(fixup);
        if address != 0 {
            self.address_map.insert(address, idx);
        }
        &self.fixups[idx]
    }

    /// Add a new fixup
    pub fn add_new(&mut self, address: u64, fixup_type: FixupType, size: OperandSize) -> &Fixup {
        self.add(Fixup::new(address, fixup_type, size))
    }

    /// Get fixup by index
    pub fn get(&self, index: usize) -> Option<&Fixup> {
        self.fixups.get(index)
    }

    /// Get mutable fixup by index
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Fixup> {
        self.fixups.get_mut(index)
    }

    /// Find fixup by exact address
    pub fn find_by_address(&self, address: u64) -> Option<&Fixup> {
        self.address_map.get(&address).and_then(|&idx| self.fixups.get(idx))
    }

    /// Find fixup by exact address (mutable)
    pub fn find_by_address_mut(&mut self, address: u64) -> Option<&mut Fixup> {
        self.address_map.get(&address).copied().and_then(move |idx| self.fixups.get_mut(idx))
    }

    /// Find fixup containing address (near address)
    pub fn find_by_near_address(&self, address: u64) -> Option<&Fixup> {
        if self.address_map.is_empty() {
            return None;
        }

        // Get the last entry with key <= address
        self.address_map
            .range(..=address)
            .next_back()
            .and_then(|(&addr, &idx)| {
                let fixup = &self.fixups[idx];
                if addr <= address && fixup.next_address() > address {
                    Some(fixup)
                } else {
                    None
                }
            })
    }

    /// Get fixup by near address (within tolerance bytes)
    pub fn get_by_near_address(&self, address: u64, tolerance: u64) -> Option<&Fixup> {
        self.fixups.iter().find(|f| {
            let diff = if f.address > address {
                f.address - address
            } else {
                address - f.address
            };
            diff <= tolerance
        })
    }

    /// Get number of fixups
    pub fn len(&self) -> usize {
        self.fixups.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.fixups.is_empty()
    }

    /// Clear all fixups
    pub fn clear(&mut self) {
        self.fixups.clear();
        self.address_map.clear();
    }

    /// Remove deleted fixups and rebuild map
    pub fn pack(&mut self) {
        self.fixups.retain(|f| !f.deleted);
        self.rebuild_map();
    }

    /// Rebase all fixups
    pub fn rebase(&mut self, delta: u64) {
        for fixup in &mut self.fixups {
            fixup.rebase(delta);
        }
        self.rebuild_map();
    }

    /// Rebuild address map
    fn rebuild_map(&mut self) {
        self.address_map.clear();
        for (idx, fixup) in self.fixups.iter().enumerate() {
            if fixup.address != 0 {
                self.address_map.insert(fixup.address, idx);
            }
        }
    }

    /// Get all fixups
    pub fn fixups(&self) -> &[Fixup] {
        &self.fixups
    }

    /// Get mutable fixups
    pub fn fixups_mut(&mut self) -> &mut Vec<Fixup> {
        &mut self.fixups
    }

    /// Iterate over fixups
    pub fn iter(&self) -> std::slice::Iter<Fixup> {
        self.fixups.iter()
    }

    /// Iterate mutably over fixups
    pub fn iter_mut(&mut self) -> std::slice::IterMut<Fixup> {
        self.fixups.iter_mut()
    }

    /// Get addresses as a vector
    pub fn addresses(&self) -> Vec<u64> {
        self.fixups.iter().map(|f| f.address).collect()
    }

    /// Merge another fixup list
    pub fn merge(&mut self, other: &FixupList) {
        for fixup in &other.fixups {
            if !self.address_map.contains_key(&fixup.address) {
                self.add(*fixup);
            }
        }
    }

    /// Remove fixup by address
    pub fn remove_by_address(&mut self, address: u64) -> bool {
        if let Some(&idx) = self.address_map.get(&address) {
            self.fixups.remove(idx);
            self.rebuild_map();
            true
        } else {
            false
        }
    }

    /// Remove fixups in range
    pub fn remove_range(&mut self, start: u64, end: u64) -> Vec<Fixup> {
        let mut removed = Vec::new();
        self.fixups.retain(|f| {
            if f.address >= start && f.address < end {
                removed.push(*f);
                false
            } else {
                true
            }
        });
        self.rebuild_map();
        removed
    }

    /// Mark fixup as deleted
    pub fn mark_deleted(&mut self, address: u64) -> bool {
        if let Some(fixup) = self.find_by_address_mut(address) {
            fixup.mark_deleted();
            true
        } else {
            false
        }
    }

    /// Clear deleted fixups
    pub fn clear_deleted(&mut self) {
        self.fixups.retain(|f| !f.is_deleted());
        self.rebuild_map();
    }

    /// Find fixups by type
    pub fn find_by_type(&self, fixup_type: FixupType) -> Vec<&Fixup> {
        self.fixups.iter().filter(|f| f.fixup_type == fixup_type).collect()
    }

    /// Get count of non-deleted fixups
    pub fn active_count(&self) -> usize {
        self.fixups.iter().filter(|f| !f.deleted).count()
    }

    /// Apply all fixups to data
    pub fn apply_all(&self, data: &mut [u8], old_base: u64, new_base: u64) -> Result<(), String> {
        for fixup in &self.fixups {
            if !fixup.is_deleted() {
                fixup.apply(data, old_base, new_base)?;
            }
        }
        Ok(())
    }

    /// Find fixups in range
    pub fn find_in_range(&self, start: u64, end: u64) -> Vec<&Fixup> {
        self.fixups.iter()
            .filter(|f| f.address >= start && f.address < end)
            .collect()
    }

    /// Get statistics
    pub fn statistics(&self) -> FixupStatistics {
        let mut stats = FixupStatistics::default();
        stats.total_count = self.fixups.len();

        for fixup in &self.fixups {
            match fixup.fixup_type {
                FixupType::Absolute => stats.absolute_count += 1,
                FixupType::HighLow => stats.high_low_count += 1,
                FixupType::Dir64 => stats.dir64_count += 1,
                FixupType::High => stats.high_count += 1,
                FixupType::Low => stats.low_count += 1,
                FixupType::HighAdj => stats.high_adj_count += 1,
                _ => stats.other_count += 1,
            }

            if fixup.is_deleted() {
                stats.deleted_count += 1;
            }
        }

        stats
    }

    /// Validate all fixups
    pub fn validate(&self, data_size: usize) -> Vec<FixupValidationError> {
        let mut errors = Vec::new();

        for fixup in &self.fixups {
            let offset = fixup.address as usize;
            let size = fixup.size.size_in_bytes();

            if offset + size > data_size {
                errors.push(FixupValidationError {
                    address: fixup.address,
                    error: format!("Fixup extends beyond data (offset: 0x{:X}, size: {}, data_size: 0x{:X})",
                        offset, size, data_size),
                });
            }

            // Check for overlapping fixups
            for other in &self.fixups {
                if other.address != fixup.address && fixup.overlaps(other) {
                    errors.push(FixupValidationError {
                        address: fixup.address,
                        error: format!("Overlapping fixup at 0x{:X}", other.address),
                    });
                }
            }
        }

        errors
    }

    /// Dump fixup list for debugging
    pub fn dump(&self) -> String {
        let mut output = String::from("Fixup List:\n");
        output.push_str(&format!("Total fixups: {}\n", self.fixups.len()));
        output.push_str("Fixups:\n");

        for (i, fixup) in self.fixups.iter().enumerate() {
            let status = if fixup.is_deleted() { " [DELETED]" } else { "" };
            output.push_str(&format!(
                "  [{}] 0x{:016X}: {:?} ({:?}){}\n",
                i, fixup.address, fixup.fixup_type, fixup.size, status
            ));
        }

        output
    }
}

/// Fixup statistics
#[derive(Debug, Default, Clone)]
pub struct FixupStatistics {
    pub total_count: usize,
    pub absolute_count: usize,
    pub high_low_count: usize,
    pub dir64_count: usize,
    pub high_count: usize,
    pub low_count: usize,
    pub high_adj_count: usize,
    pub other_count: usize,
    pub deleted_count: usize,
}

/// Fixup validation error
#[derive(Debug, Clone)]
pub struct FixupValidationError {
    pub address: u64,
    pub error: String,
}

/// Symbol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolType {
    Function,
    Data,
    Section,
    External,
    Unknown,
}

impl SymbolType {
    /// Get symbol type description
    pub fn description(&self) -> &'static str {
        match self {
            Self::Function => "Function",
            Self::Data => "Data",
            Self::Section => "Section",
            Self::External => "External",
            Self::Unknown => "Unknown",
        }
    }
}

/// Symbol information
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub symbol_type: SymbolType,
    pub section_index: u16,
}

impl Symbol {
    /// Create a new symbol
    pub fn new(name: String, address: u64, size: u64, symbol_type: SymbolType) -> Self {
        Self {
            name,
            address,
            size,
            symbol_type,
            section_index: 0,
        }
    }

    /// Set section index
    pub fn with_section_index(mut self, index: u16) -> Self {
        self.section_index = index;
        self
    }

    /// Get end address
    pub fn end_address(&self) -> u64 {
        self.address + self.size
    }

    /// Check if contains address
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.address && addr < self.end_address()
    }
}

/// Symbol table for managing symbols
#[derive(Debug, Clone)]
pub struct SymbolTable {
    symbols: Vec<Symbol>,
    by_name: HashMap<String, usize>,
    by_address: BTreeMap<u64, usize>,
}

impl SymbolTable {
    /// Create a new empty symbol table
    pub fn new() -> Self {
        Self {
            symbols: Vec::new(),
            by_name: HashMap::new(),
            by_address: BTreeMap::new(),
        }
    }

    /// Add a symbol
    pub fn add(&mut self, symbol: Symbol) {
        let index = self.symbols.len();
        self.by_name.insert(symbol.name.clone(), index);
        self.by_address.insert(symbol.address, index);
        self.symbols.push(symbol);
    }

    /// Find symbol by name
    pub fn find_by_name(&self, name: &str) -> Option<&Symbol> {
        self.by_name.get(name).map(|&idx| &self.symbols[idx])
    }

    /// Find symbol by address
    pub fn find_by_address(&self, address: u64) -> Option<&Symbol> {
        self.by_address.get(&address).map(|&idx| &self.symbols[idx])
    }

    /// Find nearest symbol to address
    pub fn find_nearest(&self, address: u64) -> Option<&Symbol> {
        // Find the largest address <= given address
        let candidates: Vec<_> = self.by_address
            .range(..=address)
            .map(|(_, &idx)| &self.symbols[idx])
            .collect();

        candidates.last().copied()
    }

    /// Find symbol containing address
    pub fn find_containing(&self, address: u64) -> Option<&Symbol> {
        self.symbols.iter().find(|s| s.contains(address))
    }

    /// Find symbols by type
    pub fn find_by_type(&self, symbol_type: SymbolType) -> Vec<&Symbol> {
        self.symbols.iter().filter(|s| s.symbol_type == symbol_type).collect()
    }

    /// Get all symbols
    pub fn symbols(&self) -> &[Symbol] {
        &self.symbols
    }

    /// Get symbol count
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Clear all symbols
    pub fn clear(&mut self) {
        self.symbols.clear();
        self.by_name.clear();
        self.by_address.clear();
    }

    /// Remove symbol by name
    pub fn remove_by_name(&mut self, name: &str) -> Option<Symbol> {
        if let Some(&index) = self.by_name.get(name) {
            let symbol = self.symbols.remove(index);
            self.rebuild_indices();
            Some(symbol)
        } else {
            None
        }
    }

    /// Remove symbol by address
    pub fn remove_by_address(&mut self, address: u64) -> Option<Symbol> {
        if let Some(&index) = self.by_address.get(&address) {
            let symbol = self.symbols.remove(index);
            self.rebuild_indices();
            Some(symbol)
        } else {
            None
        }
    }

    /// Rebuild indices after removal
    fn rebuild_indices(&mut self) {
        self.by_name.clear();
        self.by_address.clear();
        for (index, symbol) in self.symbols.iter().enumerate() {
            self.by_name.insert(symbol.name.clone(), index);
            self.by_address.insert(symbol.address, index);
        }
    }

    /// Merge with another symbol table
    pub fn merge(&mut self, other: &SymbolTable) {
        for symbol in &other.symbols {
            if self.find_by_name(&symbol.name).is_none() {
                self.add(symbol.clone());
            }
        }
    }

    /// Sort symbols by address
    pub fn sort_by_address(&mut self) {
        self.symbols.sort_by_key(|s| s.address);
        self.rebuild_indices();
    }

    /// Sort symbols by name
    pub fn sort_by_name(&mut self) {
        self.symbols.sort_by(|a, b| a.name.cmp(&b.name));
        self.rebuild_indices();
    }

    /// Get statistics
    pub fn statistics(&self) -> SymbolStatistics {
        let mut stats = SymbolStatistics::default();
        stats.total_count = self.symbols.len();

        for symbol in &self.symbols {
            match symbol.symbol_type {
                SymbolType::Function => stats.function_count += 1,
                SymbolType::Data => stats.data_count += 1,
                SymbolType::Section => stats.section_count += 1,
                SymbolType::External => stats.external_count += 1,
                SymbolType::Unknown => stats.unknown_count += 1,
            }
        }

        stats
    }

    /// Dump symbol table for debugging
    pub fn dump(&self) -> String {
        let mut output = String::from("Symbol Table:\n");
        output.push_str(&format!("Total symbols: {}\n", self.symbols.len()));
        output.push_str("Symbols:\n");

        for (i, symbol) in self.symbols.iter().enumerate() {
            output.push_str(&format!(
                "  [{}] 0x{:016X} - 0x{:016X} ({}) {}\n",
                i,
                symbol.address,
                symbol.end_address(),
                symbol.symbol_type.description(),
                symbol.name
            ));
        }

        output
    }
}

impl Default for SymbolTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Symbol statistics
#[derive(Debug, Default, Clone)]
pub struct SymbolStatistics {
    pub total_count: usize,
    pub function_count: usize,
    pub data_count: usize,
    pub section_count: usize,
    pub external_count: usize,
    pub unknown_count: usize,
}

/// Advanced relocation handler for different architectures
pub struct AdvancedRelocHandler;

impl AdvancedRelocHandler {
    /// Handle IA64 relocation
    pub fn handle_ia64_reloc(data: &mut [u8], offset: usize, reloc_type: u16, delta: i64) -> Result<(), String> {
        match reloc_type {
            0x0000 => Ok(()), // IMAGE_REL_BASED_IA64_IMM64
            0x0001 => { // IMAGE_REL_BASED_IA64_DIR64
                if offset + 8 > data.len() {
                    return Err("Not enough data for IA64_DIR64".to_string());
                }
                let value = u64::from_le_bytes([
                    data[offset], data[offset+1], data[offset+2], data[offset+3],
                    data[offset+4], data[offset+5], data[offset+6], data[offset+7]
                ]);
                let new_value = (value as i64 + delta) as u64;
                let bytes = new_value.to_le_bytes();
                data[offset..offset+8].copy_from_slice(&bytes);
                Ok(())
            }
            0x0002 => { // IMAGE_REL_BASED_IA64_DIR32
                if offset + 4 > data.len() {
                    return Err("Not enough data for IA64_DIR32".to_string());
                }
                let value = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
                let new_value = (value as i64 + delta) as u32;
                let bytes = new_value.to_le_bytes();
                data[offset..offset+4].copy_from_slice(&bytes);
                Ok(())
            }
            _ => Err(format!("Unsupported IA64 relocation type: {}", reloc_type)),
        }
    }

    /// Handle MIPS relocation
    pub fn handle_mips_reloc(data: &mut [u8], offset: usize, reloc_type: u16, delta: i64) -> Result<(), String> {
        match reloc_type {
            0x0005 => { // IMAGE_REL_BASED_MIPS_JMPADDR
                if offset + 4 > data.len() {
                    return Err("Not enough data for MIPS_JMPADDR".to_string());
                }
                // MIPS jump address is 26 bits, shifted left by 2
                let inst = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
                let addr = (inst & 0x03FFFFFF) << 2;
                let new_addr = ((addr as i64 + delta) >> 2) as u32;
                let new_inst = (inst & !0x03FFFFFF) | (new_addr & 0x03FFFFFF);
                let bytes = new_inst.to_le_bytes();
                data[offset..offset+4].copy_from_slice(&bytes);
                Ok(())
            }
            _ => Err(format!("Unsupported MIPS relocation type: {}", reloc_type)),
        }
    }

    /// Handle ARM relocation
    pub fn handle_arm_reloc(data: &mut [u8], offset: usize, reloc_type: u16, delta: i64) -> Result<(), String> {
        match reloc_type {
            0x0006 => { // IMAGE_REL_BASED_ARM_MOV32
                if offset + 4 > data.len() {
                    return Err("Not enough data for ARM_MOV32".to_string());
                }
                // ARM MOV32 is complex, involving multiple instructions
                // Simplified implementation
                let inst = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
                let value = (inst & 0xFFF) as i64 + delta;
                let new_inst = (inst & !0xFFF) | ((value as u32) & 0xFFF);
                let bytes = new_inst.to_le_bytes();
                data[offset..offset+4].copy_from_slice(&bytes);
                Ok(())
            }
            _ => Err(format!("Unsupported ARM relocation type: {}", reloc_type)),
        }
    }

    /// Handle ARM64 relocation
    pub fn handle_arm64_reloc(data: &mut [u8], offset: usize, reloc_type: u16, delta: i64) -> Result<(), String> {
        match reloc_type {
            0x000A => { // IMAGE_REL_BASED_ARM64_MOV32
                if offset + 4 > data.len() {
                    return Err("Not enough data for ARM64_MOV32".to_string());
                }
                let inst = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
                let value = (inst & 0xFFF) as i64 + delta;
                let new_inst = (inst & !0xFFF) | ((value as u32) & 0xFFF);
                let bytes = new_inst.to_le_bytes();
                data[offset..offset+4].copy_from_slice(&bytes);
                Ok(())
            }
            _ => Err(format!("Unsupported ARM64 relocation type: {}", reloc_type)),
        }
    }

    /// Handle RISC-V relocation
    pub fn handle_riscv_reloc(data: &mut [u8], offset: usize, reloc_type: u16, delta: i64) -> Result<(), String> {
        match reloc_type {
            0x0007 => { // IMAGE_REL_BASED_RISCV_HI20
                if offset + 4 > data.len() {
                    return Err("Not enough data for RISCV_HI20".to_string());
                }
                let inst = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
                let hi20 = ((inst >> 12) & 0xFFFFF) as i64;
                let new_hi20 = ((hi20 << 12) + delta) >> 12;
                let new_inst = (inst & !0xFFFFF000) | ((new_hi20 as u32) << 12);
                let bytes = new_inst.to_le_bytes();
                data[offset..offset+4].copy_from_slice(&bytes);
                Ok(())
            }
            _ => Err(format!("Unsupported RISC-V relocation type: {}", reloc_type)),
        }
    }
}

impl IntoIterator for FixupList {
    type Item = Fixup;
    type IntoIter = std::vec::IntoIter<Fixup>;

    fn into_iter(self) -> Self::IntoIter {
        self.fixups.into_iter()
    }
}

impl<'a> IntoIterator for &'a FixupList {
    type Item = &'a Fixup;
    type IntoIter = std::slice::Iter<'a, Fixup>;

    fn into_iter(self) -> Self::IntoIter {
        self.fixups.iter()
    }
}

impl<'a> IntoIterator for &'a mut FixupList {
    type Item = &'a mut Fixup;
    type IntoIter = std::slice::IterMut<'a, Fixup>;

    fn into_iter(self) -> Self::IntoIter {
        self.fixups.iter_mut()
    }
}

impl Extend<Fixup> for FixupList {
    fn extend<T: IntoIterator<Item = Fixup>>(&mut self, iter: T) {
        for fixup in iter {
            self.add(fixup);
        }
    }
}

impl FromIterator<Fixup> for FixupList {
    fn from_iter<I: IntoIterator<Item = Fixup>>(iter: I) -> Self {
        let mut list = Self::new();
        list.extend(iter);
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixup_new() {
        let fixup = Fixup::new(0x1000, FixupType::HighLow, OperandSize::DWord);
        assert_eq!(fixup.address, 0x1000);
        assert_eq!(fixup.fixup_type, FixupType::HighLow);
        assert_eq!(fixup.size, OperandSize::DWord);
        assert!(!fixup.deleted);
    }

    #[test]
    fn test_fixup_next_address() {
        let fixup = Fixup::new(0x1000, FixupType::HighLow, OperandSize::DWord);
        assert_eq!(fixup.next_address(), 0x1004);
    }

    #[test]
    fn test_fixup_rebase() {
        let mut fixup = Fixup::new(0x1000, FixupType::HighLow, OperandSize::DWord);
        fixup.rebase(0x100);
        assert_eq!(fixup.address, 0x1100);
    }

    #[test]
    fn test_fixup_list_add() {
        let mut list = FixupList::new();
        list.add(Fixup::new(0x1000, FixupType::HighLow, OperandSize::DWord));
        list.add(Fixup::new(0x1004, FixupType::HighLow, OperandSize::DWord));
        
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_fixup_list_find_by_address() {
        let mut list = FixupList::new();
        list.add(Fixup::new(0x1000, FixupType::HighLow, OperandSize::DWord));
        
        let found = list.find_by_address(0x1000);
        assert!(found.is_some());
        
        assert!(list.find_by_address(0x9999).is_none());
    }

    #[test]
    fn test_fixup_list_find_by_near_address() {
        let mut list = FixupList::new();
        list.add(Fixup::new(0x1000, FixupType::HighLow, OperandSize::DWord)); // 0x1000-0x1003
        list.add(Fixup::new(0x1004, FixupType::HighLow, OperandSize::DWord)); // 0x1004-0x1007
        
        let found = list.find_by_near_address(0x1002);
        assert!(found.is_some());
        assert_eq!(found.unwrap().address, 0x1000);
    }

    #[test]
    fn test_fixup_list_pack() {
        let mut list = FixupList::new();
        list.add(Fixup::new(0x1000, FixupType::HighLow, OperandSize::DWord));
        let mut f = Fixup::new(0x1004, FixupType::HighLow, OperandSize::DWord);
        f.mark_deleted();
        list.add(f);
        
        list.pack();
        
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn test_fixup_list_rebase() {
        let mut list = FixupList::new();
        list.add(Fixup::new(0x1000, FixupType::HighLow, OperandSize::DWord));
        
        list.rebase(0x100);
        
        assert!(list.find_by_address(0x1100).is_some());
    }

    #[test]
    fn test_fixup_list_active_count() {
        let mut list = FixupList::new();
        list.add(Fixup::new(0x1000, FixupType::HighLow, OperandSize::DWord));
        let mut f = Fixup::new(0x1004, FixupType::HighLow, OperandSize::DWord);
        f.mark_deleted();
        list.add(f);
        
        assert_eq!(list.active_count(), 1);
    }
}
