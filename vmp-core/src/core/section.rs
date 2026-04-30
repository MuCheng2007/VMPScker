//! Executable sections and load commands abstractions
//! Translated from core/files/sections.h/cc
//!
//! This module provides unified abstractions for:
//! - PE sections
//! - Mach-O segments/sections
//! - ELF segments

use crate::core::types::{MemoryTypeFlags, OperandSize};
use crate::pe::segment::Segment as PeSegment;

/// A section/segment in an executable file
/// Unified abstraction for PE sections, Mach-O segments, ELF segments
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Section name
    pub name: String,
    /// Virtual address in memory
    pub virtual_address: u64,
    /// Virtual size in memory
    pub virtual_size: u64,
    /// Physical offset in file
    pub physical_offset: u32,
    /// Physical size in file
    pub physical_size: u32,
    /// Memory protection flags
    pub memory_type: MemoryTypeFlags,
    /// Platform-specific flags
    pub flags: u32,
    /// Write type tracking (for packing)
    pub write_type: MemoryTypeFlags,
    /// Excluded from packing
    pub excluded_from_packing: bool,
    /// Excluded from memory protection
    pub excluded_from_memory_protection: bool,
    /// Parent segment (for Mach-O nested sections)
    pub parent: Option<Box<Section>>,
    /// Whether this section needs parsing
    pub need_parse: bool,
}

impl Section {
    /// Create a new section
    pub fn new(name: impl Into<String>, virtual_address: u64, virtual_size: u64) -> Self {
        Self {
            name: name.into(),
            virtual_address,
            virtual_size,
            physical_offset: 0,
            physical_size: 0,
            memory_type: MemoryTypeFlags::NONE,
            flags: 0,
            write_type: MemoryTypeFlags::NONE,
            excluded_from_packing: false,
            excluded_from_memory_protection: false,
            parent: None,
            need_parse: true,
        }
    }

    /// Create from PE segment
    pub fn from_pe_segment(segment: &PeSegment) -> Self {
        let memory_type = segment_to_memory_type(segment);
        Self {
            name: segment.name.clone(),
            virtual_address: segment.virtual_address,
            virtual_size: segment.virtual_size,
            physical_offset: segment.raw_address as u32,
            physical_size: segment.raw_size as u32,
            memory_type,
            flags: segment.characteristics,
            write_type: MemoryTypeFlags::NONE,
            excluded_from_packing: false,
            excluded_from_memory_protection: false,
            parent: None,
            need_parse: true,
        }
    }

    /// Check if address is within this section
    pub fn contains_address(&self, address: u64) -> bool {
        address >= self.virtual_address && address < self.virtual_address + self.virtual_size
    }

    /// Check if offset is within this section
    pub fn contains_offset(&self, offset: u64) -> bool {
        let end = self.physical_offset as u64 + self.physical_size as u64;
        offset >= self.physical_offset as u64 && offset < end
    }

    /// Convert virtual address to file offset
    pub fn rva_to_offset(&self, rva: u64) -> Option<u64> {
        if !self.contains_address(rva) {
            return None;
        }
        if self.physical_size == 0 {
            return None;
        }
        let offset = rva - self.virtual_address;
        if offset >= self.physical_size as u64 {
            return None;
        }
        Some(self.physical_offset as u64 + offset)
    }

    /// Convert file offset to virtual address
    pub fn offset_to_rva(&self, offset: u64) -> Option<u64> {
        if !self.contains_offset(offset) {
            return None;
        }
        let rel_offset = offset - self.physical_offset as u64;
        Some(self.virtual_address + rel_offset)
    }

    /// Check if this is a code section
    pub fn is_code(&self) -> bool {
        self.memory_type.contains(MemoryTypeFlags::EXECUTABLE)
    }

    /// Check if this is a data section
    pub fn is_data(&self) -> bool {
        !self.is_code() && self.memory_type.contains(MemoryTypeFlags::READABLE)
    }

    /// Check if this is a writable section
    pub fn is_writable(&self) -> bool {
        self.memory_type.contains(MemoryTypeFlags::WRITABLE)
    }

    /// Include write type
    pub fn include_write_type(&mut self, write_type: MemoryTypeFlags) {
        self.write_type.insert(write_type);
    }

    /// Update memory type
    pub fn update_memory_type(&mut self, mem_type: MemoryTypeFlags) {
        self.memory_type = mem_type;
    }

    /// Rebase addresses
    pub fn rebase(&mut self, delta: u64) {
        self.virtual_address = self.virtual_address.wrapping_add(delta);
    }

    /// Get end address
    pub fn end_address(&self) -> u64 {
        self.virtual_address + self.virtual_size
    }

    /// Get end offset
    pub fn end_offset(&self) -> u64 {
        self.physical_offset as u64 + self.physical_size as u64
    }

    /// Get address size (based on virtual address range)
    pub fn address_size(&self) -> OperandSize {
        if self.virtual_address > u32::MAX as u64 || self.end_address() > u32::MAX as u64 {
            OperandSize::QWord
        } else {
            OperandSize::DWord
        }
    }

    /// Calculate hash for comparison
    pub fn hash(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        self.name.hash(&mut hasher);
        self.excluded_from_packing.hash(&mut hasher);
        self.excluded_from_memory_protection.hash(&mut hasher);
        hasher.finish()
    }
}

impl Default for Section {
    fn default() -> Self {
        Self {
            name: String::new(),
            virtual_address: 0,
            virtual_size: 0,
            physical_offset: 0,
            physical_size: 0,
            memory_type: MemoryTypeFlags::NONE,
            flags: 0,
            write_type: MemoryTypeFlags::NONE,
            excluded_from_packing: false,
            excluded_from_memory_protection: false,
            parent: None,
            need_parse: true,
        }
    }
}

/// Convert PE segment characteristics to memory type flags
fn segment_to_memory_type(segment: &PeSegment) -> MemoryTypeFlags {
    let mut mem_type = MemoryTypeFlags::NONE;
    
    // IMAGE_SCN_MEM_READ = 0x40000000
    if segment.characteristics & 0x40000000 != 0 {
        mem_type.insert(MemoryTypeFlags::READABLE);
    }
    
    // IMAGE_SCN_MEM_WRITE = 0x80000000
    if segment.characteristics & 0x80000000 != 0 {
        mem_type.insert(MemoryTypeFlags::WRITABLE);
    }
    
    // IMAGE_SCN_MEM_EXECUTE = 0x20000000
    if segment.characteristics & 0x20000000 != 0 {
        mem_type.insert(MemoryTypeFlags::EXECUTABLE);
    }
    
    // IMAGE_SCN_MEM_NOT_PAGED = 0x08000000
    if segment.characteristics & 0x08000000 != 0 {
        mem_type.insert(MemoryTypeFlags::NOT_PAGED);
    }
    
    // IMAGE_SCN_MEM_SHARED = 0x10000000
    if segment.characteristics & 0x10000000 != 0 {
        mem_type.insert(MemoryTypeFlags::SHARED);
    }
    
    // IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
    if segment.characteristics & 0x02000000 != 0 {
        mem_type.insert(MemoryTypeFlags::DISCARDABLE);
    }
    
    mem_type
}

/// List of sections
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SectionList {
    sections: Vec<Section>,
}

impl SectionList {
    /// Create a new empty section list
    pub fn new() -> Self {
        Self { sections: Vec::new() }
    }

    /// Create with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            sections: Vec::with_capacity(capacity),
        }
    }

    /// Add a section
    pub fn add(&mut self, section: Section) -> &Section {
        self.sections.push(section);
        self.sections.last().unwrap()
    }

    /// Get section by index
    pub fn get(&self, index: usize) -> Option<&Section> {
        self.sections.get(index)
    }

    /// Get mutable section by index
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Section> {
        self.sections.get_mut(index)
    }

    /// Find section by address
    pub fn find_by_address(&self, address: u64) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains_address(address))
    }

    /// Find section by address (mutable)
    pub fn find_by_address_mut(&mut self, address: u64) -> Option<&mut Section> {
        self.sections.iter_mut().find(|s| s.contains_address(address))
    }

    /// Find section by offset
    pub fn find_by_offset(&self, offset: u64) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains_offset(offset))
    }

    /// Find section by offset (mutable)
    pub fn find_by_offset_mut(&mut self, offset: u64) -> Option<&mut Section> {
        self.sections.iter_mut().find(|s| s.contains_offset(offset))
    }

    /// Find section by name
    pub fn find_by_name(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Find section by name (mutable)
    pub fn find_by_name_mut(&mut self, name: &str) -> Option<&mut Section> {
        self.sections.iter_mut().find(|s| s.name == name)
    }

    /// Find child section by name within a parent
    pub fn find_child_by_name(&self, parent: &Section, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| {
            s.name == name && s.parent.as_ref().map(|p| p.name == parent.name).unwrap_or(false)
        })
    }

    /// Get memory type for an address
    pub fn get_memory_type_by_address(&self, address: u64) -> MemoryTypeFlags {
        self.find_by_address(address)
            .map(|s| s.memory_type)
            .unwrap_or(MemoryTypeFlags::NONE)
    }

    /// Rebase all sections
    pub fn rebase(&mut self, delta: u64) {
        for section in &mut self.sections {
            section.rebase(delta);
        }
    }

    /// Get number of sections
    pub fn len(&self) -> usize {
        self.sections.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.sections.is_empty()
    }

    /// Clear all sections
    pub fn clear(&mut self) {
        self.sections.clear();
    }

    /// Get all sections
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// Get mutable sections
    pub fn sections_mut(&mut self) -> &mut Vec<Section> {
        &mut self.sections
    }

    /// Iterate over sections
    pub fn iter(&self) -> std::slice::Iter<Section> {
        self.sections.iter()
    }

    /// Iterate mutably over sections
    pub fn iter_mut(&mut self) -> std::slice::IterMut<Section> {
        self.sections.iter_mut()
    }

    /// Get code sections
    pub fn code_sections(&self) -> Vec<&Section> {
        self.sections.iter().filter(|s| s.is_code()).collect()
    }

    /// Get data sections
    pub fn data_sections(&self) -> Vec<&Section> {
        self.sections.iter().filter(|s| s.is_data()).collect()
    }

    /// Get writable sections
    pub fn writable_sections(&self) -> Vec<&Section> {
        self.sections.iter().filter(|s| s.is_writable()).collect()
    }

    /// Find section containing RVA and convert to offset
    pub fn rva_to_offset(&self, rva: u64) -> Option<u64> {
        self.find_by_address(rva)?.rva_to_offset(rva)
    }

    /// Find section containing offset and convert to RVA
    pub fn offset_to_rva(&self, offset: u64) -> Option<u64> {
        self.find_by_offset(offset)?.offset_to_rva(offset)
    }

    /// Merge another section list
    pub fn merge(&mut self, other: &SectionList) {
        self.sections.extend_from_slice(&other.sections);
    }

    /// Sort sections by virtual address
    pub fn sort_by_address(&mut self) {
        self.sections.sort_by_key(|s| s.virtual_address);
    }

    /// Sort sections by physical offset
    pub fn sort_by_offset(&mut self) {
        self.sections.sort_by_key(|s| s.physical_offset);
    }

    /// Calculate total virtual size
    pub fn total_virtual_size(&self) -> u64 {
        self.sections.iter().map(|s| s.virtual_size).sum()
    }

    /// Calculate total physical size
    pub fn total_physical_size(&self) -> u64 {
        self.sections.iter().map(|s| s.physical_size as u64).sum()
    }

    /// Get first section
    pub fn first(&self) -> Option<&Section> {
        self.sections.first()
    }

    /// Get last section
    pub fn last(&self) -> Option<&Section> {
        self.sections.last()
    }
}

impl IntoIterator for SectionList {
    type Item = Section;
    type IntoIter = std::vec::IntoIter<Section>;

    fn into_iter(self) -> Self::IntoIter {
        self.sections.into_iter()
    }
}

impl<'a> IntoIterator for &'a SectionList {
    type Item = &'a Section;
    type IntoIter = std::slice::Iter<'a, Section>;

    fn into_iter(self) -> Self::IntoIter {
        self.sections.iter()
    }
}

impl<'a> IntoIterator for &'a mut SectionList {
    type Item = &'a mut Section;
    type IntoIter = std::slice::IterMut<'a, Section>;

    fn into_iter(self) -> Self::IntoIter {
        self.sections.iter_mut()
    }
}

impl Extend<Section> for SectionList {
    fn extend<T: IntoIterator<Item = Section>>(&mut self, iter: T) {
        self.sections.extend(iter);
    }
}

impl FromIterator<Section> for SectionList {
    fn from_iter<I: IntoIterator<Item = Section>>(iter: I) -> Self {
        Self {
            sections: iter.into_iter().collect(),
        }
    }
}

/// Load command abstraction (for Mach-O)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadCommand {
    /// Command type
    pub cmd_type: u32,
    /// Command name
    pub name: String,
    /// Virtual address
    pub address: u64,
    /// Size
    pub size: u32,
    /// Whether this command is visible
    pub visible: bool,
}

impl LoadCommand {
    /// Create a new load command
    pub fn new(cmd_type: u32, name: impl Into<String>, address: u64, size: u32) -> Self {
        Self {
            cmd_type,
            name: name.into(),
            address,
            size,
            visible: true,
        }
    }

    /// Rebase address
    pub fn rebase(&mut self, delta: u64) {
        self.address = self.address.wrapping_add(delta);
    }
}

/// List of load commands
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadCommandList {
    commands: Vec<LoadCommand>,
}

impl LoadCommandList {
    /// Create a new empty list
    pub fn new() -> Self {
        Self { commands: Vec::new() }
    }

    /// Add a command
    pub fn add(&mut self, command: LoadCommand) -> &LoadCommand {
        self.commands.push(command);
        self.commands.last().unwrap()
    }

    /// Find command by type
    pub fn find_by_type(&self, cmd_type: u32) -> Option<&LoadCommand> {
        self.commands.iter().find(|c| c.cmd_type == cmd_type)
    }

    /// Find command by type (mutable)
    pub fn find_by_type_mut(&mut self, cmd_type: u32) -> Option<&mut LoadCommand> {
        self.commands.iter_mut().find(|c| c.cmd_type == cmd_type)
    }

    /// Rebase all commands
    pub fn rebase(&mut self, delta: u64) {
        for cmd in &mut self.commands {
            cmd.rebase(delta);
        }
    }

    /// Get number of commands
    pub fn len(&self) -> usize {
        self.commands.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    /// Clear all commands
    pub fn clear(&mut self) {
        self.commands.clear();
    }

    /// Iterate over commands
    pub fn iter(&self) -> std::slice::Iter<LoadCommand> {
        self.commands.iter()
    }
}

impl IntoIterator for LoadCommandList {
    type Item = LoadCommand;
    type IntoIter = std::vec::IntoIter<LoadCommand>;

    fn into_iter(self) -> Self::IntoIter {
        self.commands.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_new() {
        let section = Section::new(".text", 0x1000, 0x100);
        assert_eq!(section.name, ".text");
        assert_eq!(section.virtual_address, 0x1000);
        assert_eq!(section.virtual_size, 0x100);
    }

    #[test]
    fn test_section_contains_address() {
        let section = Section::new(".text", 0x1000, 0x100);
        assert!(section.contains_address(0x1000));
        assert!(section.contains_address(0x10FF));
        assert!(!section.contains_address(0x1100));
        assert!(!section.contains_address(0x0FFF));
    }

    #[test]
    fn test_section_rva_to_offset() {
        let mut section = Section::new(".text", 0x1000, 0x100);
        section.physical_offset = 0x400;
        section.physical_size = 0x100;
        
        assert_eq!(section.rva_to_offset(0x1000), Some(0x400));
        assert_eq!(section.rva_to_offset(0x1040), Some(0x440));
        assert_eq!(section.rva_to_offset(0x1100), None); // Beyond virtual size
    }

    #[test]
    fn test_section_is_code() {
        let mut section = Section::new(".text", 0x1000, 0x100);
        assert!(!section.is_code());
        
        section.memory_type.insert(MemoryTypeFlags::EXECUTABLE);
        assert!(section.is_code());
    }

    #[test]
    fn test_section_list_add() {
        let mut list = SectionList::new();
        list.add(Section::new(".text", 0x1000, 0x100));
        list.add(Section::new(".data", 0x2000, 0x100));
        
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_section_list_find_by_address() {
        let mut list = SectionList::new();
        list.add(Section::new(".text", 0x1000, 0x100));
        list.add(Section::new(".data", 0x2000, 0x100));
        
        let found = list.find_by_address(0x1050);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, ".text");
    }

    #[test]
    fn test_section_list_find_by_name() {
        let mut list = SectionList::new();
        list.add(Section::new(".text", 0x1000, 0x100));
        list.add(Section::new(".data", 0x2000, 0x100));
        
        let found = list.find_by_name(".data");
        assert!(found.is_some());
        assert_eq!(found.unwrap().virtual_address, 0x2000);
    }

    #[test]
    fn test_section_list_rebase() {
        let mut list = SectionList::new();
        list.add(Section::new(".text", 0x1000, 0x100));
        list.add(Section::new(".data", 0x2000, 0x100));
        
        list.rebase(0x100);
        
        assert_eq!(list.find_by_name(".text").unwrap().virtual_address, 0x1100);
        assert_eq!(list.find_by_name(".data").unwrap().virtual_address, 0x2100);
    }

    #[test]
    fn test_section_list_code_sections() {
        let mut list = SectionList::new();
        let mut text = Section::new(".text", 0x1000, 0x100);
        text.memory_type.insert(MemoryTypeFlags::EXECUTABLE);
        list.add(text);
        list.add(Section::new(".data", 0x2000, 0x100));
        
        let code = list.code_sections();
        assert_eq!(code.len(), 1);
        assert_eq!(code[0].name, ".text");
    }

    #[test]
    fn test_load_command() {
        let cmd = LoadCommand::new(1, "LC_SEGMENT", 0x1000, 0x100);
        assert_eq!(cmd.cmd_type, 1);
        assert_eq!(cmd.name, "LC_SEGMENT");
        assert_eq!(cmd.address, 0x1000);
    }

    #[test]
    fn test_load_command_list() {
        let mut list = LoadCommandList::new();
        list.add(LoadCommand::new(1, "LC_SEGMENT", 0x1000, 0x100));
        list.add(LoadCommand::new(2, "LC_SYMTAB", 0x2000, 0x50));
        
        let found = list.find_by_type(2);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "LC_SYMTAB");
    }
}
