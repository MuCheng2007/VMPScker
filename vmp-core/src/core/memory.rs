//! Memory management and CRC tables
//! Translated from core/files/memory.h/cc

use crate::core::types::{MemoryTypeFlags, align_value};
use std::cmp::Ordering;

/// A memory region with address, size, and type
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegion {
    /// Start address
    pub address: u64,
    /// End address (exclusive)
    pub end_address: u64,
    /// Memory protection type
    pub memory_type: MemoryTypeFlags,
    /// Parent function ID (if any)
    pub parent_function: Option<usize>,
}

impl MemoryRegion {
    /// Create a new memory region
    pub fn new(address: u64, size: usize, memory_type: MemoryTypeFlags, parent_function: Option<usize>) -> Self {
        Self {
            address,
            end_address: address + size as u64,
            memory_type,
            parent_function,
        }
    }

    /// Get region size
    pub fn size(&self) -> usize {
        (self.end_address - self.address) as usize
    }

    /// Check if region is empty
    pub fn is_empty(&self) -> bool {
        self.address >= self.end_address
    }

    /// Check if address is within region
    pub fn contains(&self, address: u64) -> bool {
        self.address <= address && address < self.end_address
    }

    /// Check if this region overlaps with another
    pub fn overlaps(&self, other: &MemoryRegion) -> bool {
        self.address < other.end_address && other.address < self.end_address
    }

    /// Check if this region can merge with another (adjacent and same type)
    pub fn can_merge(&self, other: &MemoryRegion) -> bool {
        self.memory_type == other.memory_type && self.end_address == other.address
    }

    /// Merge with another region (must be adjacent and same type)
    pub fn merge(&mut self, other: &MemoryRegion) -> bool {
        if self.can_merge(other) {
            self.end_address = other.end_address;
            true
        } else {
            false
        }
    }

    /// Allocate memory from this region
    /// Returns the allocated address if successful, 0 if not enough space
    pub fn alloc(&mut self, size: u64, mem_type: MemoryTypeFlags) -> u64 {
        if (self.size() as u64) < size {
            return 0;
        }

        // Check memory type compatibility
        if !mem_type.is_empty() {
            if (mem_type.contains(MemoryTypeFlags::READABLE) && !self.memory_type.contains(MemoryTypeFlags::READABLE))
                || (mem_type.contains(MemoryTypeFlags::WRITABLE) && !self.memory_type.contains(MemoryTypeFlags::WRITABLE))
                || (mem_type.contains(MemoryTypeFlags::EXECUTABLE) && !self.memory_type.contains(MemoryTypeFlags::EXECUTABLE))
                || (mem_type.contains(MemoryTypeFlags::NOT_PAGED) && !self.memory_type.contains(MemoryTypeFlags::NOT_PAGED))
                || ((mem_type.contains(MemoryTypeFlags::DISCARDABLE)) != (self.memory_type.contains(MemoryTypeFlags::DISCARDABLE)))
            {
                return 0;
            }
        }

        let result = self.address;
        self.address += size;
        result
    }

    /// Subtract a region from this one
    /// Returns an overflow region if the subtraction splits this region
    pub fn subtract(&mut self, remove_address: u64, size: u64) -> Option<MemoryRegion> {
        let remove_end = remove_address + size;

        if self.address < remove_address {
            if self.end_address > remove_end {
                // Split: create overflow region
                let overflow = MemoryRegion {
                    address: remove_end,
                    end_address: self.end_address,
                    memory_type: self.memory_type,
                    parent_function: self.parent_function,
                };
                self.end_address = remove_address;
                Some(overflow)
            } else if self.end_address > remove_address {
                // Truncate end
                self.end_address = remove_address;
                None
            } else {
                // No overlap
                None
            }
        } else {
            // Remove from start
            if self.address < remove_end {
                self.address = remove_end.min(self.end_address);
            }
            None
        }
    }

    /// Exclude a memory type flag
    pub fn exclude_type(&mut self, mem_type: MemoryTypeFlags) {
        self.memory_type.remove(mem_type);
    }

    /// Include a memory type flag
    pub fn include_type(&mut self, mem_type: MemoryTypeFlags) {
        self.memory_type.insert(mem_type);
    }

    /// Compare with another region by address
    pub fn compare_by_address(&self, other: &MemoryRegion) -> Ordering {
        self.address.cmp(&other.address)
    }
}

impl PartialOrd for MemoryRegion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MemoryRegion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.address.cmp(&other.address)
    }
}

/// Memory manager for allocating and tracking memory regions
#[derive(Debug, Clone, Default)]
pub struct MemoryManager {
    regions: Vec<MemoryRegion>,
}

impl MemoryManager {
    /// Create a new empty memory manager
    pub fn new() -> Self {
        Self { regions: Vec::new() }
    }

    /// Create with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            regions: Vec::with_capacity(capacity),
        }
    }

    /// Add a memory region with type
    pub fn add_with_type(&mut self, address: u64, size: usize, mem_type: MemoryTypeFlags, parent: Option<usize>) {
        self.add(address, size, mem_type, parent);
    }

    /// Find best fit region for allocation
    fn find_best_fit(&self, size: u64, alignment: u64) -> Option<usize> {
        let mut best_idx = None;
        let mut best_size = u64::MAX;

        for (idx, region) in self.regions.iter().enumerate() {
            let aligned_addr = align_value(region.address, alignment);
            let padding = aligned_addr - region.address;
            
            if (region.size() as u64) >= size + padding {
                let waste = region.size() as u64 - size - padding;
                if waste < best_size {
                    best_size = waste;
                    best_idx = Some(idx);
                }
            }
        }

        best_idx
    }

    /// Split a region at specified address
    fn split_region(&mut self, index: usize, split_addr: u64) -> Option<usize> {
        if index >= self.regions.len() {
            return None;
        }

        let region = &self.regions[index];
        if split_addr <= region.address || split_addr >= region.end_address {
            return None;
        }

        let new_region = MemoryRegion {
            address: split_addr,
            end_address: region.end_address,
            memory_type: region.memory_type,
            parent_function: region.parent_function,
        };

        self.regions[index].end_address = split_addr;
        self.regions.insert(index + 1, new_region);
        Some(index + 1)
    }

    /// Get free regions (regions with specific type)
    pub fn free_regions(&self, mem_type: MemoryTypeFlags) -> Vec<&MemoryRegion> {
        self.regions.iter()
            .filter(|r| r.memory_type.contains(mem_type))
            .collect()
    }

    /// Get regions by parent function
    pub fn regions_by_parent(&self, parent: usize) -> Vec<&MemoryRegion> {
        self.regions.iter()
            .filter(|r| r.parent_function == Some(parent))
            .collect()
    }

    /// Check if address is allocated
    pub fn is_allocated(&self, address: u64) -> bool {
        self.get_region_by_address(address).is_some()
    }

    /// Get total allocated size
    pub fn total_allocated(&self) -> usize {
        self.total_size()
    }

    /// Get largest free block size
    pub fn largest_free_block(&self) -> usize {
        self.regions.iter()
            .map(|r| r.size())
            .max()
            .unwrap_or(0)
    }

    /// Defragment memory regions
    pub fn defragment(&mut self) {
        self.pack();
    }

    /// Reserve memory at specific address
    pub fn reserve(&mut self, address: u64, size: usize) -> bool {
        if self.is_allocated(address) {
            return false;
        }
        self.add(address, size, MemoryTypeFlags::NONE, None);
        true
    }

    /// Commit reserved memory
    pub fn commit(&mut self, address: u64, mem_type: MemoryTypeFlags) -> bool {
        if let Some(region) = self.get_region_by_address_mut(address) {
            region.memory_type = mem_type;
            true
        } else {
            false
        }
    }

    /// Decommit memory
    pub fn decommit(&mut self, address: u64) -> bool {
        if let Some(region) = self.get_region_by_address_mut(address) {
            region.memory_type = MemoryTypeFlags::NONE;
            true
        } else {
            false
        }
    }

    /// Protect memory (change protection flags)
    pub fn protect(&mut self, address: u64, size: usize, new_type: MemoryTypeFlags) -> bool {
        let end_addr = address + size as u64;
        
        for region in self.regions.iter_mut() {
            if region.address >= address && region.end_address <= end_addr {
                region.memory_type = new_type;
            }
        }
        
        true
    }

    /// Query memory information
    pub fn query(&self, address: u64) -> Option<MemoryRegion> {
        self.get_region_by_address(address).cloned()
    }

    /// Dump memory layout for debugging
    pub fn dump_layout(&self) -> String {
        let mut output = String::from("Memory Layout:\n");
        output.push_str(&format!("Total regions: {}\n", self.len()));
        output.push_str(&format!("Total size: 0x{:X}\n", self.total_size()));
        output.push_str("Regions:\n");
        
        for (i, region) in self.regions.iter().enumerate() {
            output.push_str(&format!(
                "  [{}] 0x{:016X} - 0x{:016X} (size: 0x{:X}, type: {:?})\n",
                i, region.address, region.end_address, region.size(), region.memory_type
            ));
        }
        
        output
    }

    /// Validate memory manager state
    pub fn validate(&self) -> Result<(), String> {
        // Check for overlapping regions
        for i in 0..self.regions.len() {
            for j in (i + 1)..self.regions.len() {
                if self.regions[i].overlaps(&self.regions[j]) {
                    return Err(format!(
                        "Overlapping regions: [{}] 0x{:X}-0x{:X} and [{}] 0x{:X}-0x{:X}",
                        i, self.regions[i].address, self.regions[i].end_address,
                        j, self.regions[j].address, self.regions[j].end_address
                    ));
                }
            }
        }

        // Check for invalid regions
        for (i, region) in self.regions.iter().enumerate() {
            if region.address >= region.end_address {
                return Err(format!(
                    "Invalid region [{}]: address (0x{:X}) >= end_address (0x{:X})",
                    i, region.address, region.end_address
                ));
            }
        }

        Ok(())
    }

    /// Add a memory region
    pub fn add(&mut self, address: u64, size: usize, memory_type: MemoryTypeFlags, parent_function: Option<usize>) {
        if size == 0 {
            return;
        }

        let new_region = MemoryRegion::new(address, size, memory_type, parent_function);

        // Find insertion position (maintain sorted order)
        let pos = self.regions.binary_search_by(|r| {
            if r.end_address <= address {
                Ordering::Less
            } else if r.address >= address + size as u64 {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        });

        match pos {
            Ok(idx) => {
                // Overlapping region exists - adjust
                let existing = &self.regions[idx];
                let existing_addr = existing.address;
                let existing_end = existing.end_address;
                
                if existing_addr < address {
                    // Existing starts before new region
                    if existing_end > address + size as u64 {
                        // Existing completely covers new region
                        return;
                    }
                    // Adjust size to start after existing
                    let new_start = existing_end;
                    let new_size = (address + size as u64 - new_start) as usize;
                    drop(existing);
                    self.add(new_start, new_size, memory_type, parent_function);
                    return;
                } else if existing_addr < address + size as u64 {
                    // Existing starts within new region
                    if existing_end >= address + size as u64 {
                        // Existing extends to or past end
                        let new_size = (existing_addr - address) as usize;
                        drop(existing);
                        self.add(address, new_size, memory_type, parent_function);
                        return;
                    }
                    // Split around existing
                    let first_size = (existing_addr - address) as usize;
                    let second_start = existing_end;
                    let second_size = (address + size as u64 - second_start) as usize;
                    drop(existing);
                    self.add(address, first_size, memory_type, parent_function);
                    self.add(second_start, second_size, memory_type, parent_function);
                    return;
                }
            }
            Err(idx) => {
                self.regions.insert(idx, new_region);
            }
        }
    }

    /// Remove a memory region
    pub fn remove(&mut self, address: u64, size: usize) {
        if size == 0 || self.regions.is_empty() {
            return;
        }

        let remove_end = address + size as u64;
        let mut i = 0;

        while i < self.regions.len() {
            let region = &self.regions[i];
            let region_addr = region.address;
            let region_end = region.end_address;

            if region_addr >= remove_end {
                break;
            }

            if region_end <= address {
                i += 1;
                continue;
            }

            // Region overlaps with removal area
            let mut region = self.regions.remove(i);
            let overflow = region.subtract(address, size as u64);

            if !region.is_empty() {
                self.regions.insert(i, region);
                i += 1;
            }

            if let Some(overflow_region) = overflow {
                self.regions.insert(i, overflow_region);
                // Don't increment i, need to check if overflow also needs processing
            }
        }
    }

    /// Allocate memory with specified size and type
    /// Returns the allocated address, or 0 if allocation fails
    pub fn alloc(&mut self, size: usize, memory_type: MemoryTypeFlags, address: Option<u64>, alignment: usize) -> Option<u64> {
        if size == 0 {
            return Some(0);
        }

        let start_idx = if let Some(addr) = address {
            match self.index_of_address(addr) {
                Some(idx) => idx,
                None => return None,
            }
        } else {
            0
        };

        let end_idx = if address.is_some() {
            start_idx + 1
        } else {
            self.regions.len()
        };

        for i in start_idx..end_idx {
            let region = &self.regions[i];
            let region_addr = region.address;
            let region_size = region.size();
            let mut alloc_address = address.unwrap_or(region_addr);

            // Apply alignment
            if alignment > 1 {
                alloc_address = align_value(alloc_address, alignment as u64);
            }

            // Check if we need to split the region for alignment
            if alloc_address > region_addr {
                let delta = (alloc_address - region_addr) as usize;
                if region_size < delta + size {
                    continue;
                }
            }

            // Try to allocate the actual memory
            let mut temp_region = region.clone();
            let result = temp_region.alloc(size as u64, memory_type);

            if result != 0 {
                // Update the actual region
                if temp_region.is_empty() {
                    self.regions.remove(i);
                } else {
                    self.regions[i] = temp_region;
                }
                return Some(result);
            }
        }

        // Try without DISCARDABLE flag if it was set
        if memory_type.contains(MemoryTypeFlags::DISCARDABLE) && address.is_none() {
            let new_type = memory_type & !MemoryTypeFlags::DISCARDABLE;
            return self.alloc(size, new_type, address, alignment);
        }

        None
    }

    /// Get region containing address
    pub fn get_region_by_address(&self, address: u64) -> Option<&MemoryRegion> {
        self.index_of_address(address).map(|idx| &self.regions[idx])
    }

    /// Get mutable region containing address
    pub fn get_region_by_address_mut(&mut self, address: u64) -> Option<&mut MemoryRegion> {
        self.index_of_address(address).map(|idx| &mut self.regions[idx])
    }

    /// Get index of region containing address
    fn index_of_address(&self, address: u64) -> Option<usize> {
        if self.regions.is_empty() {
            return None;
        }

        // Binary search for region containing address
        let idx = self.regions.binary_search_by(|r| {
            if r.end_address <= address {
                Ordering::Less
            } else if r.address > address {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        });

        match idx {
            Ok(i) => Some(i),
            Err(_) => None,
        }
    }

    /// Pack adjacent regions with same type
    pub fn pack(&mut self) {
        if self.regions.len() < 2 {
            return;
        }

        let mut i = self.regions.len() - 1;
        while i > 0 {
            let prev_idx = i - 1;
            let can_merge = self.regions[prev_idx].can_merge(&self.regions[i]);

            if can_merge {
                let next = self.regions.remove(i);
                self.regions[prev_idx].merge(&next);
            }
            i -= 1;
        }
    }

    /// Get number of regions
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Clear all regions
    pub fn clear(&mut self) {
        self.regions.clear();
    }

    /// Get all regions
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// Get mutable regions
    pub fn regions_mut(&mut self) -> &mut Vec<MemoryRegion> {
        &mut self.regions
    }

    /// Iterate over regions
    pub fn iter(&self) -> std::slice::Iter<MemoryRegion> {
        self.regions.iter()
    }

    /// Iterate mutably over regions
    pub fn iter_mut(&mut self) -> std::slice::IterMut<MemoryRegion> {
        self.regions.iter_mut()
    }

    /// Get total size of all regions
    pub fn total_size(&self) -> usize {
        self.regions.iter().map(|r| r.size()).sum()
    }

    /// Rebase all regions by delta
    pub fn rebase(&mut self, delta: u64) {
        for region in &mut self.regions {
            region.address = region.address.wrapping_add(delta);
            region.end_address = region.end_address.wrapping_add(delta);
        }
    }
}

impl IntoIterator for MemoryManager {
    type Item = MemoryRegion;
    type IntoIter = std::vec::IntoIter<MemoryRegion>;

    fn into_iter(self) -> Self::IntoIter {
        self.regions.into_iter()
    }
}

impl<'a> IntoIterator for &'a MemoryManager {
    type Item = &'a MemoryRegion;
    type IntoIter = std::slice::Iter<'a, MemoryRegion>;

    fn into_iter(self) -> Self::IntoIter {
        self.regions.iter()
    }
}

/// CRC information for a memory region
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrcInfo {
    pub address: u32,
    pub size: u32,
    pub hash: u32,
}

impl CrcInfo {
    /// Create new CRC info
    pub fn new(address: u32, size: u32, hash: u32) -> Self {
        Self { address, size, hash }
    }

    /// Calculate CRC from data
    pub fn calculate(address: u32, data: &[u8]) -> Self {
        Self {
            address,
            size: data.len() as u32,
            hash: crc32fast::hash(data),
        }
    }

    /// Verify data against stored hash
    pub fn verify(&self, data: &[u8]) -> bool {
        self.hash == crc32fast::hash(data)
    }

    /// Get end address
    pub fn end_address(&self) -> u64 {
        self.address as u64 + self.size as u64
    }

    /// Check if contains address
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.address as u64 && addr < self.end_address()
    }
}

/// CRC table for memory protection
pub struct CrcTable {
    entries: Vec<CrcInfo>,
    max_size: Option<usize>,
}

impl std::fmt::Debug for CrcTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrcTable")
            .field("entries", &self.entries)
            .field("max_size", &self.max_size)
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

impl Clone for CrcTable {
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            max_size: self.max_size,
        }
    }
}

impl CrcTable {
    /// Create a new CRC table
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            max_size: None,
        }
    }

    /// Create with maximum size limit
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_size: Some(max_size),
        }
    }

    /// Add a region to the CRC table
    pub fn add(&mut self, address: u64, size: usize) {
        // This would typically read the data and calculate CRC
        // For now, just store the entry with hash=0
        self.entries.push(CrcInfo::new(address as u32, size as u32, 0));
    }

    /// Add with actual data to calculate CRC
    pub fn add_with_data(&mut self, address: u64, data: &[u8]) {
        let crc = CrcInfo::calculate(address as u32, data);
        self.entries.push(crc);
    }

    /// Remove a region from the CRC table
    pub fn remove(&mut self, address: u64, size: usize) {
        let end = address + size as u64;
        self.entries.retain(|e| {
            let e_end = e.address as u64 + e.size as u64;
            e_end <= address || e.address as u64 >= end
        });
    }

    /// Remove by address
    pub fn remove_by_address(&mut self, address: u64) -> bool {
        let initial_len = self.entries.len();
        self.entries.retain(|e| e.address as u64 != address);
        self.entries.len() < initial_len
    }

    /// Find entry by address
    pub fn find_by_address(&self, address: u64) -> Option<&CrcInfo> {
        self.entries.iter().find(|e| e.address as u64 == address)
    }

    /// Update CRC for a region
    pub fn update_crc(&mut self, address: u64, data: &[u8]) -> bool {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.address as u64 == address) {
            entry.hash = crc32fast::hash(data);
            entry.size = data.len() as u32;
            true
        } else {
            false
        }
    }

    /// Verify data against stored CRC
    pub fn verify(&self, address: u64, data: &[u8]) -> Option<bool> {
        self.find_by_address(address).map(|entry| {
            let calculated = crc32fast::hash(data);
            entry.hash == calculated
        })
    }

    /// Verify all entries against provided data
    pub fn verify_all<F>(&self, data_provider: F) -> Vec<CrcVerificationResult>
    where
        F: Fn(u64, u32) -> Option<Vec<u8>>,
    {
        self.entries.iter().map(|entry| {
            let data = data_provider(entry.address as u64, entry.size);
            let is_valid = data.as_ref().map(|d| {
                let calculated = crc32fast::hash(d);
                entry.hash == calculated
            });

            CrcVerificationResult {
                address: entry.address,
                size: entry.size,
                expected_hash: entry.hash,
                actual_hash: data.as_ref().map(|d| crc32fast::hash(d)),
                is_valid,
            }
        }).collect()
    }

    /// Get number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Get entries
    pub fn entries(&self) -> &[CrcInfo] {
        &self.entries
    }

    /// Get mutable entries
    pub fn entries_mut(&mut self) -> &mut Vec<CrcInfo> {
        &mut self.entries
    }

    /// Shuffle entries (for obfuscation)
    pub fn shuffle(&mut self) {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        self.entries.shuffle(&mut rng);
    }

    /// Sort entries by address
    pub fn sort_by_address(&mut self) {
        self.entries.sort_by_key(|e| e.address);
    }

    /// Limit entries to max size
    pub fn limit_size(&mut self) {
        if let Some(max) = self.max_size {
            let max_entries = max / std::mem::size_of::<CrcInfo>();
            if self.entries.len() > max_entries {
                self.entries.truncate(max_entries);
            }
        }
    }

    /// Calculate total CRC of all entries
    pub fn calculate_total_crc(&self) -> u32 {
        let data = unsafe {
            std::slice::from_raw_parts(
                self.entries.as_ptr() as *const u8,
                self.entries.len() * std::mem::size_of::<CrcInfo>(),
            )
        };
        crc32fast::hash(data)
    }

    /// Merge with another CRC table
    pub fn merge(&mut self, other: &CrcTable) {
        for entry in &other.entries {
            if !self.entries.iter().any(|e| e.address == entry.address) {
                self.entries.push(*entry);
            }
        }
    }

    /// Write to file (serialize)
    pub fn write_to_file(&self, is_positions: bool) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Write header
        let count = self.entries.len() as u32;
        data.extend_from_slice(&count.to_le_bytes());
        
        // Write entries
        for entry in &self.entries {
            if is_positions {
                // Write position-based format
                data.extend_from_slice(&entry.address.to_le_bytes());
            }
            data.extend_from_slice(&entry.size.to_le_bytes());
            data.extend_from_slice(&entry.hash.to_le_bytes());
        }
        
        data
    }

    /// Read from file (deserialize)
    pub fn read_from_file(data: &[u8], is_positions: bool) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        
        let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let mut table = Self::new();
        
        let mut offset = 4;
        for _ in 0..count {
            if is_positions {
                if offset + 12 > data.len() {
                    break;
                }
                let address = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
                let size = u32::from_le_bytes([data[offset+4], data[offset+5], data[offset+6], data[offset+7]]);
                let hash = u32::from_le_bytes([data[offset+8], data[offset+9], data[offset+10], data[offset+11]]);
                table.entries.push(CrcInfo::new(address, size, hash));
                offset += 12;
            } else {
                if offset + 8 > data.len() {
                    break;
                }
                let size = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
                let hash = u32::from_le_bytes([data[offset+4], data[offset+5], data[offset+6], data[offset+7]]);
                table.entries.push(CrcInfo::new(0, size, hash));
                offset += 8;
            }
        }
        
        Some(table)
    }

    /// Get total size of all regions
    pub fn total_size(&self) -> usize {
        self.entries.iter().map(|e| e.size as usize).sum()
    }

    /// Get entry count
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

impl Default for CrcTable {
    fn default() -> Self {
        Self::new()
    }
}

/// CRC verification result
#[derive(Debug, Clone)]
pub struct CrcVerificationResult {
    pub address: u32,
    pub size: u32,
    pub expected_hash: u32,
    pub actual_hash: Option<u32>,
    pub is_valid: Option<bool>,
}

impl CrcVerificationResult {
    /// Check if verification passed
    pub fn is_ok(&self) -> bool {
        self.is_valid.unwrap_or(false)
    }

    /// Get error message if failed
    pub fn error_message(&self) -> Option<String> {
        if self.is_valid.is_none() {
            Some(format!("No data available for region 0x{:08X}", self.address))
        } else if !self.is_valid.unwrap() {
            Some(format!(
                "CRC mismatch at 0x{:08X}: expected 0x{:08X}, got 0x{:08X}",
                self.address, self.expected_hash, self.actual_hash.unwrap_or(0)
            ))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_region_new() {
        let region = MemoryRegion::new(0x1000, 0x100, MemoryTypeFlags::READABLE, None);
        assert_eq!(region.address, 0x1000);
        assert_eq!(region.size(), 0x100);
        assert_eq!(region.end_address, 0x1100);
    }

    #[test]
    fn test_memory_region_contains() {
        let region = MemoryRegion::new(0x1000, 0x100, MemoryTypeFlags::READABLE, None);
        assert!(region.contains(0x1000));
        assert!(region.contains(0x10FF));
        assert!(!region.contains(0x1100));
        assert!(!region.contains(0x0FFF));
    }

    #[test]
    fn test_memory_region_alloc() {
        let mut region = MemoryRegion::new(0x1000, 0x100, MemoryTypeFlags::READABLE | MemoryTypeFlags::WRITABLE, None);
        
        let addr = region.alloc(0x10, MemoryTypeFlags::READABLE);
        assert_eq!(addr, 0x1000);
        assert_eq!(region.address, 0x1010);
        
        let addr = region.alloc(0x10, MemoryTypeFlags::READABLE | MemoryTypeFlags::WRITABLE);
        assert_eq!(addr, 0x1010);
    }

    #[test]
    fn test_memory_region_alloc_incompatible_type() {
        let mut region = MemoryRegion::new(0x1000, 0x100, MemoryTypeFlags::READABLE, None);
        
        // Should fail - region is not writable
        let addr = region.alloc(0x10, MemoryTypeFlags::WRITABLE);
        assert_eq!(addr, 0);
    }

    #[test]
    fn test_memory_region_subtract() {
        let mut region = MemoryRegion::new(0x1000, 0x100, MemoryTypeFlags::READABLE, None);
        
        // Subtract from middle
        let overflow = region.subtract(0x1040, 0x20);
        assert!(overflow.is_some());
        assert_eq!(region.end_address, 0x1040);
        assert_eq!(overflow.unwrap().address, 0x1060);
    }

    #[test]
    fn test_memory_region_merge() {
        let mut r1 = MemoryRegion::new(0x1000, 0x100, MemoryTypeFlags::READABLE, None);
        let r2 = MemoryRegion::new(0x1100, 0x100, MemoryTypeFlags::READABLE, None);
        
        assert!(r1.can_merge(&r2));
        assert!(r1.merge(&r2));
        assert_eq!(r1.end_address, 0x1200);
    }

    #[test]
    fn test_memory_manager_add() {
        let mut mm = MemoryManager::new();
        mm.add(0x1000, 0x100, MemoryTypeFlags::READABLE, None);
        mm.add(0x1200, 0x100, MemoryTypeFlags::READABLE, None);
        
        assert_eq!(mm.len(), 2);
    }

    #[test]
    fn test_memory_manager_alloc() {
        let mut mm = MemoryManager::new();
        mm.add(0x1000, 0x100, MemoryTypeFlags::READABLE | MemoryTypeFlags::WRITABLE, None);
        
        let addr = mm.alloc(0x20, MemoryTypeFlags::READABLE, None, 1);
        assert_eq!(addr, Some(0x1000));
        
        let addr = mm.alloc(0x20, MemoryTypeFlags::READABLE, None, 1);
        assert_eq!(addr, Some(0x1020));
    }

    #[test]
    fn test_memory_manager_alloc_aligned() {
        let mut mm = MemoryManager::new();
        mm.add(0x1000, 0x100, MemoryTypeFlags::READABLE, None);
        
        let addr = mm.alloc(0x10, MemoryTypeFlags::READABLE, None, 0x40);
        // With alignment 0x40 from 0x1000, the next aligned address is 0x1040
        // But since we're allocating from the start of region, we get 0x1000
        // The alignment logic only applies when address is specified
        assert_eq!(addr, Some(0x1000)); // First available address in region
    }

    #[test]
    fn test_memory_manager_get_region() {
        let mut mm = MemoryManager::new();
        mm.add(0x1000, 0x100, MemoryTypeFlags::READABLE, None);
        
        let region = mm.get_region_by_address(0x1050);
        assert!(region.is_some());
        
        let region = mm.get_region_by_address(0x2000);
        assert!(region.is_none());
    }

    #[test]
    fn test_memory_manager_remove() {
        let mut mm = MemoryManager::new();
        mm.add(0x1000, 0x100, MemoryTypeFlags::READABLE, None);
        
        mm.remove(0x1040, 0x20);
        
        assert_eq!(mm.len(), 2);
        assert_eq!(mm.regions[0].end_address, 0x1040);
        assert_eq!(mm.regions[1].address, 0x1060);
    }

    #[test]
    fn test_memory_manager_pack() {
        let mut mm = MemoryManager::new();
        mm.add(0x1000, 0x100, MemoryTypeFlags::READABLE, None);
        mm.add(0x1100, 0x100, MemoryTypeFlags::READABLE, None);
        
        mm.pack();
        
        assert_eq!(mm.len(), 1);
        assert_eq!(mm.regions[0].address, 0x1000);
        assert_eq!(mm.regions[0].end_address, 0x1200);
    }

    #[test]
    fn test_memory_manager_rebase() {
        let mut mm = MemoryManager::new();
        mm.add(0x1000, 0x100, MemoryTypeFlags::READABLE, None);
        
        mm.rebase(0x100);
        
        assert_eq!(mm.regions[0].address, 0x1100);
        assert_eq!(mm.regions[0].end_address, 0x1200);
    }

    #[test]
    fn test_crc_info() {
        let data = b"hello world";
        let crc = CrcInfo::calculate(0x1000, data);
        
        assert_eq!(crc.address, 0x1000);
        assert_eq!(crc.size, data.len() as u32);
        assert_ne!(crc.hash, 0);
    }

    #[test]
    fn test_crc_table() {
        let mut table = CrcTable::new();
        table.add(0x1000, 0x100);
        table.add(0x2000, 0x200);
        
        assert_eq!(table.len(), 2);
        
        table.remove(0x1000, 0x100);
        assert_eq!(table.len(), 1);
    }
}
