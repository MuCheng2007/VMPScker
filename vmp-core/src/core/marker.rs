//! Code markers for protection/script/vm boundaries
//! Translated from core/files/markers.h/cc

use crate::core::types::ObjectType;

/// A code marker indicating protection boundaries
/// Corresponds to VMProtectBegin/End markers in the code
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkerCommand {
    /// Address of the marker instruction
    pub address: u64,
    /// Address of the operand (referenced data)
    pub operand_address: u64,
    /// Address of the name reference (for named markers)
    pub name_reference: u64,
    /// Address where the name string is located
    pub name_address: u64,
    /// Type of object being marked
    pub object_type: ObjectType,
}

impl MarkerCommand {
    /// Create a new marker command
    pub fn new(
        address: u64,
        operand_address: u64,
        name_reference: u64,
        name_address: u64,
        object_type: ObjectType,
    ) -> Self {
        Self {
            address,
            operand_address,
            name_reference,
            name_address,
            object_type,
        }
    }

    /// Create a simple marker at an address
    pub fn at_address(address: u64, object_type: ObjectType) -> Self {
        Self::new(address, 0, 0, 0, object_type)
    }

    /// Create a named marker
    pub fn named(address: u64, name_address: u64, object_type: ObjectType) -> Self {
        Self::new(address, 0, 0, name_address, object_type)
    }

    /// Rebase addresses by adding delta
    pub fn rebase(&mut self, delta: u64) {
        self.address = self.address.wrapping_add(delta);
        self.operand_address = self.operand_address.wrapping_add(delta);
        self.name_reference = self.name_reference.wrapping_add(delta);
        self.name_address = self.name_address.wrapping_add(delta);
    }

    /// Create a rebased copy
    pub fn rebased(&self, delta: u64) -> Self {
        Self {
            address: self.address.wrapping_add(delta),
            operand_address: self.operand_address.wrapping_add(delta),
            name_reference: self.name_reference.wrapping_add(delta),
            name_address: self.name_address.wrapping_add(delta),
            object_type: self.object_type,
        }
    }

    /// Compare by address
    pub fn cmp_address(&self, other: &Self) -> std::cmp::Ordering {
        self.address.cmp(&other.address)
    }

    /// Check if this is a begin marker
    pub fn is_begin(&self) -> bool {
        matches!(self.object_type, ObjectType::Marker | ObjectType::ApiMarker)
    }

    /// Check if this is an end marker
    pub fn is_end(&self) -> bool {
        // End markers typically have a different type or special marker
        self.object_type == ObjectType::Unknown && self.operand_address == 0
    }
}

impl Default for MarkerCommand {
    fn default() -> Self {
        Self {
            address: 0,
            operand_address: 0,
            name_reference: 0,
            name_address: 0,
            object_type: ObjectType::Unknown,
        }
    }
}

/// List of marker commands
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MarkerCommandList {
    markers: Vec<MarkerCommand>,
}

impl MarkerCommandList {
    /// Create a new empty marker list
    pub fn new() -> Self {
        Self { markers: Vec::new() }
    }

    /// Create with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            markers: Vec::with_capacity(capacity),
        }
    }

    /// Add a marker
    pub fn add(&mut self, marker: MarkerCommand) -> &MarkerCommand {
        self.markers.push(marker);
        self.markers.last().unwrap()
    }

    /// Add a new marker with parameters
    pub fn add_new(
        &mut self,
        address: u64,
        operand_address: u64,
        name_reference: u64,
        name_address: u64,
        object_type: ObjectType,
    ) -> &MarkerCommand {
        self.add(MarkerCommand::new(
            address,
            operand_address,
            name_reference,
            name_address,
            object_type,
        ))
    }

    /// Get marker by index
    pub fn get(&self, index: usize) -> Option<&MarkerCommand> {
        self.markers.get(index)
    }

    /// Get mutable marker by index
    pub fn get_mut(&mut self, index: usize) -> Option<&mut MarkerCommand> {
        self.markers.get_mut(index)
    }

    /// Find marker by address
    pub fn find_by_address(&self, address: u64) -> Option<&MarkerCommand> {
        self.markers.iter().find(|m| m.address == address)
    }

    /// Find marker by address (mutable)
    pub fn find_by_address_mut(&mut self, address: u64) -> Option<&mut MarkerCommand> {
        self.markers.iter_mut().find(|m| m.address == address)
    }

    /// Find markers by object type
    pub fn find_by_type(&self, object_type: ObjectType) -> Vec<&MarkerCommand> {
        self.markers.iter().filter(|m| m.object_type == object_type).collect()
    }

    /// Get number of markers
    pub fn len(&self) -> usize {
        self.markers.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.markers.is_empty()
    }

    /// Clear all markers
    pub fn clear(&mut self) {
        self.markers.clear();
    }

    /// Rebase all markers
    pub fn rebase(&mut self, delta: u64) {
        for marker in &mut self.markers {
            marker.rebase(delta);
        }
    }

    /// Sort markers by address
    pub fn sort_by_address(&mut self) {
        self.markers.sort_by(|a, b| a.address.cmp(&b.address));
    }

    /// Get all markers
    pub fn markers(&self) -> &[MarkerCommand] {
        &self.markers
    }

    /// Get mutable markers
    pub fn markers_mut(&mut self) -> &mut Vec<MarkerCommand> {
        &mut self.markers
    }

    /// Iterate over markers
    pub fn iter(&self) -> std::slice::Iter<MarkerCommand> {
        self.markers.iter()
    }

    /// Iterate mutably over markers
    pub fn iter_mut(&mut self) -> std::slice::IterMut<MarkerCommand> {
        self.markers.iter_mut()
    }

    /// Remove marker at address
    pub fn remove_by_address(&mut self, address: u64) -> bool {
        if let Some(pos) = self.markers.iter().position(|m| m.address == address) {
            self.markers.remove(pos);
            true
        } else {
            false
        }
    }

    /// Remove markers by type
    pub fn remove_by_type(&mut self, object_type: ObjectType) -> usize {
        let old_len = self.markers.len();
        self.markers.retain(|m| m.object_type != object_type);
        old_len - self.markers.len()
    }

    /// Find begin/end marker pairs
    pub fn find_pairs(&self) -> Vec<(usize, usize)> {
        let mut pairs = Vec::new();
        let mut stack = Vec::new();

        for (i, marker) in self.markers.iter().enumerate() {
            if marker.is_begin() {
                stack.push(i);
            } else if marker.is_end() && !stack.is_empty() {
                if let Some(begin_idx) = stack.pop() {
                    pairs.push((begin_idx, i));
                }
            }
        }

        pairs
    }

    /// Get markers in address range
    pub fn in_range(&self, start: u64, end: u64) -> Vec<&MarkerCommand> {
        self.markers
            .iter()
            .filter(|m| m.address >= start && m.address < end)
            .collect()
    }

    /// Merge another marker list into this one
    pub fn merge(&mut self, other: &MarkerCommandList) {
        self.markers.extend_from_slice(&other.markers);
    }
}

impl IntoIterator for MarkerCommandList {
    type Item = MarkerCommand;
    type IntoIter = std::vec::IntoIter<MarkerCommand>;

    fn into_iter(self) -> Self::IntoIter {
        self.markers.into_iter()
    }
}

impl<'a> IntoIterator for &'a MarkerCommandList {
    type Item = &'a MarkerCommand;
    type IntoIter = std::slice::Iter<'a, MarkerCommand>;

    fn into_iter(self) -> Self::IntoIter {
        self.markers.iter()
    }
}

impl<'a> IntoIterator for &'a mut MarkerCommandList {
    type Item = &'a mut MarkerCommand;
    type IntoIter = std::slice::IterMut<'a, MarkerCommand>;

    fn into_iter(self) -> Self::IntoIter {
        self.markers.iter_mut()
    }
}

impl Extend<MarkerCommand> for MarkerCommandList {
    fn extend<T: IntoIterator<Item = MarkerCommand>>(&mut self, iter: T) {
        self.markers.extend(iter);
    }
}

impl FromIterator<MarkerCommand> for MarkerCommandList {
    fn from_iter<I: IntoIterator<Item = MarkerCommand>>(iter: I) -> Self {
        Self {
            markers: iter.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_marker_command_new() {
        let marker = MarkerCommand::new(0x1000, 0x2000, 0, 0x3000, ObjectType::Marker);
        assert_eq!(marker.address, 0x1000);
        assert_eq!(marker.operand_address, 0x2000);
        assert_eq!(marker.name_address, 0x3000);
        assert_eq!(marker.object_type, ObjectType::Marker);
    }

    #[test]
    fn test_marker_command_at_address() {
        let marker = MarkerCommand::at_address(0x1000, ObjectType::Code);
        assert_eq!(marker.address, 0x1000);
        assert_eq!(marker.object_type, ObjectType::Code);
        assert_eq!(marker.operand_address, 0);
    }

    #[test]
    fn test_marker_command_rebase() {
        let mut marker = MarkerCommand::new(0x1000, 0x2000, 0x3000, 0x4000, ObjectType::Marker);
        marker.rebase(0x100);
        
        assert_eq!(marker.address, 0x1100);
        assert_eq!(marker.operand_address, 0x2100);
        assert_eq!(marker.name_reference, 0x3100);
        assert_eq!(marker.name_address, 0x4100);
    }

    #[test]
    fn test_marker_list_add() {
        let mut list = MarkerCommandList::new();
        list.add(MarkerCommand::at_address(0x1000, ObjectType::Marker));
        list.add(MarkerCommand::at_address(0x1004, ObjectType::Marker));
        
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_marker_list_find_by_address() {
        let mut list = MarkerCommandList::new();
        list.add(MarkerCommand::at_address(0x1000, ObjectType::Marker));
        list.add(MarkerCommand::at_address(0x1004, ObjectType::Marker));
        
        let found = list.find_by_address(0x1000);
        assert!(found.is_some());
        
        assert!(list.find_by_address(0x9999).is_none());
    }

    #[test]
    fn test_marker_list_find_by_type() {
        let mut list = MarkerCommandList::new();
        list.add(MarkerCommand::at_address(0x1000, ObjectType::Marker));
        list.add(MarkerCommand::at_address(0x1004, ObjectType::Code));
        list.add(MarkerCommand::at_address(0x1008, ObjectType::Marker));
        
        let markers = list.find_by_type(ObjectType::Marker);
        assert_eq!(markers.len(), 2);
    }

    #[test]
    fn test_marker_list_sort_by_address() {
        let mut list = MarkerCommandList::new();
        list.add(MarkerCommand::at_address(0x3000, ObjectType::Marker));
        list.add(MarkerCommand::at_address(0x1000, ObjectType::Marker));
        list.add(MarkerCommand::at_address(0x2000, ObjectType::Marker));
        
        list.sort_by_address();
        
        assert_eq!(list.get(0).unwrap().address, 0x1000);
        assert_eq!(list.get(1).unwrap().address, 0x2000);
        assert_eq!(list.get(2).unwrap().address, 0x3000);
    }

    #[test]
    fn test_marker_list_in_range() {
        let mut list = MarkerCommandList::new();
        list.add(MarkerCommand::at_address(0x1000, ObjectType::Marker));
        list.add(MarkerCommand::at_address(0x2000, ObjectType::Marker));
        list.add(MarkerCommand::at_address(0x3000, ObjectType::Marker));
        
        let in_range = list.in_range(0x1500, 0x2500);
        assert_eq!(in_range.len(), 1);
        assert_eq!(in_range[0].address, 0x2000);
    }

    #[test]
    fn test_marker_list_remove_by_type() {
        let mut list = MarkerCommandList::new();
        list.add(MarkerCommand::at_address(0x1000, ObjectType::Marker));
        list.add(MarkerCommand::at_address(0x1004, ObjectType::Code));
        list.add(MarkerCommand::at_address(0x1008, ObjectType::Marker));
        
        let removed = list.remove_by_type(ObjectType::Marker);
        assert_eq!(removed, 2);
        assert_eq!(list.len(), 1);
    }
}
