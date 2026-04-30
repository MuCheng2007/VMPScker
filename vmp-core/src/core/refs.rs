//! Cross-reference tracking between addresses
//! Translated from core/files/references.h/cc

/// A single address cross-reference with optional tag
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Reference {
    /// The address where the reference occurs
    pub address: u64,
    /// The address being referenced (operand address)
    pub operand_address: u64,
    /// Optional tag for categorization
    pub tag: usize,
}

impl Reference {
    /// Create a new reference
    pub fn new(address: u64, operand_address: u64, tag: usize) -> Self {
        Self {
            address,
            operand_address,
            tag,
        }
    }

    /// Rebase addresses by adding delta
    pub fn rebase(&mut self, delta: u64) {
        self.address = self.address.wrapping_add(delta);
        self.operand_address = self.operand_address.wrapping_add(delta);
    }

    /// Create a rebased copy
    pub fn rebased(&self, delta: u64) -> Self {
        Self {
            address: self.address.wrapping_add(delta),
            operand_address: self.operand_address.wrapping_add(delta),
            tag: self.tag,
        }
    }
}

impl Default for Reference {
    fn default() -> Self {
        Self {
            address: 0,
            operand_address: 0,
            tag: 0,
        }
    }
}

/// Ordered collection of References
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReferenceList {
    refs: Vec<Reference>,
}

impl ReferenceList {
    /// Create a new empty reference list
    pub fn new() -> Self {
        Self { refs: Vec::new() }
    }

    /// Create with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            refs: Vec::with_capacity(capacity),
        }
    }

    /// Add a new reference
    pub fn add(&mut self, address: u64, operand_address: u64, tag: usize) -> &Reference {
        let reference = Reference::new(address, operand_address, tag);
        self.refs.push(reference);
        self.refs.last().unwrap()
    }

    /// Get reference by index
    pub fn get(&self, index: usize) -> Option<&Reference> {
        self.refs.get(index)
    }

    /// Get mutable reference by index
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Reference> {
        self.refs.get_mut(index)
    }

    /// Find reference by address
    pub fn find_by_address(&self, address: u64) -> Option<&Reference> {
        self.refs.iter().find(|r| r.address == address)
    }

    /// Find reference by address (mutable)
    pub fn find_by_address_mut(&mut self, address: u64) -> Option<&mut Reference> {
        self.refs.iter_mut().find(|r| r.address == address)
    }

    /// Find references by operand address
    pub fn find_by_operand(&self, operand_address: u64) -> Vec<&Reference> {
        self.refs.iter().filter(|r| r.operand_address == operand_address).collect()
    }

    /// Check if contains a reference at address
    pub fn contains_address(&self, address: u64) -> bool {
        self.refs.iter().any(|r| r.address == address)
    }

    /// Get number of references
    pub fn len(&self) -> usize {
        self.refs.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.refs.is_empty()
    }

    /// Clear all references
    pub fn clear(&mut self) {
        self.refs.clear();
    }

    /// Rebase all references
    pub fn rebase(&mut self, delta: u64) {
        for reference in &mut self.refs {
            reference.rebase(delta);
        }
    }

    /// Get all references
    pub fn refs(&self) -> &[Reference] {
        &self.refs
    }

    /// Get mutable references slice
    pub fn refs_mut(&mut self) -> &mut Vec<Reference> {
        &mut self.refs
    }

    /// Iterate over references
    pub fn iter(&self) -> std::slice::Iter<Reference> {
        self.refs.iter()
    }

    /// Iterate mutably over references
    pub fn iter_mut(&mut self) -> std::slice::IterMut<Reference> {
        self.refs.iter_mut()
    }

    /// Remove reference at address
    pub fn remove_by_address(&mut self, address: u64) -> bool {
        if let Some(pos) = self.refs.iter().position(|r| r.address == address) {
            self.refs.remove(pos);
            true
        } else {
            false
        }
    }

    /// Sort references by address
    pub fn sort_by_address(&mut self) {
        self.refs.sort_by_key(|r| r.address);
    }

    /// Sort references by operand address
    pub fn sort_by_operand(&mut self) {
        self.refs.sort_by_key(|r| r.operand_address);
    }

    /// Get addresses as a vector
    pub fn addresses(&self) -> Vec<u64> {
        self.refs.iter().map(|r| r.address).collect()
    }

    /// Get operand addresses as a vector
    pub fn operand_addresses(&self) -> Vec<u64> {
        self.refs.iter().map(|r| r.operand_address).collect()
    }

    /// Merge another reference list into this one
    pub fn merge(&mut self, other: &ReferenceList) {
        self.refs.extend_from_slice(&other.refs);
    }

    /// Retain only references matching the predicate
    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&Reference) -> bool,
    {
        self.refs.retain(f);
    }

    /// Filter references by tag
    pub fn filter_by_tag(&self, tag: usize) -> Vec<&Reference> {
        self.refs.iter().filter(|r| r.tag == tag).collect()
    }
}

impl IntoIterator for ReferenceList {
    type Item = Reference;
    type IntoIter = std::vec::IntoIter<Reference>;

    fn into_iter(self) -> Self::IntoIter {
        self.refs.into_iter()
    }
}

impl<'a> IntoIterator for &'a ReferenceList {
    type Item = &'a Reference;
    type IntoIter = std::slice::Iter<'a, Reference>;

    fn into_iter(self) -> Self::IntoIter {
        self.refs.iter()
    }
}

impl<'a> IntoIterator for &'a mut ReferenceList {
    type Item = &'a mut Reference;
    type IntoIter = std::slice::IterMut<'a, Reference>;

    fn into_iter(self) -> Self::IntoIter {
        self.refs.iter_mut()
    }
}

impl FromIterator<Reference> for ReferenceList {
    fn from_iter<I: IntoIterator<Item = Reference>>(iter: I) -> Self {
        Self {
            refs: iter.into_iter().collect(),
        }
    }
}

impl Extend<Reference> for ReferenceList {
    fn extend<T: IntoIterator<Item = Reference>>(&mut self, iter: T) {
        self.refs.extend(iter);
    }
}

/// Builder for constructing reference lists
pub struct ReferenceListBuilder {
    refs: Vec<Reference>,
}

impl ReferenceListBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self { refs: Vec::new() }
    }

    /// Add a reference
    pub fn add(mut self, address: u64, operand_address: u64, tag: usize) -> Self {
        self.refs.push(Reference::new(address, operand_address, tag));
        self
    }

    /// Add multiple references
    pub fn add_many(mut self, refs: impl IntoIterator<Item = (u64, u64, usize)>) -> Self {
        for (addr, operand, tag) in refs {
            self.refs.push(Reference::new(addr, operand, tag));
        }
        self
    }

    /// Build the reference list
    pub fn build(self) -> ReferenceList {
        ReferenceList { refs: self.refs }
    }
}

impl Default for ReferenceListBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reference_new() {
        let r = Reference::new(0x1000, 0x2000, 1);
        assert_eq!(r.address, 0x1000);
        assert_eq!(r.operand_address, 0x2000);
        assert_eq!(r.tag, 1);
    }

    #[test]
    fn test_reference_rebase() {
        let mut r = Reference::new(0x1000, 0x2000, 0);
        r.rebase(0x100);
        assert_eq!(r.address, 0x1100);
        assert_eq!(r.operand_address, 0x2100);
    }

    #[test]
    fn test_reference_list_add() {
        let mut list = ReferenceList::new();
        list.add(0x1000, 0x2000, 0);
        list.add(0x1004, 0x2004, 1);
        
        assert_eq!(list.len(), 2);
        assert!(!list.is_empty());
    }

    #[test]
    fn test_find_by_address() {
        let mut list = ReferenceList::new();
        list.add(0x1000, 0x2000, 0);
        list.add(0x1004, 0x2004, 1);
        
        let found = list.find_by_address(0x1000);
        assert!(found.is_some());
        assert_eq!(found.unwrap().operand_address, 0x2000);
        
        assert!(list.find_by_address(0x9999).is_none());
    }

    #[test]
    fn test_find_by_operand() {
        let mut list = ReferenceList::new();
        list.add(0x1000, 0x2000, 0);
        list.add(0x1004, 0x2000, 1); // Same operand
        list.add(0x1008, 0x3000, 2);
        
        let found = list.find_by_operand(0x2000);
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn test_reference_list_rebase() {
        let mut list = ReferenceList::new();
        list.add(0x1000, 0x2000, 0);
        list.add(0x1004, 0x2004, 1);
        
        list.rebase(0x100);
        
        assert_eq!(list.get(0).unwrap().address, 0x1100);
        assert_eq!(list.get(0).unwrap().operand_address, 0x2100);
        assert_eq!(list.get(1).unwrap().address, 0x1104);
    }

    #[test]
    fn test_remove_by_address() {
        let mut list = ReferenceList::new();
        list.add(0x1000, 0x2000, 0);
        list.add(0x1004, 0x2004, 1);
        
        assert!(list.remove_by_address(0x1000));
        assert_eq!(list.len(), 1);
        assert!(!list.remove_by_address(0x9999));
    }

    #[test]
    fn test_sort_by_address() {
        let mut list = ReferenceList::new();
        list.add(0x3000, 0x2000, 0);
        list.add(0x1000, 0x2004, 1);
        list.add(0x2000, 0x2008, 2);
        
        list.sort_by_address();
        
        assert_eq!(list.get(0).unwrap().address, 0x1000);
        assert_eq!(list.get(1).unwrap().address, 0x2000);
        assert_eq!(list.get(2).unwrap().address, 0x3000);
    }

    #[test]
    fn test_filter_by_tag() {
        let mut list = ReferenceList::new();
        list.add(0x1000, 0x2000, 0);
        list.add(0x1004, 0x2004, 1);
        list.add(0x1008, 0x2008, 1);
        
        let filtered = list.filter_by_tag(1);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_builder() {
        let list = ReferenceListBuilder::new()
            .add(0x1000, 0x2000, 0)
            .add(0x1004, 0x2004, 1)
            .add_many([(0x1008, 0x2008, 2), (0x100C, 0x200C, 3)])
            .build();
        
        assert_eq!(list.len(), 4);
    }

    #[test]
    fn test_iterator() {
        let mut list = ReferenceList::new();
        list.add(0x1000, 0x2000, 0);
        list.add(0x1004, 0x2004, 1);
        
        let count = list.iter().count();
        assert_eq!(count, 2);
        
        let mut sum = 0u64;
        for r in &list {
            sum += r.address;
        }
        assert_eq!(sum, 0x2004);
    }

    #[test]
    fn test_extend() {
        let mut list1 = ReferenceList::new();
        list1.add(0x1000, 0x2000, 0);
        
        let mut list2 = ReferenceList::new();
        list2.add(0x1004, 0x2004, 1);
        
        list1.merge(&list2);
        assert_eq!(list1.len(), 2);
    }
}
