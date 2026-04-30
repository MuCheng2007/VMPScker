//! Windows SEH (Structured Exception Handling) handlers
//! Translated from core/files/seh.h/cc

/// SEH handler entry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SehHandler {
    /// Handler address
    pub address: u64,
    /// Deleted flag (for cleanup)
    pub deleted: bool,
}

impl SehHandler {
    /// Create a new SEH handler
    pub fn new(address: u64) -> Self {
        Self {
            address,
            deleted: false,
        }
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
        Self {
            address: self.address.wrapping_add(delta),
            deleted: self.deleted,
        }
    }
}

impl Default for SehHandler {
    fn default() -> Self {
        Self {
            address: 0,
            deleted: false,
        }
    }
}

impl From<u64> for SehHandler {
    fn from(address: u64) -> Self {
        Self::new(address)
    }
}

/// List of SEH handlers
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SehHandlerList {
    handlers: Vec<SehHandler>,
    address_map: std::collections::HashMap<u64, usize>,
}

impl SehHandlerList {
    /// Create a new empty handler list
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
            address_map: std::collections::HashMap::new(),
        }
    }

    /// Create with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            handlers: Vec::with_capacity(capacity),
            address_map: std::collections::HashMap::with_capacity(capacity),
        }
    }

    /// Add a handler
    pub fn add(&mut self, address: u64) -> &SehHandler {
        let idx = self.handlers.len();
        self.handlers.push(SehHandler::new(address));
        self.address_map.insert(address, idx);
        &self.handlers[idx]
    }

    /// Add a handler object
    pub fn add_handler(&mut self, handler: SehHandler) -> &SehHandler {
        let idx = self.handlers.len();
        let address = handler.address;
        self.handlers.push(handler);
        self.address_map.insert(address, idx);
        &self.handlers[idx]
    }

    /// Get handler by index
    pub fn get(&self, index: usize) -> Option<&SehHandler> {
        self.handlers.get(index)
    }

    /// Get mutable handler by index
    pub fn get_mut(&mut self, index: usize) -> Option<&mut SehHandler> {
        self.handlers.get_mut(index)
    }

    /// Find handler by address
    pub fn find_by_address(&self, address: u64) -> Option<&SehHandler> {
        self.address_map.get(&address).and_then(|&idx| self.handlers.get(idx))
    }

    /// Find handler by address (mutable)
    pub fn find_by_address_mut(&mut self, address: u64) -> Option<&mut SehHandler> {
        self.address_map.get(&address).copied().and_then(move |idx| self.handlers.get_mut(idx))
    }

    /// Check if contains handler at address
    pub fn contains_address(&self, address: u64) -> bool {
        self.address_map.contains_key(&address)
    }

    /// Get number of handlers
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Clear all handlers
    pub fn clear(&mut self) {
        self.handlers.clear();
        self.address_map.clear();
    }

    /// Remove deleted handlers and rebuild map
    pub fn pack(&mut self) {
        self.handlers.retain(|h| !h.deleted);
        self.rebuild_map();
    }

    /// Rebase all handlers
    pub fn rebase(&mut self, delta: u64) {
        for handler in &mut self.handlers {
            handler.rebase(delta);
        }
        self.rebuild_map();
    }

    /// Rebuild address map
    fn rebuild_map(&mut self) {
        self.address_map.clear();
        for (idx, handler) in self.handlers.iter().enumerate() {
            self.address_map.insert(handler.address, idx);
        }
    }

    /// Get all handlers
    pub fn handlers(&self) -> &[SehHandler] {
        &self.handlers
    }

    /// Get mutable handlers
    pub fn handlers_mut(&mut self) -> &mut Vec<SehHandler> {
        &mut self.handlers
    }

    /// Iterate over handlers
    pub fn iter(&self) -> std::slice::Iter<SehHandler> {
        self.handlers.iter()
    }

    /// Iterate mutably over handlers
    pub fn iter_mut(&mut self) -> std::slice::IterMut<SehHandler> {
        self.handlers.iter_mut()
    }

    /// Remove handler at address
    pub fn remove_by_address(&mut self, address: u64) -> bool {
        if let Some(&idx) = self.address_map.get(&address) {
            self.handlers.remove(idx);
            self.rebuild_map();
            true
        } else {
            false
        }
    }

    /// Mark handler as deleted
    pub fn mark_deleted(&mut self, address: u64) -> bool {
        if let Some(handler) = self.find_by_address_mut(address) {
            handler.mark_deleted();
            true
        } else {
            false
        }
    }

    /// Get addresses as a vector
    pub fn addresses(&self) -> Vec<u64> {
        self.handlers.iter().map(|h| h.address).collect()
    }

    /// Merge another handler list into this one
    pub fn merge(&mut self, other: &SehHandlerList) {
        for handler in &other.handlers {
            if !self.contains_address(handler.address) {
                self.add_handler(*handler);
            }
        }
    }
}

impl IntoIterator for SehHandlerList {
    type Item = SehHandler;
    type IntoIter = std::vec::IntoIter<SehHandler>;

    fn into_iter(self) -> Self::IntoIter {
        self.handlers.into_iter()
    }
}

impl<'a> IntoIterator for &'a SehHandlerList {
    type Item = &'a SehHandler;
    type IntoIter = std::slice::Iter<'a, SehHandler>;

    fn into_iter(self) -> Self::IntoIter {
        self.handlers.iter()
    }
}

impl<'a> IntoIterator for &'a mut SehHandlerList {
    type Item = &'a mut SehHandler;
    type IntoIter = std::slice::IterMut<'a, SehHandler>;

    fn into_iter(self) -> Self::IntoIter {
        self.handlers.iter_mut()
    }
}

impl Extend<SehHandler> for SehHandlerList {
    fn extend<T: IntoIterator<Item = SehHandler>>(&mut self, iter: T) {
        for handler in iter {
            self.add_handler(handler);
        }
    }
}

impl FromIterator<SehHandler> for SehHandlerList {
    fn from_iter<I: IntoIterator<Item = SehHandler>>(iter: I) -> Self {
        let mut list = Self::new();
        list.extend(iter);
        list
    }
}

/// Sentinel value indicating a SEH handler is needed
pub const NEED_SEH_HANDLER: u64 = u64::MAX;

/// Check if an address is the sentinel value
pub fn is_need_seh_handler(address: u64) -> bool {
    address == NEED_SEH_HANDLER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seh_handler_new() {
        let handler = SehHandler::new(0x1000);
        assert_eq!(handler.address, 0x1000);
        assert!(!handler.deleted);
    }

    #[test]
    fn test_seh_handler_mark_deleted() {
        let mut handler = SehHandler::new(0x1000);
        handler.mark_deleted();
        assert!(handler.is_deleted());
    }

    #[test]
    fn test_seh_handler_rebase() {
        let mut handler = SehHandler::new(0x1000);
        handler.rebase(0x100);
        assert_eq!(handler.address, 0x1100);
    }

    #[test]
    fn test_seh_handler_list_add() {
        let mut list = SehHandlerList::new();
        list.add(0x1000);
        list.add(0x2000);
        
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_seh_handler_list_find() {
        let mut list = SehHandlerList::new();
        list.add(0x1000);
        list.add(0x2000);
        
        let found = list.find_by_address(0x1000);
        assert!(found.is_some());
        
        assert!(list.find_by_address(0x9999).is_none());
    }

    #[test]
    fn test_seh_handler_list_contains() {
        let mut list = SehHandlerList::new();
        list.add(0x1000);
        
        assert!(list.contains_address(0x1000));
        assert!(!list.contains_address(0x2000));
    }

    #[test]
    fn test_seh_handler_list_rebase() {
        let mut list = SehHandlerList::new();
        list.add(0x1000);
        list.add(0x2000);
        
        list.rebase(0x100);
        
        assert!(list.contains_address(0x1100));
        assert!(list.contains_address(0x2100));
        assert!(!list.contains_address(0x1000));
    }

    #[test]
    fn test_seh_handler_list_pack() {
        let mut list = SehHandlerList::new();
        list.add(0x1000);
        list.add(0x2000);
        list.mark_deleted(0x1000);
        
        list.pack();
        
        assert_eq!(list.len(), 1);
        assert!(list.contains_address(0x2000));
    }

    #[test]
    fn test_seh_handler_list_remove() {
        let mut list = SehHandlerList::new();
        list.add(0x1000);
        list.add(0x2000);
        
        assert!(list.remove_by_address(0x1000));
        assert_eq!(list.len(), 1);
        assert!(!list.remove_by_address(0x9999));
    }

    #[test]
    fn test_need_seh_handler_sentinel() {
        assert!(is_need_seh_handler(NEED_SEH_HANDLER));
        assert!(!is_need_seh_handler(0x1000));
    }
}
