//! Core executable file handling module
//! Translated from core/files/*.h/cc
//!
//! This module provides unified abstractions for:
//! - Basic types and constants
//! - Memory management
//! - Section/segment handling
//! - Import/export tables
//! - Fixups and relocations
//! - Resources
//! - MAP file parsing
//! - Architecture abstractions

pub mod types;
pub mod utils;
pub mod refs;
pub mod memory;
pub mod section;
pub mod import;
pub mod export;
pub mod fixup;
pub mod marker;
pub mod seh;
pub mod compiler_func;

// Re-export commonly used types
pub use types::*;
pub use utils::{FunctionName, demangle_name};
pub use refs::{Reference, ReferenceList};
pub use memory::{MemoryRegion, MemoryManager, CrcInfo, CrcTable, CrcVerificationResult};
pub use section::{Section, SectionList, LoadCommand, LoadCommandList};
pub use import::{ImportFunction, Import, ImportList};
pub use export::{Export, ExportList};
pub use fixup::{Fixup, FixupList, FixupStatistics, FixupValidationError, Symbol, SymbolTable, SymbolType, SymbolStatistics, AdvancedRelocHandler};
pub use marker::{MarkerCommand, MarkerCommandList};
pub use seh::{SehHandler, SehHandlerList, NEED_SEH_HANDLER, is_need_seh_handler};
pub use compiler_func::{CompilerFunction, CompilerFunctionList};

/// Rebase trait for types that support address rebasing
pub trait Rebase {
    /// Rebase by adding delta to all addresses
    fn rebase(&mut self, delta: u64);
}

impl Rebase for u64 {
    fn rebase(&mut self, delta: u64) {
        *self = self.wrapping_add(delta);
    }
}

impl<T: Rebase> Rebase for Vec<T> {
    fn rebase(&mut self, delta: u64) {
        for item in self {
            item.rebase(delta);
        }
    }
}

impl<T: Rebase> Rebase for Option<T> {
    fn rebase(&mut self, delta: u64) {
        if let Some(item) = self {
            item.rebase(delta);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rebase_u64() {
        let mut addr: u64 = 0x1000;
        addr.rebase(0x100);
        assert_eq!(addr, 0x1100);
    }

    #[test]
    fn test_rebase_vec() {
        let mut addrs = vec![0x1000u64, 0x2000u64, 0x3000u64];
        addrs.rebase(0x100);
        assert_eq!(addrs, vec![0x1100, 0x2100, 0x3100]);
    }

    #[test]
    fn test_rebase_option() {
        let mut opt: Option<u64> = Some(0x1000);
        opt.rebase(0x100);
        assert_eq!(opt, Some(0x1100));

        let mut opt: Option<u64> = None;
        opt.rebase(0x100);
        assert_eq!(opt, None);
    }
}
