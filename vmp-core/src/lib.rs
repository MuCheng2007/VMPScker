pub mod error;
pub mod pe;
pub mod intel;
pub mod protector;

pub use error::VmpError;
pub use protector::{VmpProtector, ProtectConfig, ProtectRange, protect_file, protect_data};

pub mod vm;
