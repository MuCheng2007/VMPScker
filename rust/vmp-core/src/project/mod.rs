pub mod config;
pub mod loader;

pub use config::{
    ProjectConfig, ProtectionOptions, FunctionConfig, CompilationType,
    LicensingConfig, MessageType, ProjectOption, MESSAGE_COUNT, DEFAULT_MESSAGES
};
pub use loader::ProjectLoader;
