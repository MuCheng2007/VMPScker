pub mod anti_debug;
pub mod hwid;
pub mod licensing;
pub mod hooks;
pub mod strings;

pub use anti_debug::check_debugger;
pub use hwid::get_hwid;
pub use licensing::LicensingManager;
