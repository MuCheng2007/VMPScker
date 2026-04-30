//! Utility functions for executable file handling
//! Translated from core/files/utils.h/cc

use crate::core::types::{OperandSize, ObjectType};

/// Convert a name buffer to string (handling null termination)
pub fn name_to_string(name: &[u8]) -> String {
    let len = name.iter()
        .position(|&b| b == 0)
        .unwrap_or(name.len());
    String::from_utf8_lossy(&name[..len]).to_string()
}

/// Display string with escape sequences for control characters
pub fn display_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_ascii_control() => {
                result.push_str(&format!("\\{}", c as u8));
            }
            c => result.push(c),
        }
    }
    result
}

/// Display value with proper formatting based on operand size
pub fn display_value(size: OperandSize, value: u64) -> String {
    match size {
        OperandSize::QWord => format!("{:016X}", value),
        _ => format!("{:08X}", value as u32),
    }
}

/// Function name with optional return-type prefix
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FunctionName {
    full_name: String,
    name_pos: usize,
}

impl FunctionName {
    /// Create a new function name
    pub fn new(name: impl Into<String>) -> Self {
        let full_name = name.into();
        Self { full_name, name_pos: 0 }
    }

    /// Create with return type prefix
    pub fn with_return_type(return_type: impl Into<String>, name: impl Into<String>) -> Self {
        let ret = return_type.into();
        let name = name.into();
        let full_name = format!("{} {}", ret, name);
        Self { full_name, name_pos: ret.len() + 1 }
    }

    /// Get just the function name (without return type)
    pub fn name(&self) -> &str {
        &self.full_name[self.name_pos..]
    }

    /// Get the full name (with return type if present)
    pub fn full_name(&self) -> &str {
        &self.full_name
    }

    /// Get display name (optionally including return type)
    pub fn display_name(&self, show_return: bool) -> String {
        if show_return {
            display_string(&self.full_name)
        } else {
            display_string(self.name())
        }
    }

    /// Clear the name
    pub fn clear(&mut self) {
        self.full_name.clear();
        self.name_pos = 0;
    }

    /// Check if name is empty
    pub fn is_empty(&self) -> bool {
        self.name().is_empty()
    }
}

impl From<&str> for FunctionName {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for FunctionName {
    fn from(s: String) -> Self {
        Self { full_name: s, name_pos: 0 }
    }
}

/// Demangle a C++ name using available demanglers
/// Returns the demangled name if successful, or the original name if not
pub fn demangle_name(name: &str) -> FunctionName {
    if name.is_empty() {
        return FunctionName::default();
    }

    // Try rustc-demangle for Rust symbols
    if let Ok(demangled) = rustc_demangle::try_demangle(name) {
        return FunctionName::new(demangled.to_string());
    }

    // Try cpp_demangle for C++ symbols
    if let Ok(sym) = cpp_demangle::Symbol::new(name) {
        if let Ok(demangled) = sym.demangle(&cpp_demangle::DemangleOptions::default()) {
            return FunctionName::new(demangled);
        }
    }

    // Try msvc-demangler for MSVC symbols
    #[cfg(feature = "msvc-demangler")]
    {
        if let Ok(demangled) = msvc_demangler::demangle(name, msvc_demangler::DemangleFlags::NONE) {
            return FunctionName::new(demangled);
        }
    }

    // Return original if no demangler succeeded
    FunctionName::new(name)
}

/// Check if an object type represents code
pub fn is_code_type(object_type: ObjectType) -> bool {
    object_type.is_code()
}

/// Format bytes as hex string
pub fn format_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Parse hex string to bytes
pub fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.replace(" ", "").replace("-", "");
    if s.len() % 2 != 0 {
        return None;
    }

    let mut result = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i+2], 16).ok()?;
        result.push(byte);
    }
    Some(result)
}

/// Safe string truncation with ellipsis
pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Compare two strings case-insensitively
pub fn eq_ignore_ascii_case(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Check if a string is a valid C identifier
pub fn is_valid_c_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }

    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_to_string() {
        let buf = b"Hello\0World";
        assert_eq!(name_to_string(buf), "Hello");

        let buf = b"NoNullTerminator";
        assert_eq!(name_to_string(buf), "NoNullTerminator");
    }

    #[test]
    fn test_display_string() {
        assert_eq!(display_string("hello\nworld"), "hello\\nworld");
        assert_eq!(display_string("tab\there"), "tab\\there");
        assert_eq!(display_string("normal"), "normal");
    }

    #[test]
    fn test_display_value() {
        assert_eq!(display_value(OperandSize::DWord, 0x1234ABCD), "1234ABCD");
        assert_eq!(display_value(OperandSize::QWord, 0x1234ABCD), "000000001234ABCD");
    }

    #[test]
    fn test_function_name() {
        let name = FunctionName::new("test_func");
        assert_eq!(name.name(), "test_func");
        assert_eq!(name.display_name(false), "test_func");

        let name = FunctionName::with_return_type("int", "main");
        assert_eq!(name.name(), "main");
        assert_eq!(name.full_name(), "int main");
        assert_eq!(name.display_name(true), "int main");
        assert_eq!(name.display_name(false), "main");
    }

    #[test]
    fn test_demangle_rust() {
        // Rust symbol
        let rust_sym = "_ZN4core6option13Option$LT$T$GT$6unwrap17h1234567890abcdefE";
        let demangled = demangle_name(rust_sym);
        assert!(demangled.name().contains("unwrap"));
    }

    #[test]
    fn test_format_hex() {
        assert_eq!(format_hex(&[0x12, 0xAB, 0xCD]), "12 AB CD");
        assert_eq!(format_hex(&[]), "");
    }

    #[test]
    fn test_parse_hex() {
        assert_eq!(parse_hex("12 AB CD"), Some(vec![0x12, 0xAB, 0xCD]));
        assert_eq!(parse_hex("12-AB-CD"), Some(vec![0x12, 0xAB, 0xCD]));
        assert_eq!(parse_hex("12AB"), Some(vec![0x12, 0xAB]));
        assert_eq!(parse_hex("123"), None); // Odd length
    }

    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("hello", 10), "hello");
        assert_eq!(truncate_string("hello world", 8), "hello...");
    }

    #[test]
    fn test_is_valid_c_identifier() {
        assert!(is_valid_c_identifier("valid_name"));
        assert!(is_valid_c_identifier("_underscore"));
        assert!(is_valid_c_identifier("CamelCase"));
        assert!(!is_valid_c_identifier(""));
        assert!(!is_valid_c_identifier("123start"));
        assert!(!is_valid_c_identifier("has space"));
        assert!(!is_valid_c_identifier("has-dash"));
    }
}
