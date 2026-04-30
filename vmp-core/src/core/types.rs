//! Core types and constants for executable file handling
//! Translated from core/files/types.h

use bitflags::bitflags;

/// Operand size enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum OperandSize {
    Byte = 0,
    Word = 1,
    DWord = 2,
    QWord = 3,
    TByte = 4,    // 10 bytes (x87 extended)
    OWord = 5,    // 16 bytes (128-bit)
    XmmWord = 6,  // 16 bytes (XMM)
    YmmWord = 7,  // 32 bytes (YMM)
    FWord = 8,    // 6 bytes (far pointer)
}

impl OperandSize {
    /// Convert to byte size
    pub fn size_in_bytes(self) -> usize {
        match self {
            OperandSize::Byte => 1,
            OperandSize::Word => 2,
            OperandSize::DWord => 4,
            OperandSize::QWord => 8,
            OperandSize::TByte => 10,
            OperandSize::OWord | OperandSize::XmmWord => 16,
            OperandSize::YmmWord => 32,
            OperandSize::FWord => 6,
        }
    }

    /// Convert to bit size
    pub fn size_in_bits(self) -> usize {
        self.size_in_bytes() * 8
    }

    /// Get stack size (bytes are promoted to words on stack)
    pub fn stack_size(self) -> usize {
        if self == OperandSize::Byte {
            2 // Word
        } else {
            self.size_in_bytes()
        }
    }
}

impl Default for OperandSize {
    fn default() -> Self {
        OperandSize::DWord
    }
}

/// Message type for notifications
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Information,
    Warning,
    Error,
    Added,
    Changed,
    Deleted,
}

bitflags! {
    /// Memory protection flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MemoryTypeFlags: u32 {
        const NONE = 0x0;
        const READABLE = 0x1;
        const EXECUTABLE = 0x2;
        const WRITABLE = 0x4;
        const NOT_DISCARDABLE = 0x8;
        const DISCARDABLE = 0x10;
        const NOT_PAGED = 0x20;
        const SHARED = 0x40;
        const SOLID = 0x80;
    }
}

impl Default for MemoryTypeFlags {
    fn default() -> Self {
        MemoryTypeFlags::NONE
    }
}

/// SDK / API function types
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ApiType {
    None = 0,
    Begin = 1,
    End = 2,
    IsVirtualMachinePresent = 3,
    IsDebuggerPresent = 4,
    IsValidImageCrc = 5,
    DecryptStringA = 6,
    DecryptStringW = 7,
    FreeString = 8,
    ActivateLicense = 9,
    DeactivateLicense = 10,
    GetOfflineActivationString = 11,
    GetOfflineDeactivationString = 12,
    SetSerialNumber = 13,
    GetSerialNumberState = 14,
    GetSerialNumberData = 15,
    GetCurrentHwid = 16,
    LoadResource = 17,
    FindResourceA = 18,
    FindResourceExA = 19,
    FindResourceW = 20,
    FindResourceExW = 21,
    LoadStringA = 22,
    LoadStringW = 23,
    EnumResourceNamesA = 24,
    EnumResourceNamesW = 25,
    EnumResourceLanguagesA = 26,
    EnumResourceLanguagesW = 27,
    EnumResourceTypesA = 28,
    EnumResourceTypesW = 29,
    DecryptBuffer = 30,
    RuntimeInit = 31,
    LoaderData = 32,
    IsProtected = 33,
    SetupImage = 34,
    FreeImage = 35,
    CalcCrc = 36,
    Random = 37,
    BoxPointer = 38,
    UnboxPointer = 39,
}

impl Default for ApiType {
    fn default() -> Self {
        ApiType::None
    }
}

bitflags! {
    /// Import options (bit flags)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ImportOptions: u32 {
        const NONE = 0x0000;
        const NO_RETURN = 0x0001;
        const HAS_DATA_REFERENCE = 0x0002;
        const NATIVE = 0x0004;
        const HAS_COMPILATION_TYPE = 0x0008;
        const LOCK_TO_KEY = 0x0010;
        const FROM_RUNTIME = 0x0020;
        const NO_REFERENCES = 0x0040;
        const IS_RELATIVE = 0x0080;
        const HAS_DIRECT_REFERENCE = 0x0100;
        const HAS_CALL_PREFIX = 0x0200;
    }
}

impl Default for ImportOptions {
    fn default() -> Self {
        ImportOptions::NONE
    }
}

bitflags! {
    /// Runtime feature flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct RuntimeOptions: u32 {
        const NONE = 0x0000;
        const HWID = 0x0001;
        const KEY = 0x0002;
        const RESOURCES = 0x0004;
        const STRINGS = 0x0008;
        const BUNDLER = 0x0010;
        const REGISTRY = 0x0020;
        const ACTIVATION = 0x0040;
        const MEMORY_PROTECTION = 0x0080;
    }
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        RuntimeOptions::NONE
    }
}

/// Compilation strategy for protected functions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CompilationType {
    Virtualization = 0,
    Mutation = 1,
    Ultra = 2,  // Mutation + Virtualization
    #[default]
    None = 0xFF,
}

/// Fixup / relocation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FixupType {
    Unknown = 0,
    High = 1,
    Low = 2,
    HighLow = 3,
    // Extended types (values >= 4 to avoid conflict with C++ basic types)
    Absolute = 4,
    HighAdj = 5,
    Dir64 = 6,
    MipsJmpAddr = 7,
    ArmMov32 = 8,
    RiscVHi20 = 9,
}

impl Default for FixupType {
    fn default() -> Self {
        FixupType::Unknown
    }
}

/// Object type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ObjectType {
    Code = 0,
    Data = 1,
    Export = 2,
    Marker = 3,
    ApiMarker = 4,
    Import = 5,
    String = 6,
    Unknown = 7,
}

impl Default for ObjectType {
    fn default() -> Self {
        ObjectType::Unknown
    }
}

impl ObjectType {
    /// Check if this type represents code
    pub fn is_code(self) -> bool {
        matches!(self, 
            ObjectType::Marker | 
            ObjectType::ApiMarker | 
            ObjectType::Code | 
            ObjectType::String | 
            ObjectType::Export
        )
    }
}

/// Map file section types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapSectionType {
    Sections,
    Functions,
}

/// Compiler-generated helper function types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompilerFunctionType {
    None = 0,
    BaseRegister = 1,
    GetBaseRegister = 2,
    DllFunctionCall = 3,
    CxxSeh = 4,
    CxxSeh3 = 5,
    CxxSeh4 = 6,
    Seh4Prolog = 7,
    Vb6Seh = 8,
    InitBcbSeh = 9,
    BcbSeh = 10,
    RelocatorMinGW = 11,
    PatchImport = 12,
    JmpFunction = 13,
}

impl Default for CompilerFunctionType {
    fn default() -> Self {
        CompilerFunctionType::None
    }
}

bitflags! {
    /// Compiler function options
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CompilerFunctionOptions: u32 {
        const NONE = 0;
        const USED = 1;
        const NO_RETURN = 2;
    }
}

/// File open flags
bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct OpenMode: u32 {
        const READ = 0x01;
        const WRITE = 0x02;
        const HEADER_ONLY = 0x04;
        const COPY_TO_TEMP = 0x08;
    }
}

/// File open status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenStatus {
    Success,
    OpenError,
    UnknownFormat,
    InvalidFormat,
    UnsupportedCpu,
    UnsupportedSubsystem,
}

/// Calling conventions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    Stdcall,
    Cdecl,
    MsX64,
    AbIX64,
    StdcallToMsX64,
}

impl Default for CallingConvention {
    fn default() -> Self {
        CallingConvention::Cdecl
    }
}

/// Architecture types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArchType {
    X86,
    X64,
    Arm32,
    Arm64,
}

/// Compile flags (protection options)
bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CompileFlags: u32 {
        const NONE = 0;
        const PACK = 0x0001;
        const DEBUG_MODE = 0x0002;
        const IMPORT_PROTECTION = 0x0004;
        const CHECK_DEBUGGER = 0x0008;
        const CHECK_VIRTUAL_MACHINE = 0x0010;
        const MEMORY_PROTECTION = 0x0020;
        const RESOURCE_PROTECTION = 0x0040;
        const INTERNAL_MEMORY_PROTECTION = 0x0080;
        const LOADER = 0x0100;
    }
}

impl Default for CompileFlags {
    fn default() -> Self {
        CompileFlags::NONE
    }
}

/// Import info for SDK imports
#[derive(Debug, Clone, Copy)]
pub struct ImportInfo {
    pub api_type: ApiType,
    pub name: &'static str,
    pub options: ImportOptions,
    pub compilation_type: CompilationType,
}

impl ImportInfo {
    /// Encode to u64 for storage
    pub fn encode(&self) -> u64 {
        ((self.compilation_type as u64) << 16) |
        ((self.options.bits() as u64) << 8) |
        (self.api_type as u64)
    }

    /// Decode from u64
    pub fn decode(value: u64) -> (ApiType, ImportOptions, CompilationType) {
        let api_type = unsafe { std::mem::transmute((value & 0xff) as u8) };
        let options = ImportOptions::from_bits_truncate(((value >> 8) & 0xff) as u32);
        let compilation_type = unsafe { std::mem::transmute(((value >> 16) & 0xff) as u8) };
        (api_type, options, compilation_type)
    }
}

/// SDK import information table
pub static SDK_IMPORTS: &[ImportInfo] = &[
    ImportInfo { api_type: ApiType::Begin, name: "VMProtectBegin", options: ImportOptions::NONE, compilation_type: CompilationType::None },
    ImportInfo { api_type: ApiType::Begin, name: "VMProtectBeginVirtualization", options: ImportOptions::HAS_COMPILATION_TYPE, compilation_type: CompilationType::Virtualization },
    ImportInfo { api_type: ApiType::Begin, name: "VMProtectBeginMutation", options: ImportOptions::HAS_COMPILATION_TYPE, compilation_type: CompilationType::Mutation },
    ImportInfo { api_type: ApiType::Begin, name: "VMProtectBeginUltra", options: ImportOptions::HAS_COMPILATION_TYPE, compilation_type: CompilationType::Ultra },
    ImportInfo { api_type: ApiType::Begin, name: "VMProtectBeginVirtualizationLockByKey", options: ImportOptions::from_bits_truncate(ImportOptions::HAS_COMPILATION_TYPE.bits() | ImportOptions::LOCK_TO_KEY.bits()), compilation_type: CompilationType::Virtualization },
    ImportInfo { api_type: ApiType::Begin, name: "VMProtectBeginUltraLockByKey", options: ImportOptions::from_bits_truncate(ImportOptions::HAS_COMPILATION_TYPE.bits() | ImportOptions::LOCK_TO_KEY.bits()), compilation_type: CompilationType::Ultra },
    ImportInfo { api_type: ApiType::End, name: "VMProtectEnd", options: ImportOptions::NONE, compilation_type: CompilationType::None },
    ImportInfo { api_type: ApiType::IsProtected, name: "VMProtectIsProtected", options: ImportOptions::NONE, compilation_type: CompilationType::None },
    ImportInfo { api_type: ApiType::IsVirtualMachinePresent, name: "VMProtectIsVirtualMachinePresent", options: ImportOptions::NONE, compilation_type: CompilationType::None },
    ImportInfo { api_type: ApiType::IsDebuggerPresent, name: "VMProtectIsDebuggerPresent", options: ImportOptions::NONE, compilation_type: CompilationType::None },
    ImportInfo { api_type: ApiType::IsValidImageCrc, name: "VMProtectIsValidImageCRC", options: ImportOptions::NONE, compilation_type: CompilationType::None },
    ImportInfo { api_type: ApiType::DecryptStringA, name: "VMProtectDecryptStringA", options: ImportOptions::NONE, compilation_type: CompilationType::None },
    ImportInfo { api_type: ApiType::DecryptStringW, name: "VMProtectDecryptStringW", options: ImportOptions::NONE, compilation_type: CompilationType::None },
    ImportInfo { api_type: ApiType::FreeString, name: "VMProtectFreeString", options: ImportOptions::NONE, compilation_type: CompilationType::None },
    ImportInfo { api_type: ApiType::SetSerialNumber, name: "VMProtectSetSerialNumber", options: ImportOptions::NONE, compilation_type: CompilationType::None },
    ImportInfo { api_type: ApiType::GetSerialNumberState, name: "VMProtectGetSerialNumberState", options: ImportOptions::NONE, compilation_type: CompilationType::None },
    ImportInfo { api_type: ApiType::GetSerialNumberData, name: "VMProtectGetSerialNumberData", options: ImportOptions::NONE, compilation_type: CompilationType::None },
    ImportInfo { api_type: ApiType::GetCurrentHwid, name: "VMProtectGetCurrentHWID", options: ImportOptions::NONE, compilation_type: CompilationType::None },
    ImportInfo { api_type: ApiType::ActivateLicense, name: "VMProtectActivateLicense", options: ImportOptions::NONE, compilation_type: CompilationType::None },
    ImportInfo { api_type: ApiType::DeactivateLicense, name: "VMProtectDeactivateLicense", options: ImportOptions::NONE, compilation_type: CompilationType::None },
    ImportInfo { api_type: ApiType::GetOfflineActivationString, name: "VMProtectGetOfflineActivationString", options: ImportOptions::NONE, compilation_type: CompilationType::None },
    ImportInfo { api_type: ApiType::GetOfflineDeactivationString, name: "VMProtectGetOfflineDeactivationString", options: ImportOptions::NONE, compilation_type: CompilationType::None },
];

/// Get SDK import info by name
pub fn get_sdk_info(name: &str) -> Option<&'static ImportInfo> {
    SDK_IMPORTS.iter().find(|info| info.name.eq_ignore_ascii_case(name))
}

/// Get API type runtime options
pub fn get_api_runtime_options(api_type: ApiType) -> RuntimeOptions {
    match api_type {
        ApiType::SetSerialNumber |
        ApiType::GetSerialNumberState |
        ApiType::GetSerialNumberData |
        ApiType::GetOfflineActivationString |
        ApiType::GetOfflineDeactivationString => RuntimeOptions::KEY,
        ApiType::GetCurrentHwid => RuntimeOptions::HWID,
        ApiType::ActivateLicense |
        ApiType::DeactivateLicense => RuntimeOptions::from_bits_truncate(RuntimeOptions::KEY.bits() | RuntimeOptions::ACTIVATION.bits()),
        _ => RuntimeOptions::NONE,
    }
}

/// Get API type SDK options (compile flags)
pub fn get_api_sdk_options(api_type: ApiType) -> CompileFlags {
    match api_type {
        ApiType::IsValidImageCrc => CompileFlags::MEMORY_PROTECTION,
        ApiType::IsVirtualMachinePresent => CompileFlags::CHECK_VIRTUAL_MACHINE,
        ApiType::IsDebuggerPresent => CompileFlags::CHECK_DEBUGGER,
        _ => CompileFlags::NONE,
    }
}

/// Resource information structure
#[derive(Debug, Clone)]
pub struct ResourceInfo {
    pub file_data: Vec<u8>,
    pub code_data: Vec<u8>,
}

/// Sentinel value indicating a fixup is needed
pub const NEED_FIXUP: u64 = u64::MAX;

/// Sentinel value indicating a large value
pub const LARGE_VALUE: u64 = u64::MAX - 1;

/// NOT_ID sentinel for "not found" indices
pub const NOT_ID: usize = usize::MAX;

/// Bits to bytes conversion
#[inline]
pub const fn bits_to_bytes(bits: usize) -> usize {
    (bits + 7) >> 3
}

/// Bytes to bits conversion
#[inline]
pub const fn bytes_to_bits(bytes: usize) -> usize {
    bytes << 3
}

/// Align value to alignment boundary
#[inline]
pub fn align_value<T: Into<u64>>(value: T, alignment: T) -> u64 {
    let v: u64 = value.into();
    let a: u64 = alignment.into();
    if v % a == 0 {
        v
    } else {
        v + a - (v % a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operand_size() {
        assert_eq!(OperandSize::Byte.size_in_bytes(), 1);
        assert_eq!(OperandSize::Word.size_in_bytes(), 2);
        assert_eq!(OperandSize::DWord.size_in_bytes(), 4);
        assert_eq!(OperandSize::QWord.size_in_bytes(), 8);
        assert_eq!(OperandSize::TByte.size_in_bytes(), 10);
        assert_eq!(OperandSize::Byte.stack_size(), 2); // Promoted to word
        assert_eq!(OperandSize::DWord.stack_size(), 4);
    }

    #[test]
    fn test_memory_flags() {
        let flags = MemoryTypeFlags::READABLE | MemoryTypeFlags::EXECUTABLE;
        assert!(flags.contains(MemoryTypeFlags::READABLE));
        assert!(flags.contains(MemoryTypeFlags::EXECUTABLE));
        assert!(!flags.contains(MemoryTypeFlags::WRITABLE));
    }

    #[test]
    fn test_object_type_is_code() {
        assert!(ObjectType::Code.is_code());
        assert!(ObjectType::Marker.is_code());
        assert!(ObjectType::String.is_code());
        assert!(!ObjectType::Data.is_code());
        assert!(!ObjectType::Import.is_code());
    }

    #[test]
    fn test_sdk_lookup() {
        let info = get_sdk_info("VMProtectBegin");
        assert!(info.is_some());
        assert_eq!(info.unwrap().api_type, ApiType::Begin);

        let info = get_sdk_info("VMProtectBeginVirtualization");
        assert!(info.is_some());
        assert_eq!(info.unwrap().compilation_type, CompilationType::Virtualization);
    }

    #[test]
    fn test_align_value() {
        assert_eq!(align_value(0u64, 8u64), 0);
        assert_eq!(align_value(5u64, 8u64), 8);
        assert_eq!(align_value(8u64, 8u64), 8);
        assert_eq!(align_value(9u64, 8u64), 16);
    }

    #[test]
    fn test_bits_bytes_conversion() {
        assert_eq!(bits_to_bytes(7), 1);
        assert_eq!(bits_to_bytes(8), 1);
        assert_eq!(bits_to_bytes(9), 2);
        assert_eq!(bytes_to_bits(2), 16);
    }
}
