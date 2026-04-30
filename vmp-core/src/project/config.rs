use serde::{Deserialize, Serialize};

pub const MESSAGE_COUNT: usize = 5;

pub const DEFAULT_MESSAGES: [&str; MESSAGE_COUNT] = [
    "A debugger has been found running in your system.\nPlease, unload it from memory and restart your program.",
    "Sorry, this application cannot run under a Virtual Machine.",
    "File corrupted! This program has been manipulated and maybe\nit's infected by a Virus or cracked. This file won't work anymore.",
    "This code requires valid serial number to run.\nProgram will be terminated.",
    "This application cannot be executed on this computer.",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub input_file: String,
    pub output_file: String,
    pub vm_section_name: String,
    pub options: ProtectionOptions,
    pub functions: Vec<FunctionConfig>,
    pub messages: [String; MESSAGE_COUNT],
    pub licensing: Option<LicensingConfig>,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            input_file: String::new(),
            output_file: String::new(),
            vm_section_name: ".vmp".to_string(),
            options: ProtectionOptions::default(),
            functions: Vec::new(),
            messages: [
                DEFAULT_MESSAGES[0].to_string(),
                DEFAULT_MESSAGES[1].to_string(),
                DEFAULT_MESSAGES[2].to_string(),
                DEFAULT_MESSAGES[3].to_string(),
                DEFAULT_MESSAGES[4].to_string(),
            ],
            licensing: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ProtectionOptions {
    pub debug_mode: bool,
    pub crypt_values: bool,
    pub runner_crc: bool,
    pub encrypt_regs: bool,
    pub strip_fixups: bool,
    pub pack: bool,
    pub import_protection: bool,
    pub check_debugger: bool,
    pub check_virtual_machine: bool,
    pub memory_protection: bool,
    pub resource_protection: bool,
    pub check_kernel_debugger: bool,
    pub strip_debug_info: bool,
    pub classic_vm: bool,
    pub loader_crc: bool,
    pub encrypt_bytecode: bool,
    pub virtual_files: bool,
    pub internal_memory_protection: bool,
    pub loader: bool,
}

impl ProtectionOptions {
    pub const MAXIMUM_PROTECTION: u32 = 0x00000008 | 0x00000040 | 0x00000080 | 0x00040000;
}

impl Default for ProtectionOptions {
    fn default() -> Self {
        Self {
            debug_mode: false,
            crypt_values: true,
            runner_crc: true,
            encrypt_regs: true,
            strip_fixups: false,
            pack: true,
            import_protection: true,
            check_debugger: false,
            check_virtual_machine: false,
            memory_protection: false,
            resource_protection: false,
            check_kernel_debugger: false,
            strip_debug_info: true,
            classic_vm: false,
            loader_crc: false,
            encrypt_bytecode: false,
            virtual_files: false,
            internal_memory_protection: false,
            loader: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionConfig {
    pub id: String,
    pub name: String,
    pub address: u64,
    pub compilation_type: CompilationType,
    pub options: u32,
    pub folder: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum CompilationType {
    #[default]
    Default = 0,
    Mutation = 1,
    Virtualization = 2,
    Ultra = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensingConfig {
    pub license_file: String,
    pub activation_server: String,
    pub hwid: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum MessageType {
    DebuggerFound = 0,
    VirtualMachineFound = 1,
    FileCorrupted = 2,
    SerialNumberRequired = 3,
    HwidMismatched = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ProjectOption {
    DebugMode = 0x00000002,
    CryptValues = 0x00000008,
    RunnerCRC = 0x00000040,
    EncryptRegs = 0x00000080,
    StripFixups = 0x00008000,
    Pack = 0x00000100,
    ImportProtection = 0x00000200,
    CheckDebugger = 0x00000400,
    CheckVirtualMachine = 0x00000800,
    MemoryProtection = 0x00001000,
    ResourceProtection = 0x00010000,
    CheckKernelDebugger = 0x00020000,
    StripDebugInfo = 0x00040000,
    ClassicVM = 0x00080000,
    LoaderCRC = 0x10000000,
    EncryptBytecode = 0x80000000,
    VirtualFiles = 0x08000000,
    InternalMemoryProtection = 0x04000000,
    Loader = 0x02000000,
}

impl ProtectionOptions {
    pub fn from_bits(bits: u32) -> Self {
        Self {
            debug_mode: bits & 0x00000002 != 0,
            crypt_values: bits & 0x00000008 != 0,
            runner_crc: bits & 0x00000040 != 0,
            encrypt_regs: bits & 0x00000080 != 0,
            strip_fixups: bits & 0x00008000 != 0,
            pack: bits & 0x00000100 != 0,
            import_protection: bits & 0x00000200 != 0,
            check_debugger: bits & 0x00000400 != 0,
            check_virtual_machine: bits & 0x00000800 != 0,
            memory_protection: bits & 0x00001000 != 0,
            resource_protection: bits & 0x00010000 != 0,
            check_kernel_debugger: bits & 0x00020000 != 0,
            strip_debug_info: bits & 0x00040000 != 0,
            classic_vm: bits & 0x00080000 != 0,
            loader_crc: bits & 0x10000000 != 0,
            encrypt_bytecode: bits & 0x80000000 != 0,
            virtual_files: bits & 0x08000000 != 0,
            internal_memory_protection: bits & 0x04000000 != 0,
            loader: bits & 0x02000000 != 0,
        }
    }

    pub fn to_bits(&self) -> u32 {
        let mut bits = 0u32;
        if self.debug_mode { bits |= 0x00000002; }
        if self.crypt_values { bits |= 0x00000008; }
        if self.runner_crc { bits |= 0x00000040; }
        if self.encrypt_regs { bits |= 0x00000080; }
        if self.strip_fixups { bits |= 0x00008000; }
        if self.pack { bits |= 0x00000100; }
        if self.import_protection { bits |= 0x00000200; }
        if self.check_debugger { bits |= 0x00000400; }
        if self.check_virtual_machine { bits |= 0x00000800; }
        if self.memory_protection { bits |= 0x00001000; }
        if self.resource_protection { bits |= 0x00010000; }
        if self.check_kernel_debugger { bits |= 0x00020000; }
        if self.strip_debug_info { bits |= 0x00040000; }
        if self.classic_vm { bits |= 0x00080000; }
        if self.loader_crc { bits |= 0x10000000; }
        if self.encrypt_bytecode { bits |= 0x80000000; }
        if self.virtual_files { bits |= 0x08000000; }
        if self.internal_memory_protection { bits |= 0x04000000; }
        if self.loader { bits |= 0x02000000; }
        bits
    }
}
