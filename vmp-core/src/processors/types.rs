//! Processors 类型定义
//!
//! 从 C++ 的 proc_types.h 迁移

use bitflags::bitflags;

/// 命令类型别名
pub type CommandType = u32;

/// 操作数类型标志
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum OperandType {
    None = 0x0000,
    Value = 0x0001,
    Register = 0x0002,
    Memory = 0x0004,
    SegmentRegister = 0x0008,
    ControlRegister = 0x0010,
    DebugRegister = 0x0020,
    FPURegister = 0x0040,
    HiPartRegister = 0x0080,
    BaseRegister = 0x0100,
    MMXRegister = 0x0200,
    XMMRegister = 0x0400,
}

impl OperandType {
    pub fn contains(self, other: Self) -> bool {
        (self as u16) & (other as u16) != 0
    }
}

impl Default for OperandType {
    fn default() -> Self {
        Self::None
    }
}

bitflags! {
    /// 命令选项标志
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CommandOption: u32 {
        const InverseFlag = 0x0001;
        const LockPrefix = 0x0002;
        const Far = 0x0004;
        const VexPrefix = 0x0008;
        const Breaked = 0x0010;
        const ClearOriginalCode = 0x0020;
        const NeedCompile = 0x0040;
        const CreateNewBlock = 0x0080;
        const FillNop = 0x0100;
        const Internal = 0x0200;
        const NoNative = 0x0400;
        const NoSaveFlags = 0x0800;
        const Writable = 0x1000;
        const UseAsJmp = 0x2000;
        const NoProgress = 0x4000;
        const External = 0x8000;
        const NeedCRC = 0x10000;
        const InvalidOpcode = 0x20000;
        const DataSegment = 0x40000;
        const ImportSegment = 0x80000;
    }
}

/// VM 寄存器枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VMRegister {
    EFX = 16,
    ETX = 17,
    ERX = 18,
    EIX = 19,
    Empty = 20,
    Extended = 0x80,
}

/// 链接类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkType {
    None = 0,
    SEHBlock,
    FinallyBlock,
    DualSEHBlock,
    FilterSEHBlock,
    Jmp,
    JmpWithFlag,
    JmpWithFlagNSFS,
    JmpWithFlagNSNA,
    JmpWithFlagNSNS,
    Call,
    Case,
    Switch,
    Native,
    Offset,
    GateOffset,
    ExtSEHBlock,
    MemSEHBlock,
    ExtSEHHandler,
    VBMemSEHBlock,
    Delta,
}

impl Default for LinkType {
    fn default() -> Self {
        Self::None
    }
}

bitflags! {
    /// 节区选项
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SectionOption: u16 {
        const None = 0x0000;
        const LinkedToInt = 0x0001;
        const LinkedToExt = 0x0002;
        const LinkedFrom = 0x0004;
        const LinkedNext = 0x0008;
        const BeginSection = 0x0010;
        const EndSection = 0x0020;
        const CloseSection = 0x0040;
        const NoInverseResult = 0x0080;
        const InverseResult = 0x0100;
        const NoSaveFlags = 0x0200;
        const InverseWrite = 0x0400;
        const LinkedFromOtherType = 0x0800;
        const BackwardDirection = 0x1000;
    }
}

bitflags! {
    /// VM 命令选项
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct VMCommandOption: u16 {
        const None = 0x0000;
        const LinkCommand = 0x0001;
        const Fixup = 0x0002;
        const SectionCommand = 0x0004;
        const InverseValue = 0x0008;
        const UseBeginSectionCryptor = 0x0010;
        const UseEndSectionCryptor = 0x0020;
        const BeginOffset = 0x0040;
        const EndOffset = 0x0080;
        const InitOffset = 0x0100;
        const NoCRC = 0x0200;
        const NoCryptValue = 0x0400;
    }
}

/// 注释类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CommentType {
    Unknown = 0,
    None,
    Jmp,
    Function,
    Import,
    String,
    Variable,
    Comment,
    Export,
    Marker,
}

impl Default for CommentType {
    fn default() -> Self {
        Self::Unknown
    }
}

/// 访问类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AccessType {
    Read = 0,
    Write = 1,
}

/// 内部链接类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InternalLinkType {
    None = 0,
    CRCTableAddress,
    CRCTableCount,
    CRCValue,
}

impl Default for InternalLinkType {
    fn default() -> Self {
        Self::None
    }
}

/// 地址基类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressBaseType {
    Value = 0,
    ImageBase,
    FunctionBegin,
}

/// 加密命令类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CryptCommandType {
    Add = 0,
    Sub,
    Xor,
    Inc,
    Dec,
    Bswap,
    Rol,
    Ror,
    Not,
    Neg,
    Unknown,
}

impl Default for CryptCommandType {
    fn default() -> Self {
        Self::Add
    }
}

/// 入口类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryType {
    Default = 0,
    RandomAddress,
    None,
}

impl Default for EntryType {
    fn default() -> Self {
        Self::Default
    }
}

bitflags! {
    /// 编译选项
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CompilationOption: u32 {
        const LockToKey = 0x2000;
    }
}

/// 编译类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CompilationType {
    None = 0,
    Native,
    Virtualization,
    Mutation,
    Ultra,
}

impl Default for CompilationType {
    fn default() -> Self {
        Self::None
    }
}

/// 函数标签
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FunctionTag {
    None = 0,
    Licensing,
    Bundler,
    Registry,
    Resources,
    Loader,
    Processor,
}

impl Default for FunctionTag {
    fn default() -> Self {
        Self::None
    }
}

/// 命令标签
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CommandTag {
    None = 0,
    Mutant,
}

impl Default for CommandTag {
    fn default() -> Self {
        Self::None
    }
}

/// 注释信息
#[derive(Debug, Clone, Default)]
pub struct CommentInfo {
    pub value: String,
    pub comment_type: CommentType,
}

impl CommentInfo {
    pub fn new(comment_type: CommentType, value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            comment_type,
        }
    }

    pub fn display_value(&self) -> String {
        if self.value.is_empty() {
            return String::new();
        }
        // 如果第一个字符是控制字符(0-4)，则特殊处理
        if let Some(first) = self.value.chars().next() {
            if (first as u32) < 5 {
                return format!("{}{}", first as u8, &self.value[1..]);
            }
        }
        self.value.clone()
    }
}

/// 函数名结构
#[derive(Debug, Clone, Default)]
pub struct FunctionName {
    name: String,
    display_name: String,
}

impl FunctionName {
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        let display_name = name.clone();
        Self { name, display_name }
    }

    pub fn with_display(name: impl Into<String>, display: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            display_name: display.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

/// 操作数大小
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OperandSize {
    Default = 0,
    Byte = 1,
    Word = 2,
    DWord = 4,
    QWord = 8,
}

impl OperandSize {
    pub fn size_in_bytes(&self) -> usize {
        match self {
            Self::Default => 0,
            Self::Byte => 1,
            Self::Word => 2,
            Self::DWord => 4,
            Self::QWord => 8,
        }
    }
}

impl Default for OperandSize {
    fn default() -> Self {
        Self::Default
    }
}

/// 对象类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectType {
    Unknown = 0,
    Function,
    Command,
    VMCommand,
    Block,
    Link,
    Code,
    Data,
}

/// 命令块类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BlockType {
    Unknown = 0,
    Basic = 1,       // 基本块
    Loop = 2,        // 循环
    Condition = 3,   // 条件
    Switch = 4,      // Switch
    Entry = 5,       // 入口
    Exit = 6,        // 出口
    Data = 7,        // 数据
    Virtualized = 8, // 虚拟化块
}

impl Default for BlockType {
    fn default() -> Self {
        BlockType::Unknown
    }
}

impl Default for ObjectType {
    fn default() -> Self {
        Self::Unknown
    }
}

/// 消息类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Info = 0,
    Warning,
    Error,
    Debug,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operand_type() {
        let op = OperandType::Register;
        assert!(op.contains(OperandType::Register));
        assert!(!op.contains(OperandType::Memory));
    }

    #[test]
    fn test_command_option() {
        let opt = CommandOption::NeedCompile | CommandOption::Internal;
        assert!(opt.contains(CommandOption::NeedCompile));
        assert!(opt.contains(CommandOption::Internal));
        assert!(!opt.contains(CommandOption::External));
    }

    #[test]
    fn test_link_type_default() {
        let lt: LinkType = Default::default();
        assert_eq!(lt, LinkType::None);
    }

    #[test]
    fn test_comment_info() {
        let info = CommentInfo::new(CommentType::Function, "test_func");
        assert_eq!(info.comment_type, CommentType::Function);
        assert_eq!(info.value, "test_func");
    }

    #[test]
    fn test_function_name() {
        let name = FunctionName::with_display("internal_name", "显示名称");
        assert_eq!(name.name(), "internal_name");
        assert_eq!(name.display_name(), "显示名称");
    }

    #[test]
    fn test_operand_size() {
        assert_eq!(OperandSize::Byte.size_in_bytes(), 1);
        assert_eq!(OperandSize::DWord.size_in_bytes(), 4);
        assert_eq!(OperandSize::QWord.size_in_bytes(), 8);
    }
}
