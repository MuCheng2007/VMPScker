//! Processors 接口定义
//!
//! 从 C++ 的 proc_interfaces.h 迁移

use crate::error::Result;
use super::types::*;
use std::any::Any;
use std::collections::HashMap;

/// 文件接口 - 简化的文件操作 trait
/// 
/// 用于 processors 模块的文件写入操作
pub trait File: Any + Send + Sync {
    /// 写入 u64
    fn write_u64(&mut self, value: u64) -> Result<()>;
    /// 写入 u32
    fn write_u32(&mut self, value: u32) -> Result<()>;
    /// 写入 u16
    fn write_u16(&mut self, value: u16) -> Result<()>;
    /// 写入 u8
    fn write_u8(&mut self, value: u8) -> Result<()>;
    /// 写入字节切片
    fn write_bytes(&mut self, data: &[u8]) -> Result<()>;
    /// 获取当前位置
    fn position(&self) -> u64;
    /// 设置位置
    fn set_position(&mut self, pos: u64) -> Result<()>;
    
    /// 读取字节到缓冲区
    fn read_bytes(&mut self, buffer: &mut [u8]) -> Result<usize>;
    /// 读取 u64
    fn read_u64(&mut self) -> Result<u64>;
    /// 读取 u32
    fn read_u32(&mut self) -> Result<u32>;
    /// 读取 u16
    fn read_u16(&mut self) -> Result<u16>;
    /// 读取 u8
    fn read_u8(&mut self) -> Result<u8>;
}

/// 字节列表类型
pub type ByteList = Vec<u8>;

/// VM 命令接口
/// 
/// 对应 C++ 的 IVMCommand
pub trait IVMCommand: Any + Send + Sync {
    /// 写入文件
    fn write_to_file(&self, file: &mut dyn File) -> Result<()>;
    
    /// 编译命令
    fn compile(&mut self);
    
    /// 获取转储大小
    fn dump_size(&self) -> usize;
    
    /// 设置地址
    fn set_address(&mut self, address: u64);
    
    /// 获取地址
    fn address(&self) -> u64;
    
    /// 获取所属命令
    fn owner(&self) -> Option<&dyn ICommand>;
    
    /// 是否是结束命令
    fn is_end(&self) -> bool;
    
    /// 作为 Any 类型
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// 命令接口
/// 
/// 对应 C++ 的 ICommand
pub trait ICommand: Any + Send + Sync {
    /// 获取地址
    fn address(&self) -> u64;
    
    /// 获取下一个地址
    fn next_address(&self) -> u64 {
        self.address() + self.dump_size() as u64
    }
    
    /// 获取命令类型
    fn command_type(&self) -> CommandType;
    
    /// 获取文本表示
    fn text(&self) -> String;
    
    /// 获取注释
    fn comment(&self) -> CommentInfo;
    
    /// 设置注释
    fn set_comment(&mut self, comment: CommentInfo);
    
    /// 获取选项
    fn options(&self) -> CommandOption;
    
    /// 获取链接
    fn link(&self) -> Option<&dyn ICommandLink>;
    
    /// 设置链接
    fn set_link(&mut self, link: Option<Box<dyn ICommandLink>>);
    
    /// 获取转储字节
    fn dump(&self, index: usize) -> Option<u8>;
    
    /// 获取转储大小
    fn dump_size(&self) -> usize;
    
    /// 获取转储字符串
    fn dump_str(&self) -> String {
        let mut result = String::new();
        for i in 0..self.dump_size() {
            if let Some(byte) = self.dump(i) {
                result.push_str(&format!("{:02X} ", byte));
            }
        }
        result.trim_end().to_string()
    }
    
    /// 获取原始转储大小
    fn original_dump_size(&self) -> usize;
    
    /// 获取 VM 转储大小
    fn vm_dump_size(&self) -> usize;
    
    /// 清空命令
    fn clear(&mut self);
    
    /// 编译为原生代码
    fn compile_to_native(&mut self);
    
    /// 编译链接
    fn compile_link(&mut self, ctx: &CompileContext);
    
    /// 准备链接
    fn prepare_link(&mut self, ctx: &CompileContext);
    
    /// 编译信息
    fn compile_info(&mut self);
    
    /// 设置操作数值
    fn set_operand_value(&mut self, operand_index: usize, value: u64);
    
    /// 设置链接值
    fn set_link_value(&mut self, link_index: usize, value: u64);
    
    /// 设置跳转值
    fn set_jmp_value(&mut self, link_index: usize, value: u64);
    
    /// 设置地址
    fn set_address(&mut self, address: u64);
    
    /// 获取 VM 地址
    fn vm_address(&self) -> u64;
    
    /// 获取外部 VM 地址
    fn ext_vm_address(&self) -> u64 {
        self.vm_address()
    }
    
    /// 设置 VM 地址
    fn set_vm_address(&mut self, address: u64);
    
    /// 从缓冲区读取
    fn read_from_buffer(&mut self, buffer: &[u8], file: &dyn File) -> Result<usize>;
    
    /// 获取对齐
    fn alignment(&self) -> usize;
    
    /// 获取所属块
    fn block(&self) -> Option<&dyn ICommandBlock>;
    
    /// 设置所属块
    fn set_block(&mut self, block: Option<Box<dyn ICommandBlock>>);
    
    /// 重新基址
    fn rebase(&mut self, delta_base: u64);
    
    /// 获取所属函数
    fn owner(&self) -> Option<&dyn IFunction>;
    
    /// 克隆命令
    fn clone_command(&self, owner: Box<dyn IFunction>) -> Box<dyn ICommand>;
    
    /// 添加链接
    fn add_link_to_command(&mut self, operand_index: i32, link_type: LinkType, to_command: Box<dyn ICommand>) -> Box<dyn ICommandLink>;
    
    /// 添加链接到地址
    fn add_link_to_address(&mut self, operand_index: i32, link_type: LinkType, to_address: u64) -> Box<dyn ICommandLink>;
    
    /// 包含节区选项
    fn include_section_option(&mut self, option: SectionOption);
    
    /// 获取节区选项
    fn section_options(&self) -> SectionOption;
    
    /// 是否是数据
    fn is_data(&self) -> bool;
    
    /// 是否是结束
    fn is_end(&self) -> bool;
    
    /// 包含选项
    fn include_option(&mut self, value: CommandOption);
    
    /// 排除选项
    fn exclude_option(&mut self, value: CommandOption);
    
    /// 获取显示地址
    fn display_address(&self) -> String {
        format!("0x{:016X}", self.address())
    }
    
    /// 设置标签
    fn set_tag(&mut self, tag: u8);
    
    /// 获取标签
    fn tag(&self) -> u8;
    
    /// 合并命令
    fn merge(&mut self, command: Box<dyn ICommand>) -> bool;
    
    /// 作为 Any 类型
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// 命令链接接口
/// 
/// 对应 CommandLink
pub trait ICommandLink: Any + Send + Sync {
    /// 获取链接类型
    fn link_type(&self) -> LinkType;
    
    /// 获取操作数索引
    fn operand_index(&self) -> i32;
    
    /// 获取目标命令
    fn to_command(&self) -> Option<&dyn ICommand>;
    
    /// 获取目标地址
    fn to_address(&self) -> u64;
    
    /// 编译链接
    fn compile_link(&mut self, ctx: &CompileContext);
    
    /// 重新基址
    fn rebase(&mut self, delta_base: u64);
    
    /// 作为 Any 类型
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// 命令块接口
/// 
/// 对应 CommandBlock
pub trait ICommandBlock: Any + Send + Sync {
    /// 获取起始索引
    fn start_index(&self) -> usize;
    
    /// 获取命令数量
    fn command_count(&self) -> usize;
    
    /// 是否可执行
    fn is_executable(&self) -> bool;
    
    /// 编译块
    fn compile(&mut self, ctx: &CompileContext) -> Result<()>;
    
    /// 写入文件
    fn write_to_file(&self, file: &mut dyn File) -> Result<()>;
    
    /// 添加命令
    fn add_command(&mut self, command: Box<dyn ICommand>);
    
    /// 获取命令
    fn get_command(&self, index: usize) -> Option<&dyn ICommand>;
    
    /// 作为 Any 类型
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// 函数接口
/// 
/// 对应 C++ 的 IFunction
pub trait IFunction: Any + Send + Sync {
    /// 获取地址
    fn address(&self) -> u64;
    
    /// 获取断点地址
    fn break_address(&self) -> u64;
    
    /// 获取对象类型
    fn object_type(&self) -> ObjectType;
    
    /// 获取入口类型
    fn entry_type(&self) -> EntryType;
    
    /// 获取入口命令
    fn entry(&self) -> Option<&dyn ICommand>;
    
    /// 获取名称
    fn name(&self) -> &str;
    
    /// 获取显示名称
    fn display_name(&self) -> &str;
    
    /// 获取完整名称
    fn full_name(&self) -> &FunctionName;
    
    /// 获取 CPU 地址大小
    fn cpu_address_size(&self) -> OperandSize;
    
    /// 是否需要编译
    fn need_compile(&self) -> bool;
    
    /// 获取编译类型
    fn compilation_type(&self) -> CompilationType;
    
    /// 获取默认编译类型
    fn default_compilation_type(&self) -> CompilationType;
    
    /// 获取编译选项
    fn compilation_options(&self) -> u32;
    
    /// 设置断点地址
    fn set_break_address(&mut self, address: u64);
    
    /// 是否是断点地址
    fn is_breaked_address(&self, address: u64) -> bool;
    
    /// 设置编译类型
    fn set_compilation_type(&mut self, compilation_type: CompilationType);
    
    /// 设置编译选项
    fn set_compilation_options(&mut self, options: u32);
    
    /// 设置是否需要编译
    fn set_need_compile(&mut self, need_compile: bool);
    
    /// 设置标签
    fn set_tag(&mut self, tag: u8);
    
    /// 获取标签
    fn tag(&self) -> u8;
    
    /// 是否来自运行时
    fn from_runtime(&self) -> bool;
    
    /// 设置是否来自运行时
    fn set_from_runtime(&mut self, from_runtime: bool);
    
    /// 从文件读取
    fn read_from_file(&mut self, file: &dyn File, address: u64) -> Result<usize>;
    
    /// 写入文件
    fn write_to_file(&self, file: &mut dyn File) -> Result<()>;
    
    /// 初始化
    fn init(&mut self, ctx: &CompileContext) -> Result<()>;
    
    /// 准备
    fn prepare(&mut self, ctx: &CompileContext) -> Result<()>;
    
    /// 编译
    fn compile(&mut self, ctx: &CompileContext) -> Result<()>;
    
    /// 编译后处理
    fn after_compile(&mut self, ctx: &CompileContext);
    
    /// 编译链接
    fn compile_links(&mut self, ctx: &CompileContext);
    
    /// 编译信息
    fn compile_info(&mut self, ctx: &CompileContext);
    
    /// 按地址获取命令
    fn get_command_by_address(&self, address: u64) -> Option<&dyn ICommand>;
    
    /// 按近似地址获取命令
    fn get_command_by_near_address(&self, address: u64) -> Option<&dyn ICommand>;
    
    /// 从缓冲区读取
    fn read_from_buffer(&mut self, buffer: &[u8], file: &dyn File) -> Result<()>;
    
    /// 重新基址
    fn rebase(&mut self, delta_base: u64);
    
    /// 获取内存类型
    fn memory_type(&self) -> u32;
    
    /// 设置内存类型
    fn set_memory_type(&mut self, memory_type: u32);
    
    /// 解析命令
    fn parse_command(&mut self, file: &dyn File, address: u64, dump_mode: bool) -> Option<Box<dyn ICommand>>;
    
    /// 添加块
    fn add_block(&mut self, start_index: usize, is_executable: bool) -> Box<dyn ICommandBlock>;
    
    /// 添加命令
    fn add_command(&mut self, data: &[u8]) -> Box<dyn ICommand>;
    
    /// 添加数值命令
    fn add_value_command(&mut self, value_size: OperandSize, value: u64) -> Box<dyn ICommand>;
    
    /// 作为 Any 类型
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// 函数列表接口
/// 
/// 对应 C++ 的 IFunctionList
pub trait IFunctionList: Any + Send + Sync {
    /// 添加函数
    fn add(&mut self, name: &str, compilation_type: CompilationType, options: u32, need_compile: bool) -> Box<dyn IFunction>;
    
    /// 按地址获取函数
    fn get_function_by_address(&self, address: u64) -> Option<&dyn IFunction>;
    
    /// 按名称获取函数
    fn get_function_by_name(&self, name: &str) -> Option<&dyn IFunction>;
    
    /// 按地址获取命令
    fn get_command_by_address(&self, address: u64, need_compile: bool) -> Option<&dyn ICommand>;
    
    /// 按近似地址获取命令
    fn get_command_by_near_address(&self, address: u64, need_compile: bool) -> Option<&dyn ICommand>;
    
    /// 准备所有函数
    fn prepare_all(&mut self, ctx: &CompileContext) -> Result<()>;
    
    /// 编译所有函数
    fn compile_all(&mut self, ctx: &CompileContext) -> Result<()>;
    
    /// 编译所有链接
    fn compile_all_links(&mut self, ctx: &CompileContext);
    
    /// 从缓冲区读取
    fn read_from_buffer(&mut self, buffer: &[u8], file: &dyn File) -> Result<()>;
    
    /// 重新基址
    fn rebase(&mut self, delta_base: u64);
    
    /// 创建函数
    fn create_function(&self, cpu_address_size: OperandSize) -> Box<dyn IFunction>;
    
    /// 作为 Any 类型
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// 虚拟机接口
/// 
/// 对应 C++ 的 IVirtualMachine
pub trait IVirtualMachine: Any + Send + Sync {
    /// 获取 VM ID
    fn id(&self) -> u8;
    
    /// 获取寄存器顺序
    fn register_order(&self) -> &[u8];
    
    /// 是否反向
    fn backward_direction(&self) -> bool;
    
    /// 获取处理器函数
    fn processor(&self) -> Option<&dyn IFunction>;
    
    /// 作为 Any 类型
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// 虚拟机列表接口
/// 
/// 对应 C++ 的 IVirtualMachineList
pub trait IVirtualMachineList: Any + Send + Sync {
    /// 克隆
    fn clone_list(&self) -> Box<dyn IVirtualMachineList>;
    
    /// 准备
    fn prepare(&mut self, ctx: &CompileContext);
    
    /// 添加虚拟机
    fn add_vm(&mut self, vm: Box<dyn IVirtualMachine>);
    
    /// 获取虚拟机
    fn get_vm(&self, id: u8) -> Option<&dyn IVirtualMachine>;
    
    /// 作为 Any 类型
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// 编译上下文
#[derive(Debug, Clone)]
pub struct CompileContext {
    /// 图像基址
    pub image_base: u64,
    /// 是否调试模式
    pub debug_mode: bool,
    /// 编译选项
    pub options: u32,
    /// 其他上下文数据
    pub data: HashMap<String, Vec<u8>>,
}

impl Default for CompileContext {
    fn default() -> Self {
        Self {
            image_base: 0x140000000,
            debug_mode: false,
            options: 0,
            data: HashMap::new(),
        }
    }
}

impl CompileContext {
    pub fn new(image_base: u64) -> Self {
        Self {
            image_base,
            ..Default::default()
        }
    }
    
    pub fn with_debug_mode(mut self, debug: bool) -> Self {
        self.debug_mode = debug;
        self
    }
    
    pub fn with_options(mut self, options: u32) -> Self {
        self.options = options;
        self
    }
}

/// 文件夹结构 (简化)
#[derive(Debug, Clone)]
pub struct Folder {
    pub name: String,
    pub parent: Option<Box<Folder>>,
}

impl Folder {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            parent: None,
        }
    }
}

/// 地址范围
#[derive(Debug, Clone, Copy)]
pub struct AddressRange {
    pub start: u64,
    pub end: u64,
}

impl AddressRange {
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }
    
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start && address < self.end
    }
    
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

/// 函数信息
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub address: u64,
    pub size: u64,
    pub name: String,
}

impl FunctionInfo {
    pub fn new(address: u64, size: u64, name: impl Into<String>) -> Self {
        Self {
            address,
            size,
            name: name.into(),
        }
    }
}

/// 命令信息
#[derive(Debug, Clone)]
pub struct CommandInfo {
    pub address: u64,
    pub command_type: CommandType,
    pub access_type: AccessType,
}

impl CommandInfo {
    pub fn new(address: u64, command_type: CommandType, access_type: AccessType) -> Self {
        Self {
            address,
            command_type,
            access_type,
        }
    }
}

/// 值加密器 trait
pub trait ValueCryptor: Any + Send + Sync {
    /// 加密值
    fn encrypt(&self, value: u64) -> u64;
    /// 解密值
    fn decrypt(&self, value: u64) -> u64;
}

/// 加密器 trait (用于命令链接)
pub trait ICryptor: Any + Send + Sync {
    /// 加密 u64 值
    fn encrypt(&self, value: u64) -> u64;
    /// 解密 u64 值
    fn decrypt(&self, value: u64) -> u64;
    /// 克隆加密器
    fn clone_cryptor(&self) -> Box<dyn ICryptor>;
}

impl Clone for Box<dyn ICryptor> {
    fn clone(&self) -> Self {
        self.clone_cryptor()
    }
}

/// SEH 处理器接口
pub trait ISEHandler: Any + Send + Sync {
    /// 获取处理地址
    fn handler_address(&self) -> u64;
    /// 设置处理地址
    fn set_handler_address(&mut self, address: u64);
    /// 作为 Any 类型
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_context() {
        let ctx = CompileContext::new(0x10000000)
            .with_debug_mode(true)
            .with_options(0x1234);
        
        assert_eq!(ctx.image_base, 0x10000000);
        assert!(ctx.debug_mode);
        assert_eq!(ctx.options, 0x1234);
    }

    #[test]
    fn test_address_range() {
        let range = AddressRange::new(0x1000, 0x2000);
        assert!(range.contains(0x1500));
        assert!(!range.contains(0x2000));
        assert!(!range.contains(0x0FFF));
        assert_eq!(range.size(), 0x1000);
    }

    #[test]
    fn test_function_info() {
        let info = FunctionInfo::new(0x1000, 0x100, "test_func");
        assert_eq!(info.address, 0x1000);
        assert_eq!(info.size, 0x100);
        assert_eq!(info.name, "test_func");
    }
}
