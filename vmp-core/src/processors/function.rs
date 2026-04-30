//! Processors 函数管理
//!
//! 从 C++ 的 proc_function.h/cc 迁移

use crate::error::{Result, VmpError};
use super::types::*;
use super::interfaces::*;
use super::command::{BaseCommand, CommandList};
use super::command_link::CommandLinkList;
use super::command_block::{CommandBlock, CommandBlockList, ExtCommandList};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

/// 地址范围信息
#[derive(Clone, Default)]
pub struct AddressRangeInfo {
    /// 起始地址
    pub start: u64,
    /// 结束地址
    pub end: u64,
    /// 大小
    pub size: u64,
    /// 入口命令
    pub begin_entry: Option<Arc<dyn ICommand>>,
    /// 结束命令
    pub end_entry: Option<Arc<dyn ICommand>>,
    /// 大小命令
    pub size_entry: Option<Arc<dyn ICommand>>,
}

impl std::fmt::Debug for AddressRangeInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddressRangeInfo")
            .field("start", &self.start)
            .field("end", &self.end)
            .field("size", &self.size)
            .field("has_begin_entry", &self.begin_entry.is_some())
            .field("has_end_entry", &self.end_entry.is_some())
            .field("has_size_entry", &self.size_entry.is_some())
            .finish()
    }
}

impl AddressRangeInfo {
    pub fn new(start: u64, end: u64) -> Self {
        Self {
            start,
            end,
            size: end.saturating_sub(start),
            begin_entry: None,
            end_entry: None,
            size_entry: None,
        }
    }

    pub fn contains(&self, address: u64) -> bool {
        address >= self.start && address < self.end
    }
}

/// 函数信息
#[derive(Clone, Default)]
pub struct FunctionInfo {
    /// 地址
    pub address: u64,
    /// 大小
    pub size: u64,
    /// 入口命令
    pub entry: Option<Arc<dyn ICommand>>,
    /// 数据入口
    pub data_entry: Option<Arc<dyn ICommand>>,
    /// 展开操作码
    pub unwind_opcodes: Vec<Arc<dyn ICommand>>,
}

impl std::fmt::Debug for FunctionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FunctionInfo")
            .field("address", &self.address)
            .field("size", &self.size)
            .field("has_entry", &self.entry.is_some())
            .field("has_data_entry", &self.data_entry.is_some())
            .field("unwind_opcodes_count", &self.unwind_opcodes.len())
            .finish()
    }
}

impl FunctionInfo {
    pub fn new(address: u64, size: u64) -> Self {
        Self {
            address,
            size,
            entry: None,
            data_entry: None,
            unwind_opcodes: Vec::new(),
        }
    }
}

/// 函数信息列表
#[derive(Debug, Clone, Default)]
pub struct FunctionInfoList {
    infos: Vec<FunctionInfo>,
}

impl FunctionInfoList {
    pub fn new() -> Self {
        Self { infos: Vec::new() }
    }

    pub fn add(&mut self, info: FunctionInfo) -> &mut FunctionInfo {
        self.infos.push(info);
        self.infos.last_mut().unwrap()
    }

    pub fn get(&self, index: usize) -> Option<&FunctionInfo> {
        self.infos.get(index)
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut FunctionInfo> {
        self.infos.get_mut(index)
    }

    pub fn len(&self) -> usize {
        self.infos.len()
    }

    pub fn is_empty(&self) -> bool {
        self.infos.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &FunctionInfo> {
        self.infos.iter()
    }

    pub fn clear(&mut self) {
        self.infos.clear();
    }
}

/// 函数基类
///
/// 对应 C++ 的 BaseFunction
pub struct BaseFunction {
    /// 地址
    address: u64,
    /// 断点地址
    break_address: u64,
    /// 对象类型
    object_type: ObjectType,
    /// 入口类型
    entry_type: EntryType,
    /// 入口命令
    entry: Option<Arc<dyn ICommand>>,
    /// 名称
    name: FunctionName,
    /// CPU 地址大小
    cpu_address_size: OperandSize,
    /// 链接列表
    link_list: CommandLinkList,
    /// 外部命令列表
    ext_command_list: ExtCommandList,
    /// 块列表
    block_list: CommandBlockList,
    /// 命令列表
    commands: CommandList,
    /// 是否需要编译
    need_compile: bool,
    /// 编译类型
    compilation_type: CompilationType,
    /// 默认编译类型
    default_compilation_type: CompilationType,
    /// 编译选项
    compilation_options: u32,
    /// 内存类型
    memory_type: u32,
    /// 标签
    tag: u8,
    /// 是否来自运行时
    from_runtime: bool,
    /// 内部锁定到密钥
    internal_lock_to_key: bool,
    /// 地址到命令的映射
    command_map: HashMap<u64, usize>, // address -> index in commands
    /// 父函数
    parent: Option<Arc<BaseFunction>>,
    /// 范围列表
    range_list: AddressRangeInfo,
    /// 函数信息列表
    function_info_list: FunctionInfoList,
    /// 哈希值 (用于校验)
    hash_value: u64,
}

impl BaseFunction {
    /// 创建新函数
    pub fn new(name: FunctionName, compilation_type: CompilationType, options: u32, need_compile: bool) -> Self {
        Self {
            address: 0,
            break_address: 0,
            object_type: ObjectType::Function,
            entry_type: EntryType::Default,
            entry: None,
            name,
            cpu_address_size: OperandSize::QWord,
            link_list: CommandLinkList::new(),
            ext_command_list: ExtCommandList::new(),
            block_list: CommandBlockList::new(),
            commands: CommandList::new(),
            need_compile,
            compilation_type,
            default_compilation_type: CompilationType::None,
            compilation_options: options,
            memory_type: 0,
            tag: 0,
            from_runtime: false,
            internal_lock_to_key: false,
            command_map: HashMap::new(),
            parent: None,
            range_list: AddressRangeInfo::default(),
            function_info_list: FunctionInfoList::new(),
            hash_value: 0,
        }
    }

    /// 从地址创建
    pub fn from_address(address: u64, compilation_type: CompilationType, options: u32, need_compile: bool) -> Self {
        let name = FunctionName::new(format!("func_{:016X}", address));
        let mut func = Self::new(name, compilation_type, options, need_compile);
        func.address = address;
        func
    }

    /// 从 CPU 地址大小创建 (用于子函数)
    pub fn from_cpu_address_size(cpu_address_size: OperandSize, parent: Arc<BaseFunction>) -> Self {
        let name = FunctionName::new("child_func");
        let mut func = Self::new(name, CompilationType::Virtualization, 0, true);
        func.cpu_address_size = cpu_address_size;
        func.object_type = ObjectType::Code;
        func.memory_type = 0x1; // mtReadable
        func.parent = Some(parent);
        func
    }

    // Getters
    pub fn address(&self) -> u64 { self.address }
    pub fn break_address(&self) -> u64 { self.break_address }
    pub fn object_type(&self) -> ObjectType { self.object_type }
    pub fn entry_type(&self) -> EntryType { self.entry_type }
    pub fn entry(&self) -> Option<&Arc<dyn ICommand>> { self.entry.as_ref() }
    pub fn name(&self) -> &str { self.name.name() }
    pub fn display_name(&self) -> &str { self.name.display_name() }
    pub fn full_name(&self) -> &FunctionName { &self.name }
    pub fn cpu_address_size(&self) -> OperandSize { self.cpu_address_size }
    pub fn need_compile(&self) -> bool { self.need_compile }
    pub fn compilation_type(&self) -> CompilationType {
        if self.default_compilation_type != CompilationType::None {
            self.default_compilation_type
        } else {
            self.compilation_type
        }
    }
    pub fn default_compilation_type(&self) -> CompilationType { self.default_compilation_type }
    pub fn compilation_options(&self) -> u32 {
        self.compilation_options | if self.internal_lock_to_key { 0x2000 } else { 0 }
    }
    pub fn memory_type(&self) -> u32 { self.memory_type }
    pub fn tag(&self) -> u8 { self.tag }
    pub fn from_runtime(&self) -> bool { self.from_runtime }

    // Setters
    pub fn set_address(&mut self, address: u64) { self.address = address; }
    pub fn set_break_address(&mut self, address: u64) { self.break_address = address; }
    pub fn set_entry_type(&mut self, entry_type: EntryType) { self.entry_type = entry_type; }
    pub fn set_entry(&mut self, entry: Option<Arc<dyn ICommand>>) { self.entry = entry; }
    pub fn set_need_compile(&mut self, need: bool) { self.need_compile = need; }
    pub fn set_compilation_type(&mut self, compilation_type: CompilationType) { self.compilation_type = compilation_type; }
    pub fn set_default_compilation_type(&mut self, compilation_type: CompilationType) { self.default_compilation_type = compilation_type; }
    pub fn set_compilation_options(&mut self, options: u32) { self.compilation_options = options; }
    pub fn set_memory_type(&mut self, memory_type: u32) { self.memory_type = memory_type; }
    pub fn set_tag(&mut self, tag: u8) { self.tag = tag; }
    pub fn set_from_runtime(&mut self, from_runtime: bool) { self.from_runtime = from_runtime; }
    pub fn set_cpu_address_size(&mut self, size: OperandSize) { self.cpu_address_size = size; }

    /// 是否是断点地址
    pub fn is_breaked_address(&self, address: u64) -> bool {
        if self.break_address == 0 {
            false
        } else {
            address >= self.break_address
        }
    }

    /// 获取链接列表
    pub fn link_list(&self) -> &CommandLinkList { &self.link_list }
    pub fn link_list_mut(&mut self) -> &mut CommandLinkList { &mut self.link_list }

    /// 获取外部命令列表
    pub fn ext_command_list(&self) -> &ExtCommandList { &self.ext_command_list }
    pub fn ext_command_list_mut(&mut self) -> &mut ExtCommandList { &mut self.ext_command_list }

    /// 获取块列表
    pub fn block_list(&self) -> &CommandBlockList { &self.block_list }
    pub fn block_list_mut(&mut self) -> &mut CommandBlockList { &mut self.block_list }

    /// 获取命令列表
    pub fn commands(&self) -> &CommandList { &self.commands }
    pub fn commands_mut(&mut self) -> &mut CommandList { &mut self.commands }

    /// 添加命令
    pub fn add_command(&mut self, command: Box<dyn ICommand>) -> &mut dyn ICommand {
        let address = command.address();
        let index = self.commands.len();
        let cmd_ref = self.commands.add(command);
        self.command_map.insert(address, index);
        cmd_ref
    }

    /// 添加数据命令
    pub fn add_data_command(&mut self, data: &[u8]) -> &mut dyn ICommand {
        let mut cmd = BaseCommand::from_data(data);
        // Set address based on last command or function address
        let addr = if let Some(last) = self.commands.get(self.commands.len().saturating_sub(1)) {
            last.next_address()
        } else {
            self.address
        };
        cmd.set_address(addr);
        self.add_command(Box::new(cmd))
    }

    /// 添加数值命令
    pub fn add_value_command(&mut self, size: OperandSize, value: u64) -> &mut dyn ICommand {
        let data = match size {
            OperandSize::Byte => vec![value as u8],
            OperandSize::Word => (value as u16).to_le_bytes().to_vec(),
            OperandSize::DWord => (value as u32).to_le_bytes().to_vec(),
            OperandSize::QWord => value.to_le_bytes().to_vec(),
            _ => vec![],
        };
        self.add_data_command(&data)
    }

    /// 按地址获取命令
    pub fn get_command_by_address(&self, address: u64) -> Option<&dyn ICommand> {
        self.command_map.get(&address).and_then(|&idx| self.commands.get(idx))
    }

    /// 按近似地址获取命令 (C++ GetCommandByNearAddress)
    pub fn get_command_by_near_address(&self, address: u64) -> Option<&dyn ICommand> {
        // 首先尝试获取小于等于该地址的命令
        let cmd = self.get_command_by_lower_address(address);
        if let Some(c) = cmd {
            // 检查地址是否在命令范围内
            if c.address() <= address && c.address() + c.original_dump_size() as u64 > address {
                return Some(c);
            }
        }
        None
    }

    /// 获取小于等于指定地址的命令 (C++ GetCommandByLowerAddress)
    pub fn get_command_by_lower_address(&self, address: u64) -> Option<&dyn ICommand> {
        if self.command_map.is_empty() {
            return None;
        }

        // 找到第一个大于 address 的键
        let mut best_addr = 0u64;
        let mut found = false;

        for (&addr, _) in &self.command_map {
            if addr <= address {
                if !found || addr > best_addr {
                    best_addr = addr;
                    found = true;
                }
            }
        }

        if found {
            self.command_map.get(&best_addr).and_then(|&idx| self.commands.get(idx))
        } else {
            None
        }
    }

    /// 获取大于指定地址的命令 (C++ GetCommandByUpperAddress)
    pub fn get_command_by_upper_address(&self, address: u64) -> Option<&dyn ICommand> {
        if self.command_map.is_empty() {
            return None;
        }

        let mut best_addr = u64::MAX;
        let mut found = false;

        for (&addr, _) in &self.command_map {
            if addr > address {
                if !found || addr < best_addr {
                    best_addr = addr;
                    found = true;
                }
            }
        }

        if found {
            self.command_map.get(&best_addr).and_then(|&idx| self.commands.get(idx))
        } else {
            None
        }
    }

    /// 添加对象 (C++ AddObject)
    pub fn add_object(&mut self, command: Box<dyn ICommand>) {
        let address = command.address();
        let index = self.commands.len();
        self.commands.add(command);
        if address != 0 {
            self.command_map.insert(address, index);
        }
    }

    /// 移除对象 (C++ RemoveObject)
    pub fn remove_object(&mut self, command: &dyn ICommand) {
        let addr = command.address();
        self.command_map.remove(&addr);
        // Note: 实际上从 CommandList 中移除比较复杂，因为需要保持索引一致性
        // 这里简化处理，只从 map 中移除
    }

    /// 清空函数 (C++ clear)
    pub fn clear(&mut self) {
        self.commands.clear();
        self.command_map.clear();
        self.link_list.clear();
        self.ext_command_list.clear();
        self.block_list.clear();
        self.function_info_list.clear();
        self.entry = None;
        self.hash_value = 0;
    }

    /// 计算哈希 (C++ hash)
    pub fn calculate_hash(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.address.hash(&mut hasher);
        self.name.name().hash(&mut hasher);
        self.compilation_type.hash(&mut hasher);
        hasher.finish()
    }

    /// 获取哈希值
    pub fn hash(&self) -> u64 {
        self.hash_value
    }

    /// 设置哈希值
    pub fn set_hash(&mut self, hash: u64) {
        self.hash_value = hash;
    }

    /// 验证哈希 (C++ check_hash)
    pub fn check_hash(&self) -> bool {
        self.hash_value == self.calculate_hash()
    }

    /// 获取父函数
    pub fn parent(&self) -> Option<&Arc<BaseFunction>> {
        self.parent.as_ref()
    }

    /// 设置父函数
    pub fn set_parent(&mut self, parent: Option<Arc<BaseFunction>>) {
        self.parent = parent;
    }

    /// 获取范围列表
    pub fn range_list(&self) -> &AddressRangeInfo {
        &self.range_list
    }

    /// 获取可变范围列表
    pub fn range_list_mut(&mut self) -> &mut AddressRangeInfo {
        &mut self.range_list
    }

    /// 获取函数信息列表
    pub fn function_info_list(&self) -> &FunctionInfoList {
        &self.function_info_list
    }

    /// 获取可变函数信息列表
    pub fn function_info_list_mut(&mut self) -> &mut FunctionInfoList {
        &mut self.function_info_list
    }

    /// 添加块
    pub fn add_block(&mut self, start_index: usize, block_type: BlockType) -> &mut CommandBlock {
        self.block_list.create(start_index, block_type)
    }

    /// 初始化
    pub fn init(&mut self, _ctx: &CompileContext) -> Result<()> {
        // Build command map
        self.command_map.clear();
        for i in 0..self.commands.len() {
            if let Some(cmd) = self.commands.get(i) {
                self.command_map.insert(cmd.address(), i);
            }
        }
        Ok(())
    }

    /// 准备
    pub fn prepare(&mut self, _ctx: &CompileContext) -> Result<()> {
        // Prepare external commands and links
        self.prepare_ext_commands(_ctx)?;
        self.prepare_links(_ctx)?;
        Ok(())
    }

    /// 准备外部命令
    pub fn prepare_ext_commands(&mut self, _ctx: &CompileContext) -> Result<()> {
        // Implementation for preparing external commands
        Ok(())
    }

    /// 准备链接
    pub fn prepare_links(&mut self, _ctx: &CompileContext) -> Result<()> {
        // Implementation for preparing links
        Ok(())
    }

    /// 编译
    pub fn compile(&mut self, ctx: &CompileContext) -> Result<()> {
        if !self.need_compile {
            return Ok(());
        }

        // Compile blocks
        for i in 0..self.block_list.len() {
            if let Some(block) = self.block_list.get_mut(i) {
                block.compile(ctx)?;
            }
        }

        // Compile external commands
        self.ext_command_list.compile_all(ctx)?;

        // Compile links
        self.compile_links(ctx);

        Ok(())
    }

    /// 编译后处理
    pub fn after_compile(&mut self, _ctx: &CompileContext) {
        // Post-compilation processing
    }

    /// 编译链接
    pub fn compile_links(&mut self, ctx: &CompileContext) {
        let _ = self.link_list.compile_all(ctx);
    }

    /// 编译信息
    pub fn compile_info(&mut self, _ctx: &CompileContext) {
        for i in 0..self.block_list.len() {
            if let Some(block) = self.block_list.get_mut(i) {
                block.compile_info();
            }
        }
    }

    /// 从文件读取
    pub fn read_from_file(&mut self, file: &dyn File, address: u64) -> Result<usize> {
        self.address = address;
        // Parse commands from file starting at address
        // This is a simplified implementation
        Ok(0)
    }

    /// 写入文件
    pub fn write_to_file(&self, _file: &mut dyn File) -> Result<()> {
        // Write function to file
        Ok(())
    }

    /// 从缓冲区读取
    pub fn read_from_buffer(&mut self, _buffer: &[u8], _file: &dyn File) -> Result<()> {
        // Read function from buffer
        Ok(())
    }

    /// 重新基址
    pub fn rebase(&mut self, delta_base: u64) {
        self.address += delta_base;
        if self.break_address != 0 {
            self.break_address += delta_base;
        }

        // Rebase commands
        for i in 0..self.commands.len() {
            if let Some(cmd) = self.commands.get_mut(i) {
                cmd.rebase(delta_base);
            }
        }

        // Rebase blocks
        self.block_list.rebase_all(delta_base);

        // Rebase links
        self.link_list.rebase_all(delta_base as i64);

        // Rebuild command map
        self.command_map.clear();
        for i in 0..self.commands.len() {
            if let Some(cmd) = self.commands.get(i) {
                self.command_map.insert(cmd.address(), i);
            }
        }
    }

    /// 解析命令
    pub fn parse_command(&mut self, _file: &dyn File, address: u64, _dump_mode: bool) -> Option<Box<dyn ICommand>> {
        // Parse a command at the given address
        let mut cmd = BaseCommand::new();
        cmd.set_address(address);
        Some(Box::new(cmd))
    }

    /// 获取显示地址
    pub fn display_address(&self, arch_name: &str) -> String {
        format!("{}:0x{:016X}", arch_name, self.address)
    }

    /// 获取统计信息
    pub fn statistics(&self) -> FunctionStatistics {
        FunctionStatistics {
            address: self.address,
            name: self.name.name().to_string(),
            command_count: self.commands.len(),
            block_count: self.block_list.len(),
            link_count: self.link_list.len(),
            compilation_type: self.compilation_type(),
            need_compile: self.need_compile,
        }
    }
}

impl IFunction for BaseFunction {
    fn address(&self) -> u64 { self.address }
    fn break_address(&self) -> u64 { self.break_address }
    fn object_type(&self) -> ObjectType { self.object_type }
    fn entry_type(&self) -> EntryType { self.entry_type }
    fn entry(&self) -> Option<&dyn ICommand> { self.entry.as_ref().map(|e| e.as_ref()) }
    fn name(&self) -> &str { self.name() }
    fn display_name(&self) -> &str { self.display_name() }
    fn full_name(&self) -> &FunctionName { self.full_name() }
    fn cpu_address_size(&self) -> OperandSize { self.cpu_address_size }
    fn need_compile(&self) -> bool { self.need_compile }
    fn compilation_type(&self) -> CompilationType { self.compilation_type() }
    fn default_compilation_type(&self) -> CompilationType { self.default_compilation_type }
    fn compilation_options(&self) -> u32 { self.compilation_options() }
    fn set_break_address(&mut self, address: u64) { self.break_address = address; }
    fn is_breaked_address(&self, address: u64) -> bool { self.is_breaked_address(address) }
    fn set_compilation_type(&mut self, compilation_type: CompilationType) { self.compilation_type = compilation_type; }
    fn set_compilation_options(&mut self, options: u32) { self.compilation_options = options; }
    fn set_need_compile(&mut self, need: bool) { self.need_compile = need; }
    fn set_tag(&mut self, tag: u8) { self.tag = tag; }
    fn tag(&self) -> u8 { self.tag }
    fn from_runtime(&self) -> bool { self.from_runtime }
    fn set_from_runtime(&mut self, from_runtime: bool) { self.from_runtime = from_runtime; }
    fn read_from_file(&mut self, file: &dyn File, address: u64) -> Result<usize> {
        self.read_from_file(file, address)
    }
    fn write_to_file(&self, file: &mut dyn File) -> Result<()> {
        self.write_to_file(file)
    }
    fn init(&mut self, ctx: &CompileContext) -> Result<()> { self.init(ctx) }
    fn prepare(&mut self, ctx: &CompileContext) -> Result<()> { self.prepare(ctx) }
    fn compile(&mut self, ctx: &CompileContext) -> Result<()> { self.compile(ctx) }
    fn after_compile(&mut self, ctx: &CompileContext) { self.after_compile(ctx); }
    fn compile_links(&mut self, ctx: &CompileContext) { self.compile_links(ctx); }
    fn compile_info(&mut self, ctx: &CompileContext) { self.compile_info(ctx); }
    fn get_command_by_address(&self, address: u64) -> Option<&dyn ICommand> {
        self.get_command_by_address(address)
    }
    fn get_command_by_near_address(&self, address: u64) -> Option<&dyn ICommand> {
        self.get_command_by_near_address(address)
    }
    fn read_from_buffer(&mut self, buffer: &[u8], file: &dyn File) -> Result<()> {
        self.read_from_buffer(buffer, file)
    }
    fn rebase(&mut self, delta_base: u64) { self.rebase(delta_base); }
    fn memory_type(&self) -> u32 { self.memory_type }
    fn set_memory_type(&mut self, memory_type: u32) { self.memory_type = memory_type; }
    fn parse_command(&mut self, file: &dyn File, address: u64, dump_mode: bool) -> Option<Box<dyn ICommand>> {
        self.parse_command(file, address, dump_mode)
    }
    fn add_block(&mut self, start_index: usize, is_executable: bool) -> Box<dyn ICommandBlock> {
        // Create a new block directly instead of cloning
        let block_type = if is_executable { BlockType::Basic } else { BlockType::Data };
        let block = CommandBlock::new(start_index, block_type);
        Box::new(block)
    }
    fn add_command(&mut self, data: &[u8]) -> Box<dyn ICommand> {
        Box::new(BaseCommand::from_data(data))
    }
    fn add_value_command(&mut self, value_size: OperandSize, value: u64) -> Box<dyn ICommand> {
        let data = match value_size {
            OperandSize::Byte => vec![value as u8],
            OperandSize::Word => (value as u16).to_le_bytes().to_vec(),
            OperandSize::DWord => (value as u32).to_le_bytes().to_vec(),
            OperandSize::QWord => value.to_le_bytes().to_vec(),
            _ => vec![],
        };
        Box::new(BaseCommand::from_data(&data))
    }
    fn as_any(&self) -> &dyn Any { self }
    fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl Clone for BaseFunction {
    fn clone(&self) -> Self {
        Self {
            address: self.address,
            break_address: self.break_address,
            object_type: self.object_type,
            entry_type: self.entry_type,
            entry: None, // Arc clone would require ICommand to be Clone
            name: self.name.clone(),
            cpu_address_size: self.cpu_address_size,
            link_list: CommandLinkList::new(),
            ext_command_list: ExtCommandList::new(),
            block_list: CommandBlockList::new(),
            commands: CommandList::new(),
            need_compile: self.need_compile,
            compilation_type: self.compilation_type,
            default_compilation_type: self.default_compilation_type,
            compilation_options: self.compilation_options,
            memory_type: self.memory_type,
            tag: self.tag,
            from_runtime: self.from_runtime,
            internal_lock_to_key: self.internal_lock_to_key,
            command_map: HashMap::new(),
            parent: self.parent.clone(),
            range_list: self.range_list.clone(),
            function_info_list: FunctionInfoList::new(),
            hash_value: self.hash_value,
        }
    }
}

/// 函数统计信息
#[derive(Debug, Clone)]
pub struct FunctionStatistics {
    pub address: u64,
    pub name: String,
    pub command_count: usize,
    pub block_count: usize,
    pub link_count: usize,
    pub compilation_type: CompilationType,
    pub need_compile: bool,
}

/// 函数列表
///
/// 对应 C++ 的 BaseFunctionList
pub struct BaseFunctionList {
    functions: Vec<BaseFunction>,
    function_map: HashMap<u64, usize>, // address -> index
    name_map: HashMap<String, usize>,   // name -> index
}

impl BaseFunctionList {
    pub fn new() -> Self {
        Self {
            functions: Vec::new(),
            function_map: HashMap::new(),
            name_map: HashMap::new(),
        }
    }

    /// 添加函数
    pub fn add(&mut self, name: &str, compilation_type: CompilationType, options: u32, need_compile: bool) -> &mut BaseFunction {
        let func_name = FunctionName::new(name);
        let func = BaseFunction::new(func_name, compilation_type, options, need_compile);
        let index = self.functions.len();
        self.functions.push(func);
        self.name_map.insert(name.to_string(), index);
        &mut self.functions[index]
    }

    /// 从地址添加
    pub fn add_by_address(&mut self, address: u64, compilation_type: CompilationType, options: u32, need_compile: bool) -> &mut BaseFunction {
        let func = BaseFunction::from_address(address, compilation_type, options, need_compile);
        let index = self.functions.len();
        self.functions.push(func);
        self.function_map.insert(address, index);
        &mut self.functions[index]
    }

    /// 获取数量
    pub fn len(&self) -> usize { self.functions.len() }
    pub fn is_empty(&self) -> bool { self.functions.is_empty() }

    /// 按索引获取
    pub fn get(&self, index: usize) -> Option<&BaseFunction> {
        self.functions.get(index)
    }
    pub fn get_mut(&mut self, index: usize) -> Option<&mut BaseFunction> {
        self.functions.get_mut(index)
    }

    /// 按地址获取
    pub fn get_by_address(&self, address: u64) -> Option<&BaseFunction> {
        self.function_map.get(&address).and_then(|&idx| self.functions.get(idx))
    }
    pub fn get_by_address_mut(&mut self, address: u64) -> Option<&mut BaseFunction> {
        self.function_map.get(&address).and_then(|&idx| self.functions.get_mut(idx))
    }

    /// 按名称获取
    pub fn get_by_name(&self, name: &str) -> Option<&BaseFunction> {
        self.name_map.get(name).and_then(|&idx| self.functions.get(idx))
    }
    pub fn get_by_name_mut(&mut self, name: &str) -> Option<&mut BaseFunction> {
        self.name_map.get(name).and_then(|&idx| self.functions.get_mut(idx))
    }

    /// 迭代器
    pub fn iter(&self) -> impl Iterator<Item = &BaseFunction> {
        self.functions.iter()
    }
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut BaseFunction> {
        self.functions.iter_mut()
    }

    /// 准备所有
    pub fn prepare_all(&mut self, ctx: &CompileContext) -> Result<()> {
        for func in &mut self.functions {
            func.prepare(ctx)?;
        }
        Ok(())
    }

    /// 编译所有
    pub fn compile_all(&mut self, ctx: &CompileContext) -> Result<()> {
        for func in &mut self.functions {
            func.compile(ctx)?;
        }
        Ok(())
    }

    /// 编译所有链接
    pub fn compile_all_links(&mut self, ctx: &CompileContext) {
        for func in &mut self.functions {
            func.compile_links(ctx);
        }
    }

    /// 从缓冲区读取
    pub fn read_from_buffer(&mut self, _buffer: &[u8], _file: &dyn File) -> Result<()> {
        Ok(())
    }

    /// 重新基址
    pub fn rebase(&mut self, delta_base: u64) {
        for func in &mut self.functions {
            func.rebase(delta_base);
        }
        // Rebuild maps
        self.function_map.clear();
        for (idx, func) in self.functions.iter().enumerate() {
            self.function_map.insert(func.address(), idx);
        }
    }

    /// 按地址获取命令
    pub fn get_command_by_address(&self, address: u64, need_compile: bool) -> Option<&dyn ICommand> {
        for func in &self.functions {
            if !need_compile || func.need_compile() {
                if let Some(cmd) = func.get_command_by_address(address) {
                    return Some(cmd);
                }
            }
        }
        None
    }

    /// 按近似地址获取命令
    pub fn get_command_by_near_address(&self, address: u64, need_compile: bool) -> Option<&dyn ICommand> {
        for func in &self.functions {
            if !need_compile || func.need_compile() {
                if let Some(cmd) = func.get_command_by_near_address(address) {
                    return Some(cmd);
                }
            }
        }
        None
    }

    /// 清空
    pub fn clear(&mut self) {
        self.functions.clear();
        self.function_map.clear();
        self.name_map.clear();
    }

    /// 获取统计信息
    pub fn statistics(&self) -> FunctionListStatistics {
        let mut stats = FunctionListStatistics {
            function_count: self.functions.len(),
            total_commands: 0,
            total_blocks: 0,
            total_links: 0,
            functions_need_compile: 0,
        };

        for func in &self.functions {
            let func_stats = func.statistics();
            stats.total_commands += func_stats.command_count;
            stats.total_blocks += func_stats.block_count;
            stats.total_links += func_stats.link_count;
            if func_stats.need_compile {
                stats.functions_need_compile += 1;
            }
        }

        stats
    }
}

impl Default for BaseFunctionList {
    fn default() -> Self {
        Self::new()
    }
}

/// 函数列表统计信息
#[derive(Debug, Clone, Default)]
pub struct FunctionListStatistics {
    pub function_count: usize,
    pub total_commands: usize,
    pub total_blocks: usize,
    pub total_links: usize,
    pub functions_need_compile: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_function_new() {
        let func = BaseFunction::new(FunctionName::new("test"), CompilationType::Native, 0, true);
        assert_eq!(func.name(), "test");
        assert!(func.need_compile());
        assert_eq!(func.compilation_type(), CompilationType::Native);
    }

    #[test]
    fn test_base_function_from_address() {
        let func = BaseFunction::from_address(0x140001000, CompilationType::Virtualization, 0, true);
        assert_eq!(func.address(), 0x140001000);
        assert!(func.name().contains("140001000"));
    }

    #[test]
    fn test_base_function_add_command() {
        let mut func = BaseFunction::new(FunctionName::new("test"), CompilationType::Native, 0, true);
        func.set_address(0x1000);

        let cmd = Box::new(BaseCommand::new());
        func.add_command(cmd);

        assert_eq!(func.commands().len(), 1);
    }

    #[test]
    fn test_base_function_break_address() {
        let mut func = BaseFunction::new(FunctionName::new("test"), CompilationType::Native, 0, true);
        func.set_break_address(0x2000);

        assert!(func.is_breaked_address(0x2000));
        assert!(func.is_breaked_address(0x3000));
        assert!(!func.is_breaked_address(0x1000));
    }

    #[test]
    fn test_base_function_list() {
        let mut list = BaseFunctionList::new();
        assert!(list.is_empty());

        list.add("func1", CompilationType::Native, 0, true);
        list.add("func2", CompilationType::Virtualization, 0, false);

        assert_eq!(list.len(), 2);

        let func1 = list.get_by_name("func1");
        assert!(func1.is_some());
        assert!(func1.unwrap().need_compile());
    }

    #[test]
    fn test_base_function_list_by_address() {
        let mut list = BaseFunctionList::new();
        list.add_by_address(0x1000, CompilationType::Native, 0, true);
        list.add_by_address(0x2000, CompilationType::Virtualization, 0, false);

        let func = list.get_by_address(0x1000);
        assert!(func.is_some());
        assert_eq!(func.unwrap().compilation_type(), CompilationType::Native);
    }

    #[test]
    fn test_function_statistics() {
        let func = BaseFunction::new(FunctionName::new("test"), CompilationType::Native, 0, true);
        let stats = func.statistics();
        assert_eq!(stats.name, "test");
        assert_eq!(stats.command_count, 0);
        assert!(stats.need_compile);
    }

    #[test]
    fn test_function_list_statistics() {
        let mut list = BaseFunctionList::new();
        list.add("func1", CompilationType::Native, 0, true);
        list.add("func2", CompilationType::Virtualization, 0, false);

        let stats = list.statistics();
        assert_eq!(stats.function_count, 2);
        assert_eq!(stats.functions_need_compile, 1);
    }

    #[test]
    fn test_base_function_rebase() {
        let mut func = BaseFunction::from_address(0x1000, CompilationType::Native, 0, true);
        func.set_break_address(0x2000);

        func.rebase(0x1000);

        assert_eq!(func.address(), 0x2000);
        assert_eq!(func.break_address(), 0x3000);
    }

    #[test]
    fn test_base_function_clear() {
        let mut func = BaseFunction::new(FunctionName::new("test"), CompilationType::Native, 0, true);
        func.set_address(0x1000);
        
        let cmd = Box::new(BaseCommand::new());
        func.add_command(cmd);
        assert_eq!(func.commands().len(), 1);

        func.clear();
        assert_eq!(func.commands().len(), 0);
        assert!(func.entry().is_none());
    }

    #[test]
    fn test_base_function_hash() {
        let mut func = BaseFunction::new(FunctionName::new("test"), CompilationType::Native, 0, true);
        func.set_address(0x1000);

        let hash = func.calculate_hash();
        func.set_hash(hash);

        assert!(func.check_hash());

        func.set_address(0x2000);
        assert!(!func.check_hash());
    }

    #[test]
    fn test_base_function_add_remove_object() {
        let mut func = BaseFunction::new(FunctionName::new("test"), CompilationType::Native, 0, true);
        
        let mut cmd = BaseCommand::new();
        cmd.set_address(0x1000);
        func.add_object(Box::new(cmd));

        assert_eq!(func.commands().len(), 1);
        
        // Test that we can find the command
        let found = func.get_command_by_address(0x1000);
        assert!(found.is_some());
    }

    #[test]
    fn test_base_function_lower_upper_address() {
        let mut func = BaseFunction::new(FunctionName::new("test"), CompilationType::Native, 0, true);
        
        let mut cmd1 = BaseCommand::new();
        cmd1.set_address(0x1000);
        func.add_object(Box::new(cmd1));

        let mut cmd2 = BaseCommand::new();
        cmd2.set_address(0x2000);
        func.add_object(Box::new(cmd2));

        let lower = func.get_command_by_lower_address(0x1500);
        assert!(lower.is_some());
        assert_eq!(lower.unwrap().address(), 0x1000);

        let upper = func.get_command_by_upper_address(0x1500);
        assert!(upper.is_some());
        assert_eq!(upper.unwrap().address(), 0x2000);
    }

    #[test]
    fn test_function_info() {
        let info = FunctionInfo::new(0x1000, 0x100);
        assert_eq!(info.address, 0x1000);
        assert_eq!(info.size, 0x100);
    }

    #[test]
    fn test_function_info_list() {
        let mut list = FunctionInfoList::new();
        list.add(FunctionInfo::new(0x1000, 0x100));
        list.add(FunctionInfo::new(0x2000, 0x200));

        assert_eq!(list.len(), 2);
        
        let info = list.get(0);
        assert!(info.is_some());
        assert_eq!(info.unwrap().address, 0x1000);
    }

    #[test]
    fn test_address_range_info() {
        let range = AddressRangeInfo::new(0x1000, 0x2000);
        assert_eq!(range.start, 0x1000);
        assert_eq!(range.end, 0x2000);
        assert_eq!(range.size, 0x1000);
        assert!(range.contains(0x1500));
        assert!(!range.contains(0x2000));
    }

    #[test]
    fn test_base_function_parent() {
        let parent = Arc::new(BaseFunction::new(FunctionName::new("parent"), CompilationType::Native, 0, true));
        let child = BaseFunction::from_cpu_address_size(OperandSize::QWord, parent.clone());

        assert!(child.parent().is_some());
        assert_eq!(child.parent().unwrap().name(), "parent");
    }

    #[test]
    fn test_base_function_clone() {
        let mut func = BaseFunction::new(FunctionName::new("test"), CompilationType::Native, 0, true);
        func.set_address(0x1000);
        func.set_hash(0x12345678);

        let cloned = func.clone();
        assert_eq!(cloned.address(), 0x1000);
        assert_eq!(cloned.name(), "test");
        assert_eq!(cloned.hash(), 0x12345678);
    }
}
