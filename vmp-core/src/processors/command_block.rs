//! Processors 命令块系统
//!
//! 从 C++ 的 proc_command_block.h/cc 迁移

use crate::error::{Result, VmpError};
use super::types::*;
use super::interfaces::*;
use super::command::{BaseCommand, CommandList};
use super::command_link::{CommandLink, CommandLinkList};
use std::any::Any;
use std::sync::Arc;

/// 外部命令引用
///
/// 对应 C++ 的 ExtCommand
pub struct ExtCommand {
    /// 所属列表
    owner: Option<Arc<ExtCommandList>>,
    /// 地址
    address: u64,
    /// 引用的命令
    reference_command: Option<Arc<dyn ICommand>>,
    /// 链接
    link: Option<CommandLink>,
    /// 是否使用调用
    use_call: bool,
}

impl ExtCommand {
    pub fn new(address: u64) -> Self {
        Self {
            owner: None,
            address,
            reference_command: None,
            link: None,
            use_call: false,
        }
    }

    /// 克隆到新的所有者
    pub fn clone_with_owner(&self, owner: Arc<ExtCommandList>) -> Self {
        let mut cloned = self.clone();
        cloned.owner = Some(owner);
        cloned
    }

    /// 获取所属列表
    pub fn owner(&self) -> Option<&Arc<ExtCommandList>> {
        self.owner.as_ref()
    }

    /// 设置所属列表
    pub fn set_owner(&mut self, owner: Option<Arc<ExtCommandList>>) {
        self.owner = owner;
    }

    /// 获取地址
    pub fn address(&self) -> u64 {
        self.address
    }

    /// 设置地址
    pub fn set_address(&mut self, address: u64) {
        self.address = address;
    }

    /// 获取引用命令
    pub fn reference_command(&self) -> Option<&Arc<dyn ICommand>> {
        self.reference_command.as_ref()
    }

    /// 设置引用命令
    pub fn set_reference_command(&mut self, command: Option<Arc<dyn ICommand>>) {
        self.reference_command = command;
    }

    /// 获取链接
    pub fn link(&self) -> Option<&CommandLink> {
        self.link.as_ref()
    }

    /// 设置链接
    pub fn set_link(&mut self, link: Option<CommandLink>) {
        self.link = link;
    }

    /// 是否使用调用
    pub fn use_call(&self) -> bool {
        self.use_call
    }

    /// 设置是否使用调用
    pub fn set_use_call(&mut self, use_call: bool) {
        self.use_call = use_call;
    }

    /// 比较两个外部命令 (C++ 风格，返回 -1, 0, 1)
    pub fn CompareWith(&self, other: &ExtCommand) -> i32 {
        if self.address < other.address {
            -1
        } else if self.address > other.address {
            1
        } else if self.use_call != other.use_call {
            if self.use_call { -1 } else { 1 }
        } else {
            0
        }
    }

    /// 编译外部命令
    pub fn compile(&mut self, ctx: &CompileContext) -> Result<()> {
        if let Some(ref mut link) = self.link {
            link.compile_link(ctx)?;
        }
        Ok(())
    }

    /// 写入文件
    pub fn write_to_file(&self, file: &mut dyn File) -> Result<()> {
        // 写入外部命令引用
        if let Some(ref cmd) = self.reference_command {
            // 写入目标命令的地址
            file.write_u64(cmd.vm_address())?;
        } else {
            // 写入本地地址
            file.write_u64(self.address)?;
        }
        Ok(())
    }
}

impl Clone for ExtCommand {
    fn clone(&self) -> Self {
        Self {
            owner: None, // owner 不克隆
            address: self.address,
            reference_command: None, // Arc 克隆需要特殊处理
            link: self.link.clone(),
            use_call: self.use_call,
        }
    }
}

/// 外部命令列表
///
/// 对应 C++ 的 ExtCommandList
pub struct ExtCommandList {
    /// 所属函数
    owner: Option<Arc<dyn IFunction>>,
    commands: Vec<ExtCommand>,
}

impl ExtCommandList {
    pub fn new() -> Self {
        Self { 
            owner: None,
            commands: Vec::new(),
        }
    }

    /// 克隆到新的所有者
    pub fn clone_with_owner(&self, owner: Arc<dyn IFunction>) -> Self {
        let mut cloned = self.clone();
        cloned.owner = Some(owner);
        cloned
    }

    /// 获取所属函数
    pub fn owner(&self) -> Option<&dyn IFunction> {
        self.owner.as_ref().map(|o| o.as_ref())
    }

    /// 设置所属函数
    pub fn set_owner(&mut self, owner: Option<Arc<dyn IFunction>>) {
        self.owner = owner;
    }

    /// 添加外部命令
    pub fn add(&mut self, command: ExtCommand) -> &mut ExtCommand {
        self.commands.push(command);
        self.commands.last_mut().unwrap()
    }

    /// 创建并添加
    pub fn create(&mut self, address: u64) -> &mut ExtCommand {
        self.commands.push(ExtCommand::new(address));
        self.commands.last_mut().unwrap()
    }

    /// 添加对象 (C++ 风格)
    pub fn AddObject(&mut self, ext_command: ExtCommand) {
        self.commands.push(ext_command);
    }

    /// 移除对象 (C++ 风格)
    pub fn RemoveObject(&mut self, ext_command: &ExtCommand) -> bool {
        if let Some(pos) = self.commands.iter().position(|c| c.address() == ext_command.address()) {
            self.commands.remove(pos);
            true
        } else {
            false
        }
    }

    /// 获取数量
    pub fn len(&self) -> usize {
        self.commands.len()
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    /// 获取
    pub fn get(&self, index: usize) -> Option<&ExtCommand> {
        self.commands.get(index)
    }

    /// 获取可变
    pub fn get_mut(&mut self, index: usize) -> Option<&mut ExtCommand> {
        self.commands.get_mut(index)
    }

    /// 迭代器
    pub fn iter(&self) -> impl Iterator<Item = &ExtCommand> {
        self.commands.iter()
    }

    /// 可变迭代器
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut ExtCommand> {
        self.commands.iter_mut()
    }

    /// 按地址查找
    pub fn find_by_address(&self, address: u64) -> Option<&ExtCommand> {
        self.commands.iter().find(|c| c.address() == address)
    }

    /// 按地址获取命令 (C++ 风格命名)
    pub fn GetCommandByAddress(&self, address: u64) -> Option<&ExtCommand> {
        self.find_by_address(address)
    }

    /// 按地址获取可变命令 (C++ 风格命名)
    pub fn GetCommandByAddress_mut(&mut self, address: u64) -> Option<&mut ExtCommand> {
        self.commands.iter_mut().find(|c| c.address() == address)
    }

    /// 编译所有
    pub fn compile_all(&mut self, ctx: &CompileContext) -> Result<()> {
        for cmd in &mut self.commands {
            cmd.compile(ctx)?;
        }
        Ok(())
    }

    /// 写入文件
    pub fn write_to_file(&self, file: &mut dyn File) -> Result<()> {
        for cmd in &self.commands {
            cmd.write_to_file(file)?;
        }
        Ok(())
    }

    /// 清空
    pub fn clear(&mut self) {
        self.commands.clear();
    }
}

impl Clone for ExtCommandList {
    fn clone(&self) -> Self {
        Self {
            owner: None, // 所有者不克隆
            commands: self.commands.clone(),
        }
    }
}

impl Default for ExtCommandList {
    fn default() -> Self {
        Self::new()
    }
}

/// VM 命令 trait（占位符，实际应该在 vm/command.rs 中定义）
pub trait IVMCommand: Any + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// 命令块
///
/// 对应 C++ 的 CommandBlock
pub struct CommandBlock {
    /// 所属块列表
    owner: Option<Arc<CommandBlockList>>,
    /// 起始索引
    start_index: usize,
    /// 结束索引
    end_index: usize,
    /// 块类型
    block_type: BlockType,
    /// 命令列表
    commands: CommandList,
    /// 修正命令列表（VM 命令）
    correct_command_list: Vec<Box<dyn IVMCommand>>,
    /// 节区选项
    section_options: SectionOption,
    /// 链接列表
    links: CommandLinkList,
    /// 外部命令列表
    ext_commands: ExtCommandList,
    /// 入口地址
    entry_address: u64,
    /// 大小
    size: usize,
    /// 对齐
    alignment: usize,
    /// 寄存器索引数组（固定大小 24，如 C++）
    registr_indexes: [u8; 24],
    /// 寄存器数量
    registr_count: usize,
    /// 虚拟机
    virtual_machine: Option<Arc<dyn IVirtualMachine>>,
    /// 排序索引
    sort_index: usize,
}

impl CommandBlock {
    pub fn new(start_index: usize, block_type: BlockType) -> Self {
        Self {
            owner: None,
            start_index,
            end_index: start_index,
            block_type,
            commands: CommandList::new(),
            correct_command_list: Vec::new(),
            section_options: SectionOption::None,
            links: CommandLinkList::new(),
            ext_commands: ExtCommandList::new(),
            entry_address: 0,
            size: 0,
            alignment: 1,
            registr_indexes: [0; 24],
            registr_count: 0,
            virtual_machine: None,
            sort_index: 0,
        }
    }

    /// 克隆到新的所有者
    pub fn clone_with_owner(&self, owner: Arc<CommandBlockList>) -> Self {
        let mut cloned = self.clone();
        cloned.owner = Some(owner);
        cloned
    }

    /// 获取所属列表
    pub fn owner(&self) -> Option<&Arc<CommandBlockList>> {
        self.owner.as_ref()
    }

    /// 设置所属列表
    pub fn set_owner(&mut self, owner: Option<Arc<CommandBlockList>>) {
        self.owner = owner;
    }

    /// 获取起始索引
    pub fn start_index(&self) -> usize {
        self.start_index
    }

    /// 设置起始索引
    pub fn set_start_index(&mut self, index: usize) {
        self.start_index = index;
    }

    /// 获取结束索引
    pub fn end_index(&self) -> usize {
        self.end_index
    }

    /// 设置结束索引
    pub fn set_end_index(&mut self, index: usize) {
        self.end_index = index;
    }

    /// 更新索引（根据命令数量）
    pub fn update_indices(&mut self) {
        self.end_index = self.start_index + self.commands.len();
    }

    /// 获取块类型
    pub fn block_type(&self) -> BlockType {
        self.block_type
    }

    /// 设置块类型
    pub fn set_block_type(&mut self, block_type: BlockType) {
        self.block_type = block_type;
    }

    /// 获取命令数量
    pub fn command_count(&self) -> usize {
        self.commands.len()
    }

    /// 是否可执行（基于块类型）
    pub fn is_executable(&self) -> bool {
        matches!(self.block_type, 
            BlockType::Basic | BlockType::Loop | BlockType::Condition | 
            BlockType::Entry | BlockType::Virtualized)
    }

    /// 获取寄存器（C++ 风格，带 OperandSize 参数）
    /// 
    /// # Arguments
    /// * `size` - 操作数大小
    /// * `registr` - 寄存器索引
    /// * `is_write` - 是否是写操作
    pub fn GetRegistr(&mut self, size: OperandSize, registr: u8, is_write: bool) -> u8 {
        // 简化的寄存器分配逻辑
        // 实际应该根据大小和操作类型返回合适的寄存器索引
        let index = (registr % 24) as usize;
        
        if is_write && self.registr_count < 24 {
            // 如果是写操作且寄存器未分配，分配新寄存器
            if self.registr_indexes[index] == 0 {
                self.registr_indexes[self.registr_count] = registr;
                self.registr_count += 1;
            }
        }
        
        self.registr_indexes[index]
    }

    /// 获取寄存器索引数组
    pub fn registr_indexes(&self) -> &[u8; 24] {
        &self.registr_indexes
    }

    /// 获取寄存器数量
    pub fn registr_count(&self) -> usize {
        self.registr_count
    }

    /// 添加修正命令（VM 命令）
    pub fn AddCorrectCommand(&mut self, command: Box<dyn IVMCommand>) {
        self.correct_command_list.push(command);
    }

    /// 获取修正命令列表
    pub fn correct_command_list(&self) -> &[Box<dyn IVMCommand>] {
        &self.correct_command_list
    }

    /// 获取可变修正命令列表
    pub fn correct_command_list_mut(&mut self) -> &mut Vec<Box<dyn IVMCommand>> {
        &mut self.correct_command_list
    }

    /// 获取虚拟机
    pub fn virtual_machine(&self) -> Option<&dyn IVirtualMachine> {
        self.virtual_machine.as_ref().map(|vm| vm.as_ref())
    }

    /// 设置虚拟机
    pub fn set_virtual_machine(&mut self, vm: Option<Arc<dyn IVirtualMachine>>) {
        self.virtual_machine = vm;
    }

    /// 获取排序索引
    pub fn sort_index(&self) -> usize {
        self.sort_index
    }

    /// 设置排序索引
    pub fn set_sort_index(&mut self, index: usize) {
        self.sort_index = index;
    }

    /// 获取所属函数
    pub fn function(&self) -> Option<&dyn IFunction> {
        // 通过 owner 获取函数
        None
    }

    /// 获取节区选项
    pub fn section_options(&self) -> SectionOption {
        self.section_options
    }

    /// 设置节区选项
    pub fn set_section_options(&mut self, options: SectionOption) {
        self.section_options = options;
    }

    /// 包含节区选项
    pub fn include_section_option(&mut self, option: SectionOption) {
        self.section_options |= option;
    }

    /// 排除节区选项
    pub fn exclude_section_option(&mut self, option: SectionOption) {
        self.section_options &= !option;
    }

    /// 获取入口地址
    pub fn entry_address(&self) -> u64 {
        self.entry_address
    }

    /// 设置入口地址
    pub fn set_entry_address(&mut self, address: u64) {
        self.entry_address = address;
    }

    /// 获取大小
    pub fn size(&self) -> usize {
        self.size
    }

    /// 计算大小
    pub fn calculate_size(&mut self) -> usize {
        let mut size = 0;
        for i in 0..self.commands.len() {
            if let Some(cmd) = self.commands.get(i) {
                size += cmd.dump_size();
            }
        }
        self.size = size;
        size
    }

    /// 获取对齐
    pub fn alignment(&self) -> usize {
        self.alignment
    }

    /// 设置对齐
    pub fn set_alignment(&mut self, alignment: usize) {
        self.alignment = alignment;
    }

    /// 添加命令
    pub fn add_command(&mut self, command: Box<dyn ICommand>) -> &mut dyn ICommand {
        let cmd_count = self.commands.len() + 1;
        let result = self.commands.add(command);
        // 更新结束索引
        self.end_index = self.start_index + cmd_count;
        result
    }

    /// 获取命令
    pub fn get_command(&self, index: usize) -> Option<&dyn ICommand> {
        self.commands.get(index)
    }

    /// 获取可变命令
    pub fn get_command_mut(&mut self, index: usize) -> Option<&mut dyn ICommand> {
        self.commands.get_mut(index)
    }

    /// 获取第一个命令的地址
    pub fn first_address(&self) -> Option<u64> {
        self.commands.get(0).map(|c| c.address())
    }

    /// 获取最后一个命令的地址
    pub fn last_address(&self) -> Option<u64> {
        if self.commands.len() > 0 {
            self.commands.get(self.commands.len() - 1).map(|c| c.address())
        } else {
            None
        }
    }

    /// 添加链接
    pub fn add_link(&mut self, link: CommandLink) -> &mut CommandLink {
        self.links.add(link)
    }

    /// 获取链接列表
    pub fn links(&self) -> &CommandLinkList {
        &self.links
    }

    /// 获取可变链接列表
    pub fn links_mut(&mut self) -> &mut CommandLinkList {
        &mut self.links
    }

    /// 添加外部命令
    pub fn add_ext_command(&mut self, command: ExtCommand) -> &mut ExtCommand {
        self.ext_commands.add(command)
    }

    /// 获取外部命令列表
    pub fn ext_commands(&self) -> &ExtCommandList {
        &self.ext_commands
    }

    /// 获取可变外部命令列表
    pub fn ext_commands_mut(&mut self) -> &mut ExtCommandList {
        &mut self.ext_commands
    }

    /// 编译块
    pub fn compile(&mut self, ctx: &CompileContext) -> Result<()> {
        // 编译所有命令
        for i in 0..self.commands.len() {
            if let Some(cmd) = self.commands.get_mut(i) {
                cmd.compile_to_native();
            }
        }

        // 编译链接
        self.links.compile_all(ctx)?;

        // 编译外部命令
        self.ext_commands.compile_all(ctx)?;

        // 重新计算大小
        self.calculate_size();

        Ok(())
    }

    /// 编译链接
    pub fn compile_links(&mut self, ctx: &CompileContext) -> Result<()> {
        self.links.compile_all(ctx)
    }

    /// 编译信息
    pub fn compile_info(&mut self) {
        for i in 0..self.commands.len() {
            if let Some(cmd) = self.commands.get_mut(i) {
                cmd.compile_info();
            }
        }
    }

    /// 写入文件
    pub fn write_to_file(&self, file: &mut dyn File) -> Result<usize> {
        let mut bytes_written = 0;
        
        // 写入所有命令
        for i in 0..self.commands.len() {
            if let Some(cmd) = self.commands.get(i) {
                // 逐字节写入转储
                for j in 0..cmd.dump_size() {
                    if let Some(byte) = cmd.dump(j) {
                        file.write_u8(byte)?;
                        bytes_written += 1;
                    }
                }
            }
        }

        // 写入外部命令
        self.ext_commands.write_to_file(file)?;

        Ok(bytes_written)
    }

    /// 重新基址
    pub fn rebase(&mut self, delta_base: u64) {
        for i in 0..self.commands.len() {
            if let Some(cmd) = self.commands.get_mut(i) {
                cmd.rebase(delta_base);
            }
        }

        self.links.rebase_all(delta_base as i64);

        if self.entry_address != 0 {
            self.entry_address += delta_base;
        }
    }

    /// 查找命令
    pub fn find_command(&self, address: u64) -> Option<&dyn ICommand> {
        self.commands.find_by_address(address)
    }

    /// 查找可变命令
    pub fn find_command_mut(&mut self, address: u64) -> Option<&mut dyn ICommand> {
        self.commands.find_by_address_mut(address)
    }

    /// 按地址范围获取命令
    pub fn commands_in_range(&self, start: u64, end: u64) -> Vec<&dyn ICommand> {
        self.commands
            .iter()
            .filter(|c| {
                let addr = c.address();
                addr >= start && addr < end
            })
            .collect()
    }

    /// 是否包含地址
    pub fn contains_address(&self, address: u64) -> bool {
        if let Some(first) = self.first_address() {
            if let Some(last) = self.last_address() {
                return address >= first && address <= last;
            }
        }
        false
    }

    /// 获取统计信息
    pub fn statistics(&self) -> BlockStatistics {
        let mut stats = BlockStatistics::default();
        stats.command_count = self.commands.len();
        stats.link_count = self.links.len();
        stats.ext_command_count = self.ext_commands.len();
        stats.correct_command_count = self.correct_command_list.len();
        stats.size = self.size;
        stats.is_executable = self.is_executable();
        stats
    }
}

impl Clone for CommandBlock {
    fn clone(&self) -> Self {
        Self {
            owner: None, // owner 不克隆
            start_index: self.start_index,
            end_index: self.end_index,
            block_type: self.block_type,
            commands: CommandList::new(), // CommandList 需要特殊处理
            correct_command_list: Vec::new(), // IVMCommand 克隆复杂
            section_options: self.section_options,
            links: self.links.clone(),
            ext_commands: self.ext_commands.clone(),
            entry_address: self.entry_address,
            size: self.size,
            alignment: self.alignment,
            registr_indexes: self.registr_indexes,
            registr_count: self.registr_count,
            virtual_machine: None, // 不克隆虚拟机引用
            sort_index: self.sort_index,
        }
    }
}

impl ICommandBlock for CommandBlock {
    fn start_index(&self) -> usize {
        self.start_index
    }

    fn command_count(&self) -> usize {
        self.commands.len()
    }

    fn is_executable(&self) -> bool {
        CommandBlock::is_executable(self)
    }

    fn compile(&mut self, ctx: &CompileContext) -> Result<()> {
        CommandBlock::compile(self, ctx)
    }

    fn write_to_file(&self, file: &mut dyn File) -> Result<()> {
        let _ = CommandBlock::write_to_file(self, file);
        Ok(())
    }

    fn add_command(&mut self, command: Box<dyn ICommand>) {
        self.commands.add(command);
        self.end_index = self.start_index + self.commands.len();
    }

    fn get_command(&self, index: usize) -> Option<&dyn ICommand> {
        self.commands.get(index)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// 命令块统计信息
#[derive(Debug, Clone, Default)]
pub struct BlockStatistics {
    pub command_count: usize,
    pub correct_command_count: usize,
    pub link_count: usize,
    pub ext_command_count: usize,
    pub size: usize,
    pub is_executable: bool,
}

/// 命令块列表
///
/// 对应 C++ 的 CommandBlockList
pub struct CommandBlockList {
    blocks: Vec<CommandBlock>,
    /// 当前块索引（用于遍历）
    current_index: usize,
}

impl CommandBlockList {
    pub fn new() -> Self {
        Self {
            blocks: Vec::new(),
            current_index: 0,
        }
    }

    /// 添加块
    pub fn add(&mut self, block: CommandBlock) -> &mut CommandBlock {
        self.blocks.push(block);
        self.blocks.last_mut().unwrap()
    }

    /// 创建并添加块
    pub fn create(&mut self, start_index: usize, block_type: BlockType) -> &mut CommandBlock {
        self.blocks.push(CommandBlock::new(start_index, block_type));
        self.blocks.last_mut().unwrap()
    }

    /// 获取数量
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// 获取
    pub fn get(&self, index: usize) -> Option<&CommandBlock> {
        self.blocks.get(index)
    }

    /// 获取可变
    pub fn get_mut(&mut self, index: usize) -> Option<&mut CommandBlock> {
        self.blocks.get_mut(index)
    }

    /// 迭代器
    pub fn iter(&self) -> impl Iterator<Item = &CommandBlock> {
        self.blocks.iter()
    }

    /// 可变迭代器
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut CommandBlock> {
        self.blocks.iter_mut()
    }

    /// 按起始索引查找
    pub fn find_by_start_index(&self, start_index: usize) -> Option<&CommandBlock> {
        self.blocks.iter().find(|b| b.start_index() == start_index)
    }

    /// 按地址查找（查找包含该地址的块）
    pub fn find_by_address(&self, address: u64) -> Option<&CommandBlock> {
        self.blocks.iter().find(|b| b.contains_address(address))
    }

    /// 按地址查找可变
    pub fn find_by_address_mut(&mut self, address: u64) -> Option<&mut CommandBlock> {
        self.blocks.iter_mut().find(|b| b.contains_address(address))
    }

    /// 获取第一个可执行块
    pub fn first_executable(&self) -> Option<&CommandBlock> {
        self.blocks.iter().find(|b| b.is_executable())
    }

    /// 编译所有块
    pub fn compile_all(&mut self, ctx: &CompileContext) -> Result<()> {
        for block in &mut self.blocks {
            block.compile(ctx)?;
        }
        Ok(())
    }

    /// 编译所有链接
    pub fn compile_all_links(&mut self, ctx: &CompileContext) -> Result<()> {
        for block in &mut self.blocks {
            block.compile_links(ctx)?;
        }
        Ok(())
    }

    /// 写入文件
    pub fn write_to_file(&self, file: &mut dyn File) -> Result<()> {
        for block in &self.blocks {
            block.write_to_file(file)?;
        }
        Ok(())
    }

    /// 重新基址
    pub fn rebase_all(&mut self, delta_base: u64) {
        for block in &mut self.blocks {
            block.rebase(delta_base);
        }
    }

    /// 计算总大小
    pub fn total_size(&self) -> usize {
        self.blocks.iter().map(|b| b.size()).sum()
    }

    /// 清空
    pub fn clear(&mut self) {
        self.blocks.clear();
        self.current_index = 0;
    }

    /// 获取统计信息
    pub fn statistics(&self) -> BlockListStatistics {
        let mut stats = BlockListStatistics::default();
        stats.block_count = self.blocks.len();

        for block in &self.blocks {
            let block_stats = block.statistics();
            stats.total_commands += block_stats.command_count;
            stats.total_correct_commands += block_stats.correct_command_count;
            stats.total_links += block_stats.link_count;
            stats.total_size += block_stats.size;

            if block_stats.is_executable {
                stats.executable_blocks += 1;
            }
        }

        stats
    }

    /// 排序（按起始索引）
    pub fn sort_by_start_index(&mut self) {
        self.blocks.sort_by(|a, b| a.start_index().cmp(&b.start_index()));
    }

    /// 合并相邻块
    pub fn merge_adjacent(&mut self) {
        if self.blocks.len() < 2 {
            return;
        }

        self.sort_by_start_index();

        let mut i = 0;
        while i + 1 < self.blocks.len() {
            // 检查是否可以合并
            // 简化实现：这里可以根据实际需要添加合并逻辑
            i += 1;
        }
    }
}

impl Default for CommandBlockList {
    fn default() -> Self {
        Self::new()
    }
}

/// 块列表统计信息
#[derive(Debug, Clone, Default)]
pub struct BlockListStatistics {
    pub block_count: usize,
    pub executable_blocks: usize,
    pub total_commands: usize,
    pub total_correct_commands: usize,
    pub total_links: usize,
    pub total_size: usize,
}

/// 块构建器
pub struct BlockBuilder {
    start_index: usize,
    block_type: BlockType,
    section_options: SectionOption,
    alignment: usize,
}

impl BlockBuilder {
    pub fn new(start_index: usize) -> Self {
        Self {
            start_index,
            block_type: BlockType::Basic,
            section_options: SectionOption::None,
            alignment: 1,
        }
    }
    
    pub fn with_type(start_index: usize, block_type: BlockType) -> Self {
        Self {
            start_index,
            block_type,
            section_options: SectionOption::None,
            alignment: 1,
        }
    }

    pub fn block_type(mut self, block_type: BlockType) -> Self {
        self.block_type = block_type;
        self
    }

    pub fn section_options(mut self, options: SectionOption) -> Self {
        self.section_options = options;
        self
    }

    pub fn alignment(mut self, alignment: usize) -> Self {
        self.alignment = alignment;
        self
    }

    pub fn build(self) -> CommandBlock {
        let mut block = CommandBlock::new(self.start_index, self.block_type);
        block.set_section_options(self.section_options);
        block.set_alignment(self.alignment);
        block
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::command::BaseCommand;

    #[test]
    fn test_command_block_new() {
        let block = CommandBlock::new(0, BlockType::Basic);
        assert_eq!(block.start_index(), 0);
        assert!(block.is_executable());
        assert_eq!(block.command_count(), 0);
    }

    #[test]
    fn test_command_block_add_command() {
        let mut block = CommandBlock::new(0, BlockType::Basic);
        let cmd = Box::new(BaseCommand::new());
        block.add_command(cmd);
        assert_eq!(block.command_count(), 1);
    }

    #[test]
    fn test_command_block_section_options() {
        let mut block = CommandBlock::new(0, BlockType::Basic);
        block.include_section_option(SectionOption::BeginSection);
        assert!(block.section_options().contains(SectionOption::BeginSection));

        block.exclude_section_option(SectionOption::BeginSection);
        assert!(!block.section_options().contains(SectionOption::BeginSection));
    }

    #[test]
    fn test_ext_command() {
        let mut ext = ExtCommand::new(0x1000);
        assert_eq!(ext.address(), 0x1000);

        ext.set_address(0x2000);
        assert_eq!(ext.address(), 0x2000);
    }

    #[test]
    fn test_ext_command_compare() {
        let ext1 = ExtCommand::new(0x1000);
        let mut ext2 = ExtCommand::new(0x2000);
        
        assert_eq!(ext1.CompareWith(&ext2), -1);
        assert_eq!(ext2.CompareWith(&ext1), 1);
        assert_eq!(ext1.CompareWith(&ext1), 0);
        
        ext2.set_address(0x1000);
        assert_eq!(ext1.CompareWith(&ext2), 0);
    }

    #[test]
    fn test_ext_command_list() {
        let mut list = ExtCommandList::new();
        assert!(list.is_empty());

        list.create(0x1000);
        list.create(0x2000);

        assert_eq!(list.len(), 2);

        let found = list.find_by_address(0x1000);
        assert!(found.is_some());
    }

    #[test]
    fn test_ext_command_list_add_remove_object() {
        let mut list = ExtCommandList::new();
        let ext = ExtCommand::new(0x1000);
        
        list.AddObject(ext);
        assert_eq!(list.len(), 1);
        
        let ext_to_remove = ExtCommand::new(0x1000);
        assert!(list.RemoveObject(&ext_to_remove));
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn test_command_block_list() {
        let mut list = CommandBlockList::new();
        assert!(list.is_empty());

        list.create(0, BlockType::Basic);
        list.create(10, BlockType::Data);

        assert_eq!(list.len(), 2);

        let executable = list.first_executable();
        assert!(executable.is_some());
        assert_eq!(executable.unwrap().start_index(), 0);
    }

    #[test]
    fn test_block_statistics() {
        let mut block = CommandBlock::new(0, BlockType::Basic);
        block.add_command(Box::new(BaseCommand::new()));
        block.add_command(Box::new(BaseCommand::new()));

        let stats = block.statistics();
        assert_eq!(stats.command_count, 2);
        assert!(stats.is_executable);
    }

    #[test]
    fn test_block_list_statistics() {
        let mut list = CommandBlockList::new();
        list.create(0, BlockType::Basic);
        list.create(10, BlockType::Data);

        let stats = list.statistics();
        assert_eq!(stats.block_count, 2);
        assert_eq!(stats.executable_blocks, 1);
    }

    #[test]
    fn test_block_builder() {
        let block = BlockBuilder::new(0)
            .block_type(BlockType::Basic)
            .section_options(SectionOption::BeginSection)
            .alignment(16)
            .build();

        assert_eq!(block.start_index(), 0);
        assert!(block.is_executable());
        assert!(block.section_options().contains(SectionOption::BeginSection));
        assert_eq!(block.alignment(), 16);
    }

    #[test]
    fn test_contains_address() {
        let mut block = CommandBlock::new(0, BlockType::Basic);

        let mut cmd1 = BaseCommand::new();
        cmd1.set_address(0x1000);
        block.add_command(Box::new(cmd1));

        let mut cmd2 = BaseCommand::new();
        cmd2.set_address(0x1005);
        block.add_command(Box::new(cmd2));

        assert!(block.contains_address(0x1000));
        assert!(block.contains_address(0x1005));
        assert!(!block.contains_address(0x2000));
    }

    #[test]
    fn test_command_block_registr() {
        let mut block = CommandBlock::new(0, BlockType::Basic);
        
        // 测试寄存器分配
        let reg = block.GetRegistr(OperandSize::DWord, 0, true);
        assert_eq!(reg, 0);
        assert_eq!(block.registr_count(), 1);
        
        // 再次分配相同寄存器
        let reg2 = block.GetRegistr(OperandSize::DWord, 0, false);
        assert_eq!(reg2, 0);
    }

    #[test]
    fn test_command_block_indices() {
        let mut block = CommandBlock::new(10, BlockType::Basic);
        assert_eq!(block.start_index(), 10);
        assert_eq!(block.end_index(), 10);
        
        block.add_command(Box::new(BaseCommand::new()));
        assert_eq!(block.end_index(), 11);
        
        block.set_start_index(5);
        block.update_indices();
        assert_eq!(block.start_index(), 5);
        assert_eq!(block.end_index(), 6);
    }
}
