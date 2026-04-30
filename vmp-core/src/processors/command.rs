//! Processors 命令实现
//!
//! 从 C++ 的 proc_command.h/cc 迁移

use crate::error::{Result, VmpError};
use super::types::*;
use super::interfaces::*;
use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// VM 命令基类
/// 
/// 对应 C++ 的 BaseVMCommand
pub struct BaseVMCommand {
    /// 所属命令
    owner: Option<Arc<dyn ICommand>>,
    /// 地址
    address: u64,
    /// 转储大小
    dump_size: usize,
}

impl BaseVMCommand {
    pub fn new() -> Self {
        Self {
            owner: None,
            address: 0,
            dump_size: 0,
        }
    }

    pub fn with_owner(owner: Arc<dyn ICommand>) -> Self {
        Self {
            owner: Some(owner),
            address: 0,
            dump_size: 0,
        }
    }

    /// 设置所属命令
    pub fn set_owner(&mut self, owner: Arc<dyn ICommand>) {
        self.owner = Some(owner);
    }

    /// 获取所属命令
    pub fn owner(&self) -> Option<&Arc<dyn ICommand>> {
        self.owner.as_ref()
    }

    /// 设置地址
    pub fn set_address(&mut self, address: u64) {
        self.address = address;
    }

    /// 获取地址
    pub fn address(&self) -> u64 {
        self.address
    }

    /// 设置转储大小
    pub fn set_dump_size(&mut self, size: usize) {
        self.dump_size = size;
    }

    /// 获取转储大小
    pub fn dump_size(&self) -> usize {
        self.dump_size
    }
}

impl Default for BaseVMCommand {
    fn default() -> Self {
        Self::new()
    }
}

/// 内部链接
/// 
/// 对应 C++ 的 InternalLink
pub struct InternalLink {
    /// 链接类型
    link_type: InternalLinkType,
    /// 源命令
    from_command: Option<Arc<dyn IVMCommand>>,
    /// 目标命令
    to_command: Option<Arc<dyn Any>>,
}

impl InternalLink {
    pub fn new(
        link_type: InternalLinkType,
        from_command: Option<Arc<dyn IVMCommand>>,
        to_command: Option<Arc<dyn Any>>,
    ) -> Self {
        Self {
            link_type,
            from_command,
            to_command,
        }
    }

    /// 获取链接类型
    pub fn link_type(&self) -> InternalLinkType {
        self.link_type
    }

    /// 获取源命令
    pub fn from_command(&self) -> Option<&Arc<dyn IVMCommand>> {
        self.from_command.as_ref()
    }

    /// 获取目标命令
    pub fn to_command(&self) -> Option<&Arc<dyn Any>> {
        self.to_command.as_ref()
    }
}

/// 内部链接列表
/// 
/// 对应 C++ 的 InternalLinkList
pub struct InternalLinkList {
    links: Vec<InternalLink>,
}

impl InternalLinkList {
    pub fn new() -> Self {
        Self { links: Vec::new() }
    }

    /// 添加链接
    pub fn add(
        &mut self,
        link_type: InternalLinkType,
        from_command: Option<Arc<dyn IVMCommand>>,
        to_command: Option<Arc<dyn Any>>,
    ) -> &InternalLink {
        self.links.push(InternalLink::new(link_type, from_command, to_command));
        self.links.last().unwrap()
    }

    /// 获取链接数量
    pub fn len(&self) -> usize {
        self.links.len()
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    /// 获取链接
    pub fn get(&self, index: usize) -> Option<&InternalLink> {
        self.links.get(index)
    }

    /// 迭代器
    pub fn iter(&self) -> impl Iterator<Item = &InternalLink> {
        self.links.iter()
    }

    /// 清空
    pub fn clear(&mut self) {
        self.links.clear();
    }
}

impl Default for InternalLinkList {
    fn default() -> Self {
        Self::new()
    }
}

/// 命令基类
/// 
/// 对应 C++ 的 BaseCommand
pub struct BaseCommand {
    /// 指令字节码
    dump: Vec<u8>,
    /// 地址
    address: AtomicU64,
    /// VM 地址
    vm_address: AtomicU64,
    /// 所属函数
    owner: Option<Arc<dyn IFunction>>,
    /// 命令链接
    link: Option<Box<dyn ICommandLink>>,
    /// 所属块
    block: Option<Box<dyn ICommandBlock>>,
    /// 命令选项
    options: CommandOption,
    /// 注释
    comment: CommentInfo,
    /// 对齐
    alignment: usize,
    /// 标签
    tag: u8,
    /// 地址范围
    address_range: Option<AddressRange>,
}

impl BaseCommand {
    pub fn new() -> Self {
        Self {
            dump: Vec::new(),
            address: AtomicU64::new(0),
            vm_address: AtomicU64::new(0),
            owner: None,
            link: None,
            block: None,
            options: CommandOption::empty(),
            comment: CommentInfo::default(),
            alignment: 1,
            tag: 0,
            address_range: None,
        }
    }

    /// 从数据创建
    pub fn from_data(data: &[u8]) -> Self {
        let mut cmd = Self::new();
        cmd.dump = data.to_vec();
        cmd
    }

    /// 从字符串创建
    pub fn from_string(s: &str) -> Self {
        let mut cmd = Self::new();
        cmd.dump = s.as_bytes().to_vec();
        cmd
    }

    /// 从文件创建命令（读取指定大小）
    pub fn from_file(file: &mut dyn File, size: usize) -> Result<Self> {
        let mut cmd = Self::new();
        cmd.read_from_file(file, size)?;
        Ok(cmd)
    }

    /// 从文件读取指定字节数到转储
    pub fn read_from_file(&mut self, file: &mut dyn File, count: usize) -> Result<usize> {
        let mut buffer = vec![0u8; count];
        let bytes_read = file.read_bytes(&mut buffer)?;
        self.dump.extend_from_slice(&buffer[..bytes_read]);
        Ok(bytes_read)
    }

    /// 从文件读取单个字节
    pub fn read_byte_from_file(&mut self, file: &mut dyn File) -> Result<u8> {
        let byte = file.read_u8()?;
        self.dump.push(byte);
        Ok(byte)
    }

    /// 从文件读取字 (2字节)
    pub fn read_word_from_file(&mut self, file: &mut dyn File) -> Result<u16> {
        let word = file.read_u16()?;
        self.push_word(word);
        Ok(word)
    }

    /// 从文件读取双字 (4字节)
    pub fn read_dword_from_file(&mut self, file: &mut dyn File) -> Result<u32> {
        let dword = file.read_u32()?;
        self.push_dword(dword);
        Ok(dword)
    }

    /// 从文件读取四字 (8字节)
    pub fn read_qword_from_file(&mut self, file: &mut dyn File) -> Result<u64> {
        let qword = file.read_u64()?;
        self.push_qword(qword);
        Ok(qword)
    }

    /// 获取转储值
    pub fn dump_value(&self, pos: usize, size: OperandSize) -> u64 {
        let bytes = size.size_in_bytes();
        if pos + bytes > self.dump.len() {
            return 0;
        }

        match size {
            OperandSize::Byte => self.dump[pos] as u64,
            OperandSize::Word => {
                let bytes = [self.dump[pos], self.dump[pos + 1]];
                u16::from_le_bytes(bytes) as u64
            }
            OperandSize::DWord => {
                let bytes = [
                    self.dump[pos],
                    self.dump[pos + 1],
                    self.dump[pos + 2],
                    self.dump[pos + 3],
                ];
                u32::from_le_bytes(bytes) as u64
            }
            OperandSize::QWord => {
                let bytes = [
                    self.dump[pos],
                    self.dump[pos + 1],
                    self.dump[pos + 2],
                    self.dump[pos + 3],
                    self.dump[pos + 4],
                    self.dump[pos + 5],
                    self.dump[pos + 6],
                    self.dump[pos + 7],
                ];
                u64::from_le_bytes(bytes)
            }
            _ => 0,
        }
    }

    /// 获取原始转储
    pub fn raw_dump(&self) -> &[u8] {
        &self.dump
    }

    /// 获取转储大小
    pub fn dump_size(&self) -> usize {
        self.dump.len()
    }

    /// 获取 VM 转储大小
    pub fn vm_dump_size(&self) -> usize {
        // 默认与转储大小相同，子类可覆盖
        self.dump.len()
    }

    /// 清空命令
    pub fn clear(&mut self) {
        self.dump.clear();
        self.address.store(0, Ordering::SeqCst);
        self.vm_address.store(0, Ordering::SeqCst);
    }

    /// 设置 VM 地址
    pub fn set_vm_address(&mut self, address: u64) {
        self.vm_address.store(address, Ordering::SeqCst);
    }

    /// 获取 VM 地址
    pub fn vm_address(&self) -> u64 {
        self.vm_address.load(Ordering::SeqCst)
    }

    /// 从缓冲区读取
    pub fn read_from_buffer(&mut self, buffer: &[u8], _file: &dyn File) -> Result<usize> {
        self.dump = buffer.to_vec();
        Ok(buffer.len())
    }

    /// 比较转储
    pub fn compare_dump(&self, buffer: &[u8]) -> bool {
        self.dump == buffer
    }

    /// 设置转储
    pub fn set_dump(&mut self, buffer: &[u8]) {
        self.dump = buffer.to_vec();
    }

    /// 添加字节
    pub fn push_byte(&mut self, value: u8) {
        self.dump.push(value);
    }

    /// 添加字
    pub fn push_word(&mut self, value: u16) {
        self.dump.extend_from_slice(&value.to_le_bytes());
    }

    /// 添加双字
    pub fn push_dword(&mut self, value: u32) {
        self.dump.extend_from_slice(&value.to_le_bytes());
    }

    /// 添加四字
    pub fn push_qword(&mut self, value: u64) {
        self.dump.extend_from_slice(&value.to_le_bytes());
    }

    /// 插入字节
    pub fn insert_byte(&mut self, position: usize, value: u8) {
        if position <= self.dump.len() {
            self.dump.insert(position, value);
        }
    }

    /// 写入双字
    pub fn write_dword(&mut self, position: usize, value: u32) {
        if position + 4 <= self.dump.len() {
            self.dump[position..position + 4].copy_from_slice(&value.to_le_bytes());
        }
    }

    /// 读取字节
    pub fn read_byte(&self, position: usize) -> Option<u8> {
        self.dump.get(position).copied()
    }

    /// 读取字
    pub fn read_word(&self, position: usize) -> Option<u16> {
        if position + 2 <= self.dump.len() {
            let bytes = [self.dump[position], self.dump[position + 1]];
            Some(u16::from_le_bytes(bytes))
        } else {
            None
        }
    }

    /// 读取双字
    pub fn read_dword(&self, position: usize) -> Option<u32> {
        if position + 4 <= self.dump.len() {
            let bytes = [
                self.dump[position],
                self.dump[position + 1],
                self.dump[position + 2],
                self.dump[position + 3],
            ];
            Some(u32::from_le_bytes(bytes))
        } else {
            None
        }
    }

    /// 读取四字
    pub fn read_qword(&self, position: usize) -> Option<u64> {
        if position + 8 <= self.dump.len() {
            let bytes = [
                self.dump[position],
                self.dump[position + 1],
                self.dump[position + 2],
                self.dump[position + 3],
                self.dump[position + 4],
                self.dump[position + 5],
                self.dump[position + 6],
                self.dump[position + 7],
            ];
            Some(u64::from_le_bytes(bytes))
        } else {
            None
        }
    }

    /// 编译信息
    pub fn compile_info(&mut self) {
        // 基础实现为空，子类可覆盖
    }

    /// 获取注释文本
    pub fn comment_text(&self) -> &str {
        &self.comment.value
    }

    /// 设置对齐
    pub fn set_alignment(&mut self, alignment: usize) {
        self.alignment = alignment;
    }

    /// 获取对齐
    pub fn alignment(&self) -> usize {
        self.alignment
    }

    /// 设置地址范围
    pub fn set_address_range(&mut self, range: AddressRange) {
        self.address_range = Some(range);
    }

    /// 获取地址范围
    pub fn address_range(&self) -> Option<&AddressRange> {
        self.address_range.as_ref()
    }

    /// 获取可变地址范围
    pub fn address_range_mut(&mut self) -> Option<&mut AddressRange> {
        self.address_range.as_mut()
    }

    /// 清除地址范围
    pub fn clear_address_range(&mut self) {
        self.address_range = None;
    }

    /// 设置标签
    pub fn set_tag(&mut self, tag: u8) {
        self.tag = tag;
    }

    /// 获取标签
    pub fn tag(&self) -> u8 {
        self.tag
    }

    /// 获取转储字符串
    pub fn dump_str(&self) -> String {
        self.dump
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// 调整转储大小
    pub fn resize_dump(&mut self, new_size: usize) {
        self.dump.resize(new_size, 0);
    }

    /// 预分配转储空间
    pub fn reserve_dump(&mut self, additional: usize) {
        self.dump.reserve(additional);
    }

    /// 裁剪转储（移除末尾的空字节）
    pub fn trim_dump(&mut self) {
        while let Some(&last) = self.dump.last() {
            if last == 0 {
                self.dump.pop();
            } else {
                break;
            }
        }
    }
}

impl Default for BaseCommand {
    fn default() -> Self {
        Self::new()
    }
}

// 实现 ICommand trait
impl ICommand for BaseCommand {
    fn address(&self) -> u64 {
        self.address.load(Ordering::SeqCst)
    }

    fn command_type(&self) -> CommandType {
        0 // 基础实现返回0
    }

    fn text(&self) -> String {
        format!("Command @ 0x{:016X}", self.address())
    }

    fn comment(&self) -> CommentInfo {
        self.comment.clone()
    }

    fn set_comment(&mut self, comment: CommentInfo) {
        self.comment = comment;
    }

    fn options(&self) -> CommandOption {
        self.options
    }

    fn link(&self) -> Option<&dyn ICommandLink> {
        self.link.as_ref().map(|l| l.as_ref())
    }

    fn set_link(&mut self, link: Option<Box<dyn ICommandLink>>) {
        self.link = link;
    }

    fn dump(&self, index: usize) -> Option<u8> {
        self.dump.get(index).copied()
    }

    fn dump_size(&self) -> usize {
        self.dump.len()
    }

    fn original_dump_size(&self) -> usize {
        self.dump.len()
    }

    fn vm_dump_size(&self) -> usize {
        self.dump.len()
    }

    fn clear(&mut self) {
        self.dump.clear();
    }

    fn compile_to_native(&mut self) {
        // 基础实现为空
    }

    fn compile_link(&mut self, _ctx: &CompileContext) {
        // 基础实现为空
    }

    fn prepare_link(&mut self, _ctx: &CompileContext) {
        // 基础实现为空
    }

    fn compile_info(&mut self) {
        BaseCommand::compile_info(self);
    }

    fn set_operand_value(&mut self, _operand_index: usize, _value: u64) {
        // 基础实现为空
    }

    fn set_link_value(&mut self, _link_index: usize, _value: u64) {
        // 基础实现为空
    }

    fn set_jmp_value(&mut self, _link_index: usize, _value: u64) {
        // 基础实现为空
    }

    fn set_address(&mut self, address: u64) {
        self.address.store(address, Ordering::SeqCst);
    }

    fn vm_address(&self) -> u64 {
        self.vm_address.load(Ordering::SeqCst)
    }

    fn set_vm_address(&mut self, address: u64) {
        self.vm_address.store(address, Ordering::SeqCst);
    }

    fn read_from_buffer(&mut self, buffer: &[u8], file: &dyn File) -> Result<usize> {
        BaseCommand::read_from_buffer(self, buffer, file)
    }

    fn alignment(&self) -> usize {
        self.alignment
    }

    fn block(&self) -> Option<&dyn ICommandBlock> {
        self.block.as_ref().map(|b| b.as_ref())
    }

    fn set_block(&mut self, block: Option<Box<dyn ICommandBlock>>) {
        self.block = block;
    }

    fn rebase(&mut self, delta_base: u64) {
        let old_addr = self.address.load(Ordering::SeqCst);
        self.address.store(old_addr + delta_base, Ordering::SeqCst);
        
        let old_vm_addr = self.vm_address.load(Ordering::SeqCst);
        if old_vm_addr != 0 {
            self.vm_address.store(old_vm_addr + delta_base, Ordering::SeqCst);
        }
    }

    fn owner(&self) -> Option<&dyn IFunction> {
        self.owner.as_ref().map(|o| o.as_ref())
    }

    fn clone_command(&self, _owner: Box<dyn IFunction>) -> Box<dyn ICommand> {
        Box::new(BaseCommand {
            dump: self.dump.clone(),
            address: AtomicU64::new(self.address.load(Ordering::SeqCst)),
            vm_address: AtomicU64::new(self.vm_address.load(Ordering::SeqCst)),
            owner: None,
            link: None,
            block: None,
            options: self.options,
            comment: self.comment.clone(),
            alignment: self.alignment,
            tag: self.tag,
            address_range: self.address_range,
        })
    }

    fn add_link_to_command(&mut self, _operand_index: i32, _link_type: LinkType, _to_command: Box<dyn ICommand>) -> Box<dyn ICommandLink> {
        unimplemented!("BaseCommand::add_link_to_command")
    }

    fn add_link_to_address(&mut self, _operand_index: i32, _link_type: LinkType, _to_address: u64) -> Box<dyn ICommandLink> {
        unimplemented!("BaseCommand::add_link_to_address")
    }

    fn include_section_option(&mut self, option: SectionOption) {
        self.options |= CommandOption::from_bits_truncate(option.bits() as u32);
    }

    fn section_options(&self) -> SectionOption {
        SectionOption::from_bits_truncate(self.options.bits() as u16)
    }

    fn is_data(&self) -> bool {
        self.options.contains(CommandOption::DataSegment)
    }

    fn is_end(&self) -> bool {
        self.options.contains(CommandOption::ClearOriginalCode)
    }

    fn include_option(&mut self, value: CommandOption) {
        self.options |= value;
    }

    fn exclude_option(&mut self, value: CommandOption) {
        self.options &= !value;
    }

    fn set_tag(&mut self, tag: u8) {
        self.tag = tag;
    }

    fn tag(&self) -> u8 {
        self.tag
    }

    fn merge(&mut self, _command: Box<dyn ICommand>) -> bool {
        false // 基础实现返回false
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// 命令列表
pub struct CommandList {
    commands: Vec<Box<dyn ICommand>>,
}

impl CommandList {
    pub fn new() -> Self {
        Self { commands: Vec::new() }
    }

    /// 添加命令
    pub fn add(&mut self, command: Box<dyn ICommand>) -> &mut dyn ICommand {
        self.commands.push(command);
        self.commands.last_mut().unwrap().as_mut()
    }

    /// 获取命令数量
    pub fn len(&self) -> usize {
        self.commands.len()
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    /// 获取命令
    pub fn get(&self, index: usize) -> Option<&dyn ICommand> {
        self.commands.get(index).map(|c| c.as_ref())
    }

    /// 获取可变命令
    pub fn get_mut(&mut self, index: usize) -> Option<&mut dyn ICommand> {
        self.commands.get_mut(index).map(|c| c.as_mut())
    }

    /// 迭代器
    pub fn iter(&self) -> impl Iterator<Item = &dyn ICommand> {
        self.commands.iter().map(|c| c.as_ref())
    }

    /// 可变迭代器
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut dyn ICommand> {
        self.commands.iter_mut().map(|c| c.as_mut())
    }

    /// 清空
    pub fn clear(&mut self) {
        self.commands.clear();
    }

    /// 按地址查找命令
    pub fn find_by_address(&self, address: u64) -> Option<&dyn ICommand> {
        self.commands.iter().find(|c| c.address() == address).map(|c| c.as_ref())
    }

    /// 按地址查找可变命令
    pub fn find_by_address_mut(&mut self, address: u64) -> Option<&mut dyn ICommand> {
        self.commands.iter_mut().find(|c| c.address() == address).map(|c| c.as_mut())
    }

    /// 排序
    pub fn sort_by_address(&mut self) {
        self.commands.sort_by(|a, b| a.address().cmp(&b.address()));
    }
}

impl Default for CommandList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_command_new() {
        let cmd = BaseCommand::new();
        assert_eq!(cmd.dump_size(), 0);
        assert_eq!(cmd.address(), 0);
    }

    #[test]
    fn test_base_command_from_data() {
        let data = vec![0x48, 0x89, 0xC3]; // mov rbx, rax
        let cmd = BaseCommand::from_data(&data);
        assert_eq!(cmd.dump_size(), 3);
        assert_eq!(cmd.dump(0), Some(0x48));
        assert_eq!(cmd.dump(1), Some(0x89));
    }

    #[test]
    fn test_base_command_push_bytes() {
        let mut cmd = BaseCommand::new();
        cmd.push_byte(0x48);
        cmd.push_word(0x1234);
        cmd.push_dword(0xDEADBEEF);
        
        assert_eq!(cmd.dump_size(), 7);
        assert_eq!(cmd.read_byte(0), Some(0x48));
        assert_eq!(cmd.read_word(1), Some(0x1234));
        assert_eq!(cmd.read_dword(3), Some(0xDEADBEEF));
    }

    #[test]
    fn test_base_command_address() {
        let mut cmd = BaseCommand::new();
        cmd.set_address(0x140001000);
        assert_eq!(cmd.address(), 0x140001000);
        
        cmd.rebase(0x1000);
        assert_eq!(cmd.address(), 0x140002000);
    }

    #[test]
    fn test_base_command_options() {
        let mut cmd = BaseCommand::new();
        cmd.include_option(CommandOption::NeedCompile);
        assert!(cmd.options().contains(CommandOption::NeedCompile));
        
        cmd.exclude_option(CommandOption::NeedCompile);
        assert!(!cmd.options().contains(CommandOption::NeedCompile));
    }

    #[test]
    fn test_base_command_dump_str() {
        let mut cmd = BaseCommand::new();
        cmd.push_byte(0x48);
        cmd.push_byte(0x89);
        cmd.push_byte(0xC3);
        
        assert_eq!(cmd.dump_str(), "48 89 C3");
    }

    #[test]
    fn test_internal_link_list() {
        let mut list = InternalLinkList::new();
        assert!(list.is_empty());
        
        list.add(InternalLinkType::CRCValue, None, None);
        assert_eq!(list.len(), 1);
        
        let link = list.get(0).unwrap();
        assert_eq!(link.link_type(), InternalLinkType::CRCValue);
    }

    #[test]
    fn test_command_list() {
        let mut list = CommandList::new();
        assert!(list.is_empty());
        
        let cmd = Box::new(BaseCommand::new());
        list.add(cmd);
        assert_eq!(list.len(), 1);
        
        let retrieved = list.get(0);
        assert!(retrieved.is_some());
    }
}
