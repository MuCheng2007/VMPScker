//! Processors 命令链接系统
//!
//! 从 C++ 的 proc_command_link.h/cc 迁移

use crate::error::{Result, VmpError};
use super::types::*;
use super::interfaces::*;
use std::any::Any;
use std::sync::Arc;

/// 命令链接
///
/// 对应 C++ 的 CommandLink
pub struct CommandLink {
    /// 所属链接列表
    owner: Option<Arc<CommandLinkList>>,
    /// 链接类型
    link_type: LinkType,
    /// 操作数索引
    operand_index: i32,
    /// 目标命令
    to_command: Option<Arc<dyn ICommand>>,
    /// 目标地址
    to_address: u64,
    /// 是否已链接
    is_linked: bool,
    /// 链接值（加密后的值）
    link_value: u64,
    /// 子链接列表（用于 switch/case）
    sub_links: Vec<CommandLink>,
    /// 源命令
    from_command: Option<Arc<dyn ICommand>>,
    /// 父命令
    parent_command: Option<Arc<dyn ICommand>>,
    /// 下一个命令
    next_command: Option<Arc<dyn ICommand>>,
    /// 子值
    sub_value: u64,
    /// 加密器
    cryptor: Option<Box<dyn ICryptor>>,
    /// 门命令列表
    gate_commands: Vec<Arc<dyn ICommand>>,
    /// 基础函数信息
    base_function_info: Option<Arc<dyn IFunction>>,
    /// 是否反向
    is_inverse: bool,
    /// 是否已解析
    parsed: bool,
}

impl Clone for CommandLink {
    fn clone(&self) -> Self {
        Self {
            owner: None, // owner 不克隆
            link_type: self.link_type,
            operand_index: self.operand_index,
            to_command: self.to_command.clone(),
            to_address: self.to_address,
            is_linked: self.is_linked,
            link_value: self.link_value,
            sub_links: self.sub_links.clone(),
            from_command: self.from_command.clone(),
            parent_command: self.parent_command.clone(),
            next_command: self.next_command.clone(),
            sub_value: self.sub_value,
            cryptor: self.cryptor.clone(),
            gate_commands: self.gate_commands.clone(),
            base_function_info: self.base_function_info.clone(),
            is_inverse: self.is_inverse,
            parsed: self.parsed,
        }
    }
}

impl CommandLink {
    /// 创建新的命令链接
    pub fn new(link_type: LinkType, operand_index: i32) -> Self {
        Self {
            owner: None,
            link_type,
            operand_index,
            to_command: None,
            to_address: 0,
            is_linked: false,
            link_value: 0,
            sub_links: Vec::new(),
            from_command: None,
            parent_command: None,
            next_command: None,
            sub_value: 0,
            cryptor: None,
            gate_commands: Vec::new(),
            base_function_info: None,
            is_inverse: false,
            parsed: false,
        }
    }

    /// 创建指向命令的链接
    pub fn new_to_command(link_type: LinkType, operand_index: i32, command: Arc<dyn ICommand>) -> Self {
        let mut link = Self::new(link_type, operand_index);
        link.to_command = Some(command);
        link
    }

    /// 创建指向地址的链接
    pub fn new_to_address(link_type: LinkType, operand_index: i32, address: u64) -> Self {
        let mut link = Self::new(link_type, operand_index);
        link.to_address = address;
        link
    }

    /// 克隆链接到新的所有者
    pub fn clone_with_owner(&self, owner: Arc<CommandLinkList>) -> Self {
        let mut cloned = self.clone();
        cloned.owner = Some(owner);
        cloned
    }

    /// 获取所属列表
    pub fn owner(&self) -> Option<&Arc<CommandLinkList>> {
        self.owner.as_ref()
    }

    /// 设置所属列表
    pub fn set_owner(&mut self, owner: Option<Arc<CommandLinkList>>) {
        self.owner = owner;
    }

    /// 获取链接类型
    pub fn link_type(&self) -> LinkType {
        self.link_type
    }

    /// 设置链接类型
    pub fn set_link_type(&mut self, link_type: LinkType) {
        self.link_type = link_type;
    }

    /// 获取操作数索引
    pub fn operand_index(&self) -> i32 {
        self.operand_index
    }

    /// 设置操作数索引
    pub fn set_operand_index(&mut self, index: i32) {
        self.operand_index = index;
    }

    /// 获取目标命令
    pub fn to_command(&self) -> Option<&Arc<dyn ICommand>> {
        self.to_command.as_ref()
    }

    /// 设置目标命令
    pub fn set_to_command(&mut self, command: Option<Arc<dyn ICommand>>) {
        self.to_command = command;
    }

    /// 获取目标地址
    pub fn to_address(&self) -> u64 {
        self.to_address
    }

    /// 设置目标地址
    pub fn set_to_address(&mut self, address: u64) {
        self.to_address = address;
    }

    /// 是否已链接
    pub fn is_linked(&self) -> bool {
        self.is_linked
    }

    /// 设置是否已链接
    pub fn set_linked(&mut self, linked: bool) {
        self.is_linked = linked;
    }

    /// 获取链接值
    pub fn link_value(&self) -> u64 {
        self.link_value
    }

    /// 设置链接值
    pub fn set_link_value(&mut self, value: u64) {
        self.link_value = value;
    }

    /// 添加子链接
    pub fn add_sub_link(&mut self, link: CommandLink) {
        self.sub_links.push(link);
    }

    /// 获取子链接
    pub fn sub_links(&self) -> &[CommandLink] {
        &self.sub_links
    }

    /// 获取可变子链接
    pub fn sub_links_mut(&mut self) -> &mut Vec<CommandLink> {
        &mut self.sub_links
    }

    // 源命令方法
    pub fn from_command(&self) -> Option<&Arc<dyn ICommand>> {
        self.from_command.as_ref()
    }

    pub fn set_from_command(&mut self, cmd: Option<Arc<dyn ICommand>>) {
        self.from_command = cmd;
    }

    // 父命令方法
    pub fn parent_command(&self) -> Option<&Arc<dyn ICommand>> {
        self.parent_command.as_ref()
    }

    pub fn set_parent_command(&mut self, cmd: Option<Arc<dyn ICommand>>) {
        self.parent_command = cmd;
    }

    // 下一个命令方法
    pub fn next_command(&self) -> Option<&Arc<dyn ICommand>> {
        self.next_command.as_ref()
    }

    pub fn set_next_command(&mut self, cmd: Option<Arc<dyn ICommand>>) {
        self.next_command = cmd;
    }

    // 子值方法
    pub fn sub_value(&self) -> u64 {
        self.sub_value
    }

    pub fn set_sub_value(&mut self, value: u64) {
        self.sub_value = value;
    }

    // 加密器方法
    pub fn cryptor(&self) -> Option<&dyn ICryptor> {
        self.cryptor.as_ref().map(|c| c.as_ref())
    }

    pub fn set_cryptor(&mut self, cryptor: Option<Box<dyn ICryptor>>) {
        self.cryptor = cryptor;
    }

    /// 使用加密器加密
    pub fn encrypt_with_cryptor(&mut self) -> Result<()> {
        if let Some(ref cryptor) = self.cryptor {
            self.link_value = cryptor.encrypt(self.link_value);
        }
        Ok(())
    }

    /// 加密值
    pub fn encrypt(&self, value: u64) -> u64 {
        if let Some(ref cryptor) = self.cryptor {
            cryptor.encrypt(value)
        } else {
            value
        }
    }

    // 门命令方法
    pub fn gate_commands(&self) -> &[Arc<dyn ICommand>] {
        &self.gate_commands
    }

    /// 获取指定索引的门命令
    pub fn gate_command(&self, index: usize) -> Option<&Arc<dyn ICommand>> {
        self.gate_commands.get(index)
    }

    pub fn add_gate_command(&mut self, cmd: Arc<dyn ICommand>) {
        self.gate_commands.push(cmd);
    }

    pub fn clear_gate_commands(&mut self) {
        self.gate_commands.clear();
    }

    // 基础函数信息方法
    pub fn base_function_info(&self) -> Option<&Arc<dyn IFunction>> {
        self.base_function_info.as_ref()
    }

    pub fn set_base_function_info(&mut self, info: Option<Arc<dyn IFunction>>) {
        self.base_function_info = info;
    }

    // 反向标志方法
    pub fn is_inverse(&self) -> bool {
        self.is_inverse
    }

    pub fn set_inverse(&mut self, inverse: bool) {
        self.is_inverse = inverse;
    }

    // 解析标志方法
    pub fn parsed(&self) -> bool {
        self.parsed
    }

    pub fn set_parsed(&mut self, parsed: bool) {
        self.parsed = parsed;
    }

    /// 链接到命令
    pub fn link_to_command(&mut self, cmd: Arc<dyn ICommand>) {
        self.to_command = Some(cmd);
        self.is_linked = true;
    }

    /// 链接到地址
    pub fn link_to_address(&mut self, address: u64) {
        self.to_address = address;
        self.is_linked = true;
    }

    /// 解除链接
    pub fn unlink(&mut self) {
        self.to_command = None;
        self.to_address = 0;
        self.is_linked = false;
        self.link_value = 0;
    }

    /// 更新链接
    pub fn update_link(&mut self) -> Result<()> {
        if let Some(ref cmd) = self.to_command {
            self.to_address = cmd.vm_address();
        }
        Ok(())
    }

    /// 编译链接
    ///
    /// 根据链接类型和目标计算最终的链接值
    pub fn compile_link(&mut self, ctx: &CompileContext) -> Result<()> {
        let target_address = if let Some(ref cmd) = self.to_command {
            cmd.vm_address()
        } else {
            self.to_address
        };

        // 根据链接类型进行不同的处理
        self.link_value = match self.link_type {
            LinkType::Jmp | LinkType::Call => {
                // 直接跳转/调用：计算相对偏移或绝对地址
                target_address
            }
            LinkType::JmpWithFlag | LinkType::JmpWithFlagNSFS | LinkType::JmpWithFlagNSNA | LinkType::JmpWithFlagNSNS => {
                // 条件跳转
                target_address
            }
            LinkType::Switch | LinkType::Case => {
                // Switch/Case：需要特殊处理
                self.compile_switch_link(ctx)?
            }
            LinkType::Native => {
                // 原生链接：保持原地址
                target_address
            }
            LinkType::Offset | LinkType::GateOffset | LinkType::Delta => {
                // 偏移链接
                target_address.wrapping_sub(ctx.image_base)
            }
            _ => {
                // 其他类型：默认处理
                target_address
            }
        };

        // 递归编译子链接
        for sub_link in &mut self.sub_links {
            sub_link.compile_link(ctx)?;
        }

        self.is_linked = true;
        Ok(())
    }

    /// 编译 Switch 链接
    fn compile_switch_link(&mut self, _ctx: &CompileContext) -> Result<u64> {
        // Switch 链接需要特殊处理
        // 这里简化实现，实际应该构建跳转表
        let base_address = if let Some(ref cmd) = self.to_command {
            cmd.vm_address()
        } else {
            self.to_address
        };

        // 计算所有 case 的地址
        for (i, sub_link) in self.sub_links.iter().enumerate() {
            let case_address = if let Some(ref cmd) = sub_link.to_command {
                cmd.vm_address()
            } else {
                sub_link.to_address
            };

            // 这里可以构建跳转表项
            // 简化处理：返回第一个 case 的地址
            if i == 0 {
                return Ok(case_address);
            }
        }

        Ok(base_address)
    }

    /// 重新基址
    ///
    /// 当图像基址改变时，更新链接地址
    pub fn rebase(&mut self, delta_base: i64) {
        if self.to_address != 0 {
            if delta_base >= 0 {
                self.to_address = self.to_address.wrapping_add(delta_base as u64);
            } else {
                self.to_address = self.to_address.wrapping_sub((-delta_base) as u64);
            }
        }

        // 重新计算链接值
        if self.is_linked && self.link_value != 0 {
            if delta_base >= 0 {
                self.link_value = self.link_value.wrapping_add(delta_base as u64);
            } else {
                self.link_value = self.link_value.wrapping_sub((-delta_base) as u64);
            }
        }

        // 递归处理子链接
        for sub_link in &mut self.sub_links {
            sub_link.rebase(delta_base);
        }
    }

    /// 加密地址
    ///
    /// 对目标地址进行加密处理
    pub fn encrypt_address(&mut self, key: u64) {
        self.link_value ^= key;

        for sub_link in &mut self.sub_links {
            sub_link.encrypt_address(key);
        }
    }

    /// 解密地址
    pub fn decrypt_address(&mut self, key: u64) {
        self.link_value ^= key;

        for sub_link in &mut self.sub_links {
            sub_link.decrypt_address(key);
        }
    }

    /// 获取链接描述
    pub fn description(&self) -> String {
        let type_str = match self.link_type {
            LinkType::None => "None",
            LinkType::Jmp => "Jmp",
            LinkType::Call => "Call",
            LinkType::JmpWithFlag => "JmpWithFlag",
            LinkType::Switch => "Switch",
            LinkType::Case => "Case",
            LinkType::Native => "Native",
            LinkType::Offset => "Offset",
            LinkType::SEHBlock => "SEHBlock",
            LinkType::FinallyBlock => "FinallyBlock",
            _ => "Other",
        };

        format!(
            "{} -> 0x{:016X} (op_idx: {})",
            type_str,
            self.to_address,
            self.operand_index
        )
    }
}

impl ICommandLink for CommandLink {
    fn link_type(&self) -> LinkType {
        self.link_type
    }

    fn operand_index(&self) -> i32 {
        self.operand_index
    }

    fn to_command(&self) -> Option<&dyn ICommand> {
        self.to_command.as_ref().map(|c| c.as_ref())
    }

    fn to_address(&self) -> u64 {
        self.to_address
    }

    fn compile_link(&mut self, ctx: &CompileContext) {
        let _ = CommandLink::compile_link(self, ctx);
    }

    fn rebase(&mut self, delta_base: u64) {
        CommandLink::rebase(self, delta_base as i64);
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// 命令链接列表
///
/// 对应 C++ 的 CommandLinkList
#[derive(Clone)]
pub struct CommandLinkList {
    links: Vec<CommandLink>,
}

impl CommandLinkList {
    pub fn new() -> Self {
        Self { links: Vec::new() }
    }

    /// 添加链接
    pub fn add(&mut self, link: CommandLink) -> &mut CommandLink {
        self.links.push(link);
        self.links.last_mut().unwrap()
    }

    /// 创建并添加链接到命令
    pub fn add_to_command(
        &mut self,
        link_type: LinkType,
        operand_index: i32,
        command: Arc<dyn ICommand>,
    ) -> &mut CommandLink {
        let link = CommandLink::new_to_command(link_type, operand_index, command);
        self.links.push(link);
        self.links.last_mut().unwrap()
    }

    /// 创建并添加链接到地址
    pub fn add_to_address(
        &mut self,
        link_type: LinkType,
        operand_index: i32,
        address: u64,
    ) -> &mut CommandLink {
        let link = CommandLink::new_to_address(link_type, operand_index, address);
        self.links.push(link);
        self.links.last_mut().unwrap()
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
    pub fn get(&self, index: usize) -> Option<&CommandLink> {
        self.links.get(index)
    }

    /// 获取可变链接
    pub fn get_mut(&mut self, index: usize) -> Option<&mut CommandLink> {
        self.links.get_mut(index)
    }

    /// 迭代器
    pub fn iter(&self) -> impl Iterator<Item = &CommandLink> {
        self.links.iter()
    }

    /// 可变迭代器
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut CommandLink> {
        self.links.iter_mut()
    }

    /// 按目标命令查找链接
    pub fn find_by_command(&self, command: &dyn ICommand) -> Option<&CommandLink> {
        self.links.iter().find(|l| {
            if let Some(ref cmd) = l.to_command {
                cmd.address() == command.address()
            } else {
                false
            }
        })
    }

    /// 按目标地址查找链接
    pub fn find_by_address(&self, address: u64) -> Option<&CommandLink> {
        self.links.iter().find(|l| l.to_address == address)
    }

    /// 按链接类型查找链接
    pub fn find_by_type(&self, link_type: LinkType) -> impl Iterator<Item = &CommandLink> {
        self.links.iter().filter(move |l| l.link_type == link_type)
    }

    /// 移除链接
    pub fn remove(&mut self, index: usize) -> Option<CommandLink> {
        if index < self.links.len() {
            Some(self.links.remove(index))
        } else {
            None
        }
    }

    /// 清空
    pub fn clear(&mut self) {
        self.links.clear();
    }

    /// 编译所有链接
    pub fn compile_all(&mut self, ctx: &CompileContext) -> Result<()> {
        for link in &mut self.links {
            link.compile_link(ctx)?;
        }
        Ok(())
    }

    /// 重新基址所有链接
    pub fn rebase_all(&mut self, delta_base: i64) {
        for link in &mut self.links {
            link.rebase(delta_base);
        }
    }

    /// 加密所有链接
    pub fn encrypt_all(&mut self, key: u64) {
        for link in &mut self.links {
            link.encrypt_address(key);
        }
    }

    /// 解密所有链接
    pub fn decrypt_all(&mut self, key: u64) {
        for link in &mut self.links {
            link.decrypt_address(key);
        }
    }

    /// 排序（按目标地址）
    pub fn sort_by_address(&mut self) {
        self.links.sort_by(|a, b| a.to_address.cmp(&b.to_address));
    }

    /// 获取统计信息
    pub fn statistics(&self) -> LinkStatistics {
        let mut stats = LinkStatistics::default();

        for link in &self.links {
            match link.link_type {
                LinkType::Jmp => stats.jmp_count += 1,
                LinkType::Call => stats.call_count += 1,
                LinkType::JmpWithFlag | LinkType::JmpWithFlagNSFS | LinkType::JmpWithFlagNSNA | LinkType::JmpWithFlagNSNS => {
                    stats.conditional_jmp_count += 1;
                }
                LinkType::Switch => stats.switch_count += 1,
                LinkType::Case => stats.case_count += 1,
                _ => stats.other_count += 1,
            }
        }

        stats.total_count = self.links.len();
        stats
    }
}

impl Default for CommandLinkList {
    fn default() -> Self {
        Self::new()
    }
}

/// 链接统计信息
#[derive(Debug, Clone, Default)]
pub struct LinkStatistics {
    pub total_count: usize,
    pub jmp_count: usize,
    pub call_count: usize,
    pub conditional_jmp_count: usize,
    pub switch_count: usize,
    pub case_count: usize,
    pub other_count: usize,
}

impl LinkStatistics {
    pub fn new() -> Self {
        Self::default()
    }

    /// 获取直接跳转比例
    pub fn direct_jmp_ratio(&self) -> f64 {
        if self.total_count == 0 {
            return 0.0;
        }
        self.jmp_count as f64 / self.total_count as f64
    }

    /// 获取调用比例
    pub fn call_ratio(&self) -> f64 {
        if self.total_count == 0 {
            return 0.0;
        }
        self.call_count as f64 / self.total_count as f64
    }
}

/// 链接构建器
///
/// 用于方便地构建复杂的链接结构
pub struct LinkBuilder {
    link_type: LinkType,
    operand_index: i32,
    to_address: Option<u64>,
    to_command: Option<Arc<dyn ICommand>>,
    sub_links: Vec<CommandLink>,
}

impl LinkBuilder {
    pub fn new(link_type: LinkType, operand_index: i32) -> Self {
        Self {
            link_type,
            operand_index,
            to_address: None,
            to_command: None,
            sub_links: Vec::new(),
        }
    }

    /// 设置目标地址
    pub fn to_address(mut self, address: u64) -> Self {
        self.to_address = Some(address);
        self
    }

    /// 设置目标命令
    pub fn to_command(mut self, command: Arc<dyn ICommand>) -> Self {
        self.to_command = Some(command);
        self
    }

    /// 添加子链接
    pub fn with_sub_link(mut self, link: CommandLink) -> Self {
        self.sub_links.push(link);
        self
    }

    /// 构建链接
    pub fn build(self) -> CommandLink {
        let mut link = if let Some(cmd) = self.to_command {
            CommandLink::new_to_command(self.link_type, self.operand_index, cmd)
        } else if let Some(addr) = self.to_address {
            CommandLink::new_to_address(self.link_type, self.operand_index, addr)
        } else {
            CommandLink::new(self.link_type, self.operand_index)
        };

        for sub_link in self.sub_links {
            link.add_sub_link(sub_link);
        }

        link
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::command::BaseCommand;

    #[test]
    fn test_command_link_new() {
        let link = CommandLink::new(LinkType::Jmp, 0);
        assert_eq!(link.link_type(), LinkType::Jmp);
        assert_eq!(link.operand_index(), 0);
        assert!(!link.is_linked());
    }

    #[test]
    fn test_command_link_to_address() {
        let link = CommandLink::new_to_address(LinkType::Call, 1, 0x140001000);
        assert_eq!(link.to_address(), 0x140001000);
        assert_eq!(link.link_type(), LinkType::Call);
    }

    #[test]
    fn test_command_link_rebase() {
        let mut link = CommandLink::new_to_address(LinkType::Jmp, 0, 0x1000);
        link.set_linked(true);
        link.set_link_value(0x1000);

        link.rebase(0x1000);

        assert_eq!(link.to_address(), 0x2000);
        assert_eq!(link.link_value(), 0x2000);
    }

    #[test]
    fn test_command_link_encryption() {
        let mut link = CommandLink::new_to_address(LinkType::Jmp, 0, 0x1000);
        link.set_link_value(0x1000);

        let key = 0xDEADBEEF;
        link.encrypt_address(key);
        assert_ne!(link.link_value(), 0x1000);

        link.decrypt_address(key);
        assert_eq!(link.link_value(), 0x1000);
    }

    #[test]
    fn test_command_link_list() {
        let mut list = CommandLinkList::new();
        assert!(list.is_empty());

        list.add_to_address(LinkType::Jmp, 0, 0x1000);
        list.add_to_address(LinkType::Call, 1, 0x2000);

        assert_eq!(list.len(), 2);

        let link = list.get(0).unwrap();
        assert_eq!(link.to_address(), 0x1000);
    }

    #[test]
    fn test_command_link_list_find() {
        let mut list = CommandLinkList::new();
        list.add_to_address(LinkType::Jmp, 0, 0x1000);
        list.add_to_address(LinkType::Call, 1, 0x2000);

        let found = list.find_by_address(0x2000);
        assert!(found.is_some());
        assert_eq!(found.unwrap().link_type(), LinkType::Call);
    }

    #[test]
    fn test_link_statistics() {
        let mut list = CommandLinkList::new();
        list.add_to_address(LinkType::Jmp, 0, 0x1000);
        list.add_to_address(LinkType::Jmp, 0, 0x2000);
        list.add_to_address(LinkType::Call, 1, 0x3000);
        list.add_to_address(LinkType::JmpWithFlag, 0, 0x4000);

        let stats = list.statistics();
        assert_eq!(stats.total_count, 4);
        assert_eq!(stats.jmp_count, 2);
        assert_eq!(stats.call_count, 1);
        assert_eq!(stats.conditional_jmp_count, 1);
    }

    #[test]
    fn test_link_builder() {
        let link = LinkBuilder::new(LinkType::Switch, 0)
            .to_address(0x1000)
            .build();

        assert_eq!(link.link_type(), LinkType::Switch);
        assert_eq!(link.to_address(), 0x1000);
    }

    #[test]
    fn test_command_link_description() {
        let link = CommandLink::new_to_address(LinkType::Jmp, 2, 0x140001000);
        let desc = link.description();
        assert!(desc.contains("Jmp"));
        assert!(desc.contains("140001000"));
        assert!(desc.contains("2"));
    }

    #[test]
    fn test_command_link_gate_command() {
        let mut link = CommandLink::new(LinkType::Switch, 0);
        let cmd = Arc::new(BaseCommand::new());
        link.add_gate_command(cmd.clone());
        
        assert_eq!(link.gate_commands().len(), 1);
        assert!(link.gate_command(0).is_some());
    }

    #[test]
    fn test_command_link_clone() {
        let mut link = CommandLink::new_to_address(LinkType::Jmp, 0, 0x1000);
        link.set_sub_value(0x1234);
        link.set_inverse(true);
        link.set_parsed(true);
        
        let cloned = link.clone();
        assert_eq!(cloned.to_address(), 0x1000);
        assert_eq!(cloned.sub_value(), 0x1234);
        assert!(cloned.is_inverse());
        assert!(cloned.parsed());
    }
}
