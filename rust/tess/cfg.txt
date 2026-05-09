//! 控制流图（CFG）模块
//!
//! 构建和分析控制流图。

use super::{
    BasicBlock, BasicBlockId, Decoder, DecoderConfig, DisassemblyMode,
    Instruction,
};
use super::basic_block::BasicBlockBuilder;
use crate::error::Result;
use std::collections::{HashMap, HashSet, VecDeque};

/// 控制流图
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    /// 基本块映射
    blocks: HashMap<BasicBlockId, BasicBlock>,
    /// 入口基本块
    entry_block: Option<BasicBlockId>,
    /// 出口基本块列表
    exit_blocks: HashSet<BasicBlockId>,
    /// 地址到基本块 ID 的映射
    address_to_block: HashMap<u64, BasicBlockId>,
}

impl ControlFlowGraph {
    /// 创建新的控制流图
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            entry_block: None,
            exit_blocks: HashSet::new(),
            address_to_block: HashMap::new(),
        }
    }

    /// 添加基本块
    pub fn add_block(&mut self, block: BasicBlock) {
        let id = block.id;
        self.address_to_block.insert(block.start_address, id);
        self.blocks.insert(id, block);
    }

    /// 获取基本块
    pub fn get_block(&self, id: BasicBlockId) -> Option<&BasicBlock> {
        self.blocks.get(&id)
    }

    /// 获取基本块（可变）
    pub fn get_block_mut(&mut self, id: BasicBlockId) -> Option<&mut BasicBlock> {
        self.blocks.get_mut(&id)
    }

    /// 设置入口基本块
    pub fn set_entry_block(&mut self, id: BasicBlockId) {
        self.entry_block = Some(id);
    }

    /// 获取入口基本块
    pub fn entry_block(&self) -> Option<BasicBlockId> {
        self.entry_block
    }

    /// 添加出口基本块
    pub fn add_exit_block(&mut self, id: BasicBlockId) {
        self.exit_blocks.insert(id);
    }

    /// 获取出口基本块列表
    pub fn exit_blocks(&self) -> &HashSet<BasicBlockId> {
        &self.exit_blocks
    }

    /// 获取基本块数量
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// 获取所有基本块
    pub fn blocks(&self) -> &HashMap<BasicBlockId, BasicBlock> {
        &self.blocks
    }

    /// 获取基本块迭代器
    pub fn block_iter(&self) -> impl Iterator<Item = &BasicBlock> {
        self.blocks.values()
    }

    /// 根据地址查找基本块
    pub fn find_block_by_address(&self, address: u64) -> Option<BasicBlockId> {
        self.address_to_block.get(&address).copied()
    }

    /// 查找包含地址的基本块
    pub fn find_block_containing(&self, address: u64) -> Option<BasicBlockId> {
        for (block_id, block) in &self.blocks {
            if block.contains_address(address) {
                return Some(*block_id);
            }
        }
        None
    }

    /// 连接两个基本块（添加边）
    pub fn connect_blocks(&mut self, from: BasicBlockId, to: BasicBlockId) {
        if let Some(from_block) = self.blocks.get_mut(&from) {
            from_block.add_successor(to);
        }
        if let Some(to_block) = self.blocks.get_mut(&to) {
            to_block.add_predecessor(from);
        }
    }

    /// 移除两个基本块之间的连接
    pub fn disconnect_blocks(&mut self, from: BasicBlockId, to: BasicBlockId) {
        if let Some(from_block) = self.blocks.get_mut(&from) {
            from_block.remove_successor(to);
        }
        if let Some(to_block) = self.blocks.get_mut(&to) {
            to_block.remove_predecessor(from);
        }
    }

    /// 执行深度优先搜索
    pub fn dfs<F>(&self, start: BasicBlockId, mut visitor: F)
    where
        F: FnMut(BasicBlockId, &BasicBlock),
    {
        let mut visited = HashSet::new();
        let mut stack = vec![start];

        while let Some(id) = stack.pop() {
            if visited.contains(&id) {
                continue;
            }
            visited.insert(id);

            if let Some(block) = self.blocks.get(&id) {
                visitor(id, block);

                // 将后继加入栈
                for &succ in &block.successors {
                    if !visited.contains(&succ) {
                        stack.push(succ);
                    }
                }
            }
        }
    }

    /// 执行广度优先搜索
    pub fn bfs<F>(&self, start: BasicBlockId, mut visitor: F)
    where
        F: FnMut(BasicBlockId, &BasicBlock),
    {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);
        visited.insert(start);

        while let Some(id) = queue.pop_front() {
            if let Some(block) = self.blocks.get(&id) {
                visitor(id, block);

                // 将后继加入队列
                for &succ in &block.successors {
                    if !visited.contains(&succ) {
                        visited.insert(succ);
                        queue.push_back(succ);
                    }
                }
            }
        }
    }

    /// 获取后序遍历顺序
    pub fn post_order(&self, start: BasicBlockId) -> Vec<BasicBlockId> {
        let mut visited = HashSet::new();
        let mut order = Vec::new();

        fn dfs_visit(
            cfg: &ControlFlowGraph,
            id: BasicBlockId,
            visited: &mut HashSet<BasicBlockId>,
            order: &mut Vec<BasicBlockId>,
        ) {
            if visited.contains(&id) {
                return;
            }
            visited.insert(id);

            if let Some(block) = cfg.blocks.get(&id) {
                for &succ in &block.successors {
                    dfs_visit(cfg, succ, visited, order);
                }
                order.push(id);
            }
        }

        dfs_visit(self, start, &mut visited, &mut order);
        order
    }

    /// 获取逆后序遍历顺序
    pub fn reverse_post_order(&self, start: BasicBlockId) -> Vec<BasicBlockId> {
        let mut order = self.post_order(start);
        order.reverse();
        order
    }

    /// 计算支配者
    pub fn compute_dominators(&self, start: BasicBlockId) -> HashMap<BasicBlockId, HashSet<BasicBlockId>> {
        let mut dominators: HashMap<BasicBlockId, HashSet<BasicBlockId>> = HashMap::new();
        
        // 初始化：所有节点被所有节点支配，除了入口节点只被自己支配
        for &id in self.blocks.keys() {
            if id == start {
                let mut set = HashSet::new();
                set.insert(id);
                dominators.insert(id, set);
            } else {
                dominators.insert(id, self.blocks.keys().copied().collect());
            }
        }

        // 迭代直到不动点
        let mut changed = true;
        while changed {
            changed = false;

            for &id in self.blocks.keys() {
                if id == start {
                    continue;
                }

                if let Some(block) = self.blocks.get(&id) {
                    // 新支配者集合 = 所有前驱的支配者集合的交集 ∪ {自身}
                    let mut new_dom: Option<HashSet<BasicBlockId>> = None;

                    for &pred in &block.predecessors {
                        if let Some(pred_dom) = dominators.get(&pred) {
                            new_dom = Some(match new_dom {
                                Some(current) => current.intersection(pred_dom).copied().collect(),
                                None => pred_dom.clone(),
                            });
                        }
                    }

                    if let Some(mut new_dom) = new_dom {
                        new_dom.insert(id);

                        if let Some(old_dom) = dominators.get(&id) {
                            if *old_dom != new_dom {
                                changed = true;
                                dominators.insert(id, new_dom);
                            }
                        }
                    }
                }
            }
        }

        dominators
    }

    /// 格式化 CFG
    pub fn format(&self) -> String {
        let mut result = format!("Control Flow Graph: {} blocks\n", self.block_count());

        if let Some(entry) = self.entry_block {
            result.push_str(&format!("Entry: Block {}\n", entry.value()));
        }

        if !self.exit_blocks.is_empty() {
            let exits: Vec<_> = self.exit_blocks.iter().map(|e| e.value().to_string()).collect();
            result.push_str(&format!("Exits: {}\n", exits.join(", ")));
        }

        result.push_str("\nBlocks:\n");
        for block in self.block_iter() {
            result.push_str(&block.format());
            result.push('\n');
        }

        result
    }
}

impl Default for ControlFlowGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// CFG 构建器
pub struct CfgBuilder {
    mode: DisassemblyMode,
    builder: BasicBlockBuilder,
}

impl CfgBuilder {
    /// 创建新的 CFG 构建器
    pub fn new(mode: DisassemblyMode) -> Self {
        Self {
            mode,
            builder: BasicBlockBuilder::new(),
        }
    }

    /// 从字节数组构建 CFG
    pub fn build_from_bytes(&mut self, data: &[u8], base_address: u64) -> Result<ControlFlowGraph> {
        let config = DecoderConfig::new(self.mode, base_address);
        let mut decoder = Decoder::new(config);
        let instructions = decoder.decode_all(data)?;
        self.build_from_instructions(instructions, base_address)
    }

    /// 从指令列表构建 CFG
    pub fn build_from_instructions(
        &mut self,
        instructions: Vec<Instruction>,
        base_address: u64,
    ) -> Result<ControlFlowGraph> {
        let mut cfg = ControlFlowGraph::new();
        let mut block_starts: HashSet<u64> = HashSet::new();
        let mut block_end_targets: HashMap<u64, Vec<u64>> = HashMap::new();

        // 第一遍：识别所有基本块边界
        block_starts.insert(base_address);

        for instruction in &instructions {
            let ip = instruction.ip();
            let next_ip = instruction.next_ip();

            if instruction.is_control_flow() {
                // 控制流指令结束当前基本块
                if let Some(target) = instruction.branch_target() {
                    block_starts.insert(target);
                    block_end_targets
                        .entry(ip)
                        .or_default()
                        .push(target);
                }

                // 条件跳转还有 fall-through
                if instruction.is_conditional_jump() {
                    block_starts.insert(next_ip);
                    block_end_targets
                        .entry(ip)
                        .or_default()
                        .push(next_ip);
                }

                // call 指令 fall-through
                if instruction.is_call() {
                    block_starts.insert(next_ip);
                }
            }
        }

        // 第二遍：创建基本块
        let mut current_block_instructions = Vec::new();
        let mut current_block_start = base_address;
        let mut block_map: HashMap<u64, BasicBlockId> = HashMap::new();

        for instruction in instructions {
            let ip = instruction.ip();

            // 如果需要开始新基本块
            if ip != current_block_start && block_starts.contains(&ip) {
                // 保存当前基本块
                if !current_block_instructions.is_empty() {
                    let block = self.builder.build_from_instructions(current_block_instructions);
                    let block_id = block.id;
                    block_map.insert(current_block_start, block_id);
                    cfg.add_block(block);
                }
                current_block_instructions = Vec::new();
                current_block_start = ip;
            }

            current_block_instructions.push(instruction.clone());

            // 如果这是控制流指令，结束当前基本块
            if instruction.is_control_flow() {
                let block = self.builder.build_from_instructions(current_block_instructions);
                let block_id = block.id;
                block_map.insert(current_block_start, block_id);
                cfg.add_block(block);
                current_block_instructions = Vec::new();
                current_block_start = instruction.next_ip();
            }
        }

        // 处理剩余指令
        if !current_block_instructions.is_empty() {
            let block = self.builder.build_from_instructions(current_block_instructions);
            let block_id = block.id;
            block_map.insert(current_block_start, block_id);
            cfg.add_block(block);
        }

        // 第三遍：连接基本块
        let block_ids: Vec<_> = cfg.blocks().keys().copied().collect();
        for block_id in block_ids {
            if let Some(block) = cfg.get_block(block_id) {
                if let Some(last) = block.last_instruction() {
                    let ip = last.ip();

                    if let Some(targets) = block_end_targets.get(&ip) {
                        for &target in targets {
                            if let Some(&target_block_id) = block_map.get(&target) {
                                cfg.connect_blocks(block_id, target_block_id);
                            }
                        }
                    }
                }
            }
        }

        // 设置入口基本块
        if let Some(&entry_id) = block_map.get(&base_address) {
            cfg.set_entry_block(entry_id);
        }

        // 识别出口基本块
        let block_ids: Vec<_> = cfg.blocks().keys().copied().collect();
        for block_id in block_ids {
            if let Some(block) = cfg.get_block(block_id) {
                if block.is_return() || (block.is_exit() && !block.is_call()) {
                    cfg.add_exit_block(block_id);
                }
            }
        }

        Ok(cfg)
    }
}

impl Default for CfgBuilder {
    fn default() -> Self {
        Self::new(DisassemblyMode::Mode64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cfg_creation() {
        let cfg = ControlFlowGraph::new();
        assert_eq!(cfg.block_count(), 0);
        assert!(cfg.entry_block().is_none());
        assert!(cfg.exit_blocks().is_empty());
    }

    #[test]
    fn test_cfg_add_block() {
        let mut cfg = ControlFlowGraph::new();
        let mut builder = BasicBlockBuilder::new();
        
        let block = builder.create_block(0x1000);
        let block_id = block.id;
        cfg.add_block(block);
        
        assert_eq!(cfg.block_count(), 1);
        assert!(cfg.get_block(block_id).is_some());
    }

    #[test]
    fn test_cfg_connect_blocks() {
        let mut cfg = ControlFlowGraph::new();
        let mut builder = BasicBlockBuilder::new();
        
        let block1 = builder.create_block(0x1000);
        let block2 = builder.create_block(0x1010);
        let id1 = block1.id;
        let id2 = block2.id;
        
        cfg.add_block(block1);
        cfg.add_block(block2);
        cfg.connect_blocks(id1, id2);
        
        let b1 = cfg.get_block(id1).unwrap();
        let b2 = cfg.get_block(id2).unwrap();
        
        assert!(b1.successors.contains(&id2));
        assert!(b2.predecessors.contains(&id1));
    }

    #[test]
    fn test_cfg_builder_simple() {
        // nop; nop; nop
        let data = vec![0x90, 0x90, 0x90];
        let mut builder = CfgBuilder::new(DisassemblyMode::Mode64);
        let cfg = builder.build_from_bytes(&data, 0x1000).unwrap();
        
        assert_eq!(cfg.block_count(), 1);
        assert!(cfg.entry_block().is_some());
    }

    #[test]
    fn test_cfg_builder_with_jump() {
        // jmp short $+5
        let data = vec![0xEB, 0x03, 0x90, 0x90, 0x90];
        let mut builder = CfgBuilder::new(DisassemblyMode::Mode64);
        let cfg = builder.build_from_bytes(&data, 0x1000).unwrap();
        
        // 应该有两个基本块：跳转指令和目标
        assert!(cfg.block_count() >= 1);
    }

    #[test]
    fn test_dfs() {
        let mut cfg = ControlFlowGraph::new();
        let mut builder = BasicBlockBuilder::new();
        
        let block1 = builder.create_block(0x1000);
        let block2 = builder.create_block(0x1010);
        let block3 = builder.create_block(0x1020);
        let id1 = block1.id;
        let id2 = block2.id;
        let id3 = block3.id;
        
        cfg.add_block(block1);
        cfg.add_block(block2);
        cfg.add_block(block3);
        cfg.connect_blocks(id1, id2);
        cfg.connect_blocks(id1, id3);
        
        let mut visited = Vec::new();
        cfg.dfs(id1, |id, _| visited.push(id));
        
        assert_eq!(visited.len(), 3);
        assert!(visited.contains(&id1));
        assert!(visited.contains(&id2));
        assert!(visited.contains(&id3));
    }

    #[test]
    fn test_bfs() {
        let mut cfg = ControlFlowGraph::new();
        let mut builder = BasicBlockBuilder::new();
        
        let block1 = builder.create_block(0x1000);
        let block2 = builder.create_block(0x1010);
        let id1 = block1.id;
        let id2 = block2.id;
        
        cfg.add_block(block1);
        cfg.add_block(block2);
        cfg.connect_blocks(id1, id2);
        
        let mut visited = Vec::new();
        cfg.bfs(id1, |id, _| visited.push(id));
        
        assert_eq!(visited.len(), 2);
        assert_eq!(visited[0], id1);
        assert_eq!(visited[1], id2);
    }

    #[test]
    fn test_find_block_by_address() {
        let mut cfg = ControlFlowGraph::new();
        let mut builder = BasicBlockBuilder::new();
        
        let block = builder.create_block(0x1000);
        let block_id = block.id;
        cfg.add_block(block);
        
        assert_eq!(cfg.find_block_by_address(0x1000), Some(block_id));
        assert_eq!(cfg.find_block_by_address(0x2000), None);
    }
}
