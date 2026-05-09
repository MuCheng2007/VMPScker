//! 基本块模块
//!
//! 定义基本块和控制流图的基础结构。

use super::{Instruction, IrInstruction};
use crate::intel::decoder::{decode_instructions};
use std::collections::HashSet;

/// 基本块 ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BasicBlockId(pub u32);

impl BasicBlockId {
    /// 创建新的基本块 ID
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    /// 获取 ID 值
    pub fn value(&self) -> u32 {
        self.0
    }
}

impl From<u32> for BasicBlockId {
    fn from(id: u32) -> Self {
        Self::new(id)
    }
}

impl From<BasicBlockId> for u32 {
    fn from(id: BasicBlockId) -> Self {
        id.0
    }
}

/// 基本块
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// 基本块 ID
    pub id: BasicBlockId,
    /// 起始地址
    pub start_address: u64,
    /// 结束地址（最后一条指令的地址 + 长度）
    pub end_address: u64,
    /// 原始指令
    pub instructions: Vec<Instruction>,
    /// 转换后的 IR 指令
    pub ir_instructions: Vec<IrInstruction>,
    /// 前驱基本块
    pub predecessors: HashSet<BasicBlockId>,
    /// 后继基本块
    pub successors: HashSet<BasicBlockId>,
}

impl BasicBlock {
    /// 创建新的基本块
    pub fn new(id: BasicBlockId, start_address: u64) -> Self {
        Self {
            id,
            start_address,
            end_address: start_address,
            instructions: Vec::new(),
            ir_instructions: Vec::new(),
            predecessors: HashSet::new(),
            successors: HashSet::new(),
        }
    }

    /// 添加指令
    pub fn add_instruction(&mut self, instruction: Instruction) {
        self.end_address = instruction.next_ip();
        self.instructions.push(instruction);
    }

    /// 添加 IR 指令
    pub fn add_ir_instruction(&mut self, ir_instruction: IrInstruction) {
        self.ir_instructions.push(ir_instruction);
    }

    /// 添加 IR 指令列表
    pub fn add_ir_instructions(&mut self, ir_instructions: Vec<IrInstruction>) {
        self.ir_instructions.extend(ir_instructions);
    }

    /// 添加后继基本块
    pub fn add_successor(&mut self, successor_id: BasicBlockId) {
        self.successors.insert(successor_id);
    }

    /// 添加前驱基本块
    pub fn add_predecessor(&mut self, predecessor_id: BasicBlockId) {
        self.predecessors.insert(predecessor_id);
    }

    /// 移除后继基本块
    pub fn remove_successor(&mut self, successor_id: BasicBlockId) {
        self.successors.remove(&successor_id);
    }

    /// 移除前驱基本块
    pub fn remove_predecessor(&mut self, predecessor_id: BasicBlockId) {
        self.predecessors.remove(&predecessor_id);
    }

    /// 获取指令数量
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// 获取 IR 指令数量
    pub fn ir_instruction_count(&self) -> usize {
        self.ir_instructions.len()
    }

    /// 获取基本块大小（字节）
    pub fn size(&self) -> u64 {
        self.end_address - self.start_address
    }

    /// 是否是入口基本块（无前驱）
    pub fn is_entry(&self) -> bool {
        self.predecessors.is_empty()
    }

    /// 是否是出口基本块（无后继）
    pub fn is_exit(&self) -> bool {
        self.successors.is_empty()
    }

    /// 获取最后一条指令
    pub fn last_instruction(&self) -> Option<&Instruction> {
        self.instructions.last()
    }

    /// 获取第一条指令
    pub fn first_instruction(&self) -> Option<&Instruction> {
        self.instructions.first()
    }

    /// 是否包含地址
    pub fn contains_address(&self, address: u64) -> bool {
        address >= self.start_address && address < self.end_address
    }

    /// 是否是条件分支结束
    pub fn is_conditional_branch(&self) -> bool {
        self.last_instruction()
            .map(|i| i.is_conditional_jump())
            .unwrap_or(false)
    }

    /// 是否是无条件跳转结束
    pub fn is_unconditional_branch(&self) -> bool {
        self.last_instruction()
            .map(|i| i.is_unconditional_jump() && !i.is_call())
            .unwrap_or(false)
    }

    /// 是否是调用结束
    pub fn is_call(&self) -> bool {
        self.last_instruction()
            .map(|i| i.is_call())
            .unwrap_or(false)
    }

    /// 是否是返回结束
    pub fn is_return(&self) -> bool {
        self.last_instruction()
            .map(|i| i.is_return())
            .unwrap_or(false)
    }

    /// 获取分支目标地址列表
    pub fn branch_targets(&self) -> Vec<u64> {
        let mut targets = Vec::new();
        
        if let Some(last) = self.last_instruction() {
            if let Some(target) = last.branch_target() {
                targets.push(target);
            }
            
            // 对于条件跳转，还有 fall-through 目标
            if last.is_conditional_jump() {
                targets.push(last.next_ip());
            }
        }
        
        targets
    }

    /// 格式化基本块信息
    pub fn format(&self) -> String {
        let mut result = format!(
            "Block {}: [{:X} - {:X})\n",
            self.id.value(),
            self.start_address,
            self.end_address
        );

        // 前驱
        if !self.predecessors.is_empty() {
            let preds: Vec<_> = self.predecessors.iter().map(|p| p.value().to_string()).collect();
            result.push_str(&format!("  Preds: {}\n", preds.join(", ")));
        }

        // 后继
        if !self.successors.is_empty() {
            let succs: Vec<_> = self.successors.iter().map(|s| s.value().to_string()).collect();
            result.push_str(&format!("  Succs: {}\n", succs.join(", ")));
        }

        // 指令
        for insn in &self.instructions {
            result.push_str(&format!("    {:X}: {}\n", insn.ip(), insn.mnemonic()));
        }

        result
    }
}

/// 基本块构建器
pub struct BasicBlockBuilder {
    next_id: u32,
}

impl BasicBlockBuilder {
    /// 创建新的构建器
    pub fn new() -> Self {
        Self { next_id: 0 }
    }

    /// 创建新的基本块
    pub fn create_block(&mut self, start_address: u64) -> BasicBlock {
        let id = BasicBlockId::new(self.next_id);
        self.next_id += 1;
        BasicBlock::new(id, start_address)
    }

    /// 从指令列表构建基本块
    pub fn build_from_instructions(&mut self, instructions: Vec<Instruction>) -> BasicBlock {
        if instructions.is_empty() {
            panic!("Cannot build basic block from empty instruction list");
        }

        let start_address = instructions[0].ip();
        let mut block = self.create_block(start_address);

        for instruction in instructions {
            block.add_instruction(instruction);
        }

        block
    }

    /// 获取下一个基本块 ID
    pub fn next_id(&self) -> BasicBlockId {
        BasicBlockId::new(self.next_id)
    }
}

impl Default for BasicBlockBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::decoder::decode_instructions;
    use crate::intel::DisassemblyMode;

    fn create_test_instructions() -> Vec<Instruction> {
        // nop; mov rax, rbx; add rax, rcx
        let data = vec![0x90, 0x48, 0x89, 0xD8, 0x48, 0x01, 0xC8];
        decode_instructions(&data, super::super::DisassemblyMode::Mode64, 0x1000).unwrap()
    }

    #[test]
    fn test_basic_block_id() {
        let id1 = BasicBlockId::new(0);
        let id2 = BasicBlockId::new(1);
        
        assert_eq!(id1.value(), 0);
        assert_eq!(id2.value(), 1);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_basic_block_creation() {
        let block = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        
        assert_eq!(block.id.value(), 0);
        assert_eq!(block.start_address, 0x1000);
        assert_eq!(block.end_address, 0x1000);
        assert!(block.instructions.is_empty());
        assert!(block.predecessors.is_empty());
        assert!(block.successors.is_empty());
    }

    #[test]
    fn test_add_instructions() {
        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        let instructions = create_test_instructions();
        
        for insn in instructions {
            block.add_instruction(insn);
        }
        
        assert_eq!(block.instruction_count(), 3);
        assert!(block.end_address > block.start_address);
    }

    #[test]
    fn test_predecessors_successors() {
        let mut block1 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        let block2 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        
        block1.add_successor(block2.id);
        
        assert!(block1.successors.contains(&block2.id));
        assert_eq!(block1.successors.len(), 1);
    }

    #[test]
    fn test_is_entry_exit() {
        let block = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        
        assert!(block.is_entry());
        assert!(block.is_exit());
    }

    #[test]
    fn test_contains_address() {
        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        
        // nop (1 byte)
        let data = vec![0x90];
        let instructions = decode_instructions(&data, super::super::DisassemblyMode::Mode64, 0x1000).unwrap();
        block.add_instruction(instructions[0].clone());
        
        assert!(block.contains_address(0x1000));
        assert!(!block.contains_address(0x1001));
    }

    #[test]
    fn test_basic_block_builder() {
        let mut builder = BasicBlockBuilder::new();
        let instructions = create_test_instructions();
        
        let block = builder.build_from_instructions(instructions);
        
        assert_eq!(block.id.value(), 0);
        assert_eq!(block.instruction_count(), 3);
    }

    #[test]
    fn test_builder_multiple_blocks() {
        let mut builder = BasicBlockBuilder::new();
        
        let block1 = builder.create_block(0x1000);
        let block2 = builder.create_block(0x1010);
        
        assert_eq!(block1.id.value(), 0);
        assert_eq!(block2.id.value(), 1);
        assert_ne!(block1.id, block2.id);
    }

    #[test]
    fn test_block_format() {
        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        let instructions = create_test_instructions();
        
        for insn in instructions {
            block.add_instruction(insn);
        }
        
        let formatted = block.format();
        assert!(formatted.contains("Block 0"));
        assert!(formatted.contains("1000"));
    }
}
