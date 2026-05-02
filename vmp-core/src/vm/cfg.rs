//! 虚拟机控制流图 (Control Flow Graph) 分析
//!
//! 负责将线性的 IR 指令流切割成逻辑上的“基本块”，并建立跳转关系。

use crate::intel::ir::{IrInstruction, IrJumpTarget, IrOpcode};
use std::collections::{HashMap, HashSet};

/// 虚拟机基本块
#[derive(Debug, Clone)]
pub struct VmBasicBlock {
    /// 块 ID
    pub id: u32,
    /// 起始 RVA
    pub start_rva: u64,
    /// 指令列表
    pub instructions: Vec<IrInstruction>,
    /// 后继块的 RVA 列表
    pub successor_rvas: Vec<u64>,
}

/// 控制流图
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    /// 所有基本块，按起始 RVA 索引
    pub blocks: HashMap<u64, VmBasicBlock>,
    /// 入口 RVA
    pub entry_rva: u64,
}

impl ControlFlowGraph {
    /// 从 IR 指令流构建 CFG
    pub fn from_ir(instructions: &[IrInstruction], entry_rva: u64) -> Self {
        let mut blocks = HashMap::new();
        let mut leaders = HashSet::new();
        
        // 1. 识别所有 Leader (基本块入口)
        leaders.insert(entry_rva);
        
        for inst in instructions {
            if inst.is_flow_control() {
                // 流控指令的后继是 Leader
                for succ in Self::get_successors_from_inst(inst) {
                    leaders.insert(succ);
                }
                // 流控指令之后的第一条指令也是 Leader (Fall-through)
                // 在我们的线性指令流中，这需要更复杂的逻辑，暂且简化处理
            }
        }

        // 2. 切割基本块
        let mut current_block_insts = Vec::new();
        let mut current_start_rva = entry_rva;
        let mut block_id_counter = 0;

        for inst in instructions {
            let rva = inst.address();
            
            if leaders.contains(&rva) && !current_block_insts.is_empty() {
                // 结束当前块
                let successors = Self::get_successors(&current_block_insts);
                blocks.insert(current_start_rva, VmBasicBlock {
                    id: block_id_counter,
                    start_rva: current_start_rva,
                    instructions: current_block_insts,
                    successor_rvas: successors,
                });
                
                block_id_counter += 1;
                current_block_insts = Vec::new();
                current_start_rva = rva;
            }
            
            current_block_insts.push(inst.clone());
        }

        // 处理最后一个块
        if !current_block_insts.is_empty() {
            let successors = Self::get_successors(&current_block_insts);
            blocks.insert(current_start_rva, VmBasicBlock {
                id: block_id_counter,
                start_rva: current_start_rva,
                instructions: current_block_insts,
                successor_rvas: successors,
            });
        }
        
        Self {
            blocks,
            entry_rva,
        }
    }
    
    fn get_successors(instructions: &[IrInstruction]) -> Vec<u64> {
        if let Some(last) = instructions.last() {
            Self::get_successors_from_inst(last)
        } else {
            Vec::new()
        }
    }

    fn get_successors_from_inst(inst: &IrInstruction) -> Vec<u64> {
        let mut succs = Vec::new();
        match &inst.opcode {
            IrOpcode::Jmp { target } => {
                if let IrJumpTarget::Direct(addr) = target {
                    succs.push(*addr);
                }
            }
            IrOpcode::Jcc { target, .. } => {
                if let IrJumpTarget::Direct(addr) = target {
                    succs.push(*addr);
                }
            }
            _ => {}
        }
        succs
    }
}
