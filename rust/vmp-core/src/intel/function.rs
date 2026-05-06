//! 函数分析模块
//!
//! 识别和分析函数。

use super::{
    BasicBlockId, ControlFlowGraph, CfgBuilder, Decoder, DecoderConfig, DisassemblyMode,
    Instruction,
};
use crate::error::Result;
use std::collections::{HashMap, HashSet};

/// 函数信息
#[derive(Debug, Clone)]
pub struct Function {
    /// 函数起始地址
    pub entry_point: u64,
    /// 函数名称（如果有）
    pub name: Option<String>,
    /// 控制流图
    pub cfg: ControlFlowGraph,
    /// 函数大小（字节）
    pub size: u64,
    /// 调用该函数的地址列表
    pub callers: Vec<u64>,
    /// 该函数调用的地址列表
    pub callees: Vec<u64>,
    /// 栈帧大小（如果已知）
    pub stack_frame_size: Option<u32>,
    /// 是否是叶函数（不调用其他函数）
    pub is_leaf: bool,
}

impl Function {
    /// 创建新的函数
    pub fn new(entry_point: u64, cfg: ControlFlowGraph) -> Self {
        let size = Self::calculate_size(&cfg);
        let is_leaf = Self::check_is_leaf(&cfg);

        Self {
            entry_point,
            name: None,
            cfg,
            size,
            callers: Vec::new(),
            callees: Vec::new(),
            stack_frame_size: None,
            is_leaf,
        }
    }

    /// 创建带名称的函数
    pub fn with_name(entry_point: u64, name: impl Into<String>, cfg: ControlFlowGraph) -> Self {
        let mut func = Self::new(entry_point, cfg);
        func.name = Some(name.into());
        func
    }

    /// 获取函数名称（如果没有则返回地址）
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("sub_{:X}", self.entry_point))
    }

    /// 获取基本块数量
    pub fn block_count(&self) -> usize {
        self.cfg.block_count()
    }

    /// 获取指令数量
    pub fn instruction_count(&self) -> usize {
        self.cfg
            .block_iter()
            .map(|b| b.instruction_count())
            .sum()
    }

    /// 添加调用者
    pub fn add_caller(&mut self, caller_address: u64) {
        if !self.callers.contains(&caller_address) {
            self.callers.push(caller_address);
        }
    }

    /// 添加被调用者
    pub fn add_callee(&mut self, callee_address: u64) {
        if !self.callees.contains(&callee_address) {
            self.callees.push(callee_address);
        }
    }

    /// 计算函数大小
    fn calculate_size(cfg: &ControlFlowGraph) -> u64 {
        let mut min_addr = u64::MAX;
        let mut max_addr = u64::MIN;

        for block in cfg.block_iter() {
            min_addr = min_addr.min(block.start_address);
            max_addr = max_addr.max(block.end_address);
        }

        if max_addr >= min_addr {
            max_addr - min_addr
        } else {
            0
        }
    }

    /// 检查是否是叶函数
    fn check_is_leaf(cfg: &ControlFlowGraph) -> bool {
        for block in cfg.block_iter() {
            if let Some(last) = block.last_instruction() {
                if last.is_call() {
                    return false;
                }
            }
        }
        true
    }

    /// 获取所有返回指令的地址
    pub fn return_addresses(&self) -> Vec<u64> {
        let mut addresses = Vec::new();
        for block in self.cfg.block_iter() {
            if block.is_return() {
                if let Some(last) = block.last_instruction() {
                    addresses.push(last.ip());
                }
            }
        }
        addresses
    }

    /// 格式化函数信息
    pub fn format(&self) -> String {
        let mut result = format!(
            "Function {} @ {:X} ({} bytes, {} blocks, {} instructions)\n",
            self.display_name(),
            self.entry_point,
            self.size,
            self.block_count(),
            self.instruction_count()
        );

        if self.is_leaf {
            result.push_str("  [Leaf function]\n");
        }

        if !self.callers.is_empty() {
            result.push_str(&format!("  Callers: {}\n", self.callers.len()));
        }

        if !self.callees.is_empty() {
            result.push_str(&format!("  Callees: {}\n", self.callees.len()));
        }

        if let Some(frame_size) = self.stack_frame_size {
            result.push_str(&format!("  Stack frame: {} bytes\n", frame_size));
        }

        result
    }
}

/// 函数分析器
pub struct FunctionAnalyzer {
    mode: DisassemblyMode,
    functions: HashMap<u64, Function>,
    call_graph: HashMap<u64, Vec<u64>>, // caller -> callees
}

impl FunctionAnalyzer {
    /// 创建新的函数分析器
    pub fn new(mode: DisassemblyMode) -> Self {
        Self {
            mode,
            functions: HashMap::new(),
            call_graph: HashMap::new(),
        }
    }

    /// 分析单个函数
    pub fn analyze_function(
        &mut self,
        data: &[u8],
        entry_point: u64,
        base_address: u64,
    ) -> Result<Function> {
        // 计算在数据中的偏移
        let offset = if entry_point >= base_address {
            (entry_point - base_address) as usize
        } else {
            0
        };

        if offset >= data.len() {
            return Err(crate::error::VmpError::Disassembly(
                "Entry point out of bounds".to_string()
            ));
        }

        let function_data = &data[offset..];
        let mut cfg_builder = CfgBuilder::new(self.mode);
        let cfg = cfg_builder.build_from_bytes(function_data, entry_point)?;

        let function = Function::new(entry_point, cfg);
        self.functions.insert(entry_point, function.clone());

        Ok(function)
    }

    /// 分析函数并指定名称
    pub fn analyze_function_with_name(
        &mut self,
        data: &[u8],
        entry_point: u64,
        base_address: u64,
        name: impl Into<String>,
    ) -> Result<Function> {
        let mut func = self.analyze_function(data, entry_point, base_address)?;
        func.name = Some(name.into());
        self.functions.insert(entry_point, func.clone());
        Ok(func)
    }

    /// 从导出表获取函数入口点
    pub fn discover_functions_from_exports(&mut self, exports: &[(String, u64)]) -> Vec<u64> {
        exports
            .iter()
            .map(|(_, addr)| *addr)
            .collect()
    }

    /// 从调用指令发现函数
    pub fn discover_functions_from_calls(&self, data: &[u8], base_address: u64) -> Result<Vec<u64>> {
        let config = DecoderConfig::new(self.mode, base_address);
        let mut decoder = Decoder::new(config);
        let instructions = decoder.decode_all(data)?;

        let mut function_entries = HashSet::new();

        for instruction in instructions {
            if instruction.is_call() {
                if let Some(target) = instruction.branch_target() {
                    function_entries.insert(target);
                }
            }
        }

        Ok(function_entries.into_iter().collect())
    }

    /// 获取所有分析的函数
    pub fn functions(&self) -> &HashMap<u64, Function> {
        &self.functions
    }

    /// 获取函数
    pub fn get_function(&self, entry_point: u64) -> Option<&Function> {
        self.functions.get(&entry_point)
    }

    /// 构建调用图
    pub fn build_call_graph(&mut self) {
        self.call_graph.clear();

        for (addr, func) in &self.functions {
            let mut callees = Vec::new();
            for block in func.cfg.block_iter() {
                if let Some(last) = block.last_instruction() {
                    if last.is_call() {
                        if let Some(target) = last.branch_target() {
                            callees.push(target);
                        }
                    }
                }
            }
            self.call_graph.insert(*addr, callees);
        }
    }

    /// 获取调用图
    pub fn call_graph(&self) -> &HashMap<u64, Vec<u64>> {
        &self.call_graph
    }

    /// 获取函数的调用者
    pub fn get_callers(&self, entry_point: u64) -> Vec<u64> {
        let mut callers = Vec::new();
        for (caller, callees) in &self.call_graph {
            if callees.contains(&entry_point) {
                callers.push(*caller);
            }
        }
        callers
    }

    /// 获取递归函数
    pub fn find_recursive_functions(&self) -> Vec<u64> {
        let mut recursive = Vec::new();

        for (addr, func) in &self.functions {
            for block in func.cfg.block_iter() {
                if let Some(last) = block.last_instruction() {
                    if last.is_call() {
                        if let Some(target) = last.branch_target() {
                            if target == *addr {
                                recursive.push(*addr);
                                break;
                            }
                        }
                    }
                }
            }
        }

        recursive
    }

    /// 分析所有发现的函数
    pub fn analyze_all_functions(
        &mut self,
        data: &[u8],
        entry_points: &[u64],
        base_address: u64,
    ) -> Result<()> {
        for &entry in entry_points {
            if !self.functions.contains_key(&entry) {
                let _ = self.analyze_function(data, entry, base_address);
            }
        }

        self.build_call_graph();

        // 更新调用者信息
        for (caller, callees) in &self.call_graph {
            for callee in callees.clone() {
                if let Some(func) = self.functions.get_mut(&callee) {
                    func.add_caller(*caller);
                }
                if let Some(func) = self.functions.get_mut(caller) {
                    func.add_callee(callee);
                }
            }
        }

        Ok(())
    }

    /// 获取函数统计信息
    pub fn statistics(&self) -> FunctionStatistics {
        let total_functions = self.functions.len();
        let total_instructions: usize = self.functions.values().map(|f| f.instruction_count()).sum();
        let leaf_functions = self.functions.values().filter(|f| f.is_leaf).count();
        let recursive_functions = self.find_recursive_functions().len();

        FunctionStatistics {
            total_functions,
            total_instructions,
            leaf_functions,
            recursive_functions,
            average_instructions: if total_functions > 0 {
                total_instructions / total_functions
            } else {
                0
            },
        }
    }
}

impl Default for FunctionAnalyzer {
    fn default() -> Self {
        Self::new(DisassemblyMode::Mode64)
    }
}

/// 函数统计信息
#[derive(Debug, Clone)]
pub struct FunctionStatistics {
    pub total_functions: usize,
    pub total_instructions: usize,
    pub leaf_functions: usize,
    pub recursive_functions: usize,
    pub average_instructions: usize,
}

impl FunctionStatistics {
    /// 格式化统计信息
    pub fn format(&self) -> String {
        format!(
            "Function Statistics:\n\
             - Total functions: {}\n\
             - Total instructions: {}\n\
             - Leaf functions: {}\n\
             - Recursive functions: {}\n\
             - Average instructions per function: {}",
            self.total_functions,
            self.total_instructions,
            self.leaf_functions,
            self.recursive_functions,
            self.average_instructions
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_creation() {
        let cfg = ControlFlowGraph::new();
        let func = Function::new(0x1000, cfg);

        assert_eq!(func.entry_point, 0x1000);
        assert_eq!(func.display_name(), "sub_1000");
        assert!(func.name.is_none());
    }

    #[test]
    fn test_function_with_name() {
        let cfg = ControlFlowGraph::new();
        let func = Function::with_name(0x1000, "main", cfg);

        assert_eq!(func.display_name(), "main");
        assert_eq!(func.name, Some("main".to_string()));
    }

    #[test]
    fn test_function_analyzer() {
        let analyzer = FunctionAnalyzer::new(DisassemblyMode::Mode64);
        assert!(analyzer.functions().is_empty());
    }

    #[test]
    fn test_discover_functions_from_calls() {
        // call 0x1020; nop; nop; nop
        let data = vec![0xE8, 0x1B, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90];
        let analyzer = FunctionAnalyzer::new(DisassemblyMode::Mode64);
        let functions = analyzer.discover_functions_from_calls(&data, 0x1000).unwrap();

        assert!(!functions.is_empty());
        // call 目标应该是 0x1000 + 5 + 0x1B = 0x1020
        assert!(functions.contains(&0x1020));
    }

    #[test]
    fn test_function_statistics() {
        let stats = FunctionStatistics {
            total_functions: 10,
            total_instructions: 100,
            leaf_functions: 5,
            recursive_functions: 1,
            average_instructions: 10,
        };

        let formatted = stats.format();
        assert!(formatted.contains("10"));
        assert!(formatted.contains("100"));
    }
}
