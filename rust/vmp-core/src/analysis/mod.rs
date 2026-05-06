//! 代码分析模块
//!
//! 提供各种代码分析功能，包括：
//! - 寄存器存活分析 (Liveness Analysis)
//! - 数据流分析
//! - 控制流分析

pub mod liveness;

pub use liveness::LivenessInfo;
