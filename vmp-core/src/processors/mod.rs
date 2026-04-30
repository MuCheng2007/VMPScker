//! Processors 模块
//!
//! 提供编译器核心功能，包括：
//! - 指令解析和表示
//! - 控制流分析（基本块）
//! - 命令链接管理
//! - 函数管理
//! - 虚拟化转换基础

pub mod types;
pub mod interfaces;
pub mod command;
pub mod command_block;
pub mod command_link;
pub mod function;

// 重新导出常用类型
pub use types::*;
pub use interfaces::*;
pub use command::{BaseCommand, BaseVMCommand, InternalLink, InternalLinkList};
pub use command_block::{CommandBlock, CommandBlockList, ExtCommand, ExtCommandList};
pub use command_link::{CommandLink, CommandLinkList};
pub use function::{BaseFunction, BaseFunctionList};
