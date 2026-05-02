//! 虚拟机字节码编译器 (VM Compiler)
//!
//! 负责将 src/intel/ir 中的标准 x86 中间表示 (IR) 
//! 降级 (Lowering) 为虚拟机微指令流，并进行流加密。

use crate::intel::ir::{IrInstruction, IrOperand, IrRegister, IrImmediate, IrOpcode, IrMemoryOperand, IrCondition, IrJumpTarget};
use crate::vm::arch::{ArchConfig, VMOpcode, CryptAlgorithm, VMRegister};
use crate::vm::cfg::ControlFlowGraph;

/// VM 字节码编译器
pub struct VmCompiler<'a> {
    config: &'a ArchConfig,
}

impl<'a> VmCompiler<'a> {
    pub fn new(config: &'a ArchConfig) -> Self {
        Self { config }
    }

    /// 编译入口：将整个 CFG 编译为加密的 VM 字节码流
    pub fn compile_cfg(&self, cfg: &ControlFlowGraph) -> Vec<u8> {
        let mut final_bytecode = Vec::new();
        let mut block_data = std::collections::HashMap::new();
        let mut block_offsets = std::collections::HashMap::new();

        // 1. 编译每个基本块为独立的微指令序列 (尚未加密)
        let mut current_offset = 0;
        
        // 按照 RVA 顺序排序块
        let mut sorted_rvas: Vec<_> = cfg.blocks.keys().cloned().collect();
        sorted_rvas.sort();

        for rva in &sorted_rvas {
            let block = &cfg.blocks[rva];
            let mut block_ops = Vec::new();
            
            for inst in &block.instructions {
                block_ops.extend(self.lower_instruction(inst));
            }
            
            block_offsets.insert(*rva, current_offset);
            // 计算这个块预计产生的字节码长度 (每个 Op 1 字节 + 立即数长度)
            let block_len: usize = block_ops.iter().map(|(_op, imm)| {
                1 + imm.as_ref().map_or(0, |v| v.len())
            }).sum();
            
            block_data.insert(*rva, block_ops);
            current_offset += block_len;
        }

        // 2. 进行第二次遍历：加密并拼接
        let mut current_key = self.config.initial_crypt_key as u8;
        
        for rva in &sorted_rvas {
            let ops = &block_data[rva];
            for (opcode, imm_data) in ops {
                // 操作码加密
                let raw_opcode = *self.config.opcode_mapping.get(&opcode).expect("Invalid VM Opcode mapping");
                let enc_opcode = self.encrypt_byte(raw_opcode, &mut current_key);
                final_bytecode.push(enc_opcode);
                
                // 立即数加密
                if let Some(data) = imm_data {
                    for b in data {
                        final_bytecode.push(self.encrypt_byte(*b, &mut current_key));
                    }
                }
            }
        }
        
        // 注入退出指令
        let raw_exit = *self.config.opcode_mapping.get(&VMOpcode::VmExit).unwrap();
        final_bytecode.push(self.encrypt_byte(raw_exit, &mut current_key));

        final_bytecode
    }

    /// 单字节加密，同时更新密钥流 (Rolling Key)
    fn encrypt_byte(&self, byte: u8, key: &mut u8) -> u8 {
        let mut res = byte;
        for algo in &self.config.crypt_sequence {
            match algo {
                CryptAlgorithm::Add => res = res.wrapping_add(*key),
                CryptAlgorithm::Sub => res = res.wrapping_sub(*key),
                CryptAlgorithm::Xor => res ^= *key,
                CryptAlgorithm::Rol => res = res.rotate_left(1),
                CryptAlgorithm::Ror => res = res.rotate_right(1),
                CryptAlgorithm::Not => res = !res,
                CryptAlgorithm::Neg => res = res.wrapping_neg(),
            }
        }
        // 更新密钥
        *key = key.wrapping_add(res);
        res
    }

    /// 核心降级逻辑：x86 IR -> VM 微指令
    fn lower_instruction(&self, inst: &IrInstruction) -> Vec<(VMOpcode, Option<Vec<u8>>)> {
        let mut ops = Vec::new();

        match &inst.opcode {
            // MOV dst, src -> vPush src, vPop dst
            IrOpcode::Mov { dst, src } => {
                self.lower_push_operand(src, &mut ops);
                self.lower_pop_operand(dst, &mut ops);
            }

            // LEA dst, mem -> 展开地址计算 -> vPop dst
            IrOpcode::Lea { dst, src } => {
                self.lower_push_memory_address(src, &mut ops);
                self.lower_pop_operand(&IrOperand::Register(*dst), &mut ops);
            }

            // ADD dst, src -> vPush src, vPush dst, vAdd, vPop dst, vPop (flags)
            IrOpcode::Add { dst, src } => {
                self.lower_push_operand(src, &mut ops);
                self.lower_push_operand(dst, &mut ops);
                ops.push((VMOpcode::Add, None));
                self.lower_pop_operand(dst, &mut ops);
                ops.push((VMOpcode::PopReg, Some(vec![VMRegister::R15 as u8])));
            }
            
            IrOpcode::Sub { dst, src } => {
                self.lower_push_operand(src, &mut ops);
                self.lower_push_operand(dst, &mut ops);
                ops.push((VMOpcode::Sub, None));
                self.lower_pop_operand(dst, &mut ops);
                ops.push((VMOpcode::PopReg, Some(vec![VMRegister::R15 as u8])));
            }

            IrOpcode::Xor { dst, src } => {
                self.lower_push_operand(src, &mut ops);
                self.lower_push_operand(dst, &mut ops);
                ops.push((VMOpcode::Xor, None));
                self.lower_pop_operand(dst, &mut ops);
                ops.push((VMOpcode::PopReg, Some(vec![VMRegister::R15 as u8])));
            }

            IrOpcode::And { dst, src } => {
                self.lower_push_operand(src, &mut ops);
                self.lower_push_operand(dst, &mut ops);
                ops.push((VMOpcode::And, None));
                self.lower_pop_operand(dst, &mut ops);
                ops.push((VMOpcode::PopReg, Some(vec![VMRegister::R15 as u8])));
            }

            IrOpcode::Or { dst, src } => {
                self.lower_push_operand(src, &mut ops);
                self.lower_push_operand(dst, &mut ops);
                ops.push((VMOpcode::Or, None));
                self.lower_pop_operand(dst, &mut ops);
                ops.push((VMOpcode::PopReg, Some(vec![VMRegister::R15 as u8])));
            }

            IrOpcode::Not { op } => {
                self.lower_push_operand(op, &mut ops);
                ops.push((VMOpcode::Not, None));
                self.lower_pop_operand(op, &mut ops);
                ops.push((VMOpcode::PopReg, Some(vec![VMRegister::R15 as u8])));
            }

            IrOpcode::Shl { dst, count } => {
                self.lower_push_operand(count, &mut ops);
                self.lower_push_operand(dst, &mut ops);
                ops.push((VMOpcode::Shl, None));
                self.lower_pop_operand(dst, &mut ops);
                ops.push((VMOpcode::PopReg, Some(vec![VMRegister::R15 as u8])));
            }

            IrOpcode::Shr { dst, count } => {
                self.lower_push_operand(count, &mut ops);
                self.lower_push_operand(dst, &mut ops);
                ops.push((VMOpcode::Shr, None));
                self.lower_pop_operand(dst, &mut ops);
                ops.push((VMOpcode::PopReg, Some(vec![VMRegister::R15 as u8])));
            }
            
            IrOpcode::Jmp { target } => {
                if let IrJumpTarget::Direct(addr) = target {
                    ops.push((VMOpcode::PushImm64, Some(addr.to_le_bytes().to_vec())));
                    ops.push((VMOpcode::Jmp, None));
                }
            }

            IrOpcode::Jcc { condition: _, target } => {
                if let IrJumpTarget::Direct(addr) = target {
                    ops.push((VMOpcode::PushReg, Some(vec![VMRegister::R15 as u8])));
                    ops.push((VMOpcode::PushImm64, Some(addr.to_le_bytes().to_vec())));
                    ops.push((VMOpcode::Jcc, None)); 
                }
            }

            _ => {}
        }

        ops
    }

    fn lower_push_operand(&self, op: &IrOperand, ops: &mut Vec<(VMOpcode, Option<Vec<u8>>)>) {
        match op {
            IrOperand::Register(reg) => {
                let vreg = self.map_register(reg);
                ops.push((VMOpcode::PushReg, Some(vec![vreg as u8])));
            }
            IrOperand::Immediate(imm) => {
                let val = imm.as_u64();
                ops.push((VMOpcode::PushImm64, Some(val.to_le_bytes().to_vec())));
            }
            IrOperand::Memory(mem) => {
                self.lower_push_memory_address(mem, ops);
                match mem.size_bits {
                    8  => ops.push((VMOpcode::ReadMem8, None)),
                    16 => ops.push((VMOpcode::ReadMem16, None)),
                    32 => ops.push((VMOpcode::ReadMem32, None)),
                    64 => ops.push((VMOpcode::ReadMem64, None)),
                    _ => ops.push((VMOpcode::ReadMem64, None)),
                }
            }
        }
    }

    fn lower_pop_operand(&self, op: &IrOperand, ops: &mut Vec<(VMOpcode, Option<Vec<u8>>)>) {
        match op {
            IrOperand::Register(reg) => {
                let vreg = self.map_register(reg);
                ops.push((VMOpcode::PopReg, Some(vec![vreg as u8])));
            }
            IrOperand::Immediate(_) => panic!("Cannot pop to immediate"),
            IrOperand::Memory(mem) => {
                self.lower_push_memory_address(mem, ops);
                match mem.size_bits {
                    8  => ops.push((VMOpcode::WriteMem8, None)),
                    16 => ops.push((VMOpcode::WriteMem16, None)),
                    32 => ops.push((VMOpcode::WriteMem32, None)),
                    64 => ops.push((VMOpcode::WriteMem64, None)),
                    _ => ops.push((VMOpcode::WriteMem64, None)),
                }
            }
        }
    }

    fn lower_push_memory_address(&self, mem: &IrMemoryOperand, ops: &mut Vec<(VMOpcode, Option<Vec<u8>>)>) {
        if let Some(base) = mem.base {
            ops.push((VMOpcode::PushReg, Some(vec![self.map_register(&base) as u8])));
        } else {
            ops.push((VMOpcode::PushImm64, Some(0u64.to_le_bytes().to_vec())));
        }
        
        if let Some(index) = mem.index {
            ops.push((VMOpcode::PushReg, Some(vec![self.map_register(&index) as u8])));
            ops.push((VMOpcode::Add, None));
            ops.push((VMOpcode::PopReg, Some(vec![VMRegister::R15 as u8])));
        }
        
        if mem.displacement != 0 {
            ops.push((VMOpcode::PushImm64, Some((mem.displacement as u64).to_le_bytes().to_vec())));
            ops.push((VMOpcode::Add, None));
            ops.push((VMOpcode::PopReg, Some(vec![VMRegister::R15 as u8])));
        }
    }

    fn map_register(&self, reg: &IrRegister) -> VMRegister {
        match reg {
            IrRegister::Rax | IrRegister::Eax | IrRegister::Ax | IrRegister::Al => VMRegister::R0,
            IrRegister::Rcx | IrRegister::Ecx | IrRegister::Cx | IrRegister::Cl => VMRegister::R1,
            IrRegister::Rdx | IrRegister::Edx | IrRegister::Dx | IrRegister::Dl => VMRegister::R2,
            IrRegister::Rbx | IrRegister::Ebx | IrRegister::Bx | IrRegister::Bl => VMRegister::R3,
            IrRegister::Rsp | IrRegister::Esp | IrRegister::Sp | IrRegister::Spl => VMRegister::R4,
            IrRegister::Rbp | IrRegister::Ebp | IrRegister::Bp | IrRegister::Bpl => VMRegister::R5,
            IrRegister::Rsi | IrRegister::Esi | IrRegister::Si | IrRegister::Sil => VMRegister::R6,
            IrRegister::Rdi | IrRegister::Edi | IrRegister::Di | IrRegister::Dil => VMRegister::R7,
            IrRegister::R8 | IrRegister::R8d | IrRegister::R8w | IrRegister::R8b => VMRegister::R8,
            IrRegister::R9 | IrRegister::R9d | IrRegister::R9w | IrRegister::R9b => VMRegister::R9,
            _ => VMRegister::R15,
        }
    }
}
