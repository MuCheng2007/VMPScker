//! 字节码编译器模块 (Bytecode Compiler)
//! 负责将 VM IR 编译为加密的字节码流 (Bytecode Stream)
//! 支持标签解析和内部跳转

use crate::vm::arch::ArchConfig;
use crate::vm::opcode::VmOpcode;
use std::collections::HashMap;

/// 待修补的跳转指令信息
struct PatchInfo {
    /// 字节码中操作数的起始偏移量
    operand_offset: usize,
    /// 跳转目标的标签 ID
    target_label: u32,
    /// 操作数加密时使用的 rolling key
    encrypt_key: u32,
}

pub struct BytecodeCompiler<'a> {
    arch: &'a ArchConfig,
}

impl<'a> BytecodeCompiler<'a> {
    pub fn new(arch: &'a ArchConfig) -> Self {
        Self { arch }
    }

    /// 将给定的 VM IR 序列编译为加密的 Vec<u8>
    /// 支持标签解析：VLabel 标记位置，VJmp(id)/VJcc(cond, id) 引用标签
    pub fn compile_block(&self, vm_irs: &[VmOpcode]) -> Vec<u8> {
        // === Pass 1: 生成字节码并记录标签位置 ===
        let mut bytecode = Vec::new();
        let mut label_positions: HashMap<u32, usize> = HashMap::new();
        let mut patches: Vec<PatchInfo> = Vec::new();

        let mut current_key = self.arch.initial_crypt_key;

        for ir in vm_irs {
            match ir {
                VmOpcode::VLabel(id) => {
                    // 标签：记录当前位置，不生成字节码
                    label_positions.insert(*id, bytecode.len());
                    continue;
                }
                VmOpcode::VJmp(target_label) => {
                    // 无条件内部跳转
                    let core_opcode = self.extract_core_opcode(ir);
                    let plain_index = *self.arch.opcode_map.get(&core_opcode).unwrap_or(&0) as u32;
                    let cipher_opcode = self.arch.opcode_cryptor.encrypt(plain_index, current_key);
                    bytecode.extend_from_slice(&cipher_opcode.to_le_bytes());
                    current_key = current_key.wrapping_add(plain_index);

                    // 占位操作数 (4 bytes)，Pass 2 修补
                    patches.push(PatchInfo {
                        operand_offset: bytecode.len(),
                        target_label: *target_label,
                        encrypt_key: current_key,
                    });
                    bytecode.extend_from_slice(&[0u8; 4]);
                }
                VmOpcode::VJcc(_cond, target_label) => {
                    // 条件跳转
                    let core_opcode = self.extract_core_opcode(ir);
                    let plain_index = *self.arch.opcode_map.get(&core_opcode).unwrap_or(&0) as u32;
                    let cipher_opcode = self.arch.opcode_cryptor.encrypt(plain_index, current_key);
                    bytecode.extend_from_slice(&cipher_opcode.to_le_bytes());
                    current_key = current_key.wrapping_add(plain_index);

                    // 占位操作数 (4 bytes)，Pass 2 修补
                    patches.push(PatchInfo {
                        operand_offset: bytecode.len(),
                        target_label: *target_label,
                        encrypt_key: current_key,
                    });
                    bytecode.extend_from_slice(&[0u8; 4]);
                }
                _ => {
                    // 常规指令处理
                    let core_opcode = self.extract_core_opcode(ir);
                    let plain_index = *self.arch.opcode_map.get(&core_opcode).unwrap_or(&0) as u32;
                    let cipher_opcode = self.arch.opcode_cryptor.encrypt(plain_index, current_key);
                    bytecode.extend_from_slice(&cipher_opcode.to_le_bytes());
                    current_key = current_key.wrapping_add(plain_index);

                    match ir {
                        VmOpcode::VPushReg(offset) | VmOpcode::VPopReg(offset) => {
                            let plain_arg = *offset as u32;
                            let cipher_arg = self.arch.opcode_cryptor.encrypt(plain_arg, current_key);
                            bytecode.extend_from_slice(&cipher_arg.to_le_bytes());
                            current_key = current_key.wrapping_add(plain_arg);
                        }
                        VmOpcode::VPushImm32(val) => {
                            let cipher_arg = self.arch.opcode_cryptor.encrypt(*val, current_key);
                            bytecode.extend_from_slice(&cipher_arg.to_le_bytes());
                            current_key = current_key.wrapping_add(*val);
                        }
                        VmOpcode::VPushImm64(val) => {
                            // 8-byte immediate: encrypt as two 32-bit halves
                            let lo = *val as u32;
                            let hi = (*val >> 32) as u32;
                            let cipher_lo = self.arch.opcode_cryptor.encrypt(lo, current_key);
                            bytecode.extend_from_slice(&cipher_lo.to_le_bytes());
                            current_key = current_key.wrapping_add(lo);
                            let cipher_hi = self.arch.opcode_cryptor.encrypt(hi, current_key);
                            bytecode.extend_from_slice(&cipher_hi.to_le_bytes());
                            current_key = current_key.wrapping_add(hi);
                        }
                        VmOpcode::VCall(arg_count) => {
                            let plain_arg = *arg_count as u32;
                            let cipher_arg = self.arch.opcode_cryptor.encrypt(plain_arg, current_key);
                            bytecode.extend_from_slice(&cipher_arg.to_le_bytes());
                            current_key = current_key.wrapping_add(plain_arg);
                        }
                        _ => {}
                    }
                }
            }
        }

        // === Pass 2: 修补跳转偏移量 ===
        for patch in &patches {
            if let Some(&target_pos) = label_positions.get(&patch.target_label) {
                // 计算相对偏移量: target_pos - (operand_offset + 4)
                // VIP 在读取操作数后指向 operand_offset + 4
                let current_pos = patch.operand_offset + 4;
                let offset = target_pos as i64 - current_pos as i64;
                let offset_i32 = offset as i32;

                // 加密偏移量
                let cipher_offset = self.arch.opcode_cryptor.encrypt(offset_i32 as u32, patch.encrypt_key);
                bytecode[patch.operand_offset..patch.operand_offset + 4]
                    .copy_from_slice(&cipher_offset.to_le_bytes());
            }
        }

        bytecode
    }

    /// 提取不带参数的核心操作码枚举，用于哈希查表
    fn extract_core_opcode(&self, ir: &VmOpcode) -> VmOpcode {
        match ir {
            VmOpcode::VPushReg(_) => VmOpcode::VPushReg(0),
            VmOpcode::VPopReg(_) => VmOpcode::VPopReg(0),
            VmOpcode::VPushImm32(_) => VmOpcode::VPushImm32(0),
            VmOpcode::VPushImm64(_) => VmOpcode::VPushImm64(0),
            VmOpcode::VCall(_) => VmOpcode::VCall(0),
            VmOpcode::VJcc(_, _) => VmOpcode::VJcc(0, 0),
            VmOpcode::VLabel(_) => VmOpcode::VLabel(0),
            VmOpcode::VJmp(_) => VmOpcode::VJmp(0),
            VmOpcode::VReadMem(_) => VmOpcode::VReadMem(0),
            VmOpcode::VWriteMem(_) => VmOpcode::VWriteMem(0),
            _ => ir.clone(),
        }
    }
}
