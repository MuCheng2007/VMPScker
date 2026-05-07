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

    /// 预扫描 IR，计算每个 label 处的 VKEY 值 (不含 label 之后指令的贡献)
    fn compute_label_keys(&self, vm_irs: &[VmOpcode]) -> HashMap<u32, u32> {
        let mut label_keys: HashMap<u32, u32> = HashMap::new();
        let mut current_key = self.arch.initial_crypt_key;

        for ir in vm_irs {
            match ir {
                VmOpcode::VLabel(id) => {
                    label_keys.insert(*id, current_key);
                    continue;
                }
                VmOpcode::VJmp(_) | VmOpcode::VJcc(_, _) => {
                    let core_opcode = self.extract_core_opcode(ir);
                    let plain_index = *self.arch.opcode_map.get(&core_opcode).unwrap_or(&0) as u32;
                    current_key = current_key.wrapping_add(plain_index);
                    // jump operands do not update key (consistent with runtime handlers)
                }
                _ => {
                    let core_opcode = self.extract_core_opcode(ir);
                    let plain_index = *self.arch.opcode_map.get(&core_opcode).unwrap_or(&0) as u32;
                    current_key = current_key.wrapping_add(plain_index);

                    match ir {
                        VmOpcode::VPushReg(offset) | VmOpcode::VPopReg(offset) => {
                            current_key = current_key.wrapping_add(*offset as u32);
                        }
                        VmOpcode::VPushImm32(val) => {
                            current_key = current_key.wrapping_add(*val);
                        }
                        VmOpcode::VPushImm64(val) => {
                            current_key = current_key.wrapping_add(*val as u32);
                            current_key = current_key.wrapping_add((*val >> 32) as u32);
                        }
                        _ => {}
                    }
                }
            }
        }

        label_keys
    }

    /// 将给定的 VM IR 序列编译为加密的 Vec<u8>
    /// 支持标签解析：VLabel 标记位置，VJmp(id)/VJcc(cond, id) 引用标签
    pub fn compile_block(&self, vm_irs: &[VmOpcode]) -> Vec<u8> {
        // Pre-pass: compute VKEY at each label position
        let label_keys = self.compute_label_keys(vm_irs);

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
                    // 无条件内部跳转: [encrypted_distance(4)] [encrypted_target_vkey(4)]
                    let core_opcode = self.extract_core_opcode(ir);
                    let plain_index = *self.arch.opcode_map.get(&core_opcode).unwrap_or(&0) as u32;
                    let cipher_opcode = self.arch.opcode_cryptor.encrypt(plain_index, current_key);
                    bytecode.extend_from_slice(&cipher_opcode.to_le_bytes());
                    current_key = current_key.wrapping_add(plain_index);

                    let operand_key = current_key;

                    // 占位 distance (4 bytes)，Pass 2 修补
                    patches.push(PatchInfo {
                        operand_offset: bytecode.len(),
                        target_label: *target_label,
                        encrypt_key: operand_key,
                    });
                    bytecode.extend_from_slice(&[0u8; 4]);

                    // target_vkey (4 bytes, encrypted with same operand_key)
                    let target_vkey = label_keys.get(target_label).copied().unwrap_or(self.arch.initial_crypt_key);
                    let cipher_vkey = self.arch.opcode_cryptor.encrypt(target_vkey, operand_key);
                    bytecode.extend_from_slice(&cipher_vkey.to_le_bytes());
                }
                VmOpcode::VJcc(_cond, target_label) => {
                    // 条件跳转: [encrypted_distance(4)] [encrypted_target_vkey(4)]
                    let core_opcode = self.extract_core_opcode(ir);
                    let plain_index = *self.arch.opcode_map.get(&core_opcode).unwrap_or(&0) as u32;
                    let cipher_opcode = self.arch.opcode_cryptor.encrypt(plain_index, current_key);
                    bytecode.extend_from_slice(&cipher_opcode.to_le_bytes());
                    current_key = current_key.wrapping_add(plain_index);

                    let operand_key = current_key;

                    // 占位 distance (4 bytes)，Pass 2 修补
                    patches.push(PatchInfo {
                        operand_offset: bytecode.len(),
                        target_label: *target_label,
                        encrypt_key: operand_key,
                    });
                    bytecode.extend_from_slice(&[0u8; 4]);

                    // target_vkey (4 bytes, encrypted with same operand_key)
                    let target_vkey = label_keys.get(target_label).copied().unwrap_or(self.arch.initial_crypt_key);
                    let cipher_vkey = self.arch.opcode_cryptor.encrypt(target_vkey, operand_key);
                    bytecode.extend_from_slice(&cipher_vkey.to_le_bytes());
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
                        VmOpcode::VCall(_) => {
                            // VCall has no inline operand — func addr is on the VM stack
                        }
                        _ => {}
                    }
                }
            }
        }

        // === Pass 2: 修补跳转偏移量 ===
        for patch in &patches {
            if let Some(&target_pos) = label_positions.get(&patch.target_label) {
                // 计算相对偏移量: target_pos - (operand_offset + 8)
                // VIP 在读取两个操作数 (distance + target_vkey) 后指向 operand_offset + 8
                let current_pos = patch.operand_offset + 8;
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
            VmOpcode::VJcc(cond, _) => VmOpcode::VJcc(*cond, 0),
            VmOpcode::VLabel(_) => VmOpcode::VLabel(0),
            VmOpcode::VJmp(_) => VmOpcode::VJmp(0),
            VmOpcode::VReadMem(_) => VmOpcode::VReadMem(0),
            VmOpcode::VWriteMem(_) => VmOpcode::VWriteMem(0),
            VmOpcode::VDiv => VmOpcode::VDiv,
            VmOpcode::VIdiv => VmOpcode::VIdiv,
            _ => ir.clone(),
        }
    }
}
