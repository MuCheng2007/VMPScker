//! 载荷装配器 (Payload Assembler)
//! 将生成的机器码和字节码合并，处理所有相对地址引用

use crate::vm::arch::ArchConfig;
use crate::vm::opcode::VmOpcode;
use crate::vm::handlers::HandlerGenerator;
use crate::vm::gates::VmGates;
use iced_x86::code_asm::*;
use iced_x86::{Decoder, DecoderOptions, Instruction, IcedError};

pub struct VmPayload {
    pub binary_data: Vec<u8>, // 最终要写入 PE Section 的二进制数据
    pub entry_offset: usize,  // VM_Entry 在 binary_data 中的字节偏移量
}

/// 计算指令索引到字节偏移量的映射
/// 用 Decoder 从已汇编的字节流中解析每条指令的边界
fn compute_byte_offsets_from_bytes(asm: &CodeAssembler, code_bytes: &[u8], base_rip: u64) -> Vec<usize> {
    let mut decoder = Decoder::with_ip(64, code_bytes, base_rip, DecoderOptions::NONE);
    let mut offsets = Vec::with_capacity(asm.instructions().len());
    let mut inst = Instruction::default();

    while decoder.can_decode() {
        offsets.push((decoder.ip() - base_rip) as usize);
        decoder.decode_out(&mut inst);
    }

    offsets
}

impl VmPayload {
    /// 构建最终的虚拟机内存布局
    /// new_section_va: 该数据将被放置在 PE 中的绝对虚拟地址 (ImageBase + RVA)
    /// bytecode: 编译器生成的加密字节码
    /// return_va: VM Exit 跳转目标虚拟地址 (被保护代码之后的下一条指令地址)
    pub fn build(
        arch: &ArchConfig,
        bytecode: &[u8],
        new_section_va: u64,
        return_va: u64,
    ) -> Result<Self, IcedError> {
        // ==========================================
        // 第一步：生成所有代码组件（获取大小）
        // ==========================================

        let mut asm = CodeAssembler::new(64)?;

        let temp_table_va = new_section_va;
        let temp_bytecode_va = new_section_va;
        VmGates::gen_vmentry(&mut asm, arch, temp_table_va, temp_bytecode_va, 0)?;

        let mut handler_gen = HandlerGenerator::new(&mut asm, arch);
        let mut handler_offsets: std::collections::HashMap<VmOpcode, (usize, usize)> =
            std::collections::HashMap::new();

        handler_offsets.insert(VmOpcode::VAdd, handler_gen.gen_vadd_with_label()?);
        handler_offsets.insert(VmOpcode::VSub, handler_gen.gen_vsub_with_label()?);
        handler_offsets.insert(VmOpcode::VXor, handler_gen.gen_vxor_with_label()?);
        handler_offsets.insert(VmOpcode::VNand, handler_gen.gen_vnand_with_label()?);
        handler_offsets.insert(VmOpcode::VNor, handler_gen.gen_vnor_with_label()?);
        handler_offsets.insert(VmOpcode::VMul, handler_gen.gen_vmul_with_label()?);
        handler_offsets.insert(VmOpcode::VPushImm32(0), handler_gen.gen_vpush_imm32_with_label()?);
        handler_offsets.insert(VmOpcode::VPushImm64(0), handler_gen.gen_vpush_imm64_with_label()?);
        handler_offsets.insert(VmOpcode::VPushReg(0), handler_gen.gen_vpush_reg_with_label()?);
        handler_offsets.insert(VmOpcode::VPopReg(0), handler_gen.gen_vpop_reg_with_label()?);
        handler_offsets.insert(VmOpcode::VJmp(0), handler_gen.gen_vjmp_with_label()?);
        handler_offsets.insert(VmOpcode::VJcc(0, 0), handler_gen.gen_vjcc_with_label(0)?);
        // VCall 使用临时地址，第二步会用实际地址
        handler_offsets.insert(VmOpcode::VCall(0), handler_gen.gen_vcall_with_label(0, 0, 0)?);
        handler_offsets.insert(VmOpcode::VReadMem(0), handler_gen.gen_vreadmem_with_label(8)?);
        handler_offsets.insert(VmOpcode::VWriteMem(0), handler_gen.gen_vwritemem_with_label(8)?);
        handler_offsets.insert(VmOpcode::VNop, handler_gen.gen_vnop_with_label()?);
        handler_offsets.insert(VmOpcode::VExit, handler_gen.gen_vexit_with_label(return_va, 0)?);

        // 生成重入桩 (使用临时地址)
        let reentry_idx = VmGates::gen_vm_reentry(&mut asm, arch, 0, 0)?;

        let code_bytes = asm.assemble(new_section_va)?;
        let code_size = code_bytes.len();

        // 布局: [code] [save_area(40)] [handler_table(2048)] [bytecode]
        let save_area_offset = code_size;
        let save_area_size = 176usize; // VIP(8)+VSP(8)+VKEY(4)+pad(4)+NativeRSP(8)+func_addr(8) + reg_save_area(17*8=136)
        let table_offset = save_area_offset + save_area_size;
        let table_size = 256 * 8;
        let bytecode_offset = table_offset + table_size;

        // ==========================================
        // 第二步：使用实际偏移量重新生成
        // ==========================================

        let save_area_va = new_section_va + save_area_offset as u64;
        let table_va = new_section_va + table_offset as u64;
        let bytecode_va = new_section_va + bytecode_offset as u64;

        // 计算重入桩的实际地址
        let temp_byte_offsets = compute_byte_offsets_from_bytes(&asm, &code_bytes, new_section_va);
        let reentry_byte_off = temp_byte_offsets[reentry_idx.0];
        let reentry_va = new_section_va + reentry_byte_off as u64;
        eprintln!("[VM] Re-entry stub VA: 0x{:X}", reentry_va);
        eprintln!("[VM] Save area VA: 0x{:X}", save_area_va);
        eprintln!("[VM] Handler table VA: 0x{:X}", table_va);

        let mut final_asm = CodeAssembler::new(64)?;

        // 1. 重新生成 VM_Entry
        let (final_entry_idx, _) =
            VmGates::gen_vmentry(&mut final_asm, arch, table_va, bytecode_va, save_area_va)?;

        // 2. 重新生成所有 Handlers (VCall 使用实际地址，save_area_va 提供给寄存器保存区访问)
        let mut final_handler_gen = HandlerGenerator::with_save_area(&mut final_asm, arch, save_area_va);
        let mut final_handler_offsets: std::collections::HashMap<VmOpcode, (usize, usize)> =
            std::collections::HashMap::new();

        final_handler_offsets.insert(VmOpcode::VAdd, final_handler_gen.gen_vadd_with_label()?);
        final_handler_offsets.insert(VmOpcode::VSub, final_handler_gen.gen_vsub_with_label()?);
        final_handler_offsets.insert(VmOpcode::VXor, final_handler_gen.gen_vxor_with_label()?);
        final_handler_offsets.insert(VmOpcode::VNand, final_handler_gen.gen_vnand_with_label()?);
        final_handler_offsets.insert(VmOpcode::VNor, final_handler_gen.gen_vnor_with_label()?);
        final_handler_offsets.insert(VmOpcode::VMul, final_handler_gen.gen_vmul_with_label()?);
        final_handler_offsets.insert(VmOpcode::VPushImm32(0), final_handler_gen.gen_vpush_imm32_with_label()?);
        final_handler_offsets.insert(VmOpcode::VPushImm64(0), final_handler_gen.gen_vpush_imm64_with_label()?);
        final_handler_offsets.insert(VmOpcode::VPushReg(0), final_handler_gen.gen_vpush_reg_with_label()?);
        final_handler_offsets.insert(VmOpcode::VPopReg(0), final_handler_gen.gen_vpop_reg_with_label()?);
        final_handler_offsets.insert(VmOpcode::VJmp(0), final_handler_gen.gen_vjmp_with_label()?);
        final_handler_offsets.insert(VmOpcode::VJcc(0, 0), final_handler_gen.gen_vjcc_with_label(0)?);
        final_handler_offsets.insert(VmOpcode::VCall(0), final_handler_gen.gen_vcall_with_label(0, reentry_va, save_area_va)?);
        final_handler_offsets.insert(VmOpcode::VReadMem(0), final_handler_gen.gen_vreadmem_with_label(8)?);
        final_handler_offsets.insert(VmOpcode::VWriteMem(0), final_handler_gen.gen_vwritemem_with_label(8)?);
        final_handler_offsets.insert(VmOpcode::VNop, final_handler_gen.gen_vnop_with_label()?);
        final_handler_offsets.insert(VmOpcode::VExit, final_handler_gen.gen_vexit_with_label(return_va, save_area_va)?);

        // 3. 重新生成重入桩
        let (final_reentry_idx, _) = VmGates::gen_vm_reentry(&mut final_asm, arch, save_area_va, table_va)?;

        // 4. 汇编并计算偏移
        let final_code_bytes = final_asm.assemble(new_section_va)?;
        let byte_offsets = compute_byte_offsets_from_bytes(&final_asm, &final_code_bytes, new_section_va);

        let entry_byte_offset = byte_offsets[final_entry_idx];

        let handler_byte_offsets: std::collections::HashMap<VmOpcode, usize> =
            final_handler_offsets
                .iter()
                .map(|(op, (start_idx, _end_idx))| (*op, byte_offsets[*start_idx]))
                .collect();

        let exit_byte_offset = final_handler_offsets
            .get(&VmOpcode::VExit)
            .map(|(start_idx, _)| byte_offsets[*start_idx])
            .unwrap_or(0);

        // 5. 生成 Handler Table
        let mut handler_table_bytes = Vec::with_capacity(256 * 8);
        for i in 0..=255u8 {
            let handler_va = if let Some(op) = arch.reverse_map.get(&i) {
                if let Some(&byte_off) = handler_byte_offsets.get(op) {
                    new_section_va + byte_off as u64
                } else {
                    new_section_va + exit_byte_offset as u64
                }
            } else {
                new_section_va + exit_byte_offset as u64
            };
            handler_table_bytes.extend_from_slice(&handler_va.to_le_bytes());
        }

        // 6. 合并: code + save_area(zeros) + handler_table + bytecode
        let mut final_binary = final_code_bytes;
        // Save area (176 bytes: 40 header + 136 register buffer, zeroed — written at runtime)
        final_binary.extend_from_slice(&[0u8; 176]);
        final_binary.extend_from_slice(&handler_table_bytes);
        final_binary.extend_from_slice(bytecode);

        Ok(VmPayload {
            binary_data: final_binary,
            entry_offset: entry_byte_offset,
        })
    }
}
