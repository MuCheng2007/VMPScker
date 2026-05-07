//! VM 组装器
//! 负责生成所有的 Handler，并记录它们的偏移以构建 Handler Table

use crate::vm::arch::ArchConfig;
use crate::vm::opcode::VmOpcode;
use crate::vm::handlers::HandlerGenerator;
use iced_x86::code_asm::CodeAssembler;
use iced_x86::IcedError;
use std::collections::HashMap;

pub struct VmBuilder;

impl VmBuilder {
    /// 生成机器码并返回 Handler Table 映射
    pub fn build_handlers(
        arch: &ArchConfig,
        asm: &mut CodeAssembler,
    ) -> Result<HashMap<VmOpcode, (usize, usize)>, IcedError> {
        let mut handler_offsets = HashMap::new();
        let mut gen = HandlerGenerator::new(asm, arch);

        handler_offsets.insert(VmOpcode::VAdd, gen.gen_vadd_with_label()?);
        handler_offsets.insert(VmOpcode::VSub, gen.gen_vsub_with_label()?);
        handler_offsets.insert(VmOpcode::VXor, gen.gen_vxor_with_label()?);
        handler_offsets.insert(VmOpcode::VNand, gen.gen_vnand_with_label()?);
        handler_offsets.insert(VmOpcode::VNor, gen.gen_vnor_with_label()?);
        handler_offsets.insert(VmOpcode::VPushImm32(0), gen.gen_vpush_imm32_with_label()?);
        handler_offsets.insert(VmOpcode::VPushReg(0), gen.gen_vpush_reg_with_label()?);
        handler_offsets.insert(VmOpcode::VPopReg(0), gen.gen_vpop_reg_with_label()?);
        handler_offsets.insert(VmOpcode::VJmp(0), gen.gen_vjmp_with_label()?);
        handler_offsets.insert(VmOpcode::VJcc(0, 0), gen.gen_vjcc_with_label(0)?);
        handler_offsets.insert(VmOpcode::VReadMem(0), gen.gen_vreadmem_with_label(8)?);

        Ok(handler_offsets)
    }
}
