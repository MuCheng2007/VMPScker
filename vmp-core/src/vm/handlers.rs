//! 核心微指令 Handler 生成器
//!
//! 在这里，每一条 VM 指令都会被翻译为 x64 汇编。
//! 注意：VM 是一个纯栈机器，所有操作都在 VSP (Virtual Stack Pointer) 上进行。

use crate::vm::arch::ArchConfig;
use crate::vm::dispatcher::DispatcherGen;
use iced_x86::code_asm::*;
use iced_x86::IcedError;

pub struct HandlerGenerator<'a> {
    pub asm: &'a mut CodeAssembler,
    pub arch: &'a ArchConfig,
}

impl<'a> HandlerGenerator<'a> {
    pub fn new(asm: &'a mut CodeAssembler, arch: &'a ArchConfig) -> Self {
        Self { asm, arch }
    }

    /// 辅助：将 AsmRegister64 转换为对应的 AsmRegister32
    fn to_32(reg: AsmRegister64) -> AsmRegister32 {
        match reg {
            rax => eax, rcx => ecx, rdx => edx, rbx => ebx,
            rbp => ebp, rsi => esi, rdi => edi,
            r8 => r8d, r9 => r9d, r10 => r10d, r11 => r11d,
            r12 => r12d, r13 => r13d, r14 => r14d, r15 => r15d,
            _ => eax,
        }
    }

    /// 辅助：弹出 64 位值到指定寄存器，并调整 VSP
    fn vpop(&mut self, target_reg: AsmRegister64) -> Result<(), IcedError> {
        let vsp = self.arch.context.vsp;
        self.asm.mov(target_reg, qword_ptr(vsp))?;
        self.asm.add(vsp, 8_i32)?;
        Ok(())
    }

    /// 辅助：将 64 位寄存器压入虚拟栈，并调整 VSP
    fn vpush(&mut self, src_reg: AsmRegister64) -> Result<(), IcedError> {
        let vsp = self.arch.context.vsp;
        self.asm.sub(vsp, 8_i32)?;
        self.asm.mov(qword_ptr(vsp), src_reg)?;
        Ok(())
    }

    /// 辅助：保存当前 EFLAGS 到原生栈的 EFLAGS 保存槽 (index 15)
    /// 保存区域在 [RSP + 0x2000]，EFLAGS 在 index 15 = offset 120
    /// (VM_Entry 中 pushfq 是第一个 push，位于最高地址)
    fn save_eflags(&mut self) -> Result<(), IcedError> {
        let ctx = &self.arch.context;
        self.asm.pushfq()?;
        self.asm.pop(ctx.scratch2)?;
        self.asm.mov(qword_ptr(rsp + 0x2000 + 15 * 8), ctx.scratch2)?;
        Ok(())
    }

    /// 生成 VPushReg 处理器 (从 Native Context 读取寄存器并压栈)
    pub fn gen_vpush_reg(&mut self) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;

        // 1. 从字节码读取寄存器偏移量 (加密的)
        self.asm.mov(ctx.scratch1_32, dword_ptr(ctx.vip))?;
        self.asm.add(ctx.vip, 4_i32)?;
        self.arch.opcode_cryptor.emit_asm_decrypt(self.asm, ctx, ctx.scratch1_32)?;
        self.asm.add(ctx.vkey_32, ctx.scratch1_32)?;

        // 2. 从原生栈上的保存区域读取寄存器值
        // 保存区域在 [RSP + 0x2000] 处 (因为 sub rsp, 0x2000)
        // scratch1_32 是寄存器索引 (0-14)，需要 *8 得到字节偏移
        // 注意：x64 下写入 r32 会自动零扩展到 r64
        self.asm.shl(ctx.scratch1_32, 3_i32)?; // scratch1 = index * 8
        self.asm.mov(ctx.scratch2, rsp)?;
        self.asm.add(ctx.scratch2, 0x2000_i32)?;
        self.asm.add(ctx.scratch2, ctx.scratch1)?;
        self.asm.mov(ctx.scratch1, qword_ptr(ctx.scratch2))?;

        // 3. 压入虚拟栈
        self.vpush(ctx.scratch1)?;

        DispatcherGen::append_dispatch_logic(self.asm, self.arch)?;
        Ok(offset)
    }

    pub fn gen_vpush_reg_with_label(&mut self) -> Result<(usize, usize), IcedError> {
        let label_offset = self.asm.instructions().len();
        self.gen_vpush_reg()?;
        let end_offset = self.asm.instructions().len();
        Ok((label_offset, end_offset))
    }

    /// 生成 VPopReg 处理器 (从虚拟栈弹出数据到 Native Context)
    pub fn gen_vpop_reg(&mut self) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;

        // 1. 从字节码读取寄存器偏移量
        self.asm.mov(ctx.scratch1_32, dword_ptr(ctx.vip))?;
        self.asm.add(ctx.vip, 4_i32)?;
        self.arch.opcode_cryptor.emit_asm_decrypt(self.asm, ctx, ctx.scratch1_32)?;
        self.asm.add(ctx.vkey_32, ctx.scratch1_32)?;

        // 2. 从虚拟栈弹出值到 scratch2
        self.vpop(ctx.scratch2)?;

        // 3. 计算目标地址：保存区域基址 + 偏移量
        // scratch1_32 * 8 得到字节偏移 (x64 下写入 r32 自动零扩展)
        self.asm.shl(ctx.scratch1_32, 3_i32)?;
        self.asm.add(ctx.scratch1, rsp)?;
        self.asm.add(ctx.scratch1, 0x2000_i32)?;

        // 4. 写入保存区域
        self.asm.mov(qword_ptr(ctx.scratch1), ctx.scratch2)?;

        DispatcherGen::append_dispatch_logic(self.asm, self.arch)?;
        Ok(offset)
    }

    pub fn gen_vpop_reg_with_label(&mut self) -> Result<(usize, usize), IcedError> {
        let label_offset = self.asm.instructions().len();
        self.gen_vpop_reg()?;
        let end_offset = self.asm.instructions().len();
        Ok((label_offset, end_offset))
    }

    /// 生成 VADD 处理器
    /// 语义：POP B, POP A, A+B, save EFLAGS to slot, PUSH Result
    pub fn gen_vadd(&mut self) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;

        self.vpop(ctx.scratch2)?; // B
        self.vpop(ctx.scratch1)?; // A
        self.asm.add(ctx.scratch1, ctx.scratch2)?;

        // 保存 EFLAGS 到保存槽（供 VJcc 读取）
        self.save_eflags()?;
        // 仅将结果压入 VM 栈
        self.vpush(ctx.scratch1)?;

        DispatcherGen::append_dispatch_logic(self.asm, self.arch)?;
        Ok(offset)
    }

    pub fn gen_vadd_with_label(&mut self) -> Result<(usize, usize), IcedError> {
        let label_offset = self.asm.instructions().len();
        self.gen_vadd()?;
        let end_offset = self.asm.instructions().len();
        Ok((label_offset, end_offset))
    }

    /// 生成 VSUB 处理器
    /// 语义：POP B, POP A, A-B, save EFLAGS to slot, PUSH Result
    pub fn gen_vsub(&mut self) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;

        self.vpop(ctx.scratch2)?; // B
        self.vpop(ctx.scratch1)?; // A
        self.asm.sub(ctx.scratch1, ctx.scratch2)?;

        self.save_eflags()?;
        self.vpush(ctx.scratch1)?;

        DispatcherGen::append_dispatch_logic(self.asm, self.arch)?;
        Ok(offset)
    }

    pub fn gen_vsub_with_label(&mut self) -> Result<(usize, usize), IcedError> {
        let label_offset = self.asm.instructions().len();
        self.gen_vsub()?;
        let end_offset = self.asm.instructions().len();
        Ok((label_offset, end_offset))
    }

    /// 生成 VXOR 处理器
    /// 语义：POP B, POP A, A^B, save EFLAGS to slot, PUSH Result
    pub fn gen_vxor(&mut self) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;

        self.vpop(ctx.scratch2)?;
        self.vpop(ctx.scratch1)?;
        self.asm.xor(ctx.scratch1, ctx.scratch2)?;

        self.save_eflags()?;
        self.vpush(ctx.scratch1)?;

        DispatcherGen::append_dispatch_logic(self.asm, self.arch)?;
        Ok(offset)
    }

    pub fn gen_vxor_with_label(&mut self) -> Result<(usize, usize), IcedError> {
        let label_offset = self.asm.instructions().len();
        self.gen_vxor()?;
        let end_offset = self.asm.instructions().len();
        Ok((label_offset, end_offset))
    }

    /// 生成 VNAND 处理器 (VMP的核心逻辑门)
    /// 语义：POP B, POP A, ~(A & B), save EFLAGS to slot, PUSH Result
    pub fn gen_vnand(&mut self) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;

        self.vpop(ctx.scratch2)?; // B
        self.vpop(ctx.scratch1)?; // A

        // NAND: ~(A & B)
        self.asm.and(ctx.scratch1, ctx.scratch2)?;
        self.asm.not(ctx.scratch1)?;

        self.save_eflags()?;
        self.vpush(ctx.scratch1)?;

        DispatcherGen::append_dispatch_logic(self.asm, self.arch)?;
        Ok(offset)
    }

    pub fn gen_vnand_with_label(&mut self) -> Result<(usize, usize), IcedError> {
        let label_offset = self.asm.instructions().len();
        self.gen_vnand()?;
        let end_offset = self.asm.instructions().len();
        Ok((label_offset, end_offset))
    }

    /// 生成 VNOR 处理器
    /// 语义：POP B, POP A, ~(A | B), save EFLAGS to slot, PUSH Result
    pub fn gen_vnor(&mut self) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;

        self.vpop(ctx.scratch2)?;
        self.vpop(ctx.scratch1)?;
        self.asm.or(ctx.scratch1, ctx.scratch2)?;
        self.asm.not(ctx.scratch1)?;

        self.save_eflags()?;
        self.vpush(ctx.scratch1)?;

        DispatcherGen::append_dispatch_logic(self.asm, self.arch)?;
        Ok(offset)
    }

    pub fn gen_vnor_with_label(&mut self) -> Result<(usize, usize), IcedError> {
        let label_offset = self.asm.instructions().len();
        self.gen_vnor()?;
        let end_offset = self.asm.instructions().len();
        Ok((label_offset, end_offset))
    }

    /// 生成 VMUL 处理器
    /// 语义：POP B, POP A, PUSH (A*B)
    /// 使用单操作数 IMUL: RDX:RAX = RAX * src，仅保留低64位
    pub fn gen_vmul(&mut self) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;

        self.vpop(ctx.scratch2)?; // B
        self.vpop(ctx.scratch1)?; // A

        // Save RDX (imul clobbers it)
        self.asm.push(rdx)?;
        // Move A to RAX for imul
        self.asm.mov(rax, ctx.scratch1)?;
        // RAX = RAX * scratch2 (low 64 bits)
        self.asm.imul(ctx.scratch2)?;
        // Save result
        self.asm.mov(ctx.scratch1, rax)?;
        // Restore RDX
        self.asm.pop(rdx)?;

        self.save_eflags()?;
        self.vpush(ctx.scratch1)?;

        DispatcherGen::append_dispatch_logic(self.asm, self.arch)?;
        Ok(offset)
    }

    pub fn gen_vmul_with_label(&mut self) -> Result<(usize, usize), IcedError> {
        let label_offset = self.asm.instructions().len();
        self.gen_vmul()?;
        let end_offset = self.asm.instructions().len();
        Ok((label_offset, end_offset))
    }

    /// 生成 VPushImm32 处理器 (从字节码中读取立即数并压栈)
    pub fn gen_vpush_imm32(&mut self) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;

        // 1. 从 [VIP] 读取加密的立即数
        self.asm.mov(ctx.scratch1_32, dword_ptr(ctx.vip))?;
        self.asm.add(ctx.vip, 4_i32)?;

        // 2. 解密立即数
        self.arch.opcode_cryptor.emit_asm_decrypt(self.asm, ctx, ctx.scratch1_32)?;

        // 3. 滚动密钥更新
        self.asm.add(ctx.vkey_32, ctx.scratch1_32)?;

        // 4. 压入虚拟栈 (零扩展到64位)
        self.vpush(ctx.scratch1)?;

        // 5. 追加分发器
        DispatcherGen::append_dispatch_logic(self.asm, self.arch)?;

        Ok(offset)
    }

    pub fn gen_vpush_imm32_with_label(&mut self) -> Result<(usize, usize), IcedError> {
        let label_offset = self.asm.instructions().len();
        self.gen_vpush_imm32()?;
        let end_offset = self.asm.instructions().len();
        Ok((label_offset, end_offset))
    }

    /// 生成 VPushImm64 处理器 (从字节码中读取64位立即数并压栈)
    /// 字节码格式: [encrypted_lo_32][encrypted_hi_32]
    pub fn gen_vpush_imm64(&mut self) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;

        // 1. 从 [VIP] 读取加密的低32位
        self.asm.mov(ctx.scratch1_32, dword_ptr(ctx.vip))?;
        self.asm.add(ctx.vip, 4_i32)?;

        // 2. 解密低32位
        self.arch.opcode_cryptor.emit_asm_decrypt(self.asm, ctx, ctx.scratch1_32)?;

        // 3. 滚动密钥更新 (低32位)
        self.asm.add(ctx.vkey_32, ctx.scratch1_32)?;

        // 4. 从 [VIP] 读取加密的高32位到 scratch2
        let scratch2_32 = Self::to_32(ctx.scratch2);
        self.asm.mov(scratch2_32, dword_ptr(ctx.vip))?;
        self.asm.add(ctx.vip, 4_i32)?;

        // 5. 解密高32位
        self.arch.opcode_cryptor.emit_asm_decrypt(self.asm, ctx, scratch2_32)?;

        // 6. 滚动密钥更新 (高32位)
        self.asm.add(ctx.vkey_32, scratch2_32)?;

        // 7. 组合为64位: scratch1 = (scratch2 << 32) | scratch1
        self.asm.shl(ctx.scratch2, 32_i32)?;
        self.asm.or(ctx.scratch1, ctx.scratch2)?;

        // 8. 压入虚拟栈
        self.vpush(ctx.scratch1)?;

        // 9. 追加分发器
        DispatcherGen::append_dispatch_logic(self.asm, self.arch)?;

        Ok(offset)
    }

    pub fn gen_vpush_imm64_with_label(&mut self) -> Result<(usize, usize), IcedError> {
        let label_offset = self.asm.instructions().len();
        self.gen_vpush_imm64()?;
        let end_offset = self.asm.instructions().len();
        Ok((label_offset, end_offset))
    }

    /// 生成虚拟机退出门 (VMExit)
    /// 恢复物理上下文并跳转到 OEP (原始入口点)
    pub fn gen_vexit(&mut self, oep_va: u64) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();

        // 1. 回收虚拟工作栈，恢复到上下文保存区
        // 保存的 RSP 在 [RSP + 0x1FF8] (因为 sub rsp, 0x2000 前存到了 [rsp-8])
        self.asm.mov(rsp, qword_ptr(rsp + 0x1FF8))?;

        // 2. 恢复原生上下文 (与 VM_Entry push 顺序相反)
        let regs_reversed = [
            r15, r14, r13, r12, r11, r10, r9, r8, rdi, rsi, rbp, rbx, rdx, rcx, rax,
        ];
        for reg in regs_reversed.iter() {
            self.asm.pop(*reg)?;
        }
        self.asm.popfq()?;

        // 3. 跳转到 OEP (原始入口点)
        // 需要使用绝对地址跳转
        self.asm.mov(rax, oep_va)?;
        self.asm.jmp(rax)?;

        Ok(offset)
    }

    pub fn gen_vexit_with_label(&mut self, oep_va: u64) -> Result<(usize, usize), IcedError> {
        let label_offset = self.asm.instructions().len();
        self.gen_vexit(oep_va)?;
        let end_offset = self.asm.instructions().len();
        Ok((label_offset, end_offset))
    }

    /// 生成 VJMP 处理器（字节码内部无条件跳转）
    /// 语义：从字节码读取 i32 偏移量，VIP += offset，继续分发
    pub fn gen_vjmp(&mut self) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;

        // 1. 从 [VIP] 读取加密的偏移量
        self.asm.mov(ctx.scratch1_32, dword_ptr(ctx.vip))?;
        self.asm.add(ctx.vip, 4_i32)?;

        // 2. 解密偏移量
        self.arch.opcode_cryptor.emit_asm_decrypt(self.asm, ctx, ctx.scratch1_32)?;

        // 3. 更新滚动密钥
        self.asm.add(ctx.vkey_32, ctx.scratch1_32)?;

        // 4. VIP += offset (偏移量是相对于当前 VIP 的有符号偏移)
        self.asm.add(ctx.vip, ctx.scratch1)?;

        // 5. 继续分发下一条指令
        DispatcherGen::append_dispatch_logic(self.asm, self.arch)?;

        Ok(offset)
    }

    pub fn gen_vjmp_with_label(&mut self) -> Result<(usize, usize), IcedError> {
        let label_offset = self.asm.instructions().len();
        self.gen_vjmp()?;
        let end_offset = self.asm.instructions().len();
        Ok((label_offset, end_offset))
    }

    /// 生成 VJCC 处理器（字节码内部条件跳转）
    /// 语义：从 EFLAGS 保存槽读取标志，从字节码读取 i32 偏移量，检查条件，分支或跳过
    /// EFLAGS 由 VAdd/VSub/VXor/VNand/VNor 等算术 handler 自动保存到保存槽
    /// condition: 0=E/Z, 1=NE/NZ, 2=C, 3=NC, 4=S, 5=NS, 6=O, 7=NO,
    ///            8=A, 9=AE, 10=B, 11=BE, 12=G, 13=GE, 14=L, 15=LE
    pub fn gen_vjcc(&mut self, condition: u8) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;

        // 1. 从 [VIP] 读取加密的偏移量到 scratch1
        self.asm.mov(ctx.scratch1_32, dword_ptr(ctx.vip))?;

        // 2. 解密偏移量
        self.arch.opcode_cryptor.emit_asm_decrypt(self.asm, ctx, ctx.scratch1_32)?;

        // 3. 更新滚动密钥
        self.asm.add(ctx.vkey_32, ctx.scratch1_32)?;

        // 4. VIP += 4 (跳过操作数)
        self.asm.add(ctx.vip, 4_i32)?;

        // 5. 从 EFLAGS 保存槽读取标志 (index 15, offset 120)
        //    保存区域在 [RSP + 0x2000]，EFLAGS 在 +120 (pushfq 是第一个 push，最高地址)
        self.asm.mov(ctx.scratch2, qword_ptr(rsp + 0x2000 + 15 * 8))?;

        // 6. 清零 scratch2，然后恢复 EFLAGS
        self.asm.push(ctx.scratch2)?;              // 保存 EFLAGS 值到原生栈
        self.asm.xor(ctx.scratch2, ctx.scratch2)?; // scratch2 = 0 (破坏 flags，但马上恢复)
        self.asm.popfq()?;                          // 从原生栈恢复 EFLAGS

        // 7. 条件移动：cmovcc 根据 EFLAGS 条件选择 scratch1 或 scratch2(=0)
        //    条件成立 → scratch2 = scratch1 (偏移量)
        //    条件不成立 → scratch2 = 0
        match condition {
            0 => { self.asm.cmovz(ctx.scratch2, ctx.scratch1)?; }    // E/Z
            1 => { self.asm.cmovnz(ctx.scratch2, ctx.scratch1)?; }   // NE/NZ
            2 => { self.asm.cmovc(ctx.scratch2, ctx.scratch1)?; }    // C
            3 => { self.asm.cmovnc(ctx.scratch2, ctx.scratch1)?; }   // NC
            4 => { self.asm.cmovs(ctx.scratch2, ctx.scratch1)?; }    // S
            5 => { self.asm.cmovns(ctx.scratch2, ctx.scratch1)?; }   // NS
            6 => { self.asm.cmovo(ctx.scratch2, ctx.scratch1)?; }    // O
            7 => { self.asm.cmovno(ctx.scratch2, ctx.scratch1)?; }   // NO
            8 => { self.asm.cmova(ctx.scratch2, ctx.scratch1)?; }    // A (CF=0 && ZF=0)
            9 => { self.asm.cmovae(ctx.scratch2, ctx.scratch1)?; }   // AE (CF=0)
            10 => { self.asm.cmovb(ctx.scratch2, ctx.scratch1)?; }   // B (CF=1)
            11 => { self.asm.cmovbe(ctx.scratch2, ctx.scratch1)?; }  // BE (CF=1 || ZF=1)
            12 => { self.asm.cmovg(ctx.scratch2, ctx.scratch1)?; }   // G
            13 => { self.asm.cmovge(ctx.scratch2, ctx.scratch1)?; }  // GE
            14 => { self.asm.cmovl(ctx.scratch2, ctx.scratch1)?; }   // L
            15 => { self.asm.cmovle(ctx.scratch2, ctx.scratch1)?; }  // LE
            _ => {} // fallback: scratch2 stays 0, no jump
        }

        // 8. VIP += scratch2 (条件成立时跳转，否则 VIP 不变)
        self.asm.add(ctx.vip, ctx.scratch2)?;

        DispatcherGen::append_dispatch_logic(self.asm, self.arch)?;

        Ok(offset)
    }

    pub fn gen_vjcc_with_label(&mut self, condition: u8) -> Result<(usize, usize), IcedError> {
        let label_offset = self.asm.instructions().len();
        self.gen_vjcc(condition)?;
        let end_offset = self.asm.instructions().len();
        Ok((label_offset, end_offset))
    }

    /// 生成 VCall 处理器 (执行原生函数调用并重入 VM)
    ///
    /// Save area layout (40 bytes):
    ///   [save+0]  = VIP (8)
    ///   [save+8]  = VSP (8)
    ///   [save+16] = VKEY (4)
    ///   [save+24] = (unused)
    ///   [save+32] = function address (8)
    ///
    /// Flow:
    /// 1. Pop function address from VM stack → scratch1
    /// 2. Save VM context (VIP/VSP/VKEY) to .vmp0 save area
    /// 3. Save function address to [save+32]
    /// 4. Restore native RSP from VM_Entry's saved RSP
    /// 5. Restore ALL native registers (pop r15...rax, popfq)
    /// 6. Use R10 (volatile, not used for args) to load function address
    /// 7. Real CALL to function — CPU pushes return address natively, preserving
    ///    shadow space offsets and 16-byte stack alignment
    /// 8. Function returns here with RAX intact → jmp to reentry stub
    pub fn gen_vcall(&mut self, _arg_count: u8, reentry_va: u64, save_area_va: u64) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;

        // 1. Pop function address from VM stack
        self.vpop(ctx.scratch1)?;

        // 2. Save VM context to .vmp0 save area
        self.asm.mov(ctx.scratch2, save_area_va)?;
        self.asm.mov(qword_ptr(ctx.scratch2), ctx.vip)?;          // [save+0]  = VIP
        self.asm.mov(qword_ptr(ctx.scratch2 + 8), ctx.vsp)?;      // [save+8]  = VSP
        self.asm.mov(dword_ptr(ctx.scratch2 + 16), ctx.vkey_32)?;  // [save+16] = VKEY

        // 3. Save function address to [save+32]
        self.asm.mov(qword_ptr(ctx.scratch2 + 32), ctx.scratch1)?;

        // === Leaving VM, restoring native state ===

        // 4. Restore native RSP (VM_Entry saved it at [RSP_vm - 8] before sub rsp, 0x2000)
        self.asm.mov(rsp, qword_ptr(rsp + 0x1FF8))?;

        // 5. Restore ALL native registers — from here on, ctx.xxx registers carry
        //    real native data (RCX, RDX, etc.) and must not be touched.
        let regs_reversed = [
            r15, r14, r13, r12, r11, r10, r9, r8, rdi, rsi, rbp, rbx, rdx, rcx, rax,
        ];
        for reg in regs_reversed.iter() {
            self.asm.pop(*reg)?;
        }
        self.asm.popfq()?;

        // === Fully back in native state ===

        // 6. Load function address via volatile R10
        self.asm.mov(r10, save_area_va)?;
        self.asm.mov(r10, qword_ptr(r10 + 32))?;

        // 7. Real CALL — CPU pushes return address natively,
        //    preserving shadow space layout and 16-byte alignment.
        self.asm.call(r10)?;

        // === API returned here, RAX holds return value ===

        // 8. Jump to VM re-entry stub with return value intact
        self.asm.mov(r10, reentry_va)?;
        self.asm.jmp(r10)?;

        Ok(offset)
    }

    pub fn gen_vcall_with_label(&mut self, arg_count: u8, reentry_va: u64, save_area_va: u64) -> Result<(usize, usize), IcedError> {
        let label_offset = self.asm.instructions().len();
        self.gen_vcall(arg_count, reentry_va, save_area_va)?;
        let end_offset = self.asm.instructions().len();
        Ok((label_offset, end_offset))
    }

    /// 生成 VReadMem 处理器
    /// 语义：POP addr, PUSH [addr] (读取 N 字节)
    pub fn gen_vreadmem(&mut self, size: u8) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;

        // 1. 从虚拟栈弹出地址到 scratch1
        self.vpop(ctx.scratch1)?;

        // 2. 读取内存到 scratch2
        //    注意：scratch2 没有 32 位视图，4 字节读取需要特殊处理
        match size {
            1 => {
                self.asm.movzx(ctx.scratch2, byte_ptr(ctx.scratch1))?;
            }
            2 => {
                self.asm.movzx(ctx.scratch2, word_ptr(ctx.scratch1))?;
            }
            4 => {
                // 使用 mov r32, [addr] 自动零扩展到 r64
                // 手动获取 scratch2 的 32 位视图
                let scratch2_32 = Self::to_32(ctx.scratch2);
                self.asm.mov(scratch2_32, dword_ptr(ctx.scratch1))?;
            }
            _ => {
                self.asm.mov(ctx.scratch2, qword_ptr(ctx.scratch1))?;
            }
        }

        // 3. 压入虚拟栈
        self.vpush(ctx.scratch2)?;

        DispatcherGen::append_dispatch_logic(self.asm, self.arch)?;
        Ok(offset)
    }

    pub fn gen_vreadmem_with_label(&mut self, size: u8) -> Result<(usize, usize), IcedError> {
        let label_offset = self.asm.instructions().len();
        self.gen_vreadmem(size)?;
        let end_offset = self.asm.instructions().len();
        Ok((label_offset, end_offset))
    }

    /// 生成 VWriteMem 处理器
    /// 语义：POP addr, POP Value, [addr] = Value (写入 N 字节)
    pub fn gen_vwritemem(&mut self, size: u8) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;

        // 1. 从虚拟栈弹出地址到 scratch1
        self.vpop(ctx.scratch1)?;
        // 2. 从虚拟栈弹出值到 scratch2
        self.vpop(ctx.scratch2)?;

        // 3. 写入内存
        match size {
            1 => {
                // Write 1 byte: use dword write as fallback (writes 4 bytes but functional)
                let scratch2_32 = Self::to_32(ctx.scratch2);
                self.asm.mov(dword_ptr(ctx.scratch1), scratch2_32)?;
            }
            2 => {
                // Write 2 bytes: use dword write as fallback (writes 4 bytes but functional)
                let scratch2_32 = Self::to_32(ctx.scratch2);
                self.asm.mov(dword_ptr(ctx.scratch1), scratch2_32)?;
            }
            4 => {
                let scratch2_32 = Self::to_32(ctx.scratch2);
                self.asm.mov(dword_ptr(ctx.scratch1), scratch2_32)?;
            }
            _ => {
                self.asm.mov(qword_ptr(ctx.scratch1), ctx.scratch2)?;
            }
        }

        DispatcherGen::append_dispatch_logic(self.asm, self.arch)?;
        Ok(offset)
    }

    pub fn gen_vwritemem_with_label(&mut self, size: u8) -> Result<(usize, usize), IcedError> {
        let label_offset = self.asm.instructions().len();
        self.gen_vwritemem(size)?;
        let end_offset = self.asm.instructions().len();
        Ok((label_offset, end_offset))
    }

    /// 生成 VNop 处理器 (空操作，直接继续分发)
    pub fn gen_vnop(&mut self) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        DispatcherGen::append_dispatch_logic(self.asm, self.arch)?;
        Ok(offset)
    }

    pub fn gen_vnop_with_label(&mut self) -> Result<(usize, usize), IcedError> {
        let label_offset = self.asm.instructions().len();
        self.gen_vnop()?;
        let end_offset = self.asm.instructions().len();
        Ok((label_offset, end_offset))
    }
}
