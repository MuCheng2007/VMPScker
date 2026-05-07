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
    pub save_area_va: u64,
}

impl<'a> HandlerGenerator<'a> {
    pub fn new(asm: &'a mut CodeAssembler, arch: &'a ArchConfig) -> Self {
        Self { asm, arch, save_area_va: 0 }
    }

    pub fn with_save_area(asm: &'a mut CodeAssembler, arch: &'a ArchConfig, save_area_va: u64) -> Self {
        Self { asm, arch, save_area_va }
    }

    /// 返回寄存器保存区基址 (.vmp0 中 [save_area + 40]) 作为 i64 立即数
    fn reg_save_base(&self) -> i64 {
        self.save_area_va as i64 + 40
    }

    /// 加载寄存器保存区基址 (.vmp0 中 [save_area + 40]) 到指定寄存器
    fn load_reg_save_base(&mut self, reg: AsmRegister64) -> Result<(), IcedError> {
        self.asm.mov(reg, self.save_area_va)?;
        self.asm.add(reg, 40_i32)?;
        Ok(())
    }

    /// 加载 save_area_va 到指定寄存器 (用于访问 save_area 头部)
    fn load_save_area_va(&mut self, reg: AsmRegister64) -> Result<(), IcedError> {
        self.asm.mov(reg, self.save_area_va)?;
        Ok(())
    }

    /// 辅助：将 AsmRegister64 转换为对应的 AsmRegister32
    /// 使用 iced_x86::Register 枚举进行匹配，避免 Rust match 变量绑定陷阱
    fn to_32(reg: AsmRegister64) -> AsmRegister32 {
        let r: iced_x86::Register = reg.into();
        match r {
            iced_x86::Register::RAX => eax,
            iced_x86::Register::RCX => ecx,
            iced_x86::Register::RDX => edx,
            iced_x86::Register::RBX => ebx,
            iced_x86::Register::RSP => esp,
            iced_x86::Register::RBP => ebp,
            iced_x86::Register::RSI => esi,
            iced_x86::Register::RDI => edi,
            iced_x86::Register::R8  => r8d,
            iced_x86::Register::R9  => r9d,
            iced_x86::Register::R10 => r10d,
            iced_x86::Register::R11 => r11d,
            iced_x86::Register::R12 => r12d,
            iced_x86::Register::R13 => r13d,
            iced_x86::Register::R14 => r14d,
            iced_x86::Register::R15 => r15d,
            _ => eax,
        }
    }

    /// 辅助：将 AsmRegister64 转换为对应的 AsmRegister16
    fn to_16(reg: AsmRegister64) -> AsmRegister16 {
        let r: iced_x86::Register = reg.into();
        match r {
            iced_x86::Register::RAX => ax,
            iced_x86::Register::RCX => cx,
            iced_x86::Register::RDX => dx,
            iced_x86::Register::RBX => bx,
            iced_x86::Register::RSP => sp,
            iced_x86::Register::RBP => bp,
            iced_x86::Register::RSI => si,
            iced_x86::Register::RDI => di,
            iced_x86::Register::R8  => r8w,
            iced_x86::Register::R9  => r9w,
            iced_x86::Register::R10 => r10w,
            iced_x86::Register::R11 => r11w,
            iced_x86::Register::R12 => r12w,
            iced_x86::Register::R13 => r13w,
            iced_x86::Register::R14 => r14w,
            iced_x86::Register::R15 => r15w,
            _ => ax,
        }
    }

    /// 辅助：将 AsmRegister64 转换为对应的 AsmRegister8
    fn to_8(reg: AsmRegister64) -> AsmRegister8 {
        let r: iced_x86::Register = reg.into();
        match r {
            iced_x86::Register::RAX => al,
            iced_x86::Register::RCX => cl,
            iced_x86::Register::RDX => dl,
            iced_x86::Register::RBX => bl,
            iced_x86::Register::RSP => spl,
            iced_x86::Register::RBP => bpl,
            iced_x86::Register::RSI => sil,
            iced_x86::Register::RDI => dil,
            iced_x86::Register::R8  => r8b,
            iced_x86::Register::R9  => r9b,
            iced_x86::Register::R10 => r10b,
            iced_x86::Register::R11 => r11b,
            iced_x86::Register::R12 => r12b,
            iced_x86::Register::R13 => r13b,
            iced_x86::Register::R14 => r14b,
            iced_x86::Register::R15 => r15b,
            _ => al,
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

    /// 辅助：保存当前 EFLAGS 到 .vmp0 寄存器保存区的 EFLAGS 槽 (index 15)
    fn save_eflags(&mut self) -> Result<(), IcedError> {
        let ctx = &self.arch.context;
        self.asm.pushfq()?;
        self.asm.pop(ctx.scratch2)?;            // scratch2 = EFLAGS
        self.asm.push(ctx.scratch1)?;           // save result to native stack
        self.load_reg_save_base(ctx.scratch1)?; // scratch1 = base
        self.asm.mov(qword_ptr(ctx.scratch1 + 15 * 8), ctx.scratch2)?;
        self.asm.pop(ctx.scratch1)?;            // restore result
        Ok(())
    }

    /// 生成 VPushReg 处理器 (从 .vmp0 寄存器缓冲区读取寄存器并压栈)
    /// 索引 16 = 原生 RSP (从 [+40+16*8] 读取跟踪的原生 RSP)
    pub fn gen_vpush_reg(&mut self) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;
        let base = self.reg_save_base();

        // 1. 从字节码读取寄存器偏移量 (加密的)
        self.asm.mov(ctx.scratch1_32, dword_ptr(ctx.vip))?;
        self.asm.add(ctx.vip, 4_i32)?;
        self.arch.opcode_cryptor.emit_asm_decrypt(self.asm, ctx, ctx.scratch1_32)?;
        self.asm.add(ctx.vkey_32, ctx.scratch1_32)?;

        // 2. 哨兵检查：索引 16 = Native RSP (直接存储，无需 +128)
        let mut label_rsp_done = self.asm.create_label();
        self.asm.cmp(ctx.scratch1_32, 16_i32)?;
        self.asm.jne(label_rsp_done)?;

        // RSP 路径: 从 [base + 16*8] 直接读取跟踪的原生 RSP
        self.load_reg_save_base(ctx.scratch2)?;
        self.asm.mov(ctx.scratch1, qword_ptr(ctx.scratch2 + 16 * 8))?;
        let mut label_push = self.asm.create_label();
        self.asm.jmp(label_push)?;

        // 正常路径: 从寄存器保存区读取 (base + index*8)
        self.asm.set_label(&mut label_rsp_done)?;
        self.asm.shl(ctx.scratch1_32, 3_i32)?; // scratch1 = index * 8
        self.asm.mov(ctx.scratch2, base)?;
        self.asm.add(ctx.scratch2, ctx.scratch1)?;
        self.asm.mov(ctx.scratch1, qword_ptr(ctx.scratch2))?;

        // 3. 压入虚拟栈
        self.asm.set_label(&mut label_push)?;
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

    /// 生成 VPopReg 处理器 (从虚拟栈弹出数据到 .vmp0 寄存器缓冲区)
    /// 索引 16 = 原生 RSP (直接写入 [+40+16*8]，无需 -128)
    pub fn gen_vpop_reg(&mut self) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;
        let base = self.reg_save_base();

        // 1. 从字节码读取寄存器偏移量
        self.asm.mov(ctx.scratch1_32, dword_ptr(ctx.vip))?;
        self.asm.add(ctx.vip, 4_i32)?;
        self.arch.opcode_cryptor.emit_asm_decrypt(self.asm, ctx, ctx.scratch1_32)?;
        self.asm.add(ctx.vkey_32, ctx.scratch1_32)?;

        // 2. 从虚拟栈弹出值到 scratch2
        self.vpop(ctx.scratch2)?;

        // 3. 哨兵检查：索引 16 = Native RSP (直接存储实际值)
        let mut label_rsp_done = self.asm.create_label();
        self.asm.cmp(ctx.scratch1_32, 16_i32)?;
        self.asm.jne(label_rsp_done)?;

        // RSP 路径: 直接写入 (存储实际 RSP 值，无需 -128 变换)
        self.load_reg_save_base(ctx.scratch1)?;
        self.asm.mov(qword_ptr(ctx.scratch1 + 16 * 8), ctx.scratch2)?;
        let mut label_dispatch = self.asm.create_label();
        self.asm.jmp(label_dispatch)?;

        // 正常路径: 写入寄存器保存区 (base + index*8)
        //  scratch2 = value to write, scratch1_32 = raw index
        self.asm.set_label(&mut label_rsp_done)?;
        self.asm.shl(ctx.scratch1_32, 3_i32)?; // scratch1 (64) = index * 8 (zero-extended)
        // 暂存 value 到原生栈以释放 scratch2 用于地址计算
        self.asm.push(ctx.scratch2)?;
        self.asm.mov(ctx.scratch2, base)?;       // scratch2 = base (64-bit imm)
        self.asm.add(ctx.scratch2, ctx.scratch1)?;// scratch2 = base + index*8
        self.asm.pop(ctx.scratch1)?;              // scratch1 = value
        self.asm.mov(qword_ptr(ctx.scratch2), ctx.scratch1)?; // [base+index*8] = value

        self.asm.set_label(&mut label_dispatch)?;
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
    /// 使用双操作数 IMUL 避免 RDX:RAX 隐式寄存器冲突
    pub fn gen_vmul(&mut self) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;

        self.vpop(ctx.scratch2)?;
        self.vpop(ctx.scratch1)?;

        self.asm.imul_2(ctx.scratch1, ctx.scratch2)?;

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

    /// 生成 VDiv 处理器 (无符号除法)
    /// 语义：栈上 [divisor(below), dividend(top)]，弹出后计算 dividend / divisor
    /// 注意：将除数先压入原生栈，防止 xor rdx,rdx 时误伤 scratch1(=RDX)
    pub fn gen_vdiv(&mut self) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;

        self.vpop(ctx.scratch2)?; // Dividend (pushed last, on top)
        self.vpop(ctx.scratch1)?; // Divisor  (pushed first, below)

        self.asm.push(ctx.scratch1)?;        // save divisor to native stack
        self.asm.mov(rax, ctx.scratch2)?;    // RAX = dividend
        self.asm.xor(rdx, rdx)?;             // clear RDX (safe: divisor on stack)
        self.asm.div(qword_ptr(rsp))?;       // RAX = quotient, RDX = remainder
        self.asm.add(rsp, 8_i32)?;           // pop saved divisor

        self.asm.mov(ctx.scratch1, rax)?;    // scratch1 = quotient
        self.asm.push(rdx)?;                 // save remainder to native stack (safe_eflags uses native stack too)

        self.save_eflags()?;                 // clobbers scratch2; native stack balanced
        self.asm.pop(ctx.scratch2)?;         // scratch2 = remainder

        self.vpush(ctx.scratch2)?;           // push remainder first (below)
        self.vpush(ctx.scratch1)?;           // push quotient (on top)

        DispatcherGen::append_dispatch_logic(self.asm, self.arch)?;
        Ok(offset)
    }

    pub fn gen_vdiv_with_label(&mut self) -> Result<(usize, usize), IcedError> {
        let label_offset = self.asm.instructions().len();
        self.gen_vdiv()?;
        let end_offset = self.asm.instructions().len();
        Ok((label_offset, end_offset))
    }

    /// 生成 VIdiv 处理器 (有符号除法)
    /// 语义：栈上 [divisor(below), dividend(top)]，弹出后计算 dividend / divisor
    /// 结果压入 [remainder(below), quotient(top)]，对应 lowering 先 pop RAX 再 pop RDX
    pub fn gen_vidiv(&mut self) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;

        self.vpop(ctx.scratch2)?; // Dividend (pushed last, on top)
        self.vpop(ctx.scratch1)?; // Divisor  (pushed first, below)

        self.asm.push(ctx.scratch1)?;        // save divisor to native stack (cqo clobbers RDX)
        self.asm.mov(rax, ctx.scratch2)?;    // RAX = dividend
        self.asm.cqo()?;                     // sign-extend RAX → RDX:RAX
        self.asm.idiv(qword_ptr(rsp))?;      // RAX = quotient, RDX = remainder
        self.asm.add(rsp, 8_i32)?;           // pop saved divisor
        self.asm.mov(ctx.scratch1, rax)?;    // scratch1 = quotient
        self.asm.push(rdx)?;                 // save remainder to native stack

        self.save_eflags()?;                 // clobbers scratch2; native stack balanced
        self.asm.pop(ctx.scratch2)?;         // scratch2 = remainder

        self.vpush(ctx.scratch2)?;           // push remainder first (below)
        self.vpush(ctx.scratch1)?;           // push quotient (on top)

        DispatcherGen::append_dispatch_logic(self.asm, self.arch)?;
        Ok(offset)
    }

    pub fn gen_vidiv_with_label(&mut self) -> Result<(usize, usize), IcedError> {
        let label_offset = self.asm.instructions().len();
        self.gen_vidiv()?;
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
    /// 使用 ret 跳板技术：在恢复寄存器前将 OEP 压入原生栈，
    /// 全部寄存器恢复后用 ret 弹出 OEP → 零寄存器污染回宿主。
    pub fn gen_vexit(&mut self, oep_va: u64, save_area_va: u64) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;

        // Save tracked RSP, reserve 8 bytes and push OEP for ret-trampoline
        self.asm.mov(ctx.scratch2, save_area_va)?;
        self.asm.mov(ctx.scratch1, qword_ptr(ctx.scratch2 + 40 + 16 * 8))?;

        self.asm.sub(ctx.scratch1, 8_i32)?;
        self.asm.mov(qword_ptr(ctx.scratch2 + 24), ctx.scratch1)?;

        self.asm.mov(ctx.scratch2, oep_va)?;
        self.asm.mov(qword_ptr(ctx.scratch1), ctx.scratch2)?;

        // Load r15 as base for register restore
        self.asm.mov(r15, save_area_va)?;

        // Restore R14..RAX (index 1..14), R15 restored last
        self.asm.mov(r14, qword_ptr(r15 + 40 + 1 * 8))?;
        self.asm.mov(r13, qword_ptr(r15 + 40 + 2 * 8))?;
        self.asm.mov(r12, qword_ptr(r15 + 40 + 3 * 8))?;
        self.asm.mov(r11, qword_ptr(r15 + 40 + 4 * 8))?;
        self.asm.mov(r10, qword_ptr(r15 + 40 + 5 * 8))?;
        self.asm.mov(r9, qword_ptr(r15 + 40 + 6 * 8))?;
        self.asm.mov(r8, qword_ptr(r15 + 40 + 7 * 8))?;
        self.asm.mov(rdi, qword_ptr(r15 + 40 + 8 * 8))?;
        self.asm.mov(rsi, qword_ptr(r15 + 40 + 9 * 8))?;
        self.asm.mov(rbp, qword_ptr(r15 + 40 + 10 * 8))?;
        self.asm.mov(rbx, qword_ptr(r15 + 40 + 11 * 8))?;
        self.asm.mov(rdx, qword_ptr(r15 + 40 + 12 * 8))?;
        self.asm.mov(rcx, qword_ptr(r15 + 40 + 13 * 8))?;
        self.asm.mov(rax, qword_ptr(r15 + 40 + 14 * 8))?;

        // Restore EFLAGS
        self.asm.push(qword_ptr(r15 + 40 + 15 * 8))?;
        self.asm.popfq()?;

        // Restore native RSP (points to OEP on stack)
        self.asm.mov(rsp, qword_ptr(r15 + 24))?;

        // Restore R15 LAST (index 0)
        self.asm.mov(r15, qword_ptr(r15 + 40 + 0 * 8))?;

        // ret 从栈顶弹出 OEP → 零寄存器污染跳回宿主
        self.asm.ret()?;

        Ok(offset)
    }

    pub fn gen_vexit_with_label(&mut self, oep_va: u64, save_area_va: u64) -> Result<(usize, usize), IcedError> {
        let label_offset = self.asm.instructions().len();
        self.gen_vexit(oep_va, save_area_va)?;
        let end_offset = self.asm.instructions().len();
        Ok((label_offset, end_offset))
    }

    /// 生成 VJMP 处理器（字节码内部无条件跳转）
    /// 语义：从字节码读取 i32 偏移量和目标 VKEY，VIP += offset，VKEY = target_vkey，继续分发
    /// 字节码格式: [encrypted_distance(4)] [encrypted_target_vkey(4)]
    pub fn gen_vjmp(&mut self) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;
        let scratch2_32 = Self::to_32(ctx.scratch2);

        // 1. 从 [VIP] 读取加密的距离
        self.asm.mov(ctx.scratch1_32, dword_ptr(ctx.vip))?;
        // 2. 从 [VIP+4] 读取加密的目标 VKEY
        self.asm.mov(scratch2_32, dword_ptr(ctx.vip + 4_i32))?;
        self.asm.add(ctx.vip, 8_i32)?;

        // 3. 解密两个操作数（使用相同的 VKEY）
        self.arch.opcode_cryptor.emit_asm_decrypt(self.asm, ctx, ctx.scratch1_32)?;
        self.arch.opcode_cryptor.emit_asm_decrypt(self.asm, ctx, scratch2_32)?;

        // 4. 符号扩展距离
        self.asm.movsxd(ctx.scratch1, ctx.scratch1_32)?;

        // 5. VIP += offset
        self.asm.add(ctx.vip, ctx.scratch1)?;

        // 6. VKEY = target_vkey
        self.asm.mov(ctx.vkey_32, scratch2_32)?;

        // 7. 继续分发下一条指令
        DispatcherGen::append_dispatch_logic(self.asm, self.arch)?;

        Ok(offset)
    }

    pub fn gen_vjmp_with_label(&mut self) -> Result<(usize, usize), IcedError> {
        let label_offset = self.asm.instructions().len();
        self.gen_vjmp()?;
        let end_offset = self.asm.instructions().len();
        Ok((label_offset, end_offset))
    }

    /// 生成 VJCC 处理器（字节码内部条件跳转，含目标 VKEY 同步）
    /// 语义：从 EFLAGS 保存槽读取标志，从字节码读取 i32 偏移量和目标 VKEY，
    ///       条件成立时 VIP += offset 且 VKEY = target_vkey，确保回跳/前跳后密钥同步
    /// 字节码格式: [encrypted_distance(4)] [encrypted_target_vkey(4)]
    /// condition: 0=E/Z, 1=NE/NZ, 2=C, 3=NC, 4=S, 5=NS, 6=O, 7=NO,
    ///            8=A, 9=AE, 10=B, 11=BE, 12=G, 13=GE, 14=L, 15=LE
    pub fn gen_vjcc(&mut self, condition: u8) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;
        let scratch2_32 = Self::to_32(ctx.scratch2);

        // 1. 从 [VIP] 读取加密的距离
        self.asm.mov(ctx.scratch1_32, dword_ptr(ctx.vip))?;
        // 2. 从 [VIP+4] 读取加密的目标 VKEY
        self.asm.mov(scratch2_32, dword_ptr(ctx.vip + 4_i32))?;
        self.asm.add(ctx.vip, 8_i32)?;

        // 3. 解密两个操作数（使用相同的 VKEY，跳转时不更新 VKEY）
        self.arch.opcode_cryptor.emit_asm_decrypt(self.asm, ctx, ctx.scratch1_32)?;
        self.arch.opcode_cryptor.emit_asm_decrypt(self.asm, ctx, scratch2_32)?;

        // 4. 符号扩展距离
        self.asm.movsxd(ctx.scratch1, ctx.scratch1_32)?;

        // 5. 保存 target_vkey 到原生栈 (scratch2 将被用于 EFLAGS 加载)
        self.asm.push(ctx.scratch2)?;

        // 6. 从 .vmp0 寄存器缓冲区恢复 EFLAGS
        self.asm.mov(ctx.scratch2, self.save_area_va)?;
        self.asm.push(qword_ptr(ctx.scratch2 + 40_i32 + 15_i32 * 8_i32))?;
        self.asm.popfq()?;

        // 7. 条件跳转: 使用逆条件跳过 branch-taken 代码块
        //    条件成立 → 执行 VIP+=offset, VKEY=target_vkey
        //    条件不成立 → 跳过 (fallthrough VIP, 保持当前 VKEY)
        let mut skip_label = self.asm.create_label();
        match condition {
            0 => { self.asm.jnz(skip_label)?; }    // E/Z  → skip if NZ
            1 => { self.asm.jz(skip_label)?; }      // NE/NZ → skip if Z
            2 => { self.asm.jnc(skip_label)?; }     // C     → skip if NC
            3 => { self.asm.jc(skip_label)?; }      // NC    → skip if C
            4 => { self.asm.jns(skip_label)?; }     // S     → skip if NS
            5 => { self.asm.js(skip_label)?; }      // NS    → skip if S
            6 => { self.asm.jno(skip_label)?; }     // O     → skip if NO
            7 => { self.asm.jo(skip_label)?; }      // NO    → skip if O
            8 => { self.asm.jbe(skip_label)?; }     // A     → skip if BE (CF=1||ZF=1)
            9 => { self.asm.jb(skip_label)?; }      // AE    → skip if B (CF=1)
            10 => { self.asm.jae(skip_label)?; }    // B     → skip if AE (CF=0)
            11 => { self.asm.ja(skip_label)?; }     // BE    → skip if A (CF=0&&ZF=0)
            12 => { self.asm.jle(skip_label)?; }    // G     → skip if LE (ZF=1||SF!=OF)
            13 => { self.asm.jl(skip_label)?; }     // GE    → skip if L (SF!=OF)
            14 => { self.asm.jge(skip_label)?; }    // L     → skip if GE (SF=OF)
            15 => { self.asm.jg(skip_label)?; }     // LE    → skip if G (ZF=0&&SF=OF)
            _ => {}
        }

        // Branch taken: VIP += offset, VKEY = target_vkey
        self.asm.add(ctx.vip, ctx.scratch1)?;
        self.asm.pop(ctx.scratch2)?;  // restore target_vkey
        self.asm.mov(ctx.vkey_32, scratch2_32)?;

        // Jump to dispatch, bypassing stack-cleanup at skip_label
        let mut dispatch_label = self.asm.create_label();
        self.asm.jmp(dispatch_label)?;

        // Branch NOT taken: pop and discard saved target_vkey (balance stack)
        self.asm.set_label(&mut skip_label)?;
        self.asm.pop(ctx.scratch2)?;  // discard saved target_vkey

        self.asm.set_label(&mut dispatch_label)?;
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
    /// 使用 ret 跳板技术：在恢复寄存器前将 [func_addr, reentry_va] 压入原生栈，
    /// 全部寄存器恢复后用 ret 弹出 func_addr → 零寄存器污染跳入 API。
    /// 当 API 执行 ret 时自动返回到 reentry_va。
    pub fn gen_vcall(&mut self, _arg_count: u8, reentry_va: u64, save_area_va: u64) -> Result<usize, IcedError> {
        let offset = self.asm.instructions().len();
        let ctx = &self.arch.context;

        // Phase 1: Pop func addr from VM stack
        self.vpop(ctx.scratch1)?;

        // Phase 2: Save VM context using scratch2 as temp base
        self.asm.mov(ctx.scratch2, save_area_va)?;
        self.asm.mov(qword_ptr(ctx.scratch2), ctx.vip)?;
        self.asm.mov(qword_ptr(ctx.scratch2 + 8), ctx.vsp)?;
        self.asm.mov(dword_ptr(ctx.scratch2 + 16), ctx.vkey_32)?;
        self.asm.mov(qword_ptr(ctx.scratch2 + 32), ctx.scratch1)?;

        // Build ret trampoline on native stack:
        // Reserve 16 bytes, write [func_addr, reentry_va] so that after register
        // restore, a single `ret` pops func_addr into RIP with zero register pollution.
        self.asm.mov(ctx.scratch1, qword_ptr(ctx.scratch2 + 40 + 16 * 8))?;
        self.asm.sub(ctx.scratch1, 16_i32)?;
        self.asm.mov(qword_ptr(ctx.scratch2 + 24), ctx.scratch1)?;

        // Write func_addr to [native RSP]
        self.asm.mov(ctx.scratch1, qword_ptr(ctx.scratch2 + 24))?;
        self.asm.mov(ctx.scratch2, qword_ptr(ctx.scratch2 + 32))?;
        self.asm.mov(qword_ptr(ctx.scratch1), ctx.scratch2)?;

        // Write reentry_va to [native RSP + 8]
        self.asm.mov(ctx.scratch2, reentry_va)?;
        self.asm.mov(qword_ptr(ctx.scratch1 + 8_i32), ctx.scratch2)?;

        // === VM context ops complete. Safe to clobber r15 for register restore. ===

        // Phase 3: Load r15 as base for register restore (r15 restored last)
        self.asm.mov(r15, save_area_va)?;

        // Restore R14..RAX (index 1..14)
        self.asm.mov(r14, qword_ptr(r15 + 40 + 1 * 8))?;
        self.asm.mov(r13, qword_ptr(r15 + 40 + 2 * 8))?;
        self.asm.mov(r12, qword_ptr(r15 + 40 + 3 * 8))?;
        self.asm.mov(r11, qword_ptr(r15 + 40 + 4 * 8))?;
        self.asm.mov(r10, qword_ptr(r15 + 40 + 5 * 8))?;
        self.asm.mov(r9, qword_ptr(r15 + 40 + 6 * 8))?;
        self.asm.mov(r8, qword_ptr(r15 + 40 + 7 * 8))?;
        self.asm.mov(rdi, qword_ptr(r15 + 40 + 8 * 8))?;
        self.asm.mov(rsi, qword_ptr(r15 + 40 + 9 * 8))?;
        self.asm.mov(rbp, qword_ptr(r15 + 40 + 10 * 8))?;
        self.asm.mov(rbx, qword_ptr(r15 + 40 + 11 * 8))?;
        self.asm.mov(rdx, qword_ptr(r15 + 40 + 12 * 8))?;
        self.asm.mov(rcx, qword_ptr(r15 + 40 + 13 * 8))?;
        self.asm.mov(rax, qword_ptr(r15 + 40 + 14 * 8))?;

        // Restore EFLAGS
        self.asm.push(qword_ptr(r15 + 40 + 15 * 8))?;
        self.asm.popfq()?;

        // Restore native RSP (points to func_addr on stack, reentry_va underneath)
        self.asm.mov(rsp, qword_ptr(r15 + 24))?;

        // Restore r15 LAST (index 0)
        self.asm.mov(r15, qword_ptr(r15 + 40 + 0 * 8))?;

        // ret pops func_addr → jump to API; API's ret lands on reentry_va
        self.asm.ret()?;

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

        // 3. 安全精准的对齐写入
        match size {
            1 => {
                let scratch2_8 = Self::to_8(ctx.scratch2);
                self.asm.mov(byte_ptr(ctx.scratch1), scratch2_8)?;
            }
            2 => {
                let scratch2_16 = Self::to_16(ctx.scratch2);
                self.asm.mov(word_ptr(ctx.scratch1), scratch2_16)?;
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
