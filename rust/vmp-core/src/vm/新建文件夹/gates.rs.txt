//! 虚拟机出入大门 (VM Gates)
//! 负责 Native 环境与 VM 环境的上下文切换

use crate::vm::arch::ArchConfig;
use crate::vm::dispatcher::DispatcherGen;
use iced_x86::code_asm::*;
use iced_x86::IcedError;

pub struct VmGates;

impl VmGates {
    /// 生成 VM_Entry (进入虚拟机)
    /// save_area_va: .vmp0 固定保存区虚拟地址
    ///   保存区布局 (176 bytes):
    ///     [+0]  = VIP (8), [+8] = VSP (8), [+16] = VKEY (4)
    ///     [+24] = Native RSP (8), [+32] = func_addr (8)
    ///     [+40] = 寄存器保存区 (17×8=136 bytes)
    ///       索引: 0=R15, 1=R14, 2=R13, 3=R12, 4=R11, 5=R10,
    ///             6=R9, 7=R8, 8=RDI, 9=RSI, 10=RBP, 11=RBX,
    ///             12=RDX, 13=RCX, 14=RAX, 15=EFLAGS, 16=Native RSP
    /// 返回值：(entry_offset, end_offset) 作为指令索引
    pub fn gen_vmentry(
        asm: &mut CodeAssembler,
        arch: &ArchConfig,
        table_va: u64,       // Handler Table 的虚拟地址
        bytecode_va: u64,    // Bytecode 的虚拟地址
        save_area_va: u64,   // .vmp0 保存区虚拟地址
    ) -> Result<(usize, usize), IcedError> {
        let entry_offset = asm.instructions().len();
        let ctx = &arch.context;

        // 1. 保存所有原生寄存器到 .vmp0 寄存器缓冲区
        // 使用 RBP 作为基址 (RBP 不在 VM 寄存器池中，不会冲突)
        asm.push(rbp)?;
        asm.mov(rbp, save_area_va)?;

        // 先保存 RAX (释放 RAX 作为临时寄存器)
        asm.mov(qword_ptr(rbp + 40 + 14 * 8), rax)?;

        // 索引 15 = EFLAGS (使用已保存的 RAX 作为临时寄存器)
        asm.pushfq()?;
        asm.pop(rax)?;
        asm.mov(qword_ptr(rbp + 40 + 15 * 8), rax)?;

        // 索引 13..0: RCX, RDX, RBX, RSI, RDI, R8..R15
        // (RBP 保存在原生栈中，稍后恢复再保存)
        asm.mov(qword_ptr(rbp + 40 + 13 * 8), rcx)?;
        asm.mov(qword_ptr(rbp + 40 + 12 * 8), rdx)?;
        asm.mov(qword_ptr(rbp + 40 + 11 * 8), rbx)?;
        // RBP: 稍后从栈中恢复并保存
        asm.mov(qword_ptr(rbp + 40 + 9 * 8), rsi)?;
        asm.mov(qword_ptr(rbp + 40 + 8 * 8), rdi)?;
        asm.mov(qword_ptr(rbp + 40 + 7 * 8), r8)?;
        asm.mov(qword_ptr(rbp + 40 + 6 * 8), r9)?;
        asm.mov(qword_ptr(rbp + 40 + 5 * 8), r10)?;
        asm.mov(qword_ptr(rbp + 40 + 4 * 8), r11)?;
        asm.mov(qword_ptr(rbp + 40 + 3 * 8), r12)?;
        asm.mov(qword_ptr(rbp + 40 + 2 * 8), r13)?;
        asm.mov(qword_ptr(rbp + 40 + 1 * 8), r14)?;
        asm.mov(qword_ptr(rbp + 40 + 0 * 8), r15)?;

        // 弹出原始 RBP 并保存
        asm.pop(rcx)?;
        asm.mov(qword_ptr(rbp + 40 + 10 * 8), rcx)?;

        // 索引 16 = 跟踪的原生 RSP
        asm.mov(qword_ptr(rbp + 40 + 16 * 8), rsp)?;

        // 2. 初始化虚拟上下文
        // VSP 初始化为 RSP_entry - 136 (与旧版语义一致，留出空间)
        asm.mov(ctx.vsp, rsp)?;
        asm.sub(ctx.vsp, 136_i32)?;
        // 分配 VM 栈空间 (在原生栈上)
        asm.sub(rsp, 0x2000_i32)?;

        // 2.2 加载初始滚动密钥
        asm.mov(ctx.vkey_32, arch.initial_crypt_key)?;

        // 2.3 加载 Handler Table 和 Bytecode 基址
        asm.mov(ctx.table, table_va)?;
        asm.mov(ctx.vip, bytecode_va)?;
        asm.mov(ctx.vbase, bytecode_va)?;

        // 3. 进入分发器流水线
        DispatcherGen::append_dispatch_logic(asm, arch)?;

        let end_offset = asm.instructions().len();
        Ok((entry_offset, end_offset))
    }

    /// 生成 VM_Exit (退出虚拟机，用于独立退出路径)
    /// 注意：正常退出通过 VExit handler，这里仅作为备用
    pub fn gen_vmexit(
        asm: &mut CodeAssembler,
        _arch: &ArchConfig,
        oep_va: u64, // 原始入口点的虚拟地址
    ) -> Result<(usize, usize), IcedError> {
        let exit_offset = asm.instructions().len();

        // 1. 恢复 RSP
        asm.mov(rsp, qword_ptr(rsp + 0x1FF8))?;

        // 2. 恢复原生上下文
        let regs_reversed = [
            r15, r14, r13, r12, r11, r10, r9, r8, rdi, rsi, rbp, rbx, rdx, rcx, rax,
        ];
        for reg in regs_reversed.iter() {
            asm.pop(*reg)?;
        }
        asm.popfq()?;

        // 3. 跳转到 OEP
        asm.mov(rax, oep_va)?;
        asm.jmp(rax)?;

        let end_offset = asm.instructions().len();
        Ok((exit_offset, end_offset))
    }

    /// 生成 VM 重入桩 (Re-entry Stub)
    ///
    /// 当 VCall 执行原生函数调用后，函数返回到此桩代码。
    /// 桩代码保存原生上下文到 .vmp0 寄存器缓冲区，从 .vmp0 固定保存区恢复 VM 上下文，然后跳转到分发器。
    pub fn gen_vm_reentry(
        asm: &mut CodeAssembler,
        arch: &ArchConfig,
        save_area_va: u64,
        table_va: u64,
    ) -> Result<(usize, usize), IcedError> {
        let entry_offset = asm.instructions().len();
        let ctx = &arch.context;

        // 1. 保存原生上下文到 .vmp0 寄存器缓冲区
        // 使用 RBP 作为基址 (不在 VM 寄存器池中，不会覆盖 RAX 返回值)
        asm.push(rbp)?;
        asm.mov(rbp, save_area_va)?;

        // 先保存 RAX (API 返回值，必须在任何 scratch 操作前保存)
        asm.mov(qword_ptr(rbp + 40 + 14 * 8), rax)?;

        // 索引 15 = EFLAGS (使用已保存的 RAX 作为临时寄存器)
        asm.pushfq()?;
        asm.pop(rax)?;
        asm.mov(qword_ptr(rbp + 40 + 15 * 8), rax)?;

        // 索引 13..0: RCX, RDX, RBX, RSI, RDI, R8..R15
        asm.mov(qword_ptr(rbp + 40 + 13 * 8), rcx)?;
        asm.mov(qword_ptr(rbp + 40 + 12 * 8), rdx)?;
        asm.mov(qword_ptr(rbp + 40 + 11 * 8), rbx)?;
        asm.mov(qword_ptr(rbp + 40 + 9 * 8), rsi)?;
        asm.mov(qword_ptr(rbp + 40 + 8 * 8), rdi)?;
        asm.mov(qword_ptr(rbp + 40 + 7 * 8), r8)?;
        asm.mov(qword_ptr(rbp + 40 + 6 * 8), r9)?;
        asm.mov(qword_ptr(rbp + 40 + 5 * 8), r10)?;
        asm.mov(qword_ptr(rbp + 40 + 4 * 8), r11)?;
        asm.mov(qword_ptr(rbp + 40 + 3 * 8), r12)?;
        asm.mov(qword_ptr(rbp + 40 + 2 * 8), r13)?;
        asm.mov(qword_ptr(rbp + 40 + 1 * 8), r14)?;
        asm.mov(qword_ptr(rbp + 40 + 0 * 8), r15)?;

        // 弹出 API 调用者的 RBP 并保存
        asm.pop(rcx)?;
        asm.mov(qword_ptr(rbp + 40 + 10 * 8), rcx)?;

        // 索引 16 = 跟踪的原生 RSP (API 返回后的栈指针)
        asm.mov(qword_ptr(rbp + 40 + 16 * 8), rsp)?;

        // 2. 分配 VM 栈空间
        asm.sub(rsp, 0x2000_i32)?;

        // 3. 从 .vmp0 固定保存区恢复 VM 上下文
        asm.mov(ctx.scratch2, save_area_va)?;
        asm.mov(ctx.vip, qword_ptr(ctx.scratch2))?;          // VIP
        asm.mov(ctx.vsp, qword_ptr(ctx.scratch2 + 8))?;      // VSP
        asm.mov(ctx.vkey_32, dword_ptr(ctx.scratch2 + 16))?;  // VKEY

        // 4. 恢复 handler table 地址
        asm.mov(ctx.table, table_va)?;

        // 5. 跳转到分发器
        DispatcherGen::append_dispatch_logic(asm, arch)?;

        let end_offset = asm.instructions().len();
        Ok((entry_offset, end_offset))
    }
}
