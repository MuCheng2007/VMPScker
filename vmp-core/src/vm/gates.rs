//! 虚拟机出入大门 (VM Gates)
//! 负责 Native 环境与 VM 环境的上下文切换

use crate::vm::arch::ArchConfig;
use crate::vm::dispatcher::DispatcherGen;
use iced_x86::code_asm::*;
use iced_x86::IcedError;

pub struct VmGates;

impl VmGates {
    /// 生成 VM_Entry (进入虚拟机)
    /// 返回值：(entry_offset, end_offset) 作为指令索引
    pub fn gen_vmentry(
        asm: &mut CodeAssembler,
        arch: &ArchConfig,
        table_va: u64,       // Handler Table 的虚拟地址
        bytecode_va: u64,    // Bytecode 的虚拟地址
    ) -> Result<(usize, usize), IcedError> {
        let entry_offset = asm.instructions().len();

        // 1. 保存所有原生上下文到原生栈 (Native Stack)
        // 顺序必须与 VExit 弹出的顺序完全逆序！
        asm.pushfq()?; // EFLAGS
        let regs = [
            rax, rcx, rdx, rbx, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15,
        ];
        for reg in regs.iter() {
            asm.push(*reg)?;
        }
        // 保存区域: [RSP, RSP+128) 包含 16 个 8 字节值

        let ctx = &arch.context;

        // 2. 初始化虚拟上下文
        // 保存当前 RSP 到 [RSP-8]，供 VM Exit 恢复使用
        asm.mov(qword_ptr(rsp - 8), rsp)?;
        // VSP 初始化到 RSP-8，这样 vpush (先减8再写) 不会覆盖保存的 RSP
        asm.mov(ctx.vsp, rsp)?;
        asm.sub(ctx.vsp, 8_i32)?;
        // 分配 VM 栈空间 (native RSP 用于中断处理等)
        asm.sub(rsp, 0x2000_i32)?;

        // 2.2 加载初始滚动密钥
        asm.mov(ctx.vkey_32, arch.initial_crypt_key)?;

        // 2.3 加载 Handler Table 和 Bytecode 基址
        asm.mov(ctx.table, table_va)?;
        asm.mov(ctx.vip, bytecode_va)?;
        asm.mov(ctx.vbase, bytecode_va)?; // 保存字节码基址供 VJmp/VJcc 使用

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
    /// 桩代码保存原生上下文，从 .vmp0 固定保存区恢复 VM 上下文，然后跳转到分发器。
    ///
    /// save_area_va: .vmp0 中固定保存区的虚拟地址 (40 bytes)
    /// table_va: Handler Table 的虚拟地址 (用于恢复 ctx.table)
    ///   [save+0]  = VIP
    ///   [save+8]  = VSP
    ///   [save+16] = VKEY (32-bit)
    ///   [save+24] = (unused)
    ///   [save+32] = scratch (used by VCall)
    ///
    /// 返回值: (entry_instruction_index, end_instruction_index)
    pub fn gen_vm_reentry(
        asm: &mut CodeAssembler,
        arch: &ArchConfig,
        save_area_va: u64,
        table_va: u64,
    ) -> Result<(usize, usize), IcedError> {
        let entry_offset = asm.instructions().len();
        let ctx = &arch.context;

        // 1. 保存原生上下文 (与 VMEntry 相同顺序)
        //    此时 [RSP] = return address (from CALL by VCall's push + jmp)
        //    我们需要先保存 RSP (函数返回后的栈指针) 到 .vmp0
        //    RSP_before_push = RSP + 8 (accounting for return address push)
        //    但实际上，重入桩是由 jmp 跳转来的，不是 call
        //    所以 [RSP] 不是返回地址，而是 VCall push 的 reentry_va
        //    函数通过 ret 弹出了 reentry_va 并跳转到这里
        //    所以当前 RSP 就是函数返回后的 RSP (指向原始栈内容)
        asm.pushfq()?;
        let regs = [
            rax, rcx, rdx, rbx, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15,
        ];
        for reg in regs.iter() {
            asm.push(*reg)?;
        }

        // 2. 保存当前 RSP，分配 VM 栈空间
        //    RSP 现在 = 原始 RSP - 128 (16 pushes) - 8 (pushfq)
        //    原始 RSP = RSP + 136
        //    但我们不直接用原始 RSP，而是用 [RSP-8] 存当前 RSP (与 VMEntry 一致)
        asm.mov(qword_ptr(rsp - 8), rsp)?;
        asm.sub(rsp, 0x2000_i32)?;

        // 3. 从 .vmp0 固定保存区恢复 VM 上下文
        asm.mov(ctx.scratch2, save_area_va)?;
        asm.mov(ctx.vip, qword_ptr(ctx.scratch2))?;          // VIP
        asm.mov(ctx.vsp, qword_ptr(ctx.scratch2 + 8))?;      // VSP
        asm.mov(ctx.vkey_32, dword_ptr(ctx.scratch2 + 16))?;  // VKEY

        // 4. 恢复 handler table 地址 (dispatch 需要 table 指向 handler table)
        asm.mov(ctx.table, table_va)?;

        // 5. 跳转到分发器
        DispatcherGen::append_dispatch_logic(asm, arch)?;

        let end_offset = asm.instructions().len();
        Ok((entry_offset, end_offset))
    }
}
