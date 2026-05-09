use crate::vm::handlers::HandlerGenerator;
use iced_x86::code_asm::*;
use iced_x86::IcedError;

// ========== VExit: 退出虚拟机，返回原生调用者 ==========

pub fn gen_vexit(gen: &mut HandlerGenerator) -> Result<(usize, usize), IcedError> {
    let start = gen.asm.instructions().len();
    let ctx = &gen.arch.context;

    // 1. 从 VM 栈顶弹出目标返回地址到 scratch2
    gen.vpop(ctx.scratch2)?;

    // 2. 从 save_area 读取真正的 Native RSP
    gen.asm.mov(ctx.scratch1, gen.save_area_va)?;
    gen.asm.mov(ctx.scratch1, qword_ptr(ctx.scratch1 + 40 + 16 * 8))?;

    // 3. Native 栈向下增长 8 字节，存放目标返回地址
    gen.asm.sub(ctx.scratch1, 8_i32)?;

    // 4. 保存计算后的新 RSP 供 restore_native_and_ret 使用 (偏移 24 处)
    gen.asm.mov(ctx.vip, gen.save_area_va)?;
    gen.asm.mov(qword_ptr(ctx.vip + 24), ctx.scratch1)?;

    // 5. 将目标返回地址写入栈中
    gen.asm.mov(qword_ptr(ctx.scratch1), ctx.scratch2)?;

    // 6. 恢复所有原生寄存器，并在末尾执行 ret (跳转到目标返回地址)
    gen.restore_native_and_ret()?;

    let end = gen.asm.instructions().len();
    Ok((start, end))
}

// ========== VExec: 陷阱到原生执行，返回后重入 VM ==========

pub fn gen_vexec(gen: &mut HandlerGenerator) -> Result<(usize, usize), IcedError> {
    let start = gen.asm.instructions().len();
    let ctx = &gen.arch.context;

    // 1. 从 VM 栈弹出要执行的指令岛地址
    gen.vpop(ctx.scratch1)?;

    // 2. 保存 VM 上下文 (VIP, VSP) 到 save_area
    gen.asm.mov(ctx.scratch2, gen.save_area_va)?;
    gen.asm.mov(qword_ptr(ctx.scratch2), ctx.vip)?;
    gen.asm.mov(qword_ptr(ctx.scratch2 + 8), ctx.vsp)?;

    // 临时将目标地址存放在 save_area + 32
    gen.asm.mov(qword_ptr(ctx.scratch2 + 32), ctx.scratch1)?;

    // 3. 在原生栈上构建 ret 跳板: 仅压入 func_addr！
    //    Island 末尾使用 JMP 跃迁回虚拟机，不再需要 reentry_va 在栈上
    gen.asm.mov(ctx.scratch1, qword_ptr(ctx.scratch2 + 40 + 16 * 8))?; // 取出 Native RSP
    gen.asm.sub(ctx.scratch1, 8_i32)?; // 只腾出 8 字节

    // 保存新 RSP 供 restore 使用
    gen.asm.mov(qword_ptr(ctx.scratch2 + 24), ctx.scratch1)?;

    // 取回目标地址，写入 [RSP]
    gen.asm.mov(ctx.scratch2, qword_ptr(ctx.scratch2 + 32))?;
    gen.asm.mov(qword_ptr(ctx.scratch1), ctx.scratch2)?; // func_addr

    // 4. 恢复原生寄存器并 ret (跳转到 func_addr，跳板出栈后 Island 将拿到 100% 完美的 RSP)
    gen.restore_native_and_ret()?;

    let end = gen.asm.instructions().len();
    Ok((start, end))
}
