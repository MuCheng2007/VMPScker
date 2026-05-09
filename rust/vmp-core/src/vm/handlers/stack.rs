use crate::vm::handlers::HandlerGenerator;
use crate::vm::dispatcher::DispatcherGen;
use iced_x86::code_asm::*;
use iced_x86::IcedError;

// ========== VNop: 空操作 ==========

pub fn gen_vnop(gen: &mut HandlerGenerator) -> Result<(usize, usize), IcedError> {
    let start = gen.asm.instructions().len();
    DispatcherGen::append_dispatch_logic(gen.asm, gen.arch)?;
    let end = gen.asm.instructions().len();
    Ok((start, end))
}

// ========== VPushImm32: 从字节码读取 32 位立即数压栈 ==========

pub fn gen_vpush_imm32(gen: &mut HandlerGenerator) -> Result<(usize, usize), IcedError> {
    let start = gen.asm.instructions().len();
    let ctx = &gen.arch.context;

    gen.asm.mov(ctx.scratch1_32, dword_ptr(ctx.vip))?;
    gen.asm.add(ctx.vip, 4_i32)?;
    gen.vpush(ctx.scratch1)?;

    DispatcherGen::append_dispatch_logic(gen.asm, gen.arch)?;
    let end = gen.asm.instructions().len();
    Ok((start, end))
}

// ========== VPushImm64: 从字节码读取 64 位立即数压栈 ==========

pub fn gen_vpush_imm64(gen: &mut HandlerGenerator) -> Result<(usize, usize), IcedError> {
    let start = gen.asm.instructions().len();
    let ctx = &gen.arch.context;

    // 直接读取 64 位立即数
    gen.asm.mov(ctx.scratch1, qword_ptr(ctx.vip))?;
    gen.asm.add(ctx.vip, 8_i32)?;
    gen.vpush(ctx.scratch1)?;

    DispatcherGen::append_dispatch_logic(gen.asm, gen.arch)?;
    let end = gen.asm.instructions().len();
    Ok((start, end))
}

// ========== VPushReg: 将原生寄存器（从 Context）压入 VM 栈 ==========

pub fn gen_vpush_reg(gen: &mut HandlerGenerator) -> Result<(usize, usize), IcedError> {
    let start = gen.asm.instructions().len();
    let ctx = &gen.arch.context;

    // 读取操作数 (寄存器偏移) 到 scratch1_32
    gen.asm.movzx(ctx.scratch1_32, byte_ptr(ctx.vip))?;
    gen.asm.add(ctx.vip, 1_i32)?;

    // 计算实际保存地址: save_area_va + 40 + (index * 8)
    gen.asm.mov(ctx.scratch2, gen.save_area_va)?;
    gen.asm.add(ctx.scratch2, 40_i32)?;
    gen.asm.shl(ctx.scratch1, 3_i32)?; // 索引 × 8 (每个 u64 占 8 字节)
    gen.asm.add(ctx.scratch2, ctx.scratch1)?; // scratch2 = &Context[index]

    // 读取寄存器原始值
    gen.asm.mov(ctx.scratch1, qword_ptr(ctx.scratch2))?;
    // 压入虚拟栈
    gen.vpush(ctx.scratch1)?;

    DispatcherGen::append_dispatch_logic(gen.asm, gen.arch)?;
    let end = gen.asm.instructions().len();
    Ok((start, end))
}

// ========== VPopReg: 从 VM 栈弹出值到原生寄存器（Context） ==========

pub fn gen_vpop_reg(gen: &mut HandlerGenerator) -> Result<(usize, usize), IcedError> {
    let start = gen.asm.instructions().len();
    let ctx = &gen.arch.context;

    // 读取操作数 (寄存器偏移) 到 scratch1_32
    gen.asm.movzx(ctx.scratch1_32, byte_ptr(ctx.vip))?;
    gen.asm.add(ctx.vip, 1_i32)?;

    // 计算实际保存地址: save_area_va + 40 + (index * 8)
    gen.asm.mov(ctx.scratch2, gen.save_area_va)?;
    gen.asm.add(ctx.scratch2, 40_i32)?;
    gen.asm.shl(ctx.scratch1, 3_i32)?; // 索引 × 8 (每个 u64 占 8 字节)
    gen.asm.add(ctx.scratch1, ctx.scratch2)?; // scratch1 = &Context[index]

    // 从虚拟栈弹出值
    gen.vpop(ctx.scratch2)?;
    
    // 写回 Context
    gen.asm.mov(qword_ptr(ctx.scratch1), ctx.scratch2)?;

    DispatcherGen::append_dispatch_logic(gen.asm, gen.arch)?;
    let end = gen.asm.instructions().len();
    Ok((start, end))
}
