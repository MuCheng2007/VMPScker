//! 线索化分发器 (Threaded Dispatcher)

use crate::vm::arch::ArchConfig;
use iced_x86::code_asm::*;
use iced_x86::IcedError;

pub struct DispatcherGen;

impl DispatcherGen {
    /// 向当前的汇编流中追加"获取-解密-跳转"逻辑
    pub fn append_dispatch_logic(
        asm: &mut CodeAssembler,
        arch: &ArchConfig,
    ) -> Result<(), IcedError> {
        let ctx = &arch.context;
        
        // 我们假设字节码中的 Opcode 是 32 位的 (为了抵抗爆破，VMP高级模式通常使用 32位 Opcode)
        let t_op_32 = ctx.scratch1_32;
        let t_op_64 = ctx.scratch1; // x86_64 下，对 r32 赋值会自动零扩展到 r64

        // 1. Fetch: 读取加密的下一个 Opcode
        // mov scratch1_32, dword ptr [VIP]
        asm.mov(t_op_32, dword_ptr(ctx.vip))?;
        
        // 2. VIP += 4 (移动到下一条指令)
        asm.add(ctx.vip, 4_i32)?;

        // 3. Decrypt: 应用当前架构的密码链进行解密
        arch.opcode_cryptor.emit_asm_decrypt(asm, ctx, t_op_32)?;

        // 4. Rolling Key: 更新滚动密钥
        // VKEY = VKEY + 解密后的明文 (也可以配置成 XOR)
        asm.add(ctx.vkey_32, t_op_32)?;

        // 5. Indirect Jump: 查表并跳转
        // 明文的 Opcode 实际上就是 Handler Table 的索引
        // jmp qword ptr [Table + scratch1 * 8]
        asm.jmp(qword_ptr(ctx.table + t_op_64 * 8))?;

        Ok(())
    }
}
