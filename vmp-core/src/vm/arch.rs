//! 虚拟机架构与上下文配置模块
//! 负责物理寄存器轮转、操作码乱序和指令解密链生成

use super::opcode::VmOpcode;
use iced_x86::Register;
use iced_x86::code_asm::*;
use iced_x86::IcedError;
use rand::seq::SliceRandom;
use std::collections::HashMap;

/// 密码学算子
#[derive(Debug, Clone, Copy)]
pub enum CryptoOp {
    Xor,
    Add,
    Sub,
    Rol,
    Ror,
    Not,
    Neg,
}

/// 解密链/加密链
#[derive(Debug, Clone)]
pub struct CryptoChain {
    pub ops: Vec<CryptoOp>,
}

impl CryptoChain {
    /// 生成随机算子链 (长度 2-4)
    pub fn generate_random() -> Self {
        let mut rng = rand::thread_rng();
        let pool = [
            CryptoOp::Xor, CryptoOp::Add, CryptoOp::Sub, 
            CryptoOp::Rol, CryptoOp::Ror, CryptoOp::Not, CryptoOp::Neg
        ];
        let len = rand::random::<usize>() % 3 + 2; // 2 to 4 operations
        let mut ops = Vec::new();
        for _ in 0..len {
            ops.push(*pool.choose(&mut rng).unwrap());
        }
        Self { ops }
    }

    /// 在编译期加密字节码
    /// 解密函数 (emit_asm_decrypt) 按 ops 逆序 + 逆操作执行解密
    /// 所以加密函数按 ops 正序 + 原始操作执行加密
    pub fn encrypt(&self, mut value: u32, key: u32) -> u32 {
        for op in self.ops.iter() {
            value = match op {
                CryptoOp::Xor => value ^ key,
                CryptoOp::Add => value.wrapping_add(key),
                CryptoOp::Sub => value.wrapping_sub(key),
                CryptoOp::Rol => value.rotate_left(1),
                CryptoOp::Ror => value.rotate_right(1),
                CryptoOp::Not => !value,
                CryptoOp::Neg => value.wrapping_neg(),
            };
        }
        value
    }

    /// 运行期：生成解密汇编代码 (注意解密是加密的逆运算)
    /// target_reg: 存放刚刚从 [VIP] 读取出来的加密操作码
    pub fn emit_asm_decrypt(
        &self,
        asm: &mut CodeAssembler,
        ctx: &VmRegContext,
        target_reg: AsmRegister32
    ) -> Result<(), IcedError> {
        // 解密是加密的逆运算，需要反向遍历操作符，并执行其相反操作
        for op in self.ops.iter().rev() {
            match op {
                CryptoOp::Xor => asm.xor(target_reg, ctx.vkey_32)?,
                CryptoOp::Add => asm.sub(target_reg, ctx.vkey_32)?, // Encrypt是Add，Decrypt就是Sub
                CryptoOp::Sub => asm.add(target_reg, ctx.vkey_32)?,
                CryptoOp::Not => asm.not(target_reg)?,
                CryptoOp::Neg => asm.neg(target_reg)?,
                // 循环移位：使用立即数 (key % 32)
                // 注意：解密是加密的逆运算，所以 Rol 的解密是 Ror，Ror 的解密是 Rol
                // 由于无法在汇编时获取 vkey_32 的值，我们使用固定的移位值
                CryptoOp::Rol => {
                    // 加密是 Rol，解密就是 Ror
                    // 使用固定的移位值 1 作为简化实现
                    asm.ror(target_reg, 1_i32)?;
                }
                CryptoOp::Ror => {
                    // 加密是 Ror，解密就是 Rol
                    // 使用固定的移位值 1 作为简化实现
                    asm.rol(target_reg, 1_i32)?;
                }
            };
        }
        Ok(())
    }
}

/// 虚拟机控制上下文 (物理寄存器轮转)
/// 使用 AsmRegister64 以便与 CodeAssembler 兼容
#[derive(Debug, Clone, Copy)]
pub struct VmRegContext {
    pub vip: AsmRegister64,       // 虚拟指令指针 (Virtual IP)
    pub vsp: AsmRegister64,       // 虚拟堆栈指针 (Virtual SP)
    pub vkey: AsmRegister64,      // 滚动解密密钥 (64位)
    pub vkey_32: AsmRegister32,   // 滚动解密密钥 (32位视图)
    pub table: AsmRegister64,     // Handler Table 基址
    pub scratch1: AsmRegister64,  // 临时操作寄存器1
    pub scratch1_32: AsmRegister32, // 临时操作寄存器1 (32位视图)
    pub scratch2: AsmRegister64,  // 临时操作寄存器2
    pub vbase: AsmRegister64,     // 字节码基址 (初始 VIP 值)
}

impl VmRegContext {
    /// 从 iced_x86::Register 创建完整的寄存器上下文
    fn from_register(reg: Register) -> (AsmRegister64, AsmRegister32) {
        match reg {
            Register::RAX => (rax, eax),
            Register::RCX => (rcx, ecx),
            Register::RDX => (rdx, edx),
            Register::RBX => (rbx, ebx),
            Register::RSI => (rsi, esi),
            Register::RDI => (rdi, edi),
            Register::R8 => (r8, r8d),
            Register::R9 => (r9, r9d),
            Register::R10 => (r10, r10d),
            Register::R11 => (r11, r11d),
            Register::R12 => (r12, r12d),
            Register::R13 => (r13, r13d),
            Register::R14 => (r14, r14d),
            Register::R15 => (r15, r15d),
            _ => (rax, eax), // 默认回退
        }
    }
}

/// 全局架构配置 (每个被保护的函数或文件生成一份独一无二的配置)
#[derive(Debug, Clone)]
pub struct ArchConfig {
    pub context: VmRegContext,
    pub opcode_map: HashMap<VmOpcode, u8>,  // VmOpcode -> 随机混淆的单字节字节码
    pub reverse_map: HashMap<u8, VmOpcode>, // 用于生成器的反向映射
    pub opcode_cryptor: CryptoChain,        // 针对操作码的解密链
    pub initial_crypt_key: u32,             // 进入 VM 时的初始 Key
}

impl ArchConfig {
    /// 实例化一个完全随机的架构
    pub fn new_random() -> Self {
        let mut rng = rand::thread_rng();
        
        // 1. 寄存器轮转 (排除 RSP 和 RBP，以备外部调用或栈溢出保护)
        let mut available_regs = vec![
            Register::RAX, Register::RCX, Register::RDX, Register::RBX,
            Register::RSI, Register::RDI, Register::R8, Register::R9,
            Register::R10, Register::R11, Register::R12, Register::R13,
            Register::R14, Register::R15,
        ];
        available_regs.shuffle(&mut rng);

        let (vip, _) = VmRegContext::from_register(available_regs[0]);
        let (vsp, _) = VmRegContext::from_register(available_regs[1]);
        let (vkey, vkey_32) = VmRegContext::from_register(available_regs[2]);
        let (table, _) = VmRegContext::from_register(available_regs[3]);
        let (scratch1, scratch1_32) = VmRegContext::from_register(available_regs[4]);
        let (scratch2, _) = VmRegContext::from_register(available_regs[5]);
        let (vbase, _) = VmRegContext::from_register(available_regs[6]);

        let context = VmRegContext {
            vip,
            vsp,
            vkey,
            vkey_32,
            table,
            scratch1,
            scratch1_32,
            scratch2,
            vbase,
        };

        // 2. 随机生成 0-255 的 Opcode 字典
        let mut opcodes: Vec<u8> = (0..=255).collect();
        opcodes.shuffle(&mut rng);

        let mut opcode_map = HashMap::new();
        let mut reverse_map = HashMap::new();

        // 为核心指令分配乱序操作码 (必须包含所有 lowering 可能生成的指令)
        let core_ops = vec![
            VmOpcode::VNop, VmOpcode::VAdd, VmOpcode::VSub,
            VmOpcode::VXor, VmOpcode::VNand, VmOpcode::VNor,
            VmOpcode::VJmp(0), VmOpcode::VJcc(0, 0), VmOpcode::VCall(0), VmOpcode::VExit,
            VmOpcode::VPushImm32(0), VmOpcode::VPushImm64(0), VmOpcode::VPushReg(0), VmOpcode::VPopReg(0),
            VmOpcode::VReadMem(0), VmOpcode::VLabel(0),
        ];

        for (i, op) in core_ops.into_iter().enumerate() {
            opcode_map.insert(op.clone(), opcodes[i]);
            reverse_map.insert(opcodes[i], op);
        }

        Self {
            context,
            opcode_map,
            reverse_map,
            opcode_cryptor: CryptoChain::generate_random(),
            initial_crypt_key: rand::random(),
        }
    }
}
