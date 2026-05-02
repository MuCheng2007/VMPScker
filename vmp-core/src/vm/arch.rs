//! VM 高级架构定义
//!
//! 定义高级版虚拟机的静态结构，包含：
//! - 虚拟寄存器与真实硬件寄存器的乱序映射 (含 VSP, VIP, VJMP, VCRYPT)
//! - VMOpcode 乱序映射
//! - 字节码加密流水线配置

use iced_x86::Register;
use rand::seq::SliceRandom;
use rand::Rng;
use std::collections::HashMap;

/// 高级版 VM 的核心操作码
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VMOpcode {
    // 基础操作
    PushReg,
    PopReg,
    PushImm32,
    PushImm64,
    
    // 内存操作 [NEW]
    ReadMem8,
    ReadMem16,
    ReadMem32,
    ReadMem64,
    WriteMem8,
    WriteMem16,
    WriteMem32,
    WriteMem64,

    // 算术与逻辑运算 (原生 EFLAGS 同步)
    Add,
    Sub,
    Nor,
    Nand,
    Xor,
    And,  // [NEW]
    Or,   // [NEW]
    Not,  // [NEW]
    Neg,  // [NEW]

    // 位移操作 [NEW]
    Shl,
    Shr,
    Sar,
    Rol,
    Ror,
    
    // 控制流
    Jmp,
    Jcc,  // [NEW]
    
    // 栈操作 [NEW]
    Dup,

    // 上下文操作
    VmExit,
}

impl VMOpcode {
    /// 获取所有支持的操作码列表
    pub fn all() -> Vec<VMOpcode> {
        vec![
            VMOpcode::PushReg, VMOpcode::PopReg, VMOpcode::PushImm32, VMOpcode::PushImm64,
            VMOpcode::ReadMem8, VMOpcode::ReadMem16, VMOpcode::ReadMem32, VMOpcode::ReadMem64,
            VMOpcode::WriteMem8, VMOpcode::WriteMem16, VMOpcode::WriteMem32, VMOpcode::WriteMem64,
            VMOpcode::Add, VMOpcode::Sub, VMOpcode::Nor, VMOpcode::Nand, VMOpcode::Xor,
            VMOpcode::And, VMOpcode::Or, VMOpcode::Not, VMOpcode::Neg,
            VMOpcode::Shl, VMOpcode::Shr, VMOpcode::Sar, VMOpcode::Rol, VMOpcode::Ror,
            VMOpcode::Jmp, VMOpcode::Jcc, VMOpcode::Dup, VMOpcode::VmExit,
        ]
    }
}

/// 高级版 VM 的虚拟寄存器定义
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VMRegister {
    // 通用寄存器 (0-15)
    R0, R1, R2, R3, R4, R5, R6, R7,
    R8, R9, R10, R11, R12, R13, R14, R15,
    
    // ====== 高级版四大核心特殊寄存器 ======
    
    /// VSP (Virtual Stack Pointer): 虚拟栈指针
    /// 对应 C++ 的 `stack_registr_`。在 CheckStack 机制中，VSP 受 RSP 的保护。
    VSP,
    
    /// VIP (Virtual Instruction Pointer): 虚拟指令指针
    /// 对应 C++ 的 `pcode_registr_`。指向已加密的字节码流。
    VIP,
    
    /// VJMP (Virtual Jump Base): 动态分发基址/偏移寄存器
    /// 对应 C++ 的 `jmp_registr_`。Threaded Code 的灵魂，每个 Handler 末尾使用它进行动态跳转。
    VJMP,
    
    /// VCRYPT (Virtual Crypt Key): 流解密密钥寄存器
    /// 对应 C++ 的 `crypt_registr_`。用于在获取下一个 Opcode 或操作数时进行解密计算。
    VCRYPT,
}

impl VMRegister {
    pub fn all_general() -> Vec<VMRegister> {
        vec![
            VMRegister::R0, VMRegister::R1, VMRegister::R2, VMRegister::R3,
            VMRegister::R4, VMRegister::R5, VMRegister::R6, VMRegister::R7,
            VMRegister::R8, VMRegister::R9, VMRegister::R10, VMRegister::R11,
            VMRegister::R12, VMRegister::R13, VMRegister::R14, VMRegister::R15,
        ]
    }
}

/// 解密/加密算法类型 (对应 C++ 的 CryptCommandType)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptAlgorithm {
    Add,
    Sub,
    Xor,
    Rol,
    Ror,
    Not,
    Neg,
}

impl CryptAlgorithm {
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        let algos = [
            CryptAlgorithm::Add, CryptAlgorithm::Sub, CryptAlgorithm::Xor,
            CryptAlgorithm::Rol, CryptAlgorithm::Ror, CryptAlgorithm::Not, CryptAlgorithm::Neg,
        ];
        *algos.choose(rng).unwrap()
    }
}

/// 虚拟机架构配置表 (每个被保护的函数通常独享一份随机配置)
#[derive(Debug, Clone)]
pub struct ArchConfig {
    /// 虚拟操作码到随机 8-bit 字节的映射表
    pub opcode_mapping: HashMap<VMOpcode, u8>,
    /// 反向查找表 (用于调试或解释器生成)
    pub reverse_opcode_mapping: HashMap<u8, VMOpcode>,
    
    /// 虚拟寄存器到物理硬件寄存器 (iced_x86::Register) 的映射表
    pub register_mapping: HashMap<VMRegister, Register>,
    
    /// 初始流解密密钥
    pub initial_crypt_key: u64,
    /// 解密算法流水线组合 (例如: 先 XOR, 再 ROL, 再 ADD)
    pub crypt_sequence: Vec<CryptAlgorithm>,
}

impl ArchConfig {
    /// 随机生成一份全新的高级版 VM 架构配置
    pub fn new_random() -> Self {
        let mut rng = rand::thread_rng();
        
        // 1. 生成 Opcode 映射
        let mut opcode_mapping = HashMap::new();
        let mut reverse_opcode_mapping = HashMap::new();
        
        let mut available_bytes: Vec<u8> = (0..=255).collect();
        available_bytes.shuffle(&mut rng);
        
        for (i, opcode) in VMOpcode::all().into_iter().enumerate() {
            let rand_byte = available_bytes[i];
            opcode_mapping.insert(opcode, rand_byte);
            reverse_opcode_mapping.insert(rand_byte, opcode);
        }
        
        // 2. 生成物理寄存器映射 (x64 架构下有 16 个通用寄存器可用)
        // 排除 RSP (因为 RSP 作为原生栈指针需要一直保留并随 VSP 变动而扩张)
        let mut available_phys_regs = vec![
            Register::RAX, Register::RBX, Register::RCX, Register::RDX,
            Register::RBP, Register::RSI, Register::RDI, 
            Register::R8, Register::R9, Register::R10, Register::R11,
            Register::R12, Register::R13, Register::R14, Register::R15,
        ];
        available_phys_regs.shuffle(&mut rng);
        
        let mut register_mapping = HashMap::new();
        
        // 优先分配四大特殊寄存器 (这是 Advanced VM 的特征)
        register_mapping.insert(VMRegister::VSP, available_phys_regs.pop().unwrap());
        register_mapping.insert(VMRegister::VIP, available_phys_regs.pop().unwrap());
        register_mapping.insert(VMRegister::VJMP, available_phys_regs.pop().unwrap());
        register_mapping.insert(VMRegister::VCRYPT, available_phys_regs.pop().unwrap());
        
        // 分配普通寄存器映射 (如果物理寄存器不够，则映射到虚拟栈的固定槽位，这里为简化起见，只用部分 Rx 或假设我们有足够的存储)
        // 在真实 x64 中，15 个寄存器 - 4 个特殊 = 11 个。其余 5 个需要放在 NativeVMContext 内存中。
        // 为了目前汇编生成的简便，我们将部分 Rx 映射到物理，剩下的暂时设为 None 或内存引用（这里暂时用剩下的填充部分）。
        let general_regs = VMRegister::all_general();
        for (i, v_reg) in general_regs.into_iter().enumerate() {
            if let Some(p_reg) = available_phys_regs.pop() {
                register_mapping.insert(v_reg, p_reg);
            }
            // 剩下的寄存器在实际实现中将映射到线程局部存储或堆栈固定偏移。
        }
        
        // 3. 生成密码学配置
        let initial_crypt_key = rng.gen::<u64>();
        let sequence_len = rng.gen_range(1..=3); // 1到3层组合加密
        let mut crypt_sequence = Vec::new();
        for _ in 0..sequence_len {
            crypt_sequence.push(CryptAlgorithm::random(&mut rng));
        }

        Self {
            opcode_mapping,
            reverse_opcode_mapping,
            register_mapping,
            initial_crypt_key,
            crypt_sequence,
        }
    }
}
