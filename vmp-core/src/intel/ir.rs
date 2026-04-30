//! 中间表示（IR）模块
//!
//! 定义 VMProtect 特定的 IR 指令类型，用于虚拟化保护。

use std::fmt;

/// IR 寄存器
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IrRegister {
    // 8-bit registers
    Al, Cl, Dl, Bl, Ah, Ch, Dh, Bh,
    R8b, R9b, R10b, R11b, R12b, R13b, R14b, R15b,
    
    // 16-bit registers
    Ax, Cx, Dx, Bx, Sp, Bp, Si, Di,
    R8w, R9w, R10w, R11w, R12w, R13w, R14w, R15w,
    
    // 32-bit registers
    Eax, Ecx, Edx, Ebx, Esp, Ebp, Esi, Edi,
    R8d, R9d, R10d, R11d, R12d, R13d, R14d, R15d,
    
    // 64-bit registers
    Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi,
    R8, R9, R10, R11, R12, R13, R14, R15,
    
    // Segment registers
    Es, Cs, Ss, Ds, Fs, Gs,
    
    // RIP (instruction pointer)
    Rip,
    
    // EFLAGS/RFLAGS
    Eflags,
    Rflags,
}

impl IrRegister {
    /// 获取寄存器大小（位）
    pub fn size_bits(&self) -> u32 {
        match self {
            IrRegister::Al | IrRegister::Cl | IrRegister::Dl | IrRegister::Bl |
            IrRegister::Ah | IrRegister::Ch | IrRegister::Dh | IrRegister::Bh |
            IrRegister::R8b | IrRegister::R9b | IrRegister::R10b | IrRegister::R11b |
            IrRegister::R12b | IrRegister::R13b | IrRegister::R14b | IrRegister::R15b => 8,
            
            IrRegister::Ax | IrRegister::Cx | IrRegister::Dx | IrRegister::Bx |
            IrRegister::Sp | IrRegister::Bp | IrRegister::Si | IrRegister::Di |
            IrRegister::R8w | IrRegister::R9w | IrRegister::R10w | IrRegister::R11w |
            IrRegister::R12w | IrRegister::R13w | IrRegister::R14w | IrRegister::R15w => 16,
            
            IrRegister::Eax | IrRegister::Ecx | IrRegister::Edx | IrRegister::Ebx |
            IrRegister::Esp | IrRegister::Ebp | IrRegister::Esi | IrRegister::Edi |
            IrRegister::R8d | IrRegister::R9d | IrRegister::R10d | IrRegister::R11d |
            IrRegister::R12d | IrRegister::R13d | IrRegister::R14d | IrRegister::R15d => 32,
            
            IrRegister::Rax | IrRegister::Rcx | IrRegister::Rdx | IrRegister::Rbx |
            IrRegister::Rsp | IrRegister::Rbp | IrRegister::Rsi | IrRegister::Rdi |
            IrRegister::R8 | IrRegister::R9 | IrRegister::R10 | IrRegister::R11 |
            IrRegister::R12 | IrRegister::R13 | IrRegister::R14 | IrRegister::R15 |
            IrRegister::Rip => 64,
            
            IrRegister::Es | IrRegister::Cs | IrRegister::Ss |
            IrRegister::Ds | IrRegister::Fs | IrRegister::Gs => 16,
            
            IrRegister::Eflags => 32,
            IrRegister::Rflags => 64,
        }
    }

    /// 获取寄存器大小（字节）
    pub fn size_bytes(&self) -> u32 {
        self.size_bits() / 8
    }

    /// 获取对应的 64 位寄存器
    pub fn to_64bit(&self) -> Option<IrRegister> {
        match self {
            IrRegister::Al | IrRegister::Ax | IrRegister::Eax | IrRegister::Rax => Some(IrRegister::Rax),
            IrRegister::Cl | IrRegister::Cx | IrRegister::Ecx | IrRegister::Rcx => Some(IrRegister::Rcx),
            IrRegister::Dl | IrRegister::Dx | IrRegister::Edx | IrRegister::Rdx => Some(IrRegister::Rdx),
            IrRegister::Bl | IrRegister::Bx | IrRegister::Ebx | IrRegister::Rbx => Some(IrRegister::Rbx),
            IrRegister::Sp | IrRegister::Esp | IrRegister::Rsp => Some(IrRegister::Rsp),
            IrRegister::Bp | IrRegister::Ebp | IrRegister::Rbp => Some(IrRegister::Rbp),
            IrRegister::Si | IrRegister::Esi | IrRegister::Rsi => Some(IrRegister::Rsi),
            IrRegister::Di | IrRegister::Edi | IrRegister::Rdi => Some(IrRegister::Rdi),
            IrRegister::R8b | IrRegister::R8w | IrRegister::R8d | IrRegister::R8 => Some(IrRegister::R8),
            IrRegister::R9b | IrRegister::R9w | IrRegister::R9d | IrRegister::R9 => Some(IrRegister::R9),
            IrRegister::R10b | IrRegister::R10w | IrRegister::R10d | IrRegister::R10 => Some(IrRegister::R10),
            IrRegister::R11b | IrRegister::R11w | IrRegister::R11d | IrRegister::R11 => Some(IrRegister::R11),
            IrRegister::R12b | IrRegister::R12w | IrRegister::R12d | IrRegister::R12 => Some(IrRegister::R12),
            IrRegister::R13b | IrRegister::R13w | IrRegister::R13d | IrRegister::R13 => Some(IrRegister::R13),
            IrRegister::R14b | IrRegister::R14w | IrRegister::R14d | IrRegister::R14 => Some(IrRegister::R14),
            IrRegister::R15b | IrRegister::R15w | IrRegister::R15d | IrRegister::R15 => Some(IrRegister::R15),
            IrRegister::Eflags | IrRegister::Rflags => Some(IrRegister::Rflags),
            _ => None,
        }
    }

    /// 是否是通用寄存器
    pub fn is_gpr(&self) -> bool {
        matches!(
            self,
            IrRegister::Al | IrRegister::Cl | IrRegister::Dl | IrRegister::Bl |
            IrRegister::Ah | IrRegister::Ch | IrRegister::Dh | IrRegister::Bh |
            IrRegister::R8b | IrRegister::R9b | IrRegister::R10b | IrRegister::R11b |
            IrRegister::R12b | IrRegister::R13b | IrRegister::R14b | IrRegister::R15b |
            IrRegister::Ax | IrRegister::Cx | IrRegister::Dx | IrRegister::Bx |
            IrRegister::Sp | IrRegister::Bp | IrRegister::Si | IrRegister::Di |
            IrRegister::R8w | IrRegister::R9w | IrRegister::R10w | IrRegister::R11w |
            IrRegister::R12w | IrRegister::R13w | IrRegister::R14w | IrRegister::R15w |
            IrRegister::Eax | IrRegister::Ecx | IrRegister::Edx | IrRegister::Ebx |
            IrRegister::Esp | IrRegister::Ebp | IrRegister::Esi | IrRegister::Edi |
            IrRegister::R8d | IrRegister::R9d | IrRegister::R10d | IrRegister::R11d |
            IrRegister::R12d | IrRegister::R13d | IrRegister::R14d | IrRegister::R15d |
            IrRegister::Rax | IrRegister::Rcx | IrRegister::Rdx | IrRegister::Rbx |
            IrRegister::Rsp | IrRegister::Rbp | IrRegister::Rsi | IrRegister::Rdi |
            IrRegister::R8 | IrRegister::R9 | IrRegister::R10 | IrRegister::R11 |
            IrRegister::R12 | IrRegister::R13 | IrRegister::R14 | IrRegister::R15
        )
    }

    /// 是否是段寄存器
    pub fn is_segment(&self) -> bool {
        matches!(
            self,
            IrRegister::Es | IrRegister::Cs | IrRegister::Ss |
            IrRegister::Ds | IrRegister::Fs | IrRegister::Gs
        )
    }
}

impl fmt::Display for IrRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self).map(|_| ()).map_err(|_| fmt::Error)
    }
}

/// IR 立即数
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrImmediate {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
}

impl IrImmediate {
    /// 获取立即数值（作为 u64）
    pub fn as_u64(&self) -> u64 {
        match self {
            IrImmediate::U8(v) => *v as u64,
            IrImmediate::U16(v) => *v as u64,
            IrImmediate::U32(v) => *v as u64,
            IrImmediate::U64(v) => *v,
            IrImmediate::I8(v) => *v as u64,
            IrImmediate::I16(v) => *v as u64,
            IrImmediate::I32(v) => *v as u64,
            IrImmediate::I64(v) => *v as u64,
        }
    }

    /// 获取立即数值（作为 i64）
    pub fn as_i64(&self) -> i64 {
        match self {
            IrImmediate::U8(v) => *v as i64,
            IrImmediate::U16(v) => *v as i64,
            IrImmediate::U32(v) => *v as i64,
            IrImmediate::U64(v) => *v as i64,
            IrImmediate::I8(v) => *v as i64,
            IrImmediate::I16(v) => *v as i64,
            IrImmediate::I32(v) => *v as i64,
            IrImmediate::I64(v) => *v,
        }
    }

    /// 获取大小（位）
    pub fn size_bits(&self) -> u32 {
        match self {
            IrImmediate::U8(_) | IrImmediate::I8(_) => 8,
            IrImmediate::U16(_) | IrImmediate::I16(_) => 16,
            IrImmediate::U32(_) | IrImmediate::I32(_) => 32,
            IrImmediate::U64(_) | IrImmediate::I64(_) => 64,
        }
    }
}

impl From<u8> for IrImmediate {
    fn from(v: u8) -> Self {
        IrImmediate::U8(v)
    }
}

impl From<u16> for IrImmediate {
    fn from(v: u16) -> Self {
        IrImmediate::U16(v)
    }
}

impl From<u32> for IrImmediate {
    fn from(v: u32) -> Self {
        IrImmediate::U32(v)
    }
}

impl From<u64> for IrImmediate {
    fn from(v: u64) -> Self {
        IrImmediate::U64(v)
    }
}

impl From<i8> for IrImmediate {
    fn from(v: i8) -> Self {
        IrImmediate::I8(v)
    }
}

impl From<i16> for IrImmediate {
    fn from(v: i16) -> Self {
        IrImmediate::I16(v)
    }
}

impl From<i32> for IrImmediate {
    fn from(v: i32) -> Self {
        IrImmediate::I32(v)
    }
}

impl From<i64> for IrImmediate {
    fn from(v: i64) -> Self {
        IrImmediate::I64(v)
    }
}

/// IR 内存操作数
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrMemoryOperand {
    /// 段寄存器（可选）
    pub segment: Option<IrRegister>,
    /// 基址寄存器（可选）
    pub base: Option<IrRegister>,
    /// 索引寄存器（可选）
    pub index: Option<IrRegister>,
    /// 缩放因子（1, 2, 4, 8）
    pub scale: u32,
    /// 位移
    pub displacement: i64,
    /// 访问大小（位）
    pub size_bits: u32,
}

impl IrMemoryOperand {
    /// 创建简单的内存操作数 [base]
    pub fn new_base(base: IrRegister, size_bits: u32) -> Self {
        Self {
            segment: None,
            base: Some(base),
            index: None,
            scale: 1,
            displacement: 0,
            size_bits,
        }
    }

    /// 创建带位移的内存操作数 [base + disp]
    pub fn new_base_disp(base: IrRegister, displacement: i64, size_bits: u32) -> Self {
        Self {
            segment: None,
            base: Some(base),
            index: None,
            scale: 1,
            displacement,
            size_bits,
        }
    }

    /// 创建完整内存操作数 [base + index * scale + disp]
    pub fn new_complex(
        base: Option<IrRegister>,
        index: Option<IrRegister>,
        scale: u32,
        displacement: i64,
        size_bits: u32,
    ) -> Self {
        Self {
            segment: None,
            base,
            index,
            scale,
            displacement,
            size_bits,
        }
    }

    /// 创建 RIP 相对寻址 [rip + disp]
    pub fn new_rip_relative(displacement: i64, size_bits: u32) -> Self {
        Self {
            segment: None,
            base: Some(IrRegister::Rip),
            index: None,
            scale: 1,
            displacement,
            size_bits,
        }
    }

    /// 获取访问大小（字节）
    pub fn size_bytes(&self) -> u32 {
        self.size_bits / 8
    }

    /// 是否是 RIP 相对寻址
    pub fn is_rip_relative(&self) -> bool {
        matches!(self.base, Some(IrRegister::Rip))
    }

    /// 是否是简单基址寻址
    pub fn is_simple_base(&self) -> bool {
        self.base.is_some() && self.index.is_none() && self.displacement == 0
    }
}

impl Default for IrMemoryOperand {
    fn default() -> Self {
        Self {
            segment: None,
            base: None,
            index: None,
            scale: 1,
            displacement: 0,
            size_bits: 64,
        }
    }
}

/// IR 操作数
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrOperand {
    /// 寄存器
    Register(IrRegister),
    /// 立即数
    Immediate(IrImmediate),
    /// 内存操作数
    Memory(IrMemoryOperand),
}

impl IrOperand {
    /// 创建寄存器操作数
    pub fn reg(reg: IrRegister) -> Self {
        IrOperand::Register(reg)
    }

    /// 创建立即数操作数
    pub fn imm<T: Into<IrImmediate>>(imm: T) -> Self {
        IrOperand::Immediate(imm.into())
    }

    /// 创建内存操作数
    pub fn mem(mem: IrMemoryOperand) -> Self {
        IrOperand::Memory(mem)
    }

    /// 是否是寄存器操作数
    pub fn is_register(&self) -> bool {
        matches!(self, IrOperand::Register(_))
    }

    /// 是否是立即数操作数
    pub fn is_immediate(&self) -> bool {
        matches!(self, IrOperand::Immediate(_))
    }

    /// 是否是内存操作数
    pub fn is_memory(&self) -> bool {
        matches!(self, IrOperand::Memory(_))
    }

    /// 获取操作数大小（位）
    pub fn size_bits(&self) -> u32 {
        match self {
            IrOperand::Register(r) => r.size_bits(),
            IrOperand::Immediate(i) => i.size_bits(),
            IrOperand::Memory(m) => m.size_bits,
        }
    }

    /// 获取操作数大小（字节）
    pub fn size_bytes(&self) -> u32 {
        self.size_bits() / 8
    }
}

impl From<IrRegister> for IrOperand {
    fn from(reg: IrRegister) -> Self {
        IrOperand::Register(reg)
    }
}

impl From<IrImmediate> for IrOperand {
    fn from(imm: IrImmediate) -> Self {
        IrOperand::Immediate(imm)
    }
}

impl From<IrMemoryOperand> for IrOperand {
    fn from(mem: IrMemoryOperand) -> Self {
        IrOperand::Memory(mem)
    }
}

impl From<u8> for IrOperand {
    fn from(v: u8) -> Self {
        IrOperand::Immediate(v.into())
    }
}

impl From<u16> for IrOperand {
    fn from(v: u16) -> Self {
        IrOperand::Immediate(v.into())
    }
}

impl From<u32> for IrOperand {
    fn from(v: u32) -> Self {
        IrOperand::Immediate(v.into())
    }
}

impl From<u64> for IrOperand {
    fn from(v: u64) -> Self {
        IrOperand::Immediate(v.into())
    }
}

impl From<i8> for IrOperand {
    fn from(v: i8) -> Self {
        IrOperand::Immediate(v.into())
    }
}

impl From<i16> for IrOperand {
    fn from(v: i16) -> Self {
        IrOperand::Immediate(v.into())
    }
}

impl From<i32> for IrOperand {
    fn from(v: i32) -> Self {
        IrOperand::Immediate(v.into())
    }
}

impl From<i64> for IrOperand {
    fn from(v: i64) -> Self {
        IrOperand::Immediate(v.into())
    }
}

/// IR 指令
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrInstruction {
    // 数据传输指令
    /// 移动操作数
    Mov { dst: IrOperand, src: IrOperand },
    /// 加载有效地址
    Lea { dst: IrRegister, src: IrMemoryOperand },
    /// 压栈
    Push { src: IrOperand },
    /// 出栈
    Pop { dst: IrOperand },
    /// 交换
    Xchg { op1: IrOperand, op2: IrOperand },
    /// 条件移动
    Cmov { condition: IrCondition, dst: IrRegister, src: IrOperand },

    // 算术指令
    /// 加法
    Add { dst: IrOperand, src: IrOperand },
    /// 减法
    Sub { dst: IrOperand, src: IrOperand },
    /// 乘法
    Mul { src: IrOperand },
    /// 有符号乘法
    Imul { dst: Option<IrOperand>, src1: IrOperand, src2: Option<IrOperand> },
    /// 除法
    Div { src: IrOperand },
    /// 有符号除法
    Idiv { src: IrOperand },
    /// 自增
    Inc { op: IrOperand },
    /// 自减
    Dec { op: IrOperand },
    /// 取负
    Neg { op: IrOperand },
    /// 比较
    Cmp { op1: IrOperand, op2: IrOperand },

    // 逻辑指令
    /// 与
    And { dst: IrOperand, src: IrOperand },
    /// 或
    Or { dst: IrOperand, src: IrOperand },
    /// 异或
    Xor { dst: IrOperand, src: IrOperand },
    /// 非
    Not { op: IrOperand },
    /// 测试
    Test { op1: IrOperand, op2: IrOperand },

    // 移位指令
    /// 逻辑左移
    Shl { dst: IrOperand, count: IrOperand },
    /// 逻辑右移
    Shr { dst: IrOperand, count: IrOperand },
    /// 算术右移
    Sar { dst: IrOperand, count: IrOperand },
    /// 循环左移
    Rol { dst: IrOperand, count: IrOperand },
    /// 循环右移
    Ror { dst: IrOperand, count: IrOperand },

    // 位操作指令
    /// 位测试
    Bt { base: IrOperand, offset: IrOperand },
    /// 位测试并置位
    Bts { base: IrOperand, offset: IrOperand },
    /// 位测试并复位
    Btr { base: IrOperand, offset: IrOperand },
    /// 位扫描正向
    Bsf { dst: IrRegister, src: IrOperand },
    /// 位扫描反向
    Bsr { dst: IrRegister, src: IrOperand },

    // 控制流指令
    /// 无条件跳转
    Jmp { target: IrJumpTarget },
    /// 条件跳转
    Jcc { condition: IrCondition, target: IrJumpTarget },
    /// 调用
    Call { target: IrJumpTarget },
    /// 返回
    Ret { pop_bytes: Option<u16> },
    /// 系统调用
    Syscall,
    /// 系统返回
    Sysret,
    /// 中断
    Int { vector: u8 },

    // 标志操作
    /// 清除方向标志
    Cld,
    /// 设置方向标志
    Std,
    /// 清除进位标志
    Clc,
    /// 设置进位标志
    Stc,
    /// 压入标志
    Pushf,
    /// 弹出标志
    Popf,
    /// 加载标志到 AH
    Lahf,
    /// 存储 AH 到标志
    Sahf,

    // 无操作
    Nop,
    /// 断点
    Int3,
    /// 未定义指令
    Ud2,

    // 伪指令
    /// 标签
    Label { id: u32 },
    /// 注释
    Comment { text: String },
}

/// 跳转目标
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrJumpTarget {
    /// 直接地址
    Direct(u64),
    /// 相对偏移
    Relative(i64),
    /// 寄存器
    Register(IrRegister),
    /// 内存
    Memory(IrMemoryOperand),
    /// 标签引用
    Label(u32),
}

/// 条件码
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrCondition {
    /// 相等/零
    E,  // Equal / Zero
    /// 不等/非零
    Ne, // Not Equal / Not Zero
    /// 大于（有符号）
    G,  // Greater (signed)
    /// 大于等于（有符号）
    Ge, // Greater or Equal (signed)
    /// 小于（有符号）
    L,  // Less (signed)
    /// 小于等于（有符号）
    Le, // Less or Equal (signed)
    /// 高于（无符号）
    A,  // Above (unsigned)
    /// 高于等于（无符号）
    Ae, // Above or Equal (unsigned)
    /// 低于（无符号）
    B,  // Below (unsigned)
    /// 低于等于（无符号）
    Be, // Below or Equal (unsigned)
    /// 溢出
    O,  // Overflow
    /// 无溢出
    No, // No Overflow
    /// 符号
    S,  // Sign
    /// 无符号
    Ns, // No Sign
    /// 奇偶校验
    P,  // Parity
    /// 奇偶校验奇
    Np, // No Parity
    /// 计数器非零
    Cxnz, // CX/ECX/RCX Not Zero
}

impl IrInstruction {
    /// 是否是控制流指令
    pub fn is_control_flow(&self) -> bool {
        matches!(
            self,
            IrInstruction::Jmp { .. }
                | IrInstruction::Jcc { .. }
                | IrInstruction::Call { .. }
                | IrInstruction::Ret { .. }
                | IrInstruction::Syscall
                | IrInstruction::Sysret
                | IrInstruction::Int { .. }
        )
    }

    /// 是否是条件指令
    pub fn is_conditional(&self) -> bool {
        matches!(
            self,
            IrInstruction::Jcc { .. } | IrInstruction::Cmov { .. }
        )
    }

    /// 是否是跳转指令
    pub fn is_jump(&self) -> bool {
        matches!(self, IrInstruction::Jmp { .. } | IrInstruction::Jcc { .. })
    }

    /// 是否是调用指令
    pub fn is_call(&self) -> bool {
        matches!(self, IrInstruction::Call { .. })
    }

    /// 是否是返回指令
    pub fn is_return(&self) -> bool {
        matches!(self, IrInstruction::Ret { .. })
    }

    /// 获取目标操作数（如果有）
    pub fn destination_operand(&self) -> Option<IrOperand> {
        match self {
            IrInstruction::Mov { dst, .. } => Some(dst.clone()),
            IrInstruction::Lea { dst, .. } => Some(IrOperand::Register(dst.clone())),
            IrInstruction::Pop { dst } => Some(dst.clone()),
            IrInstruction::Add { dst, .. } => Some(dst.clone()),
            IrInstruction::Sub { dst, .. } => Some(dst.clone()),
            IrInstruction::Imul { dst, .. } => dst.clone(),
            IrInstruction::Inc { op } => Some(op.clone()),
            IrInstruction::Dec { op } => Some(op.clone()),
            IrInstruction::Neg { op } => Some(op.clone()),
            IrInstruction::And { dst, .. } => Some(dst.clone()),
            IrInstruction::Or { dst, .. } => Some(dst.clone()),
            IrInstruction::Xor { dst, .. } => Some(dst.clone()),
            IrInstruction::Not { op } => Some(op.clone()),
            IrInstruction::Shl { dst, .. } => Some(dst.clone()),
            IrInstruction::Shr { dst, .. } => Some(dst.clone()),
            IrInstruction::Sar { dst, .. } => Some(dst.clone()),
            IrInstruction::Rol { dst, .. } => Some(dst.clone()),
            IrInstruction::Ror { dst, .. } => Some(dst.clone()),
            IrInstruction::Bsf { dst, .. } => Some(IrOperand::Register(dst.clone())),
            IrInstruction::Bsr { dst, .. } => Some(IrOperand::Register(dst.clone())),
            IrInstruction::Cmov { dst, .. } => Some(IrOperand::Register(dst.clone())),
            IrInstruction::Xchg { op1, .. } => Some(op1.clone()),
            _ => None,
        }
    }

    /// 获取源操作数列表
    pub fn source_operands(&self) -> Vec<IrOperand> {
        match self {
            IrInstruction::Mov { src, .. } => vec![src.clone()],
            IrInstruction::Lea { .. } => vec![],
            IrInstruction::Push { src } => vec![src.clone()],
            IrInstruction::Add { src, .. } => vec![src.clone()],
            IrInstruction::Sub { src, .. } => vec![src.clone()],
            IrInstruction::Mul { src } => vec![src.clone()],
            IrInstruction::Imul { src1, src2, .. } => {
                let mut ops = vec![src1.clone()];
                if let Some(s2) = src2 {
                    ops.push(s2.clone());
                }
                ops
            }
            IrInstruction::Div { src } => vec![src.clone()],
            IrInstruction::Idiv { src } => vec![src.clone()],
            IrInstruction::Inc { .. } => vec![],
            IrInstruction::Dec { .. } => vec![],
            IrInstruction::Neg { .. } => vec![],
            IrInstruction::Cmp { op1, op2 } => vec![op1.clone(), op2.clone()],
            IrInstruction::And { src, .. } => vec![src.clone()],
            IrInstruction::Or { src, .. } => vec![src.clone()],
            IrInstruction::Xor { src, .. } => vec![src.clone()],
            IrInstruction::Not { .. } => vec![],
            IrInstruction::Test { op1, op2 } => vec![op1.clone(), op2.clone()],
            IrInstruction::Shl { count, .. } => vec![count.clone()],
            IrInstruction::Shr { count, .. } => vec![count.clone()],
            IrInstruction::Sar { count, .. } => vec![count.clone()],
            IrInstruction::Rol { count, .. } => vec![count.clone()],
            IrInstruction::Ror { count, .. } => vec![count.clone()],
            IrInstruction::Bt { base, offset } => vec![base.clone(), offset.clone()],
            IrInstruction::Bts { base, offset } => vec![base.clone(), offset.clone()],
            IrInstruction::Btr { base, offset } => vec![base.clone(), offset.clone()],
            IrInstruction::Bsf { src, .. } => vec![src.clone()],
            IrInstruction::Bsr { src, .. } => vec![src.clone()],
            IrInstruction::Xchg { op1, op2 } => vec![op1.clone(), op2.clone()],
            IrInstruction::Cmov { src, .. } => vec![src.clone()],
            _ => vec![],
        }
    }
}

impl fmt::Display for IrInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IrInstruction::Mov { dst, src } => write!(f, "mov {:?}, {:?}", dst, src),
            IrInstruction::Lea { dst, src } => write!(f, "lea {:?}, {:?}", dst, src),
            IrInstruction::Push { src } => write!(f, "push {:?}", src),
            IrInstruction::Pop { dst } => write!(f, "pop {:?}", dst),
            IrInstruction::Add { dst, src } => write!(f, "add {:?}, {:?}", dst, src),
            IrInstruction::Sub { dst, src } => write!(f, "sub {:?}, {:?}", dst, src),
            IrInstruction::Jmp { target } => write!(f, "jmp {:?}", target),
            IrInstruction::Jcc { condition, target } => write!(f, "j{:?} {:?}", condition, target),
            IrInstruction::Call { target } => write!(f, "call {:?}", target),
            IrInstruction::Ret { pop_bytes } => {
                if let Some(bytes) = pop_bytes {
                    write!(f, "ret {}", bytes)
                } else {
                    write!(f, "ret")
                }
            }
            IrInstruction::Nop => write!(f, "nop"),
            IrInstruction::Label { id } => write!(f, "L{}:", id),
            IrInstruction::Comment { text } => write!(f, "; {}", text),
            _ => write!(f, "{:?}", self),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_sizes() {
        assert_eq!(IrRegister::Al.size_bits(), 8);
        assert_eq!(IrRegister::Ax.size_bits(), 16);
        assert_eq!(IrRegister::Eax.size_bits(), 32);
        assert_eq!(IrRegister::Rax.size_bits(), 64);
        assert_eq!(IrRegister::Rax.size_bytes(), 8);
    }

    #[test]
    fn test_register_to_64bit() {
        assert_eq!(IrRegister::Al.to_64bit(), Some(IrRegister::Rax));
        assert_eq!(IrRegister::Ax.to_64bit(), Some(IrRegister::Rax));
        assert_eq!(IrRegister::Eax.to_64bit(), Some(IrRegister::Rax));
        assert_eq!(IrRegister::Rax.to_64bit(), Some(IrRegister::Rax));
    }

    #[test]
    fn test_immediate_conversions() {
        let imm8: IrImmediate = 42u8.into();
        assert_eq!(imm8.as_u64(), 42);
        assert_eq!(imm8.size_bits(), 8);

        let imm32: IrImmediate = 1000u32.into();
        assert_eq!(imm32.as_u64(), 1000);
        assert_eq!(imm32.size_bits(), 32);

        let imm64: IrImmediate = 0x123456789ABCDEF0u64.into();
        assert_eq!(imm64.as_u64(), 0x123456789ABCDEF0);
    }

    #[test]
    fn test_memory_operand() {
        let mem = IrMemoryOperand::new_base(IrRegister::Rax, 64);
        assert_eq!(mem.base, Some(IrRegister::Rax));
        assert_eq!(mem.size_bits, 64);
        assert!(mem.is_simple_base());

        let mem_disp = IrMemoryOperand::new_base_disp(IrRegister::Rbp, 8, 32);
        assert_eq!(mem_disp.displacement, 8);
        assert!(!mem_disp.is_simple_base());

        let mem_rip = IrMemoryOperand::new_rip_relative(-4, 32);
        assert!(mem_rip.is_rip_relative());
    }

    #[test]
    fn test_ir_operand() {
        let reg_op = IrOperand::reg(IrRegister::Rax);
        assert!(reg_op.is_register());
        assert_eq!(reg_op.size_bits(), 64);

        let imm_op = IrOperand::imm(42u32);
        assert!(imm_op.is_immediate());

        let mem = IrMemoryOperand::new_base(IrRegister::Rbx, 32);
        let mem_op = IrOperand::mem(mem);
        assert!(mem_op.is_memory());
        assert_eq!(mem_op.size_bits(), 32);
    }

    #[test]
    fn test_ir_instruction_mov() {
        let mov = IrInstruction::Mov {
            dst: IrOperand::reg(IrRegister::Rax),
            src: IrOperand::imm(42u64),
        };
        assert!(!mov.is_control_flow());
        assert!(mov.destination_operand().is_some());
        assert_eq!(mov.source_operands().len(), 1);
    }

    #[test]
    fn test_ir_instruction_jmp() {
        let jmp = IrInstruction::Jmp {
            target: IrJumpTarget::Direct(0x1234),
        };
        assert!(jmp.is_control_flow());
        assert!(jmp.is_jump());
        assert!(!jmp.is_conditional());
    }

    #[test]
    fn test_ir_instruction_jcc() {
        let jcc = IrInstruction::Jcc {
            condition: IrCondition::E,
            target: IrJumpTarget::Relative(10),
        };
        assert!(jcc.is_control_flow());
        assert!(jcc.is_jump());
        assert!(jcc.is_conditional());
    }

    #[test]
    fn test_ir_instruction_call() {
        let call = IrInstruction::Call {
            target: IrJumpTarget::Direct(0x5678),
        };
        assert!(call.is_control_flow());
        assert!(call.is_call());
    }

    #[test]
    fn test_ir_instruction_ret() {
        let ret = IrInstruction::Ret { pop_bytes: None };
        assert!(ret.is_control_flow());
        assert!(ret.is_return());

        let ret_pop = IrInstruction::Ret {
            pop_bytes: Some(8),
        };
        assert!(ret_pop.is_return());
    }

    #[test]
    fn test_instruction_display() {
        let mov = IrInstruction::Mov {
            dst: IrOperand::reg(IrRegister::Rax),
            src: IrOperand::imm(42u64),
        };
        let s = format!("{}", mov);
        assert!(s.contains("mov"));
    }
}
