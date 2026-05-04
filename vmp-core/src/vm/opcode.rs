//! 虚拟机底层堆栈机指令集

use std::fmt;

/// VM 内部的操作码枚举 (纯栈式操作)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VmOpcode {
    /// 无操作
    VNop,
    /// 栈顶两个元素相加: POP B, POP A, PUSH (A+B), PUSH EFLAGS
    VAdd,
    /// 栈顶两个元素相减: POP B, POP A, PUSH (A-B), PUSH EFLAGS
    VSub,
    /// 栈顶两个元素异或
    VXor,
    /// 栈顶两个元素 NAND (VMP 核心算子之一)
    VNand,
    /// 栈顶两个元素 NOR
    VNor,
    
    /// 从当前上下文 (Native Context) 读取寄存器压入虚拟栈
    /// 这里的 u8 是该寄存器在 Context 数组中的偏移/索引
    VPushReg(u8),
    /// 从虚拟栈弹出数据到 Native Context
    VPopReg(u8),
    
    /// 压入立即数 (跟随在字节码后面)
    VPushImm8(u8),
    VPushImm16(u16),
    VPushImm32(u32),
    VPushImm64(u64),
    
    /// 读取内存：POP Addr, PUSH [Addr]
    VReadMem(u8), // u8表示读取的字节数 (1, 2, 4, 8)
    /// 写入内存：POP Addr, POP Value, [Addr] = Value
    VWriteMem(u8),
    
    /// 虚拟机内部无条件跳转：读取字节码偏移量，设置 VIP
    /// u32 = 目标标签 ID（编译器解析为字节码偏移量）
    VJmp(u32),
    /// 条件跳转: 读取字节码偏移量，检查 EFLAGS，条件成立则设置 VIP
    /// u8 = 条件码 (0=E/Z, 1=NE/NZ, 2=C, 3=NC, 4=S, 5=NS, 6=O, 7=NO, 8=A, 9=AE, 10=B, 11=BE, 12=G, 13=GE, 14=L, 15=LE)
    /// u32 = 目标标签 ID
    VJcc(u8, u32),
    /// 标签标记（伪指令，不生成字节码）
    VLabel(u32),
    /// 原生函数调用：读取参数数量 N，POP Target, POP ArgN..Arg1, call Target, PUSH 返回值
    /// VM 上下文 (VIP/VSP/VKEY/TABLE) 在调用期间保存/恢复
    VCall(u8),
    /// 退出虚拟机，恢复物理上下文
    VExit,
}

impl fmt::Display for VmOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VmOpcode::VPushReg(offset) => write!(f, "VPushReg[off:{:#x}]", offset),
            VmOpcode::VPopReg(offset)  => write!(f, "VPopReg[off:{:#x}]", offset),
            VmOpcode::VPushImm32(val)  => write!(f, "VPushImm32({:#x})", val),
            VmOpcode::VPushImm64(val)  => write!(f, "VPushImm64({:#x})", val),
            VmOpcode::VReadMem(sz)     => write!(f, "VReadMem({})", sz),
            VmOpcode::VWriteMem(sz)    => write!(f, "VWriteMem({})", sz),
            VmOpcode::VCall(argc)      => write!(f, "VCall({})", argc),
            VmOpcode::VJcc(cond, id)   => write!(f, "VJcc({},{})", cond, id),
            VmOpcode::VLabel(id)       => write!(f, "VLabel({})", id),
            _ => write!(f, "{:?}", self),
        }
    }
}
