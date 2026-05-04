//! 寄存器存活分析 (Liveness Analysis)

use iced_x86::{Instruction, Register};

/// 描述一条指令位置的寄存器和标志位存活状态
#[derive(Debug, Clone, Default)]
pub struct LivenessInfo {
    pub live_regs: u32,  // Bitmask for General Purpose Registers
    pub live_flags: u32, // Bitmask for EFLAGS (ZF, CF, OF, etc.)
}

impl LivenessInfo {
    /// 检查指定寄存器是否活跃
    pub fn is_live(&self, reg: Register) -> bool {
        let bit = Self::reg_to_bit(reg);
        if bit < 0 { return true; } // Unknown registers considered live
        (self.live_regs & (1 << bit)) != 0
    }

    /// 设置寄存器为活跃 (Read)
    pub fn set_live(&mut self, reg: Register) {
        let bit = Self::reg_to_bit(reg);
        if bit >= 0 { self.live_regs |= 1 << bit; }
    }

    /// 设置寄存器为死亡 (Written/Overwritten)
    pub fn set_dead(&mut self, reg: Register) {
        let bit = Self::reg_to_bit(reg);
        if bit >= 0 { self.live_regs &= !(1 << bit); }
    }

    /// 将 iced_x86::Register 映射到 0-15 的位掩码索引
    fn reg_to_bit(reg: Register) -> i32 {
        match reg {
            Register::RAX | Register::EAX | Register::AX | Register::AL => 0,
            Register::RCX | Register::ECX | Register::CX | Register::CL => 1,
            Register::RDX | Register::EDX | Register::DX | Register::DL => 2,
            Register::RBX | Register::EBX | Register::BX | Register::BL => 3,
            Register::RSP | Register::ESP | Register::SP | Register::SPL => 4,
            Register::RBP | Register::EBP | Register::BP | Register::BPL => 5,
            Register::RSI | Register::ESI | Register::SI | Register::SIL => 6,
            Register::RDI | Register::EDI | Register::DI | Register::DIL => 7,
            Register::R8  | Register::R8D  | Register::R8W  | Register::R8L  => 8,
            Register::R9  | Register::R9D  | Register::R9W  | Register::R9L  => 9,
            Register::R10 | Register::R10D | Register::R10W | Register::R10L => 10,
            Register::R11 | Register::R11D | Register::R11W | Register::R11L => 11,
            Register::R12 | Register::R12D | Register::R12W | Register::R12L => 12,
            Register::R13 | Register::R13D | Register::R13W | Register::R13L => 13,
            Register::R14 | Register::R14D | Register::R14W | Register::R14L => 14,
            Register::R15 | Register::R15D | Register::R15W | Register::R15L => 15,
            _ => -1,
        }
    }
}
