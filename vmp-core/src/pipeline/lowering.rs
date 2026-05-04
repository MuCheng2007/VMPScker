//! 降级器模块 (Lowering Pass)
//! 负责将原生 x86 IR 降级为基于栈的 VM Opcode 序列
//! 
//! 参考 C++ 项目中的 IntelCommand::CompileToVM 实现

use crate::intel::ir::{IrOpcode, IrOperand, IrRegister, IrJumpTarget, IrCondition};
use crate::pipeline::node::InstNode;
use crate::vm::opcode::VmOpcode;
use std::collections::HashMap;

pub struct LoweringPass;

impl LoweringPass {
    /// 原始 run 方法（保持向后兼容，不支持内部跳转）
    pub fn run(nodes: &mut Vec<InstNode>) {
        Self::run_with_range(nodes, 0, 0);
    }

    /// 带地址范围的 run 方法，支持 VM 内部跳转
    /// code_start/code_end: 被虚拟化代码的原始地址范围 [code_start, code_end)
    /// image_base: PE 的 ImageBase，用于将 RVA 转换为 VA
    pub fn run_with_range(nodes: &mut Vec<InstNode>, code_start: u64, code_end: u64) {
        Self::run_with_range_and_base(nodes, code_start, code_end, 0);
    }

    /// 带地址范围和 ImageBase 的 run 方法
    pub fn run_with_range_and_base(nodes: &mut Vec<InstNode>, code_start: u64, code_end: u64, image_base: u64) {
        // === 预扫描：为范围内的指令分配标签 ID ===
        let mut label_map: HashMap<u64, u32> = HashMap::new(); // x86 RVA -> label ID
        let mut label_counter: u32 = 0;

        if code_start < code_end {
            for node in nodes.iter() {
                if node.is_junk || node.x86_ir.is_none() {
                    continue;
                }
                let rva = node.rva;
                if rva >= code_start && rva < code_end {
                    label_map.entry(rva).or_insert_with(|| {
                        let id = label_counter;
                        label_counter += 1;
                        id
                    });
                }
            }

            // 为跳转目标也分配标签（目标可能不在节点列表的起始位置）
            for node in nodes.iter() {
                if node.is_junk || node.x86_ir.is_none() {
                    continue;
                }
                let x86_ir = node.x86_ir.as_ref().unwrap();
                if let IrOpcode::Jcc { target, .. } = &x86_ir.opcode {
                    if let IrJumpTarget::Direct(addr) = target {
                        if *addr >= code_start && *addr < code_end {
                            label_map.entry(*addr).or_insert_with(|| {
                                let id = label_counter;
                                label_counter += 1;
                                id
                            });
                        }
                    }
                }
                if let IrOpcode::Jmp { target } = &x86_ir.opcode {
                    if let IrJumpTarget::Direct(addr) = target {
                        if *addr >= code_start && *addr < code_end {
                            label_map.entry(*addr).or_insert_with(|| {
                                let id = label_counter;
                                label_counter += 1;
                                id
                            });
                        }
                    }
                }
            }
        }

        // === 主循环：降级每条指令 ===
        for node in nodes.iter_mut() {
            if node.is_junk || node.x86_ir.is_none() {
                continue;
            }

            let mut vm_ir = Vec::new();
            let x86_ir = node.x86_ir.as_ref().unwrap();

            // 如果当前指令有标签，先发出 VLabel
            if let Some(&label_id) = label_map.get(&node.rva) {
                vm_ir.push(VmOpcode::VLabel(label_id));
            }

            match &x86_ir.opcode {
                // === 数据传输指令 ===
                IrOpcode::Mov { dst, src } => {
                    Self::compile_operand(&mut vm_ir, src);
                    Self::compile_operand_save(&mut vm_ir, dst);
                }

                IrOpcode::Push { src } => {
                    Self::compile_operand(&mut vm_ir, src);
                    vm_ir.push(VmOpcode::VPushReg(Self::reg_to_offset(IrRegister::Rsp)));
                }

                IrOpcode::Pop { dst } => {
                    Self::compile_operand_save(&mut vm_ir, dst);
                    vm_ir.push(VmOpcode::VPopReg(Self::reg_to_offset(IrRegister::Rsp)));
                }

                IrOpcode::Lea { dst, src } => {
                    // Lea: 计算地址并保存到 dst
                    // 简化实现：将地址作为立即数处理
                    vm_ir.push(VmOpcode::VPushImm32(src.displacement as u32));
                    vm_ir.push(VmOpcode::VPopReg(Self::reg_to_offset(*dst)));
                }

                IrOpcode::Xchg { op1, op2 } => {
                    // Xchg: 交换两个操作数
                    Self::compile_operand(&mut vm_ir, op2);
                    Self::compile_operand(&mut vm_ir, op1);
                    Self::compile_operand_save(&mut vm_ir, op2);
                    Self::compile_operand_save(&mut vm_ir, op1);
                }

                IrOpcode::Cmov { condition: _, dst, src } => {
                    // Cmov: 条件移动
                    // 简化实现：直接移动（实际需要条件判断）
                    if let IrOperand::Register(src_reg) = src {
                        vm_ir.push(VmOpcode::VPushReg(Self::reg_to_offset(*src_reg)));
                    }
                    vm_ir.push(VmOpcode::VPopReg(Self::reg_to_offset(*dst)));
                }

                // === 算术指令 ===
                // 注意：算术 handler (VAdd/VSub 等) 现在直接将 EFLAGS 保存到保存槽，
                // 不再压入 VM 栈。VJcc 从保存槽读取 EFLAGS。
                IrOpcode::Add { dst, src } => {
                    Self::compile_operand(&mut vm_ir, src);
                    Self::compile_operand(&mut vm_ir, src);
                    vm_ir.push(VmOpcode::VAdd);
                    // VAdd 已将 EFLAGS 保存到保存槽，结果在 VM 栈顶
                    Self::compile_operand_save(&mut vm_ir, dst);
                }

                IrOpcode::Sub { dst, src } => {
                    // Sub = dst - src = dst + NOT(src) + 1 (two's complement)
                    // NOT(src) = NAND(src, src)
                    Self::compile_operand(&mut vm_ir, src);    // push src
                    Self::compile_operand(&mut vm_ir, src);    // push src (NAND 需要两个相同操作数)
                    vm_ir.push(VmOpcode::VNand);               // NOT(src), EFLAGS → 保存槽
                    vm_ir.push(VmOpcode::VPopReg(Self::reg_to_offset(IrRegister::Rax))); // RAX = NOT(src)
                    // -src = NOT(src) + 1
                    vm_ir.push(VmOpcode::VPushReg(Self::reg_to_offset(IrRegister::Rax)));
                    vm_ir.push(VmOpcode::VPushImm32(1));
                    vm_ir.push(VmOpcode::VAdd);                // -src, EFLAGS → 保存槽
                    vm_ir.push(VmOpcode::VPopReg(Self::reg_to_offset(IrRegister::Rax))); // RAX = -src
                    // dst + (-src)
                    Self::compile_operand(&mut vm_ir, dst);
                    vm_ir.push(VmOpcode::VPushReg(Self::reg_to_offset(IrRegister::Rax)));
                    vm_ir.push(VmOpcode::VAdd);                // dst - src, EFLAGS → 保存槽
                    Self::compile_operand_save(&mut vm_ir, dst);
                }

                IrOpcode::Cmp { op1, op2 } => {
                    // Cmp = op1 - op2, discard result, keep EFLAGS
                    // NOT(op2) = NAND(op2, op2)
                    Self::compile_operand(&mut vm_ir, op2);    // push op2
                    Self::compile_operand(&mut vm_ir, op2);    // push op2
                    vm_ir.push(VmOpcode::VNand);               // NOT(op2), EFLAGS → 保存槽
                    vm_ir.push(VmOpcode::VPopReg(Self::reg_to_offset(IrRegister::Rax)));
                    // -op2 = NOT(op2) + 1
                    vm_ir.push(VmOpcode::VPushReg(Self::reg_to_offset(IrRegister::Rax)));
                    vm_ir.push(VmOpcode::VPushImm32(1));
                    vm_ir.push(VmOpcode::VAdd);                // -op2, EFLAGS → 保存槽
                    vm_ir.push(VmOpcode::VPopReg(Self::reg_to_offset(IrRegister::Rax)));
                    // op1 + (-op2) = op1 - op2
                    Self::compile_operand(&mut vm_ir, op2);
                    vm_ir.push(VmOpcode::VPushReg(Self::reg_to_offset(IrRegister::Rax)));
                    vm_ir.push(VmOpcode::VAdd);                // op1 - op2, EFLAGS → 保存槽
                    // 弹出并丢弃结果，EFLAGS 保留在保存槽供 VJcc 使用
                    vm_ir.push(VmOpcode::VPopReg(Self::reg_to_offset(IrRegister::Rax)));
                }

                IrOpcode::Inc { op } => {
                    vm_ir.push(VmOpcode::VPushImm32(1));
                    Self::compile_operand(&mut vm_ir, op);
                    vm_ir.push(VmOpcode::VAdd);
                    // VAdd 的 EFLAGS 已保存到保存槽
                    Self::compile_operand_save(&mut vm_ir, op);
                }

                IrOpcode::Dec { op } => {
                    vm_ir.push(VmOpcode::VPushImm32(0xFFFFFFFF)); // -1
                    Self::compile_operand(&mut vm_ir, op);
                    vm_ir.push(VmOpcode::VAdd);
                    // VAdd 的 EFLAGS 已保存到保存槽
                    Self::compile_operand_save(&mut vm_ir, op);
                }

                IrOpcode::Neg { op } => {
                    // Neg = NOT(op) + 1
                    Self::compile_operand(&mut vm_ir, op);
                    Self::compile_operand(&mut vm_ir, op);
                    vm_ir.push(VmOpcode::VNand);    // NOT(op), EFLAGS → slot
                    vm_ir.push(VmOpcode::VPushImm32(1));
                    vm_ir.push(VmOpcode::VAdd);     // -op, EFLAGS → slot
                    Self::compile_operand_save(&mut vm_ir, op);
                }

                IrOpcode::Mul { src } => {
                    Self::compile_operand(&mut vm_ir, src);
                    vm_ir.push(VmOpcode::VPushReg(Self::reg_to_offset(IrRegister::Rax)));
                    vm_ir.push(VmOpcode::VAdd);     // EFLAGS → slot
                    vm_ir.push(VmOpcode::VPopReg(Self::reg_to_offset(IrRegister::Rax)));
                }

                IrOpcode::Imul { src1, .. } => {
                    Self::compile_operand(&mut vm_ir, src);
                    vm_ir.push(VmOpcode::VPushReg(Self::reg_to_offset(IrRegister::Rax)));
                    vm_ir.push(VmOpcode::VAdd);     // EFLAGS → slot
                    vm_ir.push(VmOpcode::VPopReg(Self::reg_to_offset(IrRegister::Rax)));
                }

                IrOpcode::Div { src } | IrOpcode::Idiv { src } => {
                    Self::compile_operand(&mut vm_ir, src);
                    vm_ir.push(VmOpcode::VPushReg(Self::reg_to_offset(IrRegister::Rax)));
                    vm_ir.push(VmOpcode::VPushReg(Self::reg_to_offset(IrRegister::Rdx)));
                    vm_ir.push(VmOpcode::VPopReg(Self::reg_to_offset(IrRegister::Rax)));
                    vm_ir.push(VmOpcode::VPopReg(Self::reg_to_offset(IrRegister::Rdx)));
                }

                // === 逻辑指令 ===
                IrOpcode::And { dst, src } => {
                    // A AND B = NOT(NOT(A) OR NOT(B)) = NOR(NAND(A,A), NAND(B,B))
                    Self::compile_operand(&mut vm_ir, src);
                    Self::compile_operand(&mut vm_ir, src);
                    vm_ir.push(VmOpcode::VNand);    // NOT(src)
                    Self::compile_operand(&mut vm_ir, dst);
                    Self::compile_operand(&mut vm_ir, dst);
                    vm_ir.push(VmOpcode::VNand);    // NOT(dst)
                    vm_ir.push(VmOpcode::VNor);     // NOT(NOT(src) OR NOT(dst)) = src AND dst
                    Self::compile_operand_save(&mut vm_ir, dst);
                }

                IrOpcode::Or { dst, src } => {
                    // A OR B = NOT(NOT(A) AND NOT(B)) = NAND(NAND(A,A), NAND(B,B))
                    Self::compile_operand(&mut vm_ir, src);
                    Self::compile_operand(&mut vm_ir, src);
                    vm_ir.push(VmOpcode::VNand);    // NOT(src)
                    Self::compile_operand(&mut vm_ir, dst);
                    Self::compile_operand(&mut vm_ir, dst);
                    vm_ir.push(VmOpcode::VNand);    // NOT(dst)
                    vm_ir.push(VmOpcode::VNand);    // NOT(NOT(src) AND NOT(dst)) = src OR dst
                    Self::compile_operand_save(&mut vm_ir, dst);
                }

                IrOpcode::Xor { dst, src } => {
                    // XOR = NAND(NAND(A, NAND(A,B)), NAND(B, NAND(A,B)))
                    // 简化：使用已有的 VXor handler
                    Self::compile_operand(&mut vm_ir, src);
                    Self::compile_operand(&mut vm_ir, src);
                    vm_ir.push(VmOpcode::VXor);     // EFLAGS → slot
                    Self::compile_operand_save(&mut vm_ir, dst);
                }

                IrOpcode::Not { op } => {
                    // NOT(op) = NAND(op, op)
                    Self::compile_operand(&mut vm_ir, op);
                    Self::compile_operand(&mut vm_ir, op);
                    vm_ir.push(VmOpcode::VNand);    // EFLAGS → slot
                    Self::compile_operand_save(&mut vm_ir, op);
                }

                IrOpcode::Test { op1, op2 } => {
                    // Test = And but discard result, keep EFLAGS
                    Self::compile_operand(&mut vm_ir, op2);
                    Self::compile_operand(&mut vm_ir, op2);
                    vm_ir.push(VmOpcode::VNand);    // NOT(op2)
                    Self::compile_operand(&mut vm_ir, op1);
                    Self::compile_operand(&mut vm_ir, op);
                    vm_ir.push(VmOpcode::VNand);    // NOT(op1)
                    vm_ir.push(VmOpcode::VNor);     // op1 AND op2, EFLAGS → slot
                    vm_ir.push(VmOpcode::VPopReg(Self::reg_to_offset(IrRegister::Rax))); // discard result
                }

                // === 移位指令 ===
                IrOpcode::Shl { dst, count } => {
                    Self::compile_operand(&mut vm_ir, dst);
                    Self::compile_operand(&mut vm_ir, dst);
                    vm_ir.push(VmOpcode::VAdd);     // EFLAGS → slot
                    Self::compile_operand_save(&mut vm_ir, dst);
                }

                IrOpcode::Shr { dst, count } => {
                    Self::compile_operand(&mut vm_ir, dst);
                    Self::compile_operand(&mut vm_ir, dst);
                    vm_ir.push(VmOpcode::VSub);     // EFLAGS → slot
                    Self::compile_operand_save(&mut vm_ir, dst);
                }

                IrOpcode::Sar { dst, count } => {
                    Self::compile_operand(&mut vm_ir, dst);
                    Self::compile_operand(&mut vm_ir, dst);
                    vm_ir.push(VmOpcode::VSub);     // EFLAGS → slot
                    Self::compile_operand_save(&mut vm_ir, dst);
                }

                IrOpcode::Rol { dst, count } | IrOpcode::Ror { dst, count } => {
                    Self::compile_operand(&mut vm_ir, dst);
                    Self::compile_operand(&mut vm_ir, dst);
                    vm_ir.push(VmOpcode::VAdd);     // EFLAGS → slot
                    Self::compile_operand_save(&mut vm_ir, dst);
                }

                // === 位操作指令 ===
                IrOpcode::Bt { base, offset } |
                IrOpcode::Bts { base, offset } => {
                    Self::compile_operand(&mut vm_ir, base);
                    Self::compile_operand(&mut vm_ir, offset);
                    vm_ir.push(VmOpcode::VPushImm32(1));
                    vm_ir.push(VmOpcode::VSub);     // EFLAGS → slot
                    vm_ir.push(VmOpcode::VPopReg(Self::reg_to_offset(IrRegister::Rax))); // discard result
                }

                // === 控制流指令 ===
                IrOpcode::Jmp { target } => {
                    match target {
                        IrJumpTarget::Direct(addr) if code_start < code_end && *addr >= code_start && *addr < code_end => {
                            // 内部直接跳转：使用 VJmp
                            let label_id = label_map.get(addr).copied().unwrap_or(0);
                            vm_ir.push(VmOpcode::VJmp(label_id));
                        }
                        _ => {
                            // 外部跳转或间接跳转：退出 VM
                            vm_ir.push(VmOpcode::VExit);
                        }
                    }
                }

                IrOpcode::Jcc { condition, target } => {
                    match target {
                        IrJumpTarget::Direct(addr) if code_start < code_end && *addr >= code_start && *addr < code_end => {
                            // 内部条件跳转：使用 VJcc
                            let label_id = label_map.get(addr).copied().unwrap_or(0);
                            let cond_code = Self::condition_to_u8(*condition);
                            vm_ir.push(VmOpcode::VJcc(cond_code, label_id));
                        }
                        _ => {
                            // 外部跳转或间接跳转：退出 VM
                            vm_ir.push(VmOpcode::VExit);
                        }
                    }
                }

                IrOpcode::Call { target } => {
                    // Call 指令：将目标地址压入虚拟栈，然后使用 VCall 调用原生函数
                    // VCall 会保存 VM 上下文，恢复原生上下文，调用函数，然后通过重入桩恢复 VM
                    eprintln!("[Lowering] Call at 0x{:X} -> VCall, target={:?}", node.rva, target);
                    Self::compile_jump_target(&mut vm_ir, target, image_base);
                    vm_ir.push(VmOpcode::VCall(0));
                }

                IrOpcode::Ret { .. } => {
                    // Ret 总是退出 VM
                    vm_ir.push(VmOpcode::VExit);
                }

                IrOpcode::Syscall => {
                    vm_ir.push(VmOpcode::VExit);
                }

                // === 标志操作 ===
                IrOpcode::Pushf => {
                    vm_ir.push(VmOpcode::VPushReg(Self::eflags_offset()));
                    vm_ir.push(VmOpcode::VPushReg(Self::reg_to_offset(IrRegister::Rsp)));
                }

                IrOpcode::Popf => {
                    vm_ir.push(VmOpcode::VPopReg(Self::eflags_offset()));
                    vm_ir.push(VmOpcode::VPopReg(Self::reg_to_offset(IrRegister::Rsp)));
                }

                IrOpcode::Clc | IrOpcode::Stc => {
                    // 进位标志操作（简化）
                    vm_ir.push(VmOpcode::VNop);
                }

                IrOpcode::Cld | IrOpcode::Std => {
                    // 方向标志操作（简化）
                    vm_ir.push(VmOpcode::VNop);
                }

                IrOpcode::Lahf => {
                    vm_ir.push(VmOpcode::VPushReg(Self::eflags_offset()));
                    vm_ir.push(VmOpcode::VPopReg(Self::reg_to_offset(IrRegister::Rax)));
                }

                IrOpcode::Sahf => {
                    vm_ir.push(VmOpcode::VPushReg(Self::reg_to_offset(IrRegister::Rax)));
                    vm_ir.push(VmOpcode::VPopReg(Self::eflags_offset()));
                }

                // === 无操作 ===
                IrOpcode::Nop => {
                    vm_ir.push(VmOpcode::VNop);
                }

                IrOpcode::Int3 => {
                    // 断点（简化）
                    vm_ir.push(VmOpcode::VNop);
                }

                IrOpcode::Ud2 => {
                    // 未定义指令
                    vm_ir.push(VmOpcode::VExit);
                }

                // === 标签和注释 ===
                IrOpcode::Label { .. } => {
                    // 标签不产生代码
                }

                IrOpcode::Comment { .. } => {
                    // 注释不产生代码
                }

                _ => {
                    // 未实现的指令，暂时跳过
                }
            }

            node.vm_ir = vm_ir;
        }
    }

    /// 编译跳转目标（将目标地址压入虚拟栈）
    /// 对于内存操作数，会读取内存中的值（函数指针）
    /// image_base: PE 的 ImageBase，用于将 RVA 转换为 VA
    fn compile_jump_target(vm_ir: &mut Vec<VmOpcode>, target: &IrJumpTarget, image_base: u64) {
        match target {
            IrJumpTarget::Direct(addr) => {
                // 绝对地址，直接压入（截断为32位，适用于默认ImageBase 0x140000000）
                vm_ir.push(VmOpcode::VPushImm32(*addr as u32));
            }
            IrJumpTarget::Register(reg) => {
                // 寄存器间接调用：寄存器中就是函数地址
                vm_ir.push(VmOpcode::VPushReg(Self::reg_to_offset(*reg)));
            }
            IrJumpTarget::Memory(mem) => {
                // 内存间接调用：需要计算内存地址，然后读取函数指针
                if mem.base == Some(IrRegister::Rip) {
                    // RIP 相对寻址：decoder 使用 RVA 作为 IP，所以 displacement 是 RVA
                    // 需要加上 ImageBase 得到 VA
                    let va = image_base.wrapping_add(mem.displacement as u64);
                    vm_ir.push(VmOpcode::VPushImm64(va));
                } else if let Some(base) = mem.base {
                    vm_ir.push(VmOpcode::VPushReg(Self::reg_to_offset(base)));
                    if mem.displacement != 0 {
                        vm_ir.push(VmOpcode::VPushImm32(mem.displacement as u32));
                        vm_ir.push(VmOpcode::VAdd);
                    }
                } else {
                    // 无基址，直接用位移作为地址
                    vm_ir.push(VmOpcode::VPushImm32(mem.displacement as u32));
                }
                // 读取内存中的函数指针
                vm_ir.push(VmOpcode::VReadMem((mem.size_bits / 8) as u8));
            }
            IrJumpTarget::Relative(_offset) => {
                // 相对偏移：需要基于当前指令地址计算绝对地址
                // 暂时用 0 占位，后续需要传入指令 RVA
                vm_ir.push(VmOpcode::VPushImm32(0));
            }
            IrJumpTarget::Label(_id) => {
                // 标签引用：需要标签解析支持
                vm_ir.push(VmOpcode::VPushImm32(0));
            }
        }
    }

    /// 编译操作数（入栈）
    fn compile_operand(vm_ir: &mut Vec<VmOpcode>, op: &IrOperand) {
        match op {
            IrOperand::Register(reg) => {
                vm_ir.push(VmOpcode::VPushReg(Self::reg_to_offset(*reg)));
            }
            IrOperand::Immediate(imm) => {
                vm_ir.push(VmOpcode::VPushImm32(imm.as_u64() as u32));
            }
            IrOperand::Memory(mem) => {
                // 内存操作数：计算地址并读取
                if mem.base == Some(IrRegister::Rip) {
                    // RIP 相对寻址：displacement 已经是绝对地址 (由 iced_x86 解码器计算)
                    // 使用 VPushImm64 确保 64 位地址不被截断
                    vm_ir.push(VmOpcode::VPushImm64(mem.displacement as u64));
                } else if let Some(base) = mem.base {
                    vm_ir.push(VmOpcode::VPushReg(Self::reg_to_offset(base)));
                    if mem.displacement != 0 {
                        vm_ir.push(VmOpcode::VPushImm32(mem.displacement as u32));
                        vm_ir.push(VmOpcode::VAdd); // EFLAGS → slot, addr stays on stack
                    }
                } else {
                    vm_ir.push(VmOpcode::VPushImm32(mem.displacement as u32));
                }

                // 读取内存
                vm_ir.push(VmOpcode::VReadMem((mem.size_bits / 8) as u8));
            }
        }
    }

    /// 编译操作数（出栈保存）
    fn compile_operand_save(vm_ir: &mut Vec<VmOpcode>, op: &IrOperand) {
        match op {
            IrOperand::Register(reg) => {
                vm_ir.push(VmOpcode::VPopReg(Self::reg_to_offset(*reg)));
            }
            IrOperand::Memory(mem) => {
                // 内存操作数：计算地址并写入
                if mem.base == Some(IrRegister::Rip) {
                    // RIP 相对寻址：displacement 已经是绝对地址
                    vm_ir.push(VmOpcode::VPushImm64(mem.displacement as u64));
                } else if let Some(base) = mem.base {
                    vm_ir.push(VmOpcode::VPushReg(Self::reg_to_offset(base)));
                } else {
                    vm_ir.push(VmOpcode::VPushImm32(0));
                }

                if mem.displacement != 0 && mem.base != Some(IrRegister::Rip) {
                    vm_ir.push(VmOpcode::VPushImm32(mem.displacement as u32));
                    vm_ir.push(VmOpcode::VAdd); // EFLAGS → slot, addr stays on stack
                }
                
                // 交换地址和值，然后写入内存
                // 栈顶: [value, addr] -> 需要: [addr, value]
                vm_ir.push(VmOpcode::VPushReg(Self::reg_to_offset(IrRegister::Rax)));
                vm_ir.push(VmOpcode::VPushReg(Self::reg_to_offset(IrRegister::Rcx)));
                vm_ir.push(VmOpcode::VPopReg(Self::reg_to_offset(IrRegister::Rax)));
                vm_ir.push(VmOpcode::VPopReg(Self::reg_to_offset(IrRegister::Rcx)));
                
                vm_ir.push(VmOpcode::VWriteMem((mem.size_bits / 8) as u8));
            }
            _ => {}
        }
    }

    /// 将原生寄存器映射到 VM 保存区域中的索引
    ///
    /// VM_Entry push 顺序: pushfq, rax, rcx, rdx, rbx, rbp, rsi, rdi, r8-r15
    /// 保存区域布局 (从 RSP+0x2000 向高地址):
    ///   [0] R15  [1] R14  [2] R13  [3] R12  [4] R11  [5] R10
    ///   [6] R9   [7] R8   [8] RDI  [9] RSI  [10] RBP [11] RBX
    ///   [12] RDX [13] RCX [14] RAX [15] RFLAGS
    ///
    /// Handler 通过 `address = RSP + 0x2000 + index * 8` 计算实际地址
    fn reg_to_offset(reg: IrRegister) -> u8 {
        match reg {
            // 64-bit registers
            IrRegister::Rax => 14,
            IrRegister::Rcx => 13,
            IrRegister::Rdx => 12,
            IrRegister::Rbx => 11,
            IrRegister::Rsp => 11, // RSP 无保存槽，暂映射到 RBX 槽
            IrRegister::Rbp => 10,
            IrRegister::Rsi => 9,
            IrRegister::Rdi => 8,
            IrRegister::R8 => 7,
            IrRegister::R9 => 6,
            IrRegister::R10 => 5,
            IrRegister::R11 => 4,
            IrRegister::R12 => 3,
            IrRegister::R13 => 2,
            IrRegister::R14 => 1,
            IrRegister::R15 => 0,

            // 32-bit registers
            IrRegister::Eax => 14,
            IrRegister::Ecx => 13,
            IrRegister::Edx => 12,
            IrRegister::Ebx => 11,
            IrRegister::Esp => 11,
            IrRegister::Ebp => 10,
            IrRegister::Esi => 9,
            IrRegister::Edi => 8,
            IrRegister::R8d => 7,
            IrRegister::R9d => 6,
            IrRegister::R10d => 5,
            IrRegister::R11d => 4,
            IrRegister::R12d => 3,
            IrRegister::R13d => 2,
            IrRegister::R14d => 1,
            IrRegister::R15d => 0,

            // 16-bit registers
            IrRegister::Ax => 14,
            IrRegister::Cx => 13,
            IrRegister::Dx => 12,
            IrRegister::Bx => 11,
            IrRegister::Sp => 11,
            IrRegister::Bp => 10,
            IrRegister::Si => 9,
            IrRegister::Di => 8,

            // 8-bit registers
            IrRegister::Al | IrRegister::Ah => 14,
            IrRegister::Cl | IrRegister::Ch => 13,
            IrRegister::Dl | IrRegister::Dh => 12,
            IrRegister::Bl | IrRegister::Bh => 11,

            IrRegister::Spl => 11,
            IrRegister::Bpl => 10,
            IrRegister::Sil => 9,
            IrRegister::Dil => 8,
            IrRegister::R8b => 7,
            IrRegister::R9b => 6,
            IrRegister::R10b => 5,
            IrRegister::R11b => 4,
            IrRegister::R12b => 3,
            IrRegister::R13b => 2,
            IrRegister::R14b => 1,
            IrRegister::R15b => 0,

            _ => 0,
        }
    }

    fn eflags_offset() -> u8 {
        15
    }

    /// 将 IrCondition 映射到 VJcc 的条件码 u8
    /// 必须与 handlers.rs gen_vjcc() 的 match 分支完全一致:
    /// 0=E/Z, 1=NE/NZ, 2=C, 3=NC, 4=S, 5=NS, 6=O, 7=NO,
    /// 8=A, 9=AE, 10=B, 11=BE, 12=G, 13=GE, 14=L, 15=LE
    fn condition_to_u8(cond: IrCondition) -> u8 {
        match cond {
            IrCondition::E => 0,
            IrCondition::Ne => 1,
            IrCondition::B => 10,   // CF=1
            IrCondition::Ae => 9,   // CF=0
            IrCondition::S => 4,
            IrCondition::Ns => 5,
            IrCondition::O => 6,
            IrCondition::No => 7,
            IrCondition::A => 8,    // CF=0 && ZF=0
            IrCondition::Be => 11,  // CF=1 || ZF=1
            IrCondition::G => 12,   // ZF=0 && SF=OF
            IrCondition::Ge => 13,  // SF=OF
            IrCondition::L => 14,   // SF!=OF
            IrCondition::Le => 15,  // ZF=1 || SF!=OF
            IrCondition::P => 0,    // 无 PF 条件码，回退到 E
            IrCondition::Np => 1,   // 无 PF 条件码，回退到 NE
            IrCondition::Cxnz => 1, // CX!=0 → treat as NE
        }
    }
}
