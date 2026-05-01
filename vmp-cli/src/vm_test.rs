//! VM 转换测试模块 - 完整对比版本

use tracing::{info, error};
use std::path::PathBuf;
use vmp_core::pe::{PeFile, VmpMarkerFinder};
use vmp_core::intel::{DisassemblyMode, disassemble, Instruction};
use vmp_core::intel::ir_converter::IrConverter;
use vmp_core::intel::ir::{IrInstruction, IrRegister, IrOperand, IrMemoryOperand, IrCondition, IrJumpTarget};
use vmp_core::vm::{IrToVmCompiler, VmCodeGenerator, VMCommand};
use vmp_core::vm::types::CommandType;

/// 运行 VM 转换测试
pub fn run_test(input: PathBuf, mode: String) -> Result<(), Box<dyn std::error::Error>> {
    let disasm_mode = match mode.as_str() {
        "32" => DisassemblyMode::Mode32,
        "64" => DisassemblyMode::Mode64,
        _ => {
            error!("Invalid mode: {}. Use '32' or '64'", mode);
            return Err("Invalid mode".into());
        }
    };

    println!("Loading PE file: {:?}", input);
    let pe_file = PeFile::load(&input)?;

    let finder = VmpMarkerFinder::with_mode(disasm_mode);
    
    // 查找虚拟化标记
    println!("\n查找虚拟化标记...");
    let virt_markers = finder.find_virtualization_markers(&pe_file)?;

    if virt_markers.is_empty() {
        println!("未找到虚拟化标记，使用默认测试代码");
        let test_code = vec![
            0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00,
            0x48, 0x01, 0xC8,
            0xC3,
        ];
        test_vm_conversion(&test_code, 0x1000, disasm_mode)?;
    } else {
        println!("找到 {} 个虚拟化标记\n", virt_markers.len());
        
        for (i, (pair, _asm)) in virt_markers.iter().enumerate() {
            println!("=== 测试虚拟化标记 #{} ===", i + 1);
            println!("Begin RVA: 0x{:08X}", pair.begin.call_rva);
            println!("End RVA: 0x{:08X}", pair.end.call_rva);
            println!("代码大小: {} 字节\n", pair.code_end - pair.code_start);
            
            let code_bytes = finder.read_protected_code(&pe_file, pair)?;
            if !code_bytes.is_empty() {
                test_vm_conversion(&code_bytes, pair.code_start, disasm_mode)?;
            }
            
            println!("{}", "=".repeat(80));
        }
    }

    Ok(())
}

/// 获取指令的简化描述用于对比
fn get_instruction_signature(inst: &Instruction) -> String {
    format!("{}_{}_{}", 
        inst.mnemonic(),
        inst.category() as u8,
        inst.op_count()
    )
}

/// 获取IR指令的简化描述
fn get_ir_signature(ir: &IrInstruction) -> String {
    match ir {
        IrInstruction::Push { .. } => "Push".to_string(),
        IrInstruction::Pop { .. } => "Pop".to_string(),
        IrInstruction::Mov { .. } => "Mov".to_string(),
        IrInstruction::Lea { .. } => "Lea".to_string(),
        IrInstruction::Call { .. } => "Call".to_string(),
        IrInstruction::Ret { .. } => "Ret".to_string(),
        IrInstruction::Add { .. } => "Add".to_string(),
        IrInstruction::Sub { .. } => "Sub".to_string(),
        IrInstruction::Jmp { .. } => "Jmp".to_string(),
        IrInstruction::Jcc { .. } => "Jcc".to_string(),
        IrInstruction::Cmp { .. } => "Cmp".to_string(),
        IrInstruction::Test { .. } => "Test".to_string(),
        IrInstruction::Nop => "Nop".to_string(),
        _ => format!("{:?}", ir).split_whitespace().next().unwrap_or("Unknown").to_string(),
    }
}

/// 获取VM指令的简化描述
fn get_vm_signature(cmd: &VMCommand) -> String {
    format!("{:?}", cmd.command_type())
}

/// 打印所有原始指令
fn print_all_original_instructions(instructions: &[Instruction]) {
    println!("\n  完整原始指令列表 (共 {} 条):", instructions.len());
    println!("  {}", "-".repeat(70));
    for (i, inst) in instructions.iter().enumerate() {
        println!("    [{:2}] 0x{:04X}: {:12} (类别: {:?}, 操作数: {}, 长度: {})", 
            i,
            inst.ip() as u32,
            inst.mnemonic(),
            inst.category(),
            inst.op_count(),
            inst.len()
        );
    }
}

/// 打印所有IR指令
fn print_all_ir_instructions(ir_instructions: &[IrInstruction]) {
    println!("\n  完整IR指令列表 (共 {} 条):", ir_instructions.len());
    println!("  {}", "-".repeat(70));
    for (i, ir) in ir_instructions.iter().enumerate() {
        println!("    [{:2}] {:?}", i, ir);
    }
}

/// 打印所有VM指令
fn print_all_vm_commands(vm_commands: &[VMCommand]) {
    println!("\n  完整VM指令列表 (共 {} 条):", vm_commands.len());
    println!("  {}", "-".repeat(70));
    for (i, cmd) in vm_commands.iter().enumerate() {
        println!("    [{:2}] {:?} - 操作数: {:?}, 大小: {:?}", 
            i,
            cmd.command_type(),
            cmd.operand_type(),
            cmd.size()
        );
    }
}

/// 打印所有生成的指令
fn print_all_generated_instructions(instructions: &[Instruction]) {
    println!("\n  完整生成指令列表 (共 {} 条):", instructions.len());
    println!("  {}", "-".repeat(70));
    for (i, inst) in instructions.iter().enumerate() {
        println!("    [{:2}] 0x{:04X}: {:12} (类别: {:?}, 操作数: {})", 
            i,
            inst.ip() as u32,
            inst.mnemonic(),
            inst.category(),
            inst.op_count()
        );
    }
}

/// 验证原始指令和生成指令的语义等价性
fn verify_semantic_equivalence(
    original: &[Instruction],
    generated: &[Instruction],
    vm_commands: &[VMCommand],
) -> (bool, Vec<String>) {
    let mut mismatches = Vec::new();
    let mut is_equivalent = true;

    // 1. 检查指令数量
    if original.len() != generated.len() {
        mismatches.push(format!(
            "⚠ 指令数量不匹配: 原始={}, 生成={}",
            original.len(),
            generated.len()
        ));
        is_equivalent = false;
    }

    // 2. 对比指令序列的语义特征
    let orig_signatures: Vec<String> = original.iter()
        .map(|i| get_instruction_signature(i))
        .collect();
    
    let gen_signatures: Vec<String> = generated.iter()
        .map(|i| get_instruction_signature(i))
        .collect();

    // 3. 统计各类指令数量
    let mut orig_counts = std::collections::HashMap::new();
    let mut gen_counts = std::collections::HashMap::new();
    
    for sig in &orig_signatures {
        *orig_counts.entry(sig.split('_').next().unwrap_or("").to_string()).or_insert(0) += 1;
    }
    
    for sig in &gen_signatures {
        *gen_counts.entry(sig.split('_').next().unwrap_or("").to_string()).or_insert(0) += 1;
    }

    // 4. 对比指令类型分布
    println!("\n  指令类型分布对比:");
    println!("  {}", "-".repeat(50));
    println!("  {:<20} {:>10} {:>10}", "指令类型", "原始", "生成");
    println!("  {}", "-".repeat(50));
    
    let all_types: std::collections::HashSet<_> = orig_counts.keys()
        .chain(gen_counts.keys())
        .cloned()
        .collect();
    
    for inst_type in all_types {
        let orig_count = orig_counts.get(&inst_type).unwrap_or(&0);
        let gen_count = gen_counts.get(&inst_type).unwrap_or(&0);
        let marker = if orig_count == gen_count { "✓" } else { "✗" };
        println!("  {:<20} {:>10} {:>10} {}", inst_type, orig_count, gen_count, marker);
        
        if orig_count != gen_count {
            mismatches.push(format!(
                "✗ {} 指令数量不匹配: 原始={}, 生成={}",
                inst_type, orig_count, gen_count
            ));
            is_equivalent = false;
        }
    }

    // 5. 详细对比每条指令
    println!("\n  逐指令对比:");
    println!("  {}", "-".repeat(70));
    println!("  {:<6} {:<20} {:<20} {}", "序号", "原始指令", "生成指令", "状态");
    println!("  {}", "-".repeat(70));
    
    let max_len = original.len().max(generated.len());
    for i in 0..max_len {
        let orig = original.get(i).map(|i| i.mnemonic()).unwrap_or("-".to_string());
        let gen = generated.get(i).map(|i| i.mnemonic()).unwrap_or("-".to_string());
        
        let status = if i < original.len() && i < generated.len() {
            if get_instruction_signature(&original[i]) == get_instruction_signature(&generated[i]) {
                "✓"
            } else {
                "~"
            }
        } else {
            "✗"
        };
        
        println!("  [{:2}]   {:<20} {:<20} {}", i, orig, gen, status);
    }

    (is_equivalent, mismatches)
}

/// 测试 VM 转换流程 - 完整对比版本
fn test_vm_conversion(code_bytes: &[u8], base_rva: u64, mode: DisassemblyMode) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n╔════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                         VM 转换完整对比分析                                     ║");
    println!("╚════════════════════════════════════════════════════════════════════════════════╝\n");
    
    // ═══════════════════════════════════════════════════════════
    // 阶段 1: 原始 x86-64 指令
    // ═══════════════════════════════════════════════════════════
    println!("【阶段 1】原始 x86-64 指令反汇编");
    println!("{}", "═".repeat(80));
    let instructions = disassemble(code_bytes, mode, base_rva)?;
    println!("  总指令数: {} 条", instructions.len());
    println!("  代码大小: {} 字节", code_bytes.len());
    
    print_all_original_instructions(&instructions);
    
    // ═══════════════════════════════════════════════════════════
    // 阶段 2: IR (中间表示)
    // ═══════════════════════════════════════════════════════════
    println!("\n\n【阶段 2】转换为 IR (中间表示)");
    println!("{}", "═".repeat(80));
    let ir_converter = IrConverter::new(mode);
    let ir_instructions = ir_converter.convert_instructions(&instructions)?;
    println!("  IR 指令数: {} 条", ir_instructions.len());
    println!("  转换比率: {:.1}%", (ir_instructions.len() as f64 / instructions.len() as f64) * 100.0);
    
    print_all_ir_instructions(&ir_instructions);
    
    // ═══════════════════════════════════════════════════════════
    // 阶段 3: VM 字节码
    // ═══════════════════════════════════════════════════════════
    println!("\n\n【阶段 3】IR 转换为 VM 字节码");
    println!("{}", "═".repeat(80));
    let vm_compiler = IrToVmCompiler::new();
    let mut vm_commands: Vec<VMCommand> = Vec::new();
    for ir in &ir_instructions {
        let mut cmds = vm_compiler.compile(ir)?;
        vm_commands.append(&mut cmds);
    }
    println!("  VM 指令数: {} 条", vm_commands.len());
    println!("  转换比率: {:.1}%", (vm_commands.len() as f64 / ir_instructions.len() as f64) * 100.0);
    
    print_all_vm_commands(&vm_commands);
    
    // ═══════════════════════════════════════════════════════════
    // 阶段 4: 生成机器码
    // ═══════════════════════════════════════════════════════════
    println!("\n\n【阶段 4】VM 生成机器码");
    println!("{}", "═".repeat(80));
    let codegen = VmCodeGenerator::with_mode(mode);
    let machine_code = codegen.generate(&vm_commands)?;
    println!("  生成字节数: {} 字节", machine_code.len());
    println!("  扩展比率: {:.1}%", (machine_code.len() as f64 / code_bytes.len() as f64) * 100.0);
    
    // 打印完整机器码
    println!("\n  完整机器码 ({} 字节):", machine_code.len());
    for (i, chunk) in machine_code.chunks(16).enumerate() {
        let offset = i * 16;
        print!("    0x{:04X}: ", base_rva as u32 + offset as u32);
        for byte in chunk {
            print!("{:02X} ", byte);
        }
        println!();
    }
    
    // ═══════════════════════════════════════════════════════════
    // 阶段 5: 验证和对比
    // ═══════════════════════════════════════════════════════════
    println!("\n\n【阶段 5】验证 - 语义等价性对比");
    println!("{}", "═".repeat(80));
    let verified_instructions = disassemble(&machine_code, mode, base_rva)?;
    println!("  反汇编指令数: {} 条", verified_instructions.len());
    println!("  原始指令数: {} 条", instructions.len());
    
    print_all_generated_instructions(&verified_instructions);
    
    // 执行详细对比
    let (is_equivalent, mismatches) = verify_semantic_equivalence(
        &instructions,
        &verified_instructions,
        &vm_commands
    );
    
    // ═══════════════════════════════════════════════════════════
    // 验证结果总结
    // ═══════════════════════════════════════════════════════════
    println!("\n\n【验证结果】");
    println!("{}", "═".repeat(80));
    
    if mismatches.is_empty() {
        println!("  ✓✓✓ 所有检查通过！原始指令和生成指令语义等价 ✓✓✓");
    } else {
        println!("  发现以下差异:");
        for mismatch in &mismatches {
            println!("    {}", mismatch);
        }
    }
    
    // ═══════════════════════════════════════════════════════════
    // 最终总结
    // ═══════════════════════════════════════════════════════════
    println!("\n\n╔════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                              转换流程总结                                       ║");
    println!("╠════════════════════════════════════════════════════════════════════════════════╣");
    println!("║  原始 x86-64 指令:   {:4} 条                                                    ║", instructions.len());
    println!("║  IR 中间表示:        {:4} 条   (扩展率: {:.1}%)                              ║", 
        ir_instructions.len(), 
        (ir_instructions.len() as f64 / instructions.len().max(1) as f64) * 100.0
    );
    println!("║  VM 字节码:          {:4} 条   (压缩率: {:.1}%)                              ║", 
        vm_commands.len(),
        (vm_commands.len() as f64 / ir_instructions.len().max(1) as f64) * 100.0
    );
    println!("║  生成机器码:         {:4} 字节 (大小比: {:.1}%)                              ║", 
        machine_code.len(),
        (machine_code.len() as f64 / code_bytes.len().max(1) as f64) * 100.0
    );
    println!("╠════════════════════════════════════════════════════════════════════════════════╣");
    if is_equivalent {
        println!("║  验证结果: ✓✓✓ 语义等价 - 转换正确！                                          ║");
    } else {
        println!("║  验证结果: ✗✗✗ 存在差异 - 需要检查                                            ║");
    }
    println!("╚════════════════════════════════════════════════════════════════════════════════╝");
    
    Ok(())
}
