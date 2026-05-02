use vmp_core::pe::file::PeFile;
use vmp_core::pe::vmp_marker_finder::{VmpMarkerFinder, VmpMarkerType};
use vmp_core::intel::{disassemble_to_ir, DisassemblyMode};
use vmp_core::intel::ir_converter::IrConverter;
use vmp_core::vm::arch::{ArchConfig, VMRegister};
use vmp_core::vm::compiler::VmCompiler;
use vmp_core::vm::interpreter::InterpreterGenerator;
use vmp_core::vm::handlers::HandlerGenerator;
use vmp_core::vm::cfg::{ControlFlowGraph, VmBasicBlock};
use iced_x86::code_asm::CodeAssembler;
use vmp_core::intel::ir::{IrInstruction, IrOpcode, IrOperand, IrRegister, IrImmediate, IrMemoryOperand};
use std::path::PathBuf;

/// 运行 VM 转换测试
pub fn run_test(input: PathBuf, mode_str: String) -> Result<(), Box<dyn std::error::Error>> {
    let disasm_mode = match mode_str.as_str() {
        "16" => DisassemblyMode::Mode16,
        "32" => DisassemblyMode::Mode32,
        "64" => DisassemblyMode::Mode64,
        _ => DisassemblyMode::Mode64,
    };

    println!("正在加载 PE 文件: {:?}", input);
    let pe_file = PeFile::load(&input)?;
    
    // 1. 探测标记
    println!("正在探测虚拟化标记...");
    let finder = VmpMarkerFinder::with_mode(disasm_mode);
    let pairs = finder.find_marker_pairs(&pe_file)?;
    
    // 过滤出虚拟化标记
    let virt_pairs: Vec<_> = pairs.iter()
        .filter(|p| p.begin.marker_type == VmpMarkerType::Virtualization || 
                    p.begin.marker_type == VmpMarkerType::Begin)
        .collect();

    if virt_pairs.is_empty() {
        println!("未找到虚拟化标记，尝试运行内置测试用例...");
        
        // 构造一个测试代码: mov rax, 1; add rax, 2; ret
        let mut test_code = vec![0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00]; // mov rax, 1
        test_code.extend_from_slice(&[0x48, 0x83, 0xC0, 0x02]);           // add rax, 2
        test_code.extend_from_slice(&[0xC3]);                             // ret
        
        test_advanced_vm_pipeline(&pe_file, &test_code, 0x1000, disasm_mode)?;
        
        // 构造一个更复杂的测试用例：循环 + 内存读写
        let mut ir = Vec::new();
        let base_rva = 0x2000;
        
        // 1. 初始化内存 [RBP-0x10] = 0
        ir.push(IrInstruction::new(base_rva, IrOpcode::Mov { 
            dst: IrOperand::Memory(IrMemoryOperand::new_base_disp(IrRegister::Rbp, -0x10, 64)),
            src: IrOperand::Immediate(IrImmediate::U64(0)) 
        }));

        // 2. 循环开始标签 (L1)
        ir.push(IrInstruction::new(base_rva + 7, IrOpcode::Label { id: 1 }));
        
        // 3. 读取内存 -> RAX
        ir.push(IrInstruction::new(base_rva + 8, IrOpcode::Mov {
            dst: IrOperand::Register(IrRegister::Rax),
            src: IrOperand::Memory(IrMemoryOperand::new_base_disp(IrRegister::Rbp, -0x10, 64))
        }));

        // 4. RAX += 1
        ir.push(IrInstruction::new(base_rva + 12, IrOpcode::Add {
            dst: IrOperand::Register(IrRegister::Rax),
            src: IrOperand::Immediate(IrImmediate::U64(1))
        }));

        // 5. 写回内存
        ir.push(IrInstruction::new(base_rva + 16, IrOpcode::Mov {
            dst: IrOperand::Memory(IrMemoryOperand::new_base_disp(IrRegister::Rbp, -0x10, 64)),
            src: IrOperand::Register(IrRegister::Rax)
        }));

        // 6. 比较并跳转
        ir.push(IrInstruction::new(base_rva + 20, IrOpcode::Cmp {
            op1: IrOperand::Register(IrRegister::Rax),
            op2: IrOperand::Immediate(IrImmediate::U64(5))
        }));
        
        println!("[+] Generated {} IR instructions for complex test", ir.len());
        test_advanced_vm_pipeline_with_ir(&pe_file, &ir, disasm_mode)?;
        return Ok(());
    }
    
    println!("找到 {} 个标记对\n", virt_pairs.len());
    
    for (i, pair) in virt_pairs.iter().enumerate() {
        println!("=== 测试虚拟化标记 #{} ===", i + 1);
        println!("Begin RVA: 0x{:08X}", pair.begin.call_rva);
        println!("Code Range: 0x{:08X} - 0x{:08X} ({} bytes)", 
            pair.code_start, pair.code_end, pair.code_end - pair.code_start);
        
        // 提取标记范围内的代码
        let code_bytes = finder.read_protected_code(&pe_file, pair)?;
        if !code_bytes.is_empty() {
            test_advanced_vm_pipeline(&pe_file, &code_bytes, pair.code_start, disasm_mode)?;
        } else {
            println!("  跳过空代码块");
        }
    }

    Ok(())
}

fn test_advanced_vm_pipeline(pe_file: &PeFile, code_bytes: &[u8], base_rva: u64, mode: DisassemblyMode) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n【阶段 1】反汇编原始机器码并构建 CFG");
    let ir_instructions = disassemble_to_ir(code_bytes, mode, base_rva)?;
    let vm_cfg = ControlFlowGraph::from_ir(&ir_instructions, base_rva);
    println!("  解码基本块数: {} 个", vm_cfg.blocks.len());

    println!("\n【阶段 2】初始化 ArchConfig 架构");
    let arch_config = ArchConfig::new_random();
    println!("  Initial Crypt Key: {:#X}", arch_config.initial_crypt_key);

    println!("\n【阶段 3】编译 CFG 至加密 VM 字节码");
    let compiler = VmCompiler::new(&arch_config);
    let bytecode = compiler.compile_cfg(&vm_cfg);
    println!("  生成字节码大小: {} bytes", bytecode.len());
    
    Ok(())
}

fn test_advanced_vm_pipeline_with_ir(_pe_file: &PeFile, ir: &[IrInstruction], _mode: DisassemblyMode) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n【阶段 1】手动 IR 转为单块 CFG");
    let mut blocks = std::collections::HashMap::new();
    let entry_rva = ir.first().map(|i| i.rva).unwrap_or(0);
    blocks.insert(entry_rva, VmBasicBlock {
        id: 0,
        start_rva: entry_rva,
        instructions: ir.to_vec(),
        successor_rvas: vec![],
    });
    let vm_cfg = ControlFlowGraph {
        blocks,
        entry_rva,
    };

    println!("\n【阶段 2-3】启动 VM 编译器流程");
    let arch_config = ArchConfig::new_random();
    let compiler = VmCompiler::new(&arch_config);
    let bytecode = compiler.compile_cfg(&vm_cfg);
    println!("  生成字节码大小: {} bytes", bytecode.len());
    
    Ok(())
}
