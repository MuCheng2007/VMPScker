//! VM 转换测试
//!
//! 测试从 x86 汇编代码到 VM 字节码再到机器码的完整流程

use crate::error::Result;
use crate::intel::{DisassemblyMode, disassemble};
use crate::ir::{IrConverter, IrInstruction};
use crate::vm::{IrToVmCompiler, VmToIrConverter, CodeGenerator};

/// 测试 VM 转换流程
pub fn test_vm_conversion(code_bytes: &[u8], base_rva: u64) -> Result<VmConversionResult> {
    println!("=== VM 转换测试 ===\n");
    
    // 步骤 1: 反汇编原始代码
    println!("步骤 1: 反汇编原始代码");
    let instructions = disassemble(code_bytes, DisassemblyMode::Mode64, base_rva)?;
    println!("  反汇编得到 {} 条指令\n", instructions.len());
    
    // 步骤 2: 转换为 IR
    println!("步骤 2: 转换为 IR");
    let mut ir_converter = IrConverter::new();
    let ir_instructions = ir_converter.convert_to_ir(&instructions)?;
    println!("  转换为 {} 条 IR 指令\n", ir_instructions.len());
    
    // 打印 IR 指令
    for (i, ir) in ir_instructions.iter().enumerate() {
        println!("  IR[{}]: {:?}", i, ir);
    }
    println!();
    
    // 步骤 3: IR 转换为 VM 字节码
    println!("步骤 3: IR 转换为 VM 字节码");
    let mut vm_compiler = IrToVmCompiler::new();
    let vm_bytecode = vm_compiler.compile(&ir_instructions)?;
    println!("  生成 {} 字节 VM 字节码\n", vm_bytecode.len());
    
    // 打印 VM 字节码（前 64 字节）
    print!("  VM 字节码: ");
    for (i, byte) in vm_bytecode.iter().take(64).enumerate() {
        if i > 0 && i % 16 == 0 {
            print!("\n             ");
        }
        print!("{:02X} ", byte);
    }
    if vm_bytecode.len() > 64 {
        println!("... (共 {} 字节)", vm_bytecode.len());
    } else {
        println!();
    }
    println!();
    
    // 步骤 4: VM 字节码转换回 IR
    println!("步骤 4: VM 字节码转换回 IR");
    let mut vm_to_ir = VmToIrConverter::new();
    let restored_ir = vm_to_ir.convert(&vm_bytecode, base_rva)?;
    println!("  恢复为 {} 条 IR 指令\n", restored_ir.len());
    
    // 步骤 5: IR 生成机器码
    println!("步骤 5: IR 生成机器码");
    let mut codegen = CodeGenerator::new(DisassemblyMode::Mode64);
    let machine_code = codegen.generate(&restored_ir)?;
    println!("  生成 {} 字节机器码\n", machine_code.len());
    
    // 打印机器码（前 64 字节）
    print!("  机器码: ");
    for (i, byte) in machine_code.iter().take(64).enumerate() {
        if i > 0 && i % 16 == 0 {
            print!("\n          ");
        }
        print!("{:02X} ", byte);
    }
    if machine_code.len() > 64 {
        println!("... (共 {} 字节)", machine_code.len());
    } else {
        println!();
    }
    println!();
    
    // 验证：反汇编生成的机器码
    println!("步骤 6: 验证 - 反汇编生成的机器码");
    let verified_instructions = disassemble(&machine_code, DisassemblyMode::Mode64, base_rva)?;
    println!("  反汇编得到 {} 条指令\n", verified_instructions.len());
    
    // 打印前 10 条指令
    for (i, inst) in verified_instructions.iter().take(10).enumerate() {
        println!("  0x{:08X}: {}", inst.ip(), inst.mnemonic());
    }
    if verified_instructions.len() > 10 {
        println!("  ... (共 {} 条指令)", verified_instructions.len());
    }
    
    Ok(VmConversionResult {
        original_instruction_count: instructions.len(),
        ir_instruction_count: ir_instructions.len(),
        vm_bytecode_size: vm_bytecode.len(),
        restored_ir_count: restored_ir.len(),
        machine_code_size: machine_code.len(),
        verified_instruction_count: verified_instructions.len(),
        machine_code,
    })
}

/// VM 转换结果
pub struct VmConversionResult {
    pub original_instruction_count: usize,
    pub ir_instruction_count: usize,
    pub vm_bytecode_size: usize,
    pub restored_ir_count: usize,
    pub machine_code_size: usize,
    pub verified_instruction_count: usize,
    pub machine_code: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_vm_conversion() {
        // 简单的测试代码: mov rax, 0x1234; ret
        let code = vec![
            0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00,  // mov rax, 0x1234
            0xC3,                                      // ret
        ];
        
        let result = test_vm_conversion(&code, 0x1000).unwrap();
        
        assert!(result.ir_instruction_count > 0);
        assert!(result.vm_bytecode_size > 0);
        assert!(result.machine_code_size > 0);
    }
}
