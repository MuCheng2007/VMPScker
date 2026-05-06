use iced_x86::Decoder;

fn main() {
    // 指令: call qword ptr [rip+0x30FE] at RVA 0x1024
    // 机器码: FF 15 FE 30 00 00
    let data = [0xFF, 0x15, 0xFE, 0x30, 0x00, 0x00];
    let ip = 0x1024u64;
    
    let mut decoder = Decoder::with_ip(64, &data, ip, iced_x86::DecoderOptions::NONE);
    
    if let Some(insn) = decoder.decode() {
        println!("Instruction: {}", insn);
        println!("IP: 0x{:08X}", insn.ip());
        println!("Next IP: 0x{:08X}", insn.next_ip());
        println!("Memory displacement32: 0x{:08X}", insn.memory_displacement32());
        println!("Memory displacement64: 0x{:016X}", insn.memory_displacement64());
        
        // 计算目标地址
        let next_ip = insn.next_ip() as i64;
        let displ = insn.memory_displacement32() as i32 as i64;
        let target = (next_ip + displ) as u64;
        println!("Target address: 0x{:08X}", target);
        println!("Expected target: 0x4128");
    }
}
