pub enum Operand {
    Register(String),
    Immediate(u64),
    Memory { base: Option<String>, index: Option<String>, scale: u32, displacement: i64 },
}
