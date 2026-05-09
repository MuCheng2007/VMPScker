use super::Instruction;

pub struct Function {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub instructions: Vec<Instruction>,
}
