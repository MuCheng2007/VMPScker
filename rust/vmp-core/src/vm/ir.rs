use crate::vm::opcode::VmOpcode;

#[derive(Debug, Clone)]
pub struct VmInstruction {
    pub opcode: VmOpcode,
    pub address_offset: u64,
    pub handler_id: u32,
    pub crypt_key: Option<u32>,
    pub native_bytes: Option<Vec<u8>>,
}

impl VmInstruction {
    pub fn new(opcode: VmOpcode) -> Self {
        Self {
            opcode,
            address_offset: 0,
            handler_id: 0,
            crypt_key: None,
            native_bytes: None,
        }
    }

    pub fn new_native(bytes: Vec<u8>) -> Self {
        Self {
            opcode: VmOpcode::VNop, // Dummy opcode for native island
            address_offset: 0,
            handler_id: 0,
            crypt_key: None,
            native_bytes: Some(bytes),
        }
    }
}
