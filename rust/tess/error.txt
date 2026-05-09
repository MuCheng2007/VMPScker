use thiserror::Error;

#[derive(Error, Debug)]
pub enum VmpError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PE parse error: {0}")]
    PeParse(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Compilation error: {0}")]
    Compilation(String),

    #[error("Index out of range")]
    IndexOutOfRange,

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Disassembly error: {0}")]
    Disassembly(String),

    #[error("VM error: {0}")]
    VM(String),
}

impl VmpError {
    /// 创建 VM 错误
    pub fn vm_error(msg: impl Into<String>) -> Self {
        VmpError::VM(msg.into())
    }
}

pub type Result<T> = std::result::Result<T, VmpError>;
