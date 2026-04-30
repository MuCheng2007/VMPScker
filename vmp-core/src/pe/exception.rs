//! PE 异常处理目录 (x64 UNWIND_INFO)
//!
//! 支持解析和重建 x64 PE 文件的异常处理信息。

use crate::error::{Result, VmpError};
use std::collections::HashMap;

/// Unwind 操作码
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UnwindOp {
    /// 无操作
    Nop = 0,
    /// 分配大栈空间（16-512字节）
    AllocLarge = 1,
    /// 分配小栈空间（8字节）
    AllocSmall = 2,
    /// 设置帧寄存器
    SetFpReg = 3,
    /// 保存非易失性寄存器（整数）
    SaveNonVol = 4,
    /// 保存非易失性寄存器（整数，远）
    SaveNonVolFar = 5,
    /// 保存XMM128寄存器
    SaveXmm128 = 6,
    /// 保存XMM128寄存器（远）
    SaveXmm128Far = 7,
    /// 推送机器帧
    PushMachFrame = 8,
    /// 设置Epilog（ARM64）
    SetEpilog = 9,
    /// 稀疏打包（ARM64）
    SparsePack = 10,
    /// 保存下一个R19/R20（ARM64）
    SaveNextR19R20 = 11,
    /// 保存任何寄存器（ARM64）
    SaveAnyReg = 12,
    /// 保存任何寄存器对（ARM64）
    SaveAnyRegPair = 13,
    /// 保存任何寄存器对远（ARM64）
    SaveAnyRegPairFar = 14,
    /// 保存任何寄存器远（ARM64）
    SaveAnyRegFar = 15,
}

impl UnwindOp {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Nop),
            1 => Some(Self::AllocLarge),
            2 => Some(Self::AllocSmall),
            3 => Some(Self::SetFpReg),
            4 => Some(Self::SaveNonVol),
            5 => Some(Self::SaveNonVolFar),
            6 => Some(Self::SaveXmm128),
            7 => Some(Self::SaveXmm128Far),
            8 => Some(Self::PushMachFrame),
            9 => Some(Self::SetEpilog),
            10 => Some(Self::SparsePack),
            11 => Some(Self::SaveNextR19R20),
            12 => Some(Self::SaveAnyReg),
            13 => Some(Self::SaveAnyRegPair),
            14 => Some(Self::SaveAnyRegPairFar),
            15 => Some(Self::SaveAnyRegFar),
            _ => None,
        }
    }

    /// 获取操作码的大小（字节）
    pub fn size(&self) -> usize {
        match self {
            Self::Nop | Self::PushMachFrame => 1,
            Self::AllocSmall | Self::SetFpReg => 1,
            Self::AllocLarge => 2,
            Self::SaveNonVol | Self::SaveXmm128 => 2,
            Self::SaveNonVolFar | Self::SaveXmm128Far => 3,
            _ => 1,
        }
    }

    /// 获取操作码的描述
    pub fn description(&self) -> &'static str {
        match self {
            Self::Nop => "No operation",
            Self::AllocLarge => "Allocate large stack space (16-512 bytes)",
            Self::AllocSmall => "Allocate small stack space (8 bytes * n)",
            Self::SetFpReg => "Set frame pointer register",
            Self::SaveNonVol => "Save non-volatile register",
            Self::SaveNonVolFar => "Save non-volatile register (far)",
            Self::SaveXmm128 => "Save XMM128 register",
            Self::SaveXmm128Far => "Save XMM128 register (far)",
            Self::PushMachFrame => "Push machine frame",
            Self::SetEpilog => "Set epilog (ARM64)",
            Self::SparsePack => "Sparse pack (ARM64)",
            Self::SaveNextR19R20 => "Save next R19/R20 (ARM64)",
            Self::SaveAnyReg => "Save any register (ARM64)",
            Self::SaveAnyRegPair => "Save any register pair (ARM64)",
            Self::SaveAnyRegPairFar => "Save any register pair far (ARM64)",
            Self::SaveAnyRegFar => "Save any register far (ARM64)",
        }
    }

    /// 检查是否是x64操作码
    pub fn is_x64(&self) -> bool {
        matches!(self, Self::Nop | Self::AllocLarge | Self::AllocSmall |
                 Self::SetFpReg | Self::SaveNonVol | Self::SaveNonVolFar |
                 Self::SaveXmm128 | Self::SaveXmm128Far | Self::PushMachFrame)
    }

    /// 检查是否是ARM64操作码
    pub fn is_arm64(&self) -> bool {
        matches!(self, Self::SetEpilog | Self::SparsePack | Self::SaveNextR19R20 |
                 Self::SaveAnyReg | Self::SaveAnyRegPair | Self::SaveAnyRegPairFar |
                 Self::SaveAnyRegFar)
    }
}

/// 扩展的Unwind操作码信息
#[derive(Debug, Clone)]
pub struct UnwindOpInfo {
    pub op: UnwindOp,
    pub register: Option<u8>,       // 涉及的寄存器
    pub offset: Option<u64>,        // 栈偏移
    pub size: Option<u32>,          // 操作大小
}

impl UnwindOpInfo {
    pub fn new(op: UnwindOp) -> Self {
        Self {
            op,
            register: None,
            offset: None,
            size: None,
        }
    }

    pub fn with_register(mut self, reg: u8) -> Self {
        self.register = Some(reg);
        self
    }

    pub fn with_offset(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }

    pub fn with_size(mut self, size: u32) -> Self {
        self.size = Some(size);
        self
    }
}

/// 栈帧操作类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameOperation {
    PushRegister(u8),           // 推送寄存器
    AllocateStack(u64),         // 分配栈空间
    SetFramePointer(u8, u8),    // 设置帧指针 (寄存器, 偏移)
    SaveRegister(u8, u64),      // 保存寄存器到栈 (寄存器, 栈偏移)
    SaveXmm(u8, u64),           // 保存XMM寄存器 (寄存器, 栈偏移)
    PushMachineFrame,           // 推送机器帧
}

impl FrameOperation {
    /// 获取操作描述
    pub fn description(&self) -> String {
        match self {
            Self::PushRegister(reg) => format!("Push register {}", reg),
            Self::AllocateStack(size) => format!("Allocate {} bytes of stack", size),
            Self::SetFramePointer(reg, offset) => format!("Set frame pointer: R{} + {}", reg, offset),
            Self::SaveRegister(reg, offset) => format!("Save register {} at stack offset {}", reg, offset),
            Self::SaveXmm(reg, offset) => format!("Save XMM{} at stack offset {}", reg, offset),
            Self::PushMachineFrame => "Push machine frame".to_string(),
        }
    }
}

/// Unwind 代码
#[derive(Debug, Clone)]
pub struct UnwindCode {
    pub code_offset: u8,
    pub unwind_op: UnwindOp,
    pub op_info: u8,
    pub frame_offset: u16,
}

impl UnwindCode {
    pub fn new(code_offset: u8, unwind_op: UnwindOp, op_info: u8) -> Self {
        Self {
            code_offset,
            unwind_op,
            op_info,
            frame_offset: 0,
        }
    }

    pub fn with_frame_offset(mut self, offset: u16) -> Self {
        self.frame_offset = offset;
        self
    }

    /// 从字节解析
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 2 {
            return None;
        }

        let code_offset = data[0];
        let unwind_op_code = data[1] & 0x0F;
        let op_info = (data[1] >> 4) & 0x0F;

        let unwind_op = UnwindOp::from_u8(unwind_op_code)?;
        let mut consumed = 2;
        let mut frame_offset = 0u16;

        // 根据操作码解析额外数据
        match unwind_op {
            UnwindOp::AllocLarge => {
                if data.len() >= 4 {
                    frame_offset = u16::from_le_bytes([data[2], data[3]]);
                    consumed = 4;
                }
            }
            UnwindOp::SaveNonVol | UnwindOp::SaveXmm128 => {
                if data.len() >= 4 {
                    frame_offset = u16::from_le_bytes([data[2], data[3]]);
                    consumed = 4;
                }
            }
            UnwindOp::SaveNonVolFar | UnwindOp::SaveXmm128Far => {
                if data.len() >= 6 {
                    frame_offset = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as u16;
                    consumed = 6;
                }
            }
            _ => {}
        }

        Some((Self::new(code_offset, unwind_op, op_info).with_frame_offset(frame_offset), consumed))
    }

    /// 编码为字节
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.code_offset);
        bytes.push((self.op_info << 4) | (self.unwind_op as u8));

        match self.unwind_op {
            UnwindOp::AllocLarge => {
                bytes.extend_from_slice(&self.frame_offset.to_le_bytes());
            }
            UnwindOp::SaveNonVol | UnwindOp::SaveXmm128 => {
                bytes.extend_from_slice(&self.frame_offset.to_le_bytes());
            }
            UnwindOp::SaveNonVolFar | UnwindOp::SaveXmm128Far => {
                bytes.extend_from_slice(&(self.frame_offset as u32).to_le_bytes());
            }
            _ => {}
        }

        bytes
    }
}

/// Unwind 信息标志
#[derive(Debug, Clone, Copy)]
pub struct UnwindInfoFlags {
    pub has_exception_handler: bool,
    pub has_unwind_code: bool,
    pub chained: bool,
}

impl UnwindInfoFlags {
    pub fn from_u8(flags: u8) -> Self {
        Self {
            has_exception_handler: (flags & 0x01) != 0,
            has_unwind_code: (flags & 0x02) != 0,
            chained: (flags & 0x04) != 0,
        }
    }

    pub fn to_u8(&self) -> u8 {
        let mut flags = 0u8;
        if self.has_exception_handler {
            flags |= 0x01;
        }
        if self.has_unwind_code {
            flags |= 0x02;
        }
        if self.chained {
            flags |= 0x04;
        }
        flags
    }
}

/// Unwind 信息
#[derive(Debug, Clone)]
pub struct UnwindInfo {
    pub version: u8,
    pub flags: UnwindInfoFlags,
    pub size_of_prolog: u8,
    pub count_of_codes: u8,
    pub frame_register: u8,
    pub frame_offset: u8,
    pub unwind_codes: Vec<UnwindCode>,
    pub exception_handler: Option<u32>,
    pub chained_info: Option<Box<UnwindInfo>>,
}

impl UnwindInfo {
    pub fn new() -> Self {
        Self {
            version: 1,
            flags: UnwindInfoFlags::from_u8(0),
            size_of_prolog: 0,
            count_of_codes: 0,
            frame_register: 0,
            frame_offset: 0,
            unwind_codes: Vec::new(),
            exception_handler: None,
            chained_info: None,
        }
    }

    /// 从数据解析
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }

        let version = data[0] & 0x07;
        let flags = UnwindInfoFlags::from_u8((data[0] >> 3) & 0x1F);
        let size_of_prolog = data[1];
        let count_of_codes = data[2];
        let frame_register_and_offset = data[3];
        let frame_register = frame_register_and_offset & 0x0F;
        let frame_offset = (frame_register_and_offset >> 4) & 0x0F;

        let mut info = Self {
            version,
            flags,
            size_of_prolog,
            count_of_codes,
            frame_register,
            frame_offset,
            unwind_codes: Vec::new(),
            exception_handler: None,
            chained_info: None,
        };

        let mut offset = 4;

        // 解析 unwind codes
        let code_count = count_of_codes as usize;
        for _ in 0..code_count {
            if offset >= data.len() {
                break;
            }
            if let Some((code, consumed)) = UnwindCode::parse(&data[offset..]) {
                info.unwind_codes.push(code);
                offset += consumed;
            } else {
                break;
            }
        }

        // 对齐到 4 字节边界
        offset = (offset + 3) & !3;

        // 解析异常处理程序地址（如果存在）
        if flags.has_exception_handler && offset + 4 <= data.len() {
            info.exception_handler = Some(u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]));
            offset += 4;
        }

        // 解析链式 unwind info（如果存在）
        if flags.chained && offset + 4 <= data.len() {
            // 链式信息是另一个 UnwindInfo 的 RVA
            let chained_rva = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            // 注意：这里需要外部数据来解析链式信息
            offset += 4;
        }

        Some((info, offset))
    }

    /// 重建为字节
    pub fn rebuild(&self) -> Vec<u8> {
        let mut data = Vec::new();

        let version_and_flags = (self.version & 0x07) | (self.flags.to_u8() << 3);
        data.push(version_and_flags);
        data.push(self.size_of_prolog);
        data.push(self.count_of_codes);
        data.push((self.frame_offset << 4) | (self.frame_register & 0x0F));

        // 写入 unwind codes
        for code in &self.unwind_codes {
            data.extend_from_slice(&code.to_bytes());
        }

        // 对齐到 4 字节边界
        while data.len() % 4 != 0 {
            data.push(0);
        }

        // 写入异常处理程序地址
        if let Some(handler) = self.exception_handler {
            data.extend_from_slice(&handler.to_le_bytes());
        }

        data
    }

    /// 计算大小
    pub fn size(&self) -> usize {
        let mut size = 4; // 头部
        for code in &self.unwind_codes {
            size += code.unwind_op.size();
        }
        size = (size + 3) & !3; // 对齐
        if self.exception_handler.is_some() {
            size += 4;
        }
        size
    }

    /// 解析所有栈帧操作
    pub fn parse_frame_operations(&self) -> Vec<FrameOperation> {
        let mut operations = Vec::new();

        for code in &self.unwind_codes {
            let op = match code.unwind_op {
                UnwindOp::AllocSmall => {
                    let size = (code.op_info as u64 + 1) * 8;
                    Some(FrameOperation::AllocateStack(size))
                }
                UnwindOp::AllocLarge => {
                    let size = if code.op_info == 0 {
                        (code.frame_offset as u64) * 8
                    } else {
                        (code.frame_offset as u64) * 8 + 0x10000
                    };
                    Some(FrameOperation::AllocateStack(size))
                }
                UnwindOp::SetFpReg => {
                    Some(FrameOperation::SetFramePointer(code.op_info, self.frame_offset))
                }
                UnwindOp::SaveNonVol => {
                    let offset = code.frame_offset as u64 * 8;
                    Some(FrameOperation::SaveRegister(code.op_info, offset))
                }
                UnwindOp::SaveNonVolFar => {
                    let offset = code.frame_offset as u64 * 8;
                    Some(FrameOperation::SaveRegister(code.op_info, offset))
                }
                UnwindOp::SaveXmm128 => {
                    let offset = code.frame_offset as u64 * 16;
                    Some(FrameOperation::SaveXmm(code.op_info, offset))
                }
                UnwindOp::SaveXmm128Far => {
                    let offset = code.frame_offset as u64 * 16;
                    Some(FrameOperation::SaveXmm(code.op_info, offset))
                }
                UnwindOp::PushMachFrame => {
                    Some(FrameOperation::PushMachineFrame)
                }
                _ => None,
            };

            if let Some(frame_op) = op {
                operations.push(frame_op);
            }
        }

        operations
    }

    /// 计算栈帧大小
    pub fn calculate_stack_frame_size(&self) -> u64 {
        let mut total_size = 0u64;

        for op in self.parse_frame_operations() {
            match op {
                FrameOperation::AllocateStack(size) => total_size += size,
                _ => {}
            }
        }

        total_size
    }

    /// 获取被保存的寄存器列表
    /// 返回: (寄存器编号, 栈偏移)
    pub fn get_saved_registers(&self) -> Vec<(u8, u64)> {
        let mut registers = Vec::new();

        for op in self.parse_frame_operations() {
            match op {
                FrameOperation::SaveRegister(reg, offset) => {
                    registers.push((reg, offset));
                }
                _ => {}
            }
        }

        registers
    }

    /// 获取保存的XMM寄存器列表
    /// 返回: (寄存器编号, 栈偏移)
    pub fn get_saved_xmm_registers(&self) -> Vec<(u8, u64)> {
        let mut registers = Vec::new();

        for op in self.parse_frame_operations() {
            match op {
                FrameOperation::SaveXmm(reg, offset) => {
                    registers.push((reg, offset));
                }
                _ => {}
            }
        }

        registers
    }

    /// 获取函数序言(prolog)的详细指令信息
    pub fn get_prolog_info(&self) -> PrologInfo {
        PrologInfo {
            size: self.size_of_prolog,
            frame_register: if self.frame_register != 0 {
                Some(self.frame_register)
            } else {
                None
            },
            frame_offset: self.frame_offset,
            operations: self.parse_frame_operations(),
        }
    }

    /// 解析链式的Unwind Info
    /// 
    /// # Arguments
    /// * `data` - 包含链式信息的原始数据
    /// * `base_rva` - 基址RVA
    /// 
    /// 返回解析后的UnwindInfo和消耗的字节数
    pub fn parse_chained(data: &[u8], base_rva: u32) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }

        // 链式信息是另一个UnwindInfo的RVA
        let chained_rva = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        
        // 注意：这里需要外部数据来解析链式信息
        // 实际解析需要访问PE文件的资源节
        let offset = (chained_rva - base_rva) as usize;
        
        // 尝试解析链式UnwindInfo
        Self::parse(&data[offset..]).map(|(info, size)| (info, size + 4))
    }

    /// 获取完整的Unwind链
    pub fn get_unwind_chain(&self) -> Vec<&UnwindInfo> {
        let mut chain = vec![self];
        
        let mut current = self;
        while let Some(ref chained) = current.chained_info {
            chain.push(chained);
            current = chained;
        }
        
        chain
    }

    /// 重建链式结构
    pub fn rebuild_chained(&self, chained_infos: &[UnwindInfo]) -> Vec<u8> {
        let mut data = self.rebuild();
        
        for chained in chained_infos {
            let chained_data = chained.rebuild();
            data.extend_from_slice(&chained_data);
        }
        
        data
    }

    /// 验证UnwindInfo的有效性
    pub fn validate(&self) -> std::result::Result<(), String> {
        // 验证版本
        if self.version != 1 {
            return Err(format!("Unsupported unwind info version: {}", self.version));
        }

        // 验证代码数量
        if self.unwind_codes.len() != self.count_of_codes as usize {
            return Err(format!("Unwind code count mismatch: {} vs {}", 
                self.unwind_codes.len(), self.count_of_codes));
        }

        // 验证帧寄存器
        if self.frame_register > 15 {
            return Err(format!("Invalid frame register: {}", self.frame_register));
        }

        Ok(())
    }
}

/// 函数序言信息
#[derive(Debug, Clone)]
pub struct PrologInfo {
    pub size: u8,
    pub frame_register: Option<u8>,
    pub frame_offset: u8,
    pub operations: Vec<FrameOperation>,
}

impl PrologInfo {
    /// 获取序言大小
    pub fn size(&self) -> u8 {
        self.size
    }

    /// 检查是否使用帧指针
    pub fn uses_frame_pointer(&self) -> bool {
        self.frame_register.is_some()
    }

    /// 获取操作数量
    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }
}

impl Default for UnwindInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// 运行时函数（异常处理表条目）
#[derive(Debug, Clone)]
pub struct RuntimeFunction {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_info_rva: u32,
    pub unwind_info: Option<UnwindInfo>,
}

impl RuntimeFunction {
    pub fn new(begin_address: u32, end_address: u32, unwind_info_rva: u32) -> Self {
        Self {
            begin_address,
            end_address,
            unwind_info_rva,
            unwind_info: None,
        }
    }

    /// 从数据解析
    pub fn parse(data: &[u8], is_64bit: bool) -> Option<(Self, usize)> {
        let entry_size = if is_64bit { 12 } else { 8 };
        if data.len() < entry_size {
            return None;
        }

        let begin_address = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let end_address = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let unwind_info_rva = if is_64bit {
            u32::from_le_bytes([data[8], data[9], data[10], data[11]])
        } else {
            u32::from_le_bytes([data[4], data[5], data[6], data[7]]) // 32-bit uses different format
        };

        Some((Self::new(begin_address, end_address, unwind_info_rva), entry_size))
    }

    /// 重建为字节
    pub fn rebuild(&self, is_64bit: bool) -> Vec<u8> {
        let mut data = Vec::with_capacity(if is_64bit { 12 } else { 8 });
        data.extend_from_slice(&self.begin_address.to_le_bytes());
        data.extend_from_slice(&self.end_address.to_le_bytes());
        if is_64bit {
            data.extend_from_slice(&self.unwind_info_rva.to_le_bytes());
        }
        data
    }

    /// 更新地址
    pub fn update_addresses(&mut self, address_map: &HashMap<u32, u32>) {
        if let Some(&new_addr) = address_map.get(&self.begin_address) {
            self.begin_address = new_addr;
        }
        if let Some(&new_addr) = address_map.get(&self.end_address) {
            self.end_address = new_addr;
        }
    }

    /// 获取函数大小
    pub fn function_size(&self) -> u32 {
        self.end_address.saturating_sub(self.begin_address)
    }
}

/// 运行时函数列表
#[derive(Debug, Clone)]
pub struct RuntimeFunctionList {
    functions: Vec<RuntimeFunction>,
}

impl RuntimeFunctionList {
    pub fn new() -> Self {
        Self {
            functions: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.functions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&RuntimeFunction> {
        self.functions.get(index)
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut RuntimeFunction> {
        self.functions.get_mut(index)
    }

    pub fn iter(&self) -> impl Iterator<Item = &RuntimeFunction> {
        self.functions.iter()
    }

    pub fn add(&mut self, function: RuntimeFunction) {
        self.functions.push(function);
    }

    /// 查找包含指定 RVA 的函数
    pub fn find_function(&self, rva: u32) -> Option<&RuntimeFunction> {
        self.functions.iter().find(|f| {
            rva >= f.begin_address && rva < f.end_address
        })
    }

    /// 从数据解析
    pub fn parse(data: &[u8], size: u32, is_64bit: bool) -> Self {
        let mut list = Self::new();
        let entry_size = if is_64bit { 12 } else { 8 };
        let count = (size as usize) / entry_size;
        let mut offset = 0;

        for _ in 0..count {
            if offset + entry_size > data.len() {
                break;
            }
            if let Some((func, consumed)) = RuntimeFunction::parse(&data[offset..], is_64bit) {
                list.add(func);
                offset += consumed;
            } else {
                break;
            }
        }

        list
    }

    /// 重建为字节
    pub fn rebuild(&self, is_64bit: bool) -> Vec<u8> {
        let mut data = Vec::new();
        for func in &self.functions {
            data.extend_from_slice(&func.rebuild(is_64bit));
        }
        data
    }

    /// 更新所有地址
    pub fn update_addresses(&mut self, address_map: &HashMap<u32, u32>) {
        for func in &mut self.functions {
            func.update_addresses(address_map);
        }
    }

    /// 查找包含指定地址的函数并返回其 unwind info
    pub fn find_unwind_info(&self, rva: u32) -> Option<&UnwindInfo> {
        self.find_function(rva)
            .and_then(|f| f.unwind_info.as_ref())
    }

    /// 获取函数的所有Unwind信息（包括链式）
    pub fn get_full_unwind_info(&self, index: usize, data: &[u8]) -> Option<FullUnwindInfo> {
        let func = self.functions.get(index)?;
        
        if let Some(ref unwind_info) = func.unwind_info {
            let chain = unwind_info.get_unwind_chain();
            Some(FullUnwindInfo {
                primary: unwind_info.clone(),
                chain: chain.into_iter().skip(1).cloned().collect(),
            })
        } else {
            None
        }
    }

    /// 查找包含指定地址范围的函数
    pub fn find_functions_in_range(&self, begin: u32, end: u32) -> Vec<&RuntimeFunction> {
        self.functions.iter()
            .filter(|f| {
                (f.begin_address >= begin && f.begin_address < end) ||
                (f.end_address > begin && f.end_address <= end) ||
                (f.begin_address <= begin && f.end_address >= end)
            })
            .collect()
    }

    /// 验证所有运行时函数的完整性
    pub fn validate_all(&self, data: &[u8]) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        for (i, func) in self.functions.iter().enumerate() {
            // 验证地址范围
            if func.begin_address >= func.end_address {
                errors.push(ValidationError {
                    index: i,
                    error_type: ValidationErrorType::InvalidRange,
                    message: format!("Begin address (0x{:08X}) >= end address (0x{:08X})", 
                        func.begin_address, func.end_address),
                });
            }

            // 验证UnwindInfo
            if let Some(ref unwind_info) = func.unwind_info {
                if let Err(msg) = unwind_info.validate() {
                    errors.push(ValidationError {
                        index: i,
                        error_type: ValidationErrorType::InvalidUnwindInfo,
                        message: msg.to_string(),
                    });
                }
            }
        }

        errors
    }

    /// 合并相邻的函数条目（优化）
    pub fn merge_adjacent(&mut self) {
        if self.functions.len() < 2 {
            return;
        }

        // 按起始地址排序
        self.functions.sort_by_key(|f| f.begin_address);

        let mut i = 0;
        while i < self.functions.len() - 1 {
            let current_end = self.functions[i].end_address;
            let next_begin = self.functions[i + 1].begin_address;

            // 如果相邻或重叠，合并
            if current_end >= next_begin {
                self.functions[i].end_address = self.functions[i].end_address.max(self.functions[i + 1].end_address);
                self.functions.remove(i + 1);
            } else {
                i += 1;
            }
        }
    }

    /// 分割函数条目
    pub fn split_function(&mut self, index: usize, split_address: u32) -> std::result::Result<(), String> {
        if index >= self.functions.len() {
            return Err("Index out of bounds".to_string());
        }

        let func = &self.functions[index];
        
        if split_address <= func.begin_address || split_address >= func.end_address {
            return Err("Split address out of function range".to_string());
        }

        // 创建新的函数条目
        let new_func = RuntimeFunction::new(
            split_address,
            func.end_address,
            func.unwind_info_rva,
        );

        // 更新原函数
        self.functions[index].end_address = split_address;

        // 插入新函数
        self.functions.insert(index + 1, new_func);

        Ok(())
    }

    /// 获取函数数量
    pub fn count(&self) -> usize {
        self.functions.len()
    }

    /// 清空所有函数
    pub fn clear(&mut self) {
        self.functions.clear();
    }

    /// 批量添加函数
    pub fn add_batch(&mut self, functions: Vec<RuntimeFunction>) {
        self.functions.extend(functions);
    }
}

/// 完整的Unwind信息（包括链式）
#[derive(Debug, Clone)]
pub struct FullUnwindInfo {
    pub primary: UnwindInfo,
    pub chain: Vec<UnwindInfo>,
}

impl FullUnwindInfo {
    /// 获取所有Unwind信息（包括链式）
    pub fn all_unwind_infos(&self) -> Vec<&UnwindInfo> {
        let mut all = vec![&self.primary];
        for info in &self.chain {
            all.push(info);
        }
        all
    }

    /// 获取链式信息数量
    pub fn chain_count(&self) -> usize {
        self.chain.len()
    }
}

/// 验证错误类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationErrorType {
    InvalidRange,
    InvalidUnwindInfo,
    MissingUnwindInfo,
}

/// 验证错误
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub index: usize,
    pub error_type: ValidationErrorType,
    pub message: String,
}

/// 异常处理程序类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionHandlerType {
    SpecificHandler,    // __C_specific_handler
    CxxFrameHandler,    // __CxxFrameHandler3
    GsHandlerCheck,     // __GSHandlerCheck
    GsHandlerCheckSeh,  // __GSHandlerCheck_SEH
    SecurityCookie,     // 安全Cookie检查
    Custom(u32),        // 自定义处理器
}

impl ExceptionHandlerType {
    /// 从RVA识别处理器类型
    pub fn from_rva(rva: u32) -> Self {
        // 这里应该根据RVA查找符号来确定类型
        // 简化实现，返回Custom
        Self::Custom(rva)
    }

    /// 获取处理器名称
    pub fn name(&self) -> String {
        match self {
            Self::SpecificHandler => "__C_specific_handler".to_string(),
            Self::CxxFrameHandler => "__CxxFrameHandler3".to_string(),
            Self::GsHandlerCheck => "__GSHandlerCheck".to_string(),
            Self::GsHandlerCheckSeh => "__GSHandlerCheck_SEH".to_string(),
            Self::SecurityCookie => "__security_cookie".to_string(),
            Self::Custom(rva) => format!("CustomHandler_0x{:08X}", rva),
        }
    }
}

/// 异常处理信息
#[derive(Debug, Clone)]
pub struct ExceptionHandlerInfo {
    pub handler_rva: u32,
    pub data_rva: Option<u32>,      // 处理器数据
    pub handler_type: ExceptionHandlerType,
}

impl ExceptionHandlerInfo {
    pub fn new(handler_rva: u32) -> Self {
        Self {
            handler_rva,
            data_rva: None,
            handler_type: ExceptionHandlerType::from_rva(handler_rva),
        }
    }

    pub fn with_data_rva(mut self, data_rva: u32) -> Self {
        self.data_rva = Some(data_rva);
        self
    }
}

/// 作用域记录（SEH）
#[derive(Debug, Clone)]
pub struct ScopeRecord {
    pub begin_address: u32,
    pub end_address: u32,
    pub handler_address: u32,
    pub jump_target: u32,
}

impl ScopeRecord {
    pub fn new(begin: u32, end: u32, handler: u32, jump: u32) -> Self {
        Self {
            begin_address: begin,
            end_address: end,
            handler_address: handler,
            jump_target: jump,
        }
    }

    /// 从数据解析
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }

        Some(Self::new(
            u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        ))
    }

    /// 重建为字节
    pub fn rebuild(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&self.begin_address.to_le_bytes());
        data.extend_from_slice(&self.end_address.to_le_bytes());
        data.extend_from_slice(&self.handler_address.to_le_bytes());
        data.extend_from_slice(&self.jump_target.to_le_bytes());
        data
    }
}

/// 作用域表（SEH）
#[derive(Debug, Clone)]
pub struct ScopeTable {
    pub count: u32,
    pub scopes: Vec<ScopeRecord>,
}

impl ScopeTable {
    pub fn new() -> Self {
        Self {
            count: 0,
            scopes: Vec::new(),
        }
    }

    /// 从数据解析
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let mut table = Self::new();
        table.count = count;

        let mut offset = 4;
        for _ in 0..count {
            if offset + 16 > data.len() {
                break;
            }
            if let Some(record) = ScopeRecord::parse(&data[offset..offset + 16]) {
                table.scopes.push(record);
            }
            offset += 16;
        }

        Some(table)
    }

    /// 重建为字节
    pub fn rebuild(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + self.scopes.len() * 16);
        data.extend_from_slice(&self.count.to_le_bytes());
        for scope in &self.scopes {
            data.extend_from_slice(&scope.rebuild());
        }
        data
    }

    /// 添加作用域记录
    pub fn add_scope(&mut self, scope: ScopeRecord) {
        self.scopes.push(scope);
        self.count = self.scopes.len() as u32;
    }

    /// 查找包含指定地址的作用域
    pub fn find_scope(&self, address: u32) -> Option<&ScopeRecord> {
        self.scopes.iter().find(|s| {
            address >= s.begin_address && address < s.end_address
        })
    }
}

impl Default for RuntimeFunctionList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unwind_op_from_u8() {
        assert_eq!(UnwindOp::from_u8(0), Some(UnwindOp::Nop));
        assert_eq!(UnwindOp::from_u8(1), Some(UnwindOp::AllocLarge));
        assert_eq!(UnwindOp::from_u8(4), Some(UnwindOp::SaveNonVol));
        assert_eq!(UnwindOp::from_u8(99), None);
    }

    #[test]
    fn test_unwind_op_size() {
        assert_eq!(UnwindOp::Nop.size(), 1);
        assert_eq!(UnwindOp::AllocSmall.size(), 1);
        assert_eq!(UnwindOp::AllocLarge.size(), 2);
        assert_eq!(UnwindOp::SaveNonVol.size(), 2);
        assert_eq!(UnwindOp::SaveNonVolFar.size(), 3);
    }

    #[test]
    fn test_unwind_code() {
        let code = UnwindCode::new(0x10, UnwindOp::AllocSmall, 5);
        assert_eq!(code.code_offset, 0x10);
        assert_eq!(code.unwind_op, UnwindOp::AllocSmall);
        assert_eq!(code.op_info, 5);

        let bytes = code.to_bytes();
        assert_eq!(bytes.len(), 2); // AllocSmall is 2 bytes (code_offset + op_info/unwind_op)
    }

    #[test]
    fn test_unwind_info_flags() {
        let flags = UnwindInfoFlags::from_u8(0x05);
        assert!(flags.has_exception_handler);
        assert!(!flags.has_unwind_code);
        assert!(flags.chained);

        let back = flags.to_u8();
        assert_eq!(back, 0x05);
    }

    #[test]
    fn test_unwind_info() {
        let mut info = UnwindInfo::new();
        info.version = 1;
        info.size_of_prolog = 0x20;
        info.count_of_codes = 2;
        info.frame_register = 5; // RBP
        info.frame_offset = 0;
        info.unwind_codes.push(UnwindCode::new(0x04, UnwindOp::AllocSmall, 3));
        info.unwind_codes.push(UnwindCode::new(0x01, UnwindOp::SetFpReg, 0));

        assert_eq!(info.unwind_codes.len(), 2);
        
        let bytes = info.rebuild();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_runtime_function() {
        let func = RuntimeFunction::new(0x1000, 0x1100, 0x2000);
        assert_eq!(func.begin_address, 0x1000);
        assert_eq!(func.end_address, 0x1100);
        assert_eq!(func.unwind_info_rva, 0x2000);
        assert_eq!(func.function_size(), 0x100);
    }

    #[test]
    fn test_runtime_function_list() {
        let mut list = RuntimeFunctionList::new();
        list.add(RuntimeFunction::new(0x1000, 0x1100, 0x2000));
        list.add(RuntimeFunction::new(0x1100, 0x1200, 0x2100));
        list.add(RuntimeFunction::new(0x1200, 0x1300, 0x2200));

        assert_eq!(list.len(), 3);

        let found = list.find_function(0x1050);
        assert!(found.is_some());
        assert_eq!(found.unwrap().begin_address, 0x1000);

        let not_found = list.find_function(0x2000);
        assert!(not_found.is_none());
    }

    #[test]
    fn test_runtime_function_update_addresses() {
        let mut list = RuntimeFunctionList::new();
        list.add(RuntimeFunction::new(0x1000, 0x1100, 0x2000));
        list.add(RuntimeFunction::new(0x1100, 0x1200, 0x2100));

        let mut map = HashMap::new();
        map.insert(0x1000, 0x5000);
        map.insert(0x1100, 0x5100);

        list.update_addresses(&map);

        let func = list.get(0).unwrap();
        assert_eq!(func.begin_address, 0x5000);
        assert_eq!(func.end_address, 0x5100);
    }
}
