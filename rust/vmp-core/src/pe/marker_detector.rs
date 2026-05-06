//! VMP 标记检测器
//!
//! 用于检测 PE 文件中的 VMProtect Begin/End 标记
//! 标记格式：
//! - Begin 标记: EB 04 xx xx xx xx (jmp short $+6, 后跟标记类型和名称)
//! - End 标记: EB 02 xx xx (jmp short $+4, 后跟结束标记)

use crate::error::{Result, VmpError};
use crate::pe::file::PeFile;
use crate::intel::{DisassemblyMode, disassemble};

/// 标记类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmpMarkerType {
    /// 基本保护
    Begin,
    /// 虚拟化保护
    Virtualization,
    /// 变异保护
    Mutation,
    /// Ultra 保护
    Ultra,
    /// 虚拟化 + 密钥锁定
    VirtualizationLockByKey,
    /// Ultra + 密钥锁定
    UltraLockByKey,
    /// 结束标记
    End,
    /// 未知类型
    Unknown(u8),
}

impl VmpMarkerType {
    /// 从字节解析标记类型
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x00 => VmpMarkerType::Begin,
            0x01 => VmpMarkerType::Virtualization,
            0x02 => VmpMarkerType::Mutation,
            0x03 => VmpMarkerType::Ultra,
            0x04 => VmpMarkerType::VirtualizationLockByKey,
            0x05 => VmpMarkerType::UltraLockByKey,
            0xFF => VmpMarkerType::End,
            _ => VmpMarkerType::Unknown(byte),
        }
    }

    /// 获取标记类型的字节值
    pub fn to_byte(&self) -> u8 {
        match self {
            VmpMarkerType::Begin => 0x00,
            VmpMarkerType::Virtualization => 0x01,
            VmpMarkerType::Mutation => 0x02,
            VmpMarkerType::Ultra => 0x03,
            VmpMarkerType::VirtualizationLockByKey => 0x04,
            VmpMarkerType::UltraLockByKey => 0x05,
            VmpMarkerType::End => 0xFF,
            VmpMarkerType::Unknown(b) => *b,
        }
    }

    /// 检查是否为 Begin 类型标记
    pub fn is_begin(&self) -> bool {
        matches!(self,
            VmpMarkerType::Begin |
            VmpMarkerType::Virtualization |
            VmpMarkerType::Mutation |
            VmpMarkerType::Ultra |
            VmpMarkerType::VirtualizationLockByKey |
            VmpMarkerType::UltraLockByKey
        )
    }

    /// 检查是否为 End 类型标记
    pub fn is_end(&self) -> bool {
        matches!(self, VmpMarkerType::End)
    }
}

impl std::fmt::Display for VmpMarkerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmpMarkerType::Begin => write!(f, "Begin"),
            VmpMarkerType::Virtualization => write!(f, "Virtualization"),
            VmpMarkerType::Mutation => write!(f, "Mutation"),
            VmpMarkerType::Ultra => write!(f, "Ultra"),
            VmpMarkerType::VirtualizationLockByKey => write!(f, "VirtualizationLockByKey"),
            VmpMarkerType::UltraLockByKey => write!(f, "UltraLockByKey"),
            VmpMarkerType::End => write!(f, "End"),
            VmpMarkerType::Unknown(b) => write!(f, "Unknown(0x{:02X})", b),
        }
    }
}

/// VMP 标记
#[derive(Debug, Clone)]
pub struct VmpMarker {
    /// 标记地址（文件偏移）
    pub file_offset: usize,
    /// 标记地址（RVA）
    pub rva: u64,
    /// 标记类型
    pub marker_type: VmpMarkerType,
    /// 标记名称（如果有）
    pub name: Option<String>,
    /// 标记大小（字节）
    pub size: usize,
}

impl VmpMarker {
    /// 创建新的标记
    pub fn new(file_offset: usize, rva: u64, marker_type: VmpMarkerType, name: Option<String>, size: usize) -> Self {
        Self {
            file_offset,
            rva,
            marker_type,
            name,
            size,
        }
    }

    /// 检查是否为 Begin 标记
    pub fn is_begin(&self) -> bool {
        self.marker_type.is_begin()
    }

    /// 检查是否为 End 标记
    pub fn is_end(&self) -> bool {
        self.marker_type.is_end()
    }
}

/// 标记对（Begin 和 End）
#[derive(Debug, Clone)]
pub struct VmpMarkerPair {
    /// Begin 标记
    pub begin: VmpMarker,
    /// End 标记
    pub end: VmpMarker,
    /// 保护的代码范围（RVA）
    pub code_start: u64,
    pub code_end: u64,
    /// 保护的代码大小
    pub code_size: u64,
}

/// VMP 标记检测器
pub struct VmpMarkerDetector {
    mode: DisassemblyMode,
}

impl VmpMarkerDetector {
    /// 创建新的检测器
    pub fn new() -> Self {
        Self {
            mode: DisassemblyMode::Mode64,
        }
    }

    /// 创建指定模式的检测器
    pub fn with_mode(mode: DisassemblyMode) -> Self {
        Self { mode }
    }

    /// 检测 PE 文件中的所有标记
    pub fn detect_markers(&self, pe_file: &PeFile) -> Result<Vec<VmpMarker>> {
        let mut markers = self.detect_bytecode_markers(pe_file)?;
        
        // 尝试检测导入表标记 [NEW]
        if let Ok(mut import_markers) = self.detect_import_markers(pe_file) {
            markers.append(&mut import_markers);
        }

        // 按地址排序
        markers.sort_by_key(|m| m.rva);
        Ok(markers)
    }

    /// 基于字节码特征的传统检测
    fn detect_bytecode_markers(&self, pe_file: &PeFile) -> Result<Vec<VmpMarker>> {
        let mut markers = Vec::new();
        let pe_data = pe_file.data();
        if pe_data.is_empty() { return Ok(markers); }

        let mut offset = 0;
        while offset < pe_data.len() - 10 {
            if let Some(marker) = self.check_marker_at(pe_data, offset, pe_file)? {
                let marker_size = marker.size;
                markers.push(marker);
                offset += marker_size;
            } else {
                offset += 1;
            }
        }
        Ok(markers)
    }

    /// 基于导入表 (IAT) 的现代检测 [NEW]
    fn detect_import_markers(&self, pe_file: &PeFile) -> Result<Vec<VmpMarker>> {
        let mut markers = Vec::new();
        let pe = match pe_file.pe() {
            Some(p) => p,
            None => return Ok(markers),
        };

        // 1. 查找 IAT 中 VMProtect 相关的函数
        let mut iat_entries = std::collections::HashMap::new();
        for import in &pe.imports {
            let name = import.name.to_lowercase();
            if name.contains("vmprotectbegin") {
                iat_entries.insert(import.rva as u64, VmpMarkerType::Virtualization);
            } else if name.contains("vmprotectend") {
                iat_entries.insert(import.rva as u64, VmpMarkerType::End);
            }
        }

        if iat_entries.is_empty() {
            return Ok(markers);
        }

        // 2. 扫描代码段查找对这些 IAT 项的调用
        // x64: FF 15 <Disp32>  -> CALL [RIP + Disp32]
        // x86: FF 15 <Addr32>  -> CALL [Addr32]
        for section in &pe.sections {
            if section.characteristics & 0x20 != 0 { // IMAGE_SCN_CNT_CODE
                let section_data = pe_file.read_at_rva(section.virtual_address as u64, section.virtual_size as usize)
                    .unwrap_or(&[]);
                
                let mut offset = 0;
                while offset < section_data.len().saturating_sub(6) {
                    // 匹配 CALL [IAT] 指令模式
                    if section_data[offset] == 0xFF && section_data[offset + 1] == 0x15 {
                        let inst_rva = section.virtual_address as u64 + offset as u64;
                        let target_iat_rva = if pe.is_64 {
                            // x64 相对寻址
                            let disp = i32::from_le_bytes([
                                section_data[offset + 2], section_data[offset + 3],
                                section_data[offset + 4], section_data[offset + 5]
                            ]);
                            (inst_rva + 6).wrapping_add(disp as u64)
                        } else {
                            // x86 绝对寻址
                            let addr = u32::from_le_bytes([
                                section_data[offset + 2], section_data[offset + 3],
                                section_data[offset + 4], section_data[offset + 5]
                            ]);
                            addr as u64 - pe.image_base as u64
                        };

                        if let Some(&marker_type) = iat_entries.get(&target_iat_rva) {
                            markers.push(VmpMarker::new(
                                pe_file.rva_to_offset(inst_rva).unwrap_or(0) as usize,
                                inst_rva,
                                marker_type,
                                None,
                                6 // CALL 指令长度
                            ));
                        }
                        offset += 6;
                    } else {
                        offset += 1;
                    }
                }
            }
        }

        Ok(markers)
    }

    /// 在指定位置检查是否为标记
    fn check_marker_at(&self, data: &[u8], offset: usize, pe_file: &PeFile) -> Result<Option<VmpMarker>> {
        // 检查是否有足够的数据
        if offset + 6 > data.len() {
            return Ok(None);
        }

        // 检查 Begin 标记模式: EB 04 xx xx xx xx
        // EB = jmp short, 04 = 跳过4字节
        if data[offset] == 0xEB && data[offset + 1] == 0x04 {
            let marker_type_byte = data[offset + 2];
            let marker_type = VmpMarkerType::from_byte(marker_type_byte);

            // 检查名称长度
            let name_len = data[offset + 3] as usize;
            let total_size = 4 + name_len;

            if offset + total_size > data.len() {
                return Ok(None);
            }

            // 提取名称
            let name = if name_len > 0 {
                let name_bytes = &data[offset + 4..offset + 4 + name_len];
                String::from_utf8(name_bytes.to_vec()).ok()
            } else {
                None
            };

            // 计算 RVA
            let rva = self.file_offset_to_rva(pe_file, offset).unwrap_or(0);

            return Ok(Some(VmpMarker::new(
                offset,
                rva,
                marker_type,
                name,
                total_size,
            )));
        }

        // 检查 End 标记模式: EB 02 FF xx
        // EB = jmp short, 02 = 跳过2字节, FF = End 标记类型
        if data[offset] == 0xEB && data[offset + 1] == 0x02 && data[offset + 2] == 0xFF {
            let rva = self.file_offset_to_rva(pe_file, offset).unwrap_or(0);

            return Ok(Some(VmpMarker::new(
                offset,
                rva,
                VmpMarkerType::End,
                None,
                4,
            )));
        }

        // 检查另一种 End 标记模式: EB 01 FF
        if data[offset] == 0xEB && data[offset + 1] == 0x01 && data[offset + 2] == 0xFF {
            let rva = self.file_offset_to_rva(pe_file, offset).unwrap_or(0);

            return Ok(Some(VmpMarker::new(
                offset,
                rva,
                VmpMarkerType::End,
                None,
                3,
            )));
        }

        Ok(None)
    }

    /// 查找标记对
    pub fn find_marker_pairs(&self, pe_file: &PeFile) -> Result<Vec<VmpMarkerPair>> {
        let markers = self.detect_markers(pe_file)?;
        let mut pairs = Vec::new();
        let mut stack: Vec<VmpMarker> = Vec::new();

        for marker in markers {
            if marker.is_begin() {
                stack.push(marker);
            } else if marker.is_end() {
                if let Some(begin) = stack.pop() {
                    let code_start = begin.rva + begin.size as u64;
                    let code_end = marker.rva;
                    let code_size = if code_end > code_start {
                        code_end - code_start
                    } else {
                        0
                    };

                    pairs.push(VmpMarkerPair {
                        begin: begin.clone(),
                        end: marker,
                        code_start,
                        code_end,
                        code_size,
                    });
                }
            }
        }

        Ok(pairs)
    }

    /// 读取标记之间的汇编代码
    pub fn read_protected_code(&self, pe_file: &PeFile, pair: &VmpMarkerPair) -> Result<Vec<u8>> {
        let start_offset = self.rva_to_file_offset(pe_file, pair.code_start)?;
        let end_offset = self.rva_to_file_offset(pe_file, pair.code_end)?;

        if end_offset <= start_offset {
            return Ok(Vec::new());
        }

        let pe_data = pe_file.data();
        if end_offset > pe_data.len() {
            return Err(VmpError::vm_error("Invalid code range".to_string()));
        }

        Ok(pe_data[start_offset..end_offset].to_vec())
    }

    /// 反汇编保护的代码
    pub fn disassemble_protected_code(&self, pe_file: &PeFile, pair: &VmpMarkerPair) -> Result<String> {
        let code_bytes = self.read_protected_code(pe_file, pair)?;
        if code_bytes.is_empty() {
            return Ok("// No code between markers".to_string());
        }

        let instructions = disassemble(&code_bytes, self.mode, pair.code_start)
            .map_err(|e| VmpError::vm_error(format!("Failed to disassemble: {:?}", e)))?;

        let mut output = String::new();
        for inst in instructions {
            output.push_str(&format!("0x{:08X}: {}\n", inst.ip(), inst.mnemonic()));
        }

        Ok(output)
    }

    /// 文件偏移转换为 RVA
    fn file_offset_to_rva(&self, pe_file: &PeFile, file_offset: usize) -> Option<u64> {
        if let Some(pe) = pe_file.pe() {
            for section in &pe.sections {
                let raw_offset = section.pointer_to_raw_data as usize;
                let raw_size = section.size_of_raw_data as usize;

                if file_offset >= raw_offset && file_offset < raw_offset + raw_size {
                    let rva = section.virtual_address as u64 + (file_offset - raw_offset) as u64;
                    return Some(rva);
                }
            }
        }
        None
    }

    /// RVA 转换为文件偏移
    fn rva_to_file_offset(&self, pe_file: &PeFile, rva: u64) -> Result<usize> {
        if let Some(pe) = pe_file.pe() {
            for section in &pe.sections {
                let section_rva = section.virtual_address as u64;
                let section_size = section.virtual_size as u64;

                if rva >= section_rva && rva < section_rva + section_size {
                    let offset = section.pointer_to_raw_data as usize + (rva - section_rva) as usize;
                    return Ok(offset);
                }
            }
        }
        Err(VmpError::vm_error(format!("RVA 0x{:X} not found in any section", rva)))
    }
}

impl Default for VmpMarkerDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_marker_type_from_byte() {
        assert_eq!(VmpMarkerType::from_byte(0x00), VmpMarkerType::Begin);
        assert_eq!(VmpMarkerType::from_byte(0x01), VmpMarkerType::Virtualization);
        assert_eq!(VmpMarkerType::from_byte(0x02), VmpMarkerType::Mutation);
        assert_eq!(VmpMarkerType::from_byte(0x03), VmpMarkerType::Ultra);
        assert_eq!(VmpMarkerType::from_byte(0xFF), VmpMarkerType::End);
        assert!(matches!(VmpMarkerType::from_byte(0x99), VmpMarkerType::Unknown(_)));
    }

    #[test]
    fn test_marker_type_is_begin() {
        assert!(VmpMarkerType::Begin.is_begin());
        assert!(VmpMarkerType::Virtualization.is_begin());
        assert!(VmpMarkerType::Ultra.is_begin());
        assert!(!VmpMarkerType::End.is_begin());
    }

    #[test]
    fn test_marker_type_display() {
        assert_eq!(format!("{}", VmpMarkerType::Virtualization), "Virtualization");
        assert_eq!(format!("{}", VmpMarkerType::End), "End");
    }
}
