//! PE TLS (Thread Local Storage) 目录处理
//!
//! 支持解析和重建 TLS 目录。

use crate::error::{Result, VmpError};
use std::collections::HashMap;

/// TLS 目录结构
#[derive(Debug, Clone)]
pub struct Tls {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
    pub callbacks: Vec<u64>,
}

impl Tls {
    pub fn new() -> Self {
        Self {
            start_address_of_raw_data: 0,
            end_address_of_raw_data: 0,
            address_of_index: 0,
            address_of_callbacks: 0,
            size_of_zero_fill: 0,
            characteristics: 0,
            callbacks: Vec::new(),
        }
    }

    /// 从 32 位 PE 数据解析 TLS 目录
    pub fn from_32bit_data(data: &[u8]) -> Option<Self> {
        if data.len() < 24 {
            return None;
        }

        let mut tls = Self::new();
        tls.start_address_of_raw_data = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64;
        tls.end_address_of_raw_data = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as u64;
        tls.address_of_index = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as u64;
        tls.address_of_callbacks = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as u64;
        tls.size_of_zero_fill = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        tls.characteristics = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

        Some(tls)
    }

    /// 从 64 位 PE 数据解析 TLS 目录
    pub fn from_64bit_data(data: &[u8]) -> Option<Self> {
        if data.len() < 40 {
            return None;
        }

        let mut tls = Self::new();
        tls.start_address_of_raw_data = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        tls.end_address_of_raw_data = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);
        tls.address_of_index = u64::from_le_bytes([
            data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
        ]);
        tls.address_of_callbacks = u64::from_le_bytes([
            data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
        ]);
        tls.size_of_zero_fill = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
        tls.characteristics = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);

        Some(tls)
    }

    /// 解析回调函数地址表
    pub fn parse_callbacks(&mut self, data: &[u8], is_64bit: bool) {
        self.callbacks.clear();

        let entry_size = if is_64bit { 8 } else { 4 };
        let mut offset = 0;

        while offset + entry_size <= data.len() {
            let callback = if is_64bit {
                u64::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ])
            } else {
                u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]) as u64
            };

            if callback == 0 {
                break;
            }

            self.callbacks.push(callback);
            offset += entry_size;
        }
    }

    /// 重建回调函数地址表
    pub fn rebuild_callbacks(&self, is_64bit: bool) -> Vec<u8> {
        let entry_size = if is_64bit { 8 } else { 4 };
        let mut data = Vec::with_capacity((self.callbacks.len() + 1) * entry_size);

        for &callback in &self.callbacks {
            if is_64bit {
                data.extend_from_slice(&callback.to_le_bytes());
            } else {
                data.extend_from_slice(&(callback as u32).to_le_bytes());
            }
        }

        // 添加 NULL 终止符
        if is_64bit {
            data.extend_from_slice(&[0u8; 8]);
        } else {
            data.extend_from_slice(&[0u8; 4]);
        }

        data
    }

    /// 是否有回调函数
    pub fn has_callbacks(&self) -> bool {
        !self.callbacks.is_empty()
    }

    /// 获取 TLS 数据大小
    pub fn data_size(&self) -> u64 {
        if self.end_address_of_raw_data > self.start_address_of_raw_data {
            self.end_address_of_raw_data - self.start_address_of_raw_data
        } else {
            0
        }
    }

    /// 重建 TLS 目录
    pub fn rebuild(&self, is_64bit: bool) -> Vec<u8> {
        if is_64bit {
            let mut data = vec![0u8; 40];
            data[0..8].copy_from_slice(&self.start_address_of_raw_data.to_le_bytes());
            data[8..16].copy_from_slice(&self.end_address_of_raw_data.to_le_bytes());
            data[16..24].copy_from_slice(&self.address_of_index.to_le_bytes());
            data[24..32].copy_from_slice(&self.address_of_callbacks.to_le_bytes());
            data[32..36].copy_from_slice(&self.size_of_zero_fill.to_le_bytes());
            data[36..40].copy_from_slice(&self.characteristics.to_le_bytes());
            data
        } else {
            let mut data = vec![0u8; 24];
            data[0..4].copy_from_slice(&(self.start_address_of_raw_data as u32).to_le_bytes());
            data[4..8].copy_from_slice(&(self.end_address_of_raw_data as u32).to_le_bytes());
            data[8..12].copy_from_slice(&(self.address_of_index as u32).to_le_bytes());
            data[12..16].copy_from_slice(&(self.address_of_callbacks as u32).to_le_bytes());
            data[16..20].copy_from_slice(&self.size_of_zero_fill.to_le_bytes());
            data[20..24].copy_from_slice(&self.characteristics.to_le_bytes());
            data
        }
    }

    /// 计算目录大小
    pub fn directory_size(&self, is_64bit: bool) -> usize {
        if is_64bit { 40 } else { 24 }
    }

    /// 更新地址（用于重定位）
    pub fn update_addresses(&mut self, address_map: &HashMap<u64, u64>) {
        if let Some(&new_addr) = address_map.get(&self.start_address_of_raw_data) {
            self.start_address_of_raw_data = new_addr;
        }
        if let Some(&new_addr) = address_map.get(&self.end_address_of_raw_data) {
            self.end_address_of_raw_data = new_addr;
        }
        if let Some(&new_addr) = address_map.get(&self.address_of_index) {
            self.address_of_index = new_addr;
        }
        if let Some(&new_addr) = address_map.get(&self.address_of_callbacks) {
            self.address_of_callbacks = new_addr;
        }

        // 更新回调函数地址
        for callback in &mut self.callbacks {
            if let Some(&new_addr) = address_map.get(callback) {
                *callback = new_addr;
            }
        }
    }

    /// 添加回调函数
    pub fn add_callback(&mut self, address: u64) {
        self.callbacks.push(address);
    }

    /// 移除回调函数
    pub fn remove_callback(&mut self, index: usize) -> Option<u64> {
        if index < self.callbacks.len() {
            Some(self.callbacks.remove(index))
        } else {
            None
        }
    }
}

impl Default for Tls {
    fn default() -> Self {
        Self::new()
    }
}

/// TLS 目录信息（包含目录位置和大小）
#[derive(Debug, Clone)]
pub struct TlsDirectory {
    pub tls: Tls,
    pub directory_rva: u64,
    pub directory_size: u64,
}

impl TlsDirectory {
    pub fn new(tls: Tls, directory_rva: u64, directory_size: u64) -> Self {
        Self {
            tls,
            directory_rva,
            directory_size,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.directory_size > 0 && self.tls.start_address_of_raw_data != 0
    }

    /// 从 PE 数据解析 TLS 目录
    pub fn parse(data: &[u8], rva: u32, size: u32, is_64bit: bool) -> Result<Self> {
        let tls = if is_64bit {
            Tls::from_64bit_data(data).ok_or_else(|| {
                VmpError::InvalidData("Failed to parse 64-bit TLS directory".to_string())
            })?
        } else {
            Tls::from_32bit_data(data).ok_or_else(|| {
                VmpError::InvalidData("Failed to parse 32-bit TLS directory".to_string())
            })?
        };

        Ok(Self::new(tls, rva as u64, size as u64))
    }

    /// 重建 TLS 目录
    pub fn rebuild(&self, is_64bit: bool) -> Vec<u8> {
        self.tls.rebuild(is_64bit)
    }
}

/// TLS 回调函数类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TlsCallbackReason {
    ProcessAttach = 1,
    ProcessDetach = 0,
    ThreadAttach = 2,
    ThreadDetach = 3,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_new() {
        let tls = Tls::new();
        assert_eq!(tls.start_address_of_raw_data, 0);
        assert_eq!(tls.callbacks.len(), 0);
        assert!(!tls.has_callbacks());
    }

    #[test]
    fn test_tls_from_32bit_data() {
        let data = [
            0x00, 0x10, 0x00, 0x00, // StartAddressOfRawData
            0x00, 0x20, 0x00, 0x00, // EndAddressOfRawData
            0x00, 0x30, 0x00, 0x00, // AddressOfIndex
            0x00, 0x40, 0x00, 0x00, // AddressOfCallBacks
            0x10, 0x00, 0x00, 0x00, // SizeOfZeroFill
            0x00, 0x00, 0x00, 0x00, // Characteristics
        ];
        let tls = Tls::from_32bit_data(&data).unwrap();
        assert_eq!(tls.start_address_of_raw_data, 0x1000);
        assert_eq!(tls.end_address_of_raw_data, 0x2000);
        assert_eq!(tls.address_of_index, 0x3000);
        assert_eq!(tls.address_of_callbacks, 0x4000);
        assert_eq!(tls.size_of_zero_fill, 0x10);
    }

    #[test]
    fn test_tls_from_64bit_data() {
        let data = [
            0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, // StartAddressOfRawData
            0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, // EndAddressOfRawData
            0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, // AddressOfIndex
            0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // AddressOfCallBacks
            0x10, 0x00, 0x00, 0x00, // SizeOfZeroFill
            0x00, 0x00, 0x00, 0x00, // Characteristics
        ];
        let tls = Tls::from_64bit_data(&data).unwrap();
        assert_eq!(tls.start_address_of_raw_data, 0x100000);
        assert_eq!(tls.end_address_of_raw_data, 0x200000);
        assert_eq!(tls.address_of_index, 0x300000);
        assert_eq!(tls.address_of_callbacks, 0x400000);
        assert_eq!(tls.size_of_zero_fill, 0x10);
    }

    #[test]
    fn test_tls_callbacks() {
        let mut tls = Tls::new();
        
        // 模拟回调函数地址表（64位）
        let callback_data = [
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Callback 1
            0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Callback 2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // NULL terminator
        ];
        
        tls.parse_callbacks(&callback_data, true);
        assert_eq!(tls.callbacks.len(), 2);
        assert_eq!(tls.callbacks[0], 0x1000);
        assert_eq!(tls.callbacks[1], 0x2000);
        assert!(tls.has_callbacks());

        // 测试重建
        let rebuilt = tls.rebuild_callbacks(true);
        assert_eq!(rebuilt.len(), 24); // 2 callbacks + null terminator, 8 bytes each
    }

    #[test]
    fn test_tls_rebuild() {
        let mut tls = Tls::new();
        tls.start_address_of_raw_data = 0x1000;
        tls.end_address_of_raw_data = 0x2000;
        tls.address_of_index = 0x3000;
        tls.address_of_callbacks = 0x4000;
        tls.size_of_zero_fill = 0x10;
        tls.characteristics = 0;

        // 32-bit rebuild
        let data_32 = tls.rebuild(false);
        assert_eq!(data_32.len(), 24);

        // 64-bit rebuild
        let data_64 = tls.rebuild(true);
        assert_eq!(data_64.len(), 40);
    }

    #[test]
    fn test_tls_update_addresses() {
        let mut tls = Tls::new();
        tls.start_address_of_raw_data = 0x1000;
        tls.end_address_of_raw_data = 0x2000;
        tls.callbacks = vec![0x3000, 0x4000];

        let mut map = HashMap::new();
        map.insert(0x1000, 0x5000);
        map.insert(0x3000, 0x6000);

        tls.update_addresses(&map);

        assert_eq!(tls.start_address_of_raw_data, 0x5000);
        assert_eq!(tls.end_address_of_raw_data, 0x2000); // Not changed
        assert_eq!(tls.callbacks[0], 0x6000);
        assert_eq!(tls.callbacks[1], 0x4000); // Not changed
    }

    #[test]
    fn test_tls_directory() {
        let tls = Tls::new();
        let dir = TlsDirectory::new(tls, 0x1000, 40);
        
        assert_eq!(dir.directory_rva, 0x1000);
        assert_eq!(dir.directory_size, 40);
        assert!(!dir.is_valid()); // start_address is 0

        let mut tls2 = Tls::new();
        tls2.start_address_of_raw_data = 0x2000;
        let dir2 = TlsDirectory::new(tls2, 0x1000, 40);
        assert!(dir2.is_valid());
    }
}
