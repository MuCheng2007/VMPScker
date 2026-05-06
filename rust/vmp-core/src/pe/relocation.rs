use crate::error::{Result, VmpError};

/// 重定位类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RelocationType {
    /// 绝对引用（64位）
    Absolute = 0,
    /// 高16位
    High = 1,
    /// 低16位
    Low = 2,
    /// 高16位和低16位（两个16位组合）
    HighLow = 3,
    /// 高16位并调整（用于MIPS）
    HighAdj = 4,
    /// MIPS跳转地址 / ARM MOV32A
    MipsJmpAddr = 5,
    /// 节区相对（仅用于调试）
    Section = 6,
    /// 节区相对（仅用于调试）/ ARM MOV32T / Thumb MOV32
    SecRel = 7,
    /// MIPS16跳转地址 / IA64_IMM64
    Ia64Imm64 = 9,
    /// MIPS16跳转地址64 / 目录相对（64位）
    Dir64 = 10,
    /// 高3位（用于Alpha）
    High3Adj = 11,
}

impl RelocationType {
    /// 从重定位类型值创建
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Absolute),
            1 => Some(Self::High),
            2 => Some(Self::Low),
            3 => Some(Self::HighLow),
            4 => Some(Self::HighAdj),
            5 => Some(Self::MipsJmpAddr),
            6 => Some(Self::Section),
            7 => Some(Self::SecRel),
            9 => Some(Self::Ia64Imm64),
            10 => Some(Self::Dir64),
            11 => Some(Self::High3Adj),
            _ => None,
        }
    }

    /// 获取此重定位类型的大小（字节）
    pub fn size(&self) -> usize {
        match self {
            Self::Absolute => 8,
            Self::High | Self::Low | Self::HighAdj | Self::Section | Self::SecRel => 2,
            Self::HighLow => 4,
            Self::Dir64 | Self::Ia64Imm64 => 8,
            _ => 4,
        }
    }

    /// 获取类型的显示名称
    pub fn name(&self) -> &'static str {
        match self {
            Self::Absolute => "ABSOLUTE",
            Self::High => "HIGH",
            Self::Low => "LOW",
            Self::HighLow => "HIGHLOW",
            Self::HighAdj => "HIGHADJ",
            Self::MipsJmpAddr => "MIPS_JMPADDR",
            Self::Section => "SECTION",
            Self::SecRel => "SECREL",
            Self::Ia64Imm64 => "IA64_IMM64",
            Self::Dir64 => "DIR64",
            Self::High3Adj => "HIGH3ADJ",
        }
    }
}

/// 单个重定位项
#[derive(Debug, Clone, Copy)]
pub struct Relocation {
    /// 重定位偏移（相对于页面 RVA）
    pub offset: u16,
    /// 重定位类型
    pub reloc_type: RelocationType,
}

impl Relocation {
    pub fn new(offset: u16, reloc_type: RelocationType) -> Self {
        Self { offset, reloc_type }
    }

    /// 从重定位字解析
    pub fn from_u16(value: u16) -> Option<Self> {
        let offset = value & 0x0FFF;
        let type_val = (value >> 12) as u16;
        RelocationType::from_u16(type_val)
            .map(|reloc_type| Self::new(offset, reloc_type))
    }

    /// 编码为重定位字
    pub fn to_u16(&self) -> u16 {
        let type_val = self.reloc_type as u16;
        (type_val << 12) | (self.offset & 0x0FFF)
    }
}

/// 重定位块（一个页面内的所有重定位）
#[derive(Debug, Clone)]
pub struct RelocationBlock {
    /// 页面 RVA（4KB 对齐）
    pub page_rva: u32,
    /// 此页面内的重定位项
    pub relocations: Vec<Relocation>,
}

impl RelocationBlock {
    pub fn new(page_rva: u32) -> Self {
        Self {
            page_rva,
            relocations: Vec::new(),
        }
    }

    pub fn add_relocation(&mut self, offset: u16, reloc_type: RelocationType) {
        self.relocations.push(Relocation::new(offset, reloc_type));
    }

    /// 添加绝对地址重定位（64位）
    pub fn add_absolute64(&mut self, offset: u16) {
        self.add_relocation(offset, RelocationType::Dir64);
    }

    /// 添加高/低重定位（32位）
    pub fn add_highlow(&mut self, offset: u16) {
        self.add_relocation(offset, RelocationType::HighLow);
    }

    /// 计算此块的大小（包括头部）
    pub fn block_size(&self) -> u32 {
        // 头部：8字节（page_rva + block_size）
        // 重定位项：每个2字节
        let size = 8 + self.relocations.len() * 2;
        // 对齐到4字节边界
        ((size + 3) & !3) as u32
    }

    /// 获取重定位数量
    pub fn len(&self) -> usize {
        self.relocations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.relocations.is_empty()
    }

    /// 检查是否包含指定偏移的重定位
    pub fn contains_offset(&self, offset: u16) -> bool {
        self.relocations.iter().any(|r| r.offset == offset)
    }

    /// 查找指定偏移的重定位
    pub fn find_relocation(&self, offset: u16) -> Option<&Relocation> {
        self.relocations.iter().find(|r| r.offset == offset)
    }
}

/// 重定位列表
#[derive(Debug, Clone)]
pub struct RelocationList {
    blocks: Vec<RelocationBlock>,
}

impl RelocationList {
    pub fn new() -> Self {
        Self {
            blocks: Vec::new(),
        }
    }

    /// 从 goblin 解析重定位表
    pub fn from_goblin(relocations: &[goblin::pe::relocation::Relocation]) -> Self {
        let mut list = Self::new();

        // goblin 的 relocation 结构不同，需要按 virtual_address 分组
        use std::collections::HashMap;
        let mut block_map: HashMap<u32, RelocationBlock> = HashMap::new();

        for reloc in relocations {
            let page_rva = reloc.virtual_address & !0xFFF;
            let offset = (reloc.virtual_address - page_rva) as u16;
            
            if let Some(reloc_type) = RelocationType::from_u16(reloc.typ) {
                let block = block_map.entry(page_rva).or_insert_with(|| {
                    RelocationBlock::new(page_rva)
                });
                block.add_relocation(offset, reloc_type);
            }
        }

        // 转换为 Vec 并排序
        let mut blocks: Vec<_> = block_map.into_values().collect();
        blocks.sort_by_key(|b| b.page_rva);
        list.blocks = blocks;

        list
    }

    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&RelocationBlock> {
        self.blocks.get(index)
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut RelocationBlock> {
        self.blocks.get_mut(index)
    }

    pub fn iter(&self) -> impl Iterator<Item = &RelocationBlock> {
        self.blocks.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut RelocationBlock> {
        self.blocks.iter_mut()
    }

    /// 查找包含指定 RVA 的块
    pub fn find_block(&self, rva: u32) -> Option<&RelocationBlock> {
        let page_rva = rva & !0xFFF; // 4KB 对齐
        self.blocks.iter().find(|b| b.page_rva == page_rva)
    }

    pub fn find_block_mut(&mut self, rva: u32) -> Option<&mut RelocationBlock> {
        let page_rva = rva & !0xFFF;
        self.blocks.iter_mut().find(|b| b.page_rva == page_rva)
    }

    /// 添加重定位
    pub fn add_relocation(&mut self, rva: u32, reloc_type: RelocationType) {
        let page_rva = rva & !0xFFF;
        let offset = (rva - page_rva) as u16;

        // 先检查是否存在
        if let Some(block) = self.find_block_mut(rva) {
            block.add_relocation(offset, reloc_type);
        } else {
            // 不存在则创建新块
            let mut block = RelocationBlock::new(page_rva);
            block.add_relocation(offset, reloc_type);
            self.blocks.push(block);
        }
    }

    /// 添加 64 位绝对地址重定位
    pub fn add_absolute64(&mut self, rva: u32) {
        self.add_relocation(rva, RelocationType::Dir64);
    }

    /// 添加 32 位高/低重定位
    pub fn add_highlow(&mut self, rva: u32) {
        self.add_relocation(rva, RelocationType::HighLow);
    }

    /// 获取所有重定位的总数
    pub fn total_relocations(&self) -> usize {
        self.blocks.iter().map(|b| b.len()).sum()
    }

    /// 计算重建重定位表所需的总大小
    pub fn calculate_rebuild_size(&self) -> usize {
        self.blocks.iter()
            .map(|b| b.block_size() as usize)
            .sum()
    }

    /// 重建重定位表
    pub fn rebuild(&self) -> Vec<u8> {
        let total_size = self.calculate_rebuild_size();
        let mut data = vec![0u8; total_size];
        let mut offset = 0usize;

        for block in &self.blocks {
            // 写入块头部
            let block_size = block.block_size();
            data[offset..offset + 4].copy_from_slice(&block.page_rva.to_le_bytes());
            data[offset + 4..offset + 8].copy_from_slice(&block_size.to_le_bytes());
            offset += 8;

            // 写入重定位项
            for reloc in &block.relocations {
                data[offset..offset + 2].copy_from_slice(&reloc.to_u16().to_le_bytes());
                offset += 2;
            }

            // 对齐到4字节边界
            let aligned_size = (8 + block.len() * 2 + 3) & !3;
            offset = offset - (8 + block.len() * 2) + aligned_size;
        }

        data
    }

    /// 应用重定位（修改内存中的值）
    /// 
    /// # 参数
    /// - `data`: 要修改的数据缓冲区
    /// - `old_base`: 原始基址
    /// - `new_base`: 新基址
    /// - `section_rva`: 此节区的 RVA（用于计算文件偏移）
    pub fn apply(&self, data: &mut [u8], old_base: u64, new_base: u64, section_rva: u32) {
        let delta = new_base.wrapping_sub(old_base) as i64;

        for block in &self.blocks {
            for reloc in &block.relocations {
                let rva = block.page_rva + reloc.offset as u32;
                let offset = (rva - section_rva) as usize;

                if offset + 8 > data.len() {
                    continue;
                }

                match reloc.reloc_type {
                    RelocationType::HighLow => {
                        let old_value = u32::from_le_bytes([
                            data[offset],
                            data[offset + 1],
                            data[offset + 2],
                            data[offset + 3],
                        ]);
                        let new_value = (old_value as i64 + delta) as u32;
                        data[offset..offset + 4].copy_from_slice(&new_value.to_le_bytes());
                    }
                    RelocationType::Dir64 => {
                        let old_value = u64::from_le_bytes([
                            data[offset],
                            data[offset + 1],
                            data[offset + 2],
                            data[offset + 3],
                            data[offset + 4],
                            data[offset + 5],
                            data[offset + 6],
                            data[offset + 7],
                        ]);
                        let new_value = (old_value as i64 + delta) as u64;
                        data[offset..offset + 8].copy_from_slice(&new_value.to_le_bytes());
                    }
                    _ => {
                        // 其他类型暂不处理
                    }
                }
            }
        }
    }

    /// 合并重定位块（优化）
    pub fn optimize(&mut self) {
        // 按 page_rva 排序
        self.blocks.sort_by_key(|b| b.page_rva);

        // 合并相邻的块（如果距离小于 4KB）
        let mut i = 0;
        while i + 1 < self.blocks.len() {
            let current_end = self.blocks[i].page_rva + 0x1000;
            let next_start = self.blocks[i + 1].page_rva;

            if current_end >= next_start {
                // 可以合并
                let next_block = self.blocks.remove(i + 1);
                for reloc in next_block.relocations {
                    let new_offset = (next_block.page_rva - self.blocks[i].page_rva) as u16 + reloc.offset;
                    self.blocks[i].add_relocation(new_offset, reloc.reloc_type);
                }
            } else {
                i += 1;
            }
        }
    }

    /// 移除指定范围的重定位
    pub fn remove_range(&mut self, start_rva: u32, end_rva: u32) {
        self.blocks.retain_mut(|block| {
            block.relocations.retain(|reloc| {
                let rva = block.page_rva + reloc.offset as u32;
                rva < start_rva || rva >= end_rva
            });
            !block.relocations.is_empty()
        });
    }

    /// 更新重定位地址（用于节区移动）
    pub fn update_addresses(&mut self, address_map: &std::collections::HashMap<u32, u32>) {
        for block in &mut self.blocks {
            if let Some(&new_page_rva) = address_map.get(&block.page_rva) {
                block.page_rva = new_page_rva;
            }
        }
    }
}

impl Default for RelocationList {
    fn default() -> Self {
        Self::new()
    }
}

/// 重定位表重建结果
#[derive(Debug)]
pub struct RelocationRebuildResult {
    /// 重定位表数据
    pub data: Vec<u8>,
    /// 重定位目录 RVA
    pub relocation_rva: u32,
    /// 重定位目录大小
    pub relocation_size: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relocation_type_from_u16() {
        assert_eq!(RelocationType::from_u16(0), Some(RelocationType::Absolute));
        assert_eq!(RelocationType::from_u16(3), Some(RelocationType::HighLow));
        assert_eq!(RelocationType::from_u16(10), Some(RelocationType::Dir64));
        assert_eq!(RelocationType::from_u16(99), None);
    }

    #[test]
    fn test_relocation_type_size() {
        assert_eq!(RelocationType::HighLow.size(), 4);
        assert_eq!(RelocationType::Dir64.size(), 8);
        assert_eq!(RelocationType::High.size(), 2);
    }

    #[test]
    fn test_relocation_from_u16() {
        // 类型 3 (HighLow)，偏移 0x123
        let reloc = Relocation::from_u16(0x3123).unwrap();
        assert_eq!(reloc.offset, 0x123);
        assert_eq!(reloc.reloc_type, RelocationType::HighLow);
    }

    #[test]
    fn test_relocation_to_u16() {
        let reloc = Relocation::new(0x456, RelocationType::Dir64);
        let value = reloc.to_u16();
        // 类型 10 (Dir64) << 12 | 0x456
        assert_eq!(value, 0xA456);
    }

    #[test]
    fn test_relocation_block() {
        let mut block = RelocationBlock::new(0x1000);
        block.add_highlow(0x100);
        block.add_absolute64(0x200);

        assert_eq!(block.len(), 2);
        assert!(block.contains_offset(0x100));
        assert!(!block.contains_offset(0x300));
        assert!(block.block_size() >= 8 + 4); // 头部 + 2个重定位项
    }

    #[test]
    fn test_relocation_list_add() {
        let mut list = RelocationList::new();
        list.add_highlow(0x1100);
        list.add_absolute64(0x2208);

        assert_eq!(list.len(), 2);
        assert_eq!(list.total_relocations(), 2);

        let block1 = list.find_block(0x1100).unwrap();
        assert_eq!(block1.page_rva, 0x1000);
        assert!(block1.contains_offset(0x100));

        let block2 = list.find_block(0x2208).unwrap();
        assert_eq!(block2.page_rva, 0x2000);
        assert!(block2.contains_offset(0x208));
    }

    #[test]
    fn test_relocation_list_rebuild() {
        let mut list = RelocationList::new();
        list.add_highlow(0x1100);
        list.add_highlow(0x1104);
        list.add_absolute64(0x2200);

        let data = list.rebuild();
        assert!(!data.is_empty());

        // 验证头部
        let page_rva = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        assert_eq!(page_rva, 0x1000);
    }

    #[test]
    fn test_relocation_apply() {
        let mut data = vec![0u8; 0x2000];
        // 在 0x1100 处设置一个 64 位地址
        let original_addr = 0x140001000u64;
        data[0x1100..0x1108].copy_from_slice(&original_addr.to_le_bytes());

        let mut list = RelocationList::new();
        list.add_absolute64(0x1100);

        // 应用重定位：基址从 0x140000000 变为 0x180000000
        list.apply(&mut data, 0x140000000, 0x180000000, 0);

        let new_addr = u64::from_le_bytes([
            data[0x1100], data[0x1101], data[0x1102], data[0x1103],
            data[0x1104], data[0x1105], data[0x1106], data[0x1107],
        ]);
        assert_eq!(new_addr, 0x180001000);
    }

    #[test]
    fn test_relocation_list_calculate_size() {
        let mut list = RelocationList::new();
        list.add_highlow(0x1100);
        list.add_highlow(0x1104);

        // 一个块：头部 8 字节 + 2 个重定位项 4 字节 = 12 字节，对齐到 12
        let size = list.calculate_rebuild_size();
        assert_eq!(size, 12);
    }

    #[test]
    fn test_relocation_list_remove_range() {
        let mut list = RelocationList::new();
        list.add_highlow(0x1100);
        list.add_highlow(0x1200);
        list.add_highlow(0x1300);

        list.remove_range(0x1150, 0x1250);

        // 0x1100 和 0x1300 应该保留，0x1200 应该被移除
        // 注意：它们都在同一个块中（page_rva = 0x1000）
        let block = list.find_block(0x1100).expect("Block should exist");
        assert!(block.contains_offset(0x100)); // 0x1100
        assert!(!block.contains_offset(0x200)); // 0x1200 - removed
        assert!(block.contains_offset(0x300)); // 0x1300
        assert_eq!(block.len(), 2); // Only 2 relocations left
    }
}
