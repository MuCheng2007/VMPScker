use crate::error::{Result, VmpError};
use goblin::pe::PE;
use std::path::Path;

pub struct PeFile {
    data: Vec<u8>,
    pe: Option<PE<'static>>,
    is_64bit: bool,
    image_base: u64,
    entry_point: u64,
}

impl PeFile {
    pub fn new(data: Vec<u8>) -> Result<Self> {
        let pe = PE::parse(&data)
            .map_err(|e| VmpError::PeParse(format!("Failed to parse PE: {}", e)))?;

        let is_64bit = pe.is_64;
        let image_base = pe.image_base as u64;
        let entry_point = pe.entry as u64;

        let pe = unsafe {
            std::mem::transmute::<PE<'_>, PE<'static>>(pe)
        };

        Ok(Self {
            data,
            pe: Some(pe),
            is_64bit,
            image_base,
            entry_point,
        })
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::new(data)
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        std::fs::write(path, &self.data)?;
        Ok(())
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }

    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    pub fn is_32bit(&self) -> bool {
        !self.is_64bit
    }

    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    pub fn entry_point(&self) -> u64 {
        self.entry_point
    }

    pub fn pe(&self) -> Option<&PE> {
        self.pe.as_ref()
    }

    pub fn rva_to_offset(&self, rva: u64) -> Option<u64> {
        if let Some(ref pe) = self.pe {
            for section in &pe.sections {
                let start = section.virtual_address as u64;
                let end = start + section.virtual_size as u64;
                if rva >= start && rva < end {
                    let offset = rva - start;
                    return Some(section.pointer_to_raw_data as u64 + offset);
                }
            }
        }
        None
    }

    pub fn offset_to_rva(&self, offset: u64) -> Option<u64> {
        if let Some(ref pe) = self.pe {
            for section in &pe.sections {
                let start = section.pointer_to_raw_data as u64;
                let end = start + section.size_of_raw_data as u64;
                if offset >= start && offset < end {
                    let section_offset = offset - start;
                    return Some(section.virtual_address as u64 + section_offset);
                }
            }
        }
        None
    }

    pub fn read_at(&self, offset: u64, size: usize) -> Option<&[u8]> {
        let start = offset as usize;
        let end = start + size;
        if end <= self.data.len() {
            Some(&self.data[start..end])
        } else {
            None
        }
    }

    pub fn read_at_rva(&self, rva: u64, size: usize) -> Option<&[u8]> {
        self.rva_to_offset(rva)
            .and_then(|offset| self.read_at(offset, size))
    }
}
