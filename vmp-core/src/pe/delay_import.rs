pub struct DelayImportFunction {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub address: u64,
}

impl DelayImportFunction {
    pub fn by_name(name: impl Into<String>, address: u64) -> Self {
        Self {
            name: Some(name.into()),
            ordinal: None,
            address,
        }
    }

    pub fn by_ordinal(ordinal: u16, address: u64) -> Self {
        Self {
            name: None,
            ordinal: Some(ordinal),
            address,
        }
    }

    pub fn display_name(&self) -> String {
        match &self.name {
            Some(name) => name.clone(),
            None => format!("Ordinal_{}", self.ordinal.unwrap_or(0)),
        }
    }
}

pub struct DelayImport {
    pub dll_name: String,
    pub attributes: u32,
    pub hmod: u32,
    pub iat_rva: u32,
    pub int_rva: u32,
    pub bound_iat_rva: u32,
    pub unload_iat_rva: u32,
    pub time_stamp: u32,
    pub functions: Vec<DelayImportFunction>,
}

impl DelayImport {
    pub fn new(dll_name: impl Into<String>) -> Self {
        Self {
            dll_name: dll_name.into(),
            attributes: 0,
            hmod: 0,
            iat_rva: 0,
            int_rva: 0,
            bound_iat_rva: 0,
            unload_iat_rva: 0,
            time_stamp: 0,
            functions: Vec::new(),
        }
    }

    pub fn add_function(&mut self, function: DelayImportFunction) {
        self.functions.push(function);
    }
}

pub struct DelayImportList {
    imports: Vec<DelayImport>,
}

impl DelayImportList {
    pub fn new() -> Self {
        Self {
            imports: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.imports.len()
    }

    pub fn is_empty(&self) -> bool {
        self.imports.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&DelayImport> {
        self.imports.get(index)
    }

    pub fn iter(&self) -> impl Iterator<Item = &DelayImport> {
        self.imports.iter()
    }

    pub fn add(&mut self, import: DelayImport) {
        self.imports.push(import);
    }

    pub fn find_by_dll(&self, dll_name: &str) -> Option<&DelayImport> {
        self.imports.iter().find(|i| {
            i.dll_name.to_lowercase() == dll_name.to_lowercase()
        })
    }
}

impl Default for DelayImportList {
    fn default() -> Self {
        Self::new()
    }
}
