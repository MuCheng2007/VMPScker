use crate::error::{Result, VmpError};
use crate::project::config::ProjectConfig;
use std::fs;
use std::path::Path;

pub struct ProjectLoader;

impl ProjectLoader {
    pub fn new() -> Self {
        Self
    }

    pub fn load<P: AsRef<Path>>(&self, path: P) -> Result<ProjectConfig> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)?;
        
        let config: ProjectConfig = toml::from_str(&content)
            .map_err(|e| VmpError::InvalidConfig(format!("Failed to parse TOML: {}", e)))?;
        
        Ok(config)
    }

    pub fn save<P: AsRef<Path>>(&self, path: P, config: &ProjectConfig) -> Result<()> {
        let path = path.as_ref();
        let content = toml::to_string_pretty(config)
            .map_err(|e| VmpError::InvalidConfig(format!("Failed to serialize TOML: {}", e)))?;
        
        fs::write(path, content)?;
        Ok(())
    }

    pub fn create_default(input_file: &str, output_file: &str) -> ProjectConfig {
        ProjectConfig {
            input_file: input_file.to_string(),
            output_file: output_file.to_string(),
            ..Default::default()
        }
    }
}
