use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub log_path: String,
    pub log_format: String,
}

impl Config {
    pub fn load_yaml_config(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let s = std::fs::read_to_string(path)?;
        Ok(serde_yaml::from_str(&s)?)
    }
}
