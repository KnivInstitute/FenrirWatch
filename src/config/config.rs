use ini::Ini;

pub struct Config {
    pub log_path: String,
    pub log_format: String,
}

impl Config {
    pub fn load_ini_config(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let conf = Ini::load_from_file(path)?;
        let section = conf.section(Some("general")).ok_or("Missing [general] section")?;
        let log_path = section.get("log_path").ok_or("Missing log_path")?.trim_matches('"').to_string();
        let log_format = section.get("log_format").ok_or("Missing log_format")?.trim_matches('"').to_string();
        Ok(Config { log_path, log_format })
    }
}
