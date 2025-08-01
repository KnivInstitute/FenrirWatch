use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    // Logging settings
    pub log_path: String,
    pub log_format: String,
    
    // GUI Display settings
    pub dark_mode: bool,
    pub show_timestamps: bool,
    pub auto_scroll: bool,
    pub max_events: usize,
    
    // Event filtering settings
    pub selected_event_types: Vec<String>,
    pub event_filter: String,
    
    // Graph settings
    pub graph_max_points: usize,
    
    // Export settings
    pub export_format: String,
    
    // Search settings
    pub search_text: String,
    pub highlight_search: bool,
}

impl Config {
    pub fn load_yaml_config(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let s = std::fs::read_to_string(path)?;
        Ok(serde_yaml::from_str(&s)?)
    }
    
    pub fn save_yaml_config(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let yaml = serde_yaml::to_string(self)?;
        std::fs::write(path, yaml)?;
        Ok(())
    }
    
    pub fn default() -> Self {
        Config {
            log_path: "fenrirwatch.log".to_string(),
            log_format: "json".to_string(),
            dark_mode: false,
            show_timestamps: true,
            auto_scroll: true,
            max_events: 1000,
            selected_event_types: vec![
                "Process".to_string(),
                "Service".to_string(),
                "Registry".to_string(),
                "Driver".to_string(),
                "Autostart".to_string(),
                "Hook".to_string(),
                "FileSystem".to_string(),
                "Network".to_string(),
            ],
            event_filter: String::new(),
            graph_max_points: 100,
            export_format: "JSON".to_string(),
            search_text: String::new(),
            highlight_search: false,
        }
    }
}
