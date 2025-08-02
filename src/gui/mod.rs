// GUI module

use crossbeam_channel::Receiver;
use crate::Event;
use crate::core::ProcessEventType;
use eframe::egui;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};
use std::fs;
use std::path::Path;
use uuid::Uuid;
use egui::IconData;

#[derive(Clone)]
struct LogEvent {
    timestamp: chrono::DateTime<chrono::Utc>,
    event_type: String,
    message: String,
    color: egui::Color32,
    severity: EventSeverity,
}

#[derive(Clone, PartialEq, Debug)]
enum EventSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Clone)]
struct GraphData {
    timestamps: Vec<DateTime<Utc>>,
    process_events: Vec<f64>,
    service_events: Vec<f64>,
    registry_events: Vec<f64>,
    driver_events: Vec<f64>,
    filesystem_events: Vec<f64>,
    network_events: Vec<f64>,
    max_points: usize,
}

#[derive(Clone)]
struct EventStats {
    total_events: usize,
    events_by_type: HashMap<String, usize>,
    events_by_minute: HashMap<String, usize>,
    last_update: DateTime<Utc>,
}

#[derive(Clone, PartialEq, Debug)]
enum ExportFormat {
    JSON,
    CSV,
    TXT,
}

pub struct FenrirWatchGUI {
    receiver: Receiver<Event>,
    events: Arc<Mutex<VecDeque<LogEvent>>>,
    selected_tab: usize,
    auto_scroll: bool,
    max_events: usize,
    // Enhanced GUI features
    dark_mode: bool,
    event_filter: String,
    selected_event_types: Vec<String>,
    show_timestamps: bool,
    graph_data: Arc<Mutex<GraphData>>,
    export_format: ExportFormat,
    search_text: String,
    highlight_search: bool,
    // Statistics
    event_stats: Arc<Mutex<EventStats>>,
    // Process tree cache
    process_tree_cache: Arc<Mutex<Vec<(u32, u32, String)>>>,
    last_process_update: DateTime<Utc>,
}

impl FenrirWatchGUI {
    pub fn new(receiver: Receiver<Event>) -> Self {
        // Load config or use defaults
        let config = match crate::config::Config::load_yaml_config("src/config/config.yaml") {
            Ok(cfg) => cfg,
            Err(_) => crate::config::Config::default(),
        };
        
        FenrirWatchGUI {
            receiver,
            events: Arc::new(Mutex::new(VecDeque::new())),
            selected_tab: 0,
            auto_scroll: config.auto_scroll,
            max_events: config.max_events,
            dark_mode: config.dark_mode,
            event_filter: config.event_filter,
            selected_event_types: config.selected_event_types,
            show_timestamps: config.show_timestamps,
            graph_data: Arc::new(Mutex::new(GraphData {
                timestamps: Vec::new(),
                process_events: Vec::new(),
                service_events: Vec::new(),
                registry_events: Vec::new(),
                driver_events: Vec::new(),
                filesystem_events: Vec::new(),
                network_events: Vec::new(),
                max_points: config.graph_max_points,
            })),
            export_format: match config.export_format.as_str() {
                "JSON" => ExportFormat::JSON,
                "CSV" => ExportFormat::CSV,
                "TXT" => ExportFormat::TXT,
                _ => ExportFormat::JSON,
            },
            search_text: config.search_text,
            highlight_search: config.highlight_search,
            event_stats: Arc::new(Mutex::new(EventStats {
                total_events: 0,
                events_by_type: HashMap::new(),
                events_by_minute: HashMap::new(),
                last_update: Utc::now(),
            })),
            process_tree_cache: Arc::new(Mutex::new(Vec::new())),
            last_process_update: Utc::now(),
        }
    }

    pub fn run(self) -> eframe::Result<()> {
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1400.0, 900.0])
                .with_min_inner_size([1000.0, 700.0])
                .with_icon(Self::load_icon()),
            ..Default::default()
        };

        eframe::run_native(
            "FenrirWatch - Advanced System Monitor",
            options,
            Box::new(|_cc| Box::new(self)),
        )
    }

    /// Loads the application icon from icon.png file.
    /// 
    /// Requirements:
    /// - File must be named "icon.png" in the project root
    /// - PNG format with RGBA color space
    /// - Recommended size: 32x32, 64x64, or 128x128 pixels
    /// - If file doesn't exist or fails to load, uses default icon
    fn load_icon() -> IconData {
        // Try to load icon.png file
        if let Ok(icon_data) = std::fs::read("icon.png") {
            // Decode PNG and convert to RGBA
            if let Ok(img) = image::load_from_memory(&icon_data) {
                let rgba = img.to_rgba8();
                let (width, height) = rgba.dimensions();
                
                // Convert to IconData format
                let pixels: Vec<u8> = rgba.into_raw();
                IconData {
                    rgba: pixels,
                    width: width as u32,
                    height: height as u32,
                }
            } else {
                IconData::default()
            }
        } else {
            // Fallback to a default icon if file doesn't exist
            IconData::default()
        }
    }

    fn process_events(&mut self) {
        let mut event_count = 0;
        let max_events_per_frame = 50;
        
        while event_count < max_events_per_frame {
            match self.receiver.try_recv() {
                Ok(event) => {
                    event_count += 1;
                    let log_event = self.convert_event_to_log(event);
                    
                    // Update statistics
                    self.update_event_stats(&log_event);
                    
                    // Update graph data
                    self.update_graph_data(&log_event);
                    
                    let mut events = self.events.lock().unwrap();
                    events.push_back(log_event);
                    
                    while events.len() > self.max_events {
                        events.pop_front();
                    }
                }
                Err(_) => break,
            }
        }
    }

    fn convert_event_to_log(&self, event: Event) -> LogEvent {
        let timestamp = chrono::Utc::now();
        match event {
            Event::Process(process_event) => {
                let message = match process_event.event_type {
                    ProcessEventType::Created => {
                        format!("🟢 PROCESS CREATED: {} (PID: {})", process_event.name, process_event.pid)
                    },
                    ProcessEventType::Terminated => {
                        format!("🔴 PROCESS TERMINATED: {} (PID: {})", process_event.name, process_event.pid)
                    }
                };
                LogEvent {
                    timestamp,
                    event_type: "Process".to_string(),
                    message,
                    color: egui::Color32::from_rgb(0, 255, 0),
                    severity: EventSeverity::Info,
                }
            },
            Event::Service(service_msg) => {
                let severity = if service_msg.contains("ERROR") || service_msg.contains("FAILED") {
                    EventSeverity::Error
                } else if service_msg.contains("WARNING") {
                    EventSeverity::Warning
                } else {
                    EventSeverity::Info
                };
                LogEvent {
                    timestamp,
                    event_type: "Service".to_string(),
                    message: format!("⚙️  {}", service_msg),
                    color: egui::Color32::from_rgb(255, 165, 0),
                    severity,
                }
            },
            Event::Driver(driver_msg) => {
                let (color, severity) = if driver_msg.contains("LOADED") {
                    (egui::Color32::from_rgb(0, 255, 0), EventSeverity::Info)
                } else if driver_msg.contains("UNLOADED") {
                    (egui::Color32::from_rgb(255, 0, 0), EventSeverity::Warning)
                } else if driver_msg.contains("ERROR") {
                    (egui::Color32::from_rgb(255, 0, 0), EventSeverity::Error)
                } else {
                    (egui::Color32::from_rgb(0, 191, 255), EventSeverity::Info)
                };
                LogEvent {
                    timestamp,
                    event_type: "Driver".to_string(),
                    message: format!("🚗 {}", driver_msg),
                    color,
                    severity,
                }
            },
            Event::Registry(registry_msg) => {
                let severity = if registry_msg.contains("CRITICAL") || registry_msg.contains("MALWARE") {
                    EventSeverity::Critical
                } else if registry_msg.contains("WARNING") {
                    EventSeverity::Warning
                } else {
                    EventSeverity::Info
                };
                LogEvent {
                    timestamp,
                    event_type: "Registry".to_string(),
                    message: format!("🔧 {}", registry_msg),
                    color: egui::Color32::from_rgb(255, 255, 0),
                    severity,
                }
            },
            Event::Autostart(autostart_msg) => {
                LogEvent {
                    timestamp,
                    event_type: "Autostart".to_string(),
                    message: format!("🚀 {}", autostart_msg),
                    color: egui::Color32::from_rgb(255, 0, 255),
                    severity: EventSeverity::Info,
                }
            },
            Event::Hook(hook_msg) => {
                LogEvent {
                    timestamp,
                    event_type: "Hook".to_string(),
                    message: format!("⚠️  {}", hook_msg),
                    color: egui::Color32::from_rgb(255, 0, 0),
                    severity: EventSeverity::Critical,
                }
            },
            Event::FileSystem(filesystem_event) => {
                let (icon, color, severity) = match filesystem_event.event_type {
                    crate::core::FileSystemEventType::Created => ("📄", egui::Color32::from_rgb(0, 255, 0), EventSeverity::Info),
                    crate::core::FileSystemEventType::Modified => ("✏️", egui::Color32::from_rgb(255, 165, 0), EventSeverity::Warning),
                    crate::core::FileSystemEventType::Deleted => ("🗑️", egui::Color32::from_rgb(255, 0, 0), EventSeverity::Warning),
                    crate::core::FileSystemEventType::Renamed => ("🔄", egui::Color32::from_rgb(0, 191, 255), EventSeverity::Info),
                    crate::core::FileSystemEventType::Accessed => ("👁️", egui::Color32::from_rgb(128, 128, 128), EventSeverity::Info),
                };
                
                let size_info = if let Some(size) = filesystem_event.size {
                    format!(" ({} bytes)", size)
                } else {
                    String::new()
                };
                
                LogEvent {
                    timestamp,
                    event_type: "FileSystem".to_string(),
                    message: format!("{} FILE {}: {}{}", icon, format!("{:?}", filesystem_event.event_type).to_uppercase(), filesystem_event.path, size_info),
                    color,
                    severity,
                }
            },
            Event::Network(network_event) => {
                let (icon, color, severity) = match network_event.event_type {
                                    crate::core::NetworkEventType::ConnectionEstablished => ("🔗", egui::Color32::from_rgb(0, 255, 0), EventSeverity::Info),
                crate::core::NetworkEventType::ConnectionClosed => ("🔌", egui::Color32::from_rgb(255, 0, 0), EventSeverity::Info),
                crate::core::NetworkEventType::DataTransferred => ("📡", egui::Color32::from_rgb(0, 191, 255), EventSeverity::Info),
                crate::core::NetworkEventType::ConnectionAttempt => ("🔍", egui::Color32::from_rgb(255, 255, 0), EventSeverity::Warning),
                crate::core::NetworkEventType::DNSQuery => ("🌐", egui::Color32::from_rgb(128, 0, 128), EventSeverity::Info),
                crate::core::NetworkEventType::SuspiciousConnection => ("⚠️", egui::Color32::from_rgb(255, 165, 0), EventSeverity::Warning),
                crate::core::NetworkEventType::HighTrafficConnection => ("📊", egui::Color32::from_rgb(255, 20, 147), EventSeverity::Info),
                };
                
                // Create detailed message for network events
                let mut message_parts = Vec::new();
                
                // Add DNS query information if available
                if let Some(dns_query) = &network_event.dns_query {
                    message_parts.push(format!("DNS Query: {}", dns_query));
                    if let Some(dns_response) = &network_event.dns_response {
                        message_parts.push(format!("-> {}", dns_response));
                    }
                } else {
                    // Regular connection information
                    message_parts.push(format!("{} {} -> {}", 
                        network_event.protocol,
                        network_event.local_address,
                        network_event.remote_address
                    ));
                }
                
                let port_info = if let (Some(local_port), Some(remote_port)) = (network_event.local_port, network_event.remote_port) {
                    format!(":{} -> :{}", local_port, remote_port)
                } else {
                    format!(":{}", network_event.local_port.unwrap_or(0))
                };
                
                let process_info = if let Some(process_name) = &network_event.process_name {
                    format!(" [{}:{}]", process_name, network_event.process_pid.unwrap_or(0))
                } else {
                    String::new()
                };
                
                let connection_state = if let Some(state) = &network_event.connection_state {
                    format!(" [{}]", state)
                } else {
                    String::new()
                };
                
                let traffic_info = if let (Some(sent), Some(received)) = (network_event.bytes_sent, network_event.bytes_received) {
                    if sent > 0 || received > 0 {
                        format!(" (↑{}B ↓{}B)", sent, received)
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };
                
                let final_message = if message_parts.is_empty() {
                    format!("{} {} -> {}{}{}{}{}", 
                        network_event.protocol,
                        network_event.local_address,
                        network_event.remote_address,
                        port_info,
                        process_info,
                        connection_state,
                        traffic_info
                    )
                } else {
                    format!("{}{}{}{}{}", 
                        message_parts.join(" "),
                        port_info,
                        process_info,
                        connection_state,
                        traffic_info
                    )
                };
                
                LogEvent {
                    timestamp,
                    event_type: "Network".to_string(),
                    message: format!("{} {}", icon, final_message),
                    color,
                    severity,
                }
            }
        }
    }

    fn update_event_stats(&self, event: &LogEvent) {
        let mut stats = self.event_stats.lock().unwrap();
        stats.total_events += 1;
        *stats.events_by_type.entry(event.event_type.clone()).or_insert(0) += 1;
        
        let minute_key = event.timestamp.format("%Y-%m-%d %H:%M").to_string();
        *stats.events_by_minute.entry(minute_key).or_insert(0) += 1;
        stats.last_update = Utc::now();
    }

    fn update_graph_data(&self, event: &LogEvent) {
        let mut graph_data = self.graph_data.lock().unwrap();
        let now = Utc::now();
        
        // Define time interval (5 seconds for better granularity)
        let time_interval_seconds = 5;
        
        // Round down to nearest time interval
        let current_interval = (now.timestamp() / time_interval_seconds) * time_interval_seconds;
        let current_time = DateTime::from_timestamp(current_interval, 0).unwrap_or(now);
        
        // Check if we need to add a new time point
        let needs_new_point = graph_data.timestamps.is_empty() || 
            graph_data.timestamps.last().unwrap().timestamp() < current_interval;
        
        if needs_new_point {
            // Add new time point
            graph_data.timestamps.push(current_time);
            
            // Initialize all event type counters to 0 for this time point
            graph_data.process_events.push(0.0);
            graph_data.service_events.push(0.0);
            graph_data.registry_events.push(0.0);
            graph_data.driver_events.push(0.0);
            graph_data.filesystem_events.push(0.0);
            graph_data.network_events.push(0.0);
        }
        
        // Update the count for the current time interval (last index)
        if let Some(last_index) = graph_data.timestamps.len().checked_sub(1) {
            match event.event_type.as_str() {
                "Process" => {
                    if let Some(count) = graph_data.process_events.get_mut(last_index) {
                        *count += 1.0;
                    }
                },
                "Service" => {
                    if let Some(count) = graph_data.service_events.get_mut(last_index) {
                        *count += 1.0;
                    }
                },
                "Registry" => {
                    if let Some(count) = graph_data.registry_events.get_mut(last_index) {
                        *count += 1.0;
                    }
                },
                "Driver" => {
                    if let Some(count) = graph_data.driver_events.get_mut(last_index) {
                        *count += 1.0;
                    }
                },
                "FileSystem" => {
                    if let Some(count) = graph_data.filesystem_events.get_mut(last_index) {
                        *count += 1.0;
                    }
                },
                "Network" => {
                    if let Some(count) = graph_data.network_events.get_mut(last_index) {
                        *count += 1.0;
                    }
                },
                _ => {} // Unknown event type
            }
        }
        
        // Keep only last max_points and ensure all vectors stay synchronized
        if graph_data.timestamps.len() > graph_data.max_points {
            let excess = graph_data.timestamps.len() - graph_data.max_points;
            
            // Remove oldest data points from all vectors
            graph_data.timestamps.drain(0..excess);
            graph_data.process_events.drain(0..excess);
            graph_data.service_events.drain(0..excess);
            graph_data.registry_events.drain(0..excess);
            graph_data.driver_events.drain(0..excess);
            graph_data.filesystem_events.drain(0..excess);
            graph_data.network_events.drain(0..excess);
        }
        
        // Ensure all vectors have the same length (safety check)
        let target_len = graph_data.timestamps.len();
        graph_data.process_events.resize(target_len, 0.0);
        graph_data.service_events.resize(target_len, 0.0);
        graph_data.registry_events.resize(target_len, 0.0);
        graph_data.driver_events.resize(target_len, 0.0);
        graph_data.filesystem_events.resize(target_len, 0.0);
        graph_data.network_events.resize(target_len, 0.0);
    }

    fn export_events(&self) -> Result<String, Box<dyn std::error::Error>> {
        let events = self.events.lock().unwrap();
        match self.export_format {
            ExportFormat::JSON => {
                let json_events: Vec<serde_json::Value> = events.iter().map(|event| {
                    serde_json::json!({
                        "timestamp": event.timestamp.to_rfc3339(),
                        "event_type": event.event_type,
                        "message": event.message,
                        "severity": format!("{:?}", event.severity)
                    })
                }).collect();
                Ok(serde_json::to_string_pretty(&json_events)?)
            },
            ExportFormat::CSV => {
                let mut csv = String::from("Timestamp,Event Type,Message,Severity\n");
                for event in events.iter() {
                    csv.push_str(&format!("{},{},{},{:?}\n",
                        event.timestamp.to_rfc3339(),
                        event.event_type,
                        event.message.replace(",", ";"),
                        event.severity
                    ));
                }
                Ok(csv)
            },
            ExportFormat::TXT => {
                let mut txt = String::new();
                for event in events.iter() {
                    txt.push_str(&format!("[{}] [{}] {:?}: {}\n",
                        event.timestamp.format("%Y-%m-%d %H:%M:%S"),
                        event.event_type,
                        event.severity,
                        event.message
                    ));
                }
                Ok(txt)
            }
        }
    }

    fn save_export_to_file(&self) -> Result<String, Box<dyn std::error::Error>> {
        // Create export directory if it doesn't exist
        let export_dir = Path::new("export");
        if !export_dir.exists() {
            fs::create_dir(export_dir)?;
        }

        // Generate filename with UUID and timestamp
        let uuid = Uuid::new_v4();
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let extension = match self.export_format {
            ExportFormat::JSON => "json",
            ExportFormat::CSV => "csv",
            ExportFormat::TXT => "txt",
        };
        
        let filename = format!("fenrirwatch_export_{}_{}.{}", uuid, timestamp, extension);
        let filepath = export_dir.join(&filename);

        // Generate export data
        let export_data = self.export_events()?;
        
        // Write to file
        fs::write(&filepath, export_data)?;
        
        Ok(filename)
    }

    fn save_config(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = crate::config::Config::default();
        
        // Update config with current GUI settings
        config.dark_mode = self.dark_mode;
        config.show_timestamps = self.show_timestamps;
        config.auto_scroll = self.auto_scroll;
        config.max_events = self.max_events;
        config.selected_event_types = self.selected_event_types.clone();
        config.event_filter = self.event_filter.clone();
        config.graph_max_points = self.graph_data.lock().unwrap().max_points;
        config.export_format = match self.export_format {
            ExportFormat::JSON => "JSON".to_string(),
            ExportFormat::CSV => "CSV".to_string(),
            ExportFormat::TXT => "TXT".to_string(),
        };
        config.search_text = self.search_text.clone();
        config.highlight_search = self.highlight_search;
        
        // Save to file
        config.save_yaml_config("src/config/config.yaml")
    }
}

impl eframe::App for FenrirWatchGUI {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Apply theme
        if self.dark_mode {
            ctx.set_visuals(egui::Visuals::dark());
        } else {
            ctx.set_visuals(egui::Visuals::light());
        }

        self.process_events();

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("🐺 FenrirWatch - Advanced System Monitor");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.checkbox(&mut self.dark_mode, "🌙 Dark Mode");
                });
            });
            ui.add_space(10.0);

            // Enhanced tab bar
            egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let tabs = ["📊 Console Log", "📈 Real-time Graphs", "🌳 Process Tree", "📊 Statistics", "⚙️  Settings"];
                    for (i, tab) in tabs.iter().enumerate() {
                        let selected = self.selected_tab == i;
                        if ui.selectable_label(selected, *tab).clicked() {
                            self.selected_tab = i;
                        }
                    }
                });
            });

            // Tab content
            match self.selected_tab {
                0 => self.show_enhanced_console_tab(ui),
                1 => self.show_real_time_graphs_tab(ui),
                2 => self.show_process_tree_tab(ui),
                3 => self.show_statistics_tab(ui),
                4 => self.show_settings_tab(ui),
                _ => {}
            }
        });

        ctx.request_repaint();
    }
}

impl FenrirWatchGUI {
    fn show_enhanced_console_tab(&mut self, ui: &mut egui::Ui) {
        // Filter controls
        ui.horizontal(|ui| {
            ui.label("Filter:");
            if ui.text_edit_singleline(&mut self.event_filter).changed() {
                let _ = self.save_config();
            }
            ui.add_space(10.0);
            
            ui.label("Search:");
            if ui.text_edit_singleline(&mut self.search_text).changed() {
                let _ = self.save_config();
            }
            if ui.checkbox(&mut self.highlight_search, "🔍 Highlight").clicked() {
                let _ = self.save_config();
            }
        });

        // Event type filter
        ui.horizontal(|ui| {
            ui.label("Event Types:");
            let event_types = ["Process", "Service", "Registry", "Driver", "Autostart", "Hook", "FileSystem", "Network"];
            for event_type in event_types.iter() {
                let mut is_selected = self.selected_event_types.contains(&event_type.to_string());
                if ui.checkbox(&mut is_selected, *event_type).clicked() {
                    if is_selected {
                        self.selected_event_types.push(event_type.to_string());
                    } else {
                        self.selected_event_types.retain(|x| x != event_type);
                    }
                    let _ = self.save_config();
                }
            }
        });

        // Controls
        ui.horizontal(|ui| {
            ui.label("Auto-scroll:");
            if ui.checkbox(&mut self.auto_scroll, "").clicked() {
                let _ = self.save_config();
            }
            ui.add_space(20.0);
            ui.label("Max events:");
            if ui.add(egui::DragValue::new(&mut self.max_events).clamp_range(100..=10000)).changed() {
                let _ = self.save_config();
            }
            ui.add_space(20.0);
            if ui.checkbox(&mut self.show_timestamps, "Show timestamps").clicked() {
                let _ = self.save_config();
            }
            ui.add_space(20.0);
            
            if ui.button("🗑️ Clear Log").clicked() {
                self.events.lock().unwrap().clear();
            }
            
            ui.add_space(10.0);
            ui.label("Export:");
            let mut format_changed = false;
            egui::ComboBox::from_id_source("export_format")
                .selected_text(format!("{:?}", self.export_format))
                .show_ui(ui, |ui| {
                    if ui.selectable_value(&mut self.export_format, ExportFormat::JSON, "JSON").clicked() {
                        format_changed = true;
                    }
                    if ui.selectable_value(&mut self.export_format, ExportFormat::CSV, "CSV").clicked() {
                        format_changed = true;
                    }
                    if ui.selectable_value(&mut self.export_format, ExportFormat::TXT, "TXT").clicked() {
                        format_changed = true;
                    }
                });
            if format_changed {
                let _ = self.save_config();
            }
            
            if ui.button("💾 Export").clicked() {
                match self.save_export_to_file() {
                    Ok(filename) => {
                        ui.label(format!("✅ Exported to: export/{}", filename));
                    }
                    Err(e) => {
                        ui.label(format!("❌ Export failed: {}", e));
                    }
                }
            }
        });

        ui.add_space(10.0);

        // Enhanced console log area
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(self.auto_scroll)
            .show(ui, |ui| {
                let events = self.events.lock().unwrap();
                for event in events.iter() {
                    // Apply filters  
                    if !self.selected_event_types.contains(&event.event_type) {
                        continue;
                    }
                    
                    if !self.event_filter.is_empty() && !event.message.to_lowercase().contains(&self.event_filter.to_lowercase()) {
                        continue;
                    }
                    
                    if !self.search_text.is_empty() && !event.message.to_lowercase().contains(&self.search_text.to_lowercase()) {
                        continue;
                    }

                    ui.horizontal(|ui| {
                        // Timestamp
                        if self.show_timestamps {
                            ui.label(egui::RichText::new(
                                event.timestamp.format("%H:%M:%S").to_string()
                            ).color(egui::Color32::GRAY));
                        }
                        
                        // Event type with severity indicator
                        let severity_icon = match event.severity {
                            EventSeverity::Info => "ℹ️",
                            EventSeverity::Warning => "⚠️",
                            EventSeverity::Error => "❌",
                            EventSeverity::Critical => "🚨",
                        };
                        
                        ui.label(egui::RichText::new(
                            format!("[{}] {}", event.event_type, severity_icon)
                        ).color(egui::Color32::LIGHT_GRAY));
                        
                        // Message with search highlighting
                        let message = if self.highlight_search && !self.search_text.is_empty() {
                            event.message.replace(&self.search_text, &format!("**{}**", self.search_text))
                        } else {
                            event.message.clone()
                        };
                        
                        ui.label(egui::RichText::new(&message).color(event.color));
                    });
                }
            });
    }

    fn show_real_time_graphs_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("📈 Real-time Event Graphs");
        ui.add_space(20.0);

        let graph_data = self.graph_data.lock().unwrap();
        
        // Event rate graph
        ui.label("Event Rate Over Time");
        ui.add_space(10.0);
        
        if !graph_data.timestamps.is_empty() {
            let plot = egui_plot::Plot::new("event_rate")
                .height(200.0)
                .allow_zoom(true)
                .allow_drag(true)
                .y_axis_label("Events per 5-second interval")
                .x_axis_label("Time");
            
            plot.show(ui, |plot_ui| {
                // Process events line
                let points: Vec<[f64; 2]> = graph_data.timestamps.iter()
                    .zip(graph_data.process_events.iter())
                    .map(|(ts, &val)| [ts.timestamp() as f64, val])
                    .collect();
                
                if !points.is_empty() {
                    plot_ui.line(egui_plot::Line::new(points)
                        .name("Process Events")
                        .color(egui::Color32::GREEN));
                }
                
                // Service events line
                let points: Vec<[f64; 2]> = graph_data.timestamps.iter()
                    .zip(graph_data.service_events.iter())
                    .map(|(ts, &val)| [ts.timestamp() as f64, val])
                    .collect();
                
                if !points.is_empty() {
                    plot_ui.line(egui_plot::Line::new(points)
                        .name("Service Events")
                        .color(egui::Color32::from_rgb(255, 165, 0)));
                }
                
                // Registry events line
                let points: Vec<[f64; 2]> = graph_data.timestamps.iter()
                    .zip(graph_data.registry_events.iter())
                    .map(|(ts, &val)| [ts.timestamp() as f64, val])
                    .collect();
                
                if !points.is_empty() {
                    plot_ui.line(egui_plot::Line::new(points)
                        .name("Registry Events")
                        .color(egui::Color32::YELLOW));
                }
                
                // Driver events line
                let points: Vec<[f64; 2]> = graph_data.timestamps.iter()
                    .zip(graph_data.driver_events.iter())
                    .map(|(ts, &val)| [ts.timestamp() as f64, val])
                    .collect();
                
                if !points.is_empty() {
                    plot_ui.line(egui_plot::Line::new(points)
                        .name("Driver Events")
                        .color(egui::Color32::BLUE));
                }
                
                // FileSystem events line
                let points: Vec<[f64; 2]> = graph_data.timestamps.iter()
                    .zip(graph_data.filesystem_events.iter())
                    .map(|(ts, &val)| [ts.timestamp() as f64, val])
                    .collect();
                
                if !points.is_empty() {
                    plot_ui.line(egui_plot::Line::new(points)
                        .name("FileSystem Events")
                        .color(egui::Color32::from_rgb(128, 0, 128)));
                }
                
                // Network events line
                let points: Vec<[f64; 2]> = graph_data.timestamps.iter()
                    .zip(graph_data.network_events.iter())
                    .map(|(ts, &val)| [ts.timestamp() as f64, val])
                    .collect();
                
                if !points.is_empty() {
                    plot_ui.line(egui_plot::Line::new(points)
                        .name("Network Events")
                        .color(egui::Color32::from_rgb(0, 128, 255)));
                }
            });
        } else {
            ui.label("⏳ Waiting for events to display graph data...");
            ui.label("💡 The graph will show event rates aggregated over 5-second intervals");
        }

        // Statistics cards
        ui.add_space(20.0);
        ui.label("Live Statistics");
        ui.add_space(10.0);
        
        let stats = self.event_stats.lock().unwrap();
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(format!("Total Events: {}", stats.total_events));
                ui.label(format!("Last Update: {}", stats.last_update.format("%H:%M:%S")));
            });
            
            ui.add_space(20.0);
            
            ui.vertical(|ui| {
                for (event_type, count) in stats.events_by_type.iter() {
                    ui.label(format!("{}: {}", event_type, count));
                }
            });
        });
    }

    fn show_process_tree_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("🌳 Process Tree");
        ui.add_space(20.0);

        // Update process tree cache periodically
        let now = Utc::now();
        if now.signed_duration_since(self.last_process_update).num_seconds() > 5 {
            if let Ok(tree) = std::panic::catch_unwind(|| crate::core::get_process_tree()) {
                let mut cache = self.process_tree_cache.lock().unwrap();
                *cache = tree;
                self.last_process_update = now;
            }
        }

        let process_tree = self.process_tree_cache.lock().unwrap();
        
        ui.label(format!("Active Processes: {}", process_tree.len()));
        ui.add_space(10.0);

        // Process tree controls
        ui.horizontal(|ui| {
            ui.label("Process Filter:");
            ui.text_edit_singleline(&mut self.search_text);
            ui.add_space(20.0);
            if ui.button("🔄 Refresh").clicked() {
                // Force refresh
                self.last_process_update = Utc::now() - Duration::seconds(10);
            }
        });

        // Limit the number of processes displayed to prevent lag
        let max_processes = 100;
        let display_tree: Vec<_> = process_tree.iter()
            .filter(|(_, _, name)| {
                self.search_text.is_empty() || 
                name.to_lowercase().contains(&self.search_text.to_lowercase())
            })
            .take(max_processes)
            .collect();
        
        if display_tree.len() >= max_processes {
            ui.label(format!("⚠️  Showing first {} processes (limited to prevent lag)", max_processes));
        }

        // Create a tree view of processes with enhanced details
        egui::ScrollArea::vertical().show(ui, |ui| {
            let mut process_map = std::collections::HashMap::new();
            let mut children_map = std::collections::HashMap::new();
            
            // Build parent-child relationships
            for (pid, ppid, name) in &display_tree {
                process_map.insert(pid, name);
                children_map.entry(ppid).or_insert_with(Vec::new).push(pid);
            }
            
            // Find root processes (those with ppid = 0 or not in our list)
            let mut roots = Vec::new();
            for (pid, ppid, _) in &display_tree {
                if *ppid == 0 || !process_map.contains_key(ppid) {
                    roots.push(pid);
                }
            }
            
            // Display process tree with enhanced details
            for root_pid in roots.iter().take(20) {
                self.display_enhanced_process_node(ui, root_pid, &process_map, &children_map, 0);
            }
        });
    }

    fn display_enhanced_process_node(
        &self,
        ui: &mut egui::Ui,
        pid: &u32,
        process_map: &std::collections::HashMap<&u32, &String>,
        children_map: &std::collections::HashMap<&u32, Vec<&u32>>,
        depth: usize,
    ) {
        // Limit recursion depth to prevent stack overflow
        if depth > 10 {
            ui.label(format!("{}... (depth limit reached)", "  ".repeat(depth)));
            return;
        }
        
        let indent = "  ".repeat(depth);
        let unknown = "Unknown".to_string();
        let name = process_map.get(pid).map_or(&unknown, |v| v);
        
        ui.horizontal(|ui| {
            // Process icon based on name
            let icon = if name.to_lowercase().contains("explorer") { "🖥️" }
                else if name.to_lowercase().contains("svchost") { "⚙️" }
                else if name.to_lowercase().contains("winlogon") { "🔐" }
                else if name.to_lowercase().contains("csrss") { "💻" }
                else { "📄" };
            
            ui.label(format!("{}{} {} (PID: {})", indent, icon, name, pid));
            
            // Show process details on click
            if ui.button("📋").clicked() {
                if let Some(details) = crate::core::get_process_details(*pid) {
                    ui.label(format!("Path: {}", details.executable_path.unwrap_or_else(|| "Unknown".to_string())));
                    ui.label(format!("User: {}", details.user.unwrap_or_else(|| "Unknown".to_string())));
                }
            }
            
            // Kill process button (dangerous!)
            if ui.button("💀").clicked() {
                // In a real app, you'd add confirmation dialog
                ui.label("⚠️  Process termination requires confirmation");
            }
        });
        
        // Display children with limit
        if let Some(children) = children_map.get(pid) {
            for (i, child_pid) in children.iter().take(5).enumerate() {
                if i >= 5 {
                    ui.label(format!("{}... (showing first 5 children)", "  ".repeat(depth + 1)));
                    break;
                }
                self.display_enhanced_process_node(ui, child_pid, process_map, children_map, depth + 1);
            }
        }
    }

    fn show_statistics_tab(&self, ui: &mut egui::Ui) {
        ui.heading("📊 Enhanced Statistics");
        ui.add_space(20.0);

        let stats = self.event_stats.lock().unwrap();
        let events = self.events.lock().unwrap();
        
        // Summary cards
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(egui::RichText::new("📈 Total Events").heading());
                ui.label(egui::RichText::new(format!("{}", stats.total_events)).size(24.0));
            });
            
            ui.add_space(20.0);
            
            ui.vertical(|ui| {
                ui.label(egui::RichText::new("⏰ Last Update").heading());
                ui.label(egui::RichText::new(stats.last_update.format("%H:%M:%S").to_string()).size(24.0));
            });
            
            ui.add_space(20.0);
            
            ui.vertical(|ui| {
                ui.label(egui::RichText::new("📊 Active Events").heading());
                ui.label(egui::RichText::new(format!("{}", events.len())).size(24.0));
            });
        });

        ui.add_space(20.0);

        // Event type breakdown
        ui.label("Event Type Breakdown:");
        ui.add_space(10.0);
        
        let mut sorted_stats: Vec<_> = stats.events_by_type.iter().collect();
        sorted_stats.sort_by(|a, b| b.1.cmp(a.1));
        
        for (event_type, count) in sorted_stats {
            let percentage = if stats.total_events > 0 {
                (count * 100) / stats.total_events
            } else {
                0
            };
            
            ui.horizontal(|ui| {
                ui.label(format!("{}:", event_type));
                ui.add_space(10.0);
                ui.label(format!("{} ({:.1}%)", count, percentage as f32));
                
                // Progress bar
                let progress = percentage as f32 / 100.0;
                ui.add(egui::widgets::ProgressBar::new(progress)
                    .desired_width(100.0));
            });
        }

        ui.add_space(20.0);

        // Recent activity chart
        ui.label("Recent Activity (Last 10 Minutes):");
        ui.add_space(10.0);
        
        let mut recent_activity = Vec::new();
        for i in 0..10 {
            let minute_key = (Utc::now() - Duration::minutes(i as i64)).format("%Y-%m-%d %H:%M").to_string();
            let count = stats.events_by_minute.get(&minute_key).unwrap_or(&0);
            recent_activity.push((minute_key, *count));
        }
        recent_activity.reverse();
        
        for (minute, count) in recent_activity {
            ui.horizontal(|ui| {
                ui.label(format!("{}:", minute.split_whitespace().last().unwrap_or("")));
                ui.add_space(10.0);
                ui.label(format!("{} events", count));
                
                // Simple bar chart
                let bar_width = (count as f32 * 2.0).min(100.0);
                ui.add(egui::widgets::ProgressBar::new(bar_width / 100.0)
                    .desired_width(bar_width));
            });
        }

        ui.add_space(20.0);

        // System health indicators
        ui.label("System Health Indicators:");
        ui.add_space(10.0);
        
        let critical_events = events.iter()
            .filter(|e| e.severity == EventSeverity::Critical)
            .count();
        
        let warning_events = events.iter()
            .filter(|e| e.severity == EventSeverity::Warning)
            .count();
        
        ui.horizontal(|ui| {
            ui.label("🚨 Critical Events:");
            ui.label(format!("{}", critical_events));
        });
        
        ui.horizontal(|ui| {
            ui.label("⚠️  Warning Events:");
            ui.label(format!("{}", warning_events));
        });
        
        // Health status
        let health_status = if critical_events > 10 {
            "🔴 Poor"
        } else if warning_events > 20 {
            "🟡 Fair"
        } else {
            "🟢 Good"
        };
        
        ui.horizontal(|ui| {
            ui.label("Overall System Health:");
            ui.label(egui::RichText::new(health_status).size(18.0));
        });
    }

    fn show_settings_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("⚙️  Advanced Settings");
        ui.add_space(20.0);

        // Display settings
        ui.label("Display Settings:");
        ui.add_space(10.0);
        
        ui.horizontal(|ui| {
            ui.label("Theme:");
            if ui.checkbox(&mut self.dark_mode, "Dark Mode").clicked() {
                let _ = self.save_config();
            }
        });
        
        ui.horizontal(|ui| {
            ui.label("Show timestamps:");
            if ui.checkbox(&mut self.show_timestamps, "").clicked() {
                let _ = self.save_config();
            }
        });
        
        ui.horizontal(|ui| {
            ui.label("Auto-scroll:");
            if ui.checkbox(&mut self.auto_scroll, "").clicked() {
                let _ = self.save_config();
            }
        });

        // Performance settings
        ui.label("Performance Settings:");
        ui.add_space(10.0);
        
        ui.horizontal(|ui| {
            ui.label("Max events to display:");
            if ui.add(egui::DragValue::new(&mut self.max_events).clamp_range(100..=10000)).changed() {
                let _ = self.save_config();
            }
        });
        
        // Get graph max points without holding the lock
        let graph_max_points = {
            let graph_data = self.graph_data.lock().unwrap();
            graph_data.max_points
        };
        
        ui.horizontal(|ui| {
            ui.label("Graph data points:");
            let mut temp_max_points = graph_max_points;
            if ui.add(egui::DragValue::new(&mut temp_max_points).clamp_range(50..=500)).changed() {
                // Update the graph data
                {
                    let mut graph_data = self.graph_data.lock().unwrap();
                    graph_data.max_points = temp_max_points;
                }
                let _ = self.save_config();
            }
        });

        ui.add_space(20.0);

        // Monitoring settings
        ui.label("Monitoring Settings:");
        ui.add_space(10.0);
        
        ui.label("Event Type Filters:");
        let event_types = ["Process", "Service", "Registry", "Driver", "Autostart", "Hook"];
        for event_type in event_types.iter() {
            let mut is_selected = self.selected_event_types.contains(&event_type.to_string());
            if ui.checkbox(&mut is_selected, *event_type).clicked() {
                if is_selected {
                    self.selected_event_types.push(event_type.to_string());
                } else {
                    self.selected_event_types.retain(|x| x != event_type);
                }
                let _ = self.save_config();
            }
        }

        ui.add_space(20.0);

        // Export settings
        ui.label("Export Settings:");
        ui.add_space(10.0);
        
        ui.horizontal(|ui| {
            ui.label("Default export format:");
            let mut format_changed = false;
            egui::ComboBox::from_id_source("default_export_format")
                .selected_text(format!("{:?}", self.export_format))
                .show_ui(ui, |ui| {
                    if ui.selectable_value(&mut self.export_format, ExportFormat::JSON, "JSON").clicked() {
                        format_changed = true;
                    }
                    if ui.selectable_value(&mut self.export_format, ExportFormat::CSV, "CSV").clicked() {
                        format_changed = true;
                    }
                    if ui.selectable_value(&mut self.export_format, ExportFormat::TXT, "TXT").clicked() {
                        format_changed = true;
                    }
                });
            if format_changed {
                let _ = self.save_config();
            }
        });

        ui.add_space(20.0);

        // Save/Load buttons
        ui.label("Configuration:");
        ui.add_space(10.0);
        
        ui.horizontal(|ui| {
            if ui.button("💾 Save Settings").clicked() {
                match self.save_config() {
                    Ok(_) => {
                        ui.label("✅ Settings saved successfully!");
                    }
                    Err(e) => {
                        ui.label(format!("❌ Error saving settings: {}", e));
                    }
                }
            }
            
            ui.add_space(20.0);
            
            if ui.button("📊 Export Events").clicked() {
                match self.save_export_to_file() {
                    Ok(filename) => {
                        ui.label(format!("✅ Exported to: export/{}", filename));
                    }
                    Err(e) => {
                        ui.label(format!("❌ Export failed: {}", e));
                    }
                }
            }
            
            ui.add_space(20.0);
            
            if ui.button("🔄 Reset to Defaults").clicked() {
                // Reset to defaults
                self.dark_mode = true;
                self.show_timestamps = true;
                self.auto_scroll = true;
                self.max_events = 1000;
                self.selected_event_types = vec![
                    "Process".to_string(), "Service".to_string(), "Registry".to_string(),
                    "Driver".to_string(), "Autostart".to_string(), "Hook".to_string(),
                ];
                self.event_filter = String::new();
                {
                    let mut graph_data = self.graph_data.lock().unwrap();
                    graph_data.max_points = 100;
                }
                self.export_format = ExportFormat::JSON;
                self.search_text = String::new();
                self.highlight_search = false;
                
                let _ = self.save_config();
            }
        });

        ui.add_space(20.0);

        // About section
        ui.label("About FenrirWatch:");
        ui.label("🐺 Advanced Windows system monitoring");
        ui.label("📊 Real-time process, service, driver, registry monitoring");
        ui.label("🔍 Security-focused event logging and analysis");
        ui.label("📈 Live graphs and statistics");
        ui.label("⚙️  Configurable monitoring and filtering");
        ui.label("💾 Multi-format export capabilities");
        ui.label("🔧 Settings are automatically saved to config.yaml");
        
        ui.add_space(10.0);
        ui.label("Version: 0.1.0");
        ui.label("Built with Rust and egui");
    }
}

// Legacy function for backward compatibility
pub fn launch_gui(receiver: Receiver<Event>) {
    let gui = FenrirWatchGUI::new(receiver);
    if let Err(e) = gui.run() {
        eprintln!("GUI error: {}", e);
    }
}
