// GUI module

use crossbeam_channel::Receiver;
use crate::Event;
use crate::core::ProcessEventType;
use eframe::egui;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

pub struct FenrirWatchGUI {
    receiver: Receiver<Event>,
    events: Arc<Mutex<VecDeque<LogEvent>>>,
    selected_tab: usize,
    auto_scroll: bool,
    max_events: usize,
}

#[derive(Clone)]
struct LogEvent {
    timestamp: chrono::DateTime<chrono::Utc>,
    event_type: String,
    message: String,
    color: egui::Color32,
}

impl FenrirWatchGUI {
    pub fn new(receiver: Receiver<Event>) -> Self {
        FenrirWatchGUI {
            receiver,
            events: Arc::new(Mutex::new(VecDeque::new())),
            selected_tab: 0,
            auto_scroll: true,
            max_events: 1000,
        }
    }

    pub fn run(self) -> eframe::Result<()> {
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1200.0, 800.0])
                .with_min_inner_size([800.0, 600.0]),
            ..Default::default()
        };

        eframe::run_native(
            "FenrirWatch - System Monitor",
            options,
            Box::new(|_cc| Box::new(self)),
        )
    }

    fn process_events(&mut self) {
        let mut event_count = 0;
        let max_events_per_frame = 50; // Limit events processed per frame
        
        // Process events with rate limiting
        while event_count < max_events_per_frame {
            match self.receiver.try_recv() {
                Ok(event) => {
                    event_count += 1;
                    let log_event = self.convert_event_to_log(event);
                    let mut events = self.events.lock().unwrap();
                    events.push_back(log_event);
                    
                    // Keep only the last max_events
                    while events.len() > self.max_events {
                        events.pop_front();
                    }
                }
                Err(_) => break, // No more events to process
            }
        }
        
        // Debug output if many events were processed
        if event_count > 10 {
            println!("[GUI] Processed {} events (limited to prevent lag)", event_count);
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
                }
            },
            Event::Service(service_msg) => {
                LogEvent {
                    timestamp,
                    event_type: "Service".to_string(),
                    message: format!("⚙️  {}", service_msg),
                    color: egui::Color32::from_rgb(255, 165, 0),
                }
            },
            Event::Driver(driver_msg) => {
                let color = if driver_msg.contains("LOADED") {
                    egui::Color32::from_rgb(0, 255, 0)
                } else if driver_msg.contains("UNLOADED") {
                    egui::Color32::from_rgb(255, 0, 0)
                } else {
                    egui::Color32::from_rgb(0, 191, 255)
                };
                LogEvent {
                    timestamp,
                    event_type: "Driver".to_string(),
                    message: format!("🚗 {}", driver_msg),
                    color,
                }
            },
            Event::Registry(registry_msg) => {
                LogEvent {
                    timestamp,
                    event_type: "Registry".to_string(),
                    message: format!("🔧 {}", registry_msg),
                    color: egui::Color32::from_rgb(255, 255, 0),
                }
            },
            Event::Autostart(autostart_msg) => {
                LogEvent {
                    timestamp,
                    event_type: "Autostart".to_string(),
                    message: format!("🚀 {}", autostart_msg),
                    color: egui::Color32::from_rgb(255, 0, 255),
                }
            },
            Event::Hook(hook_msg) => {
                LogEvent {
                    timestamp,
                    event_type: "Hook".to_string(),
                    message: format!("⚠️  {}", hook_msg),
                    color: egui::Color32::from_rgb(255, 0, 0),
                }
            }
        }
    }
}

impl eframe::App for FenrirWatchGUI {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Process incoming events
        self.process_events();

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🐺 FenrirWatch - System Monitor");
            ui.add_space(10.0);

            // Tab bar
            egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let tabs = ["📊 Console Log", "🌳 Process Tree", "📈 Statistics", "⚙️  Settings"];
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
                0 => self.show_console_tab(ui),
                1 => self.show_process_tree_tab(ui),
                2 => self.show_statistics_tab(ui),
                3 => self.show_settings_tab(ui),
                _ => {}
            }
        });

        // Request continuous updates
        ctx.request_repaint();
    }
}

impl FenrirWatchGUI {
    fn show_console_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Auto-scroll:");
            ui.checkbox(&mut self.auto_scroll, "");
            ui.add_space(20.0);
            ui.label("Max events:");
            ui.add(egui::DragValue::new(&mut self.max_events).clamp_range(100..=10000));
            if ui.button("Clear Log").clicked() {
                self.events.lock().unwrap().clear();
            }
        });

        ui.add_space(10.0);

        // Console log area
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(self.auto_scroll)
            .show(ui, |ui| {
                let events = self.events.lock().unwrap();
                for event in events.iter() {
                    ui.horizontal(|ui| {
                        // Timestamp
                        ui.label(egui::RichText::new(
                            event.timestamp.format("%H:%M:%S").to_string()
                        ).color(egui::Color32::GRAY));
                        
                        // Event type
                        ui.label(egui::RichText::new(
                            format!("[{}]", event.event_type)
                        ).color(egui::Color32::LIGHT_GRAY));
                        
                        // Message
                        ui.label(egui::RichText::new(&event.message).color(event.color));
                    });
                }
            });
    }

    fn show_process_tree_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("🌳 Process Tree");
        ui.add_space(20.0);

        // Get process tree from core module with error handling
        let process_tree = match std::panic::catch_unwind(|| crate::core::get_process_tree()) {
            Ok(tree) => tree,
            Err(_) => {
                ui.label("⚠️  Error loading process tree. Please try again.");
                return;
            }
        };
        
        ui.label(format!("Active Processes: {}", process_tree.len()));
        ui.add_space(10.0);

        // Limit the number of processes displayed to prevent lag
        let max_processes = 100;
        let display_tree: Vec<_> = process_tree.into_iter().take(max_processes).collect();
        
        if display_tree.len() >= max_processes {
            ui.label(format!("⚠️  Showing first {} processes (limited to prevent lag)", max_processes));
        }

        // Create a tree view of processes
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
            
            // Display process tree with depth limiting
            for root_pid in roots.iter().take(20) { // Limit root processes too
                self.display_process_node(ui, root_pid, &process_map, &children_map, 0);
            }
        });
    }

    fn display_process_node(
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
            ui.label(format!("{}{} (PID: {})", indent, name, pid));
            
            // Show process details on click (with error handling)
            if ui.button("📋").clicked() {
                if let Some(details) = crate::core::get_process_details(*pid) {
                    ui.label(format!("Path: {}", details.executable_path.unwrap_or_else(|| "Unknown".to_string())));
                    ui.label(format!("User: {}", details.user.unwrap_or_else(|| "Unknown".to_string())));
                }
            }
        });
        
        // Display children with limit
        if let Some(children) = children_map.get(pid) {
            for (i, child_pid) in children.iter().take(5).enumerate() { // Limit children per node
                if i >= 5 {
                    ui.label(format!("{}... (showing first 5 children)", "  ".repeat(depth + 1)));
                    break;
                }
                self.display_process_node(ui, child_pid, process_map, children_map, depth + 1);
            }
        }
    }

    fn show_statistics_tab(&self, ui: &mut egui::Ui) {
        ui.heading("📈 System Statistics");
        ui.add_space(20.0);

        let events = self.events.lock().unwrap();
        let mut stats = std::collections::HashMap::new();
        
        for event in events.iter() {
            *stats.entry(&event.event_type).or_insert(0) += 1;
        }

        ui.label("Event Counts:");
        for (event_type, count) in stats.iter() {
            ui.label(format!("{}: {}", event_type, count));
        }

        ui.add_space(20.0);
        ui.label(format!("Total Events: {}", events.len()));
    }

    fn show_settings_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("⚙️  Settings");
        ui.add_space(20.0);

        ui.label("Console Settings:");
        ui.add_space(10.0);
        
        ui.horizontal(|ui| {
            ui.label("Max events to display:");
            ui.add(egui::DragValue::new(&mut self.max_events).clamp_range(100..=10000));
        });

        ui.add_space(10.0);
        ui.checkbox(&mut self.auto_scroll, "Auto-scroll to latest events");

        ui.add_space(20.0);
        ui.label("About FenrirWatch:");
        ui.label("🐺 Real-time Windows system monitoring");
        ui.label("📊 Process, Service, Driver, Registry monitoring");
        ui.label("🔍 Security-focused event logging");
    }
}

// Legacy function for backward compatibility
pub fn launch_gui(receiver: Receiver<Event>) {
    let gui = FenrirWatchGUI::new(receiver);
    if let Err(e) = gui.run() {
        eprintln!("GUI error: {}", e);
    }
}
