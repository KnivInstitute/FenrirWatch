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
        while let Ok(event) = self.receiver.try_recv() {
            event_count += 1;
            let log_event = self.convert_event_to_log(event);
            let mut events = self.events.lock().unwrap();
            events.push_back(log_event);
            
            // Keep only the last max_events
            while events.len() > self.max_events {
                events.pop_front();
            }
        }
        
        // Debug output if events were processed
        if event_count > 0 {
            println!("[GUI] Processed {} events", event_count);
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
                    let tabs = ["📊 Console Log", "📈 Statistics", "⚙️  Settings"];
                    for (i, tab) in tabs.iter().enumerate() {
                        let mut selected = self.selected_tab == i;
                        if ui.selectable_label(selected, *tab).clicked() {
                            self.selected_tab = i;
                        }
                    }
                });
            });

            // Tab content
            match self.selected_tab {
                0 => self.show_console_tab(ui),
                1 => self.show_statistics_tab(ui),
                2 => self.show_settings_tab(ui),
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
