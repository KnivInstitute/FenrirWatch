mod core;
mod gui;
mod config;

use core::{ProcessMonitor, RegistryMonitor, ServiceMonitor, DriverMonitor, AutostartMonitor, HookDetector, FileSystemMonitor, NetworkMonitor};
use core::Event;
use core::EventLogger;
use config::Config;
use crossbeam_channel::unbounded;

fn main() {
    println!("FenrirWatch starting up...");
    // Always load from src/config/config.yaml using our local config module
    let config = match Config::load_yaml_config("src/config/config.yaml") {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("[Config] Failed to load src/config/config.yaml: {}. Using defaults.", e);
            Config::default()
        }
    };
    
    // Create channels for events
    let (sender, receiver) = unbounded::<core::Event>();
    let (log_sender, log_receiver) = unbounded::<core::Event>();
    let (gui_sender, gui_receiver) = unbounded::<core::Event>();
    
    // Fan out events to both logger and GUI
    {
        let log_sender = log_sender.clone();
        let gui_sender = gui_sender.clone();
        std::thread::spawn(move || {
            for event in receiver.iter() {
                let _ = log_sender.send(event.clone());
                let _ = gui_sender.send(event);
            }
        });
    }
    
    // Start all monitors in background threads
    {
        let sender = sender.clone();
        std::thread::spawn(move || {
            let monitor = ProcessMonitor;
            if let Err(e) = monitor.start_with_sender(sender) {
                eprintln!("Error in ProcessMonitor: {}", e);
            }
        });
    }
    {
        let sender = sender.clone();
        std::thread::spawn(move || {
            let mut monitor = RegistryMonitor::new();
            if let Err(e) = monitor.start_with_sender(sender) {
                eprintln!("Error in RegistryMonitor: {}", e);
            }
        });
    }
    {
        let sender = sender.clone();
        std::thread::spawn(move || {
            let monitor = ServiceMonitor;
            if let Err(e) = monitor.start_with_sender(sender) {
                eprintln!("Error in ServiceMonitor: {}", e);
            }
        });
    }
    {
        let sender = sender.clone();
        std::thread::spawn(move || {
            let mut monitor = DriverMonitor::new();
            if let Err(e) = monitor.start_with_sender(sender) {
                eprintln!("Error in DriverMonitor: {}", e);
            }
        });
    }
    {
        let sender = sender.clone();
        std::thread::spawn(move || {
            let monitor = AutostartMonitor;
            if let Err(e) = monitor.start_with_sender(sender) {
                eprintln!("Error in AutostartMonitor: {}", e);
            }
        });
    }
    {
        let sender = sender.clone();
        std::thread::spawn(move || {
            let monitor = HookDetector;
            if let Err(e) = monitor.start_with_sender(sender) {
                eprintln!("Error in HookDetector: {}", e);
            }
        });
    }
    {
        let sender = sender.clone();
        std::thread::spawn(move || {
            let monitor = FileSystemMonitor;
            if let Err(e) = monitor.start_with_sender(sender) {
                eprintln!("Error in FileSystemMonitor: {}", e);
            }
        });
    }
    {
        let sender = sender.clone();
        std::thread::spawn(move || {
            let monitor = NetworkMonitor;
            if let Err(e) = monitor.start_with_sender(sender) {
                eprintln!("Error in NetworkMonitor: {}", e);
            }
        });
    }
    
    // Start logger
    EventLogger::start_logging(log_receiver, &config.log_path);
    
    // Launch the GUI (main thread)
    gui::launch_gui(gui_receiver);

    // After GUI window closes, signal background threads to stop
    core::request_shutdown();
    // Give monitors time to flush and exit
    std::thread::sleep(std::time::Duration::from_secs(1));
}
