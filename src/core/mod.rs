// Core logic module

use std::error::Error;
use crossbeam_channel::{Sender, Receiver};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use winreg::RegKey;
use winreg::enums::*;
use std::path::PathBuf;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::process::Command;
use std::collections::HashMap;

// Windows API imports for process monitoring
use windows::{
    core::GUID as WindowsGUID,
    Win32::Foundation::{CloseHandle, BOOL},
    Win32::System::ProcessStatus::GetModuleFileNameExW,
    Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    Win32::System::Registry::{HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER},
};

// ETW Provider GUIDs (for future ETW implementation)
// const KERNEL_IMAGE_GUID: WindowsGUID = WindowsGUID::from_u128(0x2cb15d1d_5fc1_11d2_abe1_00a0c911f518);
// const KERNEL_PROCESS_GUID: WindowsGUID = WindowsGUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_4fcc19da7094);

// Global sender for ETW callback (wrapped in Arc<Mutex> for thread safety)
static mut GLOBAL_SENDER: Option<Arc<Mutex<Sender<Event>>>> = None;

// Process information cache for parent-child relationships
static mut PROCESS_CACHE: Option<Arc<Mutex<HashMap<u32, RealTimeProcessInfo>>>> = None;

// ETW Event structures (for future ETW implementation)
// #[repr(C)]
// #[derive(Debug)]
// struct ProcessEventHeader {
//     size: u16,
//     event_type: u16,
//     timestamp: u64,
//     process_id: u32,
//     parent_process_id: u32,
//     session_id: u32,
//     exit_status: u32,
//     directory_table_base: u64,
//     user_sid_length: u32,
//     user_sid_offset: u32,
//     command_line_length: u32,
//     command_line_offset: u32,
//     image_name_length: u32,
//     image_name_offset: u32,
// }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessEventType {
    Created,
    Terminated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub event_type: ProcessEventType,
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub command_line: Option<String>,
    pub executable_path: Option<String>,
    pub user: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    Process(ProcessEvent),
    Service(String),
    Driver(String),
    Registry(String),
    Autostart(String),
    Hook(String),
}

#[derive(Debug, Clone)]
pub struct RealTimeProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub command_line: Option<String>,
    pub executable_path: Option<String>,
    pub user: Option<String>,
    pub creation_time: std::time::SystemTime,
}

pub struct ProcessMonitor;
pub struct RegistryMonitor;
pub struct ServiceMonitor;
pub struct DriverMonitor;
pub struct AutostartMonitor;
pub struct HookDetector;

impl ProcessMonitor {
    pub fn start_with_sender(self, sender: Sender<Event>) -> Result<(), Box<dyn Error>> {
        // Initialize global sender and process cache
        unsafe {
            GLOBAL_SENDER = Some(Arc::new(Mutex::new(sender.clone())));
            PROCESS_CACHE = Some(Arc::new(Mutex::new(HashMap::new())));
        }

        let _ = sender.send(Event::Process(ProcessEvent {
            event_type: ProcessEventType::Created,
            pid: 0,
            ppid: 0,
            name: "ProcessMonitor".to_string(),
            command_line: None,
            executable_path: None,
            user: Some("system".to_string()),
            timestamp: Utc::now(),
        }));

        // Start with fallback monitoring instead of ETW for now
        let _ = sender.send(Event::Process(ProcessEvent {
            event_type: ProcessEventType::Created,
            pid: 0,
            ppid: 0,
            name: "ProcessMonitor: Starting simplified process monitoring".to_string(),
            command_line: Some("Using tasklist-based monitoring due to ETW complexity".to_string()),
            executable_path: None,
            user: Some("system".to_string()),
            timestamp: Utc::now(),
        }));

        // Get initial processes using tasklist for baseline
        if let Ok(output) = Command::new("tasklist").args(&["/FO", "CSV", "/NH"]).output() {
            if let Ok(output_str) = String::from_utf8(output.stdout) {
                let mut process_count = 0;
                for line in output_str.lines().take(20) {
                    if let Some(process_info) = parse_tasklist_line(line) {
                        // Add to cache
                        unsafe {
                            if let Some(cache) = &PROCESS_CACHE {
                                if let Ok(mut cache) = cache.lock() {
                                    cache.insert(process_info.pid, RealTimeProcessInfo {
                                        pid: process_info.pid,
                                        ppid: 0, // Will be updated by future implementation
                                        name: process_info.name.clone(),
                                        command_line: None,
                                        executable_path: Some(process_info.path.clone()),
                                        user: Some(process_info.user.clone()),
                                        creation_time: std::time::SystemTime::now(),
                                    });
                                }
                            }
                        }
                        
                        let _ = sender.send(Event::Process(ProcessEvent {
                            event_type: ProcessEventType::Created,
                            pid: process_info.pid,
                            ppid: 0,
                            name: process_info.name,
                            command_line: None,
                            executable_path: Some(process_info.path),
                            user: Some(process_info.user),
                            timestamp: Utc::now(),
                        }));
                        process_count += 1;
                    }
                }
                
                let _ = sender.send(Event::Process(ProcessEvent {
                    event_type: ProcessEventType::Created,
                    pid: 0,
                    ppid: 0,
                    name: format!("ProcessMonitor: Found {} active processes via tasklist", process_count),
                    command_line: Some("Initial process scan completed - switching to periodic monitoring".to_string()),
                    executable_path: None,
                    user: Some("system".to_string()),
                    timestamp: Utc::now(),
                }));
            }
        }

        // Start periodic monitoring instead of ETW
        let sender_clone = sender.clone();
        std::thread::spawn(move || {
            Self::fallback_periodic_monitoring(sender_clone);
        });

        Ok(())
    }

    fn fallback_periodic_monitoring(sender: Sender<Event>) {
        let mut last_processes: HashMap<u32, String> = HashMap::new();
        let mut scan_count = 0;
        let mut last_summary_time = std::time::Instant::now();
        
        loop {
            // Sleep longer to reduce resource usage
            std::thread::sleep(std::time::Duration::from_secs(5));
            scan_count += 1;
            
            // Add error handling and rate limiting
            match Command::new("tasklist").args(&["/FO", "CSV", "/NH"]).output() {
                Ok(output) => {
                    if let Ok(output_str) = String::from_utf8(output.stdout) {
                        let current_processes: HashMap<u32, String> = output_str
                            .lines()
                            .filter_map(|line| parse_tasklist_line(line))
                            .map(|info| (info.pid, info.name))
                            .collect();
                        
                        let mut new_processes = 0;
                        let mut terminated_processes = 0;
                        
                        // Find new processes (limit to prevent spam)
                        for (pid, name) in &current_processes {
                            if !last_processes.contains_key(pid) {
                                new_processes += 1;
                                if new_processes <= 10 { // Limit events per scan
                                    let _ = sender.send(Event::Process(ProcessEvent {
                                        event_type: ProcessEventType::Created,
                                        pid: *pid,
                                        ppid: 0,
                                        name: name.clone(),
                                        command_line: None,
                                        executable_path: None,
                                        user: Some("system".to_string()),
                                        timestamp: Utc::now(),
                                    }));
                                }
                            }
                        }
                        
                        // Find terminated processes (limit to prevent spam)
                        for (pid, name) in &last_processes {
                            if !current_processes.contains_key(pid) {
                                terminated_processes += 1;
                                if terminated_processes <= 10 { // Limit events per scan
                                    let _ = sender.send(Event::Process(ProcessEvent {
                                        event_type: ProcessEventType::Terminated,
                                        pid: *pid,
                                        ppid: 0,
                                        name: name.clone(),
                                        command_line: None,
                                        executable_path: None,
                                        user: Some("system".to_string()),
                                        timestamp: Utc::now(),
                                    }));
                                }
                            }
                        }
                        
                        // Send summary every 30 seconds instead of individual events
                        if last_summary_time.elapsed() > std::time::Duration::from_secs(30) {
                            if new_processes > 0 || terminated_processes > 0 {
                                let _ = sender.send(Event::Process(ProcessEvent {
                                    event_type: ProcessEventType::Created,
                                    pid: 0,
                                    ppid: 0,
                                    name: format!("ProcessMonitor: Scan #{} - {} new, {} terminated processes", 
                                                scan_count, new_processes, terminated_processes),
                                    command_line: Some("Periodic process scan completed".to_string()),
                                    executable_path: None,
                                    user: Some("system".to_string()),
                                    timestamp: Utc::now(),
                                }));
                            }
                            last_summary_time = std::time::Instant::now();
                        }
                        
                        last_processes = current_processes;
                    }
                }
                Err(e) => {
                    // Log error but don't crash
                    eprintln!("[ProcessMonitor] Error running tasklist: {}", e);
                    std::thread::sleep(std::time::Duration::from_secs(10)); // Wait longer on error
                }
            }
        }
    }
}

impl ServiceMonitor {
    pub fn start_with_sender(self, sender: Sender<Event>) -> Result<(), Box<dyn Error>> {
        let _ = sender.send(Event::Service("[ServiceMonitor] Starting service monitoring...".to_string()));

        // Get initial services using sc query
        if let Ok(output) = Command::new("sc").args(&["query", "type=", "service", "state=", "all"]).output() {
            if let Ok(output_str) = String::from_utf8(output.stdout) {
                let mut service_count = 0;
                let mut current_service = String::new();
                let mut current_state = String::new();
                
                for line in output_str.lines() {
                    if line.starts_with("SERVICE_NAME:") {
                        if !current_service.is_empty() && !current_state.is_empty() {
                            let _ = sender.send(Event::Service(format!(
                                "[ServiceMonitor] Service: {} | State: {}",
                                current_service.trim(), current_state.trim()
                            )));
                            service_count += 1;
                        }
                        current_service = line.replace("SERVICE_NAME:", "").trim().to_string();
                        current_state = String::new();
                    } else if line.trim().starts_with("STATE") {
                        if let Some(state) = line.split_whitespace().nth(1) {
                            current_state = state.to_string();
                        }
                    }
                }
                
                // Send the last service
                if !current_service.is_empty() && !current_state.is_empty() {
                    let _ = sender.send(Event::Service(format!(
                        "[ServiceMonitor] Service: {} | State: {}",
                        current_service.trim(), current_state.trim()
                    )));
                    service_count += 1;
                }
                
                let _ = sender.send(Event::Service(format!(
                    "[ServiceMonitor] Found {} active services via sc command",
                    service_count
                )));
            }
        }

        // Monitor for service changes using periodic scanning
        let sender_clone = sender.clone();
        std::thread::spawn(move || {
            let mut last_services = HashMap::new();
            
            loop {
                std::thread::sleep(std::time::Duration::from_secs(10));
                
                if let Ok(output) = Command::new("sc").args(&["query", "type=", "service", "state=", "all"]).output() {
                    if let Ok(output_str) = String::from_utf8(output.stdout) {
                        let mut current_services = HashMap::new();
                        let mut current_service = String::new();
                        let mut current_state = String::new();
                        
                        for line in output_str.lines() {
                            if line.starts_with("SERVICE_NAME:") {
                                if !current_service.is_empty() && !current_state.is_empty() {
                                    current_services.insert(current_service.trim().to_string(), current_state.trim().to_string());
                                }
                                current_service = line.replace("SERVICE_NAME:", "").trim().to_string();
                                current_state = String::new();
                            } else if line.trim().starts_with("STATE") {
                                if let Some(state) = line.split_whitespace().nth(1) {
                                    current_state = state.to_string();
                                }
                            }
                        }
                        
                        // Process the last service
                        if !current_service.is_empty() && !current_state.is_empty() {
                            current_services.insert(current_service.trim().to_string(), current_state.trim().to_string());
                        }
                        
                        // Check for service state changes
                        for (name, state) in &current_services {
                            if let Some(old_state) = last_services.get(name) {
                                if old_state != state {
                                    let _ = sender_clone.send(Event::Service(format!(
                                        "[ServiceMonitor] Service changed: {} | Old State: {} | New State: {}",
                                        name, old_state, state
                                    )));
                                }
                            }
                        }
                        
                        last_services = current_services;
                    }
                }
            }
        });

        Ok(())
    }
}

impl RegistryMonitor {
    pub fn new() -> Self {
        RegistryMonitor
    }

    pub fn start_with_sender(&mut self, sender: Sender<Event>) -> Result<(), Box<dyn Error>> {
        let _ = sender.send(Event::Registry("[RegistryMonitor] Starting real-time registry monitoring...".to_string()));

        // Critical registry keys to monitor for security
        let critical_keys = vec![
            (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
            (HKEY_CURRENT_USER.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_CURRENT_USER.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks"),
            (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"),
            (HKEY_LOCAL_MACHINE.0 as isize, r"SYSTEM\CurrentControlSet\Services"),
            (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"),
            (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
        ];

        // Initial scan of critical keys
        for (hive, subkey) in &critical_keys {
            let key = RegKey::predef(*hive);
            if let Ok(subkey_handle) = key.open_subkey_with_flags(subkey, KEY_READ) {
                let _ = sender.send(Event::Registry(format!(
                    "[RegistryMonitor] Monitoring: {}",
                    subkey
                )));
                
                // Enumerate initial values
                for (name, value) in subkey_handle.enum_values().filter_map(|x| x.ok()) {
                    let msg = format!("Initial: {} = {:?}", name, value);
                    let _ = sender.send(Event::Registry(msg));
                }
            }
        }

        // Start enhanced periodic monitoring
        let sender_clone = sender.clone();
        std::thread::spawn(move || {
            Self::enhanced_registry_monitoring(sender_clone, critical_keys);
        });

        Ok(())
    }

    fn enhanced_registry_monitoring(sender: Sender<Event>, critical_keys: Vec<(isize, &'static str)>) {
        let mut last_values: HashMap<String, String> = HashMap::new();
        let mut scan_count = 0;
        let mut last_summary_time = std::time::Instant::now();
        
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3)); // More frequent scanning
            scan_count += 1;
            
            let mut current_values: HashMap<String, String> = HashMap::new();
            let mut changes_detected = 0;
            
            for (hive, subkey) in &critical_keys {
                let key = RegKey::predef(*hive);
                if let Ok(subkey_handle) = key.open_subkey_with_flags(subkey, KEY_READ) {
                    let key_name = format!("{}\\{}", 
                        if *hive == HKEY_LOCAL_MACHINE.0 as isize { "HKLM" } else { "HKCU" }, 
                        subkey
                    );
                    
                    for (name, value) in subkey_handle.enum_values().filter_map(|x| x.ok()) {
                        let full_key = format!("{}\\{}", key_name, name);
                        let value_str = format!("{:?}", value);
                        current_values.insert(full_key.clone(), value_str.clone());
                        
                        // Check for new or changed values
                        if let Some(old_value) = last_values.get(&full_key) {
                            if old_value != &value_str {
                                changes_detected += 1;
                                let _ = sender.send(Event::Registry(format!(
                                    "[RegistryMonitor] CHANGED: {} = {} (was: {})",
                                    full_key, value_str, old_value
                                )));
                            }
                        } else {
                            changes_detected += 1;
                            let _ = sender.send(Event::Registry(format!(
                                "[RegistryMonitor] NEW: {} = {}",
                                full_key, value_str
                            )));
                        }
                    }
                    
                    // Check for removed values
                    for (key_name, _) in &last_values {
                        if key_name.starts_with(&format!("{}\\", key_name)) && !current_values.contains_key(key_name) {
                            changes_detected += 1;
                            let _ = sender.send(Event::Registry(format!(
                                "[RegistryMonitor] REMOVED: {}",
                                key_name
                            )));
                        }
                    }
                }
            }
            
            // Send periodic summary
            if last_summary_time.elapsed() > std::time::Duration::from_secs(30) {
                if changes_detected > 0 {
                    let _ = sender.send(Event::Registry(format!(
                        "[RegistryMonitor] Scan #{} - {} registry changes detected",
                        scan_count, changes_detected
                    )));
                }
                last_summary_time = std::time::Instant::now();
            }
            
            last_values = current_values;
        }
    }
}

impl DriverMonitor {
    pub fn new() -> Self {
        DriverMonitor
    }

    pub fn start_with_sender(&mut self, sender: Sender<Event>) -> Result<(), Box<dyn Error>> {
        let _ = sender.send(Event::Driver("[DriverMonitor] Starting driver monitoring...".to_string()));

        // Get initial drivers using driverquery command
        if let Ok(output) = Command::new("driverquery").args(&["/FO", "CSV", "/NH"]).output() {
            if let Ok(output_str) = String::from_utf8(output.stdout) {
                let mut driver_count = 0;
                for line in output_str.lines().take(20) {
                    if let Some(driver_info) = parse_driverquery_line(line) {
                        let _ = sender.send(Event::Driver(format!(
                            "[DriverMonitor] Initial Driver: {} | State: {} | Path: {}",
                            driver_info.name, driver_info.state, driver_info.path
                        )));
                        driver_count += 1;
                    }
                }
                
                let _ = sender.send(Event::Driver(format!(
                    "[DriverMonitor] Found {} active drivers via driverquery",
                    driver_count
                )));
            }
        }

        // Monitor for driver changes using periodic scanning
        let sender_clone = sender.clone();
        std::thread::spawn(move || {
            let mut last_drivers = HashMap::new();
            let mut scan_count = 0;
            
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                scan_count += 1;
                
                if let Ok(output) = Command::new("driverquery").args(&["/FO", "CSV", "/NH"]).output() {
                    if let Ok(output_str) = String::from_utf8(output.stdout) {
                        let current_drivers: HashMap<String, String> = output_str
                            .lines()
                            .filter_map(|line| parse_driverquery_line(line))
                            .map(|info| (info.name.clone(), info.state))
                            .collect();
                        
                        // Send periodic scan info for testing
                        if scan_count % 3 == 0 {
                            let _ = sender_clone.send(Event::Driver(format!(
                                "[DriverMonitor] Periodic scan #{} - Found {} drivers",
                                scan_count, current_drivers.len()
                            )));
                        }
                        
                        // Check for new drivers
                        for (name, state) in &current_drivers {
                            if !last_drivers.contains_key(name) {
                                let _ = sender_clone.send(Event::Driver(format!(
                                    "[DriverMonitor] NEW DRIVER DETECTED: {} | State: {}",
                                    name, state
                                )));
                            } else if let Some(old_state) = last_drivers.get(name) {
                                if old_state != state {
                                    let _ = sender_clone.send(Event::Driver(format!(
                                        "[DriverMonitor] Driver changed: {} | Old State: {} | New State: {}",
                                        name, old_state, state
                                    )));
                                }
                            }
                        }
                        
                        // Check for removed drivers
                        for (name, _) in &last_drivers {
                            if !current_drivers.contains_key(name) {
                                let _ = sender_clone.send(Event::Driver(format!(
                                    "[DriverMonitor] DRIVER REMOVED: {}",
                                    name
                                )));
                            }
                        }
                        
                        last_drivers = current_drivers;
                    }
                }
            }
        });

        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), Box<dyn Error>> {
        println!("[DriverMonitor] Driver monitoring stopped");
        Ok(())
    }
}

impl Drop for DriverMonitor {
    fn drop(&mut self) {
        let _ = self.stop();
        println!("[DriverMonitor] DriverMonitor dropped");
    }
}

impl AutostartMonitor {
    pub fn start_with_sender(&self, sender: Sender<Event>) -> Result<(), Box<dyn Error>> {
        let _ = sender.send(Event::Autostart("[AutostartMonitor] Starting autostart monitoring...".to_string()));

        // Registry locations to check - using proper HKEY conversion
        let registry_locations = vec![
            (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (HKEY_CURRENT_USER.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_CURRENT_USER.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ];

        for (hive, subkey) in registry_locations {
            let key = RegKey::predef(hive);
            if let Ok(subkey_handle) = key.open_subkey(subkey) {
                for (name, value) in subkey_handle.enum_values().filter_map(|x| x.ok()) {
                    let msg = format!("Registry: {} = {:?}", name, value);
                    let _ = sender.send(Event::Autostart(msg));
                }
            }
        }

        // Scan startup folders
        let startup_folders = vec![
            std::env::var("APPDATA").ok().map(|appdata| PathBuf::from(appdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup")),
            std::env::var("PROGRAMDATA").ok().map(|progdata| PathBuf::from(progdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup")),
        ];

        for folder in startup_folders.into_iter().flatten() {
            if let Ok(entries) = fs::read_dir(folder) {
                for entry in entries.filter_map(|x| x.ok()) {
                    let path = entry.path();
                    if let Some(file_name) = path.file_name() {
                        let msg = format!("Startup folder: {}", file_name.to_string_lossy());
                        let _ = sender.send(Event::Autostart(msg));
                    }
                }
            }
        }

        let _ = sender.send(Event::Autostart("Autostart monitoring completed".to_string()));
        Ok(())
    }
}

impl HookDetector {
    pub fn start_with_sender(&self, sender: Sender<Event>) -> Result<(), Box<dyn Error>> {
        let _ = sender.send(Event::Hook("Hook detection not yet implemented".to_string()));
        Ok(())
    }
}

// Helper struct for parsing tasklist output
struct ProcessInfo {
    name: String,
    pid: u32,
    path: String,
    user: String,
}

fn parse_tasklist_line(line: &str) -> Option<ProcessInfo> {
    let parts: Vec<&str> = line.split(',').collect();
    if parts.len() >= 3 {
        let name = parts[0].trim_matches('"').to_string();
        let pid_str = parts[1].trim_matches('"');
        if let Ok(pid) = pid_str.parse::<u32>() {
            let path = if parts.len() > 4 { parts[4].trim_matches('"').to_string() } else { String::new() };
            let user = if parts.len() > 5 { parts[5].trim_matches('"').to_string() } else { "Unknown".to_string() };
            return Some(ProcessInfo { name, pid, path, user });
        }
    }
    None
}

// Helper struct for parsing driverquery output
struct DriverInfo {
    name: String,
    state: String,
    path: String,
}

fn parse_driverquery_line(line: &str) -> Option<DriverInfo> {
    let parts: Vec<&str> = line.split(',').collect();
    if parts.len() >= 3 {
        let name = parts[0].trim_matches('"').to_string();
        let state = parts[1].trim_matches('"').to_string();
        let path = parts[2].trim_matches('"').to_string();
        return Some(DriverInfo { name, state, path });
    }
    None
}

// Helper functions for process information (for future ETW implementation)
// unsafe fn get_process_executable_path(pid: u32) -> Option<String> {
//     let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, BOOL::from(false), pid);
//     if handle.is_ok() {
//         let handle = handle.unwrap();
//         let mut buffer = [0u16; 260];
//         let result = GetModuleFileNameExW(handle, None, &mut buffer);
//         let _ = CloseHandle(handle);
//         
//         if result > 0 {
//             let path = String::from_utf16_lossy(&buffer[..result as usize]);
//             Some(path)
//         } else {
//             None
//         }
//     } else {
//         None
//     }
// }
// 
// unsafe fn get_process_name_from_path(path: &str) -> String {
//     if let Some(file_name) = std::path::Path::new(path).file_name() {
//         file_name.to_string_lossy().to_string()
//     } else {
//         "Unknown".to_string()
//     }
// }

// Process tree and details functions for GUI
pub fn get_process_tree() -> Vec<(u32, u32, String)> {
    unsafe {
        if let Some(cache) = &PROCESS_CACHE {
            if let Ok(cache) = cache.lock() {
                return cache.iter()
                    .map(|(pid, info)| (*pid, info.ppid, info.name.clone()))
                    .collect();
            }
        }
    }
    Vec::new()
}

pub fn get_process_details(pid: u32) -> Option<RealTimeProcessInfo> {
    unsafe {
        if let Some(cache) = &PROCESS_CACHE {
            if let Ok(cache) = cache.lock() {
                return cache.get(&pid).cloned();
            }
        }
    }
    None
}

pub struct EventLogger;

impl EventLogger {
    pub fn start_logging(receiver: Receiver<Event>, log_path: &str) {
        let log_path = log_path.to_string();
        std::thread::spawn(move || {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path);

            match file {
                Ok(mut file) => {
                    for event in receiver.iter() {
                        if let Ok(json) = serde_json::to_string(&event) {
                            if let Err(e) = writeln!(file, "{}", json) {
                                eprintln!("[EventLogger] Failed to write to log: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[EventLogger] Failed to open log file: {}", e);
                }
            }
        });
    }
}