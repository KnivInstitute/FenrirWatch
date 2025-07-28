// Core logic module

use std::error::Error;
use crossbeam_channel::{Sender, Receiver};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use wmi::{WMIConnection, COMLibrary};
use winreg::RegKey;
use winreg::enums::*;
use winapi::um::winreg::{RegOpenKeyExW, RegCloseKey, RegNotifyChangeKeyValue, HKEY_LOCAL_MACHINE};
use winapi::shared::minwindef::HKEY__;
use widestring::U16CString;
use std::path::PathBuf;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};
use std::process::Command;
use std::collections::HashMap;
use windows::{
    core::{PCWSTR, PWSTR, GUID as WindowsGUID},
    Win32::Foundation::{ERROR_SUCCESS, INVALID_HANDLE_VALUE, HANDLE, CloseHandle},
    Win32::System::Diagnostics::Etw::{
        EVENT_RECORD, EVENT_TRACE_FLAG_IMAGE_LOAD, EVENT_TRACE_LOGFILEW,
        EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, 
        OpenTraceW, ProcessTrace, StartTraceW, StopTraceW,
        PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
        CONTROLTRACE_HANDLE, PROCESSTRACE_HANDLE, WNODE_FLAG_TRACED_GUID,
    },
};

// Kernel Image Load Provider GUID (converted to Windows crate format)
const KERNEL_IMAGE_GUID: WindowsGUID = WindowsGUID::from_u128(0x2cb15d1d_5fc1_11d2_abe1_00a0c911f518);

// Global sender for ETW callback (wrapped in Arc<Mutex> for thread safety)
static mut GLOBAL_SENDER: Option<Arc<Mutex<Sender<Event>>>> = None;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    Process(ProcessEvent),
    Service(String),
    Driver(String),
    Registry(String),
    Autostart(String),
    Hook(String),
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
pub enum ProcessEventType {
    Created,
    Terminated,
}

pub struct ProcessMonitor;
pub struct RegistryMonitor {
    hkey: Option<usize>,
}
pub struct ServiceMonitor;
pub struct DriverMonitor {
    session_handle: Option<CONTROLTRACE_HANDLE>,
    trace_handle: Option<PROCESSTRACE_HANDLE>,
}
pub struct AutostartMonitor;
pub struct HookDetector;

impl ProcessMonitor {
    pub fn start_with_sender(self, sender: Sender<Event>) -> std::result::Result<(), Box<dyn Error>> {
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

        // Use tasklist command to get real process information
        let _ = sender.send(Event::Process(ProcessEvent {
            event_type: ProcessEventType::Created,
            pid: 0,
            ppid: 0,
            name: "ProcessMonitor: Using tasklist for process enumeration".to_string(),
            command_line: Some("Getting real process list via Windows API".to_string()),
            executable_path: None,
            user: Some("system".to_string()),
            timestamp: Utc::now(),
        }));

        // Get initial processes using tasklist
        if let Ok(output) = Command::new("tasklist").args(&["/FO", "CSV", "/NH"]).output() {
            if let Ok(output_str) = String::from_utf8(output.stdout) {
                let mut process_count = 0;
                for line in output_str.lines().take(20) {
                    if let Some(process_info) = parse_tasklist_line(line) {
                        let _ = sender.send(Event::Process(ProcessEvent {
                            event_type: ProcessEventType::Created,
                            pid: process_info.pid,
                            ppid: 0, // tasklist doesn't show parent PID
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
                    command_line: Some("Initial process scan completed".to_string()),
                    executable_path: None,
                    user: Some("system".to_string()),
                    timestamp: Utc::now(),
                }));
            }
        }

        // Monitor for new processes using periodic scanning
        let sender_clone = sender.clone();
        std::thread::spawn(move || {
            let mut last_processes = HashMap::new();
            
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                
                if let Ok(output) = Command::new("tasklist").args(&["/FO", "CSV", "/NH"]).output() {
                    if let Ok(output_str) = String::from_utf8(output.stdout) {
                        let current_processes: HashMap<u32, String> = output_str
                            .lines()
                            .filter_map(|line| parse_tasklist_line(line))
                            .map(|info| (info.pid, info.name))
                            .collect();
                        
                        // Find new processes
                        for (pid, name) in &current_processes {
                            if !last_processes.contains_key(pid) {
                                let _ = sender_clone.send(Event::Process(ProcessEvent {
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
                        
                        last_processes = current_processes;
                    }
                }
            }
        });

        Ok(())
    }
}

impl ServiceMonitor {
    pub fn start_with_sender(self, sender: Sender<Event>) -> std::result::Result<(), Box<dyn Error>> {
        let _ = sender.send(Event::Service("[ServiceMonitor] Starting service monitoring...".to_string()));

        // Use sc command to get real service information
        let _ = sender.send(Event::Service("[ServiceMonitor] Using sc command for service enumeration".to_string()));

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
                    } else if line.starts_with("STATE") {
                        current_state = line.split_whitespace().nth(1).unwrap_or("Unknown").to_string();
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
                            } else if line.starts_with("STATE") {
                                current_state = line.split_whitespace().nth(1).unwrap_or("Unknown").to_string();
                            }
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

impl RegistryMonitor {
    pub fn new() -> Self {
        RegistryMonitor { hkey: None }
    }
    pub fn start_with_sender(&mut self, sender: Sender<Event>) -> std::result::Result<(), Box<dyn Error>> {
        let subkey = U16CString::from_str("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run").map_err(|e| format!("String error: {}", e))?;
        let mut hkey: *mut HKEY__ = std::ptr::null_mut();
        let result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                0,
                KEY_READ | KEY_NOTIFY,
                &mut hkey as *mut *mut HKEY__,
            )
        };
        if result != 0 {
            eprintln!("RegOpenKeyExW failed: {}", result);
            return Err(format!("RegOpenKeyExW failed: {}", result).into());
        }
        self.hkey = Some(hkey as usize);

        // Enumerate values using winreg for initial scan
        let hklm = RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
        let run_key = hklm.open_subkey_with_flags(r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_READ)?;
        for (name, value) in run_key.enum_values().filter_map(|x| x.ok()) {
            let msg = format!("Initial: {} = {:?}", name, value);
            let _ = sender.send(Event::Registry(msg));
        }

        let sender2 = sender.clone();
        let hkey_usize = hkey as usize;
        std::thread::spawn(move || {
            loop {
                let res = unsafe {
                    RegNotifyChangeKeyValue(
                        hkey_usize as *mut HKEY__,
                        0,
                        0x00000001 | 0x00000004, // REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET
                        std::ptr::null_mut(),
                        0,
                    )
                };
                if res == 0 {
                    let _ = sender2.send(Event::Registry("Change detected in HKLM...Run".to_string()));
                } else {
                    eprintln!("[RegistryMonitor] RegNotifyChangeKeyValue failed: {}", res);
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            unsafe { RegCloseKey(hkey_usize as *mut HKEY__); }
        });
        let _ = sender.send(Event::Registry("ETW-based registry event tracing not yet implemented.".to_string()));
        Ok(())
    }
}

impl DriverMonitor {
    pub fn new() -> Self {
        DriverMonitor { 
            session_handle: None,
            trace_handle: None,
        }
    }

    pub fn start_with_sender(&mut self, sender: Sender<Event>) -> std::result::Result<(), Box<dyn Error>> {
        let _ = sender.send(Event::Driver("[DriverMonitor] Starting driver monitoring...".to_string()));
        
        // Send a test event to verify the system is working
        let _ = sender.send(Event::Driver("[DriverMonitor] TEST: Driver monitoring system is active!".to_string()));

        // Use a simpler approach that doesn't require complex ETW session management
        let _ = sender.send(Event::Driver("[DriverMonitor] Using driver enumeration via Windows API".to_string()));

        // Get initial drivers using driverquery command
        if let Ok(output) = Command::new("driverquery").args(&["/FO", "CSV", "/NH"]).output() {
            if let Ok(output_str) = String::from_utf8(output.stdout) {
                let mut driver_count = 0;
                for line in output_str.lines().take(20) { // Show more drivers
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

        // Monitor for driver changes using periodic scanning - more frequent for testing
        let sender_clone = sender.clone();
        std::thread::spawn(move || {
            let mut last_drivers = HashMap::new();
            let mut scan_count = 0;
            
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5)); // More frequent scanning
                scan_count += 1;
                
                if let Ok(output) = Command::new("driverquery").args(&["/FO", "CSV", "/NH"]).output() {
                    if let Ok(output_str) = String::from_utf8(output.stdout) {
                        let current_drivers: HashMap<String, String> = output_str
                            .lines()
                            .filter_map(|line| parse_driverquery_line(line))
                            .map(|info| (info.name.clone(), info.state))
                            .collect();
                        
                        // Send periodic scan info for testing
                        if scan_count % 3 == 0 { // Every 15 seconds
                            let _ = sender_clone.send(Event::Driver(format!(
                                "[DriverMonitor] Periodic scan #{} - Found {} drivers",
                                scan_count, current_drivers.len()
                            )));
                        }
                        
                        // Check for new drivers (not just state changes)
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

    pub fn stop(&mut self) -> std::result::Result<(), Box<dyn Error>> {
        // No cleanup needed for simplified approach
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

impl AutostartMonitor {
    pub fn start_with_sender(&self, sender: Sender<Event>) -> std::result::Result<(), Box<dyn Error>> {
        // Instead of cloning RegKey, create new handles for each use
        let hklm1 = RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
        let hklm2 = RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
        let hkcu1 = RegKey::predef(HKEY_CURRENT_USER);
        let hkcu2 = RegKey::predef(HKEY_CURRENT_USER);

        let run_keys = vec![
            (hklm1, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (hklm2, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (hkcu1, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (hkcu2, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ];

        for (key, subkey) in run_keys {
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
    pub fn start_with_sender(&self, sender: Sender<Event>) -> std::result::Result<(), Box<dyn Error>> {
        let _ = sender.send(Event::Hook("Hook detection not yet implemented".to_string()));
        Ok(())
    }
}

#[derive(Deserialize, Debug)]
pub struct Win32Process {
    #[serde(rename = "Name")]
    pub Name: Option<String>,
    #[serde(rename = "ProcessId")]
    pub ProcessId: Option<u32>,
    #[serde(rename = "ParentProcessId")]
    pub ParentProcessId: Option<u32>,
    #[serde(rename = "CommandLine")]
    pub CommandLine: Option<String>,
    #[serde(rename = "ExecutablePath")]
    pub ExecutablePath: Option<String>,
    #[serde(rename = "State")]
    pub State: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InstanceCreationEvent {
    #[serde(rename = "TargetInstance")]
    pub TargetInstance: Option<Win32Process>,
}

#[derive(Debug, Deserialize)]
struct Win32Service {
    #[serde(rename = "Name")]
    pub Name: Option<String>,
    #[serde(rename = "DisplayName")]
    pub DisplayName: Option<String>,
    #[serde(rename = "State")]
    pub State: Option<String>,
    #[serde(rename = "PathName")]
    pub PathName: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ServiceEventWMI {
    #[serde(rename = "TargetInstance")]
    pub TargetInstance: Option<Win32Service>,
}

#[derive(Debug, Deserialize)]
struct Win32SystemDriver {
    #[serde(rename = "Name")]
    pub Name: Option<String>,
    #[serde(rename = "State")]
    pub State: Option<String>,
    #[serde(rename = "PathName")]
    pub PathName: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DriverEventWMI {
    #[serde(rename = "TargetInstance")]
    pub TargetInstance: Option<Win32SystemDriver>,
}

pub struct EventLogger;

impl EventLogger {
    pub fn start_logging(receiver: Receiver<Event>, log_path: &str) {
        let log_path = log_path.to_string(); // Convert to owned String
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
