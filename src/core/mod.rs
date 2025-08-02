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
use std::sync::atomic::{AtomicBool, Ordering};
use once_cell::sync::Lazy;

// Global graceful shutdown flag
pub static SHUTDOWN_FLAG: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));

/// Returns true if a shutdown has been requested.
pub fn is_shutdown() -> bool {
    SHUTDOWN_FLAG.load(Ordering::Relaxed)
}

/// Request all background threads to terminate gracefully.
pub fn request_shutdown() {
    SHUTDOWN_FLAG.store(true, Ordering::Relaxed);
}

// Windows API imports for registry monitoring
use windows::{
    Win32::System::Registry::{HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER},
    Win32::NetworkManagement::IpHelper::*,
    Win32::Networking::WinSock::*,
    Win32::Foundation::*,
};

// Global sender for ETW callback (wrapped in Arc<Mutex> for thread safety)
static mut GLOBAL_SENDER: Option<Arc<Mutex<Sender<Event>>>> = None;

// Process information cache for parent-child relationships
static mut PROCESS_CACHE: Option<Arc<Mutex<HashMap<u32, RealTimeProcessInfo>>>> = None;

// Rate limiting for repetitive events
static mut RATE_LIMIT_CACHE: Option<Arc<Mutex<HashMap<String, DateTime<Utc>>>>> = None;

// Rate limiting helper function
fn should_rate_limit(event_key: &str, window_seconds: i64) -> bool {
    unsafe {
        // Use raw pointer to avoid static mut reference warning
        let cache_ptr = &raw const RATE_LIMIT_CACHE;
        if let Some(cache) = (*cache_ptr).as_ref() {
            if let Ok(mut cache) = cache.lock() {
                let now = Utc::now();
                if let Some(last_time) = cache.get(event_key) {
                    if now.signed_duration_since(*last_time).num_seconds() < window_seconds {
                        return true; // Rate limit this event
                    }
                }
                cache.insert(event_key.to_string(), now);
                return false; // Allow this event
            }
        }
        false // Allow if cache is not available
    }
}


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
    FileSystem(FileSystemEvent),
    Network(NetworkEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileSystemEventType {
    Created,
    Modified,
    Deleted,
    Renamed,
    Accessed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSystemEvent {
    pub event_type: FileSystemEventType,
    pub path: String,
    pub size: Option<u64>,
    pub process_pid: Option<u32>,
    pub process_name: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkEventType {
    ConnectionEstablished,
    ConnectionClosed,
    DataTransferred,
    ConnectionAttempt,
    DNSQuery,
    SuspiciousConnection,
    HighTrafficConnection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub event_type: NetworkEventType,
    pub local_address: String,
    pub remote_address: String,
    pub local_port: Option<u16>,
    pub remote_port: Option<u16>,
    pub protocol: String,
    pub process_pid: Option<u32>,
    pub process_name: Option<String>,
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
    pub dns_query: Option<String>,
    pub dns_response: Option<String>,
    pub connection_state: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NetworkConnectionInfo {
    pub local_address: String,
    pub remote_address: String,
    pub local_port: Option<u16>,
    pub remote_port: Option<u16>,
    pub protocol: String,
    pub process_pid: Option<u32>,
    pub process_name: Option<String>,
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
    pub connection_state: String,
    #[allow(dead_code)]
    pub creation_time: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct RealTimeProcessInfo {
    #[allow(dead_code)]
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    #[allow(dead_code)]
    pub command_line: Option<String>,
    pub executable_path: Option<String>,
    pub user: Option<String>,
    #[allow(dead_code)]
    pub creation_time: std::time::SystemTime,
}

/// Process monitoring implementation using tasklist fallback
/// 
/// This monitor tracks process creation and termination events using the `tasklist` command
/// as a fallback method since ETW implementation is not yet complete.
/// 
/// Features:
/// - Initial process baseline establishment
/// - Periodic scanning for new/terminated processes
/// - Process cache management for GUI display
/// - Rate limiting to prevent event spam
/// - Error handling for command execution failures
pub struct ProcessMonitor;

/// Registry monitoring implementation for security-critical keys
/// 
/// Monitors critical registry locations for unauthorized changes that could indicate
/// malware activity or system compromise.
/// 
/// Monitored locations:
/// - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
/// - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
/// - HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
/// - HKLM\SYSTEM\CurrentControlSet\Services
/// - And other security-critical registry paths
pub struct RegistryMonitor;

/// Service monitoring implementation using sc command
/// 
/// Tracks Windows service state changes using the `sc query` command.
/// Monitors for unauthorized service modifications that could indicate
/// persistence mechanisms or privilege escalation attempts.
pub struct ServiceMonitor;

/// Driver monitoring implementation using driverquery command
/// 
/// Monitors kernel driver loading/unloading events using the `driverquery` command.
/// Critical for detecting rootkit activity and unauthorized kernel modifications.
pub struct DriverMonitor;

/// Autostart monitoring for persistence detection
/// 
/// Scans registry autostart locations and startup folders to detect
/// unauthorized persistence mechanisms that could indicate malware installation.
pub struct AutostartMonitor;

/// Hook detection for API monitoring (placeholder)
/// 
/// Future implementation will scan for inline hooks and API detours
/// that could indicate monitoring evasion or malicious activity.
pub struct HookDetector;

/// File system monitoring for security analysis
/// 
/// Monitors file system events including creation, modification, deletion,
/// and access patterns that could indicate malicious activity or data exfiltration.
/// 
/// Monitored events:
/// - File creation in sensitive directories
/// - File modifications in system directories
/// - Deletion of important files
/// - Access to user data directories
/// - Suspicious file extensions and patterns
pub struct FileSystemMonitor;

/// Network connection monitoring for threat detection
/// 
/// Tracks network connections, data transfers, and communication patterns
/// that could indicate malware communication, data exfiltration, or
/// unauthorized network activity.
/// 
/// Monitored events:
/// - New network connections
/// - Data transfer patterns
/// - DNS queries and resolution
/// - Connection to suspicious IPs
/// - Process-specific network activity
pub struct NetworkMonitor;

impl ProcessMonitor {
    /// Starts process monitoring with the provided event sender
    /// 
    /// This function initializes the process monitoring system and begins tracking
    /// process creation and termination events. It uses a fallback approach with
    /// the `tasklist` command since ETW implementation is not yet complete.
    /// 
    /// # Arguments
    /// * `sender` - Channel sender for broadcasting process events
    /// 
    /// # Returns
    /// * `Result<(), Box<dyn Error>>` - Success or error status
    /// 
    /// # Features
    /// * Establishes initial process baseline
    /// * Starts periodic monitoring thread
    /// * Initializes process cache for GUI
    /// * Implements rate limiting to prevent spam
    /// * Enhanced error handling and recovery
    pub fn start_with_sender(self, sender: Sender<Event>) -> Result<(), Box<dyn Error>> {
        // Initialize global sender and process cache
        unsafe {
            GLOBAL_SENDER = Some(Arc::new(Mutex::new(sender.clone())));
            PROCESS_CACHE = Some(Arc::new(Mutex::new(HashMap::new())));
            RATE_LIMIT_CACHE = Some(Arc::new(Mutex::new(HashMap::new())));
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
                            // Use raw pointer to avoid static mut reference warning
                            let cache_ptr = &raw const PROCESS_CACHE;
                            if let Some(cache) = (*cache_ptr).as_ref() {
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
        let mut consecutive_errors = 0;
        const MAX_CONSECUTIVE_ERRORS: u32 = 5;
        
        loop {
            if is_shutdown() {
                if let Err(e) = sender.send(Event::Process(ProcessEvent {
                    event_type: ProcessEventType::Terminated,
                    pid: 0,
                    ppid: 0,
                    name: "ProcessMonitor shutting down".to_string(),
                    command_line: None,
                    executable_path: None,
                    user: Some("system".to_string()),
                    timestamp: Utc::now(),
                })) {
                    eprintln!("[ProcessMonitor] Failed to send shutdown event: {:?}", e);
                }
                break;
            }
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
                        let mut event_errors = 0;
                        
                        // Find new processes (limit to prevent spam)
                        for (pid, name) in &current_processes {
                            if !last_processes.contains_key(pid) {
                                new_processes += 1;
                                if new_processes <= 10 { // Limit events per scan
                                    if let Err(e) = sender.send(Event::Process(ProcessEvent {
                                        event_type: ProcessEventType::Created,
                                        pid: *pid,
                                        ppid: 0,
                                        name: name.clone(),
                                        command_line: None,
                                        executable_path: None,
                                        user: Some("system".to_string()),
                                        timestamp: Utc::now(),
                                    })) {
                                        eprintln!("[ProcessMonitor] Failed to send new process event: {:?}", e);
                                        event_errors += 1;
                                    }
                                }
                            }
                        }
                        
                        // Find terminated processes (limit to prevent spam)
                        for (pid, name) in &last_processes {
                            if !current_processes.contains_key(pid) {
                                terminated_processes += 1;
                                if terminated_processes <= 10 { // Limit events per scan
                                    if let Err(e) = sender.send(Event::Process(ProcessEvent {
                                        event_type: ProcessEventType::Terminated,
                                        pid: *pid,
                                        ppid: 0,
                                        name: name.clone(),
                                        command_line: None,
                                        executable_path: None,
                                        user: Some("system".to_string()),
                                        timestamp: Utc::now(),
                                    })) {
                                        eprintln!("[ProcessMonitor] Failed to send terminated process event: {:?}", e);
                                        event_errors += 1;
                                    }
                                }
                            }
                        }
                        
                        // Send summary every 30 seconds instead of individual events
                        if last_summary_time.elapsed() > std::time::Duration::from_secs(30) {
                            if new_processes > 0 || terminated_processes > 0 {
                                if let Err(e) = sender.send(Event::Process(ProcessEvent {
                                    event_type: ProcessEventType::Created,
                                    pid: 0,
                                    ppid: 0,
                                    name: format!("ProcessMonitor: Scan #{} - {} new, {} terminated processes", 
                                                scan_count, new_processes, terminated_processes),
                                    command_line: Some("Periodic process scan completed".to_string()),
                                    executable_path: None,
                                    user: Some("system".to_string()),
                                    timestamp: Utc::now(),
                                })) {
                                    eprintln!("[ProcessMonitor] Failed to send summary event: {:?}", e);
                                    event_errors += 1;
                                }
                            }
                            last_summary_time = std::time::Instant::now();
                        }
                        
                        // Reset error count on successful scan
                        if event_errors == 0 {
                            consecutive_errors = 0;
                        } else {
                            consecutive_errors += 1;
                        }
                        
                        last_processes = current_processes;
                    } else {
                        consecutive_errors += 1;
                        eprintln!("[ProcessMonitor] Failed to parse tasklist output");
                    }
                }
                Err(e) => {
                    consecutive_errors += 1;
                    eprintln!("[ProcessMonitor] Error running tasklist: {}", e);
                    
                    // Send error event if we haven't had too many consecutive errors
                    if consecutive_errors <= MAX_CONSECUTIVE_ERRORS {
                        let _ = sender.send(Event::Process(ProcessEvent {
                            event_type: ProcessEventType::Created,
                            pid: 0,
                            ppid: 0,
                            name: format!("ProcessMonitor: Error - {}", e),
                            command_line: Some("Tasklist command failed".to_string()),
                            executable_path: None,
                            user: Some("system".to_string()),
                            timestamp: Utc::now(),
                        }));
                    }
                    
                    // Exponential backoff on consecutive errors
                    let backoff_duration = std::time::Duration::from_secs(10 * 2u64.pow(consecutive_errors.min(3)));
                    std::thread::sleep(backoff_duration);
                    
                    // Stop if too many consecutive errors
                    if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                        eprintln!("[ProcessMonitor] Too many consecutive errors, stopping process monitoring");
                        let _ = sender.send(Event::Process(ProcessEvent {
                            event_type: ProcessEventType::Created,
                            pid: 0,
                            ppid: 0,
                            name: "ProcessMonitor: Stopped due to excessive errors".to_string(),
                            command_line: Some("Monitoring stopped".to_string()),
                            executable_path: None,
                            user: Some("system".to_string()),
                            timestamp: Utc::now(),
                        }));
                        break;
                    }
                }
            }
        }
    }
}

impl ServiceMonitor {
    pub fn start_with_sender(self, sender: Sender<Event>) -> Result<(), Box<dyn Error>> {
        if let Err(e) = sender.send(Event::Service("[ServiceMonitor] Starting service monitoring...".to_string())) {
            eprintln!("[ServiceMonitor] Failed to send start event: {:?}", e);
        }

        // Get initial services using sc query
        match Command::new("sc").args(&["query", "type=", "service", "state=", "all"]).output() {
            Ok(output) => {
                if let Ok(output_str) = String::from_utf8(output.stdout) {
                    let mut service_count = 0;
                    let mut current_service = String::new();
                    let mut current_state = String::new();
                    let mut event_errors = 0;
                    
                    for line in output_str.lines() {
                        if line.starts_with("SERVICE_NAME:") {
                            if !current_service.is_empty() && !current_state.is_empty() {
                                if let Err(e) = sender.send(Event::Service(format!(
                                    "[ServiceMonitor] Service: {} | State: {}",
                                    current_service.trim(), current_state.trim()
                                ))) {
                                    eprintln!("[ServiceMonitor] Failed to send service event: {:?}", e);
                                    event_errors += 1;
                                } else {
                                    service_count += 1;
                                }
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
                        if let Err(e) = sender.send(Event::Service(format!(
                            "[ServiceMonitor] Service: {} | State: {}",
                            current_service.trim(), current_state.trim()
                        ))) {
                            eprintln!("[ServiceMonitor] Failed to send final service event: {:?}", e);
                            event_errors += 1;
                        } else {
                            service_count += 1;
                        }
                    }
                    
                    if let Err(e) = sender.send(Event::Service(format!(
                        "[ServiceMonitor] Found {} active services via sc command ({} event errors)",
                        service_count, event_errors
                    ))) {
                        eprintln!("[ServiceMonitor] Failed to send summary event: {:?}", e);
                    }
                } else {
                    if let Err(e) = sender.send(Event::Service("[ServiceMonitor] Error: Failed to parse sc command output".to_string())) {
                        eprintln!("[ServiceMonitor] Failed to send parse error event: {:?}", e);
                    }
                }
            }
            Err(e) => {
                if let Err(send_err) = sender.send(Event::Service(format!(
                    "[ServiceMonitor] Error: Failed to execute sc command: {}",
                    e
                ))) {
                    eprintln!("[ServiceMonitor] Failed to send command error event: {:?}", send_err);
                }
            }
        }

        // Monitor for service changes using periodic scanning
        let sender_clone = sender.clone();
        std::thread::spawn(move || {
            let mut last_services = HashMap::new();
            let mut consecutive_errors = 0;
            const MAX_CONSECUTIVE_ERRORS: u32 = 5;
            
            loop {
                if is_shutdown() {
                    if let Err(e) = sender_clone.send(Event::Service("[ServiceMonitor] Shutting down".to_string())) {
                        eprintln!("[ServiceMonitor] Failed to send shutdown event: {:?}", e);
                    }
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(10));
                
                match Command::new("sc").args(&["query", "type=", "service", "state=", "all"]).output() {
                    Ok(output) => {
                        if let Ok(output_str) = String::from_utf8(output.stdout) {
                            let mut current_services = HashMap::new();
                            let mut current_service = String::new();
                            let mut current_state = String::new();
                            let mut event_errors = 0;
                            
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
                                        if let Err(e) = sender_clone.send(Event::Service(format!(
                                            "[ServiceMonitor] Service changed: {} | Old State: {} | New State: {}",
                                            name, old_state, state
                                        ))) {
                                            eprintln!("[ServiceMonitor] Failed to send service change event: {:?}", e);
                                            event_errors += 1;
                                        }
                                    }
                                }
                            }
                            
                            // Reset error count on successful scan
                            if event_errors == 0 {
                                consecutive_errors = 0;
                            } else {
                                consecutive_errors += 1;
                            }
                            
                            last_services = current_services;
                        } else {
                            consecutive_errors += 1;
                            eprintln!("[ServiceMonitor] Error: Failed to parse sc command output");
                            
                            if consecutive_errors <= MAX_CONSECUTIVE_ERRORS {
                                let _ = sender_clone.send(Event::Service("[ServiceMonitor] Error: Failed to parse sc command output".to_string()));
                            }
                        }
                    }
                    Err(e) => {
                        consecutive_errors += 1;
                        eprintln!("[ServiceMonitor] Error: Failed to execute sc command: {}", e);
                        
                        if consecutive_errors <= MAX_CONSECUTIVE_ERRORS {
                            let _ = sender_clone.send(Event::Service(format!(
                                "[ServiceMonitor] Error: Failed to execute sc command: {}",
                                e
                            )));
                        }
                        
                        // Exponential backoff on consecutive errors
                        let backoff_duration = std::time::Duration::from_secs(10 * 2u64.pow(consecutive_errors.min(3)));
                        std::thread::sleep(backoff_duration);
                        
                        // Stop if too many consecutive errors
                        if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                            eprintln!("[ServiceMonitor] Too many consecutive errors, stopping service monitoring");
                            let _ = sender_clone.send(Event::Service("[ServiceMonitor] Stopped due to excessive errors".to_string()));
                            break;
                        }
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
        if let Err(e) = sender.send(Event::Registry("[RegistryMonitor] Starting real-time registry monitoring...".to_string())) {
            eprintln!("[RegistryMonitor] Failed to send start event: {:?}", e);
        }

        // Critical registry keys to monitor for security
        // Separated into required and optional keys for better error handling
        let critical_keys = vec![
            (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (HKEY_CURRENT_USER.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_CURRENT_USER.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
        ];
        
        // Optional registry keys that may not exist on all systems
        let optional_keys = vec![
            (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
            (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks"),
            (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"),
            (HKEY_LOCAL_MACHINE.0 as isize, r"SYSTEM\CurrentControlSet\Services"),
            (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"),
        ];

        // Initial scan of critical keys
        let mut event_errors = 0;
        let mut keys_monitored = 0;
        
        // Process critical keys (report errors)
        for (hive, subkey) in &critical_keys {
            let key = RegKey::predef(*hive);
            match key.open_subkey_with_flags(subkey, KEY_READ) {
                Ok(subkey_handle) => {
                    keys_monitored += 1;
                    if let Err(e) = sender.send(Event::Registry(format!(
                        "[RegistryMonitor] Monitoring critical key: {}",
                        subkey
                    ))) {
                        eprintln!("[RegistryMonitor] Failed to send monitoring event: {:?}", e);
                        event_errors += 1;
                    }
                    
                    // Enumerate initial values
                    for (name, value) in subkey_handle.enum_values().filter_map(|x| x.ok()) {
                        let msg = format!("Initial: {} = {:?}", name, value);
                        if let Err(e) = sender.send(Event::Registry(msg)) {
                            eprintln!("[RegistryMonitor] Failed to send initial value event: {:?}", e);
                            event_errors += 1;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[RegistryMonitor] CRITICAL: Failed to access registry key {}: {:?}", subkey, e);
                    if let Err(send_err) = sender.send(Event::Registry(format!(
                        "[RegistryMonitor] CRITICAL ERROR accessing: {} - {:?}",
                        subkey, e
                    ))) {
                        eprintln!("[RegistryMonitor] Failed to send registry error event: {:?}", send_err);
                    }
                    event_errors += 1;
                }
            }
        }
        
        // Process optional keys (silently skip missing ones)
        for (hive, subkey) in &optional_keys {
            let key = RegKey::predef(*hive);
            match key.open_subkey_with_flags(subkey, KEY_READ) {
                Ok(subkey_handle) => {
                    keys_monitored += 1;
                    if let Err(e) = sender.send(Event::Registry(format!(
                        "[RegistryMonitor] Monitoring optional key: {}",
                        subkey
                    ))) {
                        eprintln!("[RegistryMonitor] Failed to send monitoring event: {:?}", e);
                        event_errors += 1;
                    }
                    
                    // Enumerate initial values
                    for (name, value) in subkey_handle.enum_values().filter_map(|x| x.ok()) {
                        let msg = format!("Initial: {} = {:?}", name, value);
                        if let Err(e) = sender.send(Event::Registry(msg)) {
                            eprintln!("[RegistryMonitor] Failed to send initial value event: {:?}", e);
                            event_errors += 1;
                        }
                    }
                }
                Err(e) => {
                    // For optional keys, only log at debug level if key doesn't exist
                    if e.kind() == std::io::ErrorKind::NotFound {
                        // Silently skip - this is expected for optional keys
                        continue;
                    } else {
                        eprintln!("[RegistryMonitor] Warning: Failed to access optional registry key {}: {:?}", subkey, e);
                    }
                }
            }
        }

        // Send summary of initial scan
        if let Err(e) = sender.send(Event::Registry(format!(
            "[RegistryMonitor] Initial scan completed: {} keys monitored, {} event errors",
            keys_monitored, event_errors
        ))) {
            eprintln!("[RegistryMonitor] Failed to send initial scan summary: {:?}", e);
        }

        // Start enhanced periodic monitoring
        let sender_clone = sender.clone();
        std::thread::spawn(move || {
            Self::enhanced_registry_monitoring(sender_clone, critical_keys, optional_keys);
        });

        Ok(())
    }

    fn enhanced_registry_monitoring(sender: Sender<Event>, critical_keys: Vec<(isize, &'static str)>, optional_keys: Vec<(isize, &'static str)>) {
        let mut last_values: HashMap<String, String> = HashMap::new();
        let mut scan_count = 0;
        let mut last_summary_time = std::time::Instant::now();
        let mut consecutive_errors = 0;
        const MAX_CONSECUTIVE_ERRORS: u32 = 10;
        
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3)); // More frequent scanning
            scan_count += 1;
            
            let mut current_values: HashMap<String, String> = HashMap::new();
            let mut changes_detected = 0;
            let mut event_errors = 0;
            let mut scan_successful = true;
            
            // Process all keys (critical + optional) with different error handling
            let all_keys: Vec<_> = critical_keys.iter().map(|k| (*k, true)).chain(optional_keys.iter().map(|k| (*k, false))).collect();
            
            for ((hive, subkey), is_critical) in &all_keys {
                let key = RegKey::predef(*hive);
                match key.open_subkey_with_flags(subkey, KEY_READ) {
                    Ok(subkey_handle) => {
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
                                    let event_key = format!("registry_changed_{}", full_key);
                                    if !should_rate_limit(&event_key, 60) { // Rate limit to 1 minute
                                        if let Err(e) = sender.send(Event::Registry(format!(
                                            "[RegistryMonitor] CHANGED: {} = {} (was: {})",
                                            full_key, value_str, old_value
                                        ))) {
                                            eprintln!("[RegistryMonitor] Failed to send change event: {:?}", e);
                                            event_errors += 1;
                                        }
                                    }
                                }
                            } else {
                                changes_detected += 1;
                                let event_key = format!("registry_new_{}", full_key);
                                if !should_rate_limit(&event_key, 60) { // Rate limit to 1 minute
                                    if let Err(e) = sender.send(Event::Registry(format!(
                                        "[RegistryMonitor] NEW: {} = {}",
                                        full_key, value_str
                                    ))) {
                                        eprintln!("[RegistryMonitor] Failed to send new value event: {:?}", e);
                                        event_errors += 1;
                                    }
                                }
                            }
                        }
                        
                        // Check for removed values
                        for (key_name, _) in &last_values {
                            if key_name.starts_with(&format!("{}\\", key_name)) && !current_values.contains_key(key_name) {
                                changes_detected += 1;
                                let event_key = format!("registry_removed_{}", key_name);
                                if !should_rate_limit(&event_key, 60) { // Rate limit to 1 minute
                                    if let Err(e) = sender.send(Event::Registry(format!(
                                        "[RegistryMonitor] REMOVED: {}",
                                        key_name
                                    ))) {
                                        eprintln!("[RegistryMonitor] Failed to send removed value event: {:?}", e);
                                        event_errors += 1;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if *is_critical {
                            eprintln!("[RegistryMonitor] CRITICAL: Failed to access registry key {}: {:?}", subkey, e);
                            scan_successful = false;
                            consecutive_errors += 1;
                        } else {
                            // For optional keys, only log non-NotFound errors
                            if e.kind() != std::io::ErrorKind::NotFound {
                                eprintln!("[RegistryMonitor] Warning: Failed to access optional registry key {}: {:?}", subkey, e);
                            }
                            // Don't count optional key NotFound errors against scan_successful
                        }
                    }
                }
            }
            
            // Update error tracking
            if event_errors > 0 {
                consecutive_errors += 1;
            } else if scan_successful {
                consecutive_errors = 0;
            }
            
            // Send periodic summary
            if last_summary_time.elapsed() > std::time::Duration::from_secs(30) {
                if changes_detected > 0 {
                    if let Err(e) = sender.send(Event::Registry(format!(
                        "[RegistryMonitor] Scan #{} - {} registry changes detected ({} event errors)",
                        scan_count, changes_detected, event_errors
                    ))) {
                        eprintln!("[RegistryMonitor] Failed to send summary event: {:?}", e);
                    }
                }
                last_summary_time = std::time::Instant::now();
            }
            
            // Stop if too many consecutive errors
            if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                eprintln!("[RegistryMonitor] Too many consecutive errors, stopping registry monitoring");
                let _ = sender.send(Event::Registry("[RegistryMonitor] Stopped due to excessive errors".to_string()));
                break;
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
        if let Err(e) = sender.send(Event::Driver("[DriverMonitor] Starting driver monitoring...".to_string())) {
            eprintln!("[DriverMonitor] Failed to send start event: {:?}", e);
        }

        // Get initial drivers using driverquery command
        match Command::new("driverquery").args(&["/FO", "CSV", "/NH"]).output() {
            Ok(output) => {
                if let Ok(output_str) = String::from_utf8(output.stdout) {
                    let mut driver_count = 0;
                    let mut event_errors = 0;
                    
                    for line in output_str.lines().take(20) {
                        if let Some(driver_info) = parse_driverquery_line(line) {
                            if let Err(e) = sender.send(Event::Driver(format!(
                                "[DriverMonitor] Initial Driver: {} | State: {} | Path: {}",
                                driver_info.name, driver_info.state, driver_info.path
                            ))) {
                                eprintln!("[DriverMonitor] Failed to send driver event: {:?}", e);
                                event_errors += 1;
                            } else {
                                driver_count += 1;
                            }
                        }
                    }
                    
                    if let Err(e) = sender.send(Event::Driver(format!(
                        "[DriverMonitor] Found {} active drivers via driverquery ({} event errors)",
                        driver_count, event_errors
                    ))) {
                        eprintln!("[DriverMonitor] Failed to send summary event: {:?}", e);
                    }
                } else {
                    if let Err(e) = sender.send(Event::Driver("[DriverMonitor] Error: Failed to parse driverquery output".to_string())) {
                        eprintln!("[DriverMonitor] Failed to send parse error event: {:?}", e);
                    }
                }
            }
            Err(e) => {
                if let Err(send_err) = sender.send(Event::Driver(format!(
                    "[DriverMonitor] Error: Failed to execute driverquery command: {}",
                    e
                ))) {
                    eprintln!("[DriverMonitor] Failed to send command error event: {:?}", send_err);
                }
            }
        }

        // Monitor for driver changes using periodic scanning
        let sender_clone = sender.clone();
        std::thread::spawn(move || {
            let mut last_drivers = HashMap::new();
            let mut scan_count = 0;
            let mut consecutive_errors = 0;
            const MAX_CONSECUTIVE_ERRORS: u32 = 5;
            
            loop {
                if is_shutdown() {
                    if let Err(e) = sender_clone.send(Event::Driver("[DriverMonitor] Shutting down".to_string())) {
                        eprintln!("[DriverMonitor] Failed to send shutdown event: {:?}", e);
                    }
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(5));
                scan_count += 1;
                
                match Command::new("driverquery").args(&["/FO", "CSV", "/NH"]).output() {
                    Ok(output) => {
                        if let Ok(output_str) = String::from_utf8(output.stdout) {
                            let current_drivers: HashMap<String, String> = output_str
                                .lines()
                                .filter_map(|line| parse_driverquery_line(line))
                                .map(|info| (info.name.clone(), info.state))
                                .collect();
                            
                            let mut event_errors = 0;
                            
                            // Send periodic scan info for testing
                            if scan_count % 3 == 0 {
                                if let Err(e) = sender_clone.send(Event::Driver(format!(
                                    "[DriverMonitor] Periodic scan #{} - Found {} drivers",
                                    scan_count, current_drivers.len()
                                ))) {
                                    eprintln!("[DriverMonitor] Failed to send periodic scan event: {:?}", e);
                                    event_errors += 1;
                                }
                            }
                            
                            // Check for new drivers
                            for (name, state) in &current_drivers {
                                if !last_drivers.contains_key(name) {
                                    if let Err(e) = sender_clone.send(Event::Driver(format!(
                                        "[DriverMonitor] NEW DRIVER DETECTED: {} | State: {}",
                                        name, state
                                    ))) {
                                        eprintln!("[DriverMonitor] Failed to send new driver event: {:?}", e);
                                        event_errors += 1;
                                    }
                                } else if let Some(old_state) = last_drivers.get(name) {
                                    if old_state != state {
                                        if let Err(e) = sender_clone.send(Event::Driver(format!(
                                            "[DriverMonitor] Driver changed: {} | Old State: {} | New State: {}",
                                            name, old_state, state
                                        ))) {
                                            eprintln!("[DriverMonitor] Failed to send driver change event: {:?}", e);
                                            event_errors += 1;
                                        }
                                    }
                                }
                            }
                            
                            // Check for removed drivers
                            for (name, _) in &last_drivers {
                                if !current_drivers.contains_key(name) {
                                    if let Err(e) = sender_clone.send(Event::Driver(format!(
                                        "[DriverMonitor] DRIVER REMOVED: {}",
                                        name
                                    ))) {
                                        eprintln!("[DriverMonitor] Failed to send driver removed event: {:?}", e);
                                        event_errors += 1;
                                    }
                                }
                            }
                            
                            // Reset error count on successful scan
                            if event_errors == 0 {
                                consecutive_errors = 0;
                            } else {
                                consecutive_errors += 1;
                            }
                            
                            last_drivers = current_drivers;
                        } else {
                            consecutive_errors += 1;
                            eprintln!("[DriverMonitor] Error: Failed to parse driverquery output");
                            
                            if consecutive_errors <= MAX_CONSECUTIVE_ERRORS {
                                let _ = sender_clone.send(Event::Driver("[DriverMonitor] Error: Failed to parse driverquery output".to_string()));
                            }
                        }
                    }
                    Err(e) => {
                        consecutive_errors += 1;
                        eprintln!("[DriverMonitor] Error: Failed to execute driverquery command: {}", e);
                        
                        if consecutive_errors <= MAX_CONSECUTIVE_ERRORS {
                            let _ = sender_clone.send(Event::Driver(format!(
                                "[DriverMonitor] Error: Failed to execute driverquery command: {}",
                                e
                            )));
                        }
                        
                        // Exponential backoff on consecutive errors
                        let backoff_duration = std::time::Duration::from_secs(10 * 2u64.pow(consecutive_errors.min(3)));
                        std::thread::sleep(backoff_duration);
                        
                        // Stop if too many consecutive errors
                        if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                            eprintln!("[DriverMonitor] Too many consecutive errors, stopping driver monitoring");
                            let _ = sender_clone.send(Event::Driver("[DriverMonitor] Stopped due to excessive errors".to_string()));
                            break;
                        }
                    }
                }
            }
        });

        Ok(())
    }

    #[allow(dead_code)]
    pub fn stop(&mut self) -> Result<(), Box<dyn Error>> {
        println!("[DriverMonitor] Driver monitoring stopped");
        Ok(())
    }
}

// Removed Drop implementation to prevent misleading "stopped" messages
// The actual monitoring happens in a separate thread and continues independently

impl AutostartMonitor {
    pub fn start_with_sender(&self, sender: Sender<Event>) -> Result<(), Box<dyn Error>> {
        if let Err(e) = sender.send(Event::Autostart("[AutostartMonitor] Starting autostart monitoring...".to_string())) {
            eprintln!("[AutostartMonitor] Failed to send start event: {:?}", e);
        }

        // Registry locations to check - using proper HKEY conversion
        let registry_locations = vec![
            (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (HKEY_CURRENT_USER.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_CURRENT_USER.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ];

        let mut event_errors = 0;
        
        for (hive, subkey) in registry_locations {
            let key = RegKey::predef(hive);
            match key.open_subkey(subkey) {
                Ok(subkey_handle) => {
                    for (name, value) in subkey_handle.enum_values().filter_map(|x| x.ok()) {
                        let event_key = format!("autostart_registry_{}_{}", hive, name);
                        if !should_rate_limit(&event_key, 300) { // Rate limit to 5 minutes
                            let msg = format!("Registry: {} = {:?}", name, value);
                            if let Err(e) = sender.send(Event::Autostart(msg)) {
                                eprintln!("[AutostartMonitor] Failed to send registry autostart event: {:?}", e);
                                event_errors += 1;
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[AutostartMonitor] Failed to access registry key {}: {:?}", subkey, e);
                    if let Err(send_err) = sender.send(Event::Autostart(format!(
                        "Registry error: {} - {:?}",
                        subkey, e
                    ))) {
                        eprintln!("[AutostartMonitor] Failed to send registry error event: {:?}", send_err);
                        event_errors += 1;
                    }
                }
            }
        }

        // Scan startup folders
        let startup_folders = vec![
            std::env::var("APPDATA").ok().map(|appdata| PathBuf::from(appdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup")),
            std::env::var("PROGRAMDATA").ok().map(|progdata| PathBuf::from(progdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup")),
        ];

        for folder in startup_folders.into_iter().flatten() {
            match fs::read_dir(&folder) {
                Ok(entries) => {
                    for entry in entries.filter_map(|x| x.ok()) {
                        let path = entry.path();
                        if let Some(file_name) = path.file_name() {
                            let event_key = format!("autostart_folder_{}", file_name.to_string_lossy());
                            if !should_rate_limit(&event_key, 300) { // Rate limit to 5 minutes
                                let msg = format!("Startup folder: {}", file_name.to_string_lossy());
                                if let Err(e) = sender.send(Event::Autostart(msg)) {
                                    eprintln!("[AutostartMonitor] Failed to send folder autostart event: {:?}", e);
                                    event_errors += 1;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[AutostartMonitor] Failed to read startup folder {:?}: {:?}", folder, e);
                    if let Err(send_err) = sender.send(Event::Autostart(format!(
                        "Folder error: {:?} - {:?}",
                        folder, e
                    ))) {
                        eprintln!("[AutostartMonitor] Failed to send folder error event: {:?}", send_err);
                        event_errors += 1;
                    }
                }
            }
        }

        if let Err(e) = sender.send(Event::Autostart(format!(
            "Autostart monitoring completed ({} event errors)",
            event_errors
        ))) {
            eprintln!("[AutostartMonitor] Failed to send completion event: {:?}", e);
        }
        
        Ok(())
    }
}

impl HookDetector {
    pub fn start_with_sender(&self, sender: Sender<Event>) -> Result<(), Box<dyn Error>> {
        let _ = sender.send(Event::Hook("Hook detection not yet implemented".to_string()));
        Ok(())
    }
}

impl FileSystemMonitor {
    pub fn start_with_sender(&self, sender: Sender<Event>) -> Result<(), Box<dyn Error>> {
        if let Err(e) = sender.send(Event::FileSystem(FileSystemEvent {
            event_type: FileSystemEventType::Created,
            path: "FileSystemMonitor".to_string(),
            size: None,
            process_pid: None,
            process_name: Some("FileSystemMonitor".to_string()),
            timestamp: Utc::now(),
        })) {
            eprintln!("[FileSystemMonitor] Failed to send start event: {:?}", e);
        }

        // Critical directories to monitor
        let critical_dirs = vec![
            std::env::var("SYSTEMROOT").unwrap_or_else(|_| "C:\\Windows".to_string()),
            std::env::var("PROGRAMFILES").unwrap_or_else(|_| "C:\\Program Files".to_string()),
            std::env::var("APPDATA").unwrap_or_else(|_| "C:\\Users\\Default\\AppData\\Roaming".to_string()),
            std::env::var("TEMP").unwrap_or_else(|_| "C:\\Windows\\Temp".to_string()),
            std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Default".to_string()),
        ];

        // Initial scan of critical directories
        let mut _event_errors = 0;
        for dir in &critical_dirs {
            if let Err(e) = sender.send(Event::FileSystem(FileSystemEvent {
                event_type: FileSystemEventType::Accessed,
                path: format!("[FileSystemMonitor] Monitoring directory: {}", dir),
                size: None,
                process_pid: None,
                process_name: Some("FileSystemMonitor".to_string()),
                timestamp: Utc::now(),
            })) {
                eprintln!("[FileSystemMonitor] Failed to send directory monitoring event: {:?}", e);
                _event_errors += 1;
            }
        }

        // Start enhanced file system monitoring
        let sender_clone = sender.clone();
        std::thread::spawn(move || {
            Self::enhanced_file_system_monitoring(sender_clone, critical_dirs);
        });

        Ok(())
    }

    fn enhanced_file_system_monitoring(sender: Sender<Event>, critical_dirs: Vec<String>) {
        let mut last_files: HashMap<String, u64> = HashMap::new();
        let mut scan_count = 0;
        let mut last_summary_time = std::time::Instant::now();
        let mut consecutive_errors = 0;
        const MAX_CONSECUTIVE_ERRORS: u32 = 10;
        
        // Suspicious file extensions to monitor
        let suspicious_extensions = vec![
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr",
            ".com", ".pif", ".lnk", ".hta", ".wsf", ".wsh", ".reg", ".inf"
        ];
        
        loop {
            std::thread::sleep(std::time::Duration::from_secs(2)); // More frequent scanning
            scan_count += 1;
            
            let mut current_files: HashMap<String, u64> = HashMap::new();
            let mut changes_detected = 0;
            let mut event_errors = 0;
            let mut scan_successful = true;
            
            for dir in &critical_dirs {
                match Self::scan_directory(dir) {
                    Ok(files) => {
                        for (file_path, file_size) in files {
                            current_files.insert(file_path.clone(), file_size);
                            
                            // Check for new files
                            if !last_files.contains_key(&file_path) {
                                changes_detected += 1;
                                let event_key = format!("file_created_{}", file_path);
                                if !should_rate_limit(&event_key, 30) { // Rate limit to 30 seconds
                                    let severity = if Self::is_suspicious_file(&file_path, &suspicious_extensions) {
                                        FileSystemEventType::Created
                                    } else {
                                        FileSystemEventType::Created
                                    };
                                    
                                    if let Err(e) = sender.send(Event::FileSystem(FileSystemEvent {
                                        event_type: severity,
                                        path: file_path.clone(),
                                        size: Some(file_size),
                                        process_pid: None, // Will be enhanced with process tracking
                                        process_name: None,
                                        timestamp: Utc::now(),
                                    })) {
                                        eprintln!("[FileSystemMonitor] Failed to send file created event: {:?}", e);
                                        event_errors += 1;
                                    }
                                }
                            } else if let Some(old_size) = last_files.get(&file_path) {
                                // Check for file modifications
                                if old_size != &file_size {
                                    changes_detected += 1;
                                    let event_key = format!("file_modified_{}", file_path);
                                    if !should_rate_limit(&event_key, 60) { // Rate limit to 1 minute
                                        if let Err(e) = sender.send(Event::FileSystem(FileSystemEvent {
                                            event_type: FileSystemEventType::Modified,
                                            path: file_path.clone(),
                                            size: Some(file_size),
                                            process_pid: None,
                                            process_name: None,
                                            timestamp: Utc::now(),
                                        })) {
                                            eprintln!("[FileSystemMonitor] Failed to send file modified event: {:?}", e);
                                            event_errors += 1;
                                        }
                                    }
                                }
                            }
                        }
                        
                        // Check for deleted files
                        for (file_path, _) in &last_files {
                            if !current_files.contains_key(file_path) {
                                changes_detected += 1;
                                let event_key = format!("file_deleted_{}", file_path);
                                if !should_rate_limit(&event_key, 60) { // Rate limit to 1 minute
                                    if let Err(e) = sender.send(Event::FileSystem(FileSystemEvent {
                                        event_type: FileSystemEventType::Deleted,
                                        path: file_path.clone(),
                                        size: None,
                                        process_pid: None,
                                        process_name: None,
                                        timestamp: Utc::now(),
                                    })) {
                                        eprintln!("[FileSystemMonitor] Failed to send file deleted event: {:?}", e);
                                        event_errors += 1;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[FileSystemMonitor] Failed to scan directory {}: {:?}", dir, e);
                        scan_successful = false;
                        consecutive_errors += 1;
                    }
                }
            }
            
            // Update error tracking
            if event_errors > 0 {
                consecutive_errors += 1;
            } else if scan_successful {
                consecutive_errors = 0;
            }
            
            // Send periodic summary
            if last_summary_time.elapsed() > std::time::Duration::from_secs(30) {
                if changes_detected > 0 {
                    if let Err(e) = sender.send(Event::FileSystem(FileSystemEvent {
                        event_type: FileSystemEventType::Accessed,
                        path: format!("[FileSystemMonitor] Scan #{} - {} file system changes detected ({} event errors)",
                                     scan_count, changes_detected, event_errors),
                        size: None,
                        process_pid: None,
                        process_name: Some("FileSystemMonitor".to_string()),
                        timestamp: Utc::now(),
                    })) {
                        eprintln!("[FileSystemMonitor] Failed to send summary event: {:?}", e);
                    }
                }
                last_summary_time = std::time::Instant::now();
            }
            
            // Stop if too many consecutive errors
            if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                eprintln!("[FileSystemMonitor] Too many consecutive errors, stopping file system monitoring");
                let _ = sender.send(Event::FileSystem(FileSystemEvent {
                    event_type: FileSystemEventType::Accessed,
                    path: "[FileSystemMonitor] Stopped due to excessive errors".to_string(),
                    size: None,
                    process_pid: None,
                    process_name: Some("FileSystemMonitor".to_string()),
                    timestamp: Utc::now(),
                }));
                break;
            }
            
            last_files = current_files;
        }
    }

    fn scan_directory(dir_path: &str) -> Result<HashMap<String, u64>, Box<dyn Error>> {
        let mut files = HashMap::new();
        let path = std::path::Path::new(dir_path);
        
        if !path.exists() || !path.is_dir() {
            return Ok(files);
        }
        
        match fs::read_dir(path) {
            Ok(entries) => {
                for entry in entries.filter_map(|x| x.ok()) {
                    let file_path = entry.path();
                    if let Ok(metadata) = file_path.metadata() {
                        if metadata.is_file() {
                            let full_path = file_path.to_string_lossy().to_string();
                            files.insert(full_path, metadata.len());
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("[FileSystemMonitor] Error reading directory {}: {:?}", dir_path, e);
            }
        }
        
        Ok(files)
    }

    fn is_suspicious_file(file_path: &str, suspicious_extensions: &[&str]) -> bool {
        let path_lower = file_path.to_lowercase();
        suspicious_extensions.iter().any(|ext| path_lower.ends_with(ext))
    }
}

impl NetworkMonitor {
    pub fn start_with_sender(&self, sender: Sender<Event>) -> Result<(), Box<dyn Error>> {
        if let Err(e) = sender.send(Event::Network(NetworkEvent {
            event_type: NetworkEventType::ConnectionEstablished,
            local_address: "NetworkMonitor".to_string(),
            remote_address: "localhost".to_string(),
            local_port: None,
            remote_port: None,
            protocol: "TCP".to_string(),
            process_pid: None,
            process_name: Some("NetworkMonitor".to_string()),
            bytes_sent: None,
            bytes_received: None,
            dns_query: None,
            dns_response: None,
            connection_state: Some("LISTENING".to_string()),
            timestamp: Utc::now(),
        })) {
            eprintln!("[NetworkMonitor] Failed to send start event: {:?}", e);
        }

        // Start comprehensive network monitoring in separate threads
        let sender_tcp = sender.clone();
        let sender_udp = sender.clone();
        let sender_dns = sender.clone();
        
        // TCP connection monitoring
        std::thread::spawn(move || {
            Self::monitor_tcp_connections(sender_tcp);
        });
        
        // UDP connection monitoring  
        std::thread::spawn(move || {
            Self::monitor_udp_connections(sender_udp);
        });
        
        // DNS query monitoring
        std::thread::spawn(move || {
            Self::monitor_dns_queries(sender_dns);
        });

        Ok(())
    }

    // TCP Connection Monitoring using Windows IpHelper APIs
    fn monitor_tcp_connections(sender: Sender<Event>) {
        let mut last_connections: HashMap<String, NetworkConnectionInfo> = HashMap::new();
        let mut _scan_count = 0;
        let mut consecutive_errors = 0;
        const MAX_CONSECUTIVE_ERRORS: u32 = 10;
        
        println!("[NetworkMonitor] Starting TCP connection monitoring...");
        
        // Suspicious IP ranges for security analysis
        let suspicious_ips = vec![
            "0.0.0.0", "127.0.0.1", "169.254.", "224.", "239.", "255.255.255.255"
        ];
        let suspicious_ports = vec![4444, 1337, 31337, 6666, 6667]; // Common malware ports
        
        loop {
            if is_shutdown() { break; }
            
            std::thread::sleep(std::time::Duration::from_secs(2));
            _scan_count += 1;
            
            match Self::get_tcp_connections() {
                Ok(current_connections) => {
                    consecutive_errors = 0;
                    
                    // Detect new connections
                    for (conn_id, conn_info) in &current_connections {
                        if !last_connections.contains_key(conn_id) {
                            // New TCP connection detected
                            
                            let event_key = format!("tcp_new_{}", conn_id);
                            if !should_rate_limit(&event_key, 2) {
                                let event_type = if Self::is_suspicious_tcp_connection(&conn_info, &suspicious_ips, &suspicious_ports) {
                                    NetworkEventType::SuspiciousConnection
                                } else {
                                    NetworkEventType::ConnectionEstablished
                                };
                                
                                Self::send_network_event(&sender, event_type, conn_info, None, None);
                            }
                        } else if let Some(old_conn) = last_connections.get(conn_id) {
                            // Check for data transfer
                            let traffic_delta = Self::calculate_traffic_delta(old_conn, conn_info);
                            if traffic_delta > 1024 * 1024 { // More than 1MB transferred
                                let event_key = format!("tcp_traffic_{}", conn_id);
                                if !should_rate_limit(&event_key, 5) {
                                    Self::send_network_event(&sender, NetworkEventType::HighTrafficConnection, 
                                                           conn_info, None, None);
                                }
                            }
                        }
                    }
                    
                    // Detect closed connections
                    for (conn_id, old_conn) in &last_connections {
                        if !current_connections.contains_key(conn_id) {
                            // TCP connection closed
                            
                            let event_key = format!("tcp_closed_{}", conn_id);
                            if !should_rate_limit(&event_key, 5) {
                                Self::send_network_event(&sender, NetworkEventType::ConnectionClosed, 
                                                       old_conn, None, None);
                            }
                        }
                    }
                    
                    last_connections = current_connections;
                }
                Err(e) => {
                        consecutive_errors += 1;
                    eprintln!("[NetworkMonitor] TCP monitoring error: {}", e);
                    
                    if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                        eprintln!("[NetworkMonitor] Too many TCP monitoring errors, stopping");
                        break;
                    }
                    
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
            }
        }
    }
    
    // UDP Connection Monitoring
    fn monitor_udp_connections(sender: Sender<Event>) {        
        loop {
            if is_shutdown() { break; }
            
            std::thread::sleep(std::time::Duration::from_secs(5));
            
            match Self::get_udp_connections() {
                Ok(connections) => {
                    for (_conn_id, conn_info) in connections {
                        // UDP connections are often short-lived, focus on suspicious ones
                        if Self::is_suspicious_udp_connection(&conn_info) {
                            let event_key = format!("udp_suspicious_{}_{}", 
                                                   conn_info.local_address, 
                                                   conn_info.local_port.unwrap_or(0));
                            if !should_rate_limit(&event_key, 10) {
                                Self::send_network_event(&sender, NetworkEventType::SuspiciousConnection, 
                                                       &conn_info, None, None);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[NetworkMonitor] UDP monitoring error: {}", e);
                    std::thread::sleep(std::time::Duration::from_secs(10));
                }
            }
        }
    }
    
    // DNS Query Monitoring using netstat and system calls
    fn monitor_dns_queries(sender: Sender<Event>) {
        let mut last_dns_cache: HashMap<String, DateTime<Utc>> = HashMap::new();
        
        loop {
            if is_shutdown() { break; }
            
            std::thread::sleep(std::time::Duration::from_secs(3));
            
            // Monitor DNS cache for new entries
            match Self::get_dns_cache_entries() {
                Ok(dns_entries) => {
                    for entry in dns_entries {
                        let cache_key = format!("{}_{}", entry.0, entry.1);
                        if !last_dns_cache.contains_key(&cache_key) {
                            
                            let event_key = format!("dns_query_{}", entry.0);
                            if !should_rate_limit(&event_key, 3) {
                                Self::send_dns_event(&sender, &entry.0, &entry.1);
                            }
                            last_dns_cache.insert(cache_key, Utc::now());
                        }
                    }
                    
                    // Clean old entries
                    let now = Utc::now();
                    last_dns_cache.retain(|_, time| {
                        now.signed_duration_since(*time).num_minutes() < 60
                    });
                }
                Err(_) => {
                    // DNS monitoring error, wait before retry
                    std::thread::sleep(std::time::Duration::from_secs(10));
                }
            }
        }
    }
    
    // Get TCP connections using Windows APIs
    fn get_tcp_connections() -> Result<HashMap<String, NetworkConnectionInfo>, Box<dyn Error>> {
        let mut connections = HashMap::new();
        
        unsafe {
            let mut table_size = 0u32;
            let tcp_table: *mut MIB_TCPTABLE_OWNER_PID;
            
            // Get table size
            let result = GetExtendedTcpTable(
                None,
                &mut table_size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            
            if result == ERROR_INSUFFICIENT_BUFFER.0 {
                // Allocate buffer
                let layout = std::alloc::Layout::from_size_align(table_size as usize, 8)
                    .map_err(|e| format!("Layout error: {}", e))?;
                tcp_table = std::alloc::alloc(layout) as *mut MIB_TCPTABLE_OWNER_PID;
                
                if tcp_table.is_null() {
                    return Err("Failed to allocate memory for TCP table".into());
                }
                
                // Get actual table
                let result = GetExtendedTcpTable(
                    Some(tcp_table as *mut std::ffi::c_void),
                    &mut table_size,
                    false,
                    AF_INET.0 as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                );
                
                if result == NO_ERROR.0 {
                    let table = &*tcp_table;
                    let entries = std::slice::from_raw_parts(
                        &table.table[0],
                        table.dwNumEntries as usize,
                    );
                    
                    for entry in entries {
                        // Monitor all active connection states (not just ESTABLISHED)
                        if entry.dwState == MIB_TCP_STATE_ESTAB.0 as u32 || 
                           entry.dwState == MIB_TCP_STATE_SYN_SENT.0 as u32 ||
                           entry.dwState == MIB_TCP_STATE_SYN_RCVD.0 as u32 ||
                           entry.dwState == MIB_TCP_STATE_FIN_WAIT1.0 as u32 ||
                           entry.dwState == MIB_TCP_STATE_FIN_WAIT2.0 as u32 ||
                           entry.dwState == MIB_TCP_STATE_CLOSE_WAIT.0 as u32 ||
                           entry.dwState == MIB_TCP_STATE_CLOSING.0 as u32 ||
                           entry.dwState == MIB_TCP_STATE_LAST_ACK.0 as u32 ||
                           entry.dwState == MIB_TCP_STATE_TIME_WAIT.0 as u32 {
                            
                            let local_addr = format!("{}.{}.{}.{}",
                                (entry.dwLocalAddr) & 0xFF,
                                (entry.dwLocalAddr >> 8) & 0xFF,
                                (entry.dwLocalAddr >> 16) & 0xFF,
                                (entry.dwLocalAddr >> 24) & 0xFF,
                            );
                            
                            let remote_addr = if entry.dwRemoteAddr != 0 {
                                format!("{}.{}.{}.{}",
                                    (entry.dwRemoteAddr) & 0xFF,
                                    (entry.dwRemoteAddr >> 8) & 0xFF,
                                    (entry.dwRemoteAddr >> 16) & 0xFF,
                                    (entry.dwRemoteAddr >> 24) & 0xFF,
                                )
                            } else {
                                "0.0.0.0".to_string()
                            };
                            
                            let local_port = ((entry.dwLocalPort >> 8) & 0xFF) as u16 | 
                                           ((entry.dwLocalPort & 0xFF) << 8) as u16;
                            let remote_port = if entry.dwRemotePort != 0 {
                                Some(((entry.dwRemotePort >> 8) & 0xFF) as u16 | 
                                     ((entry.dwRemotePort & 0xFF) << 8) as u16)
                            } else {
                                None
                            };
                            
                            let process_name = Self::get_process_name(entry.dwOwningPid);
                            
                            let conn_info = NetworkConnectionInfo {
                                local_address: local_addr.clone(),
                                remote_address: remote_addr.clone(),
                                local_port: Some(local_port),
                                remote_port,
                            protocol: "TCP".to_string(),
                                process_pid: Some(entry.dwOwningPid),
                                process_name,
                            bytes_sent: None,
                            bytes_received: None,
                                connection_state: Self::tcp_state_to_string(entry.dwState),
                                creation_time: Utc::now(),
                            };
                            
                            let conn_id = format!("{}:{}->{}:{}", 
                                local_addr, local_port, remote_addr, remote_port.unwrap_or(0));
                            connections.insert(conn_id, conn_info);
                        }
                    }
                }
                
                std::alloc::dealloc(tcp_table as *mut u8, layout);
            }
        }
        
        Ok(connections)
    }
    
    // Get UDP connections using Windows APIs
    fn get_udp_connections() -> Result<HashMap<String, NetworkConnectionInfo>, Box<dyn Error>> {
        let mut connections = HashMap::new();
        
        unsafe {
            let mut table_size = 0u32;
            let udp_table: *mut MIB_UDPTABLE_OWNER_PID;
            
            let result = GetExtendedUdpTable(
                None,
                &mut table_size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
            
            if result == ERROR_INSUFFICIENT_BUFFER.0 {
                let layout = std::alloc::Layout::from_size_align(table_size as usize, 8)
                    .map_err(|e| format!("Layout error: {}", e))?;
                udp_table = std::alloc::alloc(layout) as *mut MIB_UDPTABLE_OWNER_PID;
                
                if !udp_table.is_null() {
                    let result = GetExtendedUdpTable(
                        Some(udp_table as *mut std::ffi::c_void),
                        &mut table_size,
                        false,
                        AF_INET.0 as u32,
                        UDP_TABLE_OWNER_PID,
                        0,
                    );
                    
                    if result == NO_ERROR.0 {
                        let table = &*udp_table;
                        let entries = std::slice::from_raw_parts(
                            &table.table[0],
                            table.dwNumEntries as usize,
                        );
                        
                        for entry in entries {
                            let local_addr = format!("{}.{}.{}.{}",
                                (entry.dwLocalAddr) & 0xFF,
                                (entry.dwLocalAddr >> 8) & 0xFF,
                                (entry.dwLocalAddr >> 16) & 0xFF,
                                (entry.dwLocalAddr >> 24) & 0xFF,
                            );
                            
                            let local_port = ((entry.dwLocalPort >> 8) & 0xFF) as u16 | 
                                           ((entry.dwLocalPort & 0xFF) << 8) as u16;
                            
                            let process_name = Self::get_process_name(entry.dwOwningPid);
                            
                            let conn_info = NetworkConnectionInfo {
                                local_address: local_addr.clone(),
                                remote_address: "0.0.0.0".to_string(),
                                local_port: Some(local_port),
                            remote_port: None,
                                protocol: "UDP".to_string(),
                                process_pid: Some(entry.dwOwningPid),
                                process_name,
                            bytes_sent: None,
                            bytes_received: None,
                                connection_state: "LISTENING".to_string(),
                                creation_time: Utc::now(),
                            };
                            
                            let conn_id = format!("UDP_{}:{}", local_addr, local_port);
                            connections.insert(conn_id, conn_info);
                        }
                    }
                    
                    std::alloc::dealloc(udp_table as *mut u8, layout);
                }
            }
        }
        
        Ok(connections)
    }
    
    // Get DNS cache entries by parsing system commands and netstat
    fn get_dns_cache_entries() -> Result<Vec<(String, String)>, Box<dyn Error>> {
        let mut entries = Vec::new();
        
        // Method 1: DNS Cache
        match Command::new("ipconfig").args(&["/displaydns"]).output() {
            Ok(output) => {
                if let Ok(output_str) = String::from_utf8(output.stdout) {
                    let mut current_record_name = String::new();
                    
                    for line in output_str.lines() {
                        let line = line.trim();
                        
                        if line.starts_with("Record Name") {
                            if let Some(colon_pos) = line.find(':') {
                                current_record_name = line[colon_pos + 1..].trim().to_string();
                            }
                        } else if line.starts_with("A (Host) Record") && !current_record_name.is_empty() {
                            continue;
                        } else if line.starts_with("Name does not exist") && !current_record_name.is_empty() {
                            entries.push((current_record_name.clone(), "NXDOMAIN".to_string()));
                            current_record_name.clear();
                        } else if !current_record_name.is_empty() && Self::is_ip_address(line) {
                            entries.push((current_record_name.clone(), line.to_string()));
                            current_record_name.clear();
                        }
                    }
                }
            }
            Err(_) => {
                // DNS cache lookup failed, silently continue
            }
        }
        
        // Method 2: Look for connections to DNS servers (port 53)
        match Command::new("netstat").args(&["-an"]).output() {
            Ok(output) => {
                if let Ok(output_str) = String::from_utf8(output.stdout) {
                    for line in output_str.lines() {
                        if line.contains(":53 ") && line.contains("UDP") {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 3 {
                                let remote_addr = parts[2];
                                if remote_addr.contains(":53") {
                                    entries.push(("DNS_SERVER_CONNECTION".to_string(), remote_addr.to_string()));
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }
        
        Ok(entries)
    }
    
    // Helper functions
    fn get_process_name(pid: u32) -> Option<String> {
        match Command::new("tasklist")
            .args(&["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/NH"])
            .output()
        {
            Ok(output) => {
                if let Ok(output_str) = String::from_utf8(output.stdout) {
                    if let Some(first_line) = output_str.lines().next() {
                        let parts: Vec<&str> = first_line.split(',').collect();
                        if parts.len() > 0 {
                            return Some(parts[0].trim_matches('"').to_string());
                        }
                    }
                }
            }
            Err(_) => {}
        }
        None
    }
    
    fn tcp_state_to_string(state: u32) -> String {
        match state {
            1 => "CLOSED".to_string(),
            2 => "LISTEN".to_string(),
            3 => "SYN_SENT".to_string(),
            4 => "SYN_RCVD".to_string(),
            5 => "ESTABLISHED".to_string(),
            6 => "FIN_WAIT1".to_string(),
            7 => "FIN_WAIT2".to_string(),
            8 => "CLOSE_WAIT".to_string(),
            9 => "CLOSING".to_string(),
            10 => "LAST_ACK".to_string(),
            11 => "TIME_WAIT".to_string(),
            12 => "DELETE_TCB".to_string(),
            _ => format!("UNKNOWN({})", state),
        }
    }
    
    fn is_ip_address(s: &str) -> bool {
        s.split('.').count() == 4 && 
        s.split('.').all(|part| part.parse::<u8>().is_ok())
    }
    
    fn is_suspicious_tcp_connection(conn: &NetworkConnectionInfo, _suspicious_ips: &[&str], suspicious_ports: &[u16]) -> bool {
        // Check for suspicious ports
        if let Some(port) = conn.remote_port {
            if suspicious_ports.contains(&port) {
                return true;
            }
        }
        
        // Mark connections to interesting web services for visibility 
        if let Some(port) = conn.remote_port {
            match port {
                80 | 443 | 8080 | 8443 => {
                    // Always show web traffic
                    return false; // Not suspicious, but important to show
                }
                _ => {}
            }
        }
        
        false
    }
    
    fn is_suspicious_udp_connection(conn: &NetworkConnectionInfo) -> bool {
        if let Some(port) = conn.local_port {
            // Check for common malware UDP ports
            match port {
                69 | 135 | 445 | 1434 | 4444 | 6666 => true,
                _ => false,
            }
        } else {
            false
        }
    }
    
    fn calculate_traffic_delta(old: &NetworkConnectionInfo, new: &NetworkConnectionInfo) -> u64 {
        let old_sent = old.bytes_sent.unwrap_or(0);
        let old_recv = old.bytes_received.unwrap_or(0);
        let new_sent = new.bytes_sent.unwrap_or(0);
        let new_recv = new.bytes_received.unwrap_or(0);
        
        (new_sent.saturating_sub(old_sent)) + (new_recv.saturating_sub(old_recv))
    }
    
    fn send_network_event(sender: &Sender<Event>, event_type: NetworkEventType, 
                         conn: &NetworkConnectionInfo, dns_query: Option<String>, 
                         dns_response: Option<String>) {
        let _ = sender.send(Event::Network(NetworkEvent {
            event_type,
            local_address: conn.local_address.clone(),
            remote_address: conn.remote_address.clone(),
            local_port: conn.local_port,
            remote_port: conn.remote_port,
            protocol: conn.protocol.clone(),
            process_pid: conn.process_pid,
            process_name: conn.process_name.clone(),
            bytes_sent: conn.bytes_sent,
            bytes_received: conn.bytes_received,
            dns_query,
            dns_response,
            connection_state: Some(conn.connection_state.clone()),
            timestamp: Utc::now(),
        }));
    }
    
    fn send_dns_event(sender: &Sender<Event>, query: &str, response: &str) {
        let _ = sender.send(Event::Network(NetworkEvent {
            event_type: NetworkEventType::DNSQuery,
            local_address: "DNS_RESOLVER".to_string(),
            remote_address: response.to_string(),
            local_port: Some(53),
            remote_port: Some(53),
            protocol: "DNS".to_string(),
            process_pid: None,
            process_name: Some("System".to_string()),
            bytes_sent: None,
            bytes_received: None,
            dns_query: Some(query.to_string()),
            dns_response: Some(response.to_string()),
            connection_state: Some("RESOLVED".to_string()),
            timestamp: Utc::now(),
        }));
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



// Process tree and details functions for GUI
pub fn get_process_tree() -> Vec<(u32, u32, String)> {
    unsafe {
        // Use raw pointer to avoid static mut reference warning
        let cache_ptr = &raw const PROCESS_CACHE;
        if let Some(cache) = (*cache_ptr).as_ref() {
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
        // Use raw pointer to avoid static mut reference warning
        let cache_ptr = &raw const PROCESS_CACHE;
        if let Some(cache) = (*cache_ptr).as_ref() {
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

            // Log rotation settings
            const MAX_LOG_SIZE: u64 = 10 * 1024 * 1024; // 10MB
            let mut event_count = 0;
            const ROTATION_CHECK_INTERVAL: usize = 100; // Check every 100 events
            let mut consecutive_write_errors = 0;
            const MAX_CONSECUTIVE_WRITE_ERRORS: u32 = 10;

            match file {
                Ok(mut file) => {
                    for event in receiver.iter() {
                        event_count += 1;
                        
                        // Check for log rotation
                        if event_count % ROTATION_CHECK_INTERVAL == 0 {
                            if let Ok(metadata) = std::fs::metadata(&log_path) {
                                if metadata.len() > MAX_LOG_SIZE {
                                    // Rotate log file
                                    let backup_path = format!("{}.backup", log_path);
                                    match std::fs::rename(&log_path, &backup_path) {
                                        Ok(_) => {
                                            // Create new log file
                                            match OpenOptions::new()
                                                .create(true)
                                                .append(true)
                                                .open(&log_path) {
                                                Ok(new_file) => {
                                                    file = new_file;
                                                    
                                                    // Log rotation event
                                                    if let Ok(json) = serde_json::to_string(&Event::Registry("[EventLogger] Log file rotated due to size limit".to_string())) {
                                                        if let Err(e) = writeln!(file, "{}", json) {
                                                            eprintln!("[EventLogger] Failed to write rotation event: {}", e);
                                                            consecutive_write_errors += 1;
                                                        } else {
                                                            consecutive_write_errors = 0;
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    eprintln!("[EventLogger] Failed to create new log file: {}", e);
                                                    consecutive_write_errors += 1;
                                                    continue;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("[EventLogger] Failed to rotate log file: {}", e);
                                            consecutive_write_errors += 1;
                                        }
                                    }
                                }
                            }
                        }
                        
                        // Write event to log
                        match serde_json::to_string(&event) {
                            Ok(json) => {
                                if let Err(e) = writeln!(file, "{}", json) {
                                    eprintln!("[EventLogger] Failed to write to log: {}", e);
                                    consecutive_write_errors += 1;
                                    
                                    // Stop if too many consecutive write errors
                                    if consecutive_write_errors >= MAX_CONSECUTIVE_WRITE_ERRORS {
                                        eprintln!("[EventLogger] Too many consecutive write errors, stopping logger");
                                        break;
                                    }
                                } else {
                                    consecutive_write_errors = 0;
                                }
                            }
                            Err(e) => {
                                eprintln!("[EventLogger] Failed to serialize event: {}", e);
                                consecutive_write_errors += 1;
                            }
                        }
                        
                        // Flush file periodically to ensure data is written
                        if event_count % 10 == 0 {
                            if let Err(e) = file.flush() {
                                eprintln!("[EventLogger] Failed to flush log file: {}", e);
                                consecutive_write_errors += 1;
                            } else {
                                consecutive_write_errors = 0;
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