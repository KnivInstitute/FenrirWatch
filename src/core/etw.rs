use crate::core::error::{MonitorError, MonitorHealth, RecoveryStrategy};
use crate::core::Event;
use crossbeam_channel::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use ferrisetw::provider::Provider;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::parser::Parser;
use crate::core::recovery::RecoveryManager;

pub struct EtwMonitor {
    health: Arc<Mutex<MonitorHealth>>,
    recovery_strategy: RecoveryStrategy,
    recovery_manager: RecoveryManager,
    is_running: Arc<Mutex<bool>>,
}

impl EtwMonitor {
    pub fn new() -> Self {
        Self {
            health: Arc::new(Mutex::new(MonitorHealth::new())),
            recovery_strategy: RecoveryStrategy::default(),
            recovery_manager: RecoveryManager::new(RecoveryStrategy::Retry { max_attempts: 3, delay_ms: 1000 }),
            is_running: Arc::new(Mutex::new(false)),
        }
    }

    pub fn start_process_monitoring(&mut self, sender: Sender<Event>) -> Result<(), MonitorError> {
        let sender_clone = sender.clone();
        let is_running_clone = self.is_running.clone();
        
        // Mark as running
        if let Ok(mut running) = is_running_clone.lock() {
            *running = true;
        }
        
        // Microsoft-Windows-Kernel-Process GUID
        let provider = Provider::by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716")
            .add_callback(move |record: &EventRecord, schema_locator: &SchemaLocator| {
                if let Ok(schema) = schema_locator.event_schema(record) {
                    let parser = Parser::create(record, &schema);
                    let event_id = record.event_id();
                    
                    // 1 = Process Start, 2 = Process End
                    if event_id == 1 || event_id == 2 {
                        let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);
                        let ppid: u32 = parser.try_parse("ParentProcessID").unwrap_or(0);
                        let name: String = parser.try_parse("ImageFileName").unwrap_or_default();
                        
                        // Only send events for real processes (PID > 0)
                        if pid > 0 {
                            let event_type = if event_id == 1 {
                                crate::core::ProcessEventType::Created
                            } else {
                                crate::core::ProcessEventType::Terminated
                            };
                            
                            let event = Event::Process(crate::core::ProcessEvent {
                                event_type,
                                pid,
                                ppid,
                                name: name.clone(),
                                command_line: None,
                                executable_path: None,
                                user: None,
                                timestamp: chrono::Utc::now(),
                            });
                            
                            // Enhanced error handling for sender
                            if let Err(e) = sender_clone.send(event) {
                                eprintln!("[EtwMonitor] Failed to send process event: {:?}", e);
                            }
                        }
                    }
                }
            })
            .build();

        // Start the ETW trace in a background thread with enhanced error handling
        let health_clone = self.health.clone();
        let recovery_manager_clone = self.recovery_manager.clone();
        
        thread::spawn(move || {
            let mut retry_count = 0;
            const MAX_RETRIES: u32 = 3;
            
            loop {
                match UserTrace::new()
                    .named("FenrirWatchProcessTrace".to_string())
                    .enable(provider.clone())
                    .start_and_process()
                {
                    Ok(mut trace) => {
                        // Update health status
                        if let Ok(mut health) = health_clone.lock() {
                            health.mark_healthy();
                        }
                        
                        // Keep the trace running
                        thread::sleep(Duration::from_secs(3600));
                        let _ = trace.stop();
                        
                        // Check if we should continue running
                        if let Ok(running) = is_running_clone.lock() {
                            if !*running {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        retry_count += 1;
                        let error_msg = format!("Failed to start ETW process trace: {:?}", e);
                        
                        // Update health status
                        if let Ok(mut health) = health_clone.lock() {
                            health.mark_failed(error_msg.clone());
                        }
                        
                        eprintln!("[EtwMonitor] {}", error_msg);
                        
                        // Send error event
                        let _ = sender_clone.send(Event::Process(crate::core::ProcessEvent {
                            event_type: crate::core::ProcessEventType::Created,
                            pid: 0,
                            ppid: 0,
                            name: format!("ETW Error: {}", error_msg),
                            command_line: None,
                            executable_path: None,
                            user: Some("system".to_string()),
                            timestamp: chrono::Utc::now(),
                        }));
                        
                        if retry_count >= MAX_RETRIES {
                            eprintln!("[EtwMonitor] Max retries exceeded, stopping ETW monitoring");
                            break;
                        }
                        
                        // Exponential backoff
                        let delay = Duration::from_millis(1000 * 2u64.pow(retry_count - 1));
                        thread::sleep(delay);
                    }
                }
            }
        });

        self.update_health_healthy();
        Ok(())
    }

    pub fn start_registry_monitoring(&mut self, sender: Sender<Event>) -> Result<(), MonitorError> {
        // For now, use a simple polling approach for registry
        let sender_clone = sender.clone();
        let health_clone = self.health.clone();
        
        thread::spawn(move || {
            Self::poll_registry_changes(sender_clone, health_clone);
        });
        
        self.update_health_healthy();
        Ok(())
    }

    pub fn start_service_monitoring(&mut self, sender: Sender<Event>) -> Result<(), MonitorError> {
        // For now, use a simple polling approach for services
        let sender_clone = sender.clone();
        let health_clone = self.health.clone();
        
        thread::spawn(move || {
            Self::poll_service_changes(sender_clone, health_clone);
        });
        
        self.update_health_healthy();
        Ok(())
    }

    fn poll_registry_changes(sender: Sender<Event>, health: Arc<Mutex<MonitorHealth>>) {
        use winreg::RegKey;
        use winreg::enums::*;
        use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER};

        let critical_keys = vec![
            (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (HKEY_CURRENT_USER.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ];

        let mut last_values: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let mut error_count = 0;
        const MAX_ERRORS: u32 = 10;

        loop {
            let mut current_values: std::collections::HashMap<String, String> = std::collections::HashMap::new();
            let mut scan_successful = true;
            
            for (hive, subkey) in &critical_keys {
                let key = RegKey::predef(*hive);
                match key.open_subkey_with_flags(subkey, KEY_READ) {
                    Ok(subkey_handle) => {
                        for (name, value) in subkey_handle.enum_values().filter_map(|x| x.ok()) {
                            let full_key = format!("{}\\{}", subkey, name);
                            let value_str = format!("{:?}", value);
                            current_values.insert(full_key.clone(), value_str.clone());

                            if let Some(old_value) = last_values.get(&full_key) {
                                if old_value != &value_str {
                                    if let Err(e) = sender.send(Event::Registry(format!(
                                        "Registry change detected: {} = {:?}",
                                        full_key, value
                                    ))) {
                                        eprintln!("[RegistryMonitor] Failed to send registry event: {:?}", e);
                                        error_count += 1;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[RegistryMonitor] Failed to access registry key {}: {:?}", subkey, e);
                        scan_successful = false;
                        error_count += 1;
                    }
                }
            }
            
            // Update health status
            if let Ok(mut health) = health.lock() {
                if scan_successful {
                    health.mark_healthy();
                } else {
                    health.mark_degraded(format!("Registry scan errors: {}", error_count));
                }
            }
            
            // Stop if too many errors
            if error_count >= MAX_ERRORS {
                eprintln!("[RegistryMonitor] Too many errors, stopping registry monitoring");
                if let Ok(mut health) = health.lock() {
                    health.mark_failed("Too many registry access errors".to_string());
                }
                break;
            }
            
            thread::sleep(Duration::from_secs(3));
            last_values = current_values;
        }
    }

    fn poll_service_changes(sender: Sender<Event>, health: Arc<Mutex<MonitorHealth>>) {
        let mut error_count = 0;
        const MAX_ERRORS: u32 = 10;
        
        loop {
            // Simple service polling - could be enhanced with WMI
            match sender.send(Event::Service("Service monitoring active".to_string())) {
                Ok(_) => {
                    if let Ok(mut health) = health.lock() {
                        health.mark_healthy();
                    }
                }
                Err(e) => {
                    eprintln!("[ServiceMonitor] Failed to send service event: {:?}", e);
                    error_count += 1;
                    
                    if let Ok(mut health) = health.lock() {
                        health.mark_degraded(format!("Service monitoring errors: {}", error_count));
                    }
                    
                    if error_count >= MAX_ERRORS {
                        eprintln!("[ServiceMonitor] Too many errors, stopping service monitoring");
                        if let Ok(mut health) = health.lock() {
                            health.mark_failed("Too many service monitoring errors".to_string());
                        }
                        break;
                    }
                }
            }
            thread::sleep(Duration::from_secs(5));
        }
    }

    fn update_health_healthy(&mut self) {
        if let Ok(mut health) = self.health.lock() {
            health.mark_healthy();
        }
    }

    fn update_health_failed(&mut self, error: &str) {
        if let Ok(mut health) = self.health.lock() {
            health.mark_failed(error.to_string());
        }
    }

    pub fn get_health(&self) -> MonitorHealth {
        if let Ok(health) = self.health.lock() {
            health.clone()
        } else {
            MonitorHealth::new()
        }
    }

    pub fn stop(&mut self) -> Result<(), MonitorError> {
        // Mark as stopped
        if let Ok(mut running) = self.is_running.lock() {
            *running = false;
        }
        
        // Update health status
        self.update_health_failed("Monitor stopped by user");
        
        Ok(())
    }
    
    pub fn is_running(&self) -> bool {
        if let Ok(running) = self.is_running.lock() {
            *running
        } else {
            false
        }
    }
}

impl Drop for EtwMonitor {
    fn drop(&mut self) {
        let _ = self.stop();
    }
} 