use crate::core::error::{MonitorError, MonitorHealth, RecoveryStrategy};
use crate::core::Event;
use crossbeam_channel::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use chrono::Utc;

#[derive(Clone)]
pub struct RecoveryManager {
    health: Arc<Mutex<MonitorHealth>>,
    strategy: RecoveryStrategy,
    retry_count: u32,
    max_retries: u32,
    backoff_delay: Duration,
}

impl RecoveryManager {
    pub fn new(strategy: RecoveryStrategy) -> Self {
        let max_retries = match strategy {
            RecoveryStrategy::Retry { max_attempts, .. } => max_attempts,
            _ => 3,
        };

        Self {
            health: Arc::new(Mutex::new(MonitorHealth::new())),
            strategy,
            retry_count: 0,
            max_retries,
            backoff_delay: Duration::from_millis(1000),
        }
    }

    pub fn execute_with_recovery<F, T>(
        &mut self,
        mut operation: F,
        fallback_operation: Option<Box<dyn Fn() -> Result<T, MonitorError> + Send + 'static>>,
    ) -> Result<T, MonitorError>
    where
        F: FnMut() -> Result<T, MonitorError>,
    {
        loop {
            match operation() {
                Ok(result) => {
                    self.mark_success();
                    return Ok(result);
                }
                Err(error) => {
                    if let Err(recovery_error) = self.handle_failure(&error, &fallback_operation) {
                        return Err(recovery_error);
                    }
                }
            }
        }
    }

    fn handle_failure<T>(
        &mut self,
        error: &MonitorError,
        fallback_operation: &Option<Box<dyn Fn() -> Result<T, MonitorError> + Send + 'static>>,
    ) -> Result<(), MonitorError> {
        self.retry_count += 1;
        self.mark_failure(error);

        match &self.strategy {
            RecoveryStrategy::Retry { max_attempts, delay_ms } => {
                if self.retry_count >= *max_attempts {
                    return Err(MonitorError::RecoveryError(
                        self.retry_count,
                        format!("Max retries exceeded: {}", error),
                    ));
                }

                // Exponential backoff
                let delay = Duration::from_millis(*delay_ms * 2u64.pow(self.retry_count - 1));
                thread::sleep(delay);
                self.mark_recovering();
                Ok(())
            }
            RecoveryStrategy::Fallback { use_alternative } => {
                if *use_alternative {
                    if let Some(fallback) = fallback_operation {
                        match fallback() {
                            Ok(_) => {
                                self.mark_success();
                                return Ok(());
                            }
                            Err(fallback_error) => {
                                return Err(MonitorError::RecoveryError(
                                    self.retry_count,
                                    format!("Fallback also failed: {}", fallback_error),
                                ));
                            }
                        }
                    }
                }
                Err(MonitorError::RecoveryError(
                    self.retry_count,
                    format!("No fallback available: {}", error),
                ))
            }
            RecoveryStrategy::GracefulDegradation { continue_with_errors } => {
                if *continue_with_errors {
                    self.mark_degraded(format!("Continuing with errors: {}", error));
                    Ok(())
                } else {
                    Err(MonitorError::RecoveryError(
                        self.retry_count,
                        format!("Graceful degradation not allowed: {}", error),
                    ))
                }
            }
            RecoveryStrategy::Stop { critical } => {
                if *critical {
                    Err(MonitorError::RecoveryError(
                        self.retry_count,
                        format!("Critical failure, stopping: {}", error),
                    ))
                } else {
                    self.mark_degraded(format!("Non-critical failure: {}", error));
                    Ok(())
                }
            }
        }
    }

    fn mark_success(&mut self) {
        if let Ok(mut health) = self.health.lock() {
            health.mark_healthy();
        }
        self.retry_count = 0;
    }

    fn mark_failure(&mut self, error: &MonitorError) {
        if let Ok(mut health) = self.health.lock() {
            health.mark_failed(error.to_string());
        }
    }

    fn mark_recovering(&mut self) {
        if let Ok(mut health) = self.health.lock() {
            health.mark_recovering();
        }
    }

    fn mark_degraded(&mut self, reason: String) {
        if let Ok(mut health) = self.health.lock() {
            health.mark_degraded(reason);
        }
    }

    pub fn get_health(&self) -> MonitorHealth {
        if let Ok(health) = self.health.lock() {
            health.clone()
        } else {
            MonitorHealth::new()
        }
    }

    pub fn reset(&mut self) {
        self.retry_count = 0;
        if let Ok(mut health) = self.health.lock() {
            health.mark_healthy();
        }
    }
    
    pub fn get_retry_count(&self) -> u32 {
        self.retry_count
    }
    
    pub fn get_max_retries(&self) -> u32 {
        self.max_retries
    }
    
    pub fn is_recovering(&self) -> bool {
        if let Ok(health) = self.health.lock() {
            matches!(health.status, crate::core::error::HealthStatus::Recovering { .. })
        } else {
            false
        }
    }
    
    pub fn should_stop(&self) -> bool {
        self.retry_count >= self.max_retries
    }
}

// Enhanced monitor with recovery capabilities
pub struct ResilientMonitor {
    recovery_manager: RecoveryManager,
    etw_monitor: Option<crate::core::etw::EtwMonitor>,
    fallback_enabled: bool,
}

impl ResilientMonitor {
    pub fn new() -> Self {
        Self {
            recovery_manager: RecoveryManager::new(RecoveryStrategy::Retry {
                max_attempts: 3,
                delay_ms: 1000,
            }),
            etw_monitor: None,
            fallback_enabled: true,
        }
    }

    pub fn start_process_monitoring(&mut self, sender: Sender<Event>) -> Result<(), MonitorError> {
        let etw_operation = || {
            let mut etw = crate::core::etw::EtwMonitor::new();
            etw.start_process_monitoring(sender.clone())?;
            self.etw_monitor = Some(etw);
            Ok(())
        };

        let fallback_operation = if self.fallback_enabled {
            let sender_clone = sender.clone();
            Some(Box::new(move || -> Result<(), MonitorError> {
                // Fallback to command-line monitoring
                Self::start_fallback_process_monitoring_static(sender_clone.clone())
            }) as Box<dyn Fn() -> Result<(), MonitorError> + Send + 'static>)
        } else {
            None
        };

        self.recovery_manager.execute_with_recovery(etw_operation, fallback_operation)
    }

    pub fn start_registry_monitoring(&mut self, sender: Sender<Event>) -> Result<(), MonitorError> {
        let etw_operation = || {
            let mut etw = crate::core::etw::EtwMonitor::new();
            etw.start_registry_monitoring(sender.clone())?;
            self.etw_monitor = Some(etw);
            Ok(())
        };

        let fallback_operation = if self.fallback_enabled {
            let sender_clone = sender.clone();
            Some(Box::new(move || -> Result<(), MonitorError> {
                // Fallback to registry polling
                Self::start_fallback_registry_monitoring_static(sender_clone.clone())
            }) as Box<dyn Fn() -> Result<(), MonitorError> + Send + 'static>)
        } else {
            None
        };

        self.recovery_manager.execute_with_recovery(etw_operation, fallback_operation)
    }

    fn start_fallback_process_monitoring(&self, sender: Sender<Event>) -> Result<(), MonitorError> {
        Self::start_fallback_process_monitoring_static(sender)
    }

    fn start_fallback_process_monitoring_static(sender: Sender<Event>) -> Result<(), MonitorError> {
        // Implement fallback using tasklist command
        thread::spawn(move || {
            loop {
                match std::process::Command::new("tasklist")
                    .args(&["/FO", "CSV", "/NH"])
                    .output()
                {
                    Ok(output) => {
                        if let Ok(output_str) = String::from_utf8(output.stdout) {
                            for line in output_str.lines() {
                                if let Some(process_info) = parse_tasklist_line(line) {
                                    let _ = sender.send(Event::Process(crate::core::ProcessEvent {
                                        event_type: crate::core::ProcessEventType::Created,
                                        pid: process_info.pid,
                                        ppid: 0, // Would need to get from parent process
                                        name: process_info.name,
                                        command_line: None,
                                        executable_path: Some(process_info.path),
                                        user: Some(process_info.user),
                                        timestamp: Utc::now(),
                                    }));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Fallback process monitoring failed: {}", e);
                    }
                }
                thread::sleep(Duration::from_secs(5));
            }
        });
        Ok(())
    }

    fn start_fallback_registry_monitoring(&self, sender: Sender<Event>) -> Result<(), MonitorError> {
        Self::start_fallback_registry_monitoring_static(sender)
    }

    fn start_fallback_registry_monitoring_static(sender: Sender<Event>) -> Result<(), MonitorError> {
        // Implement fallback using registry polling
        thread::spawn(move || {
            use winreg::RegKey;
            use winreg::enums::*;
            use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER};
            
            let critical_keys = vec![
                (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (HKEY_LOCAL_MACHINE.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                (HKEY_CURRENT_USER.0 as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            ];

            let mut last_values: std::collections::HashMap<String, String> = std::collections::HashMap::new();

            loop {
                for (hive, subkey) in &critical_keys {
                    let key = RegKey::predef(*hive);
                    if let Ok(subkey_handle) = key.open_subkey_with_flags(subkey, KEY_READ) {
                        for (name, value) in subkey_handle.enum_values().filter_map(|x| x.ok()) {
                            let full_key = format!("{}\\{}", subkey, name);
                            let value_str = format!("{:?}", value);
                            
                            if let Some(old_value) = last_values.get(&full_key) {
                                if old_value != &value_str {
                                    let _ = sender.send(Event::Registry(format!(
                                        "Registry change detected: {} = {:?}",
                                        full_key, value
                                    )));
                                }
                            }
                            last_values.insert(full_key, value_str);
                        }
                    }
                }
                thread::sleep(Duration::from_secs(3));
            }
        });
        Ok(())
    }

    pub fn get_health(&self) -> MonitorHealth {
        self.recovery_manager.get_health()
    }
    
    pub fn is_fallback_enabled(&self) -> bool {
        self.fallback_enabled
    }
    
    pub fn set_fallback_enabled(&mut self, enabled: bool) {
        self.fallback_enabled = enabled;
    }
    
    pub fn get_recovery_manager(&self) -> &RecoveryManager {
        &self.recovery_manager
    }
    
    pub fn is_etw_monitor_active(&self) -> bool {
        self.etw_monitor.is_some()
    }
}

// Helper function for parsing tasklist output
fn parse_tasklist_line(line: &str) -> Option<ProcessInfo> {
    let parts: Vec<&str> = line.split(',').collect();
    if parts.len() >= 5 {
        let name = parts[0].trim_matches('"').to_string();
        let pid_str = parts[1].trim_matches('"');
        let pid = pid_str.parse::<u32>().ok()?;
        let path = parts[4].trim_matches('"').to_string();
        let user = parts[5].trim_matches('"').to_string();
        
        Some(ProcessInfo { name, pid, path, user })
    } else {
        None
    }
}

#[derive(Debug)]
struct ProcessInfo {
    name: String,
    pid: u32,
    path: String,
    user: String,
} 