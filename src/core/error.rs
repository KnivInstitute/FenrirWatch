use thiserror::Error;
use std::io;

#[derive(Error, Debug)]
pub enum MonitorError {
    #[error("ETW session failed: {0}")]
    EtwSessionError(String),
    
    #[error("Registry access denied: {0}")]
    RegistryAccessError(String),
    
    #[error("Service monitoring failed: {0}")]
    ServiceError(String),
    
    #[error("Process monitoring failed: {0}")]
    ProcessError(String),
    
    #[error("Driver monitoring failed: {0}")]
    DriverError(String),
    
    #[error("Autostart monitoring failed: {0}")]
    AutostartError(String),
    
    #[error("Hook detection failed: {0}")]
    HookError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Channel communication error: {0}")]
    ChannelError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    
    #[error("Windows API error: {0}")]
    WindowsError(String),
    
    #[error("Privilege escalation required: {0}")]
    PrivilegeError(String),
    
    #[error("Rate limiting exceeded for: {0}")]
    RateLimitError(String),
    
    #[error("Recovery failed after {0} attempts: {1}")]
    RecoveryError(u32, String),
}

impl From<windows::core::Error> for MonitorError {
    fn from(err: windows::core::Error) -> Self {
        MonitorError::WindowsError(err.to_string())
    }
}

impl From<crossbeam_channel::SendError<crate::core::Event>> for MonitorError {
    fn from(err: crossbeam_channel::SendError<crate::core::Event>) -> Self {
        MonitorError::ChannelError(format!("Failed to send event: {:?}", err))
    }
}

impl From<serde_json::Error> for MonitorError {
    fn from(err: serde_json::Error) -> Self {
        MonitorError::ConfigError(format!("JSON serialization error: {}", err))
    }
}

impl From<std::sync::PoisonError<std::sync::MutexGuard<'_, MonitorHealth>>> for MonitorError {
    fn from(err: std::sync::PoisonError<std::sync::MutexGuard<'_, MonitorHealth>>) -> Self {
        MonitorError::IoError(io::Error::new(io::ErrorKind::Other, format!("Mutex poison error: {:?}", err)))
    }
}

// Recovery strategies
#[derive(Debug, Clone)]
pub enum RecoveryStrategy {
    Retry { max_attempts: u32, delay_ms: u64 },
    Fallback { use_alternative: bool },
    GracefulDegradation { continue_with_errors: bool },
    Stop { critical: bool },
}

impl Default for RecoveryStrategy {
    fn default() -> Self {
        RecoveryStrategy::Retry { max_attempts: 3, delay_ms: 1000 }
    }
}

// Health status for monitoring components
#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded { reason: String },
    Failed { error: String },
    Recovering { attempt: u32 },
}

#[derive(Debug, Clone)]
pub struct MonitorHealth {
    pub status: HealthStatus,
    pub last_check: chrono::DateTime<chrono::Utc>,
    pub error_count: u32,
    pub recovery_attempts: u32,
}

impl MonitorHealth {
    pub fn new() -> Self {
        Self {
            status: HealthStatus::Healthy,
            last_check: chrono::Utc::now(),
            error_count: 0,
            recovery_attempts: 0,
        }
    }
    
    pub fn mark_failed(&mut self, error: String) {
        self.status = HealthStatus::Failed { error };
        self.error_count += 1;
        self.last_check = chrono::Utc::now();
    }
    
    pub fn mark_recovering(&mut self) {
        self.status = HealthStatus::Recovering { attempt: self.recovery_attempts };
        self.recovery_attempts += 1;
    }
    
    pub fn mark_healthy(&mut self) {
        self.status = HealthStatus::Healthy;
        self.recovery_attempts = 0;
        self.last_check = chrono::Utc::now();
    }
    
    pub fn mark_degraded(&mut self, reason: String) {
        self.status = HealthStatus::Degraded { reason };
        self.last_check = chrono::Utc::now();
    }
} 