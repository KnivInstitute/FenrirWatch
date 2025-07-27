// Core logic module

use serde::Deserialize;
use wmi::{WMIConnection, COMLibrary, Variant};
use std::error::Error;

pub struct ProcessMonitor;

impl ProcessMonitor {
    pub fn start(&self) -> Result<(), Box<dyn Error>> {
        let com_con = COMLibrary::new()?;
        let wmi_con = WMIConnection::new(com_con.into())?;

        // Use __InstanceCreationEvent for process creation
        let query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'";
        let results = wmi_con.raw_notification::<InstanceCreationEvent>(query)?;

        println!("Listening for process creation events (via __InstanceCreationEvent)...");
        for event in results {
            match event {
                Ok(trace) => {
                    if let Some(process) = trace.TargetInstance {
                        let process_event = ProcessEvent {
                            event_type: ProcessEventType::Created,
                            pid: process.ProcessId.unwrap_or(0),
                            ppid: process.ParentProcessId.unwrap_or(0),
                            name: process.Name.unwrap_or_default(),
                            command_line: process.CommandLine,
                            executable_path: process.ExecutablePath,
                            user: None, // Not available here
                            timestamp: String::new(), // Not available here
                        };
                        println!("New process: {:?}", process_event);
                    }
                }
                Err(e) => {
                    eprintln!("WMI error: {:?}", e);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ProcessEvent {
    pub event_type: ProcessEventType,
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub command_line: Option<String>,
    pub executable_path: Option<String>,
    pub user: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone)]
pub enum ProcessEventType {
    Created,
    Terminated,
}

#[derive(Debug, Deserialize)]
struct InstanceCreationEvent {
    #[serde(rename = "TargetInstance")]
    pub TargetInstance: Option<Win32Process>,
}

#[derive(Debug, Deserialize)]
struct Win32Process {
    #[serde(rename = "ProcessId")]
    pub ProcessId: Option<u32>,
    #[serde(rename = "ParentProcessId")]
    pub ParentProcessId: Option<u32>,
    #[serde(rename = "Name")]
    pub Name: Option<String>,
    #[serde(rename = "CommandLine")]
    pub CommandLine: Option<String>,
    #[serde(rename = "ExecutablePath")]
    pub ExecutablePath: Option<String>,
}
