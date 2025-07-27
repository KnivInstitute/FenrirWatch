mod core;

use core::ProcessMonitor;

fn main() {
    println!("FenrirWatch starting up...");
    let monitor = ProcessMonitor;
    if let Err(e) = monitor.start() {
        eprintln!("Error starting process monitor: {}", e);
    }
}
