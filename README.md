# FenrirWatch

FenrirWatch is a comprehensive Windows system monitoring application written in Rust that provides real-time surveillance of critical system components for security analysis and threat detection.

## Features

### **Real-time Monitoring**

- **Process Monitoring**: Tracks process creation/termination using tasklist fallback
- **Registry Monitoring**: Monitors critical registry keys for unauthorized changes
- **Service Monitoring**: Tracks Windows service state changes
- **Driver Monitoring**: Monitors kernel driver loading/unloading events
- **Autostart Monitoring**: Detects persistence mechanisms in startup locations
- **Hook Detection**: Placeholder for future API hook detection

### **Advanced GUI Interface**

- **Real-time Console**: Live event streaming with filtering and search
- **Event Type Filtering**: Focus on specific event types
- **Dark/Light Mode**: Configurable theme support
- **Process Tree Visualization**: Hierarchical process relationship display
- **Statistics Dashboard**: Event analytics and system health indicators
- **Export Capabilities**: JSON, CSV, and TXT export formats

### **Security Features**

- **Rate Limiting**: Prevents event spam and reduces noise
- **Log Rotation**: Automatic log file management (10MB limit)
- **Error Handling**: Graceful degradation for monitoring failures
- **Configurable Monitoring**: YAML-based configuration system

## Technical Stack

- **Language**: Rust 2021 Edition
- **GUI Framework**: egui with eframe
- **Windows APIs**: Windows-rs for native system access
- **Serialization**: Serde with JSON/YAML support
- **Concurrency**: Crossbeam channels for thread communication
- **Time Handling**: Chrono for timestamp management

## Quick Start

### Prerequisites

- Windows 10/11
- Rust toolchain (latest stable) if building from IDE
- Administrator privilege (to install from BIN installer)

### Configuration

The application uses `src/config/config.yaml` for configuration. Key settings include:
- `dark_mode`: Enable dark theme
- `max_events`: Maximum events to display in GUI
- `selected_event_types`: Filter specific event types
- `log_path`: Log file location
- `graph_max_points`: Number of data points for graphs

## Monitoring Capabilities

### **Process Monitoring**

- Tracks process creation and termination
- Maintains process cache for GUI display
- Rate limiting prevents spam events
- Fallback to tasklist command (ETW planned)

### **Registry Monitoring**

- Critical security keys monitoring:
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
  - `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\SYSTEM\CurrentControlSet\Services`
- Real-time change detection
- Rate limiting for change events

### **Service Monitoring**

- Windows service state tracking
- Service modification detection
- Uses `sc query` command for monitoring

### **Driver Monitoring**

- Kernel driver loading/unloading events
- Rootkit detection capabilities
- Uses `driverquery` command for monitoring

### **Autostart Monitoring**

- Registry autostart locations
- Startup folder scanning
- Persistence mechanism detection

## 🔧 Development

### Project Structure

```
fenrirwatch/
├── src/
│   ├── main.rs          # Application entry point
│   ├── core/mod.rs      # Core monitoring logic
│   ├── gui/mod.rs       # GUI implementation
│   └── config/          # Configuration management
├── Cargo.toml           # Dependencies and metadata
├── config.yaml          # Default configuration
└── icon.png            # Application icon
```

### Building

```bash
# Development build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Check for warnings
cargo check
```

## Logging

The application generates detailed logs in JSON format:

- **Location**: `fenrirwatch.log` (configurable)
- **Format**: JSON with timestamps and event details
- **Rotation**: Automatic at 10MB with backup creation
- **Rate Limiting**: Prevents repetitive log entries

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is designed for security analysis and system monitoring. Use responsibly and in accordance with applicable laws and regulations. I'm not responsible for any mishandling

---