# FenrirWatch Installer

This directory contains the NSIS installer script and build tools for creating a Windows installer for FenrirWatch.

## Prerequisites

1. **NSIS (Nullsoft Scriptable Install System)**
   - Download from: https://nsis.sourceforge.io/Download
   - Install NSIS and make sure `makensis.exe` is in your PATH

2. **Built Application**
   - Ensure `fenrirwatch.exe` is compiled in release mode: `cargo build --release`
   - The executable should be copied to `InstallerPkg/dist/fenrirwatch.exe`

## Building the Installer

### Method 1: Using the Batch File (Recommended)
```cmd
build-installer.bat
```

### Method 2: Manual NSIS Compilation
```cmd
makensis installer.nsi
```

## What the Installer Does

### Installation Features:
- **Program Files Installation**: Installs to `C:\Program Files\FenrirWatch\` (64-bit)
- **Registry Entries**: Creates proper Windows registry entries for Add/Remove Programs
- **File Installation**:
  - Main executable: `fenrirwatch.exe`
  - Configuration: `assets/config.yaml`
  - Icon: `assets/icon.png`
  - License: `LICENSE.txt`
  - Auto-generated README: `README.txt`

### Optional Components:
- **Desktop Shortcut**: Creates a desktop shortcut
- **Start Menu Shortcuts**: Creates Start Menu folder with shortcuts
- **Windows Firewall Exception**: Adds firewall rule for network monitoring

### Registry Keys Created:
- `HKLM\SOFTWARE\FenrirWatch\` - Application settings
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FenrirWatch\` - Uninstaller info

## Uninstaller Features

The uninstaller will:
- Stop any running FenrirWatch processes
- Remove all installed files
- Remove registry entries
- Remove shortcuts
- Remove Windows Firewall exception
- Ask user before removing log files
- Clean up installation directory

## Files Structure

```
fenrirwatch/
├── installer.nsi              # Main NSIS installer script
├── build-installer.bat        # Build helper script
├── INSTALLER_README.md         # This file
└── InstallerPkg/
    └── dist/
        ├── fenrirwatch.exe     # Main application (copy from target/release/)
        ├── LICENSE.txt         # License file
        └── assets/
            ├── config.yaml     # Default configuration
            └── icon.png        # Application icon
```

## Customization

You can modify the installer by editing `installer.nsi`:

- **Company/Publisher**: Search for "FenrirWatch Project" and replace
- **Version**: Update version numbers in the VIProductVersion section
- **Website URLs**: Update the GitHub URLs
- **Installation Components**: Add/remove sections as needed
- **Registry Keys**: Modify the registry entries section

## Troubleshooting

### "makensis not found"
- Install NSIS from the official website
- Add NSIS installation directory to your Windows PATH
- Restart your command prompt/terminal

### Icon Issues
- NSIS doesn't directly support PNG icons in all contexts
- Consider converting icon.png to .ico format for better compatibility
- Update the MUI_ICON and MUI_UNICON defines to use .ico files

### Permission Issues
- The installer requires administrator privileges
- Make sure to run as administrator when testing

## Testing the Installer

1. Build the installer: `build-installer.bat`
2. Test installation on a clean system or VM
3. Verify all components are installed correctly
4. Test the application runs from the installed location
5. Test the uninstaller removes everything properly

## Notes

- The installer is configured for 64-bit Windows only
- Registry entries follow Microsoft guidelines for proper Add/Remove Programs integration
- The uninstaller preserves user log files by default (with option to remove)
- Firewall exception is optional to allow network monitoring features