; ===============================================================================
; FenrirWatch - Advanced Windows System Monitor
; Fancy NSIS Installer Script with Enhanced UI & Experience
; ===============================================================================

!include "MUI2.nsh"
!include "x64.nsh"
!include "WinMessages.nsh"
!include "FileFunc.nsh"

; ===============================================================================
; INSTALLER CONFIGURATION
; ===============================================================================

; Basic Information
Name "FenrirWatch - Advanced System Monitor"
OutFile "FenrirWatch-Setup.exe"
Unicode True
SetCompressor /SOLID lzma
SetCompressorDictSize 64

; Installation directory - Program Files (x64)
!ifdef WIN64
  InstallDir "$PROGRAMFILES64\FenrirWatch"
!else
  InstallDir "$PROGRAMFILES\FenrirWatch"
!endif

; Get installation folder from registry if available
InstallDirRegKey HKLM "Software\FenrirWatch" "InstallPath"

; Request admin privileges
RequestExecutionLevel admin

; ===============================================================================
; VERSION INFORMATION
; ===============================================================================

VIProductVersion "1.0.0.0"
VIAddVersionKey "ProductName" "FenrirWatch"
VIAddVersionKey "Comments" "Advanced Windows System Monitor - Real-time Security & Performance Monitoring"
VIAddVersionKey "CompanyName" "KnivInstitute"
VIAddVersionKey "LegalCopyright" "© 2025 Knivier"
VIAddVersionKey "FileDescription" "FenrirWatch Advanced Installer"
VIAddVersionKey "FileVersion" "1.0.0.0"
VIAddVersionKey "ProductVersion" "1.0.0.0"
VIAddVersionKey "InternalName" "FenrirWatch-Setup.exe"
VIAddVersionKey "LegalTrademarks" "FenrirWatch™"
VIAddVersionKey "OriginalFilename" "FenrirWatch-Setup.exe"

; ===============================================================================
; MODERN UI CONFIGURATION - ENHANCED VISUALS
; ===============================================================================

!define MUI_ABORTWARNING

; Custom Icons
!define MUI_ICON "dist\assets\icon.ico"
!define MUI_UNICON "dist\assets\icon.ico"

; Enhanced UI Appearance


; Enhanced UI with custom styling

; Welcome & Finish Page Enhancements
!define MUI_WELCOMEPAGE_TITLE "Welcome to FenrirWatch Setup!"
!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the installation of FenrirWatch, an advanced Windows system monitoring tool.$\nClick Next to continue or Cancel to exit."

; Finish Page Customization
!define MUI_FINISHPAGE_TITLE "FenrirWatch Installation Complete!"
!define MUI_FINISHPAGE_TEXT "FenrirWatch has been successfully installed on your computer.$\r$\n$\r$\nKey Features Installed:$\r$\n• Real-time system monitoring dashboard$\r$\n• Advanced security event detection$\r$\n• Live performance graphs and statistics$\r$\n• Multi-format event export capabilities$\r$\n• Customizable monitoring preferences$\r$\n$\r$\nReady to protect and monitor your system!"
!define MUI_FINISHPAGE_RUN "$INSTDIR\fenrirwatch.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Launch FenrirWatch now"
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\README.txt"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "View Quick Start Guide"
!define MUI_FINISHPAGE_LINK "Visit FenrirWatch Website"
!define MUI_FINISHPAGE_LINK_LOCATION "https://github.com/KnivInstitute/fenrirwatch"

; Custom License Page Text
!define MUI_LICENSEPAGE_TEXT_TOP "Please review the license terms below:"
!define MUI_LICENSEPAGE_TEXT_BOTTOM "If you accept the terms of the agreement, click I Agree to continue. You must accept the agreement to install FenrirWatch."

; Welcome page
!insertmacro MUI_PAGE_WELCOME

; License page
!insertmacro MUI_PAGE_LICENSE "..\LICENSE"

; Components page
!insertmacro MUI_PAGE_COMPONENTS

; Directory page
!insertmacro MUI_PAGE_DIRECTORY

; Installation page
!insertmacro MUI_PAGE_INSTFILES

; Finish page
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; Languages
!insertmacro MUI_LANGUAGE "English"

; ===============================================================================
; INSTALLATION SECTIONS - ENHANCED COMPONENTS
; ===============================================================================

Section "FenrirWatch Core" SecCore
  SectionIn RO  ; Required section
  
  ; Display status
  DetailPrint "Installing FenrirWatch core components..."
  
  ; Set output path to the installation directory
  SetOutPath $INSTDIR
  
  ; Install main executable with progress feedback
  DetailPrint "Installing main executable..."
  File "dist\fenrirwatch.exe"
  
  ; Create application data directory
  CreateDirectory "$INSTDIR\data"
  CreateDirectory "$INSTDIR\export"
  CreateDirectory "$INSTDIR\logs"
  
  ; Install assets with progress feedback
  DetailPrint "Installing application assets..."
  SetOutPath $INSTDIR\assets
  File "dist\assets\config.yaml"
  File "dist\assets\icon.ico"
  
  ; Install license
  DetailPrint "Installing license documentation..."
  SetOutPath $INSTDIR
  File /oname=LICENSE.txt "..\LICENSE"
  
  ; Create enhanced README with installation info
  DetailPrint "Generating Quick Start Guide..."
  FileOpen $0 "$INSTDIR\README.txt" w
  FileWrite $0 "FenrirWatch - Advanced Windows System Monitor$\r$\n"
  FileWrite $0 "===============================================$\r$\n$\r$\n"
  FileWrite $0 "INSTALLATION SUCCESSFUL!$\r$\n$\r$\n"
  FileWrite $0 "Thank you for installing FenrirWatch v1.0.0!$\r$\n$\r$\n"
  
  ; Get system info for README  
  FileWrite $0 "Installation Details:$\r$\n"
  FileWrite $0 "   • Install Path: $INSTDIR$\r$\n$\r$\n"
  
  FileWrite $0 "FEATURES$\r$\n"
  FileWrite $0 "========$\r$\n$\r$\n"
  
  FileWrite $0 "Real-time Monitoring:$\r$\n"
  FileWrite $0 "- Process Monitoring: Tracks process creation/termination using tasklist fallback$\r$\n"
  FileWrite $0 "- Registry Monitoring: Monitors critical registry keys for unauthorized changes$\r$\n"
  FileWrite $0 "- Service Monitoring: Tracks Windows service state changes$\r$\n"
  FileWrite $0 "- Driver Monitoring: Monitors kernel driver loading/unloading events$\r$\n"
  FileWrite $0 "- Autostart Monitoring: Detects persistence mechanisms in startup locations$\r$\n"
  FileWrite $0 "- Hook Detection: Placeholder for future API hook detection$\r$\n$\r$\n"
  
  FileWrite $0 "Advanced GUI Interface:$\r$\n"
  FileWrite $0 "- Real-time Console: Live event streaming with filtering and search$\r$\n"
  FileWrite $0 "- Event Type Filtering: Focus on specific event types$\r$\n"
  FileWrite $0 "- Dark/Light Mode: Configurable theme support$\r$\n"
  FileWrite $0 "- Process Tree Visualization: Hierarchical process relationship display$\r$\n"
  FileWrite $0 "- Statistics Dashboard: Event analytics and system health indicators$\r$\n"
  FileWrite $0 "- Export Capabilities: JSON, CSV, and TXT export formats$\r$\n$\r$\n"
  
  FileWrite $0 "Security Features:$\r$\n"
  FileWrite $0 "- Rate Limiting: Prevents event spam and reduces noise$\r$\n"
  FileWrite $0 "- Log Rotation: Automatic log file management (10MB limit)$\r$\n"
  FileWrite $0 "- Error Handling: Graceful degradation for monitoring failures$\r$\n"
  FileWrite $0 "- Configurable Monitoring: YAML-based configuration system$\r$\n$\r$\n"
  
  FileWrite $0 "TECHNICAL STACK$\r$\n"
  FileWrite $0 "===============$\r$\n"
  FileWrite $0 "- Language: Rust 2021 Edition$\r$\n"
  FileWrite $0 "- GUI Framework: egui with eframe$\r$\n"
  FileWrite $0 "- Windows APIs: Windows-rs for native system access$\r$\n"
  FileWrite $0 "- Serialization: Serde with JSON/YAML support$\r$\n"
  FileWrite $0 "- Concurrency: Crossbeam channels for thread communication$\r$\n"
  FileWrite $0 "- Time Handling: Chrono for timestamp management$\r$\n$\r$\n"
  
  FileWrite $0 "QUICK START$\r$\n"
  FileWrite $0 "===========$\r$\n$\r$\n"
  
  FileWrite $0 "Prerequisites:$\r$\n"
  FileWrite $0 "- Windows 10/11$\r$\n"
  FileWrite $0 "- Administrator privilege (required for system monitoring)$\r$\n$\r$\n"
  
  FileWrite $0 "Configuration:$\r$\n"
  FileWrite $0 "The application uses config.yaml for configuration. Key settings include:$\r$\n"
  FileWrite $0 "- dark_mode: Enable dark theme$\r$\n"
  FileWrite $0 "- max_events: Maximum events to display in GUI$\r$\n"
  FileWrite $0 "- selected_event_types: Filter specific event types$\r$\n"
  FileWrite $0 "- log_path: Log file location$\r$\n"
  FileWrite $0 "- graph_max_points: Number of data points for graphs$\r$\n$\r$\n"
  
  FileWrite $0 "MONITORING CAPABILITIES$\r$\n"
  FileWrite $0 "======================$\r$\n$\r$\n"
  
  FileWrite $0 "Process Monitoring:$\r$\n"
  FileWrite $0 "- Tracks process creation and termination$\r$\n"
  FileWrite $0 "- Maintains process cache for GUI display$\r$\n"
  FileWrite $0 "- Rate limiting prevents spam events$\r$\n"
  FileWrite $0 "- Fallback to tasklist command (ETW planned)$\r$\n$\r$\n"
  
  FileWrite $0 "Registry Monitoring:$\r$\n"
  FileWrite $0 "Critical security keys monitoring:$\r$\n"
  FileWrite $0 "  - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run$\r$\n"
  FileWrite $0 "  - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce$\r$\n"
  FileWrite $0 "  - HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run$\r$\n"
  FileWrite $0 "  - HKLM\SYSTEM\CurrentControlSet\Services$\r$\n"
  FileWrite $0 "- Real-time change detection$\r$\n"
  FileWrite $0 "- Rate limiting for change events$\r$\n$\r$\n"
  
  FileWrite $0 "Service Monitoring:$\r$\n"
  FileWrite $0 "- Windows service state tracking$\r$\n"
  FileWrite $0 "- Service modification detection$\r$\n"
  FileWrite $0 "- Uses sc query command for monitoring$\r$\n$\r$\n"
  
  FileWrite $0 "Driver Monitoring:$\r$\n"
  FileWrite $0 "- Kernel driver loading/unloading events$\r$\n"
  FileWrite $0 "- Rootkit detection capabilities$\r$\n"
  FileWrite $0 "- Uses driverquery command for monitoring$\r$\n$\r$\n"
  
  FileWrite $0 "Autostart Monitoring:$\r$\n"
  FileWrite $0 "- Registry autostart locations$\r$\n"
  FileWrite $0 "- Startup folder scanning$\r$\n"
  FileWrite $0 "- Persistence mechanism detection$\r$\n$\r$\n"
  
  FileWrite $0 "DIRECTORY STRUCTURE$\r$\n"
  FileWrite $0 "==================$\r$\n"
  FileWrite $0 "• Installation: $INSTDIR$\r$\n"
  FileWrite $0 "• Configuration: assets\config.yaml$\r$\n"
  FileWrite $0 "• Data Storage: data\$\r$\n"
  FileWrite $0 "• Export Output: export\$\r$\n"
  FileWrite $0 "• Log Files: logs\$\r$\n$\r$\n"
  
  FileWrite $0 "SUPPORT & UPDATES:$\r$\n"
  FileWrite $0 "═══════════════════$\r$\n"
  
  FileWrite $0 "IMPORTANT NOTES:$\r$\n"
  FileWrite $0 "══════════════════$\r$\n"
  FileWrite $0 "• FenrirWatch requires Administrator privileges$\r$\n"
  FileWrite $0 "• Windows Defender may show warnings (false positive)$\r$\n"
  FileWrite $0 "• Firewall exception created for network monitoring$\r$\n"
  FileWrite $0 "• Performance impact is minimal on modern systems$\r$\n$\r$\n"
  
  FileWrite $0 "Happy Monitoring! Stay secure with FenrirWatch!$\r$\n"
  FileClose $0
  DetailPrint "README.txt generation completed successfully"
  
  ; Write the installation path into the registry
  WriteRegStr HKLM "SOFTWARE\FenrirWatch" "InstallPath" "$INSTDIR"
  WriteRegStr HKLM "SOFTWARE\FenrirWatch" "Version" "1.0.0"
  WriteRegStr HKLM "SOFTWARE\FenrirWatch" "Publisher" "Knivier"
  
  ; Write the uninstall keys for Windows Add/Remove Programs
  WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FenrirWatch" "DisplayName" "FenrirWatch"
  WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FenrirWatch" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FenrirWatch" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FenrirWatch" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FenrirWatch" "DisplayIcon" "$INSTDIR\assets\icon.ico"
  WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FenrirWatch" "Publisher" "Knivier"
  WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FenrirWatch" "DisplayVersion" "1.0.0"
  WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FenrirWatch" "URLInfoAbout" "https://github.com/KnivInstitute/fenrirwatch"
  WriteRegDWORD HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FenrirWatch" "NoModify" 1
  WriteRegDWORD HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FenrirWatch" "NoRepair" 1
  WriteRegDWORD HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FenrirWatch" "EstimatedSize" 7500  ; Size in KB
  
  ; Create uninstaller
  WriteUninstaller "$INSTDIR\uninstall.exe"
  
SectionEnd

Section "Desktop Shortcut" SecDesktop
  DetailPrint "Creating desktop shortcut..."
  ; Create enhanced desktop shortcut with description
  CreateShortcut "$DESKTOP\FenrirWatch.lnk" "$INSTDIR\fenrirwatch.exe" "" "$INSTDIR\assets\icon.ico" 0 SW_SHOWNORMAL "" "FenrirWatch - Advanced System Monitor"
SectionEnd

Section "Start Menu Shortcuts" SecStartMenu
  DetailPrint "Creating Start Menu entries..."
  ; Create start menu folder
  CreateDirectory "$SMPROGRAMS\FenrirWatch"
  
  ; Create enhanced shortcuts with descriptions
  CreateShortcut "$SMPROGRAMS\FenrirWatch\FenrirWatch.lnk" "$INSTDIR\fenrirwatch.exe" "" "$INSTDIR\assets\icon.ico" 0 SW_SHOWNORMAL "" "Advanced Windows System Monitor"
  CreateShortcut "$SMPROGRAMS\FenrirWatch\Quick Start Guide.lnk" "$INSTDIR\README.txt" "" "" 0 SW_SHOWNORMAL "" "FenrirWatch Quick Start Guide"
  CreateShortcut "$SMPROGRAMS\FenrirWatch\Configuration.lnk" "$INSTDIR\assets\config.yaml" "" "" 0 SW_SHOWNORMAL "" "FenrirWatch Configuration File"
  CreateShortcut "$SMPROGRAMS\FenrirWatch\Export Folder.lnk" "$INSTDIR\export" "" "" 0 SW_SHOWNORMAL "" "FenrirWatch Export Directory"
  CreateShortcut "$SMPROGRAMS\FenrirWatch\Uninstall FenrirWatch.lnk" "$INSTDIR\uninstall.exe" "" "" 0 SW_SHOWNORMAL "" "Uninstall FenrirWatch"
SectionEnd

Section "Windows Firewall Exception" SecFirewall
  DetailPrint "Configuring Windows Firewall..."
  ; Add Windows Firewall exception for network monitoring
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="FenrirWatch Network Monitor" dir=in action=allow program="$INSTDIR\fenrirwatch.exe" enable=yes profile=any description="Allow FenrirWatch to monitor network connections"'
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="FenrirWatch Network Monitor" dir=out action=allow program="$INSTDIR\fenrirwatch.exe" enable=yes profile=any description="Allow FenrirWatch to monitor network connections"'
SectionEnd

Section "Performance Optimization" SecOptimization
  DetailPrint "Optimizing system integration..."
  ; Set high priority for better monitoring performance
  WriteRegStr HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\fenrirwatch.exe\PerfOptions" "CpuPriorityClass" "3"
  
  ; Create Windows Event Log source
  WriteRegStr HKLM "SYSTEM\CurrentControlSet\Services\EventLog\Application\FenrirWatch" "EventMessageFile" "$INSTDIR\fenrirwatch.exe"
  WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\EventLog\Application\FenrirWatch" "TypesSupported" 7
SectionEnd

; ===============================================================================
; COMPONENT DESCRIPTIONS - ENHANCED INFO
; ===============================================================================

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} "Core FenrirWatch application files, configuration, and documentation (Required - 7MB)"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} "Create a desktop shortcut for quick access to FenrirWatch"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecStartMenu} "Create Start Menu folder with shortcuts to application, guide, and settings"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecFirewall} "Add Windows Firewall exceptions for comprehensive network monitoring capabilities"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecOptimization} "System integration optimizations for better performance and Windows Event Log integration"
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; Installation function
Function .onInit
  ; Check if we're on 64-bit Windows
  ${IfNot} ${RunningX64}
    MessageBox MB_OK|MB_ICONSTOP "This application requires 64-bit Windows. Installation will be aborted."
    Abort
  ${EndIf}
  
  ; Check for existing installation
  ReadRegStr $R0 HKLM "SOFTWARE\FenrirWatch" "InstallPath"
  StrCmp $R0 "" done
  
  MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION \
  "FenrirWatch is already installed at $R0.$\n$\nClick OK to replace the existing installation, or Cancel to exit." \
  IDOK done
  Abort
  
  done:
FunctionEnd

; Uninstaller section
Section "Uninstall"
  ; Stop FenrirWatch if running
  nsExec::ExecToLog 'taskkill /F /IM fenrirwatch.exe'
  
  ; Remove firewall rule
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="FenrirWatch Monitor"'
  
  ; Remove files
  Delete "$INSTDIR\fenrirwatch.exe"
  Delete "$INSTDIR\uninstall.exe"
  Delete "$INSTDIR\README.txt"
  Delete "$INSTDIR\LICENSE.txt"
  
  ; Remove assets
  Delete "$INSTDIR\assets\config.yaml"
  Delete "$INSTDIR\assets\icon.ico"
  RMDir "$INSTDIR\assets"
  
  ; Remove export directory if it exists (but preserve user data)
  RMDir "$INSTDIR\export"
  
  ; Remove log files (ask user first)
  IfFileExists "$INSTDIR\fenrirwatch.log" 0 no_logs
    MessageBox MB_YESNO|MB_ICONQUESTION "Remove log files? This will delete all monitoring history." IDNO no_logs
    Delete "$INSTDIR\fenrirwatch.log"
    Delete "$INSTDIR\*.log"
  no_logs:
  
  ; Remove shortcuts
  Delete "$DESKTOP\FenrirWatch.lnk"
  Delete "$SMPROGRAMS\FenrirWatch\FenrirWatch.lnk"
  Delete "$SMPROGRAMS\FenrirWatch\Uninstall FenrirWatch.lnk"
  Delete "$SMPROGRAMS\FenrirWatch\FenrirWatch README.lnk"
  RMDir "$SMPROGRAMS\FenrirWatch"
  
  ; Remove registry keys
  DeleteRegKey HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FenrirWatch"
  DeleteRegKey HKLM "SOFTWARE\FenrirWatch"
  
  ; Remove installation directory if empty
  RMDir "$INSTDIR"
  
  ; Success message
  MessageBox MB_OK "FenrirWatch has been successfully removed from your computer."
  
SectionEnd

; Uninstaller function
Function un.onInit
  MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 "Are you sure you want to completely remove FenrirWatch and all of its components?" IDYES +2
  Abort
FunctionEnd