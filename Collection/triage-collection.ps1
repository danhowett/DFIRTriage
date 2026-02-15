# Enhanced Triage Collection Script v2.0
# Comprehensive forensic artifact collection with enhanced artifacts
# Run as Administrator

#Requires -RunAsAdministrator

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] ERROR: This script must be run as Administrator" -ForegroundColor Red
    Write-Host "[*] Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    pause
    exit 1
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$hostname = $env:COMPUTERNAME
$collectionDir = "C:\Triage_${hostname}_${timestamp}"

# Get script directory once at the start
$script:scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrEmpty($script:scriptDirectory)) {
    $script:scriptDirectory = Get-Location
}

Write-Host @"

========================================
  ENHANCED TRIAGE COLLECTION v2.0
========================================
  Target System: $hostname
  Collection Time: $(Get-Date)
  Output: $collectionDir
========================================

"@ -ForegroundColor Cyan

#==========================================
# COLLECTION PROFILE SELECTION
#==========================================

Write-Host "`nSelect Collection Profile:" -ForegroundColor Yellow
Write-Host "  1. Quick Triage (Essential artifacts only - 2-5 minutes)" -ForegroundColor White
Write-Host "  2. Standard Collection (Recommended - 5-15 minutes)" -ForegroundColor White
Write-Host "  3. Comprehensive Collection (Everything including MFT/USN - 15-30 minutes)" -ForegroundColor White
Write-Host "  4. Custom (Choose specific artifacts)" -ForegroundColor White
Write-Host "  5. Memory Dump Only (RAM capture)" -ForegroundColor White
Write-Host ""

$profile = Read-Host "Enter choice (1-5)"

# Initialize collection flags
$collect = @{
    EventLogs = $false
    Registry = $false
    Persistence = $false
    Network = $false
    Processes = $false
    Users = $false
    PowerShell = $false
    Browser = $false
    Prefetch = $false
    FileSystem = $false
    AmCache = $false
    MFT = $false
    USNJournal = $false
    MemoryDump = $false
    RecentFiles = $false
    SRUM = $false
    WMI = $false
    BitlockerKeys = $false
}

switch ($profile) {
    "1" { # Quick Triage
        $collect.EventLogs = $true
        $collect.Persistence = $true
        $collect.Network = $true
        $collect.Processes = $true
        $collect.PowerShell = $true
        $collect.Prefetch = $true
    }
    "2" { # Standard
        $collect.EventLogs = $true
        $collect.Registry = $true
        $collect.Persistence = $true
        $collect.Network = $true
        $collect.Processes = $true
        $collect.Users = $true
        $collect.PowerShell = $true
        $collect.Browser = $true
        $collect.Prefetch = $true
        $collect.FileSystem = $true
        $collect.AmCache = $true
        $collect.RecentFiles = $true
    }
    "3" { # Comprehensive
        $collect.EventLogs = $true
        $collect.Registry = $true
        $collect.Persistence = $true
        $collect.Network = $true
        $collect.Processes = $true
        $collect.Users = $true
        $collect.PowerShell = $true
        $collect.Browser = $true
        $collect.Prefetch = $true
        $collect.FileSystem = $true
        $collect.AmCache = $true
        $collect.MFT = $true
        $collect.USNJournal = $true
        $collect.MemoryDump = $true
        $collect.RecentFiles = $true
        $collect.SRUM = $true
        $collect.WMI = $true
        $collect.BitlockerKeys = $true
    }
    "4" { # Custom
        Write-Host "`n=== Custom Collection ===" -ForegroundColor Cyan
        Write-Host "Select artifacts to collect (Y/N):`n" -ForegroundColor Yellow
        
        $collect.EventLogs = (Read-Host "Event Logs (Security, System, Application, PowerShell, Sysmon) [Y/n]") -ne 'n'
        $collect.Registry = (Read-Host "Registry Hives (SAM, SECURITY, SOFTWARE, SYSTEM) [Y/n]") -ne 'n'
        $collect.Persistence = (Read-Host "Persistence Mechanisms (Run keys, Tasks, Services, WMI) [Y/n]") -ne 'n'
        $collect.Network = (Read-Host "Network Information (Connections, DNS, ARP, Firewall) [Y/n]") -ne 'n'
        $collect.Processes = (Read-Host "Process & Service Information [Y/n]") -ne 'n'
        $collect.Users = (Read-Host "User Account Information [Y/n]") -ne 'n'
        $collect.PowerShell = (Read-Host "PowerShell Artifacts (History, Transcripts) [Y/n]") -ne 'n'
        $collect.Browser = (Read-Host "Browser History (Chrome, Edge, Firefox, IE) [Y/n]") -ne 'n'
        $collect.Prefetch = (Read-Host "Prefetch Files [Y/n]") -ne 'n'
        $collect.FileSystem = (Read-Host "File System Artifacts (LNK, JumpLists, Recent) [Y/n]") -ne 'n'
        $collect.AmCache = (Read-Host "AmCache.hve [Y/n]") -ne 'n'
        $collect.RecentFiles = (Read-Host "Recently Modified Files (last 7 days) [y/N]") -eq 'y'
        $collect.MFT = (Read-Host "Master File Table (`$MFT) - REQUIRES RawCopy [y/N]") -eq 'y'
        $collect.USNJournal = (Read-Host "USN Journal (`$UsnJrnl) - REQUIRES RawCopy [y/N]") -eq 'y'
        $collect.SRUM = (Read-Host "SRUM Database (System Resource Usage Monitor) [y/N]") -eq 'y'
        $collect.WMI = (Read-Host "WMI Repository [y/N]") -eq 'y'
        $collect.BitlockerKeys = (Read-Host "Bitlocker Recovery Keys [y/N]") -eq 'y'
        $collect.MemoryDump = (Read-Host "Memory Dump (Full RAM) - REQUIRES Belkasoft RamCapture64 [y/N]") -eq 'y'
    }
    "5" { # Memory Only
        $collect.MemoryDump = $true
    }
    default {
        Write-Host "[!] Invalid selection. Exiting." -ForegroundColor Red
        pause
        exit 1
    }
}

#==========================================
# CONFIRM COLLECTION
#==========================================

Write-Host "`n=== Collection Summary ===" -ForegroundColor Cyan
Write-Host "The following artifacts will be collected:`n" -ForegroundColor Yellow

foreach ($artifact in $collect.Keys | Sort-Object) {
    if ($collect[$artifact]) {
        Write-Host "  [X] $artifact" -ForegroundColor Green
    }
}

Write-Host ""
$confirm = Read-Host "Proceed with collection? (Y/n)"
if ($confirm -eq 'n') {
    Write-Host "[*] Collection cancelled" -ForegroundColor Yellow
    pause
    exit 0
}

#==========================================
# CREATE DIRECTORY STRUCTURE
#==========================================

Write-Host "`n[*] Creating collection directory..." -ForegroundColor Cyan
New-Item -Path $collectionDir -ItemType Directory -Force | Out-Null

$directories = @(
    "EventLogs",
    "Registry", 
    "Persistence",
    "Network",
    "ProcessInfo",
    "UserInfo",
    "PowerShell",
    "BrowserData",
    "Prefetch",
    "FileSystem",
    "AdvancedArtifacts",
    "Memory",
    "WebServerLogs"
)

foreach ($dir in $directories) {
    New-Item -Path "$collectionDir\$dir" -ItemType Directory -Force | Out-Null
}

#==========================================
# COLLECTION FUNCTIONS
#==========================================

function Write-CollectionLog {
    param([string]$Message, [string]$Color = "White")
    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
    Add-Content "$collectionDir\collection.log" "[$timestamp] $Message"
}

function Invoke-SafeCommand {
    param(
        [string]$Command,
        [string]$OutputFile,
        [string]$Description
    )
    
    Write-CollectionLog "Collecting: $Description" "Green"
    try {
        Invoke-Expression "$Command > `"$OutputFile`" 2>&1"
        if (Test-Path $OutputFile) {
            Write-CollectionLog "  Success: $(Split-Path $OutputFile -Leaf)" "Gray"
        } else {
            Write-CollectionLog "  Warning: No output generated" "Yellow"
        }
    } catch {
        Write-CollectionLog "  Error: $_" "Red"
    }
}

function Copy-LockedFile {
    param(
        [string]$SourcePath,
        [string]$DestinationPath,
        [string]$Description
    )
    
    Write-CollectionLog "Copying: $Description" "Green"
    
    # Try normal copy first
    try {
        Copy-Item $SourcePath $DestinationPath -Force -ErrorAction Stop
        Write-CollectionLog "  Success: $(Split-Path $DestinationPath -Leaf)" "Gray"
        return $true
    } catch {
        Write-CollectionLog "  File locked, attempting RawCopy..." "Yellow"
        
        # Use script-level variable for script directory
        $rawCopyPath = Join-Path $script:scriptDirectory "RawCopy64.exe"
        if (-not (Test-Path $rawCopyPath)) {
            $rawCopyPath = Join-Path $script:scriptDirectory "RawCopy.exe"
        }
        
        if (Test-Path $rawCopyPath) {
            try {
                $outputDir = Split-Path $DestinationPath -Parent
                $outputName = Split-Path $DestinationPath -Leaf
                
                & $rawCopyPath /FileNamePath:"$SourcePath" /OutputPath:"$outputDir" /OutputName:$outputName 2>&1 | Out-Null
                
                if (Test-Path $DestinationPath) {
                    Write-CollectionLog "  SUCCESS: $(Split-Path $DestinationPath -Leaf) (via RawCopy)" "Green"
                    return $true
                } else {
                    Write-CollectionLog "  FAILED: Could not copy with RawCopy" "Red"
                    return $false
                }
            } catch {
                Write-CollectionLog "  ERROR: RawCopy failed: $_" "Red"
                return $false
            }
        } else {
            Write-CollectionLog "  FAILED: File locked and RawCopy not available" "Red"
            Write-CollectionLog "  Download RawCopy64.exe from: https://github.com/jschicht/RawCopy" "Yellow"
            return $false
        }
    }
}

#==========================================
# START COLLECTION
#==========================================

$startTime = Get-Date

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " STARTING COLLECTION" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Collection metadata
@"
TRIAGE COLLECTION METADATA
==========================
Collection Time: $(Get-Date)
Collected By: $env:USERNAME
System: $hostname
Profile: $profile
Output Directory: $collectionDir

ARTIFACTS COLLECTED:
$(foreach ($key in ($collect.Keys | Sort-Object)) { if ($collect[$key]) { "  - $key" } })
"@ | Out-File "$collectionDir\COLLECTION_INFO.txt"

#==========================================
# EVENT LOGS
#==========================================

if ($collect.EventLogs) {
    Write-CollectionLog "`n=== EVENT LOGS ===" "Cyan"
    
    $eventLogs = @{
        "Security" = "Security"
        "System" = "System"
        "Application" = "Application"
        "PowerShell-Operational" = "Microsoft-Windows-PowerShell/Operational"
        "PowerShell-Legacy" = "Windows PowerShell"
        "Sysmon" = "Microsoft-Windows-Sysmon/Operational"
        "TaskScheduler" = "Microsoft-Windows-TaskScheduler/Operational"
        "RDP-LocalSessionManager" = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
        "RDP-RemoteConnectionManager" = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
        "Defender" = "Microsoft-Windows-Windows Defender/Operational"
        "Firewall" = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
        "WMI-Activity" = "Microsoft-Windows-WMI-Activity/Operational"
        "BITS-Client" = "Microsoft-Windows-Bits-Client/Operational"
        "AppLocker-EXE" = "Microsoft-Windows-AppLocker/EXE and DLL"
        "AppLocker-MSI" = "Microsoft-Windows-AppLocker/MSI and Script"
    }
    
    foreach ($log in $eventLogs.GetEnumerator()) {
        $output = "$collectionDir\EventLogs\$($log.Key).evtx"
        try {
            wevtutil epl "$($log.Value)" "$output" 2>$null
            if (Test-Path $output) {
                Write-CollectionLog "  Exported: $($log.Key).evtx" "Gray"
            }
        } catch {
            Write-CollectionLog "  Not found: $($log.Key)" "Yellow"
        }
    }
}

#==========================================
# REGISTRY HIVES
#==========================================

if ($collect.Registry) {
    Write-CollectionLog "`n=== REGISTRY HIVES ===" "Cyan"
    
    $hives = @{
        "SAM" = "HKLM\SAM"
        "SECURITY" = "HKLM\SECURITY"
        "SOFTWARE" = "HKLM\SOFTWARE"
        "SYSTEM" = "HKLM\SYSTEM"
        "NTUSER" = "HKCU\SOFTWARE"
    }
    
    foreach ($hive in $hives.GetEnumerator()) {
        $output = "$collectionDir\Registry\$($hive.Key).hive"
        Invoke-SafeCommand "reg save `"$($hive.Value)`" `"$output`" /y" $output "Registry: $($hive.Key)"
    }
    
    # Export UsrClass.dat for all users
    Write-CollectionLog "Collecting UsrClass.dat hives..." "Green"
    Get-ChildItem "C:\Users\*\AppData\Local\Microsoft\Windows\UsrClass.dat" -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $username = $_.FullName.Split('\')[2]
        $dest = "$collectionDir\Registry\UsrClass_$username.dat"
        try {
            Copy-Item $_.FullName $dest -Force -ErrorAction SilentlyContinue
            Write-CollectionLog "  Copied: UsrClass_$username.dat" "Gray"
        } catch {
            Write-CollectionLog "  Locked: UsrClass_$username.dat (in use)" "Yellow"
        }
    }
}

#==========================================
# PERSISTENCE MECHANISMS
#==========================================

if ($collect.Persistence) {
    Write-CollectionLog "`n=== PERSISTENCE MECHANISMS ===" "Cyan"
    
    # Registry Run Keys
    $runKeys = @(
        "HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices",
        "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    )
    
    foreach ($key in $runKeys) {
        $safeName = $key -replace '\\', '_' -replace ':', ''
        Invoke-SafeCommand "reg query `"$key`"" "$collectionDir\Persistence\$safeName.txt" "Run Key: $key"
    }
    
    # Scheduled Tasks
    Invoke-SafeCommand "schtasks /query /fo LIST /v" "$collectionDir\Persistence\scheduled-tasks-verbose.txt" "Scheduled Tasks (Verbose)"
    Invoke-SafeCommand "schtasks /query /xml" "$collectionDir\Persistence\scheduled-tasks.xml" "Scheduled Tasks (XML)"
    
    # Copy task files
    Write-CollectionLog "Copying task files..." "Green"
    try {
        xcopy /s /i /y "C:\Windows\System32\Tasks" "$collectionDir\Persistence\Tasks" 2>$null
    } catch {}
    
    # Services
    Write-CollectionLog "Collecting services..." "Green"
    try {
        Get-Service | Select-Object Name, DisplayName, Status, StartType, ServiceName |
            Export-Csv "$collectionDir\Persistence\services-detailed.csv" -NoTypeInformation
        Write-CollectionLog "  Success: services-detailed.csv" "Gray"
    } catch {
        Write-CollectionLog "  Error collecting services: $_" "Red"
    }
    
    try {
        cmd /c "sc query" > "$collectionDir\Persistence\services-running.txt" 2>&1
        if (Test-Path "$collectionDir\Persistence\services-running.txt") {
            Write-CollectionLog "  Success: services-running.txt" "Gray"
        }
    } catch {
        Write-CollectionLog "  Error: $_" "Red"
    }
    
    Invoke-SafeCommand "reg query `"HKLM\SYSTEM\CurrentControlSet\Services`" /s" "$collectionDir\Persistence\services-registry.txt" "Services (Registry)"
    
    # Startup Folders
    Invoke-SafeCommand "dir `"C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`" /s" "$collectionDir\Persistence\user-startup.txt" "User Startup Folders"
    Invoke-SafeCommand "dir `"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`" /s" "$collectionDir\Persistence\all-users-startup.txt" "All Users Startup"
}

if ($collect.WMI) {
    Write-CollectionLog "Collecting WMI persistence..." "Green"
    
    try {
        Get-WmiObject -Namespace root\subscription -Class __EventFilter |
            Select-Object Name, Query, QueryLanguage, EventNamespace |
            Export-Csv "$collectionDir\Persistence\wmi-filters.csv" -NoTypeInformation
        Write-CollectionLog "  Success: wmi-filters.csv" "Gray"
    } catch {
        Write-CollectionLog "  Error collecting WMI filters: $_" "Yellow"
    }
    
    try {
        Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer |
            Select-Object Name, CommandLineTemplate, ExecutablePath |
            Export-Csv "$collectionDir\Persistence\wmi-consumers.csv" -NoTypeInformation
        Write-CollectionLog "  Success: wmi-consumers.csv" "Gray"
    } catch {
        Write-CollectionLog "  Error collecting WMI consumers: $_" "Yellow"
    }
    
    try {
        Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding |
            Select-Object Filter, Consumer |
            Export-Csv "$collectionDir\Persistence\wmi-bindings.csv" -NoTypeInformation
        Write-CollectionLog "  Success: wmi-bindings.csv" "Gray"
    } catch {
        Write-CollectionLog "  Error collecting WMI bindings: $_" "Yellow"
    }
}

#==========================================
# NETWORK INFORMATION
#==========================================

if ($collect.Network) {
    Write-CollectionLog "`n=== NETWORK INFORMATION ===" "Cyan"
    
    Invoke-SafeCommand "ipconfig /all" "$collectionDir\Network\ipconfig.txt" "IP Configuration"
    Invoke-SafeCommand "ipconfig /displaydns" "$collectionDir\Network\dns-cache.txt" "DNS Cache"
    Invoke-SafeCommand "netstat -anob" "$collectionDir\Network\netstat-anob.txt" "Network Connections"
    Invoke-SafeCommand "netstat -rn" "$collectionDir\Network\routing-table.txt" "Routing Table"
    Invoke-SafeCommand "arp -a" "$collectionDir\Network\arp-cache.txt" "ARP Cache"
    Invoke-SafeCommand "nbtstat -c" "$collectionDir\Network\netbios-cache.txt" "NetBIOS Cache"
    Invoke-SafeCommand "net session" "$collectionDir\Network\smb-sessions.txt" "SMB Sessions"
    Invoke-SafeCommand "net use" "$collectionDir\Network\mapped-drives.txt" "Mapped Drives"
    Invoke-SafeCommand "net share" "$collectionDir\Network\shares.txt" "Network Shares"
    Invoke-SafeCommand "route print" "$collectionDir\Network\routes.txt" "Routes"
    
    Write-CollectionLog "Collecting network adapters..." "Green"
    try {
        Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed |
            Export-Csv "$collectionDir\Network\network-adapters.csv" -NoTypeInformation
        Write-CollectionLog "  Success: network-adapters.csv" "Gray"
    } catch {
        Write-CollectionLog "  Error collecting network adapters: $_" "Red"
    }
    
    try {
        Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, AddressFamily, PrefixLength |
            Export-Csv "$collectionDir\Network\ip-addresses.csv" -NoTypeInformation
        Write-CollectionLog "  Success: ip-addresses.csv" "Gray"
    } catch {}
    
    Invoke-SafeCommand "netsh advfirewall show allprofiles" "$collectionDir\Network\firewall-profiles.txt" "Firewall Profiles"
    Invoke-SafeCommand "netsh advfirewall firewall show rule name=all verbose" "$collectionDir\Network\firewall-rules.txt" "Firewall Rules"
    
    # WiFi Profiles
    Invoke-SafeCommand "netsh wlan show profiles" "$collectionDir\Network\wifi-profiles.txt" "WiFi Profiles"
    
    Write-CollectionLog "Extracting WiFi passwords..." "Green"
    $wifiProfiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object { ($_ -split ':')[1].Trim() }
    foreach ($wifiProfile in $wifiProfiles) {
        netsh wlan show profile name="$wifiProfile" key=clear >> "$collectionDir\Network\wifi-details.txt" 2>&1
    }
}

#==========================================
# PROCESS & SERVICE INFORMATION
#==========================================

if ($collect.Processes) {
    Write-CollectionLog "`n=== PROCESS INFORMATION ===" "Cyan"
    
    Invoke-SafeCommand "tasklist /v" "$collectionDir\ProcessInfo\tasklist.txt" "Task List"
    Invoke-SafeCommand "tasklist /svc" "$collectionDir\ProcessInfo\tasklist-services.txt" "Task List (with Services)"
    
    Write-CollectionLog "Collecting process details..." "Green"
    try {
        Get-Process | Select-Object ProcessName, Id, Path, CommandLine, StartTime, 
            @{Name='ParentProcessId';Expression={$_.Parent.Id}},
            @{Name='Company';Expression={$_.Company}},
            @{Name='ProductVersion';Expression={$_.ProductVersion}} |
            Export-Csv "$collectionDir\ProcessInfo\processes-detailed.csv" -NoTypeInformation
        Write-CollectionLog "  Success: processes-detailed.csv" "Gray"
    } catch {
        Write-CollectionLog "  Error collecting process details: $_" "Red"
    }
    
    try {
        Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, 
            CommandLine, CreationDate, ExecutablePath |
            Export-Csv "$collectionDir\ProcessInfo\process-commandlines.csv" -NoTypeInformation
        Write-CollectionLog "  Success: process-commandlines.csv" "Gray"
    } catch {
        Write-CollectionLog "  Error collecting command lines: $_" "Red"
    }
    
    # Process DLLs
    Write-CollectionLog "Collecting loaded DLLs..." "Green"
    Get-Process | ForEach-Object {
        try {
            $_.Modules | Select-Object @{Name='ProcessName';Expression={$_.ProcessName}}, ModuleName, FileName | 
                Export-Csv "$collectionDir\ProcessInfo\loaded-dlls.csv" -Append -NoTypeInformation
        } catch {}
    }
}

#==========================================
# USER INFORMATION
#==========================================

if ($collect.Users) {
    Write-CollectionLog "`n=== USER INFORMATION ===" "Cyan"
    
    Invoke-SafeCommand "net user" "$collectionDir\UserInfo\users-local.txt" "Local Users"
    Invoke-SafeCommand "net user /domain" "$collectionDir\UserInfo\users-domain.txt" "Domain Users"
    Invoke-SafeCommand "net localgroup administrators" "$collectionDir\UserInfo\local-admins.txt" "Local Administrators"
    Invoke-SafeCommand "net accounts" "$collectionDir\UserInfo\account-policies.txt" "Account Policies"
    Invoke-SafeCommand "net accounts /domain" "$collectionDir\UserInfo\domain-account-policies.txt" "Domain Account Policies"
    
    Write-CollectionLog "Collecting user account details..." "Green"
    try {
        Get-LocalUser | Select-Object Name, Enabled, Description, LastLogon, PasswordLastSet, 
            PasswordExpires, UserMayChangePassword, PasswordRequired |
            Export-Csv "$collectionDir\UserInfo\user-accounts-detailed.csv" -NoTypeInformation
        Write-CollectionLog "  Success: user-accounts-detailed.csv" "Gray"
    } catch {
        Write-CollectionLog "  Error collecting user accounts: $_" "Red"
    }
    
    Invoke-SafeCommand "query user" "$collectionDir\UserInfo\logged-on-users.txt" "Logged On Users"
    Invoke-SafeCommand "qwinsta" "$collectionDir\UserInfo\session-info.txt" "Session Information"
}

#==========================================
# POWERSHELL ARTIFACTS
#==========================================

if ($collect.PowerShell) {
    Write-CollectionLog "`n=== POWERSHELL ARTIFACTS ===" "Cyan"
    
    # Console Host History
    Write-CollectionLog "Collecting PowerShell history files..." "Green"
    Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $username = $_.FullName.Split('\')[2]
        Copy-Item $_.FullName "$collectionDir\PowerShell\ConsoleHost_history_$username.txt" -Force -ErrorAction SilentlyContinue
        Write-CollectionLog "  Copied: ConsoleHost_history_$username.txt" "Gray"
    }
    
    # PowerShell Transcripts
    Write-CollectionLog "Collecting PowerShell transcripts..." "Green"
    Get-ChildItem "C:\Users\*\Documents\PowerShell_transcript*.txt" -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Copy-Item $_.FullName "$collectionDir\PowerShell\Transcripts\" -Force -ErrorAction SilentlyContinue
    }
    
    # PowerShell Logging Config
    Invoke-SafeCommand "reg query `"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging`"" "$collectionDir\PowerShell\module-logging-config.txt" "Module Logging Config"
    Invoke-SafeCommand "reg query `"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`"" "$collectionDir\PowerShell\scriptblock-logging-config.txt" "ScriptBlock Logging Config"
}

#==========================================
# BROWSER HISTORY
#==========================================

if ($collect.Browser) {
    Write-CollectionLog "`n=== BROWSER ARTIFACTS ===" "Cyan"
    
    # Chrome
    Write-CollectionLog "Collecting Chrome artifacts..." "Green"
    Get-ChildItem "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\History" -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $username = $_.FullName.Split('\')[2]
        Copy-LockedFile -SourcePath $_.FullName -DestinationPath "$collectionDir\BrowserData\Chrome_History_$username.db" -Description "Chrome History ($username)"
    }
    
    Get-ChildItem "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Cookies" -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $username = $_.FullName.Split('\')[2]
        Copy-LockedFile -SourcePath $_.FullName -DestinationPath "$collectionDir\BrowserData\Chrome_Cookies_$username.db" -Description "Chrome Cookies ($username)"
    }
    
    # Edge
    Write-CollectionLog "Collecting Edge artifacts..." "Green"
    Get-ChildItem "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\History" -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $username = $_.FullName.Split('\')[2]
        Copy-LockedFile -SourcePath $_.FullName -DestinationPath "$collectionDir\BrowserData\Edge_History_$username.db" -Description "Edge History ($username)"
    }
    
    # Firefox
    Write-CollectionLog "Collecting Firefox artifacts..." "Green"
    Get-ChildItem "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite" -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $username = $_.FullName.Split('\')[2]
        Copy-LockedFile -SourcePath $_.FullName -DestinationPath "$collectionDir\BrowserData\Firefox_places_$username.sqlite" -Description "Firefox places.sqlite ($username)"
    }
    
    # IE/WebCache
    Write-CollectionLog "Collecting IE WebCache..." "Green"
    Get-ChildItem "C:\Users\*\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat" -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $username = $_.FullName.Split('\')[2]
        Copy-LockedFile -SourcePath $_.FullName -DestinationPath "$collectionDir\BrowserData\IE_WebCache_$username.dat" -Description "IE WebCache ($username)"
    }
}

#==========================================
# PREFETCH FILES
#==========================================

if ($collect.Prefetch) {
    Write-CollectionLog "`n=== PREFETCH FILES ===" "Cyan"
    
    if (Test-Path "C:\Windows\Prefetch") {
        $prefetchCount = (Get-ChildItem "C:\Windows\Prefetch\*.pf" -ErrorAction SilentlyContinue).Count
        Write-CollectionLog "Copying $prefetchCount prefetch files..." "Green"
        xcopy /s /i /y "C:\Windows\Prefetch\*.pf" "$collectionDir\Prefetch\" 2>$null
    } else {
        Write-CollectionLog "Prefetch disabled on this system" "Yellow"
    }
}

#==========================================
# FILE SYSTEM ARTIFACTS
#==========================================

if ($collect.FileSystem) {
    Write-CollectionLog "`n=== FILE SYSTEM ARTIFACTS ===" "Cyan"
    
    # Recent Files / LNK
    Write-CollectionLog "Collecting Recent/LNK files..." "Green"
    Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*.lnk" -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $username = $_.FullName.Split('\')[2]
        $destDir = "$collectionDir\FileSystem\Recent_$username"
        New-Item -Path $destDir -ItemType Directory -Force | Out-Null
        Copy-Item $_.FullName $destDir -Force -ErrorAction SilentlyContinue
    }
    
    # Jump Lists
    Write-CollectionLog "Collecting Jump Lists..." "Green"
    Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*" -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $username = $_.FullName.Split('\')[2]
        $destDir = "$collectionDir\FileSystem\JumpLists_$username\Automatic"
        New-Item -Path $destDir -ItemType Directory -Force | Out-Null
        Copy-Item $_.FullName $destDir -Force -ErrorAction SilentlyContinue
    }
    
    Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*" -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $username = $_.FullName.Split('\')[2]
        $destDir = "$collectionDir\FileSystem\JumpLists_$username\Custom"
        New-Item -Path $destDir -ItemType Directory -Force | Out-Null
        Copy-Item $_.FullName $destDir -Force -ErrorAction SilentlyContinue
    }
    
    # Recycle Bin
    Write-CollectionLog "Collecting Recycle Bin listing..." "Green"
    try {
        Get-ChildItem "C:\`$Recycle.Bin" -Recurse -Force -ErrorAction SilentlyContinue |
            Select-Object FullName, Length, LastWriteTime, CreationTime |
            Export-Csv "$collectionDir\FileSystem\recycle-bin.csv" -NoTypeInformation
        Write-CollectionLog "  Success: recycle-bin.csv" "Gray"
    } catch {
        Write-CollectionLog "  Error collecting Recycle Bin: $_" "Red"
    }
    
    # USB History
    Invoke-SafeCommand "reg query `"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`" /s" "$collectionDir\FileSystem\usb-history.txt" "USB Device History"
    Invoke-SafeCommand "reg query `"HKLM\SYSTEM\MountedDevices`"" "$collectionDir\FileSystem\mounted-devices.txt" "Mounted Devices"
}

if ($collect.RecentFiles) {
    Write-CollectionLog "Collecting recently modified files..." "Green"
    try {
        Get-ChildItem "C:\Users" -Recurse -File -ErrorAction SilentlyContinue | 
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
            Select-Object FullName, LastWriteTime, Length |
            Export-Csv "$collectionDir\FileSystem\recent-files-7days.csv" -NoTypeInformation
        Write-CollectionLog "  Success: recent-files-7days.csv" "Gray"
    } catch {
        Write-CollectionLog "  Error collecting recent files: $_" "Red"
    }
}

#==========================================
# AMCACHE
#==========================================

if ($collect.AmCache) {
    Write-CollectionLog "`n=== AMCACHE ===" "Cyan"
    
    if (Test-Path "C:\Windows\appcompat\Programs\Amcache.hve") {
        Copy-LockedFile -SourcePath "C:\Windows\appcompat\Programs\Amcache.hve" -DestinationPath "$collectionDir\AdvancedArtifacts\Amcache.hve" -Description "Amcache.hve"
    }
}

#==========================================
# SHIMCACHE / APPCOMPATCACHE & BAM/DAM
#==========================================

if ($collect.AmCache) {
    Write-CollectionLog "`n=== SHIMCACHE (APPCOMPATCACHE) ===" "Cyan"
    
    Invoke-SafeCommand "reg query `"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`" /s" "$collectionDir\AdvancedArtifacts\shimcache.txt" "Shimcache (AppCompatCache)"
    
    # BAM/DAM - Background Activity Moderator (Windows 10+)
    Write-CollectionLog "Collecting BAM/DAM (Background Activity Moderator)..." "Green"
    Invoke-SafeCommand "reg query `"HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`" /s" "$collectionDir\AdvancedArtifacts\bam.txt" "BAM UserSettings"
    Invoke-SafeCommand "reg query `"HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings`" /s" "$collectionDir\AdvancedArtifacts\dam.txt" "DAM UserSettings"
}

#==========================================
# WINDOWS TIMELINE & ACTIVITIES
#==========================================

if ($collect.FileSystem) {
    Write-CollectionLog "`n=== WINDOWS TIMELINE & ACTIVITIES ===" "Cyan"
    
    # ActivitiesCache.db - Windows Timeline
    Write-CollectionLog "Collecting Windows Timeline (ActivitiesCache.db)..." "Green"
    Get-ChildItem "C:\Users\*\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db" -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $username = $_.FullName.Split('\')[2]
        $destDir = "$collectionDir\FileSystem\Timeline_$username"
        New-Item -Path $destDir -ItemType Directory -Force | Out-Null
        try {
            Copy-Item $_.FullName $destDir -Force -ErrorAction Stop
            Write-CollectionLog "  Copied: ActivitiesCache.db for $username" "Gray"
        } catch {
            Write-CollectionLog "  Locked: ActivitiesCache.db for $username" "Yellow"
        }
    }
    
    # Office Recent Files
    Write-CollectionLog "Collecting Office Recent files..." "Green"
    Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Office\Recent\*" -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $username = $_.FullName.Split('\')[2]
        $destDir = "$collectionDir\FileSystem\Office_Recent_$username"
        New-Item -Path $destDir -ItemType Directory -Force | Out-Null
        Copy-Item $_.FullName $destDir -Force -ErrorAction SilentlyContinue
    }
    
    # Sticky Notes (Windows 10+)
    Write-CollectionLog "Collecting Sticky Notes..." "Green"
    Get-ChildItem "C:\Users\*\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\plum.sqlite*" -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $username = $_.FullName.Split('\')[2]
        $destDir = "$collectionDir\FileSystem\StickyNotes_$username"
        New-Item -Path $destDir -ItemType Directory -Force | Out-Null
        Copy-Item $_.FullName $destDir -Force -ErrorAction SilentlyContinue
        Write-CollectionLog "  Copied: StickyNotes for $username" "Gray"
    }
}

#==========================================
# RECYCLE BIN METADATA
#==========================================

if ($collect.FileSystem) {
    Write-CollectionLog "`n=== RECYCLE BIN METADATA ===" "Cyan"
    
    Write-CollectionLog "Collecting Recycle Bin metadata files..." "Green"
    
    $recycleBinDir = "$collectionDir\FileSystem\RecycleBin"
    New-Item -Path $recycleBinDir -ItemType Directory -Force | Out-Null
    
    try {
        Get-ChildItem "C:\`$Recycle.Bin\*\`$I*" -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $sid = $_.DirectoryName.Split('\')[-1]
            $destDir = "$recycleBinDir\$sid"
            New-Item -Path $destDir -ItemType Directory -Force | Out-Null
            Copy-Item $_.FullName $destDir -Force -ErrorAction SilentlyContinue
        }
        Write-CollectionLog "  Copied Recycle Bin metadata files" "Gray"
    } catch {
        Write-CollectionLog "  Error collecting Recycle Bin: $_" "Yellow"
    }
}

#==========================================
# BITS TRANSFER JOBS
#==========================================

if ($collect.Network) {
    Write-CollectionLog "`n=== BITS TRANSFER JOBS ===" "Cyan"
    
    Write-CollectionLog "Collecting active BITS jobs..." "Green"
    try {
        Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | 
            Select-Object DisplayName, JobState, BytesTransferred, BytesTotal, 
                         CreationTime, TransferCompletionTime, FileList | 
            Export-Csv "$collectionDir\Network\bits-jobs-active.csv" -NoTypeInformation
        Write-CollectionLog "  Success: bits-jobs-active.csv" "Gray"
    } catch {
        Write-CollectionLog "  No active BITS jobs or insufficient permissions" "Yellow"
    }
    
    Write-CollectionLog "Collecting BITS database files..." "Green"
    try {
        Copy-Item "C:\ProgramData\Microsoft\Network\Downloader\qmgr*.dat" "$collectionDir\Network\" -Force -ErrorAction SilentlyContinue
        Write-CollectionLog "  Copied BITS database files" "Gray"
    } catch {
        Write-CollectionLog "  BITS database files locked or not found" "Yellow"
    }
}

#==========================================
# WINDOWS DEFENDER ARTIFACTS
#==========================================

if ($collect.EventLogs) {
    Write-CollectionLog "`n=== WINDOWS DEFENDER ARTIFACTS ===" "Cyan"
    
    Write-CollectionLog "Listing Defender Quarantine..." "Green"
    try {
        Get-ChildItem "C:\ProgramData\Microsoft\Windows Defender\Quarantine\*" -Force -Recurse -ErrorAction SilentlyContinue | 
            Select-Object FullName, Length, CreationTime, LastWriteTime | 
            Export-Csv "$collectionDir\AdvancedArtifacts\defender-quarantine-listing.csv" -NoTypeInformation
        Write-CollectionLog "  Success: defender-quarantine-listing.csv" "Gray"
    } catch {
        Write-CollectionLog "  Could not access Defender Quarantine" "Yellow"
    }
    
    Write-CollectionLog "Collecting Defender scan logs..." "Green"
    try {
        Copy-Item "C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\*\*" "$collectionDir\AdvancedArtifacts\Defender\" -Recurse -Force -ErrorAction SilentlyContinue
        Write-CollectionLog "  Copied Defender detection history" "Gray"
    } catch {
        Write-CollectionLog "  Defender logs not accessible" "Yellow"
    }
}

#==========================================
# VSS (VOLUME SHADOW COPY) INFORMATION
#==========================================

if ($collect.FileSystem) {
    Write-CollectionLog "`n=== VOLUME SHADOW COPY INFORMATION ===" "Cyan"
    
    Invoke-SafeCommand "vssadmin list shadows" "$collectionDir\AdvancedArtifacts\vss-shadows-list.txt" "Volume Shadow Copies List"
    Invoke-SafeCommand "vssadmin list shadowstorage" "$collectionDir\AdvancedArtifacts\vss-storage.txt" "VSS Storage Areas"
    
    Write-CollectionLog "Collecting VSS detailed information..." "Green"
    try {
        Get-WmiObject Win32_ShadowCopy | 
            Select-Object ID, VolumeName, InstallDate, DeviceObject, Count | 
            Export-Csv "$collectionDir\AdvancedArtifacts\vss-detailed.csv" -NoTypeInformation
        Write-CollectionLog "  Success: vss-detailed.csv" "Gray"
    } catch {
        Write-CollectionLog "  Error collecting VSS info: $_" "Yellow"
    }
}

#==========================================
# DRIVERS & LOADED MODULES
#==========================================

if ($collect.Processes) {
    Write-CollectionLog "`n=== DRIVERS & LOADED MODULES ===" "Cyan"
    
    Write-CollectionLog "Collecting driver list..." "Green"
    try {
        Get-WmiObject Win32_SystemDriver | 
            Select-Object Name, DisplayName, PathName, State, StartMode, ServiceType | 
            Export-Csv "$collectionDir\ProcessInfo\drivers.csv" -NoTypeInformation
        Write-CollectionLog "  Success: drivers.csv" "Gray"
    } catch {
        Write-CollectionLog "  Error collecting drivers: $_" "Yellow"
    }
    
    Invoke-SafeCommand "driverquery /v /fo csv" "$collectionDir\ProcessInfo\drivers-detailed.csv" "Drivers (Detailed)"
    
    Write-CollectionLog "Collecting loaded kernel modules..." "Green"
    try {
        Get-WmiObject Win32_PnPSignedDriver | 
            Select-Object DeviceName, DeviceID, DriverVersion, Manufacturer, InfName, IsSigned | 
            Export-Csv "$collectionDir\ProcessInfo\signed-drivers.csv" -NoTypeInformation
        Write-CollectionLog "  Success: signed-drivers.csv" "Gray"
    } catch {
        Write-CollectionLog "  Error collecting signed drivers: $_" "Yellow"
    }
}

#==========================================
# HANDLES & OPEN FILES
#==========================================

if ($collect.Processes) {
    Write-CollectionLog "`n=== HANDLES & OPEN FILES ===" "Cyan"
    
    # Open file handles (requires Sysinternals handle.exe)
    $handlePath = Join-Path $script:scriptDirectory "handle64.exe"
    if (Test-Path $handlePath) {
        Write-CollectionLog "Found handle64.exe, collecting open handles..." "Green"
        try {
            & $handlePath -a -accepteula > "$collectionDir\ProcessInfo\handles.txt" 2>&1
            Write-CollectionLog "  Success: handles.txt" "Gray"
        } catch {
            Write-CollectionLog "  Error running handle64.exe: $_" "Yellow"
        }
    } else {
        Write-CollectionLog "handle64.exe not found - download from Sysinternals for handle collection" "Yellow"
    }
    
    Write-CollectionLog "Collecting open files (PowerShell method)..." "Green"
    try {
        Get-SmbOpenFile | 
            Select-Object ClientComputerName, ClientUserName, Path, SessionId | 
            Export-Csv "$collectionDir\ProcessInfo\open-smb-files.csv" -NoTypeInformation
        Write-CollectionLog "  Success: open-smb-files.csv" "Gray"
    } catch {
        Write-CollectionLog "  No SMB open files or insufficient permissions" "Yellow"
    }
}

#==========================================
# CERTIFICATE STORE
#==========================================

if ($collect.Registry) {
    Write-CollectionLog "`n=== CERTIFICATE STORE ===" "Cyan"
    
    Write-CollectionLog "Collecting certificate store..." "Green"
    try {
        Get-ChildItem Cert:\LocalMachine\My | 
            Select-Object Subject, Issuer, Thumbprint, NotBefore, NotAfter | 
            Export-Csv "$collectionDir\Registry\certificates-machine.csv" -NoTypeInformation
        Write-CollectionLog "  Success: certificates-machine.csv" "Gray"
    } catch {
        Write-CollectionLog "  Error collecting certificates: $_" "Yellow"
    }
    
    try {
        Get-ChildItem Cert:\LocalMachine\Root | 
            Select-Object Subject, Issuer, Thumbprint, NotBefore, NotAfter | 
            Export-Csv "$collectionDir\Registry\certificates-trusted-root.csv" -NoTypeInformation
        Write-CollectionLog "  Success: certificates-trusted-root.csv" "Gray"
    } catch {}
}

#==========================================
# SRUM DATABASE
#==========================================

if ($collect.SRUM) {
    Write-CollectionLog "`n=== SRUM DATABASE ===" "Cyan"
    
    if (Test-Path "C:\Windows\System32\sru\SRUDB.dat") {
        Copy-LockedFile -SourcePath "C:\Windows\System32\sru\SRUDB.dat" -DestinationPath "$collectionDir\AdvancedArtifacts\SRUDB.dat" -Description "SRUDB.dat"
    }
}

#==========================================
# MFT & USN JOURNAL (Advanced)
#==========================================

if ($collect.MFT -or $collect.USNJournal) {
    Write-CollectionLog "`n=== ADVANCED FILE SYSTEM ARTIFACTS ===" "Cyan"
    
    # Use script-level variable
    $rawCopyPath = Join-Path $script:scriptDirectory "RawCopy64.exe"
    if (-not (Test-Path $rawCopyPath)) {
        $rawCopyPath = Join-Path $script:scriptDirectory "RawCopy.exe"
    }
    
    if (-not (Test-Path $rawCopyPath)) {
        $rawCopyCmd = Get-Command "RawCopy64.exe" -ErrorAction SilentlyContinue
        if ($rawCopyCmd) {
            $rawCopyPath = $rawCopyCmd.Source
        } else {
            $rawCopyCmd = Get-Command "RawCopy.exe" -ErrorAction SilentlyContinue
            if ($rawCopyCmd) {
                $rawCopyPath = $rawCopyCmd.Source
            }
        }
    }
    
    if (-not (Test-Path $rawCopyPath)) {
        Write-CollectionLog "WARNING: RawCopy not found" "Yellow"
        Write-CollectionLog "  Download from: https://github.com/jschicht/RawCopy" "Yellow"
        Write-CollectionLog "  Skipping MFT/USN Journal extraction" "Yellow"
    } else {
        Write-CollectionLog "Found RawCopy at: $rawCopyPath" "Green"
        
        if ($collect.MFT) {
            Write-CollectionLog "Extracting Master File Table (`$MFT)..." "Green"
            try {
                & $rawCopyPath /FileNamePath:C:\0 /OutputPath:"$collectionDir\AdvancedArtifacts" /OutputName:MFT
                
                $mftOutput = Join-Path "$collectionDir\AdvancedArtifacts" "MFT"
                if (Test-Path $mftOutput) {
                    $mftSize = (Get-Item $mftOutput).Length / 1MB
                    Write-CollectionLog "  SUCCESS: MFT extracted ($([math]::Round($mftSize, 2)) MB)" "Green"
                }
            } catch {
                Write-CollectionLog "  ERROR: Failed to extract MFT: $_" "Red"
            }
        }
        
        if ($collect.USNJournal) {
            Write-CollectionLog "Extracting USN Journal (`$UsnJrnl)..." "Green"
            try {
                & $rawCopyPath /FileNamePath:"C:\`$Extend\`$UsnJrnl" /OutputPath:"$collectionDir\AdvancedArtifacts" /OutputName:UsnJrnl
                
                $usnOutput = Join-Path "$collectionDir\AdvancedArtifacts" "UsnJrnl[ADS_`$J]"
                if (Test-Path $usnOutput) {
                    $usnSize = (Get-Item $usnOutput).Length / 1MB
                    Write-CollectionLog "  SUCCESS: USN Journal extracted ($([math]::Round($usnSize, 2)) MB)" "Green"
                    Write-CollectionLog "  Files: UsnJrnl[ADS_`$J] and UsnJrnl[ADS_`$Max]" "Gray"
                }
            } catch {
                Write-CollectionLog "  ERROR: Failed to extract USN Journal: $_" "Red"
            }
        }
        
        # Additional NTFS artifacts
        Write-CollectionLog "`n=== ADDITIONAL NTFS ARTIFACTS ===" "Cyan"
        
        # $LogFile
        Write-CollectionLog "Extracting `$LogFile..." "Green"
        try {
            & $rawCopyPath /FileNamePath:C:\2 /OutputPath:"$collectionDir\AdvancedArtifacts" /OutputName:LogFile
            
            $logFileOutput = Join-Path "$collectionDir\AdvancedArtifacts" "LogFile"
            if (Test-Path $logFileOutput) {
                $logFileSize = (Get-Item $logFileOutput).Length / 1MB
                Write-CollectionLog "  SUCCESS: `$LogFile extracted ($([math]::Round($logFileSize, 2)) MB)" "Green"
            }
        } catch {
            Write-CollectionLog "  Could not extract `$LogFile: $_" "Yellow"
        }
        
        # $Bitmap
        Write-CollectionLog "Extracting `$Bitmap..." "Green"
        try {
            & $rawCopyPath /FileNamePath:C:\6 /OutputPath:"$collectionDir\AdvancedArtifacts" /OutputName:Bitmap
            
            $bitmapOutput = Join-Path "$collectionDir\AdvancedArtifacts" "Bitmap"
            if (Test-Path $bitmapOutput) {
                $bitmapSize = (Get-Item $bitmapOutput).Length / 1MB
                Write-CollectionLog "  SUCCESS: `$Bitmap extracted ($([math]::Round($bitmapSize, 2)) MB)" "Green"
            }
        } catch {
            Write-CollectionLog "  Could not extract `$Bitmap: $_" "Yellow"
        }
    }
}

#==========================================
# WEB SERVER LOGS (IIS)
#==========================================

if ($collect.EventLogs) {
    Write-CollectionLog "`n=== WEB SERVER LOGS (IIS) ===" "Cyan"
    
    if (Test-Path "C:\inetpub\logs\LogFiles") {
        Write-CollectionLog "IIS detected, collecting web logs..." "Green"
        
        try {
            $cutoffDate = (Get-Date).AddDays(-30)
            Get-ChildItem "C:\inetpub\logs\LogFiles" -Recurse -File -ErrorAction SilentlyContinue | 
                Where-Object { $_.LastWriteTime -gt $cutoffDate } | 
                ForEach-Object {
                    $relativePath = $_.FullName.Replace("C:\inetpub\logs\LogFiles\", "")
                    $destPath = Join-Path "$collectionDir\WebServerLogs" $relativePath
                    $destDir = Split-Path $destPath -Parent
                    New-Item -Path $destDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
                    Copy-Item $_.FullName $destPath -Force -ErrorAction SilentlyContinue
                }
            Write-CollectionLog "  Copied IIS logs (last 30 days)" "Gray"
        } catch {
            Write-CollectionLog "  Error collecting IIS logs: $_" "Yellow"
        }
    } else {
        Write-CollectionLog "IIS not detected, skipping web server logs" "Gray"
    }
}

#==========================================
# BITLOCKER RECOVERY KEYS
#==========================================

if ($collect.BitlockerKeys) {
    Write-CollectionLog "`n=== BITLOCKER RECOVERY KEYS ===" "Cyan"
    
    try {
        $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
        if ($bitlockerVolumes) {
            foreach ($vol in $bitlockerVolumes) {
                $recoveryKey = $vol | Select-Object MountPoint, EncryptionMethod, VolumeStatus, ProtectionStatus
                $recoveryKey | Export-Csv "$collectionDir\AdvancedArtifacts\bitlocker-status.csv" -Append -NoTypeInformation
            }
            Invoke-SafeCommand "manage-bde -protectors C: -get" "$collectionDir\AdvancedArtifacts\bitlocker-protectors.txt" "Bitlocker Protectors"
        }
    } catch {
        Write-CollectionLog "Bitlocker not enabled or accessible" "Yellow"
    }
}

#==========================================
# MEMORY DUMP
#==========================================

if ($collect.MemoryDump) {
    Write-CollectionLog "`n=== MEMORY ACQUISITION ===" "Cyan"
    
    $isVM = $false
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $manufacturer = $computerSystem.Manufacturer
        $model = $computerSystem.Model
        
        if ($manufacturer -match "Parallels|VMware|VirtualBox|Microsoft Corporation" -or 
            $model -match "Virtual|VMware|Parallels") {
            $isVM = $true
            Write-CollectionLog "WARNING: Virtual machine detected ($manufacturer $model)" "Yellow"
            Write-CollectionLog "  Memory capture typically fails in VMs due to hypervisor protection" "Yellow"
            Write-CollectionLog "  Skipping memory collection" "Yellow"
        }
    } catch {
        Write-CollectionLog "  Could not determine if system is virtual" "Yellow"
    }
    
    if (-not $isVM) {
        # Use script-level variable
        $ramCapturePath = Join-Path $script:scriptDirectory "RamCapture64.exe"
        if (-not (Test-Path $ramCapturePath)) {
            $ramCapturePath = Join-Path $script:scriptDirectory "RamCapture.exe"
        }
        
        if (Test-Path $ramCapturePath) {
            Write-CollectionLog "Found Belkasoft RAM Capture at: $ramCapturePath" "Green"
            Write-CollectionLog "Starting memory acquisition..." "Yellow"
            Write-CollectionLog "  This may take 5-30 minutes depending on RAM size" "Yellow"
            
            try {
                $dumpOutput = "$collectionDir\Memory\memory.mem"
                & $ramCapturePath $dumpOutput
                
                if (Test-Path $dumpOutput) {
                    $dumpSize = (Get-Item $dumpOutput).Length / 1GB
                    Write-CollectionLog "  Memory dump complete: $([math]::Round($dumpSize, 2)) GB" "Green"
                }
            } catch {
                Write-CollectionLog "  Memory dump failed: $_" "Red"
            }
        } else {
            Write-CollectionLog "ERROR: RamCapture64.exe not found!" "Red"
            Write-CollectionLog "  Download from: https://belkasoft.com/ram-capturer" "Yellow"
        }
    }
}

#==========================================
# ADDITIONAL SYSTEM INFORMATION
#==========================================

Write-CollectionLog "`n=== SYSTEM INFORMATION ===" "Cyan"

Invoke-SafeCommand "systeminfo" "$collectionDir\systeminfo.txt" "System Information"

# Replace WMIC with PowerShell
Write-CollectionLog "Collecting system information..." "Green"
try {
    Get-CimInstance -ClassName Win32_ComputerSystem | 
        Select-Object * | 
        Out-File "$collectionDir\systeminfo-detailed.txt"
    Write-CollectionLog "  Success: systeminfo-detailed.txt" "Gray"
} catch {
    Write-CollectionLog "  Error collecting system info: $_" "Yellow"
}

Write-CollectionLog "Collecting BIOS information..." "Green"
try {
    Get-CimInstance -ClassName Win32_BIOS | 
        Select-Object * | 
        Out-File "$collectionDir\bios-info.txt"
    Write-CollectionLog "  Success: bios-info.txt" "Gray"
} catch {
    Write-CollectionLog "  Error collecting BIOS info: $_" "Yellow"
}

Write-CollectionLog "Collecting CPU information..." "Green"
try {
    Get-CimInstance -ClassName Win32_Processor | 
        Select-Object * | 
        Out-File "$collectionDir\cpu-info.txt"
    Write-CollectionLog "  Success: cpu-info.txt" "Gray"
} catch {
    Write-CollectionLog "  Error collecting CPU info: $_" "Yellow"
}

Write-CollectionLog "Collecting memory information..." "Green"
try {
    Get-CimInstance -ClassName Win32_PhysicalMemory | 
        Select-Object * | 
        Out-File "$collectionDir\memory-info.txt"
    Write-CollectionLog "  Success: memory-info.txt" "Gray"
} catch {
    Write-CollectionLog "  Error collecting memory info: $_" "Yellow"
}

Write-CollectionLog "Collecting computer information..." "Green"
try {
    Get-ComputerInfo | Select-Object CsName, CsManufacturer, CsModel, CsDomain, 
        OsName, OsVersion, OsArchitecture, WindowsVersion |
        Export-Csv "$collectionDir\computer-info.csv" -NoTypeInformation
    Write-CollectionLog "  Success: computer-info.csv" "Gray"
} catch {
    Write-CollectionLog "  Error collecting computer info: $_" "Red"
}

try {
    Get-TimeZone | Select-Object Id, DisplayName, StandardName |
        Export-Csv "$collectionDir\timezone.csv" -NoTypeInformation
    Write-CollectionLog "  Success: timezone.csv" "Gray"
} catch {}

Write-CollectionLog "Collecting installed software..." "Green"
try {
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
        Where-Object { $_.DisplayName } |
        Export-Csv "$collectionDir\installed-software.csv" -NoTypeInformation
    Write-CollectionLog "  Success: installed-software.csv" "Gray"
} catch {
    Write-CollectionLog "  Error collecting installed software: $_" "Red"
}

Write-CollectionLog "Collecting antivirus information..." "Green"
try {
    Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct |
        Select-Object displayName, productState, pathToSignedProductExe |
        Export-Csv "$collectionDir\antivirus.csv" -NoTypeInformation
    Write-CollectionLog "  Success: antivirus.csv" "Gray"
} catch {
    Write-CollectionLog "  Error collecting antivirus info: $_" "Yellow"
}

# Hotfixes/Updates
Write-CollectionLog "Collecting installed updates..." "Green"
try {
    Get-HotFix | Select-Object Description, HotFixID, InstalledBy, InstalledOn | 
        Export-Csv "$collectionDir\installed-updates.csv" -NoTypeInformation
    Write-CollectionLog "  Success: installed-updates.csv" "Gray"
} catch {
    Write-CollectionLog "  Error collecting updates: $_" "Yellow"
}

# Environment variables
Write-CollectionLog "Collecting environment variables..." "Green"
try {
    Get-ChildItem Env: | Select-Object Name, Value | 
        Out-File "$collectionDir\environment-variables.txt"
    Write-CollectionLog "  Success: environment-variables.txt" "Gray"
} catch {
    Write-CollectionLog "  Error collecting environment variables: $_" "Yellow"
}

# Boot configuration
Invoke-SafeCommand "bcdedit /enum all" "$collectionDir\boot-configuration.txt" "Boot Configuration"

#==========================================
# COLLECTION COMPLETE
#==========================================

$endTime = Get-Date
$duration = $endTime - $startTime

$manifest = @"
========================================
COLLECTION MANIFEST
========================================
Collection Start: $startTime
Collection End: $endTime
Duration: $($duration.ToString())

Collected By: $env:USERNAME
System: $hostname
Output Directory: $collectionDir

Profile: $profile

ARTIFACTS COLLECTED:
$(foreach ($key in ($collect.Keys | Sort-Object)) { if ($collect[$key]) { "  [X] $key" } else { "  [ ] $key" } })

FILES COLLECTED:
$((Get-ChildItem $collectionDir -Recurse -File | Measure-Object).Count) total files
$('{0:N2}' -f ((Get-ChildItem $collectionDir -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB)) MB

NEXT STEPS:
1. Parse event logs: .\evtx_to_csv.ps1 -TriageDirectory "$collectionDir"
2. Compress collection: Compress-Archive -Path "$collectionDir" -DestinationPath "${collectionDir}.zip"
3. Calculate hash: Get-FileHash "${collectionDir}.zip" -Algorithm SHA256
4. Transfer securely to analyst workstation
5. Run analysis: python ransomware_investigator.py -d "$collectionDir"

ENHANCED ARTIFACTS (v2.0):
- ShimCache/AppCompatCache (execution history)
- BAM/DAM (precise execution timestamps)
- Windows Timeline (user activity)
- Office Recent Files
- Sticky Notes
- Recycle Bin metadata
- BITS transfer jobs
- Windows Defender quarantine
- Volume Shadow Copy information
- Drivers & loaded modules
- Open handles (if handle64.exe available)
- Certificate store
- NTFS artifacts (LogFile, Bitmap)
- IIS logs (if applicable)

========================================
"@

$manifest | Out-File "$collectionDir\MANIFEST.txt"

Write-Host "`n========================================" -ForegroundColor Green
Write-Host " COLLECTION COMPLETE!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

Write-Host "Duration: $($duration.ToString())" -ForegroundColor Cyan
Write-Host "Output: $collectionDir" -ForegroundColor Cyan
Write-Host "Files Collected: $((Get-ChildItem $collectionDir -Recurse -File | Measure-Object).Count)" -ForegroundColor Cyan
Write-Host "Total Size: $('{0:N2}' -f ((Get-ChildItem $collectionDir -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB)) MB`n" -ForegroundColor Cyan

Write-Host "Review MANIFEST.txt for details" -ForegroundColor Yellow
Write-Host "`nNext: Run evtx_to_csv.ps1 to parse event logs for investigation" -ForegroundColor Green
Write-Host ""

pause
