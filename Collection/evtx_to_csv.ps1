# EVTX to CSV Converter for DFIR Analysis
# Exports Windows Event Logs to CSV format for automated investigation
# Run this after triage collection or on the analysis workstation

#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [string]$TriageDirectory,
    
    [Parameter(Mandatory=$false)]
    [switch]$ParseAll
)

# If no directory specified, prompt for it
if (-not $TriageDirectory) {
    Write-Host "`n=== EVTX to CSV Converter ===" -ForegroundColor Cyan
    Write-Host "This script converts EVTX files to CSV for analysis`n" -ForegroundColor Yellow
    
    # Look for most recent triage directory
    $recentTriage = Get-ChildItem "C:\Triage_*" -Directory -ErrorAction SilentlyContinue | 
                    Sort-Object LastWriteTime -Descending | 
                    Select-Object -First 1
    
    if ($recentTriage) {
        Write-Host "Most recent triage found: $($recentTriage.FullName)" -ForegroundColor Green
        $useRecent = Read-Host "Use this directory? (Y/n)"
        
        if ($useRecent -ne 'n') {
            $TriageDirectory = $recentTriage.FullName
        } else {
            $TriageDirectory = Read-Host "Enter triage directory path"
        }
    } else {
        $TriageDirectory = Read-Host "Enter triage directory path"
    }
}

# Validate directory
if (-not (Test-Path $TriageDirectory)) {
    Write-Host "[!] Directory not found: $TriageDirectory" -ForegroundColor Red
    exit 1
}

$evtxDir = Join-Path $TriageDirectory "EventLogs"
if (-not (Test-Path $evtxDir)) {
    Write-Host "[!] EventLogs directory not found: $evtxDir" -ForegroundColor Red
    exit 1
}

# Create parsed logs directory
$parsedDir = Join-Path $TriageDirectory "EventLogs_Parsed"
New-Item -Path $parsedDir -ItemType Directory -Force | Out-Null

Write-Host "`n[*] Output directory: $parsedDir" -ForegroundColor Cyan
Write-Host "[*] Starting EVTX parsing...`n" -ForegroundColor Cyan

$startTime = Get-Date

# Define which event IDs to extract for targeted analysis
$criticalEvents = @{
    "Security" = @{
        "EventIDs" = @(
            1102,  # Audit log cleared
            4624,  # Successful logon
            4625,  # Failed logon
            4648,  # Logon with explicit credentials
            4672,  # Special privileges assigned
            4688,  # Process creation
            4698,  # Scheduled task created
            4720,  # User account created
            4722,  # User account enabled
            4724,  # Password reset attempt
            4728,  # User added to global group
            4732,  # User added to local group
            4756,  # User added to universal group
            5140,  # Network share accessed
            5145   # Network share access check
        )
        "Description" = "Critical security events"
    }
    "System" = @{
        "EventIDs" = @(
            7034,  # Service crashed
            7035,  # Service control sent
            7036,  # Service state changed
            7040,  # Service start type changed
            7045   # Service installed
        )
        "Description" = "Service-related events"
    }
    "PowerShell-Operational" = @{
        "EventIDs" = @(
            4103,  # Module logging
            4104   # Script block logging
        )
        "Description" = "PowerShell script execution"
    }
    "Sysmon" = @{
        "EventIDs" = @(
            1,     # Process creation
            3,     # Network connection
            7,     # Image loaded
            8,     # CreateRemoteThread
            10,    # Process access
            11,    # File creation
            12,    # Registry event (create/delete)
            13,    # Registry value set
            22     # DNS query
        )
        "Description" = "Sysmon telemetry"
    }
    "TaskScheduler" = @{
        "EventIDs" = @(
            106,   # Task registered
            140,   # Task updated
            141,   # Task deleted
            200,   # Task executed
            201    # Task completed
        )
        "Description" = "Scheduled task activity"
    }
    "Defender" = @{
        "EventIDs" = @(
            1006,  # Malware detected
            1116,  # Malware detected
            1117,  # Action taken
            5001,  # Real-time protection disabled
            5007   # Configuration changed
        )
        "Description" = "Windows Defender events"
    }
}

function Export-EvtxToCsv {
    param(
        [string]$EvtxFile,
        [string]$OutputCsv,
        [array]$EventIDs = $null,
        [string]$Description = ""
    )
    
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($EvtxFile)
    
    Write-Host "[*] Processing: $fileName" -ForegroundColor Green
    if ($Description) {
        Write-Host "    $Description" -ForegroundColor Gray
    }
    
    try {
        # Build filter string
        $filterXml = "<QueryList><Query><Select Path='file://$EvtxFile'>"
        
        if ($EventIDs -and $EventIDs.Count -gt 0) {
            $eventIdFilter = ($EventIDs | ForEach-Object { "EventID=$_" }) -join " or "
            $filterXml += "*[System[($eventIdFilter)]]"
            Write-Host "    Filtering for $(($EventIDs).Count) specific Event IDs..." -ForegroundColor Gray
        } else {
            $filterXml += "*"
            Write-Host "    Extracting ALL events (may be slow)..." -ForegroundColor Yellow
        }
        
        $filterXml += "</Select></Query></QueryList>"
        
        # Get events
        $events = Get-WinEvent -Path $EvtxFile -FilterXPath $filterXml -ErrorAction Stop
        
        if ($events.Count -eq 0) {
            Write-Host "    No matching events found" -ForegroundColor Yellow
            return 0
        }
        
        Write-Host "    Found $($events.Count) events, exporting to CSV..." -ForegroundColor Gray
        
        # Parse events to objects
        $parsedEvents = @()
        $progressCount = 0
        
        foreach ($event in $events) {
            $progressCount++
            
            # Show progress for large logs
            if ($progressCount % 1000 -eq 0) {
                Write-Host "    Progress: $progressCount / $($events.Count)" -ForegroundColor DarkGray
            }
            
            # Extract event data
            $eventObj = [PSCustomObject]@{
                TimeCreated = $event.TimeCreated
                EventID = $event.Id
                Level = $event.LevelDisplayName
                Provider = $event.ProviderName
                Computer = $event.MachineName
                UserId = $event.UserId
                ProcessId = $event.ProcessId
                ThreadId = $event.ThreadId
                Message = $event.Message
                EventData = ""
            }
            
            # Extract event data XML
            if ($event.Properties) {
                $eventData = @()
                foreach ($prop in $event.Properties) {
                    $eventData += $prop.Value
                }
                $eventObj.EventData = ($eventData -join " | ")
            }
            
            $parsedEvents += $eventObj
        }
        
        # Export to CSV
        $parsedEvents | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
        
        Write-Host "    SUCCESS: Exported $($parsedEvents.Count) events" -ForegroundColor Green
        return $parsedEvents.Count
        
    } catch {
        Write-Host "    ERROR: $_" -ForegroundColor Red
        return 0
    }
}

# Process event logs
$totalEvents = 0
$evtxFiles = Get-ChildItem -Path $evtxDir -Filter "*.evtx"

Write-Host "Found $($evtxFiles.Count) EVTX files to process`n" -ForegroundColor Cyan

foreach ($evtxFile in $evtxFiles) {
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($evtxFile.Name)
    $outputCsv = Join-Path $parsedDir "$fileName.csv"
    
    # Check if this is a critical log with specific event IDs
    $eventFilter = $null
    $description = ""
    
    foreach ($logName in $criticalEvents.Keys) {
        if ($fileName -like "*$logName*") {
            $eventFilter = $criticalEvents[$logName].EventIDs
            $description = $criticalEvents[$logName].Description
            break
        }
    }
    
    # If ParseAll is set, or no specific filter found, parse everything
    if ($ParseAll -or $null -eq $eventFilter) {
        $eventFilter = $null
    }
    
    $count = Export-EvtxToCsv -EvtxFile $evtxFile.FullName -OutputCsv $outputCsv -EventIDs $eventFilter -Description $description
    $totalEvents += $count
    Write-Host ""
}

$endTime = Get-Date
$duration = $endTime - $startTime

# Create summary - Build it piece by piece to avoid here-string issues
$summary = "========================================`n"
$summary += "EVTX PARSING SUMMARY`n"
$summary += "========================================`n"
$summary += "Start Time: $startTime`n"
$summary += "End Time: $endTime`n"
$summary += "Duration: $($duration.ToString())`n`n"
$summary += "EVTX Files Processed: $($evtxFiles.Count)`n"
$summary += "Total Events Exported: $totalEvents`n`n"
$summary += "Output Directory: $parsedDir`n`n"
$summary += "========================================`n"
$summary += "CRITICAL EVENT FILTERS APPLIED`n"
$summary += "========================================`n"

foreach ($logName in $criticalEvents.Keys) {
    $summary += "$logName - $($criticalEvents[$logName].Description)`n"
    $summary += "  Event IDs: $($criticalEvents[$logName].EventIDs -join ', ')`n"
}

$summary += "`n========================================`n"
$summary += "NEXT STEPS`n"
$summary += "========================================`n"
$summary += "1. Run the investigation tool:`n"
$summary += "   python ransomware_investigator.py -d `"$TriageDirectory`"`n`n"
$summary += "2. CSVs can also be analyzed in:`n"
$summary += "   - Excel / Timeline Explorer`n"
$summary += "   - Splunk / ELK Stack`n"
$summary += "   - Custom scripts`n`n"
$summary += "3. To parse ALL events (not just critical):`n"
$summary += "   .\evtx_to_csv.ps1 -TriageDirectory `"$TriageDirectory`" -ParseAll`n`n"
$summary += "========================================`n"

$summary | Out-File (Join-Path $parsedDir "PARSING_SUMMARY.txt")

Write-Host $summary -ForegroundColor Cyan

Write-Host "`n[+] EVTX parsing complete!" -ForegroundColor Green
Write-Host "[+] Parsed CSVs saved to: $parsedDir" -ForegroundColor Green
Write-Host "`nYou can now run the investigation tool." -ForegroundColor Yellow
