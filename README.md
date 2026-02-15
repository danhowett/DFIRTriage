# Complete DFIR Triage & Investigation Toolkit

A comprehensive, automated digital forensics and incident response (DFIR) toolkit for detecting financially motivated threat actors including ransomware, credential theft, and data exfiltration.

Before you start, download the following and place in the collection folder https://belkasoft.com/ram-capturer (RamCapture64) https://github.com/jschicht/RawCopy (RawCopy64)

**Complete workflow from evidence collection to automated investigation with interactive reporting.**

---

## 📦 **Toolkit Components**

### **Collection Phase**
1. **`triage-collection.ps1`** - Live system artifact collection (35+ artifact types)
2. **`evtx_to_csv.ps1`** - Event log parser (EVTX to CSV conversion)
3. **`RawCopy64.exe`** - For locked files (MFT, USN, AmCache, browser DBs) *(optional but recommended)*

### **Analysis Phase**
4. **`ransomware_investigator.py`** - Automated investigation tool (16 analysis modules)
5. **`threat_indicators.json`** - Configurable IOC database (100+ indicators)
6. **`indicator_manager.py`** - IOC management utility

---

## 🚀 **Quick Start Guide**

### **Phase 1: Collect Artifacts (On Compromised System)**

```powershell
# Run as Administrator
.\triage-collection.ps1
```

**Select Profile:**
- **Quick Triage** (2-5 min): Essential artifacts for rapid assessment
- **Standard** (5-15 min): Comprehensive collection 
- **Comprehensive** (15-30 min): Everything including MFT/USN/Memory ⭐ **Recommended**

**Output:** `C:\Triage_HOSTNAME_YYYYMMDD_HHMMSS\`

### **Phase 2: Parse Event Logs**

```powershell
# Parse EVTX files to CSV for analysis
.\evtx_to_csv.ps1 -TriageDirectory "C:\Triage_HOSTNAME_YYYYMMDD_HHMMSS"

# Or parse ALL events (slower but comprehensive)
.\evtx_to_csv.ps1 -TriageDirectory "C:\Triage_HOSTNAME_YYYYMMDD_HHMMSS" -ParseAll
```

**Output:** `C:\Triage_HOSTNAME_YYYYMMDD_HHMMSS\EventLogs_Parsed\`

### **Phase 3: Run Automated Investigation**

```bash
# On analysis workstation
python ransomware_investigator.py -d "C:\Triage_HOSTNAME_YYYYMMDD_HHMMSS"
```

**Output:** `C:\Triage_HOSTNAME_YYYYMMDD_HHMMSS\Analysis_Output\`

### **Phase 4: Review Interactive Reports**

```powershell
# Open interactive HTML report with modern dashboard
start C:\Triage_HOSTNAME_YYYYMMDD_HHMMSS\Analysis_Output\Investigation_Report.html

# Or review executive summary
notepad C:\Triage_HOSTNAME_YYYYMMDD_HHMMSS\Analysis_Output\Executive_Summary.txt
```

---

## 📋 **Collection Artifacts**

### **Core Artifacts (All Profiles)**
- Event Logs (Security, System, Application, PowerShell, Sysmon, Defender, etc.)
- Registry Hives (SAM, SECURITY, SOFTWARE, SYSTEM, UsrClass.dat)
- Persistence (Run keys, scheduled tasks, services, WMI subscriptions)
- Network (connections, DNS cache, firewall rules, shares, WiFi profiles)
- Processes & Services (with command lines, PIDs, parent processes)
- PowerShell artifacts (history, transcripts, logging config)

### **Enhanced Artifacts (Standard/Comprehensive)**
- **ShimCache/AppCompatCache** - Program execution history
- **BAM/DAM** - Background Activity Moderator (precise execution timestamps)
- **Windows Timeline** - ActivitiesCache.db (user activity tracking)
- **Office Recent Files** - Document access patterns
- **Sticky Notes** - plum.sqlite (may contain credentials!)
- **Recycle Bin Metadata** - $I files for deletion tracking
- **BITS Transfer Jobs** - Active and historical (C2 communication)
- **Windows Defender Quarantine** - Detected malware samples
- **Volume Shadow Copies** - Status (ransomware indicator if deleted)
- **Drivers & Modules** - Loaded drivers (rootkit detection)
- **Open Handles** - Process behavior (requires handle64.exe)
- **Certificate Store** - Installed certificates (rogue CA detection)
- **Browser artifacts** - History, cookies, downloads (Chrome, Edge, Firefox, IE)
- **Prefetch files** - Program execution evidence
- **File system** - LNK files, Jump Lists, Recent files, USB history
- **AmCache** - Installation and execution tracking
- **SRUM** - System Resource Usage Monitor (network activity)

### **Advanced Artifacts (Comprehensive Only)**
- **MFT** - Master File Table (requires RawCopy)
- **USN Journal** - Change journal (requires RawCopy)
- **$LogFile** - NTFS transaction log (requires RawCopy)
- **$Bitmap** - Cluster allocation bitmap (requires RawCopy)
- **Memory Dump** - Full RAM capture (requires Belkasoft RamCapture64)
- **IIS Logs** - Web server logs (last 30 days, if applicable)

---

## 🔍 **Analysis Modules**

The automated investigation tool includes 16 comprehensive analysis modules:

### **Evidence Analysis**
1. **Event Log Analysis** - Security, PowerShell, Sysmon, Defender events
2. **PowerShell History** - Malicious commands, encoded payloads, credential dumping
3. **Process Execution** - Suspicious tools, credential theft, lateral movement
4. **ShimCache/BAM/DAM Analysis** - Execution timeline with precise timestamps
5. **Prefetch Analysis** - Program execution evidence via prefetch files

### **Persistence Detection**
6. **Persistence Mechanisms** - Registry run keys, startup folders
7. **Scheduled Tasks** - Deep analysis for malicious tasks, high-frequency execution
8. **Services** - Service-based persistence, disabled security services
9. **Drivers** - Unsigned drivers, rootkit keyword detection

### **Network & Communication**
10. **Network Activity** - C2 ports, suspicious connections, DNS queries
11. **Browser Artifacts** - Malicious URLs, suspicious domains

### **System Analysis**
12. **File System** - Ransomware extensions, ransom notes, data staging
13. **User Accounts** - Suspicious admins, recently created accounts
14. **Volume Shadow Copies** - Ransomware detection (deleted shadows)
15. **Windows Defender** - Quarantine analysis, evasion attempts
16. **Environment Variables** - Suspicious PATH modifications, unusual variables

---

## 🎯 **Threat Detection Capabilities**

### **Ransomware Indicators**
- Shadow copy deletion (`vssadmin delete shadows`) - **CRITICAL priority**
- Backup deletion (`wbadmin delete catalog`)
- Boot configuration tampering (`bcdedit`)
- Encrypted file extensions (.locked, .encrypted, .ryuk, .conti, etc.)
- Ransom notes (README.txt, HOW_TO_DECRYPT.txt, etc.)
- Event log clearing (`wevtutil cl`)
- Volume Shadow Copy status analysis

### **Credential Theft**
- Mimikatz execution (ShimCache, BAM, Prefetch, Event logs)
- LSASS process access (Sysmon Event 10)
- Credential dumping commands (PowerShell, registry)
- ProcDump on lsass.exe
- Sticky Notes credential exposure

### **Lateral Movement**
- PsExec execution (ShimCache, Prefetch, Event logs)
- WMI/WMIC remote execution
- Explicit credential logon (Event 4648)
- Network share access (Event 5140/5145)
- Remote desktop connections

### **Persistence**
- Registry Run keys in suspicious locations
- Malicious scheduled tasks
- Suspicious services
- WMI event subscriptions
- Startup folder modifications
- Malicious drivers

### **Command & Control**
- Connections to known C2 ports
- Cobalt Strike/Meterpreter indicators
- BITS transfer jobs
- Suspicious high-port connections
- DNS queries to malicious domains

### **Data Exfiltration**
- Large archive files in suspicious locations
- Cloud storage tools (Rclone, Mega, etc.)
- File compression utilities (7z, WinRAR)
- Office document access patterns
- Deleted file evidence in Recycle Bin

### **Defense Evasion**
- Windows Defender tampering/disabling
- Process injection (Sysmon Event 8)
- Living-off-the-land binaries (LOLBins)
- Encoded PowerShell commands
- Defender Quarantine evasion

### **Rootkit Detection**
- Unsigned drivers
- Suspicious driver names (rootkit, hack, inject, hide)
- Driver load timing anomalies

---

## 📊 **Output Reports**

### **1. Investigation_Report.html** 📈
**Modern Interactive Dashboard with:**
- 🔍 **Real-time search** - Find specific indicators instantly
- 🎯 **One-click filtering** - Show Critical/High/Medium/Low findings
- 📱 Responsive design (works on desktop, tablet, mobile)
- 🎨 Color-coded severity badges (Red=Critical, Orange=High, Yellow=Medium, Green=Low)
- **Click to expand/collapse** - Clean overview, detailed on demand
- **Auto-expand Critical** - Critical threats shown immediately
- **ALL evidence preserved** - No truncation (full context!)
- **Smooth scrolling** - Handle 1000+ evidence items

**Best for:** Initial review, presentations, sharing with team

### **2. Findings.csv** 📊
Excel-friendly spreadsheet with:
- Priority Score (0-100)
- Severity Level
- Category
- Title & Description
- Evidence Count
- **Full Evidence** (all items, newline-separated)
- Recommendations

**Best for:** Filtering, pivot tables, tracking, metrics

### **3. Investigation_Data.json** 🔧
Machine-readable format with:
- Complete metadata
- All findings with full evidence arrays
- Timestamps
- Statistics

**Best for:** SIEM integration, automation, custom dashboards

### **4. Executive_Summary.txt** 📄
Management-friendly text report:
- Threat assessment overview
- Critical findings requiring immediate action
- High priority findings
- Recommended next steps
- Manual review checklist

**Best for:** Leadership briefings, initial assessment

### **5. Evidence/ Directory** 📁
Individual text files per finding:
- `01_CRITICAL_Ransomware_Indicators.txt`
- `02_HIGH_Credential_Theft_Detected.txt`
- Complete numbered evidence lists
- Investigation notes template
- Next steps checklist

**Best for:** Case documentation, incident tickets, detailed investigation

---

## 💡 **Evidence Context Examples**

The toolkit provides rich contextual information for comprehensive analysis:

### **PowerShell Commands**
```
[shadow_copy_deletion] User: admin | Line 42 | 
Command: vssadmin delete shadows /all /quiet
```

### **Process Execution**
```
[credential_theft] Process: mimikatz.exe | PID: 4892 | PPID: 1234 | 
Path: C:\Temp\mimikatz.exe | 
CommandLine: mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"
```

### **ShimCache/BAM Execution**
```
[ShimCache-credential_theft] mimikatz.exe | Context: 
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\mimikatz.exe
TimeStamp: 0x1D9A4B2C3E5F678
```

### **Event Logs**
```
[critical] EventID 4688: Process Created | Time: 2025-02-13 15:30:45 | 
User: DOMAIN\admin | Computer: WORKSTATION01 | 
Message: Process Name: C:\Windows\System32\vssadmin.exe | 
Creator Process: C:\Temp\malware.exe
```

### **Sysmon Events**
```
[Sysmon LSASS Access] Potential credential dumping | Time: 2025-02-13 15:30:45 | 
Details: SourceImage: C:\Temp\procdump64.exe | 
TargetImage: C:\Windows\System32\lsass.exe | 
GrantedAccess: 0x1010
```

### **Volume Shadow Copies**
```
[CRITICAL] No shadow copies found on system - possible ransomware deleted them
Command likely used: vssadmin delete shadows /all /quiet
```

---

## ⚙️ **Installation & Requirements**

### **Collection Scripts (PowerShell)**
**Requirements:**
- Windows 7 or later
- PowerShell 5.1+
- Administrator privileges

**Optional Tools (Recommended):**
- **RawCopy64.exe** - For locked files (MFT, USN, AmCache, SRUDB, browsers)
  - Download: https://github.com/jschicht/RawCopy
  - **Place in same folder as collection script**
- **Belkasoft RamCapture64.exe** - For memory dumps
  - Download: https://belkasoft.com/ram-capturer
- **handle64.exe** - For open handles
  - Download: https://live.sysinternals.com/handle64.exe

**Setup:**
```powershell
# No installation needed - just download and run
.\triage-collection.ps1
```

### **Analysis Tool (Python)**
**Requirements:**
- Python 3.7 or later
- **No external packages** (uses standard library only)

**Setup:**
```bash
# No pip install needed - pure Python!
python ransomware_investigator.py -d <path>
```

---

## 🎓 **Detailed Usage**

### **Collection Script**

```powershell
# Interactive mode with profile selection
.\triage-collection.ps1
```

**The script will:**
1. Check for Administrator privileges
2. Show collection profile options (Quick/Standard/Comprehensive)
3. Display artifacts to be collected
4. Ask for confirmation
5. Collect artifacts with progress indicators
6. Automatically use RawCopy for locked files
7. Create manifest and collection log
8. Display summary and next steps

**Key Features:**
- Automatic RawCopy fallback for locked files (browsers, AmCache, SRUDB)
- Comprehensive error logging
- Progress indicators for each artifact type
- Detailed manifest of collected files

### **Event Log Parser**

```powershell
# Parse with critical events only (recommended - faster)
.\evtx_to_csv.ps1 -TriageDirectory "C:\Triage_HOST_DATE"

# Parse ALL events (comprehensive but slower)
.\evtx_to_csv.ps1 -TriageDirectory "C:\Triage_HOST_DATE" -ParseAll

# Auto-detect most recent triage (interactive)
.\evtx_to_csv.ps1
```

**Critical Event IDs Extracted:**
- **Security:** 1102, 4624, 4625, 4648, 4672, 4688, 4698, 4720, 4722, 4724, 4728, 4732, 4756, 5140, 5145
- **System:** 7034, 7035, 7036, 7040, 7045
- **PowerShell:** 4103, 4104
- **Sysmon:** 1, 3, 7, 8, 10, 11, 12, 13, 22
- **Defender:** 1006, 1116, 1117, 5001, 5007
- **Task Scheduler:** 106, 140, 141, 200, 201

### **Investigation Tool**

```bash
# Basic usage
python ransomware_investigator.py -d "C:\Triage_HOST_DATE"

# Use custom threat indicators
python ransomware_investigator.py -d "C:\Triage_HOST_DATE" -i custom_indicators.json

# Help
python ransomware_investigator.py --help
```

**Analysis Output:**
```
========================================
STARTING ENHANCED DFIR INVESTIGATION
========================================

[*] Analyzing event logs...
[*] Analyzing PowerShell history...
[*] Analyzing process execution...
[*] Analyzing persistence mechanisms...
[*] Analyzing network activity...
[*] Analyzing file system...
[*] Analyzing user accounts...
[*] Analyzing browser artifacts...

[*] Running enhanced analysis modules...
[*] Analyzing ShimCache/BAM/DAM...
[!] Found 12 suspicious execution entries
[*] Analyzing prefetch files...
[!] Found 8 suspicious prefetch files
[*] Analyzing scheduled tasks...
[!] Found 3 suspicious scheduled tasks
[*] Analyzing services...
[+] No suspicious services detected
[*] Analyzing Volume Shadow Copies...
[!] VSS analysis complete: CRITICAL
[*] Analyzing Windows Defender detections...
[!] Found Defender detections
[*] Analyzing drivers...
[!] Found 2 suspicious drivers
[*] Analyzing environment variables...
[+] No suspicious environment variables

========================================
INVESTIGATION COMPLETE
========================================

Total Findings: 24
  CRITICAL: 3
  HIGH: 11
  MEDIUM: 7
  LOW: 3

Review reports in: Analysis_Output
```

### **IOC Management**

```bash
# List all indicator categories
python indicator_manager.py --list-categories

# Add a ransomware extension
python indicator_manager.py --add -c ransomware_extensions -v .newvariant

# Add a credential theft tool
python indicator_manager.py --add -c suspicious_processes -s credential_theft -v newtool.exe

# Search for an indicator
python indicator_manager.py --search mimikatz

# Import indicators from file
python indicator_manager.py --import iocs.txt -c ransomware_extensions

# Validate configuration
python indicator_manager.py --validate
```

---

## 🔧 **Customizing Threat Indicators**

All threat indicators are stored in `threat_indicators.json`. Update this file to add organization-specific IOCs without modifying code.

### **Available Indicator Categories:**
- `ransomware_extensions` - File extensions (40+)
- `ransomware_notes` - Ransom note filenames
- `suspicious_processes` - Malicious executables (100+)
  - `credential_theft`, `lateral_movement`, `c2_frameworks`
  - `ransomware_tools`, `network_scanners`, `data_exfiltration`
- `suspicious_commands` - Command patterns (50+)
  - `shadow_copy_deletion`, `boot_configuration`, `event_log_clearing`
  - `defender_tampering`, `credential_dumping`, `encoded_commands`
- `suspicious_registry_keys` - Persistence locations
- `suspicious_file_locations` - Common malware paths
- `living_off_the_land_binaries` - LOLBins
- `network_indicators` - C2 ports, malicious domains
- `event_ids` - Windows Event IDs to flag
- `prefetch_indicators` - Suspicious prefetch files
- `suspicious_scheduled_tasks` - Task names/paths
- `suspicious_services` - Service names

### **Example: Adding Custom Indicators**

```json
{
  "ransomware_extensions": [
    ".locked",
    ".encrypted",
    ".yourvariant"
  ],
  "suspicious_processes": {
    "credential_theft": [
      "mimikatz.exe",
      "yourtool.exe"
    ]
  },
  "suspicious_commands": {
    "shadow_copy_deletion": [
      "vssadmin delete shadows",
      "wmic shadowcopy delete"
    ]
  }
}
```

---

## 📈 **Priority Scoring System**

Findings are automatically prioritized from 0-100 based on severity, evidence count, and matched indicators:

**Base Scores:**
- **CRITICAL:** 90 (ransomware, credential dumping, active exploitation)
- **HIGH:** 70 (persistence, lateral movement, suspicious tools)
- **MEDIUM:** 50 (policy violations, misconfigurations)
- **LOW:** 30 (informational findings)
- **INFO:** 10 (baseline information)

**Bonuses:**
- **+2 per evidence item** (max +10)
- **+5 per matched indicator** (max +20)

**Example:**
```
Finding: "Volume Shadow Copies Deleted"
Base: 90 (CRITICAL)
Evidence: 5 items = +10
Indicators: 2 matched = +10
Total Priority: 100/100 (Immediate investigation required)
```

---

## 💼 **Use Cases & Workflows**

### **Incident Response**

```
1. Isolate compromised system (network isolation)
2. Run triage collection (Standard or Comprehensive profile)
3. Transfer collection to analysis workstation (encrypted)
4. Parse event logs (evtx_to_csv.ps1)
5. Run automated investigation
6. Review Executive Summary for critical findings
7. Open HTML report for detailed analysis
8. Use Evidence/ files for incident documentation
9. Implement containment based on findings
10. Document in ticketing system
```

### **Threat Hunting**

```
1. Run Quick Triage on target systems
2. Parse event logs
3. Run investigation with custom IOCs
4. Review findings for abnormal activity
5. Use ShimCache/BAM/DAM for execution timeline
6. Correlate across multiple systems
7. Update threat indicators based on findings
8. Create detection rules for SIEM
```

### **Ransomware Investigation**

```
1. Run Comprehensive Collection (including memory)
2. Parse event logs (use -ParseAll for complete data)
3. Run investigation
4. Check VSS analysis (critical indicator!)
5. Review ShimCache/BAM/DAM for ransomware execution
6. Check Defender quarantine for samples
7. Analyze PowerShell history for commands
8. Review network activity for C2
9. Document in Evidence/ files
10. Attempt recovery if VSS available
```

### **Forensic Analysis**

```
1. Run Comprehensive Collection
2. Parse all artifacts
3. Run investigation with all indicators
4. Export findings to JSON for timeline tools
5. Use Evidence/ files for report writing
6. Correlate with other forensic tools (Volatility, Timeline Explorer)
7. Build complete attack timeline
```

---

## 🎯 **Best Practices**

### **For Incident Responders**

✅ **Evidence Preservation**
- Create forensic images before collection
- Hash collection archives (SHA256)
- Document chain of custody
- Note collection time and person

✅ **Collection Strategy**
- **Quick:** Active incident, time-critical
- **Standard:** Most investigations ⭐ Recommended
- **Comprehensive:** Malware analysis, deep forensics

✅ **Analysis Workflow**
1. Parse logs immediately after collection
2. Run enhanced investigation tool
3. Review Executive Summary first
4. Focus on CRITICAL/HIGH findings
5. Use Evidence/ files for documentation
6. Cross-reference with SIEM/EDR

✅ **Documentation**
- Use Evidence file templates
- Track investigation in checklists
- Attach findings to tickets
- Maintain investigation notes

### **For SOC Analysts**

✅ **Triage Priority**
1. Review Executive_Summary.txt
2. Check VSS status (ransomware indicator)
3. Review Critical findings in HTML report
4. Use search/filter for specific IOCs
5. Escalate as needed

✅ **Use the Right Report**
- **Executive Summary** → Quick assessment
- **HTML Report** → Detailed review with search/filter
- **CSV** → Filtering, metrics, pivot tables
- **JSON** → SIEM integration
- **Evidence files** → Ticket documentation

✅ **SIEM Integration**
- Import Investigation_Data.json
- Create alerts for high-priority indicators
- Correlate with other log sources
- Build dashboards from findings

---

## 🔒 **Security Considerations**

### **Collection**
- Runs as Administrator (required for many artifacts)
- Read-only collection (does not modify system)
- Some artifacts may be locked (RawCopy handles automatically)
- Creates files in C:\Triage_* (ensure adequate disk space)

### **Analysis**
- Analyzes local files only (no network activity)
- No external dependencies (reduces supply chain risk)
- Does not execute collected binaries
- Safe to run on analysis workstation

### **Data Handling**
- Collections contain sensitive information (credentials, PII)
- Encrypt during transfer (BitLocker, VeraCrypt)
- Store securely (encrypted storage)
- Follow data retention policies
- Sanitize before sharing externally

---

## 🐛 **Troubleshooting**

### **Collection Issues**

**"This script must be run as Administrator"**
```powershell
# Right-click PowerShell → "Run as Administrator"
```

**"Execution policy" error**
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\triage-collection.ps1
```

**RawCopy not working for locked files**
- Verify RawCopy64.exe is in same folder as script
- Check collection.log for specific errors
- Run test_rawcopy.ps1 to verify RawCopy works
- Ensure running as Administrator

**MFT/USN not collecting**
- Ensure RawCopy64.exe is present
- Select Comprehensive profile
- Check collection.log for errors
- Verify adequate disk space

### **Parsing Issues**

**"EVTX file not found"**
- Ensure EventLogs directory exists in triage collection
- Check collection completed successfully
- Verify EVTX files are present

**"No matching events found"**
- Normal if log doesn't contain critical Event IDs
- Use `-ParseAll` for comprehensive parsing
- Verify log files have content

**Parsing is slow**
- Normal for large logs with `-ParseAll`
- Use default (critical events only) for speed
- Consider parsing on analysis workstation

### **Analysis Issues**

**"Triage directory not found"**
- Use full path, not relative
- Check directory name spelling
- Ensure directory exists

**"Parsed event logs not found"**
- Run evtx_to_csv.ps1 first
- Check EventLogs_Parsed directory exists
- Verify CSV files were created

**HTML report doesn't look modern**
- Ensure using ransomware_investigator.py
- Delete old Investigation_Report.html
- Re-run analysis
- Hard refresh browser (Ctrl+F5)

**No findings detected**
- System may be clean (good news!)
- Verify IOCs are loaded (threat_indicators.json present)
- Check collection completed successfully
- Review raw artifacts manually

**Python version errors**
- Ensure Python 3.7 or later
- Try `python3` instead of `python`
- On Windows: `py -3 ransomware_investigator.py -d <path>`

---

## 🆘 **Common Questions**

**Q: Can I run collection on a live system?**  
A: Yes, designed for live collection. RawCopy handles locked files automatically.

**Q: How much disk space needed?**  
A: Quick: ~100MB, Standard: ~500MB-1GB, Comprehensive: 2-15GB (varies by system)

**Q: What if RawCopy isn't available?**  
A: Script will still collect unlocked files and create notes for locked files that couldn't be copied.

**Q: Does this replace professional forensic tools?**  
A: No, it complements them. Use alongside Timeline Explorer, Volatility, KAPE, Eric Zimmerman tools, etc.

**Q: Can I customize what gets collected?**  
A: Yes, use Custom profile during collection or modify the script directly.

**Q: How do I update IOCs?**  
A: Edit `threat_indicators.json` manually or use `indicator_manager.py` for easier management.

**Q: Does it work on Linux/Mac?**  
A: Collection: Windows only. Analysis: Any OS with Python 3.7+

**Q: Is internet access required?**  
A: No, fully offline capable. All tools run locally.

**Q: How often should I update threat indicators?**  
A: Regularly - subscribe to threat intel feeds and update after each incident to improve future detections.

---

## 📜 **License**

MIT License - See LICENSE file

---

## 🙏 **Credits**

Created by Danny Howett and Claude.ai - with thanks to https://github.com/jschicht/RawCopy for RawCopy and Belkasoft https://belkasoft.com/ram-capturer for Belkasoft Ram Capturer

---

## 🎯 **Quick Reference Card**

### **Files You Need:**
```
✓ triage-collection.ps1       (Collection)
✓ evtx_to_csv.ps1                      (Event log parsing)
✓ ransomware_investigator.py  (Analysis)
✓ threat_indicators.json               (IOC database)
✓ RawCopy64.exe                        (For locked files - optional)
```

### **Complete Workflow:**
```
1. Collect → .\triage-collection.ps1
2. Parse   → .\evtx_to_csv.ps1 -TriageDirectory <path>
3. Analyze → python ransomware_investigator.py -d <path>
4. Review  → Open Investigation_Report.html
```

### **Key Features:**
```
Collection: 35+ artifacts, Auto RawCopy fallback, MFT/USN extraction
Analysis:   16 modules, Full evidence context, Priority scoring
Reports:    Interactive HTML, Search/Filter, Multiple formats
```

### **Typical Results:**
```
Collection Time: 5-30 minutes (depending on profile)
Analysis Time:   30-90 seconds
Findings:        10-30 detections (comprehensive analysis)
Reports:         5 formats (HTML, CSV, JSON, TXT, Evidence files)
```

---

**Remember**: This toolkit augments human analysis - always verify findings and follow your organization's incident response procedures. Automated tools should guide investigation, not replace critical thinking.

**Stay safe, hunt threats, and happy investigating! 🔍🛡️**
