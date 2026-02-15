#!/usr/bin/env python3
"""
Automated DFIR Investigation Tool for Financially Motivated Threat Actors
Analyzes triage collections for ransomware, data exfiltration, and credential theft indicators

Designed to work with the PowerShell triage collection script
Focuses on automated analysis without relying on third-party DFIR tools

Author: DFIR Automation Framework  
Version: 2.0
"""

import os
import re
import csv
import json
import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Any, Optional
import argparse
import sys


class Finding:
    """Represents a single investigation finding with priority scoring"""
    
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"
    SEVERITY_INFO = "INFO"
    
    def __init__(self, category: str, severity: str, title: str, description: str, 
                 evidence: List[str], priority_score: int, recommendations: List[str]):
        self.category = category
        self.severity = severity
        self.title = title
        self.description = description
        self.evidence = evidence
        self.priority_score = priority_score
        self.recommendations = recommendations
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict:
        return {
            'category': self.category,
            'severity': self.severity,
            'priority_score': self.priority_score,
            'title': self.title,
            'description': self.description,
            'evidence_count': len(self.evidence),
            'evidence': self.evidence,  # Include ALL evidence in JSON
            'recommendations': self.recommendations,
            'timestamp': self.timestamp.isoformat()
        }


class ThreatIndicators:
    """Loads and manages threat indicators from JSON configuration"""
    
    def __init__(self, config_path: str = "threat_indicators.json"):
        self.config_path = Path(config_path)
        self.indicators = {}
        self.load_indicators()
    
    def load_indicators(self):
        """Load threat indicators from JSON file"""
        if not self.config_path.exists():
            print(f"[!] Warning: Threat indicators file not found: {self.config_path}")
            print(f"[*] Creating default configuration...")
            self.create_default_config()
        
        try:
            with open(self.config_path, 'r') as f:
                self.indicators = json.load(f)
            print(f"[+] Loaded threat indicators from {self.config_path}")
        except Exception as e:
            print(f"[!] Error loading threat indicators: {e}")
            self.indicators = {}
    
    def create_default_config(self):
        """Create a minimal default configuration if file doesn't exist"""
        default_config = {
            "ransomware_extensions": [".locked", ".encrypted", ".crypto"],
            "suspicious_processes": {"credential_theft": ["mimikatz.exe"]},
            "suspicious_commands": {"shadow_copy_deletion": ["vssadmin delete shadows"]},
            "event_ids": {"critical": {"4720": "User Account Created"}}
        }
        with open(self.config_path, 'w') as f:
            json.dump(default_config, f, indent=2)
    
    def get(self, key: str, default=None):
        """Get indicator by key"""
        return self.indicators.get(key, default)


class ThreatHunter:
    """Main threat hunting and analysis engine"""
    
    def __init__(self, triage_dir: str, indicators_file: str = "threat_indicators.json"):
        self.triage_dir = Path(triage_dir)
        self.findings = []
        self.stats = defaultdict(int)
        
        # Load threat indicators from JSON
        self.indicators = ThreatIndicators(indicators_file)
        
        # Initialize output directory
        self.output_dir = self.triage_dir / "Analysis_Output"
        self.output_dir.mkdir(exist_ok=True)
        
        print(f"\n[*] Automated DFIR Investigation Tool")
        print(f"[*] Target: {self.triage_dir}")
        print(f"[*] Output: {self.output_dir}\n")
    
    def add_finding(self, category: str, severity: str, title: str, 
                   description: str, evidence: List[str], 
                   priority_score: int, recommendations: List[str]):
        """Add a new finding to the results"""
        finding = Finding(category, severity, title, description, 
                         evidence, priority_score, recommendations)
        self.findings.append(finding)
        self.stats[f"{severity}_findings"] += 1
    
    def calculate_priority_score(self, severity: str, evidence_count: int, 
                                indicators_matched: int) -> int:
        """
        Calculate priority score (0-100) based on severity and evidence
        Higher score = higher priority for investigation
        """
        base_scores = {
            Finding.SEVERITY_CRITICAL: 90,
            Finding.SEVERITY_HIGH: 70,
            Finding.SEVERITY_MEDIUM: 50,
            Finding.SEVERITY_LOW: 30,
            Finding.SEVERITY_INFO: 10
        }
        
        base = base_scores.get(severity, 30)
        evidence_bonus = min(evidence_count * 2, 10)
        indicator_bonus = min(indicators_matched * 5, 20)
        
        return min(base + evidence_bonus + indicator_bonus, 100)
    
    def analyze_powershell_history(self):
        """Analyze PowerShell console history for suspicious commands"""
        print("[*] Analyzing PowerShell history...")
        
        ps_dir = self.triage_dir / "PowerShell"
        if not ps_dir.exists():
            print("[ ] PowerShell artifacts not found")
            return
        
        suspicious_commands = self.indicators.get('suspicious_commands', {})
        evidence = []
        matched_patterns = set()
        
        for history_file in ps_dir.glob("ConsoleHost_history_*.txt"):
            username = history_file.stem.replace("ConsoleHost_history_", "")
            
            try:
                with open(history_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    
                for line_num, line in enumerate(lines, 1):
                    line = line.strip()
                    
                    # Check all command categories
                    for category, patterns in suspicious_commands.items():
                        for pattern in patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                # Include full command for context
                                evidence.append(f"[{category}] User: {username} | Line {line_num} | Command: {line}")
                                matched_patterns.add(f"{category}: {pattern}")
            
            except Exception as e:
                print(f"[!] Error reading {history_file}: {e}")
        
        if evidence:
            severity = Finding.SEVERITY_CRITICAL if any('delete shadows' in e.lower() or 'mimikatz' in e.lower() for e in evidence) else Finding.SEVERITY_HIGH
            priority = self.calculate_priority_score(severity, len(evidence), len(matched_patterns))
            
            self.add_finding(
                category="PowerShell Execution",
                severity=severity,
                title="Suspicious PowerShell Commands Detected",
                description=f"Found {len(evidence)} suspicious PowerShell commands matching {len(matched_patterns)} known malicious patterns",
                evidence=evidence,
                priority_score=priority,
                recommendations=[
                    "Review PowerShell event logs (EventID 4104) for full script blocks",
                    "Check for encoded commands and base64 payloads",
                    "Correlate with process creation events",
                    "Investigate user accounts executing these commands"
                ]
            )
            print(f"[!] Found {len(evidence)} suspicious PowerShell commands")
        else:
            print("[+] No suspicious PowerShell commands found")
    
    def analyze_process_execution(self):
        """Analyze process execution for suspicious tools and binaries"""
        print("[*] Analyzing process execution...")
        
        process_dir = self.triage_dir / "ProcessInfo"
        if not process_dir.exists():
            print("[ ] Process information not found")
            return
        
        suspicious_procs = self.indicators.get('suspicious_processes', {})
        lolbins = self.indicators.get('living_off_the_land_binaries', [])
        
        evidence = []
        categories_matched = set()
        
        # Analyze process command lines CSV
        commandlines_file = process_dir / "process-commandlines.csv"
        if commandlines_file.exists():
            try:
                with open(commandlines_file, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        process_name = row.get('Name', '').lower()
                        cmdline = row.get('CommandLine', '')
                        pid = row.get('ProcessId', '')
                        ppid = row.get('ParentProcessId', '')
                        exe_path = row.get('ExecutablePath', '')
                        
                        # Check for suspicious process names
                        for category, proc_list in suspicious_procs.items():
                            for suspicious_proc in proc_list:
                                if suspicious_proc.lower() in process_name:
                                    evidence.append(f"[{category}] Process: {row.get('Name', 'N/A')} | PID: {pid} | PPID: {ppid} | Path: {exe_path} | CommandLine: {cmdline}")
                                    categories_matched.add(category)
            
            except Exception as e:
                print(f"[!] Error reading process commandlines: {e}")
        
        # Analyze prefetch files for execution evidence
        prefetch_dir = self.triage_dir / "Prefetch"
        if prefetch_dir.exists():
            prefetch_indicators = self.indicators.get('prefetch_indicators', [])
            for pf_file in prefetch_dir.glob("*.pf"):
                for indicator in prefetch_indicators:
                    if indicator.upper() in pf_file.name.upper():
                        evidence.append(f"Prefetch evidence: {pf_file.name}")
                        categories_matched.add("prefetch_execution")
        
        if evidence:
            severity = Finding.SEVERITY_CRITICAL if any(cat in ['credential_theft', 'c2_frameworks', 'ransomware_tools'] for cat in categories_matched) else Finding.SEVERITY_HIGH
            priority = self.calculate_priority_score(severity, len(evidence), len(categories_matched))
            
            self.add_finding(
                category="Suspicious Process Execution",
                severity=severity,
                title="Malicious Tools and Processes Detected",
                description=f"Found {len(evidence)} instances of suspicious process execution across {len(categories_matched)} threat categories",
                evidence=evidence,
                priority_score=priority,
                recommendations=[
                    "Investigate parent-child process relationships",
                    "Check process creation times and sequence",
                    "Review network connections from these processes",
                    "Examine loaded DLLs for injection evidence"
                ]
            )
            print(f"[!] Found {len(evidence)} suspicious processes")
        else:
            print("[+] No suspicious processes detected")
    
    def analyze_persistence_mechanisms(self):
        """Analyze persistence mechanisms (registry, scheduled tasks, services)"""
        print("[*] Analyzing persistence mechanisms...")
        
        persistence_dir = self.triage_dir / "Persistence"
        if not persistence_dir.exists():
            print("[ ] Persistence artifacts not found")
            return
        
        evidence = []
        
        # Analyze registry run keys
        for run_key_file in persistence_dir.glob("*Run*.txt"):
            try:
                with open(run_key_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                # Look for suspicious file locations
                suspicious_locations = self.indicators.get('suspicious_file_locations', [])
                for location in suspicious_locations:
                    # Convert wildcards to regex
                    location_pattern = location.replace('*', '.*').replace('\\', '\\\\')
                    if re.search(location_pattern, content, re.IGNORECASE):
                        matches = re.findall(f'.*{location_pattern}.*', content, re.IGNORECASE)
                        for match in matches[:5]:  # Limit to 5 matches per location
                            evidence.append(f"Run Key - {run_key_file.name}: {match.strip()[:150]}")
            
            except Exception as e:
                print(f"[!] Error reading {run_key_file}: {e}")
        
        # Analyze scheduled tasks
        tasks_file = persistence_dir / "scheduled-tasks-verbose.txt"
        if tasks_file.exists():
            suspicious_tasks = self.indicators.get('suspicious_scheduled_tasks', [])
            try:
                with open(tasks_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    tasks = content.split('\n\n')
                    
                    for task in tasks:
                        # Check for suspicious task names/paths
                        for sus_task in suspicious_tasks:
                            if sus_task.lower() in task.lower():
                                task_name = re.search(r'TaskName:\s+(.+)', task)
                                if task_name:
                                    evidence.append(f"Suspicious Task: {task_name.group(1).strip()}")
                        
                        # Check for tasks running from suspicious locations
                        suspicious_locations = self.indicators.get('suspicious_file_locations', [])
                        for location in suspicious_locations:
                            location_pattern = location.replace('*', '.*').replace('\\', '\\\\')
                            if re.search(location_pattern, task, re.IGNORECASE):
                                task_name = re.search(r'TaskName:\s+(.+)', task)
                                if task_name:
                                    evidence.append(f"Task from suspicious location: {task_name.group(1).strip()}")
            
            except Exception as e:
                print(f"[!] Error reading scheduled tasks: {e}")
        
        # Analyze services
        services_file = persistence_dir / "services-detailed.csv"
        if services_file.exists():
            suspicious_svcs = self.indicators.get('suspicious_services', [])
            try:
                with open(services_file, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        svc_name = row.get('Name', '')
                        for sus_svc in suspicious_svcs:
                            if sus_svc.lower() in svc_name.lower():
                                evidence.append(f"Suspicious Service: {svc_name} - {row.get('DisplayName', 'N/A')}")
            
            except Exception as e:
                print(f"[!] Error reading services: {e}")
        
        # Analyze WMI persistence
        wmi_files = list(persistence_dir.glob("wmi-*.csv"))
        if wmi_files:
            evidence.append(f"WMI Persistence mechanisms found - Review {len(wmi_files)} WMI artifact files")
        
        if evidence:
            severity = Finding.SEVERITY_HIGH
            priority = self.calculate_priority_score(severity, len(evidence), 3)
            
            self.add_finding(
                category="Persistence Mechanisms",
                severity=severity,
                title="Suspicious Persistence Mechanisms Detected",
                description=f"Found {len(evidence)} suspicious persistence mechanisms",
                evidence=evidence,
                priority_score=priority,
                recommendations=[
                    "Review all run keys for legitimate software",
                    "Validate scheduled task actions and triggers",
                    "Check service binary paths and digital signatures",
                    "Investigate WMI event subscriptions and consumers"
                ]
            )
            print(f"[!] Found {len(evidence)} suspicious persistence mechanisms")
        else:
            print("[+] No suspicious persistence mechanisms detected")
    
    def analyze_network_activity(self):
        """Analyze network connections for C2 and data exfiltration"""
        print("[*] Analyzing network activity...")
        
        network_dir = self.triage_dir / "Network"
        if not network_dir.exists():
            print("[ ] Network artifacts not found")
            return
        
        evidence = []
        
        # Analyze netstat output
        netstat_file = network_dir / "netstat-anob.txt"
        if netstat_file.exists():
            suspicious_ports = self.indicators.get('network_indicators', {}).get('known_c2_ports', [])
            
            try:
                with open(netstat_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    
                for line in lines:
                    # Parse netstat output
                    if 'ESTABLISHED' in line or 'LISTENING' in line:
                        for port in suspicious_ports:
                            if f":{port}" in line:
                                evidence.append(f"Suspicious port {port}: {line.strip()[:150]}")
                        
                        # Check for non-standard ports
                        port_match = re.search(r':(\d+)', line)
                        if port_match:
                            port_num = int(port_match.group(1))
                            if port_num > 49152:  # Dynamic/Private ports
                                if 'ESTABLISHED' in line and '[' in line:  # Has process name
                                    proc_match = re.search(r'\[(.+?)\]', line)
                                    if proc_match:
                                        proc_name = proc_match.group(1)
                                        if proc_name.lower() not in ['chrome.exe', 'firefox.exe', 'msedge.exe', 'teams.exe']:
                                            evidence.append(f"High port connection: {line.strip()[:150]}")
            
            except Exception as e:
                print(f"[!] Error reading netstat: {e}")
        
        # Analyze DNS cache for suspicious domains
        dns_file = network_dir / "dns-cache.txt"
        if dns_file.exists():
            suspicious_dns = self.indicators.get('network_indicators', {}).get('suspicious_dns_queries', [])
            
            try:
                with open(dns_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                for sus_domain in suspicious_dns:
                    pattern = sus_domain.replace('*', '.*')
                    if re.search(pattern, content, re.IGNORECASE):
                        matches = re.findall(f'.*{pattern}.*', content, re.IGNORECASE)
                        for match in matches[:3]:
                            evidence.append(f"Suspicious DNS: {match.strip()[:100]}")
            
            except Exception as e:
                print(f"[!] Error reading DNS cache: {e}")
        
        if evidence:
            severity = Finding.SEVERITY_HIGH
            priority = self.calculate_priority_score(severity, len(evidence), 2)
            
            self.add_finding(
                category="Network Activity",
                severity=severity,
                title="Suspicious Network Connections Detected",
                description=f"Found {len(evidence)} suspicious network indicators",
                evidence=evidence,
                priority_score=priority,
                recommendations=[
                    "Correlate network connections with process execution times",
                    "Check firewall logs for connection attempts",
                    "Investigate DNS queries for C2 domains",
                    "Review proxy logs if available"
                ]
            )
            print(f"[!] Found {len(evidence)} suspicious network connections")
        else:
            print("[+] No suspicious network activity detected")
    
    def analyze_file_system(self):
        """Analyze file system for ransomware indicators and data staging"""
        print("[*] Analyzing file system artifacts...")
        
        fs_dir = self.triage_dir / "FileSystem"
        if not fs_dir.exists():
            print("[ ] File system artifacts not found")
            return
        
        evidence = []
        
        # Check recent files for ransomware extensions
        recent_files = fs_dir / "recent-files-7days.csv"
        if recent_files.exists():
            ransomware_extensions = self.indicators.get('ransomware_extensions', [])
            ransomware_notes = self.indicators.get('ransomware_notes', [])
            
            try:
                with open(recent_files, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    encrypted_count = 0
                    ransom_notes = []
                    
                    for row in reader:
                        filepath = row.get('FullName', '')
                        filename = Path(filepath).name
                        
                        # Check for ransomware extensions
                        for ext in ransomware_extensions:
                            if filepath.lower().endswith(ext):
                                encrypted_count += 1
                                if encrypted_count <= 10:  # Limit evidence entries
                                    evidence.append(f"Encrypted file: {filepath}")
                        
                        # Check for ransom notes
                        if filename in ransomware_notes:
                            ransom_notes.append(filepath)
                            evidence.append(f"RANSOM NOTE: {filepath}")
                    
                    if encrypted_count > 10:
                        evidence.append(f"... and {encrypted_count - 10} more encrypted files")
            
            except Exception as e:
                print(f"[!] Error reading recent files: {e}")
        
        # Check for large archive files (data exfiltration staging)
        if recent_files.exists():
            try:
                with open(recent_files, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    
                    for row in reader:
                        filepath = row.get('FullName', '')
                        try:
                            size = int(row.get('Length', 0))
                            
                            # Large archives in suspicious locations
                            if size > 100 * 1024 * 1024:  # > 100MB
                                if any(ext in filepath.lower() for ext in ['.zip', '.7z', '.rar', '.tar', '.gz']):
                                    suspicious_locs = self.indicators.get('suspicious_file_locations', [])
                                    for loc in suspicious_locs:
                                        loc_pattern = loc.replace('*', '.*').replace('\\', '\\\\')
                                        if re.search(loc_pattern, filepath, re.IGNORECASE):
                                            evidence.append(f"Large archive in suspicious location ({size//1024//1024}MB): {filepath}")
                        except:
                            pass
            
            except Exception as e:
                print(f"[!] Error analyzing file sizes: {e}")
        
        if evidence:
            # Ransomware is CRITICAL
            severity = Finding.SEVERITY_CRITICAL if any('RANSOM NOTE' in e or 'Encrypted file' in e for e in evidence) else Finding.SEVERITY_MEDIUM
            priority = self.calculate_priority_score(severity, len(evidence), 3)
            
            self.add_finding(
                category="File System Analysis",
                severity=severity,
                title="Ransomware or Data Exfiltration Indicators",
                description=f"Found {len(evidence)} file system indicators of compromise",
                evidence=evidence,
                priority_score=priority,
                recommendations=[
                    "DO NOT PAY RANSOM - Contact law enforcement",
                    "Isolate affected systems immediately",
                    "Identify ransomware variant for decryption options",
                    "Check for Volume Shadow Copies",
                    "Review backup integrity"
                ]
            )
            print(f"[!] Found {len(evidence)} file system indicators")
        else:
            print("[+] No file system anomalies detected")
    
    def analyze_user_accounts(self):
        """Analyze user account activity for suspicious accounts and privilege escalation"""
        print("[*] Analyzing user accounts...")
        
        user_dir = self.triage_dir / "UserInfo"
        if not user_dir.exists():
            print("[ ] User information not found")
            return
        
        evidence = []
        
        # Analyze local administrators
        admins_file = user_dir / "local-admins.txt"
        if admins_file.exists():
            try:
                with open(admins_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    admin_lines = content.split('\n')
                    
                    # Look for suspicious admin accounts
                    suspicious_names = ['admin$', 'test', 'temp', 'support', '$']
                    for line in admin_lines:
                        line = line.strip()
                        if line and not line.startswith('-') and not line.startswith('Alias'):
                            for sus_name in suspicious_names:
                                if sus_name.lower() in line.lower():
                                    evidence.append(f"Suspicious admin account: {line}")
            
            except Exception as e:
                print(f"[!] Error reading local admins: {e}")
        
        # Analyze user account details
        accounts_file = user_dir / "user-accounts-detailed.csv"
        if accounts_file.exists():
            try:
                with open(accounts_file, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    
                    for row in reader:
                        username = row.get('Name', '')
                        enabled = row.get('Enabled', 'False')
                        last_logon = row.get('LastLogon', '')
                        
                        # Check for recently created accounts
                        if enabled == 'True' and username.startswith(('admin', 'test', 'temp', 'support')):
                            evidence.append(f"Suspicious enabled account: {username}")
                        
                        # Check for accounts without password expiration
                        if row.get('PasswordExpires', 'True') == 'False' and enabled == 'True':
                            if not username.startswith(('Guest', 'DefaultAccount', 'WDAGUtility')):
                                evidence.append(f"Account with non-expiring password: {username}")
            
            except Exception as e:
                print(f"[!] Error reading user accounts: {e}")
        
        if evidence:
            severity = Finding.SEVERITY_HIGH
            priority = self.calculate_priority_score(severity, len(evidence), 2)
            
            self.add_finding(
                category="User Accounts",
                severity=severity,
                title="Suspicious User Accounts Detected",
                description=f"Found {len(evidence)} suspicious user account indicators",
                evidence=evidence,
                priority_score=priority,
                recommendations=[
                    "Disable suspicious accounts immediately",
                    "Review account creation event logs (EventID 4720)",
                    "Check for privilege escalation (EventID 4732)",
                    "Audit password policies and enforcement"
                ]
            )
            print(f"[!] Found {len(evidence)} suspicious user accounts")
        else:
            print("[+] No suspicious user accounts detected")
    
    def analyze_browser_artifacts(self):
        """Analyze browser history for malicious sites and downloads"""
        print("[*] Analyzing browser artifacts...")
        
        browser_dir = self.triage_dir / "BrowserData"
        if not browser_dir.exists():
            print("[ ] Browser data not found")
            return
        
        evidence = []
        suspicious_dns = self.indicators.get('network_indicators', {}).get('suspicious_dns_queries', [])
        
        # Analyze Chrome/Edge history databases
        for db_file in browser_dir.glob("*History*.db"):
            try:
                conn = sqlite3.connect(db_file)
                cursor = conn.cursor()
                
                # Query URLs
                cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 1000")
                rows = cursor.fetchall()
                
                for url, title, visit_count, last_visit_time in rows:
                    # Check against suspicious domains
                    for sus_domain in suspicious_dns:
                        pattern = sus_domain.replace('*', '.*')
                        if re.search(pattern, url, re.IGNORECASE):
                            evidence.append(f"{db_file.name}: {url[:100]}")
                
                conn.close()
            
            except Exception as e:
                print(f"[!] Could not parse {db_file.name}: {e}")
        
        if evidence:
            severity = Finding.SEVERITY_MEDIUM
            priority = self.calculate_priority_score(severity, len(evidence), 1)
            
            self.add_finding(
                category="Browser Activity",
                severity=severity,
                title="Suspicious Web Activity Detected",
                description=f"Found {len(evidence)} suspicious URLs in browser history",
                evidence=evidence,
                priority_score=priority,
                recommendations=[
                    "Review full browsing history for IOCs",
                    "Check download history for malicious files",
                    "Correlate with network traffic logs",
                    "Scan downloaded files with antivirus"
                ]
            )
            print(f"[!] Found {len(evidence)} suspicious browser entries")
        else:
            print("[+] No suspicious browser activity detected")
    
    def analyze_event_logs(self):
        """Analyze parsed event logs for suspicious activity"""
        print("[*] Analyzing event logs...")
        
        # Check for parsed logs directory
        parsed_dir = self.triage_dir / "EventLogs_Parsed"
        if not parsed_dir.exists():
            print("[ ] Parsed event logs not found")
            print("[!] Run evtx_to_csv.ps1 first to parse EVTX files")
            return
        
        critical_event_ids = self.indicators.get('event_ids', {})
        suspicious_procs = self.indicators.get('suspicious_processes', {})
        suspicious_commands = self.indicators.get('suspicious_commands', {})
        
        evidence = []
        categories_matched = set()
        
        # Analyze Security log
        security_csv = parsed_dir / "Security.csv"
        if security_csv.exists():
            try:
                with open(security_csv, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    
                    for row in reader:
                        event_id = row.get('EventID', '')
                        message = row.get('Message', '')
                        event_data = row.get('EventData', '')
                        time_created = row.get('TimeCreated', '')
                        
                        # Check for critical events
                        for category, events in critical_event_ids.items():
                            if event_id in events:
                                evidence.append(f"[{category}] EventID {event_id}: {events[event_id]} | Time: {time_created} | User: {row.get('UserId', 'N/A')} | Computer: {row.get('Computer', 'N/A')} | Message: {message[:200]}")
                                categories_matched.add(category)
                        
                        # Check for suspicious process creation (4688)
                        if event_id == '4688':
                            for proc_category, proc_list in suspicious_procs.items():
                                for sus_proc in proc_list:
                                    if sus_proc.lower() in event_data.lower():
                                        evidence.append(f"[Process Creation] {sus_proc} | Time: {time_created} | EventData: {event_data}")
                                        categories_matched.add(f"process_{proc_category}")
                        
                        # Check for account manipulation
                        if event_id in ['4720', '4722', '4732', '4728', '4756']:
                            if 'admin' in event_data.lower() or 'test' in event_data.lower():
                                evidence.append(f"[Account Activity] EventID {event_id} | Time: {time_created} | Data: {event_data}")
                                categories_matched.add("account_manipulation")
            
            except Exception as e:
                print(f"[!] Error reading Security.csv: {e}")
        
        # Analyze PowerShell logs
        ps_logs = list(parsed_dir.glob("PowerShell*.csv"))
        for ps_log in ps_logs:
            try:
                with open(ps_log, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    
                    for row in reader:
                        event_id = row.get('EventID', '')
                        message = row.get('Message', '')
                        event_data = row.get('EventData', '')
                        time_created = row.get('TimeCreated', '')
                        
                        # Check for script block logging (4104)
                        if event_id == '4104':
                            # Check for suspicious commands
                            for cmd_category, patterns in suspicious_commands.items():
                                for pattern in patterns:
                                    if re.search(pattern, message + event_data, re.IGNORECASE):
                                        # Extract script block content (first 500 chars)
                                        script_content = (message + " " + event_data)[:500]
                                        evidence.append(f"[PowerShell-{cmd_category}] Time: {time_created} | Pattern: {pattern[:50]} | ScriptBlock: {script_content}")
                                        categories_matched.add(f"powershell_{cmd_category}")
                                        break  # Only match once per script block
            
            except Exception as e:
                print(f"[!] Error reading {ps_log.name}: {e}")
        
        # Analyze Sysmon logs
        sysmon_csv = parsed_dir / "Sysmon.csv"
        if sysmon_csv.exists():
            try:
                with open(sysmon_csv, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    
                    for row in reader:
                        event_id = row.get('EventID', '')
                        event_data = row.get('EventData', '')
                        time_created = row.get('TimeCreated', '')
                        
                        # Sysmon Event 1 - Process creation
                        if event_id == '1':
                            for proc_category, proc_list in suspicious_procs.items():
                                for sus_proc in proc_list:
                                    if sus_proc.lower() in event_data.lower():
                                        evidence.append(f"[Sysmon Process-{proc_category}] {sus_proc} | Time: {time_created} | Details: {event_data[:300]}")
                                        categories_matched.add(f"sysmon_{proc_category}")
                        
                        # Sysmon Event 3 - Network connection
                        elif event_id == '3':
                            network_indicators = self.indicators.get('network_indicators', {})
                            c2_ports = network_indicators.get('known_c2_ports', [])
                            for port in c2_ports:
                                if f":{port}" in event_data or f" {port} " in event_data:
                                    evidence.append(f"[Sysmon Network] C2 port {port} detected | Time: {time_created} | Connection: {event_data[:300]}")
                                    categories_matched.add("sysmon_network")
                        
                        # Sysmon Event 8 - CreateRemoteThread (injection)
                        elif event_id == '8':
                            evidence.append(f"[Sysmon Injection] CreateRemoteThread detected | Time: {time_created} | Details: {event_data[:300]}")
                            categories_matched.add("sysmon_injection")
                        
                        # Sysmon Event 10 - Process access (credential dumping)
                        elif event_id == '10':
                            if 'lsass' in event_data.lower():
                                evidence.append(f"[Sysmon LSASS Access] Potential credential dumping | Time: {time_created} | Details: {event_data[:300]}")
                                categories_matched.add("sysmon_credential_access")
            
            except Exception as e:
                print(f"[!] Error reading Sysmon.csv: {e}")
        
        # Analyze System log for service installation
        system_csv = parsed_dir / "System.csv"
        if system_csv.exists():
            try:
                with open(system_csv, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    
                    for row in reader:
                        event_id = row.get('EventID', '')
                        event_data = row.get('EventData', '')
                        message = row.get('Message', '')
                        time_created = row.get('TimeCreated', '')
                        
                        # Event 7045 - Service installed
                        if event_id == '7045':
                            suspicious_svcs = self.indicators.get('suspicious_services', [])
                            for sus_svc in suspicious_svcs:
                                if sus_svc.lower() in (event_data + message).lower():
                                    evidence.append(f"Service Installed: {sus_svc} at {time_created}")
                                    categories_matched.add("service_installation")
            
            except Exception as e:
                print(f"[!] Error reading System.csv: {e}")
        
        # Analyze Windows Defender logs
        defender_csv = parsed_dir / "Defender.csv"
        if defender_csv.exists():
            try:
                with open(defender_csv, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    
                    for row in reader:
                        event_id = row.get('EventID', '')
                        message = row.get('Message', '')
                        time_created = row.get('TimeCreated', '')
                        
                        # Malware detection or protection disabled
                        if event_id in ['1006', '1116', '1117', '5001', '5007']:
                            evidence.append(f"Defender Alert: EventID {event_id} - {message[:100]} at {time_created}")
                            categories_matched.add("defender_alert")
            
            except Exception as e:
                print(f"[!] Error reading Defender.csv: {e}")
        
        if evidence:
            # Event log findings are typically HIGH or CRITICAL
            severity = Finding.SEVERITY_CRITICAL if any('credential' in e.lower() or 'lsass' in e.lower() or 'mimikatz' in e.lower() for e in evidence) else Finding.SEVERITY_HIGH
            priority = self.calculate_priority_score(severity, len(evidence), len(categories_matched))
            
            self.add_finding(
                category="Event Log Analysis",
                severity=severity,
                title="Suspicious Activity Detected in Event Logs",
                description=f"Found {len(evidence)} suspicious events across {len(categories_matched)} categories",
                evidence=evidence,  # Include ALL evidence
                priority_score=priority,
                recommendations=[
                    "Review full event logs for complete timeline",
                    "Correlate event times with other artifacts",
                    "Check for event log tampering (EventID 1102)",
                    "Build timeline of attacker activity",
                    "Review parent-child process relationships in Sysmon"
                ]
            )
            print(f"[!] Found {len(evidence)} suspicious events in logs")
        else:
            print("[+] No suspicious activity in event logs")
    
    def generate_report(self):
        """Generate comprehensive investigation report"""
        print("\n[*] Generating investigation report...")
        
        # Sort findings by priority score
        sorted_findings = sorted(self.findings, key=lambda x: x.priority_score, reverse=True)
        
        # Generate HTML report
        html_file = self.output_dir / "Investigation_Report.html"
        self.generate_html_report(html_file, sorted_findings)
        
        # Generate CSV report
        csv_file = self.output_dir / "Findings.csv"
        self.generate_csv_report(csv_file, sorted_findings)
        
        # Generate JSON report
        json_file = self.output_dir / "Investigation_Data.json"
        self.generate_json_report(json_file, sorted_findings)
        
        # Generate executive summary
        summary_file = self.output_dir / "Executive_Summary.txt"
        self.generate_executive_summary(summary_file, sorted_findings)
        
        # NEW: Generate detailed evidence files
        self.generate_detailed_evidence_files(sorted_findings)
        
        print(f"\n[+] Reports generated in: {self.output_dir}")
        print(f"    - {html_file.name} (Interactive HTML report)")
        print(f"    - {csv_file.name} (Detailed findings)")
        print(f"    - {json_file.name} (Machine-readable data)")
        print(f"    - {summary_file.name} (Executive summary)")
        print(f"    - Evidence/ (Detailed evidence files)")
    
    def generate_detailed_evidence_files(self, findings: List[Finding]):
        """Generate separate detailed evidence files for each finding"""
        evidence_dir = self.output_dir / "Evidence"
        evidence_dir.mkdir(exist_ok=True)
        
        for i, finding in enumerate(findings, 1):
            # Create safe filename
            safe_title = re.sub(r'[^\w\s-]', '', finding.title)
            safe_title = re.sub(r'[-\s]+', '_', safe_title)
            filename = f"{i:02d}_{finding.severity}_{safe_title}.txt"
            
            filepath = evidence_dir / filename
            
            content = f"""
{'='*80}
FINDING #{i} - {finding.severity}
{'='*80}

Title: {finding.title}
Category: {finding.category}
Priority Score: {finding.priority_score}/100
Timestamp: {finding.timestamp.strftime('%Y-%m-%d %H:%M:%S')}

{'='*80}
DESCRIPTION
{'='*80}

{finding.description}

{'='*80}
EVIDENCE ({len(finding.evidence)} items)
{'='*80}

"""
            for j, evidence_item in enumerate(finding.evidence, 1):
                content += f"{j}. {evidence_item}\n"
            
            content += f"""
{'='*80}
RECOMMENDATIONS
{'='*80}

"""
            for j, rec in enumerate(finding.recommendations, 1):
                content += f"{j}. {rec}\n"
            
            content += f"""
{'='*80}
INVESTIGATION NOTES
{'='*80}

[Add your investigation notes here]

Next Steps:
[ ] Verified evidence authenticity
[ ] Correlated with other artifacts
[ ] Identified affected systems/users
[ ] Documented timeline
[ ] Escalated if needed

{'='*80}
"""
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
        
        print(f"[+] Generated {len(findings)} detailed evidence files")
    
    # ================================================================
    # ENHANCED ANALYSIS MODULES v2.0
    # ================================================================
    
        # ENHANCED ANALYSIS MODULES
        # Add these to ransomware_investigator.py after the existing analysis methods

    def analyze_shimcache_bam_dam(self):
        """Analyze ShimCache, BAM, and DAM for execution evidence"""
        print("[*] Analyzing ShimCache/BAM/DAM...")
    
        evidence = []
        suspicious_procs = self.indicators.get('suspicious_processes', {})
    
        # Analyze ShimCache
        shimcache_file = self.triage_dir / "AdvancedArtifacts" / "shimcache.txt"
        if shimcache_file.exists():
            try:
                with open(shimcache_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                    # Look for suspicious executables in shimcache
                    for proc_category, proc_list in suspicious_procs.items():
                        for sus_proc in proc_list:
                            if sus_proc.lower() in content.lower():
                                # Extract surrounding context
                                lines = content.split('\n')
                                for i, line in enumerate(lines):
                                    if sus_proc.lower() in line.lower():
                                        context = '\n'.join(lines[max(0,i-1):min(len(lines),i+2)])
                                        evidence.append(f"[ShimCache-{proc_category}] {sus_proc} | Context: {context[:200]}")
            except Exception as e:
                print(f"[!] Error reading shimcache.txt: {e}")
    
        # Analyze BAM
        bam_file = self.triage_dir / "AdvancedArtifacts" / "bam.txt"
        if bam_file.exists():
            try:
                with open(bam_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                    for proc_category, proc_list in suspicious_procs.items():
                        for sus_proc in proc_list:
                            if sus_proc.lower() in content.lower():
                                lines = content.split('\n')
                                for i, line in enumerate(lines):
                                    if sus_proc.lower() in line.lower():
                                        # Try to extract timestamp from hex
                                        evidence.append(f"[BAM-{proc_category}] {sus_proc} | Entry: {line.strip()[:200]}")
            except Exception as e:
                print(f"[!] Error reading bam.txt: {e}")
    
        # Analyze DAM
        dam_file = self.triage_dir / "AdvancedArtifacts" / "dam.txt"
        if dam_file.exists():
            try:
                with open(dam_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                    for proc_category, proc_list in suspicious_procs.items():
                        for sus_proc in proc_list:
                            if sus_proc.lower() in content.lower():
                                lines = content.split('\n')
                                for i, line in enumerate(lines):
                                    if sus_proc.lower() in line.lower():
                                        evidence.append(f"[DAM-{proc_category}] {sus_proc} | Entry: {line.strip()[:200]}")
            except Exception as e:
                print(f"[!] Error reading dam.txt: {e}")
    
        if evidence:
            severity = Finding.SEVERITY_HIGH
            priority = self.calculate_priority_score(severity, len(evidence), len(set(e.split(']')[0] for e in evidence)))
        
            self.add_finding(
                category="Execution Evidence",
                severity=severity,
                title="Suspicious Program Execution Detected in ShimCache/BAM/DAM",
                description=f"Found {len(evidence)} suspicious program execution entries",
                evidence=evidence,
                priority_score=priority,
                recommendations=[
                    "Cross-reference execution times with other artifacts",
                    "Build complete execution timeline",
                    "Investigate parent processes",
                    "Check if programs still exist on disk"
                ]
            )
            print(f"[!] Found {len(evidence)} suspicious execution entries")
        else:
            print("[+] No suspicious execution evidence in ShimCache/BAM/DAM")

    def analyze_prefetch_files(self):
        """Analyze prefetch file listing for execution evidence"""
        print("[*] Analyzing prefetch files...")
    
        prefetch_dir = self.triage_dir / "Prefetch"
        if not prefetch_dir.exists():
            print("[ ] Prefetch directory not found")
            return
    
        evidence = []
        suspicious_procs = self.indicators.get('suspicious_processes', {})
        prefetch_indicators = self.indicators.get('prefetch_indicators', [])
    
        try:
            # List all .pf files
            pf_files = list(prefetch_dir.glob("*.pf"))
        
            for pf_file in pf_files:
                pf_name = pf_file.name.upper()
            
                # Check against suspicious processes
                for proc_category, proc_list in suspicious_procs.items():
                    for sus_proc in proc_list:
                        if sus_proc.upper().replace('.EXE', '') in pf_name:
                            evidence.append(f"[{proc_category}] Prefetch: {pf_file.name} | Modified: {datetime.fromtimestamp(pf_file.stat().st_mtime)}")
            
                # Check against prefetch indicators
                for indicator in prefetch_indicators:
                    if indicator.upper() in pf_name:
                        evidence.append(f"[Indicator] Prefetch: {pf_file.name} | Modified: {datetime.fromtimestamp(pf_file.stat().st_mtime)}")
    
        except Exception as e:
            print(f"[!] Error analyzing prefetch: {e}")
    
        if evidence:
            severity = Finding.SEVERITY_HIGH
            priority = self.calculate_priority_score(severity, len(evidence), 1)
        
            self.add_finding(
                category="Execution Evidence",
                severity=severity,
                title="Suspicious Programs Found in Prefetch",
                description=f"Found {len(evidence)} prefetch files for suspicious programs",
                evidence=evidence,
                priority_score=priority,
                recommendations=[
                    "Parse prefetch files with PECmd for detailed execution info",
                    "Check execution count and last run times",
                    "Correlate with ShimCache and event logs",
                    "Investigate DLLs loaded by these programs"
                ]
            )
            print(f"[!] Found {len(evidence)} suspicious prefetch files")
        else:
            print("[+] No suspicious programs in prefetch")

    def analyze_scheduled_tasks(self):
        """Deep analysis of scheduled tasks"""
        print("[*] Analyzing scheduled tasks...")
    
        tasks_file = self.triage_dir / "Persistence" / "scheduled-tasks-verbose.txt"
        if not tasks_file.exists():
            print("[ ] Scheduled tasks file not found")
            return
    
        evidence = []
        suspicious_procs = self.indicators.get('suspicious_processes', {})
        suspicious_tasks = self.indicators.get('suspicious_scheduled_tasks', [])
        suspicious_commands = self.indicators.get('suspicious_commands', {})
    
        try:
            with open(tasks_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
                # Split by tasks
                tasks = content.split('TaskName:')
            
                for task in tasks[1:]:  # Skip first empty split
                    task_lines = task.split('\n')
                    task_name = task_lines[0].strip() if task_lines else "Unknown"
                
                    # Check task name against indicators
                    for sus_task in suspicious_tasks:
                        if sus_task.lower() in task_name.lower():
                            evidence.append(f"[Suspicious Task Name] {task_name}")
                
                    # Check task action/command
                    for line in task_lines:
                        if 'Task To Run:' in line or 'Actions:' in line:
                            # Check for suspicious processes
                            for proc_category, proc_list in suspicious_procs.items():
                                for sus_proc in proc_list:
                                    if sus_proc.lower() in line.lower():
                                        evidence.append(f"[Task-{proc_category}] {task_name} | Action: {line.strip()[:200]}")
                        
                            # Check for suspicious commands
                            for cmd_category, patterns in suspicious_commands.items():
                                for pattern in patterns:
                                    if re.search(pattern, line, re.IGNORECASE):
                                        evidence.append(f"[Task-{cmd_category}] {task_name} | Action: {line.strip()[:200]}")
                
                    # Check for unusual run times (e.g., every minute)
                    if 'Schedule Type:' in task and 'Minute' in task:
                        if any(word in task.lower() for word in ['every 1 minute', 'every minute']):
                            evidence.append(f"[High Frequency] {task_name} | Runs every minute (potential C2)")
    
        except Exception as e:
            print(f"[!] Error analyzing scheduled tasks: {e}")
    
        if evidence:
            severity = Finding.SEVERITY_HIGH
            priority = self.calculate_priority_score(severity, len(evidence), 1)
        
            self.add_finding(
                category="Persistence",
                severity=severity,
                title="Suspicious Scheduled Tasks Detected",
                description=f"Found {len(evidence)} suspicious scheduled task entries",
                evidence=evidence,
                priority_score=priority,
                recommendations=[
                    "Review task XML files for complete details",
                    "Check task triggers and schedules",
                    "Identify task creators (Author field)",
                    "Disable/delete malicious tasks immediately"
                ]
            )
            print(f"[!] Found {len(evidence)} suspicious scheduled tasks")
        else:
            print("[+] No suspicious scheduled tasks detected")

    def analyze_services(self):
        """Deep analysis of services"""
        print("[*] Analyzing services...")
    
        services_file = self.triage_dir / "Persistence" / "services-detailed.csv"
        if not services_file.exists():
            print("[ ] Services file not found")
            return
    
        evidence = []
        suspicious_procs = self.indicators.get('suspicious_processes', {})
        suspicious_services = self.indicators.get('suspicious_services', [])
    
        try:
            with open(services_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
            
                for row in reader:
                    service_name = row.get('Name', '')
                    display_name = row.get('DisplayName', '')
                    status = row.get('Status', '')
                    start_type = row.get('StartType', '')
                
                    # Check against suspicious service names
                    for sus_svc in suspicious_services:
                        if sus_svc.lower() in service_name.lower() or sus_svc.lower() in display_name.lower():
                            evidence.append(f"[Suspicious Service] {service_name} ({display_name}) | Status: {status} | StartType: {start_type}")
                
                    # Check for unusual patterns
                    if start_type == 'Automatic' and status == 'Stopped':
                        # Automatic service that's stopped might have been disabled
                        for sus_svc in suspicious_services:
                            if sus_svc.lower() in service_name.lower():
                                evidence.append(f"[Disabled Service] {service_name} | Was Automatic, now Stopped")
    
        except Exception as e:
            print(f"[!] Error analyzing services: {e}")
    
        # Also check services registry
        services_reg = self.triage_dir / "Persistence" / "services-registry.txt"
        if services_reg.exists():
            try:
                with open(services_reg, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                    for proc_category, proc_list in suspicious_procs.items():
                        for sus_proc in proc_list:
                            if sus_proc.lower() in content.lower():
                                lines = content.split('\n')
                                for i, line in enumerate(lines):
                                    if sus_proc.lower() in line.lower():
                                        context = '\n'.join(lines[max(0,i-2):min(len(lines),i+3)])
                                        evidence.append(f"[Service-{proc_category}] {sus_proc} in registry | Context: {context[:300]}")
            except Exception as e:
                print(f"[!] Error reading services registry: {e}")
    
        if evidence:
            severity = Finding.SEVERITY_HIGH
            priority = self.calculate_priority_score(severity, len(evidence), 1)
        
            self.add_finding(
                category="Persistence",
                severity=severity,
                title="Suspicious Services Detected",
                description=f"Found {len(evidence)} suspicious service entries",
                evidence=evidence,
                priority_score=priority,
                recommendations=[
                    "Check service executable paths and DLLs",
                    "Review service account permissions",
                    "Investigate service creation times",
                    "Stop and disable malicious services"
                ]
            )
            print(f"[!] Found {len(evidence)} suspicious services")
        else:
            print("[+] No suspicious services detected")

    def analyze_vss_shadow_copies(self):
        """Analyze Volume Shadow Copy status for ransomware indicators"""
        print("[*] Analyzing Volume Shadow Copies...")
    
        vss_file = self.triage_dir / "AdvancedArtifacts" / "vss-shadows-list.txt"
        if not vss_file.exists():
            print("[ ] VSS information not found")
            return
    
        evidence = []
    
        try:
            with open(vss_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
                # Check if no shadow copies exist
                if 'No items found' in content or 'No shadow copies' in content:
                    evidence.append("[CRITICAL] No shadow copies found on system - possible ransomware deleted them")
                    evidence.append("Command likely used: vssadmin delete shadows /all /quiet")
                    severity = Finding.SEVERITY_CRITICAL
                else:
                    # Parse shadow copy details
                    shadow_lines = [line for line in content.split('\n') if line.strip()]
                    if shadow_lines:
                        evidence.append(f"[INFO] Found {len([l for l in shadow_lines if 'Shadow Copy Volume' in l])} shadow copies")
                        for line in shadow_lines[:10]:  # Show first 10 lines
                            if any(keyword in line for keyword in ['Shadow Copy Volume', 'Creation Time', 'Shadow Copy Set ID']):
                                evidence.append(f"  {line.strip()}")
                        severity = Finding.SEVERITY_INFO
    
        except Exception as e:
            print(f"[!] Error analyzing VSS: {e}")
            return
    
        if evidence:
            priority = self.calculate_priority_score(severity, len(evidence), 1)
        
            self.add_finding(
                category="Anti-Forensics / Ransomware",
                severity=severity,
                title="Volume Shadow Copy Analysis",
                description="Shadow copy status indicates potential ransomware activity" if severity == Finding.SEVERITY_CRITICAL else "Shadow copy information collected",
                evidence=evidence,
                priority_score=priority,
                recommendations=[
                    "Check event logs for shadow copy deletion events",
                    "Review PowerShell history for vssadmin commands",
                    "Correlate with other ransomware indicators",
                    "Attempt shadow copy recovery if available"
                ] if severity == Finding.SEVERITY_CRITICAL else [
                    "Monitor for future shadow copy deletions",
                    "Ensure shadow copies are enabled",
                    "Review shadow copy retention policy"
                ]
            )
            print(f"[!] VSS analysis complete: {severity}")
        else:
            print("[+] VSS analysis complete")

    def analyze_defender_detections(self):
        """Analyze Windows Defender detections and quarantine"""
        print("[*] Analyzing Windows Defender detections...")
    
        quarantine_file = self.triage_dir / "AdvancedArtifacts" / "defender-quarantine-listing.csv"
        if not quarantine_file.exists():
            print("[ ] Defender quarantine listing not found")
            return
    
        evidence = []
    
        try:
            with open(quarantine_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
            
                detections = list(reader)
                if detections:
                    evidence.append(f"[INFO] Found {len(detections)} items in Defender quarantine")
                
                    for detection in detections[:20]:  # Limit to first 20
                        fullname = detection.get('FullName', '')
                        creation_time = detection.get('CreationTime', '')
                    
                        if fullname:
                            evidence.append(f"  Quarantined: {fullname} | Time: {creation_time}")
    
        except Exception as e:
            print(f"[!] Error analyzing Defender quarantine: {e}")
    
        if evidence:
            severity = Finding.SEVERITY_MEDIUM
            priority = self.calculate_priority_score(severity, len(evidence), 1)
        
            self.add_finding(
                category="Windows Defender",
                severity=severity,
                title="Windows Defender Detections Found",
                description=f"Found items in Windows Defender quarantine",
                evidence=evidence,
                priority_score=priority,
                recommendations=[
                    "Review Defender event logs for detection details",
                    "Check if Defender was disabled after detection",
                    "Extract quarantined files for analysis",
                    "Determine if threats were fully remediated"
                ]
            )
            print(f"[!] Found Defender detections")
        else:
            print("[+] No Defender detections found")

    def analyze_drivers(self):
        """Analyze loaded drivers for rootkits and malicious drivers"""
        print("[*] Analyzing drivers...")
    
        drivers_file = self.triage_dir / "ProcessInfo" / "drivers.csv"
        signed_drivers_file = self.triage_dir / "ProcessInfo" / "signed-drivers.csv"
    
        evidence = []
    
        # Check for unsigned drivers
        if signed_drivers_file.exists():
            try:
                with open(signed_drivers_file, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                
                    for row in reader:
                        is_signed = row.get('IsSigned', '')
                        device_name = row.get('DeviceName', '')
                        driver_version = row.get('DriverVersion', '')
                        manufacturer = row.get('Manufacturer', '')
                    
                        if is_signed == 'FALSE' or is_signed == 'False':
                            evidence.append(f"[Unsigned Driver] {device_name} | Version: {driver_version} | Manufacturer: {manufacturer}")
            except Exception as e:
                print(f"[!] Error analyzing signed drivers: {e}")
    
        # Check driver names for known rootkits
        if drivers_file.exists():
            try:
                with open(drivers_file, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                
                    rootkit_keywords = ['rootkit', 'hack', 'cheat', 'inject', 'hide', 'ghost']
                
                    for row in reader:
                        name = row.get('Name', '').lower()
                        display_name = row.get('DisplayName', '').lower()
                        path_name = row.get('PathName', '')
                    
                        for keyword in rootkit_keywords:
                            if keyword in name or keyword in display_name:
                                evidence.append(f"[Suspicious Driver Name] {row.get('Name')} ({row.get('DisplayName')}) | Path: {path_name}")
            except Exception as e:
                print(f"[!] Error analyzing drivers: {e}")
    
        if evidence:
            severity = Finding.SEVERITY_HIGH
            priority = self.calculate_priority_score(severity, len(evidence), 1)
        
            self.add_finding(
                category="Rootkit Detection",
                severity=severity,
                title="Suspicious or Unsigned Drivers Detected",
                description=f"Found {len(evidence)} suspicious driver entries",
                evidence=evidence,
                priority_score=priority,
                recommendations=[
                    "Verify driver signatures and publishers",
                    "Check driver file hashes against VirusTotal",
                    "Review driver load times in event logs",
                    "Disable/uninstall malicious drivers"
                ]
            )
            print(f"[!] Found {len(evidence)} suspicious drivers")
        else:
            print("[+] No suspicious drivers detected")

    def analyze_environment_variables(self):
        """Analyze environment variables for suspicious paths"""
        print("[*] Analyzing environment variables...")
    
        env_file = self.triage_dir / "environment-variables.txt"
        if not env_file.exists():
            print("[ ] Environment variables file not found")
            return
    
        evidence = []
        suspicious_paths = [
            'temp', 'tmp', 'appdata\\local\\temp', 
            'programdata', 'public', 'users\\public',
            'perflogs', 'recycler', '$recycle.bin'
        ]
    
        try:
            with open(env_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
                for line in lines:
                    line_lower = line.lower()
                
                    # Check PATH variable for suspicious additions
                    if line.startswith('PATH') or 'Path' in line[:10]:
                        for sus_path in suspicious_paths:
                            if sus_path in line_lower:
                                evidence.append(f"[Suspicious PATH] {line.strip()[:200]}")
                                break
                
                    # Check for unusual variables
                    if any(keyword in line_lower for keyword in ['malware', 'hack', 'exploit', 'payload']):
                        evidence.append(f"[Suspicious Variable] {line.strip()}")
    
        except Exception as e:
            print(f"[!] Error analyzing environment variables: {e}")
    
        if evidence:
            severity = Finding.SEVERITY_MEDIUM
            priority = self.calculate_priority_score(severity, len(evidence), 1)
        
            self.add_finding(
                category="System Configuration",
                severity=severity,
                title="Suspicious Environment Variables",
                description=f"Found {len(evidence)} suspicious environment variable entries",
                evidence=evidence,
                priority_score=priority,
                recommendations=[
                    "Check if PATH has been modified by malware",
                    "Review user-specific environment variables",
                    "Look for persistence via environment variables",
                    "Correlate with registry run keys"
                ]
            )
            print(f"[!] Found {len(evidence)} suspicious environment variables")
        else:
            print("[+] No suspicious environment variables")


    # Enhanced HTML Report Generation
        # ENHANCED HTML REPORT GENERATION
        # Replace the generate_html_report method in ransomware_investigator.py

    def generate_html_report(self, output_file: Path, findings: List[Finding]):
        """Generate enhanced interactive HTML report with modern UI"""
    
        # Calculate statistics
        stats = {
            'total': len(findings),
            'critical': len([f for f in findings if f.severity == Finding.SEVERITY_CRITICAL]),
            'high': len([f for f in findings if f.severity == Finding.SEVERITY_HIGH]),
            'medium': len([f for f in findings if f.severity == Finding.SEVERITY_MEDIUM]),
            'low': len([f for f in findings if f.severity == Finding.SEVERITY_LOW]),
        }
    
        # Group findings by category
        categories = {}
        for finding in findings:
            if finding.category not in categories:
                categories[finding.category] = []
            categories[finding.category].append(finding)
    
        html = """<!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DFIR Investigation Report</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
        
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
                color: #2d3748;
            }
        
            .container {
                max-width: 1400px;
                margin: 0 auto;
                background: white;
                border-radius: 20px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                overflow: hidden;
            }
        
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 40px;
            }
        
            .header h1 {
                font-size: 2.5em;
                margin-bottom: 10px;
                font-weight: 700;
            }
        
            .header .subtitle {
                font-size: 1.1em;
                opacity: 0.9;
                font-weight: 300;
            }
        
            .header .timestamp {
                margin-top: 15px;
                opacity: 0.8;
                font-size: 0.95em;
            }
        
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                padding: 40px;
                background: #f7fafc;
            }
        
            .stat-card {
                background: white;
                border-radius: 15px;
                padding: 25px;
                text-align: center;
                box-shadow: 0 4px 6px rgba(0,0,0,0.07);
                transition: transform 0.2s, box-shadow 0.2s;
            }
        
            .stat-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 12px 24px rgba(0,0,0,0.15);
            }
        
            .stat-number {
                font-size: 3em;
                font-weight: 700;
                margin: 10px 0;
            }
        
            .stat-label {
                font-size: 0.9em;
                text-transform: uppercase;
                letter-spacing: 1px;
                font-weight: 600;
                color: #718096;
            }
        
            .stat-card.critical { border-left: 5px solid #e53e3e; }
            .stat-card.critical .stat-number { color: #e53e3e; }
        
            .stat-card.high { border-left: 5px solid #ed8936; }
            .stat-card.high .stat-number { color: #ed8936; }
        
            .stat-card.medium { border-left: 5px solid #ecc94b; }
            .stat-card.medium .stat-number { color: #ecc94b; }
        
            .stat-card.low { border-left: 5px solid #48bb78; }
            .stat-card.low .stat-number { color: #48bb78; }
        
            .stat-card.total { border-left: 5px solid #667eea; }
            .stat-card.total .stat-number { color: #667eea; }
        
            .content {
                padding: 40px;
            }
        
            .controls {
                display: flex;
                gap: 15px;
                flex-wrap: wrap;
                margin-bottom: 30px;
                padding: 20px;
                background: #f7fafc;
                border-radius: 10px;
            }
        
            .filter-btn {
                padding: 10px 20px;
                border: 2px solid #e2e8f0;
                background: white;
                border-radius: 8px;
                cursor: pointer;
                font-weight: 600;
                transition: all 0.2s;
                font-size: 0.9em;
            }
        
            .filter-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            }
        
            .filter-btn.active {
                background: #667eea;
                color: white;
                border-color: #667eea;
            }
        
            .search-box {
                flex: 1;
                min-width: 250px;
                padding: 10px 15px;
                border: 2px solid #e2e8f0;
                border-radius: 8px;
                font-size: 1em;
                transition: border-color 0.2s;
            }
        
            .search-box:focus {
                outline: none;
                border-color: #667eea;
            }
        
            .category-section {
                margin-bottom: 40px;
            }
        
            .category-header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 15px 25px;
                border-radius: 10px;
                font-size: 1.3em;
                font-weight: 600;
                margin-bottom: 20px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
        
            .category-badge {
                background: rgba(255,255,255,0.2);
                padding: 5px 15px;
                border-radius: 20px;
                font-size: 0.8em;
            }
        
            .finding {
                background: white;
                border-radius: 12px;
                margin-bottom: 20px;
                overflow: hidden;
                border: 1px solid #e2e8f0;
                transition: all 0.3s;
            }
        
            .finding:hover {
                box-shadow: 0 8px 16px rgba(0,0,0,0.1);
                transform: translateX(5px);
            }
        
            .finding-header {
                padding: 20px 25px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                cursor: pointer;
                background: #f7fafc;
            }
        
            .finding-header:hover {
                background: #edf2f7;
            }
        
            .finding-title {
                font-size: 1.2em;
                font-weight: 600;
                color: #2d3748;
                margin-bottom: 5px;
            }
        
            .finding-meta {
                display: flex;
                gap: 15px;
                align-items: center;
                margin-top: 8px;
            }
        
            .severity-badge {
                padding: 5px 15px;
                border-radius: 20px;
                font-size: 0.85em;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
        
            .severity-badge.critical {
                background: #feb2b2;
                color: #742a2a;
            }
        
            .severity-badge.high {
                background: #fbd38d;
                color: #7c2d12;
            }
        
            .severity-badge.medium {
                background: #faf089;
                color: #744210;
            }
        
            .severity-badge.low {
                background: #9ae6b4;
                color: #22543d;
            }
        
            .priority-score {
                font-weight: 700;
                font-size: 1.1em;
                color: #667eea;
            }
        
            .evidence-count {
                color: #718096;
                font-size: 0.9em;
            }
        
            .finding-content {
                padding: 25px;
                display: none;
                border-top: 2px solid #e2e8f0;
            }
        
            .finding.expanded .finding-content {
                display: block;
            }
        
            .finding.expanded .finding-header {
                background: white;
            }
        
            .expand-icon {
                transition: transform 0.3s;
                font-size: 1.5em;
                color: #667eea;
            }
        
            .finding.expanded .expand-icon {
                transform: rotate(180deg);
            }
        
            .description {
                font-size: 1.05em;
                line-height: 1.6;
                color: #4a5568;
                margin-bottom: 25px;
                padding: 15px;
                background: #f7fafc;
                border-left: 4px solid #667eea;
                border-radius: 5px;
            }
        
            .evidence-section {
                margin-bottom: 25px;
            }
        
            .evidence-header {
                font-size: 1.1em;
                font-weight: 600;
                margin-bottom: 15px;
                color: #2d3748;
                display: flex;
                align-items: center;
                gap: 10px;
            }
        
            .evidence-list {
                max-height: 500px;
                overflow-y: auto;
                background: #f7fafc;
                border-radius: 8px;
                padding: 15px;
            }
        
            .evidence-item {
                padding: 12px 15px;
                margin-bottom: 8px;
                background: white;
                border-left: 3px solid #667eea;
                border-radius: 5px;
                font-family: 'Courier New', monospace;
                font-size: 0.9em;
                line-height: 1.5;
                word-wrap: break-word;
                overflow-wrap: break-word;
                white-space: pre-wrap;
            }
        
            .evidence-item:hover {
                background: #edf2f7;
                border-left-color: #764ba2;
            }
        
            .recommendations {
                background: #fef5e7;
                border-left: 4px solid #f59e0b;
                border-radius: 5px;
                padding: 20px;
            }
        
            .recommendations-header {
                font-size: 1.1em;
                font-weight: 600;
                margin-bottom: 12px;
                color: #78350f;
                display: flex;
                align-items: center;
                gap: 10px;
            }
        
            .recommendations ul {
                list-style: none;
                padding-left: 0;
            }
        
            .recommendations li {
                padding: 8px 0;
                padding-left: 25px;
                position: relative;
            }
        
            .recommendations li:before {
                content: "→";
                position: absolute;
                left: 0;
                color: #f59e0b;
                font-weight: bold;
            }
        
            .footer {
                background: #2d3748;
                color: white;
                padding: 30px;
                text-align: center;
            }
        
            .footer a {
                color: #90cdf4;
                text-decoration: none;
            }
        
            .no-findings {
                text-align: center;
                padding: 60px 20px;
                color: #718096;
            }
        
            .no-findings-icon {
                font-size: 4em;
                margin-bottom: 20px;
            }
        
            /* Scrollbar styling */
            .evidence-list::-webkit-scrollbar {
                width: 8px;
            }
        
            .evidence-list::-webkit-scrollbar-track {
                background: #e2e8f0;
                border-radius: 4px;
            }
        
            .evidence-list::-webkit-scrollbar-thumb {
                background: #cbd5e0;
                border-radius: 4px;
            }
        
            .evidence-list::-webkit-scrollbar-thumb:hover {
                background: #a0aec0;
            }
        
            @media (max-width: 768px) {
                .header h1 {
                    font-size: 1.8em;
                }
            
                .stats-grid {
                    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                    gap: 15px;
                    padding: 20px;
                }
            
                .content {
                    padding: 20px;
                }
            
                .finding-header {
                    flex-direction: column;
                    align-items: flex-start;
                    gap: 10px;
                }
            }
        
            @media print {
                body {
                    background: white;
                }
            
                .container {
                    box-shadow: none;
                }
            
                .controls {
                    display: none;
                }
            
                .finding-content {
                    display: block !important;
                }
            }
        </style>
        </head>
        <body>
        <div class="container">
        """
    
        # Header
        html += f"""
            <div class="header">
                <h1>🔍 DFIR Investigation Report</h1>
                <div class="subtitle">Automated Threat Analysis & Findings</div>
                <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
            </div>
        """
    
        # Statistics
        html += f"""
            <div class="stats-grid">
                <div class="stat-card total">
                    <div class="stat-label">Total Findings</div>
                    <div class="stat-number">{stats['total']}</div>
                </div>
                <div class="stat-card critical">
                    <div class="stat-label">Critical</div>
                    <div class="stat-number">{stats['critical']}</div>
                </div>
                <div class="stat-card high">
                    <div class="stat-label">High</div>
                    <div class="stat-number">{stats['high']}</div>
                </div>
                <div class="stat-card medium">
                    <div class="stat-label">Medium</div>
                    <div class="stat-number">{stats['medium']}</div>
                </div>
                <div class="stat-card low">
                    <div class="stat-label">Low</div>
                    <div class="stat-number">{stats['low']}</div>
                </div>
            </div>
        """
    
        # Controls
        html += """
            <div class="content">
                <div class="controls">
                    <button class="filter-btn active" onclick="filterFindings('all')">All</button>
                    <button class="filter-btn" onclick="filterFindings('critical')">Critical</button>
                    <button class="filter-btn" onclick="filterFindings('high')">High</button>
                    <button class="filter-btn" onclick="filterFindings('medium')">Medium</button>
                    <button class="filter-btn" onclick="filterFindings('low')">Low</button>
                    <input type="text" class="search-box" id="searchBox" placeholder="🔍 Search findings..." onkeyup="searchFindings()">
                </div>
        """
    
        # Findings by category
        if not findings:
            html += """
                <div class="no-findings">
                    <div class="no-findings-icon">✅</div>
                    <h2>No Threats Detected</h2>
                    <p>The automated analysis did not identify any suspicious indicators.</p>
                </div>
        """
        else:
            for category, category_findings in sorted(categories.items()):
                category_findings.sort(key=lambda x: x.priority_score, reverse=True)
            
                html += f"""
                <div class="category-section">
                    <div class="category-header">
                        <span>{category}</span>
                        <span class="category-badge">{len(category_findings)} finding(s)</span>
                    </div>
        """
            
                for finding in category_findings:
                    severity_class = finding.severity.lower()
                
                    # Escape HTML in evidence
                    evidence_html = []
                    for item in finding.evidence:
                        escaped = item.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                        evidence_html.append(f'<div class="evidence-item">{escaped}</div>')
                
                    html += f"""
                    <div class="finding" data-severity="{severity_class}" onclick="toggleFinding(this)">
                        <div class="finding-header">
                            <div>
                                <div class="finding-title">{finding.title}</div>
                                <div class="finding-meta">
                                    <span class="severity-badge {severity_class}">{finding.severity}</span>
                                    <span class="priority-score">Priority: {finding.priority_score}/100</span>
                                    <span class="evidence-count">📊 {len(finding.evidence)} evidence items</span>
                                </div>
                            </div>
                            <div class="expand-icon">▼</div>
                        </div>
                        <div class="finding-content">
                            <div class="description">
                                {finding.description}
                            </div>
                        
                            <div class="evidence-section">
                                <div class="evidence-header">
                                    📁 Evidence ({len(finding.evidence)} items)
                                </div>
                                <div class="evidence-list">
                                    {''.join(evidence_html)}
                                </div>
                            </div>
                        
                            <div class="recommendations">
                                <div class="recommendations-header">
                                    💡 Recommended Actions
                                </div>
                                <ul>
                                    {''.join([f'<li>{rec}</li>' for rec in finding.recommendations])}
                                </ul>
                            </div>
                        </div>
                    </div>
        """
            
                html += """
                </div>
        """
    
        html += """
            </div>
        """
    
        # Footer
        html += """
            <div class="footer">
                <p>Generated by Enhanced DFIR Investigation Tool v2.0</p>
                <p style="margin-top: 10px; opacity: 0.8;">For questions or support, contact your security team</p>
            </div>
        </div>
    
        <script>
            function toggleFinding(element) {
                element.classList.toggle('expanded');
            }
        
            function filterFindings(severity) {
                // Update button states
                document.querySelectorAll('.filter-btn').forEach(btn => {
                    btn.classList.remove('active');
                });
                event.target.classList.add('active');
            
                // Filter findings
                const findings = document.querySelectorAll('.finding');
                findings.forEach(finding => {
                    if (severity === 'all' || finding.dataset.severity === severity) {
                        finding.style.display = 'block';
                    } else {
                        finding.style.display = 'none';
                    }
                });
            }
        
            function searchFindings() {
                const searchTerm = document.getElementById('searchBox').value.toLowerCase();
                const findings = document.querySelectorAll('.finding');
            
                findings.forEach(finding => {
                    const text = finding.textContent.toLowerCase();
                    if (text.includes(searchTerm)) {
                        finding.style.display = 'block';
                    } else {
                        finding.style.display = 'none';
                    }
                });
            }
        
            // Expand all critical findings by default
            document.addEventListener('DOMContentLoaded', () => {
                document.querySelectorAll('.finding[data-severity="critical"]').forEach(finding => {
                    finding.classList.add('expanded');
                });
            });
        </script>
        </body>
        </html>
        """
    
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)

    def generate_csv_report(self, output_file: Path, findings: List[Finding]):
        """Generate CSV report of all findings with FULL evidence"""
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Priority', 'Severity', 'Category', 'Title', 'Description', 
                           'Evidence Count', 'Full Evidence', 'Recommendations'])
            
            for finding in findings:
                # Include ALL evidence separated by newlines for better Excel viewing
                full_evidence = '\n'.join(finding.evidence)
                
                writer.writerow([
                    finding.priority_score,
                    finding.severity,
                    finding.category,
                    finding.title,
                    finding.description,
                    len(finding.evidence),
                    full_evidence,  # Changed from sample to full
                    ' | '.join(finding.recommendations)
                ])
    
    def generate_json_report(self, output_file: Path, findings: List[Finding]):
        """Generate JSON report for programmatic access"""
        
        report_data = {
            'metadata': {
                'triage_directory': str(self.triage_dir),
                'analysis_time': datetime.now().isoformat(),
                'total_findings': len(findings),
                'statistics': dict(self.stats)
            },
            'findings': [f.to_dict() for f in findings]
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
    
    def generate_executive_summary(self, output_file: Path, findings: List[Finding]):
        """Generate executive summary text report"""
        
        critical = [f for f in findings if f.severity == Finding.SEVERITY_CRITICAL]
        high = [f for f in findings if f.severity == Finding.SEVERITY_HIGH]
        
        summary = f"""
================================================================================
EXECUTIVE SUMMARY - DFIR INVESTIGATION
================================================================================

Target System: {self.triage_dir.name}
Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

================================================================================
THREAT ASSESSMENT
================================================================================

Total Findings: {len(findings)}
  - CRITICAL: {len(critical)}
  - HIGH:     {len(high)}
  - MEDIUM:   {self.stats.get('MEDIUM_findings', 0)}
  - LOW:      {self.stats.get('LOW_findings', 0)}

================================================================================
CRITICAL FINDINGS REQUIRING IMMEDIATE ACTION
================================================================================
"""
        
        if critical:
            for i, finding in enumerate(critical, 1):
                summary += f"\n{i}. {finding.title}\n"
                summary += f"   Category: {finding.category}\n"
                summary += f"   Priority Score: {finding.priority_score}/100\n"
                summary += f"   {finding.description}\n"
                summary += f"   Evidence: {len(finding.evidence)} items\n"
                summary += f"\n   IMMEDIATE ACTIONS:\n"
                for rec in finding.recommendations:
                    summary += f"   • {rec}\n"
        else:
            summary += "\nNo critical findings detected.\n"
        
        summary += f"""
================================================================================
HIGH PRIORITY FINDINGS
================================================================================
"""
        
        if high:
            for i, finding in enumerate(high, 1):
                summary += f"\n{i}. {finding.title}\n"
                summary += f"   Category: {finding.category}\n"
                summary += f"   Priority Score: {finding.priority_score}/100\n"
                summary += f"   {finding.description}\n"
        else:
            summary += "\nNo high priority findings detected.\n"
        
        summary += f"""
================================================================================
RECOMMENDATIONS
================================================================================

IMMEDIATE ACTIONS (if Critical findings exist):
1. Isolate affected systems from network
2. Preserve evidence and create forensic images
3. Document all actions taken
4. Notify incident response team and management
5. Contact law enforcement if ransomware detected

NEXT STEPS:
1. Review detailed findings in Investigation_Report.html
2. Correlate findings with other security tools (SIEM, EDR)
3. Perform deeper analysis on flagged artifacts
4. Implement recommended remediation actions
5. Update detection rules based on findings

ARTIFACTS REQUIRING MANUAL REVIEW:
• Event logs for detailed timeline reconstruction
• Memory dump for malware analysis (if collected)
• Prefetch files for execution timeline
• Browser history for full URL analysis
• Registry hives for additional persistence checks

================================================================================
END OF SUMMARY
================================================================================

For detailed evidence and technical details, review:
- Investigation_Report.html (Interactive report)
- Findings.csv (Detailed findings table)
- Investigation_Data.json (Machine-readable format)

"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(summary)
    
    def run_investigation(self):
        """Execute all analysis modules"""
        print("="*70)
        print("STARTING ENHANCED DFIR INVESTIGATION v2.0")
        print("="*70)
        
        # Core analysis modules
        self.analyze_event_logs()
        self.analyze_powershell_history()
        self.analyze_process_execution()
        self.analyze_persistence_mechanisms()
        self.analyze_network_activity()
        self.analyze_file_system()
        self.analyze_user_accounts()
        self.analyze_browser_artifacts()
        
        # Enhanced analysis modules (v2.0)
        print("\n[*] Running enhanced analysis modules...")
        self.analyze_shimcache_bam_dam()
        self.analyze_prefetch_files()
        self.analyze_scheduled_tasks()
        self.analyze_services()
        self.analyze_vss_shadow_copies()
        self.analyze_defender_detections()
        self.analyze_drivers()
        self.analyze_environment_variables()
        
        # Generate reports
        self.generate_report()
        
        print("\n" + "="*70)
        print("INVESTIGATION COMPLETE")
        print("="*70)
        print(f"\nTotal Findings: {len(self.findings)}")
        print(f"  CRITICAL: {self.stats.get('CRITICAL_findings', 0)}")
        print(f"  HIGH:     {self.stats.get('HIGH_findings', 0)}")
        print(f"  MEDIUM:   {self.stats.get('MEDIUM_findings', 0)}")
        print(f"  LOW:      {self.stats.get('LOW_findings', 0)}")
        print(f"\nReview reports in: {self.output_dir}")


def main():
    parser = argparse.ArgumentParser(
        description="Automated DFIR Investigation Tool for Ransomware and Financial Threat Actors",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ransomware_investigator.py -d C:\\Triage_DESKTOP-ABC_20250214_120000
  python ransomware_investigator.py -d ./triage_data -i custom_indicators.json
  python ransomware_investigator.py -d /mnt/cases/case001/triage
        """
    )
    
    parser.add_argument('-d', '--directory', required=True,
                       help='Path to triage collection directory')
    parser.add_argument('-i', '--indicators', default='threat_indicators.json',
                       help='Path to threat indicators JSON file (default: threat_indicators.json)')
    
    args = parser.parse_args()
    
    # Validate directory
    triage_path = Path(args.directory)
    if not triage_path.exists():
        print(f"[!] Error: Triage directory not found: {triage_path}")
        sys.exit(1)
    
    # Run investigation
    hunter = ThreatHunter(str(triage_path), args.indicators)
    hunter.run_investigation()


if __name__ == "__main__":
    main()
