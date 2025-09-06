import os
import subprocess
import re
import shlex
from typing import Dict, List, Optional

# Google ADK imports
from google.adk.agents import Agent
from google.adk.agents import SequentialAgent
from google.adk.agents import ParallelAgent


class ForensicsCommandValidator:
    """Validates and categorizes forensics commands for safe execution"""
    
    def __init__(self):
        # Comprehensive forensics command categories based on the automation script
        self.command_categories = {
            # System Information & Context
            "system_info": [
                "date", "uptime", "whoami", "hostname", "uname", "lsb_release", 
                "hostnamectl", "who", "w", "id", "getent"
            ],
            
            # Process Analysis
            "process_analysis": [
                "ps", "pstree", "pgrep", "pidof", "jobs"
            ],
            
            # Memory Analysis
            "memory_analysis": [
                "cat /proc/meminfo", "cat /proc/vmstat", "cat /proc/slabinfo",
                "cat /proc/swaps", "cat /proc/*/maps", "cat /proc/*/cmdline",
                "cat /proc/*/environ", "cat /proc/*/exe", "cat /proc/*/cwd"
            ],
            
            # Network Analysis
            "network_analysis": [
                "netstat", "ss", "lsof", "ip", "arp", "resolvectl", 
                "nft list ruleset", "iptables"
            ],
            
            # File System Analysis
            "filesystem_analysis": [
                "ls", "find", "mount", "df", "lsblk", "blkid", "file", 
                "stat", "readlink", "tree"
            ],
            
            # Hash Computation
            "hash_analysis": [
                "md5sum", "sha256sum", "sha1sum", "sha512sum"
            ],
            
            # String Analysis
            "string_analysis": [
                "strings", "hexdump", "xxd", "od"
            ],
            
            # Log Analysis
            "log_analysis": [
                "cat /var/log/*", "journalctl", "last", "lastlog", "utmpdump",
                "grep", "awk", "sed", "head", "tail", "wc"
            ],
            
            # System Configuration
            "system_config": [
                "systemctl", "crontab", "lsmod", "sysctl", "cat /etc/*",
                "cat /proc/modules"
            ],
            
            # Package Analysis
            "package_analysis": [
                "dpkg", "rpm", "yum", "dnf", "pacman"
            ],
            
            # Archive and Compression (read-only)
            "archive_analysis": [
                "tar -t", "gunzip -t", "unzip -l", "zcat", "bzcat"
            ]
        }
        
        # Dangerous commands that should never be allowed
        self.forbidden_commands = [
            "rm", "mv", "cp", "dd", "mkfs", "fdisk", "parted", "mount",
            "umount", "kill", "killall", "shutdown", "reboot", "halt",
            "passwd", "useradd", "userdel", "usermod", "groupadd", "groupdel",
            "chmod", "chown", "chgrp", "su", "sudo", "systemctl start",
            "systemctl stop", "systemctl restart", "systemctl enable",
            "systemctl disable", "service", "init", "telinit", "write",
            "wall", "echo >", "cat >", "tee", "redirect"
        ]
    
    def is_safe_command(self, command: str) -> bool:
        """Check if a command is safe for forensics analysis"""
        command = command.strip().lower()
        
        # Check for forbidden commands
        for forbidden in self.forbidden_commands:
            if forbidden in command:
                return False
        
        # Check for output redirection (potentially dangerous)
        if any(redirect in command for redirect in [">", ">>", "|", "&"]):
            # Allow pipes for analysis but not file redirection
            if ">" in command and not any(safe in command for safe in ["grep", "awk", "head", "tail", "sort"]):
                return False
        
        # Check if command starts with allowed forensics tools
        all_allowed = []
        for category in self.command_categories.values():
            all_allowed.extend(category)
        
        # Extract the base command
        base_command = command.split()[0] if command.split() else ""
        
        # Special handling for /proc and /sys reads
        if command.startswith("cat /proc/") or command.startswith("cat /sys/"):
            return True
        
        # Special handling for log file reads
        if command.startswith("cat /var/log/") or command.startswith("grep"):
            return True
        
        # Check against allowed commands
        return any(base_command.startswith(allowed.split()[0]) for allowed in all_allowed)
    
    def get_command_category(self, command: str) -> Optional[str]:
        """Get the forensics category of a command"""
        command = command.strip().lower()
        
        for category, commands in self.command_categories.items():
            if any(command.startswith(allowed.split()[0]) for allowed in commands):
                return category
        
        return None


# Enhanced forensics command execution function
def system_command(command: str) -> str:
    """
    Execute forensics commands safely with comprehensive validation and error handling.
    
    Args:
        command: The forensics command to execute
        
    Returns:
        Command output or error message
    """
    validator = ForensicsCommandValidator()
    
    try:
        # Input validation
        if not command or not command.strip():
            return "Error: Empty command provided"
        
        command = command.strip()
        
        # Safety check
        if not validator.is_safe_command(command):
            return f"Command '{command}' not allowed for safety reasons. Only read-only forensics commands are permitted."
        
        # Get command category for logging
        category = validator.get_command_category(command)
        
        # Execute with timeout and proper error handling
        result = subprocess.run(
            command,
            shell=True,
            text=True,
            capture_output=True,
            timeout=60,  # Increased timeout for complex forensics commands
            cwd="/",  # Start from root for consistent paths
        )
        
        # Handle command output
        if result.returncode == 0:
            output = result.stdout.strip()
            if category:
                return f"[{category.upper()}] Command executed successfully:\n{output}"
            else:
                return f"Command executed successfully:\n{output}"
        else:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            return f"Command failed (exit code {result.returncode}): {error_msg}"
    
    except subprocess.TimeoutExpired:
        return f"Command '{command}' timed out after 60 seconds"
    except subprocess.CalledProcessError as e:
        return f"Error executing command '{command}': {e.output if e.output else str(e)}"
    except PermissionError:
        return f"Permission denied executing '{command}'. May require elevated privileges."
    except FileNotFoundError:
        return f"Command '{command}' not found. Tool may not be installed."
    except Exception as e:
        return f"Unexpected error executing '{command}': {str(e)}"


# Enhanced forensics analysis function for complex operations
def analyze_forensics_data(analysis_type: str, target: str = "") -> str:
    """
    Perform complex forensics analysis operations.
    
    Args:
        analysis_type: Type of analysis (process_tree, network_connections, file_timeline, etc.)
        target: Optional target for analysis (PID, file path, etc.)
        
    Returns:
        Analysis results
    """
    try:
        if analysis_type == "process_tree":
            cmd = "ps auxfww"
            result = system_command(cmd)
            return f"Process Tree Analysis:\n{result}"
        
        elif analysis_type == "network_connections":
            commands = [
                "ss -tulpn",
                "netstat -tulpn", 
                "lsof -i -n -P"
            ]
            results = []
            for cmd in commands:
                result = system_command(cmd)
                results.append(f"=== {cmd} ===\n{result}\n")
            return "\n".join(results)
        
        elif analysis_type == "suspicious_files":
            commands = [
                "find /tmp -type f -mtime -1",
                "find /var/tmp -type f -mtime -1",
                "find /home -name '.*' -type f",
                "find / -type f -perm -4000 2>/dev/null | head -20"
            ]
            results = []
            for cmd in commands:
                result = system_command(cmd)
                results.append(f"=== {cmd} ===\n{result}\n")
            return "\n".join(results)
        
        elif analysis_type == "system_context":
            commands = [
                "date",
                "hostname", 
                "uname -a",
                "uptime",
                "who",
                "last | head -10"
            ]
            results = []
            for cmd in commands:
                result = system_command(cmd)
                results.append(f"{cmd}: {result}")
            return "\n".join(results)
        
        elif analysis_type == "memory_analysis" and target:
            if target.isdigit():  # PID provided
                commands = [
                    f"cat /proc/{target}/cmdline",
                    f"readlink /proc/{target}/exe",
                    f"readlink /proc/{target}/cwd", 
                    f"cat /proc/{target}/environ | tr '\\0' '\\n' | head -20"
                ]
                results = []
                for cmd in commands:
                    result = system_command(cmd)
                    results.append(f"=== {cmd} ===\n{result}\n")
                return "\n".join(results)
        
        else:
            return f"Unknown analysis type: {analysis_type}"
    
    except Exception as e:
        return f"Error in forensics analysis: {str(e)}"


# Root forensic agent
root_agent = Agent(
    model="gemini-2.5-pro",
    name="forensics_investigation_agent",
    description="Advanced Linux Digital Forensics Investigation Agent",
    instruction="""
You are an expert digital forensics investigator specializing in Linux systems. Your mission is to conduct thorough, methodical investigations following established forensics protocols while maintaining evidence integrity.

## INVESTIGATION METHODOLOGY

### Phase 1: Initial System Assessment & Preparation
- Document current system state (date, uptime, users, hostname)
- Record kernel version, OS details, and system architecture
- Identify currently logged-in users and recent login activity
- Establish investigation timeline baseline

### Phase 2: Volatile Data Collection (PRIORITY - Most Critical)
- Analyze running processes with detailed parent-child relationships
- Map process memory layouts and command-line arguments
- Capture network connections and listening services
- Document open file descriptors and process working directories
- Record system resource usage and memory statistics

### Phase 3: Process Analysis
- Examine suspicious processes and their execution contexts
- Analyze process trees for unusual parent-child relationships
- Investigate processes running from unusual locations
- Check for processes with suspicious names or hidden processes
- Validate process executables and their integrity

### Phase 4: Network Analysis
- Map all network connections (TCP/UDP, listening/established)
- Identify processes associated with network activity
- Analyze network routing tables and interface configurations
- Check for unusual network services or backdoors
- Examine firewall rules and network security configurations

### Phase 5: File System Analysis
- Search for recently modified files (last 7 days)
- Identify SUID/SGID files and world-writable files
- Locate hidden files in common attack vectors (/tmp, /var/tmp, home dirs)
- Find large files that might indicate data staging
- Analyze file permissions and ownership anomalies

### Phase 6: Hash Computation & Integrity
- Compute SHA-256 hashes of critical system binaries
- Hash suspicious or recently modified files
- Compare against known-good baselines when possible
- Document file integrity for evidence chain of custody

### Phase 7: System Configuration Analysis
- Examine system services and startup configurations
- Analyze cron jobs and scheduled tasks
- Check kernel modules for potential rootkits
- Review user accounts and group memberships
- Investigate SSH configurations and authorized keys

### Phase 8: Log Analysis
- Analyze authentication logs for failed/suspicious logins
- Review system logs for error patterns and anomalies
- Examine user command histories (bash, zsh, etc.)
- Check for log tampering or gaps in logging
- Correlate log entries with timeline of suspected compromise

### Phase 9: String & Binary Analysis
- Extract strings from suspicious binaries
- Look for hardcoded IP addresses, URLs, or credentials
- Identify packing or obfuscation indicators
- Search for known malware signatures or patterns

### Phase 10: Timeline Analysis
- Create chronological timeline of file modifications
- Correlate system events with file access patterns
- Identify periods of suspicious activity
- Map attack progression through timestamp analysis

## INVESTIGATION TOOLS AVAILABLE

### Core Commands:
- `system_command(cmd)`: Execute forensics commands safely
- `analyze_forensics_data(type, target)`: Perform complex analysis operations

### Analysis Types for analyze_forensics_data():
- "system_context": Complete system overview
- "process_tree": Detailed process analysis
- "network_connections": Comprehensive network mapping
- "suspicious_files": Find potentially malicious files
- "memory_analysis": Deep process memory examination (provide PID as target)

### Supported Command Categories:
- System Info: date, hostname, uname, uptime, who, id
- Process Analysis: ps, pstree, pgrep, jobs
- Memory Analysis: /proc filesystem access
- Network Analysis: netstat, ss, lsof, ip, arp
- File System: ls, find, mount, df, lsblk, stat
- Hash Analysis: sha256sum, md5sum, sha1sum
- String Analysis: strings, hexdump, xxd
- Log Analysis: journalctl, last, grep, awk, head, tail
- System Config: systemctl, lsmod, sysctl
- Package Analysis: dpkg, rpm (read-only operations)

## CRITICAL INVESTIGATION PRINCIPLES

### Evidence Integrity:
- Never modify the system under investigation
- Document all commands executed and their timestamps
- Maintain detailed chain of custody
- Use read-only commands exclusively

### Security Indicators to Prioritize:
- Processes running from /tmp, /dev/shm, or other unusual locations
- Network connections to suspicious IPs or unusual ports
- Recently modified system binaries or configuration files
- Hidden files or files with suspicious names
- SUID binaries in non-standard locations
- Unusual user accounts or elevated privileges
- Gaps or anomalies in system logs
- Processes with no parent or unusual process trees

### Investigation Flow:
1. Start with volatile data (processes, network, memory)
2. Progress to persistent artifacts (files, logs, configurations)
3. Perform integrity checks and timeline analysis
4. Correlate findings across all data sources
5. Generate comprehensive forensics report

### Reporting Requirements:
- Executive summary of key findings
- Detailed technical analysis with evidence
- Timeline of suspected attack activities
- Indicators of Compromise (IoCs) identified
- Recommended remediation actions
- Evidence preservation documentation

## OPERATIONAL GUIDELINES

- Always explain your investigative approach before executing commands
- Provide context for why specific evidence is important
- Highlight suspicious findings with clear explanations
- Suggest additional investigation paths when relevant
- Maintain professional forensics terminology
- Document any limitations or areas requiring further analysis

Remember: You are conducting a live system investigation. Prioritize volatile data collection first, as this information can change rapidly. Be thorough but efficient, and always maintain the integrity of the evidence.
""",
    tools=[system_command, analyze_forensics_data]
)
