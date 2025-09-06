# Linux Digital Forensics Workflow

## Table of Contents
- [Phase 1: Initial System Assessment & Preparation](#phase-1-initial-system-assessment--preparation)
- [Phase 2: Memory Analysis](#phase-2-memory-analysis-critical---do-this-first)
- [Phase 3: Process Analysis](#phase-3-process-analysis)
- [Phase 4: Network Analysis](#phase-4-network-analysis)
- [Phase 5: File System Analysis](#phase-5-file-system-analysis)
- [Phase 6: Hash Computation and File Integrity](#phase-6-hash-computation-and-file-integrity)
- [Phase 7: YARA Scanning](#phase-7-yara-scanning)
- [Phase 8: Log Analysis](#phase-8-log-analysis)
- [Phase 9: User and Account Analysis](#phase-9-user-and-account-analysis)
- [Phase 10: System Configuration Analysis](#phase-10-system-configuration-analysis)
- [Phase 11: Artifact Collection and Analysis](#phase-11-artifact-collection-and-analysis)
- [Phase 12: String Analysis](#phase-12-string-analysis)
- [Phase 13: Timeline Analysis](#phase-13-timeline-analysis)
- [Phase 14: Documentation and Reporting](#phase-14-documentation-and-reporting)
- [Phase 15: Advanced Analysis](#phase-15-advanced-analysis-optional)
- [Important Notes](#important-notes)
- [Recommended Additional Tools](#recommended-additional-tools)

---

## Phase 1: Initial System Assessment & Preparation

### 1.1 Document Current State

```bash
# Record current date/time
date
uptime
whoami
hostname

# Document kernel and system info
uname -a
lsb_release -a
cat /etc/os-release
```

### 1.2 Create Working Directory

```bash
# Create forensics workspace
mkdir /tmp/forensics_$(date +%Y%m%d_%H%M%S)
cd /tmp/forensics_*
```

## Phase 2: Memory Analysis (Critical - Do This First!)

### 2.1 Memory Acquisition

```bash
# Create memory dump (requires root)
sudo dd if=/dev/mem of=memory_dump.raw bs=1M

# Alternative: Use /proc/kcore for kernel memory
sudo dd if=/proc/kcore of=kernel_memory.raw bs=1M count=100

# For better memory analysis, install lime or fmem if available
# lime: Linux Memory Extractor
# fmem: Forensic memory extractor
```

> **⚠️ Critical Note**: Memory analysis should be performed first as memory is volatile and can change rapidly.

### 2.2 Memory Analysis with Native Tools

```bash
# Analyze memory maps of running processes
for pid in $(ps -eo pid --no-headers); do
    echo "=== Process $pid ==="
    cat /proc/$pid/maps 2>/dev/null | head -20
done > memory_maps.txt

# Check memory info
cat /proc/meminfo > meminfo.txt
cat /proc/vmstat > vmstat.txt
```

## Phase 3: Process Analysis

### 3.1 Running Processes

```bash
# Comprehensive process listing
ps aux > processes_full.txt
ps -ef > processes_tree.txt
ps -eo pid,ppid,cmd,etime,user > processes_detailed.txt

# Process tree visualization
pstree -p > process_tree.txt
pstree -a -p > process_tree_args.txt

# Process relationships and sessions
ps -ejo pid,ppid,pgid,sid,comm > process_sessions.txt
```

### 3.2 Process Deep Analysis
```bash
# For each suspicious process, analyze:
for pid in $(ps -eo pid --no-headers); do
    if [ -d "/proc/$pid" ]; then
        echo "=== Analyzing PID $pid ===" >> process_analysis.txt
        echo "Command: $(cat /proc/$pid/cmdline 2>/dev/null)" >> process_analysis.txt
        echo "CWD: $(readlink /proc/$pid/cwd 2>/dev/null)" >> process_analysis.txt
        echo "Executable: $(readlink /proc/$pid/exe 2>/dev/null)" >> process_analysis.txt
        echo "Open files:" >> process_analysis.txt
        lsof -p $pid 2>/dev/null >> process_analysis.txt
        echo -e "\nEnvironment:" >> process_analysis.txt
        cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' >> process_analysis.txt
        echo -e "\n" >> process_analysis.txt
    fi
done
```

## Phase 4: Network Analysis

### 4.1 Network Connections

```bash
# Current network connections
netstat -tulpn > network_listening.txt
netstat -an > network_all.txt
ss -tulpn > ss_listening.txt
ss -a > ss_all.txt

# Network routing and interfaces
ip route > routing_table.txt
ip addr show > interfaces.txt
arp -a > arp_table.txt
```

### 4.2 Network Process Mapping

```bash
# Map network connections to processes
lsof -i > network_process_map.txt
```

## Phase 5: File System Analysis

### 5.1 File System Overview

```bash
# Mounted file systems
mount > mounted_filesystems.txt
df -h > disk_usage.txt
lsblk > block_devices.txt

# File system types and options
cat /proc/mounts > proc_mounts.txt
```

### 5.2 Critical Directory Analysis

```bash
# System directories with detailed attributes
ls -la /bin /sbin /usr/bin /usr/sbin > system_binaries.txt
ls -la /etc > etc_contents.txt
ls -la /tmp /var/tmp > temp_dirs.txt
ls -la /home > home_dirs.txt
ls -la /root > root_dir.txt

# Recently modified files (last 7 days)
find / -type f -mtime -7 2>/dev/null > recent_files.txt

# SUID/SGID files
find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null > suid_sgid_files.txt

# World-writable files
find / -type f -perm -002 2>/dev/null > world_writable_files.txt

# Hidden files in common locations
find /home /tmp /var/tmp -name ".*" -type f 2>/dev/null > hidden_files.txt
```

> **🔍 Security Focus**: Pay special attention to SUID/SGID files and world-writable files as they can be attack vectors.

### 5.3 Large Files and Anomalies

```bash
# Find large files (>100MB)
find / -type f -size +100M 2>/dev/null > large_files.txt

# Find files with no user/group
find / -nouser -o -nogroup 2>/dev/null > orphaned_files.txt
```

## Phase 6: Hash Computation and File Integrity

### 6.1 System Binary Hashing

```bash
# Hash critical system binaries
echo "=== System Binary Hashes ===" > system_hashes.txt
for binary in /bin/* /sbin/* /usr/bin/* /usr/sbin/*; do
    if [ -f "$binary" ]; then
        echo "File: $binary" >> system_hashes.txt
        md5sum "$binary" 2>/dev/null >> system_hashes.txt
        sha256sum "$binary" 2>/dev/null >> system_hashes.txt
        echo "" >> system_hashes.txt
    fi
done
```

> **🔒 Integrity Check**: Compare these hashes against known good values to detect potential tampering.

### 6.2 Suspicious File Hashing

```bash
# Hash recent and suspicious files
while read -r file; do
    echo "=== $file ===" >> suspicious_hashes.txt
    md5sum "$file" 2>/dev/null >> suspicious_hashes.txt
    sha256sum "$file" 2>/dev/null >> suspicious_hashes.txt
    echo "" >> suspicious_hashes.txt
done < recent_files.txt
```

## Phase 7: YARA Scanning

### 7.1 Install and Setup YARA

```bash
# Install YARA (if not available)
# Ubuntu/Debian: sudo apt-get install yara
# CentOS/RHEL: sudo yum install yara

# Download common YARA rules
mkdir yara_rules
cd yara_rules
# Download from repositories like:
# - https://github.com/Yara-Rules/rules
# - https://github.com/Neo23x0/signature-base
```

**Popular YARA Rule Repositories:**
- [Yara-Rules/rules](https://github.com/Yara-Rules/rules) - Community rules
- [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) - Florian Roth's signature base
- [reversinglabs/reversinglabs-yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules) - ReversingLabs rules

### 7.2 YARA Scanning

```bash
# Scan system directories
yara -r /path/to/yara/rules /bin/ > yara_bin_scan.txt
yara -r /path/to/yara/rules /sbin/ > yara_sbin_scan.txt
yara -r /path/to/yara/rules /tmp/ > yara_tmp_scan.txt
yara -r /path/to/yara/rules /home/ > yara_home_scan.txt

# Scan running processes (if YARA supports it)
yara -r /path/to/yara/rules /proc/ > yara_proc_scan.txt 2>/dev/null
```

> **🎯 Targeting**: Focus YARA scans on high-risk directories like `/tmp`, `/var/tmp`, and user home directories.

## Phase 8: Log Analysis

### 8.1 System Logs

```bash
# System logs
cp /var/log/syslog syslog_backup.txt
cp /var/log/auth.log auth_backup.txt
cp /var/log/messages messages_backup.txt 2>/dev/null

# Journal logs (systemd)
journalctl --no-pager > journal_all.txt
journalctl -u ssh --no-pager > journal_ssh.txt
journalctl --since "1 hour ago" --no-pager > journal_recent.txt
```

### 8.2 Authentication and Access Logs

```bash
# Last logins
last > last_logins.txt
lastlog > last_user_logins.txt

# Failed login attempts
grep "Failed password" /var/log/auth.log > failed_logins.txt
grep "authentication failure" /var/log/auth.log >> failed_logins.txt

# Sudo usage
grep "sudo" /var/log/auth.log > sudo_usage.txt
```

> **🔍 Key Indicators**: Look for patterns in failed login attempts, unusual sudo usage, and logins from unexpected locations.

## Phase 9: User and Account Analysis

### 9.1 User Information

```bash
# User accounts
cat /etc/passwd > users_passwd.txt
cat /etc/shadow > users_shadow.txt 2>/dev/null
cat /etc/group > users_groups.txt

# Currently logged in users
who > current_users.txt
w > user_activity.txt

# User login history
utmpdump /var/log/wtmp > login_history.txt 2>/dev/null
utmpdump /var/log/btmp > failed_login_history.txt 2>/dev/null
```

### 9.2 User Files and Configurations

```bash
# User shell histories
for user_home in /home/*; do
    if [ -d "$user_home" ]; then
        echo "=== $user_home ===" >> user_histories.txt
        cat "$user_home/.bash_history" 2>/dev/null >> user_histories.txt
        cat "$user_home/.zsh_history" 2>/dev/null >> user_histories.txt
        echo -e "\n" >> user_histories.txt
    fi
done

# Check root history
cat /root/.bash_history > root_history.txt 2>/dev/null
```

> **📜 Historical Evidence**: Shell histories can reveal commands executed by users, including potential attack vectors.

## Phase 10: System Configuration Analysis

### 10.1 Services and Startup

```bash
# System services
systemctl list-units --type=service > systemd_services.txt
systemctl list-unit-files --type=service > systemd_service_files.txt

# Startup scripts
ls -la /etc/init.d/ > initd_scripts.txt
ls -la /etc/systemd/system/ > systemd_units.txt

# Cron jobs
crontab -l > root_crontab.txt 2>/dev/null
ls -la /var/spool/cron/crontabs/ > user_crontabs.txt 2>/dev/null
cat /etc/crontab > system_crontab.txt
ls -la /etc/cron.* > cron_dirs.txt
```

> **⏰ Persistence Mechanisms**: Pay attention to unusual services and scheduled tasks that could provide persistence for attackers.

### 10.2 Kernel and Module Analysis

```bash
# Loaded kernel modules
lsmod > loaded_modules.txt
cat /proc/modules > proc_modules.txt

# Kernel parameters
sysctl -a > kernel_parameters.txt
```

> **🔌 Rootkit Detection**: Unusual or unknown kernel modules may indicate rootkit installation.

## Phase 11: Artifact Collection and Analysis

### 11.1 Browser Artifacts (if GUI system)

```bash
# Firefox profiles
find /home -name "places.sqlite" 2>/dev/null > browser_artifacts.txt
find /home -name "cookies.sqlite" 2>/dev/null >> browser_artifacts.txt
find /home -name "downloads.sqlite" 2>/dev/null >> browser_artifacts.txt

# Chrome profiles
find /home -path "*/.config/google-chrome/Default/History" 2>/dev/null >> browser_artifacts.txt
find /home -path "*/.config/google-chrome/Default/Cookies" 2>/dev/null >> browser_artifacts.txt
```

**Browser Artifact Locations:**
- **Firefox**: `~/.mozilla/firefox/*/`
- **Chrome**: `~/.config/google-chrome/Default/`
- **Edge**: `~/.config/microsoft-edge/Default/`

### 11.2 Application Artifacts

```bash
# Recently accessed files
find /home -name ".recently-used*" 2>/dev/null > recent_access.txt
find /home -name "*.tmp" -mtime -1 2>/dev/null > recent_temp_files.txt

# Configuration files
find /home -name ".*rc" 2>/dev/null > config_files.txt
find /home -name ".*.conf" 2>/dev/null >> config_files.txt
```

## Phase 12: String Analysis

### 12.1 String Extraction from Suspicious Files

```bash
# Extract strings from suspicious binaries
while read -r file; do
    if [ -f "$file" ]; then
        echo "=== Strings from $file ===" >> string_analysis.txt
        strings "$file" | head -100 >> string_analysis.txt
        echo -e "\n" >> string_analysis.txt
    fi
done < suspicious_files.txt

# Look for specific indicators
strings /bin/* /sbin/* | grep -i -E "(password|admin|root|hack|exploit)" > suspicious_strings.txt
```

**Common Suspicious String Patterns:**
- Network indicators: IP addresses, URLs, domain names
- Credentials: "password", "admin", "root"
- Attack indicators: "exploit", "payload", "backdoor"
- Encryption: "key", "cipher", "encrypt"

### 12.2 Memory String Analysis

```bash
# Extract strings from memory dump (if created)
if [ -f "memory_dump.raw" ]; then
    strings memory_dump.raw | grep -v "^.$" > memory_strings.txt
    # Look for specific patterns in memory
    strings memory_dump.raw | grep -i -E "(http|ftp|password|key)" > memory_indicators.txt
fi
```

## Phase 13: Timeline Analysis

### 13.1 File Timeline Creation

```bash
# Create timeline of file modifications
find / -type f -newermt "2024-01-01" ! -newermt "$(date +%Y-%m-%d)" -exec ls -la {} \; 2>/dev/null | sort -k6,8 > file_timeline.txt

# Access time timeline
find / -type f -atime -7 -exec ls -lau {} \; 2>/dev/null > access_timeline.txt
```

> **⏱️ Timeline Analysis**: Correlate file access and modification times with known incident timeframes to identify related activities.

## Phase 14: Documentation and Reporting

### 14.1 Create Investigation Summary

```bash
# System summary
echo "=== FORENSIC INVESTIGATION SUMMARY ===" > investigation_summary.txt
echo "Investigation Date: $(date)" >> investigation_summary.txt
echo "System: $(hostname)" >> investigation_summary.txt
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME)" >> investigation_summary.txt
echo "Kernel: $(uname -r)" >> investigation_summary.txt
echo "Uptime: $(uptime)" >> investigation_summary.txt
echo "" >> investigation_summary.txt

# File counts
echo "Files collected:" >> investigation_summary.txt
wc -l *.txt >> investigation_summary.txt
```

### 14.2 Enhanced Evidence Packaging
```bash
# Create comprehensive evidence manifest
find "$EVID" -type f -exec sha256sum {} + | sort -k2 > "$EVID/hashes/manifest.sha256"
hash_evidence "$EVID/hashes/manifest.sha256"

# Package with extended attributes, ACLs, and numeric ownership preserved
sudo tar --xattrs --acls --numeric-owner --one-file-system -cpf - "$EVID" | gzip -1 > \
  "/mnt/forensics/${CASE}.tar.gz"

# Final hash of the complete evidence package
sha256sum "/mnt/forensics/${CASE}.tar.gz" | tee -a "$EVID/hashes/SHA256.txt"

# Create chain of custody document
{
  echo "=== CHAIN OF CUSTODY ==="
  echo "Case: $CASE"
  echo "Investigator: $(whoami)"
  echo "Collection Date: $(date -u)"
  echo "System: $(hostname)"
  echo "Evidence Package: ${CASE}.tar.gz"
  echo "Package Hash: $(tail -1 "$EVID/hashes/SHA256.txt")"
  echo ""
  echo "=== EVIDENCE INVENTORY ==="
  wc -l "$EVID"/**/*.txt | tail -1
  echo ""
  echo "=== HASH VERIFICATION ==="
  echo "Total hashes recorded: $(wc -l < "$EVID/hashes/SHA256.txt")"
} > "/mnt/forensics/${CASE}_custody.txt"
```

## Phase 15: Advanced Analysis (Optional)

### 15.1 Disk Image Analysis

```bash
# If you can create disk images
sudo dd if=/dev/sda of=disk_image.raw bs=4M status=progress
# Use tools like sleuthkit for analysis:
# fls, ils, icat, mmls, fsstat
```

**Sleuthkit Tools:**
- `mmls` - Display partition layout
- `fsstat` - File system statistics
- `fls` - List files and directories
- `icat` - Extract file content by inode
- `ils` - List inodes

### 15.2 Network Packet Capture

```bash
# If still responding to incident
sudo tcpdump -i any -w network_capture.pcap &
TCPDUMP_PID=$!
sleep 300  # Capture for 5 minutes
kill $TCPDUMP_PID
```

> **📶 Live Capture**: Only perform live packet capture if the incident is ongoing and you need to observe real-time network activity.

---

## Important Notes

> **⚠️ Critical Guidelines for Digital Forensics**

### 1. **Run as root when necessary** 
Many forensic commands require root privileges to access system files and memory.

### 2. **Minimize system impact** 
Avoid writing to the system being investigated when possible. Use external storage for evidence collection.

### 3. **Chain of custody** 
Document all actions and maintain evidence integrity throughout the investigation.

### 4. **Time sensitivity** 
Memory analysis should be done first as it's volatile and changes rapidly.

### 5. **Legal considerations** 
Ensure you have proper authorization before investigation. Follow organizational policies and legal requirements.

### 6. **Tool validation** 
Verify hash integrity of forensic tools before use to ensure evidence integrity.

---

## Recommended Additional Tools

### Memory Analysis
- **[Volatility](https://www.volatilityfoundation.org/)** - Advanced memory analysis framework
- **[Rekall](http://www.rekall-forensic.com/)** - Memory forensic framework

### File System Analysis  
- **[The Sleuth Kit (TSK)](https://www.sleuthkit.org/)** - File system analysis tools
- **[Autopsy](https://www.autopsy.com/)** - Digital forensics platform with GUI

### Pattern Matching & Detection
- **[YARA](https://virustotal.github.io/yara/)** - Pattern matching engine for malware research
- **[Bulk Extractor](https://github.com/simsong/bulk_extractor)** - Feature extraction from digital media

### Timeline & Log Analysis
- **[Log2Timeline](https://github.com/log2timeline/plaso)** - Timeline analysis tools
- **[Timesketch](https://github.com/google/timesketch)** - Collaborative forensic timeline analysis

### Network Analysis
- **[Wireshark](https://www.wireshark.org/)** - Network protocol analyzer
- **[NetworkMiner](https://www.netresec.com/?page=NetworkMiner)** - Network forensic analysis tool

### Disk Imaging & Recovery
- **[dd](https://www.gnu.org/software/coreutils/manual/html_node/dd-invocation.html)** - Built-in disk imaging utility
- **[dcfldd](http://dcfldd.sourceforge.net/)** - Enhanced dd with forensic features
- **[Guymager](https://guymager.sourceforge.io/)** - Forensic imaging tool with GUI

---

## Quick Reference Commands

### Emergency Response Priority Order
1. **Memory dump** (most volatile)
2. **Running processes** 
3. **Network connections**
4. **File system snapshot**
5. **Log collection**
6. **Detailed analysis**

### One-liner Evidence Collection
```bash
# Quick system snapshot
mkdir evidence_$(date +%Y%m%d_%H%M%S) && cd $_ && \
ps aux > processes.txt && \
netstat -tulpn > network.txt && \
mount > mounts.txt && \
df -h > diskspace.txt && \
last > logins.txt
```

---

*This workflow provides a comprehensive approach to Linux digital forensics. Always adapt procedures to specific incident requirements and organizational policies.*