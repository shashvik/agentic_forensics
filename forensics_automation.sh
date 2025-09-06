#!/usr/bin/env bash
#
# Linux Digital Forensics Script
# Complete end-to-end forensic investigation tool
# 
# Usage: sudo ./linux_forensics.sh [evidence_path]
#
# Author: Digital Forensics Workflow
# Version: 2.0
# Dependencies: Automatically installs required tools
#

set -euo pipefail

# Override exit on error for specific sections
set_error_handling() {
    if [[ "${1:-}" == "strict" ]]; then
        set -euo pipefail
    else
        set +e  # Don't exit on error
        set -uo pipefail  # Keep undefined variable and pipe failure checks
    fi
}

# Script configuration
SCRIPT_VERSION="2.0"
SCRIPT_NAME="Linux Forensics Investigation Script"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    if [[ -n "${LOG_FILE:-}" ]]; then
        echo -e "${GREEN}[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] $1${NC}" | tee -a "$LOG_FILE"
    else
        echo -e "${GREEN}[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] $1${NC}"
    fi
}

log_warn() {
    if [[ -n "${LOG_FILE:-}" ]]; then
        echo -e "${YELLOW}[WARNING] $1${NC}" | tee -a "$LOG_FILE"
    else
        echo -e "${YELLOW}[WARNING] $1${NC}"
    fi
}

log_error() {
    if [[ -n "${LOG_FILE:-}" ]]; then
        echo -e "${RED}[ERROR] $1${NC}" | tee -a "$LOG_FILE"
    else
        echo -e "${RED}[ERROR] $1${NC}"
    fi
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root for complete forensic analysis"
        log "Usage: sudo $0 [evidence_path]"
        exit 1
    fi
}

# Detect OS distribution
detect_os() {
    if command -v apt-get >/dev/null 2>&1; then
        OS_TYPE="debian"
        INSTALL_CMD="apt-get update && apt-get install -y"
    elif command -v yum >/dev/null 2>&1; then
        OS_TYPE="rhel"
        INSTALL_CMD="yum install -y"
    elif command -v dnf >/dev/null 2>&1; then
        OS_TYPE="fedora" 
        INSTALL_CMD="dnf install -y"
    elif command -v pacman >/dev/null 2>&1; then
        OS_TYPE="arch"
        INSTALL_CMD="pacman -Sy --noconfirm"
    else
        OS_TYPE="unknown"
        log_warn "Unknown OS distribution. Some dependencies may not install automatically."
    fi
    log "Detected OS type: $OS_TYPE"
}

# Install dependencies based on OS
install_dependencies() {
    log "Installing forensic dependencies..."
    
    # Function to install packages individually with detailed logging
    install_package() {
        local package="$1"
        local install_cmd="$2"
        
        log "Attempting to install: $package"
        
        if eval "$install_cmd $package" >/dev/null 2>&1; then
            log "✓ Successfully installed: $package"
            return 0
        else
            log_error "✗ Failed to install: $package"
            return 1
        fi
    }
    
    # Function to check if package is available
    check_package_availability() {
        local package="$1"
        local os_type="$2"
        
        case $os_type in
            "debian")
                apt-cache show "$package" >/dev/null 2>&1
                ;;
            "rhel"|"fedora")
                if command -v dnf >/dev/null 2>&1; then
                    dnf info "$package" >/dev/null 2>&1
                else
                    yum info "$package" >/dev/null 2>&1
                fi
                ;;
            "arch")
                pacman -Si "$package" >/dev/null 2>&1
                ;;
            *)
                return 1
                ;;
        esac
    }
    
    # Define package lists for each OS type
    case $OS_TYPE in
        "debian")
            log "Updating package cache for Debian/Ubuntu..."
            apt-get update >/dev/null 2>&1 || log_warn "Failed to update package cache"
            
            PACKAGES=(
                "yara"
                "pv"
                "kpartx"
                "lsof"
                "netcat-openbsd"
                "tcpdump"
                "binutils"
                "file"
                "strace"
                "ltrace"
                "gdb"
                "bsdmainutils"
                "xxd"
                "tree"
                "htop"
                "iotop"
                "sysstat"
                "psmisc"
                "procps"
                "util-linux"
                "coreutils"
                "findutils"
                "grep"
                "sed"
                "gawk"
                "tar"
                "gzip"
                "openssl"
                "curl"
                "wget"
                "git"
            )
            
            INSTALL_BASE="apt-get install -y"
            ;;
        "rhel"|"fedora")
            PACKAGES=(
                "yara"
                "pv"
                "kpartx"
                "lsof"
                "nmap-ncat"
                "tcpdump"
                "binutils"
                "file"
                "strace"
                "ltrace"
                "gdb"
                "util-linux"
                "hexdump"
                "tree"
                "htop"
                "iotop"
                "sysstat"
                "psmisc"
                "procps-ng"
                "coreutils"
                "findutils"
                "grep"
                "sed"
                "gawk"
                "tar"
                "gzip"
                "openssl"
                "curl"
                "wget"
                "git"
            )
            
            if command -v dnf >/dev/null 2>&1; then
                INSTALL_BASE="dnf install -y"
            else
                INSTALL_BASE="yum install -y"
            fi
            ;;
        "arch")
            PACKAGES=(
                "yara"
                "pv"
                "multipath-tools"
                "lsof"
                "openbsd-netcat"
                "tcpdump"
                "binutils"
                "file"
                "strace"
                "ltrace"
                "gdb"
                "util-linux"
                "tree"
                "htop"
                "iotop"
                "sysstat"
                "psmisc"
                "procps-ng"
                "coreutils"
                "findutils"
                "grep"
                "sed"
                "gawk"
                "tar"
                "gzip"
                "openssl"
                "curl"
                "wget"
                "git"
            )
            
            INSTALL_BASE="pacman -Sy --noconfirm"
            ;;
    esac
    
    # Track installation results
    local failed_packages=()
    local successful_packages=()
    local unavailable_packages=()
    
    log "Checking package availability and installing..."
    
    for package in "${PACKAGES[@]}"; do
        # Check if package is available
        if check_package_availability "$package" "$OS_TYPE"; then
            log "Package available: $package"
            
            # Try to install the package
            if install_package "$package" "$INSTALL_BASE"; then
                successful_packages+=("$package")
            else
                failed_packages+=("$package")
            fi
        else
            log_warn "Package not available in repositories: $package"
            unavailable_packages+=("$package")
        fi
    done
    
    # Report installation results
    log "=== Package Installation Summary ==="
    log "Successfully installed (${#successful_packages[@]}): ${successful_packages[*]}"
    
    if [[ ${#failed_packages[@]} -gt 0 ]]; then
        log_error "Failed to install (${#failed_packages[@]}): ${failed_packages[*]}"
    fi
    
    if [[ ${#unavailable_packages[@]} -gt 0 ]]; then
        log_warn "Unavailable packages (${#unavailable_packages[@]}): ${unavailable_packages[*]}"
    fi
    
    # Check for critical packages
    local critical_missing=()
    for critical in "lsof" "tcpdump" "file" "strace"; do
        if ! command -v "$critical" >/dev/null 2>&1; then
            critical_missing+=("$critical")
        fi
    done
    
    if [[ ${#critical_missing[@]} -gt 0 ]]; then
        log_error "Critical forensic tools missing: ${critical_missing[*]}"
        log_error "Investigation may be limited without these tools"
    fi

    # Download YARA rules if not present
    if [[ ! -d "$EVID/yara_rules" ]]; then
        log "Downloading YARA rules..."
        mkdir -p "$EVID/yara_rules"
        cd "$EVID/yara_rules"
        
        # Download common YARA rule sets
        log "Downloading Yara-Rules repository..."
        if git clone --depth 1 https://github.com/Yara-Rules/rules.git yara-rules 2>/dev/null; then
            log "✓ Successfully downloaded yara-rules"
        else
            log_warn "✗ Failed to download yara-rules"
        fi
        
        log "Downloading signature-base repository..."
        if git clone --depth 1 https://github.com/Neo23x0/signature-base.git signature-base 2>/dev/null; then
            log "✓ Successfully downloaded signature-base"
        else
            log_warn "✗ Failed to download signature-base"
        fi
        
        cd - >/dev/null
    fi
    
    # Return success if at least some critical tools are available
    local critical_available=0
    for critical in "lsof" "tcpdump" "file" "strace" "ps" "netstat"; do
        if command -v "$critical" >/dev/null 2>&1; then
            ((critical_available++))
        fi
    done
    
    if [[ $critical_available -ge 3 ]]; then
        log "Sufficient forensic tools available for investigation"
        return 0
    else
        log_warn "Limited forensic tools available - investigation may be incomplete"
        return 1
    fi
}

# Initialize evidence workspace
init_workspace() {
    # Force UTC for consistent timelines
    export TZ=UTC
    
    # Create structured evidence workspace
    CASE="case-$(hostname)-$(date -u +%Y%m%dT%H%M%SZ)"
    
    # Use provided path or default
    if [[ $# -gt 0 && -d "$1" ]]; then
        EVID_BASE="$1"
    elif [[ -d "/mnt" ]]; then
        EVID_BASE="/mnt/forensics"
        mkdir -p "$EVID_BASE"
    else
        EVID_BASE="/tmp/forensics"
        mkdir -p "$EVID_BASE"
        log_warn "Using /tmp for evidence storage - consider using external storage"
    fi
    
    EVID="$EVID_BASE/$CASE"
    mkdir -p "$EVID"/{volatile,live,images,logs,hashes,yara_rules}
    
    LOG_FILE="$EVID/logs/forensics.log"
    
    # Record terminal I/O for chain of custody
    exec > >(tee -a "$EVID/logs/tty.log") 2>&1
    
    log "=== $SCRIPT_NAME v$SCRIPT_VERSION ==="
    log "Case: $CASE"
    log "Evidence location: $EVID"
    log "Investigation started at: $(date -u)"
    
    # Enhanced context documentation
    {
        echo "=== SYSTEM CONTEXT ==="
        date -u
        uname -a
        hostnamectl 2>/dev/null || hostname
        who -a 2>/dev/null || who
        last -Faiw 2>/dev/null | head -n 50
        uptime
        id
    } | tee "$EVID/volatile/_context.txt"
    
    # Initialize hash tracking
    touch "$EVID/hashes/manifest.sha256"
    touch "$EVID/hashes/SHA256.txt"
}

# Function to hash and log evidence
hash_evidence() {
    local file="$1"
    if [[ -f "$file" ]]; then
        sha256sum "$file" | tee -a "$EVID/hashes/SHA256.txt"
    fi
}

# Phase 1: Volatile Data Collection
collect_volatile() {
    log "=== Phase 1: Collecting Volatile Data ==="
    
    log "Collecting process information..."
    ps auxfww > "$EVID/volatile/ps_auxf.txt"
    pstree -a -p > "$EVID/volatile/pstree.txt" 2>/dev/null || pstree -p > "$EVID/volatile/pstree.txt"
    
    # Enhanced process analysis
    log "Performing deep process analysis..."
    for PID in $(ps -eo pid,ppid,cmd --no-headers | awk '{print $1}'); do
        PROC_DIR="/proc/$PID"
        [[ -d $PROC_DIR ]] || continue
        {
            echo "===== PID $PID ====="
            # Command line with null byte handling
            tr '\0' ' ' < "$PROC_DIR/cmdline" 2>/dev/null || echo "No cmdline"
            echo
            # Executable and working directory links
            ls -l "$PROC_DIR/exe" 2>/dev/null || echo "No exe link"
            readlink -f "$PROC_DIR/exe" 2>/dev/null || echo "Cannot resolve exe"
            ls -l "$PROC_DIR/cwd" 2>/dev/null || echo "No cwd link"
            readlink -f "$PROC_DIR/cwd" 2>/dev/null || echo "Cannot resolve cwd"
            # Environment variables with clear labeling
            cat "$PROC_DIR/environ" 2>/dev/null | tr '\0' '\n' | sed 's/^/ENV: /' || echo "No environment"
            # File descriptors
            ls -l "$PROC_DIR/fd" 2>/dev/null | sed 's/^/FD: /' || echo "No file descriptors"
            # Memory maps (first 50 lines)
            head -n 50 "$PROC_DIR/maps" 2>/dev/null | sed 's/^/MAP: /' || echo "No memory maps"
            echo
        } >> "$EVID/volatile/proc_quickdump.txt"
    done
    
    log "Collecting network information..."
    # Enhanced network analysis with modern tools
    ss -tulpn > "$EVID/volatile/ss_listeners.txt"
    ss -tpna > "$EVID/volatile/ss_tcp.txt"
    ss -upan > "$EVID/volatile/ss_udp.txt"
    lsof -i -n -P > "$EVID/volatile/lsof_net.txt" 2>/dev/null
    
    # Network context
    ip a > "$EVID/volatile/ip_a.txt"
    ip r > "$EVID/volatile/ip_route.txt"
    arp -an > "$EVID/volatile/arp.txt" 2>/dev/null || true
    
    # Firewall rules
    { nft list ruleset 2>/dev/null || iptables -S; } > "$EVID/volatile/firewall.txt" 2>&1
    
    # DNS configuration
    { resolvectl status 2>/dev/null || cat /etc/resolv.conf; } > "$EVID/volatile/dns.txt" 2>&1
    
    log "Collecting system logs..."
    # Live logs
    journalctl -xe --no-pager > "$EVID/volatile/journal_xe.txt" 2>/dev/null || echo "No systemd journal" > "$EVID/volatile/journal_xe.txt"
    dmesg -T > "$EVID/volatile/dmesg.txt" 2>/dev/null || dmesg > "$EVID/volatile/dmesg.txt"
    
    # Auth and system logs
    { cat /var/log/auth.log /var/log/secure 2>/dev/null; } | tail -n 1000 > "$EVID/volatile/auth_recent.txt"
    { cat /var/log/syslog /var/log/messages 2>/dev/null; } | tail -n 1000 > "$EVID/volatile/sys_recent.txt"
    
    # Hash volatile evidence
    hash_evidence "$EVID/volatile/proc_quickdump.txt" || true
    hash_evidence "$EVID/volatile/ss_listeners.txt" || true
    hash_evidence "$EVID/volatile/lsof_net.txt" || true
    
    log "Volatile data collection complete"
}

# Phase 2: Memory Analysis
collect_memory() {
    log "=== Phase 2: Memory Analysis ==="
    
    log "Collecting memory information..."
    cat /proc/meminfo > "$EVID/volatile/meminfo.txt"
    cat /proc/vmstat > "$EVID/volatile/vmstat.txt"
    cat /proc/slabinfo > "$EVID/volatile/slabinfo.txt" 2>/dev/null || echo "No slabinfo access" > "$EVID/volatile/slabinfo.txt"
    
    # Swap information
    cat /proc/swaps > "$EVID/volatile/swaps.txt"
    
    log_warn "Professional memory acquisition requires LiME or AVML"
    log "For now, collecting /proc/kcore sample (first 100MB)"
    
    # Fallback memory collection (limited)
    timeout 60 dd if=/proc/kcore of="$EVID/images/kcore_sample.raw" bs=1M count=100 2>/dev/null || log_warn "Memory collection failed or timed out"
    
    # Image swap if present
    if [[ -s "$EVID/volatile/swaps.txt" ]] && [[ $(wc -l < "$EVID/volatile/swaps.txt") -gt 1 ]]; then
        log "Imaging swap partitions..."
        while read -r swap_line; do
            [[ "$swap_line" == Filename* ]] && continue
            swap_dev=$(echo "$swap_line" | awk '{print $1}')
            if [[ -b "$swap_dev" ]]; then
                log "Imaging swap: $swap_dev"
                dd if="$swap_dev" of="$EVID/images/swap_$(basename $swap_dev).raw" bs=4M 2>/dev/null || log_warn "Failed to image $swap_dev"
            fi
        done < "$EVID/volatile/swaps.txt"
    fi
    
    # Hash memory artifacts
    find "$EVID/images" -name "*.raw" 2>/dev/null | while read -r memfile; do
        [[ -f "$memfile" ]] && hash_evidence "$memfile"
    done
    
    hash_evidence "$EVID/volatile/meminfo.txt"
    
    log "Memory analysis complete"
}

# Phase 3: Persistence Analysis
analyze_persistence() {
    log "=== Phase 3: Persistence Analysis ==="
    
    log "Analyzing user accounts..."
    getent passwd > "$EVID/live/passwd.txt"
    getent group > "$EVID/live/group.txt"
    awk -F: '($3>=1000 && $1!="nobody"){print}' /etc/passwd > "$EVID/live/human_users.txt"
    
    log "Analyzing SSH configuration..."
    sshd -T 2>/dev/null | sort > "$EVID/live/sshd_effective_cfg.txt" || cp /etc/ssh/sshd_config "$EVID/live/sshd_config_raw.txt" 2>/dev/null
    find /home -maxdepth 3 -type f \( -name authorized_keys -o -name 'id_*' \) -exec ls -l {} + 2>/dev/null > "$EVID/live/ssh_keys.txt"
    
    log "Analyzing scheduled tasks..."
    crontab -l 2>/dev/null > "$EVID/live/crontab_user.txt" || echo "No user crontab" > "$EVID/live/crontab_user.txt"
    ls -la /etc/cron.* /var/spool/cron 2>/dev/null > "$EVID/live/cron_dirs.txt"
    
    # Systemd analysis
    systemctl list-unit-files --type=service --state=enabled > "$EVID/live/services_enabled.txt" 2>/dev/null || echo "No systemd" > "$EVID/live/services_enabled.txt"
    systemctl list-timers --all > "$EVID/live/systemd_timers.txt" 2>/dev/null || echo "No systemd timers" > "$EVID/live/systemd_timers.txt"
    
    log "Checking startup hooks and preloads..."
    cat /etc/rc.local 2>/dev/null | sed 's/^/rc.local: /' > "$EVID/live/rc_local.txt" || echo "No rc.local" > "$EVID/live/rc_local.txt"
    cat /etc/ld.so.preload 2>/dev/null | sed 's/^/ld.so.preload: /' > "$EVID/live/ld_preload.txt" || echo "No ld.so.preload" > "$EVID/live/ld_preload.txt"
    
    # Kernel modules
    lsmod | sort > "$EVID/live/lsmod.txt"
    
    # Hash persistence evidence
    hash_evidence "$EVID/live/services_enabled.txt"
    hash_evidence "$EVID/live/ssh_keys.txt"
    
    log "Persistence analysis complete"
}

# Phase 4: Filesystem Analysis
analyze_filesystem() {
    log "=== Phase 4: Filesystem Analysis ==="
    
    log "Collecting filesystem metadata..."
    mount > "$EVID/live/mounted_filesystems.txt"
    df -h > "$EVID/live/disk_usage.txt"
    lsblk -o NAME,TYPE,SIZE,RO,MOUNTPOINT,UUID,PTTYPE,PARTTYPENAME > "$EVID/live/block_devices_detailed.txt"
    blkid > "$EVID/live/blkid.txt" 2>/dev/null || echo "No blkid output" > "$EVID/live/blkid.txt"
    
    log "Creating file timeline (this may take time)..."
    # Fast file timeline with epoch timestamps
    find / -xdev -type f -printf '%T@,%TY-%Tm-%Td %TH:%TM:%.2TS,%u,%g,%m,%s,%p\n' 2>/dev/null | sort -n > "$EVID/live/timeline.csv" &
    TIMELINE_PID=$!
    
    # Recent files (last 7 days)
    find / -xdev -type f -mtime -7 -printf '%TY-%Tm-%Td %TH:%TM:%TS %p\n' 2>/dev/null | sort > "$EVID/live/recent_7d.txt"
    
    log "Analyzing suspicious file locations..."
    # SUID/SGID files
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec ls -la {} + 2>/dev/null > "$EVID/live/suid_sgid.txt"
    
    # World-writable directories
    find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o -type d -perm -0002 -print 2>/dev/null > "$EVID/live/world_writable_dirs.txt"
    
    # Hidden files in common locations
    find /home /tmp /var/tmp -name ".*" -type f 2>/dev/null > "$EVID/live/hidden_files.txt"
    
    # Large files
    find / -xdev -type f -size +100M 2>/dev/null > "$EVID/live/large_files.txt"
    
    log "Analyzing system directories..."
    ls -la /bin /sbin /usr/bin /usr/sbin > "$EVID/live/system_binaries.txt" 2>/dev/null
    ls -la /etc > "$EVID/live/etc_contents.txt"
    ls -la /tmp /var/tmp > "$EVID/live/temp_dirs.txt"
    
    # Wait for timeline to complete (with timeout)
    log "Waiting for timeline creation to complete..."
    timeout 300 wait $TIMELINE_PID 2>/dev/null || log_warn "Timeline creation timed out"
    
    # Journal timeline for correlation
    journalctl --output=short-unix > "$EVID/live/journal_unix.txt" 2>/dev/null || echo "No journal" > "$EVID/live/journal_unix.txt"
    
    # Convert journal to CSV for timeline merge
    if [[ -s "$EVID/live/journal_unix.txt" ]]; then
        awk '{print $1",journal,"substr($0,index($0,$3))}' "$EVID/live/journal_unix.txt" | sort -t, -n > "$EVID/live/journal_timeline.csv"
        
        # Merge timelines if both exist
        if [[ -f "$EVID/live/timeline.csv" ]]; then
            cat "$EVID/live/journal_timeline.csv" "$EVID/live/timeline.csv" | sort -t, -n > "$EVID/live/merged_timeline.csv"
            hash_evidence "$EVID/live/merged_timeline.csv"
        fi
    fi
    
    log "Filesystem analysis complete"
}

# Phase 5: Hash Analysis
compute_hashes() {
    log "=== Phase 5: Hash Computation ==="
    
    log "Computing hashes of system binaries..."
    {
        echo "=== System Binary Hashes ==="
        for binary in /bin/* /sbin/* /usr/bin/* /usr/sbin/*; do
            if [[ -f "$binary" ]]; then
                echo "File: $binary"
                sha256sum "$binary" 2>/dev/null || echo "Hash failed: $binary"
                echo ""
            fi
        done
    } > "$EVID/live/system_hashes.txt"
    
    log "Computing hashes of recent/suspicious files..."
    if [[ -f "$EVID/live/recent_7d.txt" ]]; then
        {
            echo "=== Recent File Hashes ==="
            while IFS= read -r file_entry; do
                file_path=$(echo "$file_entry" | awk '{print $2}')
                if [[ -f "$file_path" ]]; then
                    echo "=== $file_path ==="
                    sha256sum "$file_path" 2>/dev/null || echo "Hash failed: $file_path"
                    echo ""
                fi
            done
        } < "$EVID/live/recent_7d.txt" > "$EVID/live/suspicious_hashes.txt"
    fi
    
    hash_evidence "$EVID/live/system_hashes.txt"
    
    log "Hash computation complete"
}

# Phase 6: YARA Scanning
run_yara_scan() {
    log "=== Phase 6: YARA Scanning ==="
    
    if ! command -v yara >/dev/null 2>&1; then
        log_warn "YARA not available, skipping malware scanning"
        return
    fi
    
    # Create basic YARA rules if none exist
    if [[ ! -d "$EVID/yara_rules" ]] || [[ -z "$(find "$EVID/yara_rules" -name "*.yar" -o -name "*.yara" 2>/dev/null)" ]]; then
        log "Creating basic YARA rules..."
        mkdir -p "$EVID/yara_rules"
        
        cat > "$EVID/yara_rules/basic_indicators.yar" << 'EOF'
rule Suspicious_ELF_Packed {
    meta:
        description = "Potentially packed ELF binary"
    strings:
        $upx = "UPX!"
        $elf = { 7f 45 4c 46 }
    condition:
        $elf at 0 and $upx
}

rule Suspicious_Strings {
    meta:
        description = "Suspicious strings in binaries"
    strings:
        $s1 = "/tmp/" nocase
        $s2 = "wget" nocase
        $s3 = "curl" nocase
        $s4 = "sh -c" nocase
        $s5 = "bash -c" nocase
        $s6 = "nc -" nocase
        $s7 = "netcat" nocase
    condition:
        3 of them
}

rule Hidden_ELF {
    meta:
        description = "ELF binary with suspicious name"
    strings:
        $elf = { 7f 45 4c 46 }
    condition:
        $elf at 0 and (
            filename matches /\.\w+$/ or
            filename matches /^\..*/ or
            filename matches /.*\s.*/
        )
}
EOF
    fi
    
    log "Running YARA scans on critical directories..."
    
    # Scan common directories
    for scan_dir in "/tmp" "/var/tmp" "/dev/shm" "/home" "/var/www" "/opt"; do
        if [[ -d "$scan_dir" ]]; then
            log "Scanning $scan_dir..."
            timeout 300 yara -r -p "$(nproc)" "$EVID/yara_rules"/*.{yar,yara} "$scan_dir" 2>/dev/null >> "$EVID/live/yara_hits.txt" || true
        fi
    done
    
    # Scan running process executables
    log "Scanning process executables..."
    ps -eo pid,cmd --no-headers | while read -r pid cmd; do
        exe_path=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
        if [[ -f "$exe_path" ]]; then
            timeout 30 yara -s "$EVID/yara_rules"/*.{yar,yara} "$exe_path" 2>/dev/null >> "$EVID/live/yara_process_hits.txt" || true
        fi
    done
    
    hash_evidence "$EVID/live/yara_hits.txt"
    
    log "YARA scanning complete"
}

# Phase 7: String Analysis
analyze_strings() {
    log "=== Phase 7: String Analysis ==="
    
    log "Extracting strings from suspicious files..."
    
    # String analysis of recent files
    if [[ -f "$EVID/live/recent_7d.txt" ]]; then
        while IFS= read -r file_entry; do
            file_path=$(echo "$file_entry" | awk '{print $2}')
            if [[ -f "$file_path" ]] && [[ $(file "$file_path") == *"ELF"* ]]; then
                echo "=== Strings from $file_path ===" >> "$EVID/live/string_analysis.txt"
                timeout 30 strings "$file_path" | head -100 >> "$EVID/live/string_analysis.txt" 2>/dev/null || echo "String extraction failed" >> "$EVID/live/string_analysis.txt"
                echo "" >> "$EVID/live/string_analysis.txt"
            fi
        done < "$EVID/live/recent_7d.txt"
    fi
    
    # Look for suspicious strings in system binaries
    log "Searching for suspicious string patterns..."
    find /bin /sbin /usr/bin /usr/sbin -type f -executable 2>/dev/null | while read -r binary; do
        if timeout 10 strings "$binary" | grep -qi -E "(password|admin|root|hack|exploit|shell|cmd)" 2>/dev/null; then
            echo "Suspicious strings found in: $binary" >> "$EVID/live/suspicious_strings.txt"
            timeout 10 strings "$binary" | grep -i -E "(password|admin|root|hack|exploit|shell|cmd)" | head -10 >> "$EVID/live/suspicious_strings.txt"
            echo "---" >> "$EVID/live/suspicious_strings.txt"
        fi
    done
    
    # Memory strings analysis if memory dump exists
    if [[ -f "$EVID/images/kcore_sample.raw" ]]; then
        log "Extracting strings from memory sample..."
        timeout 60 strings "$EVID/images/kcore_sample.raw" | grep -v "^.$" > "$EVID/live/memory_strings.txt" 2>/dev/null || log_warn "Memory string extraction failed"
        
        # Look for indicators in memory
        if [[ -f "$EVID/live/memory_strings.txt" ]]; then
            grep -i -E "(http|ftp|password|key|cmd)" "$EVID/live/memory_strings.txt" | head -100 > "$EVID/live/memory_indicators.txt" 2>/dev/null || true
        fi
    fi
    
    log "String analysis complete"
}

# Phase 8: Log Analysis
analyze_logs() {
    log "=== Phase 8: Log Analysis ==="
    
    log "Analyzing authentication logs..."
    
    # Failed login attempts
    { grep -i "failed password\|authentication failure\|invalid user" /var/log/auth.log /var/log/secure 2>/dev/null; } | tail -100 > "$EVID/live/failed_logins.txt"
    
    # Successful logins
    { last -Faiw; } > "$EVID/live/last_logins.txt" 2>/dev/null
    { lastlog; } > "$EVID/live/lastlog.txt" 2>/dev/null
    
    # Sudo usage
    { grep -i "sudo" /var/log/auth.log /var/log/secure 2>/dev/null; } | tail -100 > "$EVID/live/sudo_usage.txt"
    
    # Currently logged in users
    who > "$EVID/live/current_users.txt"
    w > "$EVID/live/user_activity.txt"
    
    log "Analyzing system logs for anomalies..."
    
    # Look for suspicious activities in logs
    {
        echo "=== Suspicious Log Entries ==="
        { grep -i -E "(exploit|attack|malware|backdoor|rootkit|trojan)" /var/log/syslog /var/log/messages 2>/dev/null; } | tail -50
        echo ""
        echo "=== Network Connection Logs ==="
        { grep -i -E "(connection|connect|tcp|udp)" /var/log/syslog /var/log/messages 2>/dev/null; } | tail -50
    } > "$EVID/live/suspicious_log_entries.txt"
    
    # Package management logs
    { grep -E "(install|remove|upgrade)" /var/log/dpkg.log /var/log/yum.log /var/log/dnf.log 2>/dev/null; } | tail -100 > "$EVID/live/package_changes.txt"
    
    log "Log analysis complete"
}

# Phase 9: User Analysis
analyze_users() {
    log "=== Phase 9: User Analysis ==="
    
    log "Collecting user shell histories..."
    
    # Collect shell histories with timestamps
    {
        echo "=== ROOT HISTORY ==="
        if [[ -f /root/.bash_history ]]; then
            HISTTIMEFORMAT='%F %T ' 
            export HISTTIMEFORMAT
            # Show history with timestamps if available
            history -r /root/.bash_history 2>/dev/null && history | tail -200 || cat /root/.bash_history
        else
            echo "No root bash history found"
        fi
        
        echo -e "\n=== USER HISTORIES ==="
        for user_home in /home/*; do
            if [[ -d "$user_home" ]]; then
                username=$(basename "$user_home")
                echo "--- History for $username ($user_home) ---"
                
                # Bash history
                if [[ -f "$user_home/.bash_history" ]]; then
                    echo "Bash history:"
                    tail -100 "$user_home/.bash_history" 2>/dev/null
                fi
                
                # Zsh history
                if [[ -f "$user_home/.zsh_history" ]]; then
                    echo "Zsh history:"
                    tail -100 "$user_home/.zsh_history" 2>/dev/null
                fi
                
                # Fish history
                if [[ -f "$user_home/.local/share/fish/fish_history" ]]; then
                    echo "Fish history:"
                    tail -50 "$user_home/.local/share/fish/fish_history" 2>/dev/null
                fi
                
                echo ""
            fi
        done
    } > "$EVID/live/user_histories.txt"
    
    log "Analyzing user configurations..."
    
    # SSH configurations
    {
        echo "=== SSH CLIENT CONFIGURATIONS ==="
        for user_home in /home/* /root; do
            if [[ -d "$user_home/.ssh" ]]; then
                username=$(basename "$user_home")
                echo "--- SSH config for $username ---"
                ls -la "$user_home/.ssh/" 2>/dev/null
                
                # SSH config file
                if [[ -f "$user_home/.ssh/config" ]]; then
                    echo "SSH config contents:"
                    cat "$user_home/.ssh/config"
                fi
                
                # Known hosts
                if [[ -f "$user_home/.ssh/known_hosts" ]]; then
                    echo "Known hosts (last 20):"
                    tail -20 "$user_home/.ssh/known_hosts"
                fi
                
                echo ""
            fi
        done
    } > "$EVID/live/user_ssh_configs.txt"
    
    # Browser artifacts (if GUI system)
    {
        echo "=== BROWSER ARTIFACTS ==="
        # Firefox
        find /home -name "places.sqlite" 2>/dev/null | while read -r db; do
            echo "Firefox history found: $db"
            ls -la "$db"
        done
        
        find /home -name "cookies.sqlite" 2>/dev/null | while read -r db; do
            echo "Firefox cookies found: $db" 
            ls -la "$db"
        done
        
        # Chrome/Chromium
        find /home -path "*/.config/google-chrome/Default/History" 2>/dev/null | while read -r db; do
            echo "Chrome history found: $db"
            ls -la "$db"
        done
        
        find /home -path "*/.config/chromium/Default/History" 2>/dev/null | while read -r db; do
            echo "Chromium history found: $db"
            ls -la "$db"
        done
    } > "$EVID/live/browser_artifacts.txt"
    
    # Recent file access
    find /home -name ".recently-used*" 2>/dev/null > "$EVID/live/recent_access.txt"
    find /home -name "*.tmp" -mtime -1 2>/dev/null > "$EVID/live/recent_temp_files.txt"
    
    hash_evidence "$EVID/live/user_histories.txt"
    hash_evidence "$EVID/live/user_ssh_configs.txt"
    
    log "User analysis complete"
}

# Phase 10: Package Analysis
analyze_packages() {
    log "=== Phase 10: Package Analysis ==="
    
    # Debian/Ubuntu systems
    if command -v dpkg >/dev/null 2>&1; then
        log "Analyzing Debian packages..."
        dpkg -l > "$EVID/live/dpkg_packages.txt" 2>/dev/null
        
        # Package verification
        log "Verifying package integrity (this may take time)..."
        timeout 300 dpkg -V > "$EVID/live/dpkg_verify.txt" 2>&1 || log_warn "Package verification timed out"
    fi
    
    # RPM-based systems
    if command -v rpm >/dev/null 2>&1; then
        log "Analyzing RPM packages..."
        rpm -qa > "$EVID/live/rpm_packages.txt" 2>/dev/null
        
        # Package verification
        log "Verifying RPM integrity (this may take time)..."
        timeout 300 rpm -Va > "$EVID/live/rpm_verify.txt" 2>&1 || log_warn "RPM verification timed out"
    fi
    
    # Package managers
    {
        echo "=== PACKAGE MANAGER HISTORY ==="
        
        # APT history
        if [[ -f /var/log/apt/history.log ]]; then
            echo "--- APT History (last 100 lines) ---"
            tail -100 /var/log/apt/history.log
        fi
        
        # YUM/DNF history
        if command -v yum >/dev/null 2>&1; then
            echo "--- YUM History ---"
            yum history list 2>/dev/null | head -50
        elif command -v dnf >/dev/null 2>&1; then
            echo "--- DNF History ---" 
            dnf history list 2>/dev/null | head -50
        fi
        
        # Pacman log
        if [[ -f /var/log/pacman.log ]]; then
            echo "--- Pacman Log (last 100 lines) ---"
            tail -100 /var/log/pacman.log
        fi
    } > "$EVID/live/package_history.txt"
    
    log "Package analysis complete"
}

# Phase 11: Disk Imaging
create_disk_images() {
    log "=== Phase 11: Disk Imaging ==="
    
    # List all block devices
    log "Enumerating block devices..."
    lsblk -o NAME,TYPE,SIZE,RO,MOUNTPOINT,UUID,PTTYPE,PARTTYPENAME > "$EVID/live/block_devices_detailed.txt"
    blkid > "$EVID/live/blkid.txt" 2>/dev/null
    
    # Check available space for imaging
    available_space=$(df "$EVID" | awk 'NR==2 {print $4}')
    available_gb=$((available_space / 1024 / 1024))
    
    log "Available space for imaging: ${available_gb}GB"
    
    # Get primary disk
    primary_disk=$(lsblk -no PKNAME $(findmnt -n -o SOURCE /) 2>/dev/null | head -1)
    if [[ -z "$primary_disk" ]]; then
        primary_disk=$(lsblk -dn -o NAME | head -1)
    fi
    
    if [[ -n "$primary_disk" ]]; then
        disk_size=$(lsblk -bdn -o SIZE /dev/$primary_disk 2>/dev/null)
        disk_size_gb=$((disk_size / 1024 / 1024 / 1024))
        
        log "Primary disk: /dev/$primary_disk (${disk_size_gb}GB)"
        
        if [[ $available_gb -lt $disk_size_gb ]]; then
            log_warn "Insufficient space for full disk imaging (need ${disk_size_gb}GB, have ${available_gb}GB)"
            log "Consider using external storage or imaging specific partitions"
        else
            log "Creating disk image of /dev/$primary_disk..."
            log_warn "This will take significant time. Press Ctrl+C to skip disk imaging."
            
            if pv --version >/dev/null 2>&1; then
                pv "/dev/$primary_disk" | dd of="$EVID/images/disk_${primary_disk}.img" bs=4M conv=noerror,sync
            else
                dd if="/dev/$primary_disk" of="$EVID/images/disk_${primary_disk}.img" bs=4M conv=noerror,sync status=progress
            fi
            
            sync
            hash_evidence "$EVID/images/disk_${primary_disk}.img"
            
            log "Disk imaging complete"
        fi
    else
        log_warn "Could not determine primary disk for imaging"
    fi
}

# Phase 12: Network Capture
capture_network() {
    log "=== Phase 12: Network Capture ==="
    
    if command -v tcpdump >/dev/null 2>&1; then
        log "Starting network capture (5 minutes)..."
        timeout 300 tcpdump -i any -w "$EVID/live/network_capture.pcap" &
        TCPDUMP_PID=$!
        
        sleep 300
        
        if kill -0 $TCPDUMP_PID 2>/dev/null; then
            kill $TCPDUMP_PID
        fi
        
        wait $TCPDUMP_PID 2>/dev/null || true
        
        if [[ -f "$EVID/live/network_capture.pcap" ]]; then
            hash_evidence "$EVID/live/network_capture.pcap"
            log "Network capture complete"
        else
            log_warn "Network capture failed"
        fi
    else
        log_warn "tcpdump not available, skipping network capture"
    fi
}

# Phase 13: Generate Final Report
generate_report() {
    log "=== Phase 13: Generating Final Report ==="
    
    # Create comprehensive evidence manifest
    find "$EVID" -type f -exec sha256sum {} + | sort -k2 > "$EVID/hashes/manifest.sha256"
    hash_evidence "$EVID/hashes/manifest.sha256"
    
    # Investigation summary
    {
        echo "=== LINUX FORENSIC INVESTIGATION SUMMARY ==="
        echo "Generated by: $SCRIPT_NAME v$SCRIPT_VERSION"
        echo "Investigation Date: $(date -u)"
        echo "Investigator: $(whoami)"
        echo "Case ID: $CASE"
        echo "System: $(hostname)"
        echo "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || uname -o)"
        echo "Kernel: $(uname -r)"
        echo "Architecture: $(uname -m)"
        echo "Uptime at start: $(uptime)"
        echo "Evidence location: $EVID"
        echo ""
        
        echo "=== EVIDENCE SUMMARY ==="
        echo "Total files collected: $(find "$EVID" -type f | wc -l)"
        echo "Total evidence size: $(du -sh "$EVID" | cut -f1)"
        echo ""
        
        echo "=== KEY FINDINGS ==="
        
        # Running processes summary
        echo "Active processes: $(ps aux | wc -l)"
        
        # Network connections
        echo "Network listeners: $(ss -tln | wc -l)"
        echo "Active connections: $(ss -tn | wc -l)"
        
        # Recent files
        if [[ -f "$EVID/live/recent_7d.txt" ]]; then
            echo "Files modified in last 7 days: $(wc -l < "$EVID/live/recent_7d.txt")"
        fi
        
        # YARA hits
        if [[ -f "$EVID/live/yara_hits.txt" ]] && [[ -s "$EVID/live/yara_hits.txt" ]]; then
            echo "YARA rule matches: $(wc -l < "$EVID/live/yara_hits.txt")"
            echo "--- YARA Hits ---"
            head -20 "$EVID/live/yara_hits.txt"
        fi
        
        # Failed logins
        if [[ -f "$EVID/live/failed_logins.txt" ]] && [[ -s "$EVID/live/failed_logins.txt" ]]; then
            echo "Failed login attempts: $(wc -l < "$EVID/live/failed_logins.txt")"
        fi
        
        # SUID files
        if [[ -f "$EVID/live/suid_sgid.txt" ]]; then
            echo "SUID/SGID files found: $(wc -l < "$EVID/live/suid_sgid.txt")"
        fi
        
        echo ""
        echo "=== RECOMMENDED ACTIONS ==="
        echo "1. Review YARA scan results for malware indicators"
        echo "2. Analyze timeline for suspicious file modifications" 
        echo "3. Investigate failed login attempts and unusual user activity"
        echo "4. Examine network connections for unauthorized access"
        echo "5. Verify integrity of system binaries against known good hashes"
        echo "6. Analyze memory dump with Volatility for advanced threats"
        echo "7. Cross-reference findings with threat intelligence"
        echo ""
        
        echo "=== FILE INVENTORY ==="
        find "$EVID" -type f -name "*.txt" -o -name "*.csv" -o -name "*.pcap" -o -name "*.raw" -o -name "*.img" | sort
        echo ""
        
        echo "=== HASH VERIFICATION ==="
        echo "Total hashes recorded: $(wc -l < "$EVID/hashes/SHA256.txt")"
        echo "Manifest hash: $(tail -1 "$EVID/hashes/SHA256.txt")"
        
    } > "$EVID/INVESTIGATION_REPORT.txt"
    
    log "Creating final evidence package..."
    
    # Create final evidence archive with proper preservation
    cd "$EVID/.."
    if tar --version | grep -q GNU; then
        # GNU tar with extended attributes
        tar --xattrs --acls --numeric-owner --one-file-system -czpf "${CASE}.tar.gz" "$(basename "$EVID")"
    else
        # Fallback for other tar implementations
        tar -czpf "${CASE}.tar.gz" "$(basename "$EVID")"
    fi
    
    # Hash the final package
    sha256sum "${CASE}.tar.gz" | tee -a "$EVID/hashes/SHA256.txt"
    
    # Chain of custody document
    {
        echo "=== CHAIN OF CUSTODY ==="
        echo "Case: $CASE"
        echo "Investigator: $(whoami)"
        echo "Collection Date: $(date -u)" 
        echo "Collection System: $(hostname)"
        echo "Evidence Package: ${CASE}.tar.gz"
        echo "Package Hash: $(sha256sum "${CASE}.tar.gz" | cut -d' ' -f1)"
        echo "Package Size: $(ls -lh "${CASE}.tar.gz" | awk '{print $5}')"
        echo ""
        echo "=== COLLECTION NOTES ==="
        echo "Script Version: $SCRIPT_VERSION"
        echo "Collection Method: Automated forensic script"
        echo "System State: Live system analysis"
        echo "Evidence Integrity: All artifacts hashed with SHA-256"
        echo ""
        echo "=== EVIDENCE LOCATIONS ==="
        echo "Volatile Data: $EVID/volatile/"
        echo "Live Analysis: $EVID/live/" 
        echo "Memory Images: $EVID/images/"
        echo "Hash Manifests: $EVID/hashes/"
        echo "Logs: $EVID/logs/"
        echo ""
        echo "=== VERIFICATION ==="
        echo "To verify evidence integrity:"
        echo "1. Extract archive: tar -xzf ${CASE}.tar.gz"
        echo "2. Verify manifest: cd $(basename "$EVID") && sha256sum -c hashes/manifest.sha256"
        echo "3. Check individual hashes: sha256sum -c hashes/SHA256.txt"
    } > "${CASE}_custody.txt"
    
    cd - >/dev/null
    
    log "Final report and evidence package created"
    log "Evidence package: $(realpath "$EVID/../${CASE}.tar.gz")"
    log "Chain of custody: $(realpath "$EVID/../${CASE}_custody.txt")"
}

# Cleanup function
cleanup() {
    log "Performing cleanup..."
    
    # Kill any background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    
    # Unmount any mounted images (only if EVID is set)
    if [[ -n "${EVID:-}" ]] && mountpoint -q "$EVID/images/mnt_p1" 2>/dev/null; then
        umount "$EVID/images/mnt_p1" 2>/dev/null || true
    fi
    
    # Remove loop devices (only if EVID is set)
    if [[ -n "${EVID:-}" ]]; then
        losetup -a | grep "$EVID" | cut -d: -f1 | xargs -r losetup -d 2>/dev/null || true
    fi
    
    log "Cleanup complete"
}

# Main execution function
main() {
    # Trap for cleanup on exit
    trap cleanup EXIT
    
    echo -e "${BLUE}=== Linux Digital Forensics Script v$SCRIPT_VERSION ===${NC}"
    echo -e "${BLUE}Starting comprehensive forensic investigation...${NC}"
    
    # Prerequisites
    check_root
    detect_os
    
    # Initialize workspace
    init_workspace "$@"
    
    # Install dependencies
    install_dependencies || {
        log_error "Package installation encountered issues, but continuing with investigation..."
        log "Some forensic tools may not be available, but core analysis will proceed"
    }
    
    # Execute forensic phases with relaxed error handling
    log "Starting forensic analysis phases..."
    set_error_handling "relaxed"
    
    collect_volatile || { log_error "Phase 1 failed, continuing..."; }
    log "Phase 1 completed, starting Phase 2..."
    
    collect_memory || { log_error "Phase 2 failed, continuing..."; }
    log "Phase 2 completed, starting Phase 3..."
    
    analyze_persistence || { log_error "Phase 3 failed, continuing..."; }
    log "Phase 3 completed, starting Phase 4..."
    
    analyze_filesystem || { log_error "Phase 4 failed, continuing..."; }
    log "Phase 4 completed, starting Phase 5..."
    
    compute_hashes || { log_error "Phase 5 failed, continuing..."; }
    log "Phase 5 completed, starting Phase 6..."
    
    run_yara_scan || { log_error "Phase 6 failed, continuing..."; }
    log "Phase 6 completed, starting Phase 7..."
    
    analyze_strings || { log_error "Phase 7 failed, continuing..."; }
    log "Phase 7 completed, starting Phase 8..."
    
    analyze_logs || { log_error "Phase 8 failed, continuing..."; }
    log "Phase 8 completed, starting Phase 9..."
    
    analyze_users || { log_error "Phase 9 failed, continuing..."; }
    log "Phase 9 completed, starting Phase 10..."
    
    analyze_packages || { log_error "Phase 10 failed, continuing..."; }
    
    # Optional phases (can be interrupted)
    echo -e "${YELLOW}Starting optional phases (disk imaging and network capture)${NC}"
    echo -e "${YELLOW}These can take significant time. Press Ctrl+C to skip.${NC}"
    
    create_disk_images || true
    capture_network || true
    
    # Final reporting
    generate_report
    
    echo -e "${GREEN}=== Forensic Investigation Complete ===${NC}"
    echo -e "${GREEN}Evidence package: $(realpath "$EVID/../${CASE}.tar.gz")${NC}"
    echo -e "${GREEN}Investigation report: $EVID/INVESTIGATION_REPORT.txt${NC}"
    echo -e "${GREEN}Chain of custody: $(realpath "$EVID/../${CASE}_custody.txt")${NC}"
    
    log "Investigation completed successfully"
}

# Execute main function with all arguments
main "$@"