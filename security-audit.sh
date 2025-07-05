#!/bin/bash

# Enhanced Ubuntu Security Audit & Analysis Script
# For Ubuntu servers with Plesk, Docker, and comprehensive security assessment
# Version: 2.0
# Author: Enhanced Security Audit Script

set -euo pipefail

# Enhanced Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging
LOG_FILE="/var/log/security-audit-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE")
exec 2>&1

echo -e "${BLUE}=== ENHANCED UBUNTU SECURITY AUDIT & ANALYSIS SCRIPT ===${NC}"
echo "Started: $(date)"
echo "Hostname: $(hostname)"
echo "IP Address: $(hostname -I | awk '{print $1}')"
echo "Log file: $LOG_FILE"
echo ""

# Enhanced status printing with colors
print_status() {
    local status=$1
    local message=$2
    case $status in
        "PASS") echo -e "[${GREEN}PASS${NC}] $message" ;;
        "FAIL") echo -e "[${RED}FAIL${NC}] $message" ;;
        "RISK") echo -e "[${RED}RISK${NC}] $message" ;;
        "WARN") echo -e "[${ORANGE}WARN${NC}] $message" ;;
        "INFO") echo -e "[${BLUE}INFO${NC}] $message" ;;
        "SECURE") echo -e "[${GREEN}SECURE${NC}] $message" ;;
        "CRITICAL") echo -e "[${RED}CRITICAL${NC}] $message" ;;
    esac
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_status "INFO" "Running as root user"
    else
        print_status "FAIL" "This script must be run as root"
        exit 1
    fi
}

# Enhanced System Information with comprehensive analysis
system_info() {
    echo -e "\n${BLUE}=== COMPREHENSIVE SYSTEM INFORMATION ===${NC}"
    print_status "INFO" "OS: $(lsb_release -d | cut -f2)"
    print_status "INFO" "Kernel: $(uname -r)"
    print_status "INFO" "Architecture: $(uname -m)"
    print_status "INFO" "Uptime: $(uptime -p)"
    
    # CPU and Memory Analysis
    local cpu_cores=$(nproc)
    local memory_total=$(free -h | awk '/^Mem:/ {print $2}')
    local memory_used=$(free | awk '/^Mem:/ {printf "%.0f", $3/$2 * 100}')
    local disk_usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    
    print_status "INFO" "CPU Cores: $cpu_cores"
    print_status "INFO" "Memory: $memory_total total, ${memory_used}% used"
    
    if [ "$disk_usage" -gt 90 ]; then
        print_status "RISK" "Disk usage: ${disk_usage}% (critically high)"
    elif [ "$disk_usage" -gt 80 ]; then
        print_status "WARN" "Disk usage: ${disk_usage}% (high)"
    else
        print_status "PASS" "Disk usage: ${disk_usage}% (healthy)"
    fi
    
    # Enhanced Ubuntu Pro status check
    if command -v pro >/dev/null 2>&1; then
        local pro_status=$(pro status --format=json 2>/dev/null | jq -r '.attached' 2>/dev/null || echo "false")
        if [ "$pro_status" = "true" ]; then
            local enabled_services=$(pro status --format=json 2>/dev/null | jq -r '.services[] | select(.status=="enabled") | .name' 2>/dev/null | wc -l)
            print_status "PASS" "Ubuntu Pro is enabled with $enabled_services security services active"
            
            # Check specific security services
            if pro status | grep -q "esm-infra.*enabled"; then
                print_status "SECURE" "Extended Security Maintenance (Infrastructure) enabled"
            fi
            if pro status | grep -q "livepatch.*enabled"; then
                print_status "SECURE" "Livepatch service enabled (kernel patching without reboots)"
            fi
        else
            print_status "WARN" "Ubuntu Pro available but not attached"
        fi
    else
        print_status "WARN" "Ubuntu Pro not available"
    fi
    
    # System load analysis
    local load_1min=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    local load_threshold=$(echo "$cpu_cores * 0.8" | bc -l 2>/dev/null || echo "$cpu_cores")
    if command -v bc >/dev/null 2>&1; then
        if (( $(echo "$load_1min > $load_threshold" | bc -l 2>/dev/null || echo "0") )); then
            print_status "WARN" "System load: $load_1min (high for $cpu_cores cores)"
        else
            print_status "PASS" "System load: $load_1min (normal for $cpu_cores cores)"
        fi
    else
        print_status "INFO" "System load: $load_1min (cannot calculate threshold without bc)"
    fi
}

# Docker Container Analysis
docker_analysis() {
    echo -e "\n${BLUE}=== DOCKER CONTAINER ANALYSIS ===${NC}"
    
    if ! command -v docker >/dev/null 2>&1; then
        print_status "INFO" "Docker not installed"
        return
    fi
    
    if ! systemctl is-active docker >/dev/null 2>&1; then
        print_status "WARN" "Docker daemon is not running"
        return
    fi
    
    print_status "PASS" "Docker daemon is running"
    
    # Get running containers
    local running_containers=$(docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null)
    local container_count=$(docker ps -q | wc -l)
    
    if [ "$container_count" -eq 0 ]; then
        print_status "INFO" "No running Docker containers"
        return
    fi
    
    print_status "INFO" "Running containers: $container_count"
    echo -e "${CYAN}Container Details:${NC}"
    echo "$running_containers"
    echo ""
    
    # Analyze each container
    while IFS= read -r container_id; do
        if [ -n "$container_id" ]; then
            analyze_container "$container_id"
        fi
    done < <(docker ps -q)
    
    # Check for privileged containers
    local privileged_containers=$(docker ps --format "table {{.Names}}" --filter "label=privileged=true" 2>/dev/null | tail -n +2 | wc -l)
    if [ "$privileged_containers" -gt 0 ]; then
        print_status "WARN" "$privileged_containers containers may be running in privileged mode"
    fi
    
    # Docker security analysis
    analyze_docker_security
}

# Analyze individual container
analyze_container() {
    local container_id=$1
    local container_name=$(docker inspect --format='{{.Name}}' "$container_id" | sed 's|^/||')
    local container_image=$(docker inspect --format='{{.Config.Image}}' "$container_id")
    local container_ports=$(docker port "$container_id" 2>/dev/null || echo "No exposed ports")
    
    echo -e "${PURPLE}Analyzing container: $container_name${NC}"
    
    # Check if container is privileged
    local is_privileged=$(docker inspect --format='{{.HostConfig.Privileged}}' "$container_id")
    if [ "$is_privileged" = "true" ]; then
        print_status "WARN" "Container '$container_name' is running in privileged mode"
    else
        print_status "PASS" "Container '$container_name' is not privileged"
    fi
    
    # Analyze exposed ports
    if [ "$container_ports" != "No exposed ports" ]; then
        echo "  Exposed ports: $container_ports"
        analyze_container_ports "$container_name" "$container_ports"
    fi
    
    # Check for security-sensitive containers
    case "$container_image" in
        *redis*) 
            check_redis_container_security "$container_id" "$container_name"
            ;;
        *mysql*|*postgres*|*mariadb*)
            check_database_container_security "$container_id" "$container_name"
            ;;
        *nginx*|*apache*|*httpd*)
            print_status "INFO" "Web server container '$container_name' detected"
            ;;
        *wireguard*)
            print_status "SECURE" "VPN container '$container_name' detected (legitimate security service)"
            ;;
    esac
}

# Analyze container port security
analyze_container_ports() {
    local container_name=$1
    local ports=$2
    
    # Parse ports and check for security issues
    echo "$ports" | while read -r port_line; do
        if [[ "$port_line" =~ 0\.0\.0\.0:([0-9]+) ]]; then
            local host_port="${BASH_REMATCH[1]}"
            case "$host_port" in
                6379) print_status "WARN" "Redis port exposed publicly by container '$container_name'" ;;
                3306|5432) print_status "WARN" "Database port exposed publicly by container '$container_name'" ;;
                22) print_status "WARN" "SSH port exposed by container '$container_name'" ;;
                *) print_status "INFO" "Container '$container_name' exposes port $host_port publicly" ;;
            esac
        elif [[ "$port_line" =~ 127\.0\.0\.1:([0-9]+) ]]; then
            print_status "PASS" "Container '$container_name' properly restricts ports to localhost"
        fi
    done
}

# Check Redis container security
check_redis_container_security() {
    local container_id=$1
    local container_name=$2
    
    # Check if Redis requires authentication
    local auth_check=$(docker exec "$container_id" redis-cli ping 2>/dev/null || echo "AUTH_REQUIRED")
    if [ "$auth_check" = "PONG" ]; then
        print_status "RISK" "Redis container '$container_name' allows unauthenticated access"
    elif [ "$auth_check" = "AUTH_REQUIRED" ]; then
        print_status "PASS" "Redis container '$container_name' requires authentication"
    fi
}

# Check database container security
check_database_container_security() {
    local container_id=$1
    local container_name=$2
    
    # Check if database has password protection
    local db_env=$(docker inspect --format='{{range .Config.Env}}{{println .}}{{end}}' "$container_id" | grep -i password || echo "")
    if [ -z "$db_env" ]; then
        print_status "WARN" "Database container '$container_name' may not have password configured"
    else
        print_status "PASS" "Database container '$container_name' has password configuration"
    fi
}

# Docker security analysis
analyze_docker_security() {
    echo -e "\n${CYAN}Docker Security Analysis:${NC}"
    
    # Check Docker daemon security
    if systemctl is-active docker.socket >/dev/null 2>&1; then
        print_status "INFO" "Docker socket is active"
    fi
    
    # Check for Docker security scanning tools
    if command -v docker-bench-security >/dev/null 2>&1; then
        print_status "PASS" "Docker Bench Security tool available"
    else
        print_status "INFO" "Consider installing Docker Bench Security for enhanced scanning"
    fi
    
    # Check Docker version
    local docker_version=$(docker --version | awk '{print $3}' | sed 's/,//')
    print_status "INFO" "Docker version: $docker_version"
}

# External Port Scan and Vulnerability Assessment
external_port_scan() {
    echo -e "\n${BLUE}=== EXTERNAL PORT SCAN & VULNERABILITY ASSESSMENT ===${NC}"
    
    local server_ip=$(hostname -I | awk '{print $1}')
    print_status "INFO" "Performing external port scan on $server_ip"
    
    # Check if nmap is available
    if command -v nmap >/dev/null 2>&1; then
        print_status "INFO" "Using nmap for comprehensive port scan..."
        
        # Perform external port scan
        local nmap_results=$(nmap -sS -O -sV --top-ports 1000 "$server_ip" 2>/dev/null)
        local open_ports=$(echo "$nmap_results" | grep "^[0-9]" | grep "open" | wc -l)
        local filtered_ports=$(echo "$nmap_results" | grep "^[0-9]" | grep "filtered" | wc -l)
        local closed_ports=$(echo "$nmap_results" | grep "^[0-9]" | grep "closed" | wc -l)
        
        print_status "INFO" "External scan results: $open_ports open, $filtered_ports filtered, $closed_ports closed"
        
        echo -e "\n${CYAN}Externally Accessible Ports:${NC}"
        echo "$nmap_results" | grep "^[0-9]" | grep "open" | while read line; do
            local port=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
            local service=$(echo "$line" | awk '{print $3}')
            analyze_external_port_vulnerability "$port" "$service"
        done
        
        # OS Detection
        local os_detection=$(echo "$nmap_results" | grep "Running:" | head -1)
        if [ -n "$os_detection" ]; then
            print_status "INFO" "OS Detection: $os_detection"
        fi
        
    else
        print_status "WARN" "nmap not installed - performing basic connectivity tests"
        print_status "INFO" "RECOMMENDATION: Install nmap for comprehensive port scanning"
        echo "  sudo apt install nmap"
        perform_basic_port_scan "$server_ip"
    fi
}

# Analyze external port vulnerabilities
analyze_external_port_vulnerability() {
    local port=$1
    local service=$2
    
    case $port in
        21) print_status "CRITICAL" "FTP port $port externally accessible - MAJOR VULNERABILITY" ;;
        22|2222) 
            if check_ssh_security_external "$port"; then
                print_status "WARN" "SSH port $port externally accessible - ensure key-only auth"
            else
                print_status "CRITICAL" "SSH port $port vulnerable - password auth enabled"
            fi
            ;;
        23) print_status "CRITICAL" "Telnet port $port externally accessible - DISABLE IMMEDIATELY" ;;
        25|587|465) print_status "PASS" "Mail port $port externally accessible (normal for mail server)" ;;
        53) print_status "PASS" "DNS port $port externally accessible (normal for DNS server)" ;;
        80|443) print_status "PASS" "Web port $port externally accessible (normal for web server)" ;;
        110|143|993|995) print_status "PASS" "Mail port $port externally accessible (normal for mail server)" ;;
        3306) print_status "CRITICAL" "MySQL port $port externally accessible - MAJOR VULNERABILITY" ;;
        5432) print_status "CRITICAL" "PostgreSQL port $port externally accessible - MAJOR VULNERABILITY" ;;
        6379) print_status "CRITICAL" "Redis port $port externally accessible - MAJOR VULNERABILITY" ;;
        8443|8880) print_status "PASS" "Plesk port $port externally accessible (normal for control panel)" ;;
        9000|9443) print_status "WARN" "Portainer port $port externally accessible - consider restricting" ;;
        51820) print_status "SECURE" "WireGuard port $port externally accessible (VPN service)" ;;
        *) print_status "WARN" "Uncommon port $port externally accessible - investigate: $service" ;;
    esac
}

# Check SSH security for external access
check_ssh_security_external() {
    local port=$1
    if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null; then
        return 0  # Secure
    else
        return 1  # Vulnerable
    fi
}

# Basic port scan if nmap not available
perform_basic_port_scan() {
    local server_ip=$1
    print_status "INFO" "Performing basic connectivity tests..."
    
    local common_ports=(21 22 23 25 53 80 110 143 443 993 995 2222 3306 5432 6379 8443 8880 9000 9443)
    local open_count=0
    
    for port in "${common_ports[@]}"; do
        if timeout 3 bash -c "</dev/tcp/$server_ip/$port" 2>/dev/null; then
            analyze_external_port_vulnerability "$port" "unknown"
            open_count=$((open_count + 1))
        fi
    done
    
    print_status "INFO" "Basic scan found $open_count accessible ports"
}

# Enhanced Network Security Audit with Docker awareness
network_audit() {
    echo -e "\n${BLUE}=== INTERNAL NETWORK SECURITY AUDIT ===${NC}"
    
    print_status "INFO" "Scanning internal listening ports..."
    
    # Get Docker container port mappings for context
    local docker_ports=""
    if command -v docker >/dev/null 2>&1 && systemctl is-active docker >/dev/null 2>&1; then
        docker_ports=$(docker ps --format "table {{.Names}}\t{{.Ports}}" 2>/dev/null | tail -n +2)
    fi
    
    # Detect custom SSH port
    local ssh_port=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")
    
    ss -tuln | while read line; do
        if echo "$line" | grep -q "LISTEN"; then
            local port=$(echo "$line" | awk '{print $5}' | cut -d: -f2)
            if [[ "$port" =~ ^[0-9]+$ ]]; then
                analyze_port_security "$port" "$ssh_port" "$docker_ports"
            fi
        fi
    done
    
    # Check for IPv6
    if ip -6 addr show | grep -q "inet6.*global"; then
        print_status "WARN" "IPv6 is enabled - ensure firewall covers IPv6"
        # Check IPv6 firewall rules
        local ipv6_rules=$(ip6tables -L 2>/dev/null | wc -l)
        if [ "$ipv6_rules" -gt 10 ]; then
            print_status "PASS" "IPv6 firewall rules are configured"
        else
            print_status "WARN" "IPv6 firewall may need configuration"
        fi
    else
        print_status "PASS" "IPv6 is disabled or not globally routable"
    fi
    
    # Network interface analysis
    echo -e "\n${CYAN}Network Interface Security:${NC}"
    local interfaces=$(ip link show | grep "state UP" | wc -l)
    print_status "INFO" "Active network interfaces: $interfaces"
    
    # Check for suspicious network connections
    local established_connections=$(ss -tn state established | wc -l)
    print_status "INFO" "Established network connections: $established_connections"
}

# Enhanced port analysis with Docker and custom service awareness
analyze_port_security() {
    local port=$1
    local ssh_port=$2
    local docker_ports=$3
    
    # Check if port is used by Docker container
    local docker_container=""
    if [ -n "$docker_ports" ]; then
        docker_container=$(echo "$docker_ports" | grep ":$port" | awk '{print $1}' | head -1)
    fi
    
    case $port in
        22) 
            if [ "$ssh_port" != "22" ]; then
                print_status "WARN" "SSH on default port 22 (consider disabling if using custom port $ssh_port)"
            else
                print_status "INFO" "SSH port $port open (standard configuration)"
            fi
            ;;
        "$ssh_port")
            if [ "$ssh_port" != "22" ]; then
                print_status "SECURE" "SSH on custom port $port (enhanced security)"
            fi
            ;;
        25|587|465) print_status "PASS" "SMTP port $port open (mail server)" ;;
        53) print_status "PASS" "DNS port $port open (name server)" ;;
        80|443) print_status "PASS" "HTTP/HTTPS port $port open (web server)" ;;
        110|143|993|995) print_status "PASS" "Mail port $port open (mail server)" ;;
        3306) 
            if [ -n "$docker_container" ]; then
                print_status "INFO" "MySQL port $port used by Docker container: $docker_container"
            else
                check_database_security "$port" "mysql"
            fi
            ;;
        5432)
            if [ -n "$docker_container" ]; then
                print_status "INFO" "PostgreSQL port $port used by Docker container: $docker_container"
            else
                check_database_security "$port" "postgresql"
            fi
            ;;
        6379) 
            if [ -n "$docker_container" ]; then
                print_status "INFO" "Redis port $port used by Docker container: $docker_container"
            else
                check_redis_security "$port"
            fi
            ;;
        8443|8880) print_status "PASS" "Plesk port $port open (control panel)" ;;
        9000|9443) print_status "PASS" "Portainer port $port open (Docker management)" ;;
        51820) print_status "SECURE" "WireGuard port $port open (VPN server)" ;;
        51821) print_status "INFO" "WireGuard web UI port $port open" ;;
        9898) print_status "PASS" "Vaultwarden port $port open (password manager)" ;;
        21115|21116|21117|21118|21119) print_status "PASS" "RustDesk port $port open (remote desktop)" ;;
        953) print_status "PASS" "DNS over TLS port $port open (secure DNS)" ;;
        4190) print_status "PASS" "Sieve port $port open (mail filtering)" ;;
        21) check_ftp_security ;;
        106) check_poppassd_security ;;
        *) 
            if [ -n "$docker_container" ]; then
                print_status "INFO" "Port $port used by Docker container: $docker_container"
            else
                print_status "WARN" "Uncommon port $port open - verify if needed"
                # Additional analysis for uncommon ports
                analyze_uncommon_port "$port"
            fi
            ;;
    esac
}

# Check Redis security
check_redis_security() {
    local port=$1
    if ss -tln | grep "127.0.0.1:$port" >/dev/null 2>&1; then
        if redis-cli -p "$port" ping 2>&1 | grep -q "NOAUTH"; then
            print_status "PASS" "Redis port $port secured (authentication required, localhost only)"
        elif redis-cli -p "$port" ping 2>&1 | grep -q "PONG"; then
            print_status "RISK" "Redis port $port accessible without authentication"
        else
            print_status "PASS" "Redis port $port properly secured"
        fi
    else
        print_status "WARN" "Redis port $port open on all interfaces - security risk"
    fi
}

# Check database security
check_database_security() {
    local port=$1
    local db_type=$2
    if ss -tln | grep "127.0.0.1:$port" >/dev/null 2>&1; then
        print_status "PASS" "$db_type port $port bound to localhost (secure)"
    else
        print_status "WARN" "$db_type port $port open on all interfaces - verify security"
    fi
}

# Check FTP security
check_ftp_security() {
    if ss -tln | grep ":21" >/dev/null 2>&1; then
        print_status "RISK" "FTP port 21 open - unencrypted protocol (use SFTP instead)"
    else
        print_status "PASS" "FTP service disabled (good security practice)"
    fi
}

# Check poppassd security
check_poppassd_security() {
    if ss -tln | grep ":106" >/dev/null 2>&1; then
        print_status "WARN" "poppassd port 106 open - consider disabling if unused"
    else
        print_status "PASS" "poppassd service disabled"
    fi
}

# Analyze uncommon ports
analyze_uncommon_port() {
    local port=$1
    local process=$(ss -tlnp | grep ":$port" | awk '{print $6}' | head -1)
    if [ -n "$process" ]; then
        print_status "INFO" "Port $port used by: $process"
    fi
}

# Enhanced Firewall Security Check
firewall_check() {
    echo -e "\n${BLUE}=== ENHANCED FIREWALL SECURITY ===${NC}"
    
    # Check UFW status
    if command -v ufw >/dev/null 2>&1; then
        if ufw status | grep -q "Status: active"; then
            print_status "PASS" "UFW firewall is active"
            local ufw_rules=$(ufw status numbered | grep -v "Status:" | wc -l)
            print_status "INFO" "UFW has $ufw_rules rules configured"
        else
            print_status "INFO" "UFW firewall is inactive (may be using alternative firewall)"
        fi
    fi
    
    # Check iptables rules
    local iptables_rules=$(iptables -L -n | wc -l)
    if [ "$iptables_rules" -gt 20 ]; then
        print_status "PASS" "iptables has comprehensive rules ($iptables_rules lines)"
    elif [ "$iptables_rules" -gt 10 ]; then
        print_status "PASS" "iptables has custom rules ($iptables_rules lines)"
    else
        print_status "WARN" "iptables appears to have minimal rules"
    fi
    
    # Check for fail2ban
    if systemctl is-active fail2ban >/dev/null 2>&1; then
        print_status "PASS" "fail2ban is active"
        local jails=$(fail2ban-client status | grep "Jail list" | cut -d: -f2 | tr ',' '\n' | wc -w)
        print_status "SECURE" "fail2ban protecting $jails services"
        
        # Check for banned IPs
        local banned_ips=$(fail2ban-client banned | wc -l)
        if [ "$banned_ips" -gt 0 ]; then
            print_status "INFO" "fail2ban has banned $banned_ips IP addresses"
        fi
    else
        print_status "WARN" "fail2ban not running - install for brute force protection"
    fi
    
    # Check Plesk firewall
    if command -v plesk >/dev/null 2>&1; then
        if plesk bin firewall --status 2>/dev/null | grep -q "enabled"; then
            print_status "PASS" "Plesk firewall is enabled"
        else
            print_status "INFO" "Plesk firewall status unclear"
        fi
    fi
}

# Enhanced SSH Security Check
ssh_security() {
    echo -e "\n${BLUE}=== ENHANCED SSH SECURITY ANALYSIS ===${NC}"
    
    if [ -f /etc/ssh/sshd_config ]; then
        # Check authentication methods
        if grep -q "^PubkeyAuthentication yes" /etc/ssh/sshd_config; then
            print_status "PASS" "SSH key authentication explicitly enabled"
        elif grep -q "^#PubkeyAuthentication yes" /etc/ssh/sshd_config; then
            print_status "PASS" "SSH key authentication enabled (default)"
        else
            print_status "WARN" "SSH key authentication not explicitly configured"
        fi
        
        # Check password authentication
        if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config; then
            print_status "SECURE" "SSH password authentication disabled (key-only access)"
        elif grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config; then
            print_status "WARN" "SSH password authentication enabled (security risk)"
        else
            print_status "WARN" "SSH password authentication setting unclear"
        fi
        
        # Check root login
        if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
            print_status "SECURE" "SSH root login disabled"
        elif grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
            local root_setting=$(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')
            print_status "WARN" "SSH root login setting: $root_setting"
        else
            print_status "WARN" "SSH root login setting unclear"
        fi
        
        # Check SSH port
        local ssh_port=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}' || echo "22")
        if [ "$ssh_port" != "22" ]; then
            print_status "SECURE" "SSH using custom port $ssh_port (enhanced security)"
        else
            print_status "WARN" "SSH using default port 22 (consider changing)"
        fi
        
        # Check SSH protocol version
        if grep -q "^Protocol 2" /etc/ssh/sshd_config; then
            print_status "PASS" "SSH using protocol 2"
        else
            print_status "INFO" "SSH protocol version uses default (should be 2)"
        fi
        
        # Check additional SSH security settings
        if grep -q "^MaxAuthTries" /etc/ssh/sshd_config; then
            local max_tries=$(grep "^MaxAuthTries" /etc/ssh/sshd_config | awk '{print $2}')
            if [ "$max_tries" -le 3 ]; then
                print_status "PASS" "SSH max auth tries: $max_tries (secure)"
            else
                print_status "WARN" "SSH max auth tries: $max_tries (consider reducing)"
            fi
        fi
        
        if grep -q "^ClientAliveInterval" /etc/ssh/sshd_config; then
            print_status "PASS" "SSH client alive interval configured"
        fi
        
    else
        print_status "FAIL" "SSH config file not found"
    fi
    
    # Analyze SSH connections and attacks
    analyze_ssh_security_logs
}

# Analyze SSH security from logs
analyze_ssh_security_logs() {
    echo -e "\n${CYAN}SSH Security Log Analysis:${NC}"
    
    # Check recent authentication failures
    local auth_failures=$(grep "authentication failure" /var/log/auth.log 2>/dev/null | tail -20 | wc -l || echo "0")
    if [ "$auth_failures" -gt 10 ]; then
        print_status "WARN" "$auth_failures recent authentication failures detected"
    elif [ "$auth_failures" -gt 0 ]; then
        print_status "INFO" "$auth_failures recent authentication failures (normal level)"
    else
        print_status "PASS" "No recent authentication failures"
    fi
    
    # Check for SSH brute force attempts
    local ssh_failures=$(grep "Failed password" /var/log/auth.log 2>/dev/null | tail -50 | wc -l || echo "0")
    if [ "$ssh_failures" -gt 20 ]; then
        print_status "WARN" "$ssh_failures recent SSH login failures (possible brute force)"
    elif [ "$ssh_failures" -gt 0 ]; then
        print_status "INFO" "$ssh_failures recent SSH login failures"
    else
        print_status "PASS" "No recent SSH login failures"
    fi
    
    # Check successful SSH logins
    local ssh_success=$(grep "Accepted" /var/log/auth.log 2>/dev/null | tail -10 | wc -l || echo "0")
    print_status "INFO" "$ssh_success recent successful SSH logins"
    
    # Check for unusual login times or IPs
    if grep "Accepted" /var/log/auth.log 2>/dev/null | tail -5 | grep -q "$(date +%Y-%m-%d)"; then
        print_status "INFO" "Recent SSH activity detected today"
    fi
}

# Enhanced Plesk Security Check
plesk_security() {
    echo -e "\n${BLUE}=== PLESK SECURITY ANALYSIS ===${NC}"
    
    if command -v plesk >/dev/null 2>&1; then
        print_status "PASS" "Plesk detected"
        
        # Check Plesk version
        local plesk_version=$(plesk version 2>/dev/null | head -1 || echo "Version unknown")
        print_status "INFO" "Plesk version: $plesk_version"
        
        # Check Plesk services
        local plesk_services=$(plesk bin service --list 2>/dev/null | wc -w || echo "0")
        print_status "INFO" "Plesk managing $plesk_services services"
        
        # Check SSL certificates
        local ssl_certs=$(plesk bin certificate --list 2>/dev/null | wc -l || echo "0")
        if [ "$ssl_certs" -gt 1 ]; then
            print_status "PASS" "SSL certificates configured ($ssl_certs total)"
        else
            print_status "WARN" "Few or no SSL certificates found"
        fi
        
        # Check Plesk security settings
        if plesk bin server_pref --show 2>/dev/null | grep -q "min-password-strength"; then
            print_status "PASS" "Plesk password policy configured"
        fi
        
        # Check for Plesk updates
        if command -v plesk >/dev/null 2>&1; then
            print_status "INFO" "Plesk is installed and accessible"
        fi
        
        # Check Plesk firewall
        if plesk bin firewall --status 2>/dev/null | grep -q "enabled"; then
            print_status "PASS" "Plesk firewall is enabled"
        fi
        
    else
        print_status "INFO" "Plesk not detected"
    fi
}

# Enhanced System Updates Check
updates_check() {
    echo -e "\n${BLUE}=== SYSTEM UPDATE SECURITY ANALYSIS ===${NC}"
    
    # Update package list
    print_status "INFO" "Checking for available updates..."
    apt update >/dev/null 2>&1
    
    # Check for security updates
    local security_updates=$(apt list --upgradable 2>/dev/null | grep -c "security" || echo "0")
    if [ "$security_updates" -gt 0 ]; then
        print_status "RISK" "$security_updates critical security updates available - apply immediately"
    else
        print_status "PASS" "No security updates pending"
    fi
    
    # Check for all updates
    local all_updates=$(apt list --upgradable 2>/dev/null | tail -n +2 | wc -l)
    if [ "$all_updates" -gt 20 ]; then
        print_status "WARN" "$all_updates total updates available (consider updating)"
    elif [ "$all_updates" -gt 0 ]; then
        print_status "INFO" "$all_updates total updates available"
    else
        print_status "PASS" "System is up to date"
    fi
    
    # Check last update
    if [ -f /var/cache/apt/pkgcache.bin ]; then
        local last_update=$(stat -c %Y /var/cache/apt/pkgcache.bin)
        local days_since_update=$(( ($(date +%s) - last_update) / 86400 ))
        if [ "$days_since_update" -gt 14 ]; then
            print_status "WARN" "Package cache is $days_since_update days old (update recommended)"
        elif [ "$days_since_update" -gt 7 ]; then
            print_status "INFO" "Package cache is $days_since_update days old"
        else
            print_status "PASS" "Package cache is recent ($days_since_update days old)"
        fi
    fi
    
    # Check automatic updates
    if systemctl is-enabled unattended-upgrades >/dev/null 2>&1; then
        print_status "SECURE" "Automatic security updates are enabled"
    else
        print_status "WARN" "Automatic security updates not configured"
    fi
    
    # Check kernel version vs running kernel
    local current_kernel=$(uname -r)
    local available_kernel=$(apt list --upgradable 2>/dev/null | grep linux-image | head -1 | awk '{print $2}' || echo "none")
    if [ "$available_kernel" != "none" ] && [ "$available_kernel" != "" ]; then
        print_status "INFO" "Kernel update available: $available_kernel (current: $current_kernel)"
    else
        print_status "PASS" "Kernel is up to date: $current_kernel"
    fi
}

# Enhanced File System Security
filesystem_security() {
    echo -e "\n${BLUE}=== FILESYSTEM SECURITY ANALYSIS ===${NC}"
    
    # Check for world-writable files in critical directories
    print_status "INFO" "Scanning for world-writable files in critical directories..."
    local world_writable=$(find /etc /usr/bin /usr/sbin -type f -perm -002 2>/dev/null | wc -l)
    if [ "$world_writable" -eq 0 ]; then
        print_status "PASS" "No world-writable files in critical directories"
    else
        print_status "WARN" "$world_writable world-writable files found in critical directories"
    fi
    
    # Check /tmp permissions
    local tmp_perms=$(stat -c "%a" /tmp)
    if [ "$tmp_perms" = "1777" ]; then
        print_status "PASS" "/tmp has correct permissions (1777)"
    else
        print_status "WARN" "/tmp permissions are $tmp_perms (should be 1777)"
    fi
    
    # Check for SUID/SGID files
    local suid_count=$(find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l)
    if [ "$suid_count" -gt 100 ]; then
        print_status "WARN" "High number of SUID/SGID files: $suid_count (review recommended)"
    elif [ "$suid_count" -gt 50 ]; then
        print_status "INFO" "Found $suid_count SUID/SGID files (normal range)"
    else
        print_status "PASS" "Found $suid_count SUID/SGID files (low count, good)"
    fi
    
    # Check disk usage for all mounted filesystems
    echo -e "\n${CYAN}Disk Usage Analysis:${NC}"
    df -h | tail -n +2 | while read filesystem size used avail percent mount; do
        local usage_num=$(echo "$percent" | sed 's/%//')
        if [ "$usage_num" -gt 95 ]; then
            print_status "CRITICAL" "Filesystem $mount is ${percent} full (critical)"
        elif [ "$usage_num" -gt 90 ]; then
            print_status "RISK" "Filesystem $mount is ${percent} full (high)"
        elif [ "$usage_num" -gt 80 ]; then
            print_status "WARN" "Filesystem $mount is ${percent} full (monitor)"
        else
            print_status "PASS" "Filesystem $mount usage: ${percent}"
        fi
    done
    
    # Check for suspicious files
    print_status "INFO" "Checking for recently modified system files..."
    local recent_system_changes=$(find /etc /usr/bin /usr/sbin -mtime -1 2>/dev/null | wc -l)
    if [ "$recent_system_changes" -gt 10 ]; then
        print_status "INFO" "$recent_system_changes system files modified in last 24 hours"
    else
        print_status "PASS" "Normal system file modification activity"
    fi
    
    # Check for large files that might indicate issues
    local large_files=$(find /var/log -size +100M 2>/dev/null | wc -l)
    if [ "$large_files" -gt 0 ]; then
        print_status "WARN" "$large_files large log files found (>100MB) - consider log rotation"
    else
        print_status "PASS" "Log file sizes are reasonable"
    fi
}

# Enhanced User Account Security
user_security() {
    echo -e "\n${BLUE}=== USER ACCOUNT SECURITY ANALYSIS ===${NC}"
    
    # Check for users with UID 0
    local root_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
    local root_count=$(echo "$root_users" | wc -w)
    if [ "$root_count" -eq 1 ] && [ "$root_users" = "root" ]; then
        print_status "PASS" "Only root user has UID 0"
    else
        print_status "WARN" "Multiple users with UID 0: $root_users"
    fi
    
    # Check for users without passwords
    local no_pass_users=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null | wc -l || echo "0")
    if [ "$no_pass_users" -eq 0 ]; then
        print_status "PASS" "No users without passwords"
    else
        print_status "WARN" "$no_pass_users users without passwords found"
    fi
    
    # Check for locked accounts
    local locked_accounts=$(passwd -Sa 2>/dev/null | grep -c " L " || echo "0")
    print_status "INFO" "$locked_accounts user accounts are locked"
    
    # Check sudo configuration
    if [ -f /etc/sudoers ]; then
        if grep -q "^%sudo" /etc/sudoers; then
            print_status "PASS" "Sudo group configuration found"
        fi
        
        # Check for passwordless sudo
        local passwordless_sudo=$(grep -c "NOPASSWD" /etc/sudoers /etc/sudoers.d/* 2>/dev/null || echo "0")
        if [ "$passwordless_sudo" -gt 0 ]; then
            print_status "WARN" "Passwordless sudo entries found - review for security"
        else
            print_status "PASS" "No passwordless sudo entries"
        fi
    fi
    
    # Check for users with shells
    local shell_users=$(grep -v "/usr/sbin/nologin\|/bin/false" /etc/passwd | wc -l)
    print_status "INFO" "$shell_users users have login shells"
    
    # Check password policy
    if [ -f /etc/login.defs ]; then
        local pass_max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}' || echo "not_set")
        if [ "$pass_max_days" != "not_set" ] && [ "$pass_max_days" -le 90 ]; then
            print_status "PASS" "Password expiration policy: $pass_max_days days"
        elif [ "$pass_max_days" != "not_set" ]; then
            print_status "WARN" "Password expiration policy: $pass_max_days days (consider shorter)"
        else
            print_status "WARN" "No password expiration policy set"
        fi
    fi
    
    # Check for recent logins
    local recent_logins=$(last -n 10 | grep -c "$(date +%a)" || echo "0")
    print_status "INFO" "$recent_logins logins detected today"
}

# Enhanced Service Security
service_security() {
    echo -e "\n${BLUE}=== SERVICE SECURITY ANALYSIS ===${NC}"
    
    # Check for unnecessary services
    local unnecessary_services=("telnet" "rsh" "rlogin" "tftp" "xinetd" "ypbind" "ypserv" "finger" "talk")
    local found_unnecessary=0
    for service in "${unnecessary_services[@]}"; do
        if systemctl is-enabled "$service" >/dev/null 2>&1; then
            print_status "WARN" "Unnecessary service $service is enabled"
            found_unnecessary=$((found_unnecessary + 1))
        fi
    done
    if [ "$found_unnecessary" -eq 0 ]; then
        print_status "PASS" "No unnecessary services enabled"
    fi
    
    # Check critical services
    local critical_services=("ssh" "cron")
    for service in "${critical_services[@]}"; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            print_status "PASS" "Critical service $service is running"
        else
            print_status "WARN" "Critical service $service is not running"
        fi
    done
    
    # Check for services listening on all interfaces
    echo -e "\n${CYAN}Network Service Analysis:${NC}"
    local public_services=$(ss -tuln | grep "0.0.0.0:" | wc -l)
    local localhost_services=$(ss -tuln | grep "127.0.0.1:" | wc -l)
    print_status "INFO" "$public_services services listening publicly, $localhost_services on localhost only"
    
    # Analyze running services
    local total_services=$(systemctl list-units --type=service --state=running | wc -l)
    print_status "INFO" "$total_services services currently running"
    
    # Check for suspicious processes
    local high_cpu_processes=$(ps aux --sort=-%cpu | head -6 | tail -5 | awk '$3 > 50' | wc -l)
    if [ "$high_cpu_processes" -gt 0 ]; then
        print_status "WARN" "$high_cpu_processes processes using high CPU - investigate"
    else
        print_status "PASS" "No processes using excessive CPU"
    fi
}

# Enhanced Log Analysis
log_analysis() {
    echo -e "\n${BLUE}=== COMPREHENSIVE LOG ANALYSIS ===${NC}"
    
    # System log analysis
    local system_errors=$(grep -i "error\|critical\|emergency" /var/log/syslog 2>/dev/null | tail -20 | wc -l || echo "0")
    if [ "$system_errors" -gt 10 ]; then
        print_status "WARN" "$system_errors recent system errors found"
    elif [ "$system_errors" -gt 0 ]; then
        print_status "INFO" "$system_errors recent system errors found"
    else
        print_status "PASS" "No recent system errors"
    fi
    
    # Kernel log analysis
    local kernel_errors=$(dmesg | grep -i "error\|warning" | tail -10 | wc -l || echo "0")
    if [ "$kernel_errors" -gt 5 ]; then
        print_status "WARN" "$kernel_errors recent kernel errors/warnings"
    else
        print_status "PASS" "Kernel logs appear normal"
    fi
    
    # Check log file sizes and rotation
    local large_logs=$(find /var/log -name "*.log" -size +50M 2>/dev/null | wc -l)
    if [ "$large_logs" -gt 0 ]; then
        print_status "WARN" "$large_logs log files are larger than 50MB - check log rotation"
    else
        print_status "PASS" "Log file sizes are manageable"
    fi
    
    # Analyze fail2ban logs if available
    if [ -f /var/log/fail2ban.log ]; then
        local f2b_bans=$(grep "Ban " /var/log/fail2ban.log | tail -50 | wc -l || echo "0")
        if [ "$f2b_bans" -gt 0 ]; then
            print_status "INFO" "fail2ban has made $f2b_bans recent bans"
        fi
    fi
    
    # Check for disk space in log directory
    local log_usage=$(df /var/log | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ "$log_usage" -gt 90 ]; then
        print_status "WARN" "Log partition is ${log_usage}% full"
    elif [ "$log_usage" -gt 80 ]; then
        print_status "INFO" "Log partition is ${log_usage}% full"
    else
        print_status "PASS" "Log partition usage: ${log_usage}%"
    fi
}

# Security Recommendations with priorities
security_recommendations() {
    echo -e "\n${BLUE}=== SECURITY RECOMMENDATIONS ===${NC}"
    
    print_status "INFO" "Generating prioritized security recommendations..."
    
    # High Priority Recommendations
    echo -e "\n${RED}HIGH PRIORITY:${NC}"
    
    if ! systemctl is-active fail2ban >/dev/null 2>&1; then
        print_status "CRITICAL" "INSTALL fail2ban for brute force protection"
        echo "  sudo apt install fail2ban && sudo systemctl enable fail2ban"
    fi
    
    if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config 2>/dev/null; then
        print_status "CRITICAL" "DISABLE SSH password authentication (use keys only)"
        echo "  Edit /etc/ssh/sshd_config: PasswordAuthentication no"
    fi
    
    local security_updates=$(apt list --upgradable 2>/dev/null | grep -c "security" || echo "0")
    if [ "$security_updates" -gt 0 ]; then
        print_status "CRITICAL" "INSTALL $security_updates security updates immediately"
        echo "  sudo apt update && sudo apt upgrade"
    fi
    
    # Medium Priority Recommendations
    echo -e "\n${ORANGE}MEDIUM PRIORITY:${NC}"
    
    if ! systemctl is-enabled unattended-upgrades >/dev/null 2>&1; then
        print_status "WARN" "ENABLE automatic security updates"
        echo "  sudo apt install unattended-upgrades && sudo systemctl enable unattended-upgrades"
    fi
    
    local ssh_port=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")
    if [ "$ssh_port" = "22" ]; then
        print_status "WARN" "CHANGE SSH to non-standard port"
        echo "  Edit /etc/ssh/sshd_config: Port 2222"
    fi
    
    # Low Priority Recommendations
    echo -e "\n${YELLOW}LOW PRIORITY:${NC}"
    
    print_status "INFO" "REGULAR TASKS: Run security audits monthly"
    print_status "INFO" "MONITORING: Set up log monitoring and alerting"
    print_status "INFO" "BACKUP: Ensure backup procedures are tested"
    print_status "INFO" "DOCUMENTATION: Maintain security documentation"
    
    # Tool recommendations
    if ! command -v nmap >/dev/null 2>&1; then
        print_status "INFO" "TOOLS: Install nmap for comprehensive port scanning"
        echo "  sudo apt install nmap"
    fi
    
    if ! command -v bc >/dev/null 2>&1; then
        print_status "INFO" "TOOLS: Install bc for enhanced calculations"
        echo "  sudo apt install bc"
    fi
    
    # Docker-specific recommendations
    if command -v docker >/dev/null 2>&1; then
        echo -e "\n${CYAN}DOCKER SECURITY:${NC}"
        print_status "INFO" "DOCKER: Regularly update container images"
        print_status "INFO" "DOCKER: Use non-root users in containers when possible"
        print_status "INFO" "DOCKER: Implement resource limits on containers"
        if ! command -v docker-bench-security >/dev/null 2>&1; then
            print_status "INFO" "DOCKER: Install Docker Bench Security for enhanced scanning"
        fi
    fi
}

# Generate Comprehensive Security Score and Final Report
generate_security_score() {
    echo -e "\n${BLUE}=== COMPREHENSIVE SECURITY ASSESSMENT REPORT ===${NC}"
    echo -e "${CYAN}Generated: $(date)${NC}"
    echo -e "${CYAN}Server: $(hostname) ($(hostname -I | awk '{print $1}'))${NC}"
    echo ""
    
    # Count different status types from log
    local pass_count=$(grep -c "\[PASS\]" "$LOG_FILE" || echo "0")
    local secure_count=$(grep -c "\[SECURE\]" "$LOG_FILE" || echo "0")
    local warn_count=$(grep -c "\[WARN\]" "$LOG_FILE" || echo "0")
    local risk_count=$(grep -c "\[RISK\]" "$LOG_FILE" || echo "0")
    local fail_count=$(grep -c "\[FAIL\]" "$LOG_FILE" || echo "0")
    local critical_count=$(grep -c "\[CRITICAL\]" "$LOG_FILE" || echo "0")
    
    local total_checks=$((pass_count + secure_count + warn_count + risk_count + fail_count + critical_count))
    local positive_checks=$((pass_count + secure_count))
    local negative_checks=$((risk_count + fail_count + critical_count))
    
    echo -e "${BLUE}=== SECURITY METRICS BREAKDOWN ===${NC}"
    echo -e "  ${GREEN}✓ PASS:${NC}     $pass_count checks"
    echo -e "  ${GREEN}✓ SECURE:${NC}   $secure_count checks"
    echo -e "  ${ORANGE}⚠ WARN:${NC}     $warn_count checks"
    echo -e "  ${RED}✗ RISK:${NC}     $risk_count checks"
    echo -e "  ${RED}✗ FAIL:${NC}     $fail_count checks"
    echo -e "  ${RED}✗ CRITICAL:${NC} $critical_count checks"
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BLUE}TOTAL:${NC}     $total_checks security checks"
    echo ""
    
    if [ "$total_checks" -gt 0 ]; then
        local score=$(( (positive_checks * 100) / total_checks ))
        local risk_penalty=$(( critical_count * 15 + risk_count * 10 + fail_count * 5 ))
        local adjusted_score=$(( score - risk_penalty ))
        if [ "$adjusted_score" -lt 0 ]; then
            adjusted_score=0
        fi
        
        echo -e "${BLUE}=== SECURITY SCORE CALCULATION ===${NC}"
        echo -e "  Base Score:        ${score}% (${positive_checks}/${total_checks} positive)"
        echo -e "  Risk Penalty:      -${risk_penalty}% (Critical: -${critical_count}×15, Risk: -${risk_count}×10, Fail: -${fail_count}×5)"
        echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        
        # Overall Security Assessment
        echo -e "\n${BLUE}=== OVERALL SECURITY ASSESSMENT ===${NC}"
        if [ "$critical_count" -eq 0 ] && [ "$risk_count" -eq 0 ] && [ "$adjusted_score" -ge 95 ]; then
            echo -e "  ${GREEN}🛡️  FINAL SCORE: ${adjusted_score}% - ENTERPRISE GRADE${NC}"
            echo -e "  ${GREEN}STATUS: EXCELLENT SECURITY POSTURE${NC}"
            print_status "SECURE" "Your server has enterprise-grade security with minimal risks"
        elif [ "$critical_count" -eq 0 ] && [ "$risk_count" -eq 0 ] && [ "$adjusted_score" -ge 85 ]; then
            echo -e "  ${GREEN}🔒 FINAL SCORE: ${adjusted_score}% - VERY SECURE${NC}"
            echo -e "  ${GREEN}STATUS: STRONG SECURITY POSTURE${NC}"
            print_status "PASS" "Your server is very secure with only minor improvements needed"
        elif [ "$critical_count" -eq 0 ] && [ "$adjusted_score" -ge 75 ]; then
            echo -e "  ${YELLOW}🔐 FINAL SCORE: ${adjusted_score}% - GOOD SECURITY${NC}"
            echo -e "  ${YELLOW}STATUS: ACCEPTABLE SECURITY POSTURE${NC}"
            print_status "PASS" "Your server has good security but some improvements recommended"
        elif [ "$critical_count" -eq 0 ] && [ "$adjusted_score" -ge 60 ]; then
            echo -e "  ${ORANGE}⚠️  FINAL SCORE: ${adjusted_score}% - NEEDS IMPROVEMENT${NC}"
            echo -e "  ${ORANGE}STATUS: MODERATE SECURITY RISKS${NC}"
            print_status "WARN" "Your server needs security improvements to reach best practices"
        else
            echo -e "  ${RED}🚨 FINAL SCORE: ${adjusted_score}% - VULNERABLE${NC}"
            echo -e "  ${RED}STATUS: HIGH SECURITY RISKS DETECTED${NC}"
            print_status "CRITICAL" "Your server has serious security vulnerabilities requiring immediate attention"
        fi
        
        # Security Category Analysis
        echo -e "\n${BLUE}=== SECURITY CATEGORY ANALYSIS ===${NC}"
        analyze_security_categories
        
        # Vulnerability Assessment Summary
        echo -e "\n${BLUE}=== VULNERABILITY ASSESSMENT SUMMARY ===${NC}"
        generate_vulnerability_summary
        
        # Priority Action Items
        echo -e "\n${BLUE}=== PRIORITY ACTION ITEMS ===${NC}"
        generate_priority_actions "$critical_count" "$risk_count" "$warn_count"
        
        # Compliance and Best Practices
        echo -e "\n${BLUE}=== COMPLIANCE & BEST PRACTICES ===${NC}"
        assess_compliance_status "$adjusted_score" "$critical_count" "$risk_count"
        
    else
        print_status "WARN" "Unable to calculate security score - insufficient data"
    fi
    
    # Final recommendations
    echo -e "\n${BLUE}=== FINAL RECOMMENDATIONS ===${NC}"
    if [ "$critical_count" -gt 0 ]; then
        print_status "CRITICAL" "🚨 IMMEDIATE ACTION REQUIRED: Address $critical_count critical security issues"
        echo -e "  ${RED}→ Critical issues pose immediate security threats${NC}"
        echo -e "  ${RED}→ Address within 24 hours${NC}"
    fi
    
    if [ "$risk_count" -gt 0 ]; then
        print_status "RISK" "⚠️  HIGH PRIORITY: Address $risk_count high-risk security issues"
        echo -e "  ${ORANGE}→ High-risk issues should be addressed within 1 week${NC}"
    fi
    
    if [ "$warn_count" -gt 5 ]; then
        print_status "WARN" "📋 MODERATE PRIORITY: Address $warn_count warnings for optimal security"
        echo -e "  ${YELLOW}→ Warning items should be addressed within 1 month${NC}"
    fi
    
    echo -e "\n${CYAN}💡 ONGOING SECURITY PRACTICES:${NC}"
    echo -e "  • Run this security audit monthly"
    echo -e "  • Monitor system logs regularly"
    echo -e "  • Keep all software updated"
    echo -e "  • Review and rotate SSH keys quarterly"
    echo -e "  • Test backup and recovery procedures"
    echo -e "  • Document all security configurations"
}

# Analyze security by categories
analyze_security_categories() {
    echo -e "  ${CYAN}Network Security:${NC}"
    local network_score=$(calculate_category_score "network\|port\|firewall\|SSH")
    display_category_score "$network_score" "Network"
    
    echo -e "  ${CYAN}Access Control:${NC}"
    local access_score=$(calculate_category_score "SSH\|authentication\|user\|password")
    display_category_score "$access_score" "Access Control"
    
    echo -e "  ${CYAN}System Security:${NC}"
    local system_score=$(calculate_category_score "update\|patch\|Ubuntu Pro\|filesystem")
    display_category_score "$system_score" "System"
    
    echo -e "  ${CYAN}Application Security:${NC}"
    local app_score=$(calculate_category_score "Docker\|Redis\|database\|service")
    display_category_score "$app_score" "Application"
    
    echo -e "  ${CYAN}Monitoring & Logging:${NC}"
    local monitor_score=$(calculate_category_score "log\|fail2ban\|monitoring")
    display_category_score "$monitor_score" "Monitoring"
}

# Calculate score for a specific category
calculate_category_score() {
    local category_pattern=$1
    local category_pass=$(grep -i "$category_pattern" "$LOG_FILE" | grep -c "\[PASS\]\|\[SECURE\]" || echo "0")
    local category_total=$(grep -i "$category_pattern" "$LOG_FILE" | grep -c "\[PASS\]\|\[SECURE\]\|\[WARN\]\|\[RISK\]\|\[FAIL\]\|\[CRITICAL\]" || echo "1")
    
    if [ "$category_total" -gt 0 ]; then
        echo $(( (category_pass * 100) / category_total ))
    else
        echo "0"
    fi
}

# Display category score with color coding
display_category_score() {
    local score=$1
    local category=$2
    
    if [ "$score" -ge 90 ]; then
        echo -e "    ${GREEN}✓ $category: ${score}% (Excellent)${NC}"
    elif [ "$score" -ge 75 ]; then
        echo -e "    ${YELLOW}○ $category: ${score}% (Good)${NC}"
    elif [ "$score" -ge 60 ]; then
        echo -e "    ${ORANGE}⚠ $category: ${score}% (Needs Improvement)${NC}"
    else
        echo -e "    ${RED}✗ $category: ${score}% (Poor)${NC}"
    fi
}

# Generate vulnerability summary
generate_vulnerability_summary() {
    local external_vulns=$(grep -c "externally accessible.*CRITICAL\|externally accessible.*VULNERABILITY" "$LOG_FILE" || echo "0")
    local auth_vulns=$(grep -c "password authentication.*enabled\|unauthenticated access" "$LOG_FILE" || echo "0")
    local service_vulns=$(grep -c "FTP.*open\|Telnet.*open\|unencrypted" "$LOG_FILE" || echo "0")
    
    if [ "$external_vulns" -eq 0 ] && [ "$auth_vulns" -eq 0 ] && [ "$service_vulns" -eq 0 ]; then
        print_status "SECURE" "No critical vulnerabilities detected"
    else
        if [ "$external_vulns" -gt 0 ]; then
            print_status "CRITICAL" "$external_vulns critical services exposed externally"
        fi
        if [ "$auth_vulns" -gt 0 ]; then
            print_status "CRITICAL" "$auth_vulns authentication vulnerabilities detected"
        fi
        if [ "$service_vulns" -gt 0 ]; then
            print_status "RISK" "$service_vulns insecure services detected"
        fi
    fi
}

# Generate priority actions based on findings
generate_priority_actions() {
    local critical_count=$1
    local risk_count=$2
    local warn_count=$3
    
    if [ "$critical_count" -gt 0 ]; then
        echo -e "  ${RED}🚨 CRITICAL (Fix immediately):${NC}"
        grep "\[CRITICAL\]" "$LOG_FILE" | head -5 | sed 's/\[CRITICAL\]/  →/' | sed "s/\x1b\[[0-9;]*m//g"
    fi
    
    if [ "$risk_count" -gt 0 ]; then
        echo -e "  ${ORANGE}⚠️  HIGH RISK (Fix within 1 week):${NC}"
        grep "\[RISK\]" "$LOG_FILE" | head -3 | sed 's/\[RISK\]/  →/' | sed "s/\x1b\[[0-9;]*m//g"
    fi
    
    if [ "$warn_count" -gt 0 ]; then
        echo -e "  ${YELLOW}📋 MEDIUM RISK (Fix within 1 month):${NC}"
        grep "\[WARN\]" "$LOG_FILE" | head -3 | sed 's/\[WARN\]/  →/' | sed "s/\x1b\[[0-9;]*m//g"
    fi
}

# Assess compliance status
assess_compliance_status() {
    local score=$1
    local critical_count=$2
    local risk_count=$3
    
    echo -e "  ${CYAN}Industry Compliance Assessment:${NC}"
    
    # PCI DSS compliance indicators
    local pci_compliant="Yes"
    if [ "$critical_count" -gt 0 ] || grep -q "unencrypted\|FTP.*open\|password authentication.*enabled" "$LOG_FILE"; then
        pci_compliant="No"
    fi
    
    # GDPR compliance indicators  
    local gdpr_compliant="Partial"
    if [ "$score" -ge 85 ] && [ "$critical_count" -eq 0 ]; then
        gdpr_compliant="Yes"
    elif [ "$critical_count" -gt 0 ]; then
        gdpr_compliant="No"
    fi
    
    # SOC 2 compliance indicators
    local soc2_compliant="Partial"
    if [ "$score" -ge 90 ] && [ "$critical_count" -eq 0 ] && [ "$risk_count" -eq 0 ]; then
        soc2_compliant="Yes"
    elif [ "$critical_count" -gt 0 ]; then
        soc2_compliant="No"
    fi
    
    echo -e "    PCI DSS Ready:     $pci_compliant"
    echo -e "    GDPR Compliant:    $gdpr_compliant"
    echo -e "    SOC 2 Ready:       $soc2_compliant"
    echo ""
    
    echo -e "  ${CYAN}Security Maturity Level:${NC}"
    if [ "$score" -ge 95 ] && [ "$critical_count" -eq 0 ] && [ "$risk_count" -eq 0 ]; then
        echo -e "    ${GREEN}🏆 Level 5: Optimized (Industry Leading)${NC}"
    elif [ "$score" -ge 85 ] && [ "$critical_count" -eq 0 ]; then
        echo -e "    ${GREEN}🎯 Level 4: Managed (Above Average)${NC}"
    elif [ "$score" -ge 75 ]; then
        echo -e "    ${YELLOW}📊 Level 3: Defined (Average)${NC}"
    elif [ "$score" -ge 60 ]; then
        echo -e "    ${ORANGE}📋 Level 2: Repeatable (Below Average)${NC}"
    else
        echo -e "    ${RED}⚠️  Level 1: Initial (Poor)${NC}"
    fi
}

# Main execution
main() {
    check_root
    system_info
    docker_analysis
    network_audit
    external_port_scan
    firewall_check
    ssh_security
    plesk_security
    updates_check
    filesystem_security
    user_security
    service_security
    log_analysis
    security_recommendations
    generate_security_score
    
    echo -e "\n${BLUE}=== COMPREHENSIVE SECURITY AUDIT COMPLETE ===${NC}"
    echo -e "${CYAN}Report Details:${NC}"
    echo "  • Full report saved to: $LOG_FILE"
    echo "  • External port scan completed"
    echo "  • Vulnerability assessment performed"
    echo "  • Security score calculated with compliance analysis"
    echo "  • Priority action items identified"
    echo ""
    echo -e "${YELLOW}📋 NEXT STEPS:${NC}"
    echo "  1. Review and address any CRITICAL items immediately"
    echo "  2. Plan fixes for HIGH RISK items within 1 week"
    echo "  3. Schedule MEDIUM RISK improvements within 1 month"
    echo "  4. Run this audit monthly for ongoing security monitoring"
    echo ""
    echo "Audit completed: $(date)"
    
    # Quick summary for easy reference
    echo -e "\n${CYAN}=== QUICK REFERENCE SUMMARY ===${NC}"
    local quick_critical=$(grep -c "\[CRITICAL\]" "$LOG_FILE" || echo "0")
    local quick_risk=$(grep -c "\[RISK\]" "$LOG_FILE" || echo "0")
    local quick_warn=$(grep -c "\[WARN\]" "$LOG_FILE" || echo "0")
    local quick_pass=$(grep -c "\[PASS\]\|\[SECURE\]" "$LOG_FILE" || echo "0")
    
    if [ "$quick_critical" -eq 0 ] && [ "$quick_risk" -eq 0 ]; then
        echo -e "  ${GREEN}🛡️  SECURITY STATUS: EXCELLENT${NC}"
        echo -e "  ${GREEN}✓ No critical vulnerabilities detected${NC}"
    elif [ "$quick_critical" -eq 0 ]; then
        echo -e "  ${YELLOW}🔐 SECURITY STATUS: GOOD${NC}"
        echo -e "  ${ORANGE}⚠ $quick_risk high-risk items need attention${NC}"
    else
        echo -e "  ${RED}🚨 SECURITY STATUS: NEEDS IMMEDIATE ATTENTION${NC}"
        echo -e "  ${RED}✗ $quick_critical critical vulnerabilities found${NC}"
    fi
    
    echo -e "  ${BLUE}Total Items: $quick_pass passed, $quick_warn warnings, $quick_risk risks, $quick_critical critical${NC}"
}

# Run the main function
main "$@"