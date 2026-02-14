# 🛡️ Enhanced Ubuntu Security Audit Script

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04%2B-orange.svg)](https://ubuntu.com/)
[![Shell Script](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-red.svg)](https://github.com/yourusername/security-audit)

A comprehensive, enterprise-grade security audit script for Ubuntu servers with Docker, Plesk, and cloud infrastructure support. Provides detailed vulnerability assessment, compliance analysis, and prioritized security recommendations.

## 📋 Table of Contents

- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Usage](#-usage)
- [Security Checks](#-security-checks)
- [Output Examples](#-output-examples)
- [Configuration](#-configuration)
- [Advanced Features](#-advanced-features)
- [Compliance Standards](#-compliance-standards)
- [Contributing](#-contributing)
- [License](#-license)
- [Support](#-support)

## ✨ Features

### 🔍 **Comprehensive Security Assessment**
- **External Port Scanning** with nmap integration
- **Internal Service Analysis** with Docker container awareness
- **Vulnerability Detection** for critical exposures
- **Security Score Calculation** with industry benchmarks

### 🎯 **Smart Analysis Engine**
- **Context-Aware Classification** (distinguishes legitimate Docker services)
- **Custom Configuration Recognition** (SSH custom ports, Redis localhost-only)
- **Service-Specific Security Checks** (database exposure, authentication strength)
- **Risk-Based Prioritization** (Critical → High → Medium → Low)

### 📊 **Enterprise Reporting**
- **Detailed Security Metrics** with color-coded output
- **Compliance Assessment** (PCI DSS, GDPR, SOC 2)
- **Security Maturity Scoring** (5-level industry standard)
- **Priority Action Plans** with timeframes

### 🐳 **Multi-Platform Support**
- **Docker Container Security** analysis and recommendations
- **Plesk Integration** with component-aware scanning
- **Cloud Infrastructure** compatible (AWS, DigitalOcean, etc.)
- **Ubuntu Pro** subscription analysis and optimization

## 🔧 Prerequisites

### Required System Access
```bash
# Must be run as root or with sudo privileges
sudo -i
```

### Required Packages
```bash
# Essential packages (automatically checked by script)
apt update
apt install -y curl wget net-tools

# Highly recommended for full functionality
apt install -y nmap bc jq

# Optional but beneficial
apt install -y fail2ban unattended-upgrades
```

### System Requirements
- **Operating System**: Ubuntu 18.04+ (tested on 20.04, 22.04, 24.04)
- **Memory**: Minimum 512MB RAM (1GB+ recommended)
- **Disk Space**: 100MB free space for logs and reports
- **Network**: Internet access for external scanning and updates

### Supported Environments
- ✅ **Bare Metal Servers**
- ✅ **Virtual Private Servers (VPS)**
- ✅ **Cloud Instances** (AWS EC2, DigitalOcean Droplets, etc.)
- ✅ **Docker Host Systems**
- ✅ **Plesk-managed Servers**
- ✅ **Ubuntu Pro Subscriptions**

## 🚀 Installation

### Quick Install
```bash
# Download the script
curl -fsSL https://raw.githubusercontent.com/yourusername/security-audit/main/security-audit.sh -o security-audit.sh

# Make executable
chmod +x security-audit.sh

# Move to system location
sudo mv security-audit.sh /usr/local/bin/security-audit

# Install recommended packages
sudo apt install -y nmap bc jq fail2ban
```

### Manual Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/security-audit.git
cd security-audit

# Copy script to system location
sudo cp security-audit.sh /usr/local/bin/security-audit
sudo chmod +x /usr/local/bin/security-audit

# Install dependencies
sudo apt install -y nmap bc jq
```

### Automated Setup
```bash
# Run the setup script (if provided)
curl -fsSL https://raw.githubusercontent.com/yourusername/security-audit/main/setup.sh | sudo bash
```

## 📖 Usage

### Basic Security Audit
```bash
# Run comprehensive security audit
sudo security-audit

# Run with verbose output
sudo security-audit --verbose

# Save report to custom location
sudo security-audit --output /path/to/custom/report.log
```

### Advanced Options
```bash
# Skip external port scanning (faster, internal-only)
sudo security-audit --no-external-scan

# Focus on specific security categories
sudo security-audit --category network,docker,ssh

# Generate compliance report only
sudo security-audit --compliance-only

# Schedule automated monthly audits
sudo crontab -e
# Add: 0 2 1 * * /usr/local/bin/security-audit --quiet --email admin@example.com
```

### Docker-Specific Scanning
```bash
# Enhanced Docker security analysis
sudo security-audit --docker-focus

# Scan specific containers only
sudo security-audit --containers "container1,container2"
```

## 🔍 Security Checks

### Network Security
- [x] **External Port Scanning** (nmap-based vulnerability detection)
- [x] **Internal Service Analysis** (listening services and bindings)
- [x] **Firewall Configuration** (UFW, iptables, Plesk firewall)
- [x] **IPv6 Security** (configuration and exposure analysis)
- [x] **Network Interface Analysis** (active interfaces and routing)

### Access Control
- [x] **SSH Security** (authentication methods, key management, port configuration)
- [x] **User Account Analysis** (password policies, sudo configuration, locked accounts)
- [x] **Authentication Systems** (PAM configuration, login restrictions)
- [x] **Privilege Escalation** (SUID/SGID files, sudo policies)

### System Security
- [x] **Update Management** (security patches, Ubuntu Pro status, kernel updates)
- [x] **File System Security** (permissions, world-writable files, disk usage)
- [x] **System Configuration** (boot security, core dumps, memory protection)
- [x] **Resource Management** (CPU/memory limits, process analysis)

### Application Security
- [x] **Docker Container Security** (privileged containers, exposed ports, image analysis)
- [x] **Database Security** (Redis, MySQL, PostgreSQL exposure and authentication)
- [x] **Web Server Security** (Apache, Nginx configuration analysis)
- [x] **Service Configuration** (running services, unnecessary daemons)

### Monitoring & Logging
- [x] **Log Analysis** (system errors, authentication failures, security events)
- [x] **Intrusion Detection** (fail2ban status, banned IPs, attack patterns)
- [x] **System Monitoring** (resource usage, suspicious processes)
- [x] **Audit Trail** (command history, file modifications)

### Plesk-Specific Checks
- [x] **Plesk Security** (version analysis, component security, SSL certificates)
- [x] **Mail Server Security** (Postfix/Dovecot configuration, spam protection)
- [x] **Web Hosting Security** (virtual host isolation, PHP security)
- [x] **Control Panel Security** (admin access, password policies)

## 📊 Output Examples

### Security Score Report
```
=== COMPREHENSIVE SECURITY ASSESSMENT REPORT ===
Generated: Sat Jul 5 10:00:00 AM CEST 2025
Server: example.com (192.168.1.100)

=== SECURITY METRICS BREAKDOWN ===
  ✓ PASS:     45 checks
  ✓ SECURE:   12 checks  
  ⚠ WARN:     8 checks
  ✗ RISK:     2 checks
  ✗ FAIL:     0 checks
  ✗ CRITICAL: 0 checks
  ━━━━━━━━━━━━━━━━━━━━
  TOTAL:     67 security checks

=== SECURITY SCORE CALCULATION ===
  Base Score:        85% (57/67 positive)
  Risk Penalty:      -20% (Risk: -2×10)
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  
🛡️  FINAL SCORE: 85% - VERY SECURE
STATUS: STRONG SECURITY POSTURE
```

### Category Analysis
```
=== SECURITY CATEGORY ANALYSIS ===
  Network Security:
    ✓ Network: 92% (Excellent)
  Access Control:
    ✓ Access Control: 88% (Excellent)
  System Security:
    ○ System: 78% (Good)
  Application Security:
    ✓ Application: 85% (Excellent)
  Monitoring & Logging:
    ○ Monitoring: 76% (Good)
```

### Priority Actions
```
=== PRIORITY ACTION ITEMS ===
  ⚠️  HIGH RISK (Fix within 1 week):
  → Redis port 6379 externally accessible - MAJOR VULNERABILITY
  → SSH password authentication enabled - security risk

  📋 MEDIUM RISK (Fix within 1 month):
  → 15 system updates available
  → IPv6 firewall needs configuration
  → Log files larger than 50MB detected
```

### Compliance Assessment
```
=== COMPLIANCE & BEST PRACTICES ===
Industry Compliance Assessment:
    PCI DSS Ready:     Partial
    GDPR Compliant:    Yes
    SOC 2 Ready:       Yes

Security Maturity Level:
    🎯 Level 4: Managed (Above Average)
```

## ⚙️ Configuration

### Environment Variables
```bash
# Customize audit behavior
export AUDIT_SKIP_EXTERNAL=true          # Skip external port scanning
export AUDIT_DOCKER_FOCUS=true           # Enhanced Docker analysis
export AUDIT_QUIET_MODE=true             # Minimal output
export AUDIT_LOG_RETENTION=30            # Days to keep audit logs
export AUDIT_EMAIL_ALERTS=admin@example.com  # Email critical findings
```

### Configuration File
Create `/etc/security-audit.conf`:
```bash
# Security Audit Configuration
SKIP_EXTERNAL_SCAN=false
DOCKER_ENHANCED_ANALYSIS=true
EMAIL_CRITICAL_ALERTS=true
EMAIL_RECIPIENT="security@example.com"
LOG_RETENTION_DAYS=30
NMAP_TIMING_TEMPLATE=4
COMPLIANCE_FRAMEWORKS="PCI,GDPR,SOC2"
```

### Custom Risk Thresholds
```bash
# Adjust scoring thresholds in script
CRITICAL_PENALTY=15    # Points deducted per critical issue
RISK_PENALTY=10        # Points deducted per risk issue
WARN_PENALTY=2         # Points deducted per warning
```

## 🚀 Advanced Features

### Automated Scheduling
```bash
# Setup automated monthly audits
sudo crontab -e

# Add these lines:
# Monthly comprehensive audit (1st of month at 2 AM)
0 2 1 * * /usr/local/bin/security-audit --quiet --email

# Weekly quick scan (Sundays at 3 AM)
0 3 * * 0 /usr/local/bin/security-audit --quick --email-critical-only
```

### Integration with Monitoring Systems
```bash
# Nagios/Icinga integration
sudo security-audit --nagios-output

# Zabbix integration
sudo security-audit --zabbix-sender

# Custom webhook integration
sudo security-audit --webhook https://monitoring.example.com/security-audit
```

### Docker Integration
```bash
# Run as Docker container
docker run -v /:/host:ro --privileged security-audit:latest

# Docker Compose integration
version: '3.8'
services:
  security-audit:
    image: security-audit:latest
    volumes:
      - /:/host:ro
    environment:
      - AUDIT_EMAIL_ALERTS=true
    privileged: true
    schedule: "0 2 * * *"  # Daily at 2 AM
```

## 📋 Compliance Standards

### Supported Frameworks
- **PCI DSS** (Payment Card Industry Data Security Standard)
- **GDPR** (General Data Protection Regulation)
- **SOC 2** (Service Organization Control 2)
- **ISO 27001** (Information Security Management)
- **NIST Cybersecurity Framework**
- **CIS Controls** (Center for Internet Security)

### Compliance Features
- ✅ **Automated Assessment** against industry standards
- ✅ **Gap Analysis** with remediation recommendations
- ✅ **Evidence Collection** for audit documentation
- ✅ **Risk Rating** aligned with compliance requirements
- ✅ **Reporting** suitable for compliance officers

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone and setup development environment
git clone https://github.com/yourusername/security-audit.git
cd security-audit

# Install development dependencies
sudo apt install -y shellcheck bats

# Run tests
make test

# Check code quality
make lint
```

### Reporting Issues
- 🐛 **Bug Reports**: Use the [Issue Template](.github/ISSUE_TEMPLATE/bug_report.md)
- ✨ **Feature Requests**: Use the [Feature Template](.github/ISSUE_TEMPLATE/feature_request.md)
- 🔒 **Security Issues**: Email security@example.com (GPG key available)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Documentation
- 📖 **Wiki**: [Comprehensive documentation](https://github.com/yourusername/security-audit/wiki)
- 🎥 **Video Tutorials**: [YouTube Playlist](https://youtube.com/playlist?list=example)
- 📚 **Examples**: [Real-world use cases](examples/)

### Community Support
- 💬 **Discord**: [Join our community](https://discord.gg/example)
- 📧 **Mailing List**: security-audit@googlegroups.com
- 🐦 **Twitter**: [@SecurityAudit](https://twitter.com/securityaudit)

### Professional Support
- 🏢 **Enterprise Support**: enterprise@example.com
- 🔧 **Custom Development**: consulting@example.com
- 📊 **Training Services**: training@example.com

---

## 🌟 Acknowledgments

- **Ubuntu Security Team** for security best practices
- **Docker Security Team** for container security guidelines
- **Plesk Development Team** for API documentation
- **Community Contributors** for testing and feedback

## 📈 Statistics

![GitHub stars](https://img.shields.io/github/stars/yourusername/security-audit)
![GitHub forks](https://img.shields.io/github/forks/yourusername/security-audit)
![GitHub issues](https://img.shields.io/github/issues/yourusername/security-audit)
![GitHub pull requests](https://img.shields.io/github/issues-pr/yourusername/security-audit)

---

**⭐ If this project helped secure your infrastructure, please consider giving it a star!**

Made with ❤️ for the cybersecurity community# Push mirror test - 2026-02-14T05:23:37Z
