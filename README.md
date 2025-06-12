# SuperSimpleScanner

Trying to recreate powerful and user-friendly network scanner built in Python with both GUI and CLI interfaces, **inspired by and aiming to replicate core functionalities of the renowned Nmap**. SuperSimpleScanner provides comprehensive network reconnaissance capabilities including port scanning, host discovery, service detection, OS fingerprinting, and traceroute functionality.

![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)

## Features

### 🔍 **Comprehensive Scanning**
- **Port Scanning**: TCP Connect, SYN Stealth, UDP scans
- **Host Discovery**: ICMP, ARP, TCP/UDP ping techniques  
- **Service Detection**: Banner grabbing, version detection (**Simulated/Basic functionality only**)
- **OS Detection**: Advanced fingerprinting techniques (**Simulated/Basic functionality only**)
- **Traceroute**: Multiple methods (ICMP, UDP, system)

### ⚡ **Performance & Stealth**
- **Timing Templates**: 6 predefined timing profiles (T0-T5)
- **Adaptive Scanning**: Auto-adjusts to network conditions
- **Parallel Processing**: Multi-threaded scanning
- **Stealth Techniques**: Evasion and randomization

### 🖥️ **Dual Interface**
- **Graphical Interface**: Intuitive PyQt5-based GUI
- **Command Line**: Powerful CLI with extensive options
- **Interactive Demo**: Built-in tutorial and examples

### 🛡️ **Security Features**
- **Capabilities Support**: Passwordless privileged scans
- **Permission Management**: Smart sudo/capabilities detection
- **Safe Defaults**: Responsible scanning practices

## Installation

### Prerequisites
- Python 3.7 or higher
- Linux

### Quick Install
```bash
# Clone the repository
git clone https://github.com/5coinin1/Scanner-Tool-.git
cd Scanner-Tool-

# Make launcher executable
chmod +x run_scanner.sh

# Install dependencies (auto-handled by launcher)
./run_scanner.sh setup
```

### Manual Installation
```bash
# Install Python dependencies
pip3 install -r requirements.txt

# For Linux: Install system dependencies
sudo apt-get update
sudo apt-get install python3-dev python3-pip libpcap-dev

# Set up capabilities for passwordless scanning (optional)
sudo setcap cap_net_raw=eip $(which python3)
```

## Quick Start

### GUI Mode
```bash
./run_scanner.sh gui
```

### Basic CLI Scanning
```bash
# Simple port scan
./run_scanner.sh 192.168.1.1 -p 22,80,443

# Fast aggressive scan
./run_scanner.sh 192.168.1.1 -T4

# Stealth SYN scan
./run_scanner.sh 192.168.1.1 -sS -T2
```

### Interactive Tutorial
```bash
./run_scanner.sh demo
```

## Usage Examples

### Port Scanning
```bash
# Basic TCP connect scan
./run_scanner.sh 192.168.1.1 -sT -p 80,443

# SYN stealth scan (requires capabilities/sudo)
./run_scanner.sh 192.168.1.1 -sS -p 1-1000

# UDP scan with service detection
./run_scanner.sh 192.168.1.1 -sU -p 53,161,123

# Comprehensive service scan
./run_scanner.sh 192.168.1.1 --service-scan -sV
```

### Host Discovery
```bash
# Network discovery
./run_scanner.sh 192.168.1.0/24 --host-discovery

# ICMP ping sweep
./run_scanner.sh 192.168.1.1 -PE

# Advanced discovery (all methods)
./run_scanner.sh 192.168.1.0/24 -PA
```

### Advanced Features
```bash
# OS detection
./run_scanner.sh 192.168.1.1 --os-scan

# Traceroute
./run_scanner.sh traceroute google.com

# Timing templates
./run_scanner.sh 192.168.1.1 -T0  # Paranoid (very slow)
./run_scanner.sh 192.168.1.1 -T4  # Aggressive (fast)
```

## Command Line Options

### Scan Types
- `-sS` - SYN scan (stealth, requires root)
- `-sT` - TCP Connect scan (reliable, no root needed)
- `-sU` - UDP scan with service detection
- `-sn` - Host discovery only (no port scan)
- `--service-scan` - Comprehensive service enumeration

### Host Discovery
- `-PE` - ICMP Echo ping
- `-PP` - ICMP Timestamp ping
- `-PM` - ICMP Address Mask ping
- `-PS` - TCP SYN ping
- `-PU` - UDP ping
- `-PR` - ARP ping (local network)
- `-PA` - Advanced discovery (all methods)

### Timing Control
- `-T0` - Paranoid (very slow, maximum stealth)
- `-T1` - Sneaky (slow, high stealth)
- `-T2` - Polite (slower, less bandwidth)
- `-T3` - Normal (default balanced timing)
- `-T4` - Aggressive (fast, assumes good network)
- `-T5` - Insane (very fast, may miss results)

### Advanced Options
- `-O` - Enable OS detection
- `-sV` - Service version detection
- `--parallel` - Parallel scanning
- `--stealth` - Stealth mode with evasion
- `--adaptive` - Adaptive scanning

## GUI Features

The graphical interface provides:

- **Visual Scan Configuration**: Point-and-click scan setup
- **Real-time Results**: Live updating scan results
- **Traceroute Visualization**: Network topology mapping
- **Export Capabilities**: Save results in multiple formats
- **Timing Controls**: Easy timing template selection
- **Service Analysis**: Detailed service information
- **Progress Tracking**: Visual scan progress indicators

### Launch GUI
```bash
./run_scanner.sh gui
```

## Capabilities Setup

For passwordless privileged scans (SYN, ICMP, OS detection):

```bash
# Setup capabilities (requires sudo once)
./run_scanner.sh setup

# Check current status
./run_scanner.sh status

# Remove capabilities
./run_scanner.sh remove-caps
```

This allows running privileged scans without sudo by granting network capabilities to Python.

## Configuration

### Timing Templates
```bash
# Custom timing via environment
export SCANNER_TIMING=aggressive
./run_scanner.sh target

# Direct timing specification
./run_scanner.sh target --timing polite
```

### Port Specifications
```bash
# Individual ports
-p 80,443,8080,8443

# Port ranges
-p 1-1000

# Service names
-p http,https,ssh,ftp

# Protocol specific
-p T:80,U:53  # TCP:80, UDP:53

# Predefined categories
-p web        # Web services
-p database   # Database ports
-p top100     # Top 100 ports (default)
```

## Requirements

### Python Packages
- `PyQt5>=5.15.10` - GUI framework
- `scapy>=2.5.0` - Network packet manipulation
- `colorama` - Terminal colors (auto-installed)

### System Requirements
- **Linux**: Full feature support, recommended
- **macOS**: Full support with some limitations
- **Windows**: Basic functionality, limited raw socket support

### For Advanced Features
- **Root/Admin privileges** OR **Linux capabilities** for:
  - SYN scanning
  - ICMP ping
  - OS detection
  - Raw packet manipulation


## Security & Ethics

### Responsible Usage
- **Only scan networks you own or have explicit permission to test**
- **Respect rate limits and timing controls**
- **Follow local laws and regulations**
- **Use stealth options responsibly**

### Built-in Safety Features
- Default timing prevents network flooding
- Capability-based permission model
- Safe scan defaults and warnings
- Educational demo mode

## Troubleshooting

### Common Issues

**Permission Denied for SYN Scans**
```bash
# Solution: Setup capabilities
./run_scanner.sh setup
```

**GUI Won't Start**
```bash
# Install GUI dependencies
pip3 install PyQt5
# Or use CLI mode
./run_scanner.sh target -sT
```

**Slow Scanning**
```bash
# Use faster timing
./run_scanner.sh target -T4
```

**No Results on Windows**
```bash
# Use TCP Connect instead of SYN
./run_scanner.sh target -sT
```

### Getting Help
```bash
# Show help
./run_scanner.sh --help # Show help with run_scanner
./run_scanner.sh help # Show help with command-line

# Interactive tutorial
./run_scanner.sh demo

# Check system status
./run_scanner.sh status
```


## Acknowledgments

- Built with Python and PyQt5
- Uses Scapy for network packet manipulation
- Inspired by nmap and other network scanning tools
- Thanks to the open-source security community

---

**⚠️ Disclaimer**: This tool is for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and obtaining proper authorization before scanning networks they do not own.
