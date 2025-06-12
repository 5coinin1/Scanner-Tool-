#!/bin/bash

# SuperSimpleScanner Launch Script with Privilege Management

echo "=== SuperSimpleScanner Launch Script ==="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

# Check if we can use capabilities
check_capabilities() {
    if command -v setcap &> /dev/null && command -v getcap &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# Set up capabilities for Python to create raw sockets
setup_capabilities() {
    local python_path=$(which python3)
    
    if [ -z "$python_path" ]; then
        print_error "Python3 not found"
        return 1
    fi
    
    # Resolve symlinks to get real binary path
    local real_python_path=$(readlink -f "$python_path")
    
    print_info "Setting up network capabilities for Python3..."
    print_info "Python path: $python_path"
    print_info "Real binary: $real_python_path"
    
    # Check if already has capabilities
    if getcap "$real_python_path" | grep -q "cap_net_raw"; then
        print_status "Python3 already has raw socket capabilities"
        return 0
    fi
    
    # Try to set capabilities
    if sudo setcap cap_net_raw=eip "$real_python_path" 2>/dev/null; then
        print_status "Successfully set network capabilities for Python3"
        print_info "Now you can run scans without sudo!"
        return 0
    else
        print_warning "Failed to set capabilities. You'll need sudo for SYN scans."
        return 1
    fi
}

# Remove capabilities (for cleanup)
remove_capabilities() {
    local python_path=$(which python3)
    if [ -n "$python_path" ]; then
        print_info "Removing capabilities from Python3..."
        sudo setcap -r "$python_path" 2>/dev/null
        print_status "Capabilities removed"
    fi
}

# Setup function
setup_scanner() {
    print_info "Setting up SuperSimpleScanner for passwordless operation..."
    
    if check_capabilities; then
        echo
        print_info "This will set network capabilities for Python3 to allow raw socket creation"
        print_info "without requiring sudo for SYN scans, ICMP pings, etc."
        echo
        read -p "Do you want to setup capabilities? [Y/n]: " choice
        
        case "${choice,,}" in
            ""|"y"|"yes")
                setup_capabilities
                ;;
            "n"|"no")
                print_info "Setup cancelled. You'll need to use sudo for privileged scans."
                ;;
            *)
                print_warning "Invalid choice. Setup cancelled."
                ;;
        esac
    else
        print_warning "Linux capabilities not supported on this system"
        print_info "You'll need to use sudo for privileged scans."
    fi
}



# Check setup status
check_setup_status() {
    local python_path=$(which python3)
    local real_python_path=$(readlink -f "$python_path")
    
    print_info "Checking current setup..."
    
    if getcap "$real_python_path" 2>/dev/null | grep -q "cap_net_raw"; then
        print_status "Python3 has raw socket capabilities"
        print_info "✓ You can run SYN scans without sudo!"
        print_info "✓ ICMP pings work without sudo!"
        print_info "✓ OS detection works without sudo!"
        return 0
    else
        print_warning "Python3 does not have raw socket capabilities"
        print_info "✗ SYN scans will require sudo"
        print_info "✗ ICMP pings will require sudo"  
        print_info "✗ OS detection will require sudo"
        print_info "Run './run_scanner.sh setup' to fix this"
        return 1
    fi
}

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 is not installed"
    echo "    Please install Python 3 first"
    exit 1
fi

# Check if PyQt5 is installed
if ! python3 -c "import PyQt5" &> /dev/null; then
    echo "[!] PyQt5 is not installed"
    echo "[+] Installing PyQt5..."
    pip3 install PyQt5
    if [ $? -ne 0 ]; then
        echo "[!] Failed to install PyQt5"
        echo "    Please install manually: pip3 install PyQt5"
        exit 1
    fi
fi

# Check if Scapy is installed
if ! python3 -c "import scapy" &> /dev/null; then
    echo "[!] Scapy is not installed"
    echo "[+] Installing Scapy..."
    pip3 install scapy
    if [ $? -ne 0 ]; then
        echo "[!] Failed to install Scapy"
        echo "    Please install manually: pip3 install scapy"
        exit 1
    fi
fi

# Main execution logic
main() {
    # Parse command line arguments
    case "${1:-}" in
        "setup")
            setup_scanner
            exit 0
            ;;
        "status")
            check_setup_status
            exit 0
            ;;
        "remove-caps")
            remove_capabilities
            exit 0
            ;;
        "gui")
            shift
            run_gui "$@"
            exit 0
            ;;
        "scan")
            shift
            run_scanner "$@"
            exit 0
            ;;
        "traceroute"|"trace")
            shift
            run_traceroute "$@"
            exit 0
            ;;
        "demo")
            run_demo
            exit 0
            ;;
        "--help"|"-h")
            show_help
            exit 0
            ;;
        "")
            # No arguments - show menu
            show_menu
            ;;
        *)
            # Unknown argument - try to run as scan
            run_scanner "$@"
            ;;
    esac
}

# Show interactive menu
show_menu() {
    echo
    echo "SuperSimpleScanner Options:"
    echo "1) Run GUI"
    echo "2) Setup passwordless scanning"
    echo "3) Check setup status"
    echo "4) Run traceroute"
    echo "5) Run demo/tutorial"
    echo "6) Show help"
    echo "7) Exit"
    echo
    print_info "For CLI scans, use: $0 <target> <options>"
    print_info "Example: $0 192.168.1.1 -sS -T4"
    echo
    read -p "Enter choice [1-7]: " choice
    
    case $choice in
        1) run_gui ;;
        2) setup_scanner ;;
        3) check_setup_status ;;
        4) echo; read -p "Enter target for traceroute: " target; run_traceroute "$target" ;;
        5) run_demo ;;
        6) show_help ;;
        7) exit 0 ;;
        *) print_warning "Invalid choice" ;;
    esac
}



# Function to run GUI with error handling
run_gui() {
    check_dependencies || exit 1
    
    print_status "Starting SuperSimpleScanner GUI..."
    echo
    
    if [ "$EUID" -eq 0 ]; then
        print_status "Running with root privileges - all features available"
    else
        if check_setup_status &>/dev/null; then
            print_status "Running with network capabilities - most features available"
        else
            print_warning "Running without root privileges"
            print_info "Some features will be limited (SYN scan, ICMP ping, OS detection)"
            print_info "Run './run_scanner.sh setup' to enable passwordless scanning"
        fi
    fi
    
    python3 gui_launcher.py "$@"
}

# Function to run CLI scanner
run_scanner() {
    check_dependencies || exit 1
    
    # Check if we need root privileges
    needs_root=false
    for arg in "$@"; do
        case $arg in
            -sS|--syn|--stealth|--os-scan|--icmp-ping)
                needs_root=true
                break
                ;;
        esac
    done
    
    # Determine how to run
    if [ "$needs_root" = true ] && [ "$EUID" -ne 0 ]; then
        # Check if we have capabilities
        if check_setup_status &>/dev/null; then
            print_info "Using network capabilities for privileged scan"
            python3 main.py "$@"
        else
            print_info "This scan requires root privileges, using sudo..."
            sudo python3 main.py "$@"
        fi
    else
        python3 main.py "$@"
    fi
}

# Function to run traceroute
run_traceroute() {
    check_dependencies || exit 1
    
    if [ $# -eq 0 ]; then
        print_error "Target required for traceroute"
        print_info "Usage: $0 traceroute <target> [options]"
        return 1
    fi
    
    local target="$1"
    shift
    
    print_status "Running traceroute to $target..."
    
    # Create a simple traceroute script
    python3 -c "
import sys
sys.path.append('src')
from traceroute import traceroute
import argparse

parser = argparse.ArgumentParser(description='Traceroute utility')
parser.add_argument('target', help='Target host/IP')
parser.add_argument('--max-hops', type=int, default=30, help='Maximum hops')
parser.add_argument('--timeout', type=int, default=5, help='Timeout per hop')
parser.add_argument('--method', choices=['auto', 'system', 'icmp', 'udp'], 
                   default='auto', help='Traceroute method')

args = parser.parse_args(['$target'] + [arg for arg in '$@'.split() if arg])

try:
    result = traceroute(args.target, args.max_hops, args.timeout, args.method)
    
    print(f'Traceroute to {result.target} ({result.target_ip})')
    print(f'Method: {result.method.upper()}, Max hops: {args.max_hops}')
    print()
    
    for hop in result.hops:
        if hop.ip is None:
            print(f'{hop.hop_num:2d}  * * * (timeout)')
        else:
            hostname_str = hop.hostname or \"unknown\"
            rtt = hop.avg_rtt or 0
            print(f'{hop.hop_num:2d}  {hop.ip:<15} ({hostname_str}) {rtt:.1f}ms')
    
    if hasattr(result, 'reached_target') and result.reached_target:
        print(f'\\nTarget reached in {len(result.hops)} hops')
    elif result.success:
        print(f'\\nTraceroute completed in {len(result.hops)} hops')
    else:
        print(f'\\nTarget not reached after {len(result.hops)} hops')
        
except Exception as e:
    print(f'Error: {e}')
    sys.exit(1)
" "$@"
}

# Function to run demo
run_demo() {
    check_dependencies || exit 1
    
    # Check if demo.py exists
    if [ ! -f "utils/demo.py" ]; then
        print_error "demo.py not found"
        print_info "Please ensure demo.py is in the current directory"
        return 1
    fi
    
    print_status "Starting SuperSimpleScanner Interactive Demo..."
    python3 utils/demo.py
}

# Show help
show_help() {
    echo
    echo "SuperSimpleScanner Launch Script"
    echo
    echo "Usage:"
    echo "  $0                         # Interactive menu"
    echo "  $0 gui                     # Launch GUI"
    echo "  $0 setup                   # Setup passwordless scanning"
    echo "  $0 status                  # Check setup status"
    echo "  $0 remove-caps             # Remove capabilities"
    echo "  $0 traceroute <target>     # Run traceroute"
    echo "  $0 demo                    # Show tutorial/examples"
    echo "  $0 <target> <args>         # Direct CLI scan"
    echo
    echo "Setup:"
    echo "  Capabilities will be set automatically with 'setup' command"
    echo
    echo "Examples:"
    echo "  $0 gui                        # Launch GUI"
    echo "  $0 192.168.1.1 -p 80,443     # TCP scan specific ports"
    echo "  $0 192.168.1.1 -sS -T4       # SYN scan with aggressive timing"
    echo "  $0 traceroute google.com      # Trace route to target"
    echo "  $0 demo                       # Show tutorial and examples"
    echo "  $0 setup                      # Setup passwordless scanning"
}

# Check dependencies
check_dependencies() {
    # Check if we're in the right directory
    if [ ! -f "main.py" ]; then
        print_error "main.py not found"
        print_info "Please run this script from the SuperSimpleScanner directory"
        return 1
    fi
    
    # Check if Python 3 is available
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed"
        print_info "Please install Python 3 first"
        return 1
    fi
    
    print_info "Checking dependencies..."
    
    # Check Python modules
    python3 -c "
import sys
missing = []

try:
    import scapy
except ImportError:
    missing.append('scapy')

try:
    import colorama
except ImportError:
    missing.append('colorama')

if missing:
    print(f'[!] Missing required modules: {missing}')
    print('    Installing missing modules...')
    import subprocess
    for module in missing:
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', module])
        except subprocess.CalledProcessError:
            print(f'[!] Failed to install {module}')
            exit(1)
    print('[+] All dependencies installed')
else:
    print('[+] All dependencies satisfied')
" 2>/dev/null

    return $?
}

# Run main function
main "$@"
