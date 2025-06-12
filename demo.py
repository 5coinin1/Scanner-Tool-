#!/usr/bin/env python3
"""
SuperSimpleScanner Demo Guide
Quick reference and examples
"""

import os
import sys
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

def print_header(title):
    """Print formatted header"""
    print(f"\n{Fore.CYAN}{'=' * 50}")
    print(f"{Fore.CYAN}{title:^50}")
    print(f"{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}")

def print_example(cmd, desc):
    """Print command example"""
    print(f"{Fore.GREEN}• {desc}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}{cmd}{Style.RESET_ALL}")

def print_info(text):
    """Print info text"""
    print(f"{Fore.BLUE}ℹ {text}{Style.RESET_ALL}")

def show_basic_scanning():
    """Show basic scanning examples"""
    print_header("BASIC PORT SCANNING")
    print_info("Fundamental port scanning techniques")
    
    print_example("./run_scanner.sh 127.0.0.1 -p 22", "Scan SSH port")
    print_example("./run_scanner.sh 127.0.0.1 -p 22,80,443", "Scan multiple ports")
    print_example("./run_scanner.sh 127.0.0.1 -p 1-1000", "Scan port range")
    print_example("./run_scanner.sh 127.0.0.1 -T4", "Fast aggressive scan")

def show_advanced_scanning():
    """Show advanced scanning examples"""
    print_header("ADVANCED SCANNING")
    print_info("Advanced techniques (some require capabilities/sudo)")
    
    print_example("./run_scanner.sh 127.0.0.1 -sS -p 22,80", "SYN stealth scan")
    print_example("./run_scanner.sh 127.0.0.1 -sV -p 22", "Service version detection")
    print_example("./run_scanner.sh 127.0.0.1 --service-scan", "Service enumeration")
    print_example("./run_scanner.sh 127.0.0.1 --os-scan", "OS detection")

def show_host_discovery():
    """Show host discovery examples"""
    print_header("HOST DISCOVERY")
    print_info("Find live hosts before port scanning")
    
    print_example("./run_scanner.sh 192.168.1.0/24 --host-discovery", "Network discovery")
    print_example("./run_scanner.sh 127.0.0.1 --icmp-ping", "ICMP ping test")

def show_timing_templates():
    """Show timing template examples"""
    print_header("TIMING TEMPLATES")
    print_info("Control scan speed: T0=Paranoid T1=Sneaky T2=Polite T3=Normal T4=Aggressive T5=Insane")
    
    print_example("./run_scanner.sh target -T0", "Paranoid (very slow, stealth)")
    print_example("./run_scanner.sh target -T2", "Polite (slower, respectful)")
    print_example("./run_scanner.sh target -T4", "Aggressive (fast)")

def show_traceroute():
    """Show traceroute examples"""
    print_header("TRACEROUTE")
    print_info("Network path tracing and topology mapping")
    
    print_example("./run_scanner.sh traceroute google.com", "Basic traceroute")
    print_example("./run_scanner.sh trace 8.8.8.8 --method icmp", "ICMP traceroute")

def show_gui_features():
    """Show GUI information"""
    print_header("GUI FEATURES")
    print_info("Graphical interface with visual controls")
    
    print_example("./run_scanner.sh gui", "Launch GUI interface")
    print(f"\n{Fore.GREEN}GUI Features:{Style.RESET_ALL}")
    print("  • Visual scan configuration")
    print("  • Real-time results display") 
    print("  • Traceroute visualization")
    print("  • Export capabilities")
    print("  • Timing template selection")

def show_setup():
    """Show setup examples"""
    print_header("SETUP & CONFIGURATION")
    print_info("Setup capabilities for passwordless privileged scans")
    
    print_example("./run_scanner.sh setup", "Setup capabilities (requires sudo once)")
    print_example("./run_scanner.sh status", "Check capabilities status")
    print_example("./run_scanner.sh remove-caps", "Remove capabilities")

def show_practical_examples():
    """Show practical real-world examples"""
    print_header("PRACTICAL EXAMPLES")
    print_info("Real-world scanning scenarios")
    
    examples = [
        ("Network Discovery", "./run_scanner.sh 192.168.1.0/24 --host-discovery -T4"),
        ("Web Server Audit", "./run_scanner.sh example.com -p 80,443,8080,8443 -sV"),
        ("Database Services", "./run_scanner.sh host -p 3306,5432,1433,1521 -sS"),
        ("Security Assessment", "./run_scanner.sh target.com -sS -T2 --service-scan"),
        ("Quick Check", "./run_scanner.sh host.com -p 22,80,443 -T4"),
        ("Stealth Scan", "./run_scanner.sh target -sS -T1 -p 1-1000")
    ]
    
    for name, cmd in examples:
        print_example(cmd, name)
    
    print(f"\n{Fore.YELLOW}⚠ Replace targets with your own! Get permission first!{Style.RESET_ALL}")

def main():
    """Main demo function - shows all sections"""
    print_header("SUPERSIMPLESCANNER GUIDE")
    print_info("Quick reference and command examples")
    
    # Show all sections
    show_basic_scanning()
    show_advanced_scanning() 
    show_host_discovery()
    show_timing_templates()
    show_traceroute()
    show_gui_features()
    show_setup()
    show_practical_examples()
    
    print_header("QUICK START")
    print_info("Try these commands to get started:")
    print_example("./run_scanner.sh", "Interactive menu")
    print_example("./run_scanner.sh gui", "Launch GUI")
    print_example("./run_scanner.sh setup", "Setup capabilities")
    print_example("./run_scanner.sh 127.0.0.1 -p 22,80,443", "Basic scan")

if __name__ == "__main__":
    try:
        # Check if we're in the right directory
        if not os.path.exists("run_scanner.sh"):
            print(f"{Fore.RED}Error: run_scanner.sh not found{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please run this demo from the SuperSimpleScanner directory{Style.RESET_ALL}")
            sys.exit(1)
        
        main()
        
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Demo terminated. Goodbye!{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)
