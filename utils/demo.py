#!/usr/bin/env python3
"""
SuperSimpleScanner - Comprehensive Demo & Tutorial
===================================================

This demo showcases all features and provides interactive examples.
For specific feature demos, check the examples/ folder.
"""

import sys
import os
from colorama import init, Fore, Back, Style
import time

# Initialize colorama for cross-platform colored output
init(autoreset=True)

def print_header(title):
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}{title:^60}")
    print(f"{Fore.CYAN}{'='*60}")

def print_section(title):
    print(f"\n{Fore.YELLOW}--- {title} ---")

def print_command(cmd, description=""):
    print(f"{Fore.GREEN}$ {cmd}")
    if description:
        print(f"  {Fore.WHITE}# {description}")

def print_example(title, commands):
    print(f"\n{Fore.MAGENTA}📖 {title}:")
    for cmd, desc in commands:
        print_command(cmd, desc)

def main_menu():
    print_header("SuperSimpleScanner Demo Menu")
    
    options = [
        ("1", "Basic Scanning Tutorial", "Learn fundamental scanning techniques"),
        ("2", "Timing & Performance", "Speed vs stealth optimization"),
        ("3", "Advanced Scan Types", "Parallel, adaptive, stealth scanning"),
        ("4", "Host Discovery", "Find live hosts on networks"),
        ("5", "Port Specification", "Target specific ports and ranges"),
        ("6", "Traceroute & Path Analysis", "Network path discovery and analysis"),
        ("7", "Practical Use Cases", "Real-world scenarios"),
        ("8", "GUI Tutorial", "Graphical interface walkthrough"),
        ("9", "Interactive Builder", "Build custom scan commands"),
        ("0", "Exit", "")
    ]
    
    for num, title, desc in options:
        print(f"{Fore.CYAN}{num}. {Fore.WHITE}{title}")
        if desc:
            print(f"   {Fore.LIGHTBLACK_EX}{desc}")

def basic_scanning():
    print_header("Basic Scanning Tutorial")
    
    print_example("1. Simple TCP scan", [
        ("python3 main.py scanme.nmap.org", "Basic TCP scan on common ports"),
        ("python3 main.py 192.168.1.1 -p 22,80,443", "Scan specific ports")
    ])
    
    print_example("2. Different scan types", [
        ("python3 main.py target -sT", "TCP Connect scan (no root needed)"),
        ("sudo python3 main.py target -sS", "SYN scan (requires root)"),
        ("python3 main.py target -sU", "UDP scan"),
        ("python3 main.py target -sT -sU", "Both TCP and UDP")
    ])
    
    print_example("3. Port ranges", [
        ("python3 main.py target -p 1-1000", "Scan ports 1-1000"),
        ("python3 main.py target -p-", "Scan all 65535 ports"),
        ("python3 main.py target -p T:80,443,U:53,161", "Mixed TCP/UDP ports")
    ])

def timing_performance():
    print_header("Timing & Performance")
    
    print(f"{Fore.YELLOW}🕒 Timing Templates (-T) control scan SPEED:")
    timing_levels = [
        ("T0", "paranoid", "delay=5s, timeout=10s, threads=1", "Maximum stealth"),
        ("T1", "sneaky", "delay=2s, timeout=5s, threads=1", "High stealth"),
        ("T2", "polite", "delay=1s, timeout=3s, threads=2", "Network friendly"),
        ("T3", "normal", "delay=0.5s, timeout=2s, threads=5", "Balanced (default)"),
        ("T4", "aggressive", "delay=0.1s, timeout=1s, threads=10", "Fast scanning"),
        ("T5", "insane", "delay=0.01s, timeout=0.5s, threads=20", "Maximum speed")
    ]
    
    for level, name, params, desc in timing_levels:
        print(f"  {Fore.GREEN}-{level} ({name:8}): {Fore.WHITE}{params:30} {Fore.LIGHTBLACK_EX}- {desc}")
    
    print_example("Performance comparison", [
        ("python3 main.py target -T0", "~30s - Very slow, very stealthy"),
        ("python3 main.py target -T3", "~3s - Normal speed"),
        ("python3 main.py target -T5", "~0.3s - Very fast, may be detected")
    ])

def advanced_scans():
    print_header("Advanced Scan Types")
    
    print_example("1. Parallel scanning", [
        ("python3 main.py target --parallel", "Multi-threaded scanning"),
        ("python3 main.py target --parallel -T4", "Parallel + aggressive timing")
    ])
    
    print_example("2. Adaptive scanning", [
        ("python3 main.py target --adaptive", "Smart timing based on network response"),
        ("python3 main.py target --adaptive -T2", "Adaptive + polite timing")
    ])
    
    print_example("3. Stealth scanning", [
        ("python3 main.py target --stealth", "Evasion techniques"),
        ("python3 main.py target --stealth -T1", "Maximum stealth combination")
    ])

def host_discovery():
    print_header("Host Discovery")
    
    print_example("1. Network discovery", [
        ("python3 main.py 192.168.1.0/24 --host-discovery", "Find live hosts"),
        ("python3 main.py 192.168.1.1-254 --ping-scan", "Ping sweep range")
    ])
    
    print_example("2. Custom ping options", [
        ("python3 main.py target --ping-count 3", "Send 3 ping packets"),
        ("python3 main.py target --ping-timeout 2", "2 second ping timeout")
    ])

def port_specification():
    print_header("Port Specification Guide")
    
    examples = [
        ("Single ports", [
            ("python3 main.py target -p 80", "Port 80 only"),
            ("python3 main.py target -p 22,80,443", "Multiple specific ports")
        ]),
        ("Port ranges", [
            ("python3 main.py target -p 1-100", "Ports 1 to 100"),
            ("python3 main.py target -p 80-90,443,8000-8080", "Mixed ranges and singles")
        ]),
        ("Protocol-specific", [
            ("python3 main.py target -p T:80,443", "TCP ports only"),
            ("python3 main.py target -p U:53,161", "UDP ports only"),
            ("python3 main.py target -p T:80,U:53", "Mixed TCP/UDP")
        ]),
        ("Special ranges", [
            ("python3 main.py target -p-", "All 65535 ports"),
            ("python3 main.py target --top-ports 100", "Top 100 most common ports")
        ])
    ]
    
    for category, cmds in examples:
        print_section(category)
        for cmd, desc in cmds:
            print_command(cmd, desc)

def traceroute_tutorial():
    print_header("Traceroute & Path Analysis")
    
    print(f"{Fore.YELLOW}🔍 What is Traceroute?")
    print(f"{Fore.WHITE}Traceroute shows the path packets take to reach a destination")
    print(f"{Fore.WHITE}by sending packets with incrementally increasing TTL values.\n")
    
    print(f"{Fore.YELLOW}📋 Available Methods:")
    methods = [
        ("auto", "Automatically selects best method", "Recommended default"),
        ("system", "Uses OS traceroute command", "Most reliable"),
        ("icmp", "Raw ICMP packets", "Fast but needs root"),
        ("udp", "UDP probes to high ports", "Traditional Unix method")
    ]
    
    for method, description, note in methods:
        print(f"  {Fore.GREEN}{method:8} {Fore.WHITE}- {description}")
        print(f"  {Fore.LIGHTBLACK_EX}         {note}")
    
    print_example("Basic traceroute usage", [
        ("python3 -c \"from src.traceroute import traceroute; result = traceroute('8.8.8.8'); print('\\n'.join(str(h) for h in result.hops))\"", "Simple traceroute to Google DNS"),
        ("python3 -c \"from src.traceroute import traceroute; traceroute('github.com', method='auto')\"", "Auto-select best method")
    ])
    
    print_example("Method-specific examples", [
        ("python3 -c \"from src.traceroute import traceroute; traceroute('example.com', method='system', timeout=10)\"", "System traceroute with 10s timeout"),
        ("sudo python3 -c \"from src.traceroute import traceroute; traceroute('target.com', method='icmp', max_hops=20)\"", "ICMP traceroute (needs root)"),
        ("python3 -c \"from src.traceroute import traceroute; traceroute('internal.net', method='udp', timeout=8)\"", "UDP traceroute for restricted networks")
    ])
    
    print(f"\n{Fore.YELLOW}🖥️  GUI Traceroute:")
    print(f"{Fore.WHITE}1. Launch GUI: python3 gui_launcher.py")
    print(f"{Fore.WHITE}2. Click the 'Traceroute' tab")
    print(f"{Fore.WHITE}3. Enter target and configure options:")
    print(f"   {Fore.CYAN}• Target: IP address or hostname")
    print(f"   {Fore.CYAN}• Max Hops: Usually 30 (1-64 range)")
    print(f"   {Fore.CYAN}• Timeout: 5 seconds per hop")
    print(f"   {Fore.CYAN}• Method: auto/system/icmp/udp")
    print(f"{Fore.WHITE}4. Click 'Start Traceroute'")
    print(f"{Fore.WHITE}5. Watch real-time hop discovery and visualization")
    
    print(f"\n{Fore.YELLOW}📊 Performance Comparison:")
    perf_data = [
        ("auto", "⭐⭐⭐⭐", "⭐⭐⭐⭐⭐", "No*", "⭐⭐⭐⭐", "Best overall choice"),
        ("system", "⭐⭐⭐⭐⭐", "⭐⭐⭐⭐⭐", "No", "⭐⭐⭐⭐⭐", "Most reliable"),
        ("icmp", "⭐⭐⭐⭐⭐", "⭐⭐⭐⭐⭐", "Yes", "⭐⭐⭐", "Fast but needs root"),
        ("udp", "⭐⭐⭐", "⭐⭐⭐", "No", "⭐⭐", "Fallback option")
    ]
    
    print(f"{Fore.CYAN}Method   Speed    Accuracy  Root   Bypass   Notes")
    print(f"{Fore.CYAN}{'-'*55}")
    for method, speed, acc, root, bypass, note in perf_data:
        print(f"{Fore.GREEN}{method:8} {speed:8} {acc:9} {root:6} {bypass:8} {Fore.WHITE}{note}")
    
    print(f"\n{Fore.YELLOW}🔧 Troubleshooting:")
    print(f"{Fore.RED}ICMP 'Permission denied' {Fore.WHITE}→ Run with sudo")
    print(f"{Fore.RED}System 'Command not found' {Fore.WHITE}→ Install traceroute package")
    print(f"{Fore.RED}UDP timeouts {Fore.WHITE}→ Firewall blocking, try ICMP/system")
    print(f"{Fore.RED}All methods failing {Fore.WHITE}→ Check connectivity, try different timeout")
    
    print(f"\n{Fore.YELLOW}💡 Best Practices:")
    print(f"{Fore.WHITE}• Development: Use 'auto' method")
    print(f"{Fore.WHITE}• Production: Use 'system' method")
    print(f"{Fore.WHITE}• Security testing: Use 'icmp' with root")
    print(f"{Fore.WHITE}• Restricted networks: Try 'udp' if others fail")

def practical_use_cases():
    print_header("Practical Use Cases")
    
    scenarios = [
        ("Network security audit", [
            ("python3 main.py 192.168.1.0/24 --host-discovery", "1. Find live hosts"),
            ("python3 main.py live_hosts.txt --top-ports 1000 -T3", "2. Scan top ports"),
            ("python3 main.py targets.txt -p- -T1", "3. Full port scan (stealth)")
        ]),
        ("Web server assessment", [
            ("python3 main.py target -p 80,443,8080,8443 -sT", "Common web ports"),
            ("python3 main.py target -p 80-90,443,8000-9000", "Extended web port range")
        ]),
        ("Quick network check", [
            ("python3 main.py 192.168.1.1 --parallel -T4", "Fast local network scan"),
            ("python3 main.py gateway --ping-scan", "Check gateway connectivity")
        ]),
        ("Stealth reconnaissance", [
            ("python3 main.py target --stealth -T0", "Maximum stealth"),
            ("python3 main.py target --adaptive -T1", "Adaptive stealth")
        ])
    ]
    
    for scenario, steps in scenarios:
        print_section(scenario)
        for step, desc in steps:
            print_command(step, desc)

def gui_tutorial():
    print_header("GUI Tutorial")
    
    print(f"{Fore.YELLOW}🖥️  Launch the GUI:")
    print_command("python3 gui_launcher.py", "Start graphical interface")
    
    print(f"\n{Fore.YELLOW}📋 GUI Tabs & Features:")
    
    print(f"\n{Fore.CYAN}🎯 Tab 1: Scan Results")
    scan_features = [
        "Target specification with validation",
        "Port range selection (individual, ranges, top ports)",
        "Timing template selection (-T0 to -T5)",
        "Scan type options (TCP, UDP, parallel, adaptive, stealth)",
        "Host discovery methods (ICMP, TCP, UDP, ARP)",
        "Real-time results display with color coding",
        "Progress tracking and cancellation",
        "OS detection capabilities"
    ]
    
    for feature in scan_features:
        print(f"  {Fore.GREEN}✓ {Fore.WHITE}{feature}")
    
    print(f"\n{Fore.CYAN}🔍 Tab 2: Traceroute")
    traceroute_features = [
        "Network path visualization (Zenmap-style)",
        "Multiple traceroute methods (auto/system/icmp/udp)",
        "Real-time hop discovery with RTT measurements",
        "Graphical route display with color-coded performance",
        "Detailed hop table with IP, hostname, and timing",
        "Configurable max hops and timeout settings",
        "Live progress tracking and cancellation"
    ]
    
    for feature in traceroute_features:
        print(f"  {Fore.GREEN}✓ {Fore.WHITE}{feature}")
    
    print(f"\n{Fore.YELLOW}🎨 Color Coding:")
    print(f"  {Fore.GREEN}🟢 OPEN/UP/Fast{Fore.WHITE} - Success, good performance")
    print(f"  {Fore.YELLOW}🟡 CLOSED/Normal{Fore.WHITE} - Responds but closed/moderate speed")
    print(f"  {Fore.RED}🔴 ERROR/DOWN/Slow{Fore.WHITE} - Problems or poor performance")
    print(f"  {Fore.CYAN}🔵 FILTERED{Fore.WHITE} - Firewall filtered")
    print(f"  {Fore.WHITE}⚫ TIMEOUT/Unknown{Fore.WHITE} - No response")

def interactive_builder():
    print_header("Interactive Command Builder")
    
    print(f"{Fore.YELLOW}Let's build a custom scan command step by step!\n")
    
    try:
        # Target
        target = input(f"{Fore.CYAN}Enter target (IP/hostname/network): {Fore.WHITE}")
        if not target:
            target = "scanme.nmap.org"
        
        # Scan type
        print(f"\n{Fore.CYAN}Select scan type:")
        print("1. TCP Connect (-sT)")
        print("2. SYN Scan (-sS) [requires root]")
        print("3. UDP Scan (-sU)")
        print("4. Parallel (--parallel)")
        print("5. Adaptive (--adaptive)")
        print("6. Stealth (--stealth)")
        print("7. Traceroute (from src.traceroute)")
        
        scan_choice = input(f"{Fore.CYAN}Choice (1-7): {Fore.WHITE}")
        scan_types = {
            "1": "-sT", "2": "-sS", "3": "-sU",
            "4": "--parallel", "5": "--adaptive", "6": "--stealth", "7": "traceroute"
        }
        scan_type = scan_types.get(scan_choice, "-sT")
        
        # Timing
        print(f"\n{Fore.CYAN}Select timing template:")
        print("0. Paranoid (-T0) - Very slow, very stealthy")
        print("1. Sneaky (-T1) - Slow, stealthy")
        print("2. Polite (-T2) - Moderate, network friendly")
        print("3. Normal (-T3) - Balanced [default]")
        print("4. Aggressive (-T4) - Fast")
        print("5. Insane (-T5) - Very fast")
        
        timing_choice = input(f"{Fore.CYAN}Choice (0-5): {Fore.WHITE}")
        timing = f"-T{timing_choice}" if timing_choice in "012345" else "-T3"
        
        # Ports
        ports = input(f"{Fore.CYAN}Port specification (leave empty for default): {Fore.WHITE}")
        port_opt = f"-p {ports}" if ports else ""
        
        # Build command
        if scan_type == "traceroute":
            command = f"python3 -c \"from src.traceroute import traceroute; result = traceroute('{target}', method='auto'); print('\\\\n'.join(str(h) for h in result.hops))\""
            print(f"\n{Fore.GREEN}🚀 Your traceroute command:")
            print(f"{Fore.WHITE}{command}")
            print(f"\n{Fore.CYAN}💡 For GUI traceroute: python3 gui_launcher.py → Traceroute tab")
        else:
            command = f"python3 main.py {target} {scan_type} {timing} {port_opt}".strip()
            print(f"\n{Fore.GREEN}🚀 Your custom scan command:")
            print(f"{Fore.WHITE}{command}")
        
        run_it = input(f"\n{Fore.CYAN}Run this command? (y/N): {Fore.WHITE}")
        if run_it.lower() == 'y':
            print(f"\n{Fore.YELLOW}Executing: {command}")
            os.system(command)
    
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Builder cancelled.")

def feature_summary():
    print_header("Feature Summary & Quick Start")
    
    print(f"{Fore.YELLOW}🎯 SuperSimpleScanner Capabilities:")
    
    print(f"\n{Fore.CYAN}📡 Scanning Features:")
    print(f"  {Fore.GREEN}• Basic scans: {Fore.WHITE}TCP Connect (-sT), SYN (-sS), UDP (-sU)")
    print(f"  {Fore.GREEN}• Advanced scans: {Fore.WHITE}Parallel (--parallel), Adaptive (--adaptive), Stealth (--stealth)")
    print(f"  {Fore.GREEN}• Host discovery: {Fore.WHITE}ICMP, TCP, UDP, ARP ping methods")
    print(f"  {Fore.GREEN}• Timing control: {Fore.WHITE}6 templates from paranoid (-T0) to insane (-T5)")
    print(f"  {Fore.GREEN}• Port targeting: {Fore.WHITE}Individual, ranges, top ports, protocol-specific")
    
    print(f"\n{Fore.CYAN}🔍 Traceroute Features:")
    print(f"  {Fore.GREEN}• Multiple methods: {Fore.WHITE}auto, system, ICMP, UDP")
    print(f"  {Fore.GREEN}• Path visualization: {Fore.WHITE}Real-time hop discovery with RTT")
    print(f"  {Fore.GREEN}• GUI integration: {Fore.WHITE}Zenmap-style graphical display")
    print(f"  {Fore.GREEN}• Smart fallback: {Fore.WHITE}Auto-selects best available method")
    
    print(f"\n{Fore.CYAN}🖥️ Interface Options:")
    print(f"  {Fore.GREEN}• Command line: {Fore.WHITE}python3 main.py [options]")
    print(f"  {Fore.GREEN}• Interactive demo: {Fore.WHITE}python3 demo.py")
    print(f"  {Fore.GREEN}• Graphical interface: {Fore.WHITE}python3 gui_launcher.py")
    
    print(f"\n{Fore.YELLOW}🚀 Quick Start Commands:")
    quick_starts = [
        ("python3 main.py scanme.nmap.org", "Basic scan"),
        ("python3 main.py target --parallel -T4", "Fast scan"),
        ("python3 main.py target --stealth -T1", "Stealth scan"),
        ("python3 gui_launcher.py", "Launch GUI"),
        ("python3 -c \"from src.traceroute import traceroute; traceroute('8.8.8.8')\"", "Quick traceroute")
    ]
    
    for cmd, desc in quick_starts:
        print_command(cmd, desc)
    
    print(f"\n{Fore.YELLOW}📖 Documentation:")
    print(f"  {Fore.WHITE}• README.md - Project overview")
    print(f"  {Fore.WHITE}• python3 demo.py - Interactive tutorial")
    print(f"  {Fore.WHITE}• GUI tooltips - Hover for help")
    print(f"  {Fore.WHITE}• --help - Command line help")

def main():
    try:
        while True:
            main_menu()
            choice = input(f"\n{Fore.CYAN}Enter your choice (0-9): {Fore.WHITE}")
            
            if choice == "0":
                print(f"{Fore.GREEN}Thanks for using SuperSimpleScanner!")
                break
            elif choice == "1":
                basic_scanning()
            elif choice == "2":
                timing_performance()
            elif choice == "3":
                advanced_scans()
            elif choice == "4":
                host_discovery()
            elif choice == "5":
                port_specification()
            elif choice == "6":
                traceroute_tutorial()
            elif choice == "7":
                practical_use_cases()
            elif choice == "8":
                gui_tutorial()
            elif choice == "9":
                interactive_builder()
            else:
                print(f"{Fore.RED}Invalid choice. Please try again.")
            
            input(f"\n{Fore.YELLOW}Press Enter to continue...")
    
    except KeyboardInterrupt:
        print(f"\n{Fore.GREEN}Goodbye!")

if __name__ == "__main__":
    main()
