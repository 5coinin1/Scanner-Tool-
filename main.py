import argparse

from src.port_scanner import (
    syn_scan, tcp_connect_scan, udp_scan, enhanced_udp_scan,
    parallel_port_scan, stealth_scan, adaptive_scan, 
    advanced_tcp_connect_scan
)
from src.timing import TIMING_TEMPLATES
from src.host_discovery import (
    no_port_scan, icmp_echo_ping, tcp_syn_ping, udp_ping, arp_ping, 
    advanced_host_discovery, icmp_timestamp_ping, icmp_address_mask_ping,
    icmp_info_ping, comprehensive_icmp_ping, enhanced_tcp_syn_ping
)
from src.os_detection import advanced_os_detection
from utils.scan_order import parse_ports, get_common_ports, format_port_list

def validate_ping_options(args):
    ping_options = [args.PE, args.PP, args.PM, args.PI, args.PC, args.PS, args.PSE, 
                    args.PU, args.PR, args.PA, args.sn]
    
    selected_options = sum(1 for opt in ping_options if opt)
    
    if selected_options > 1:
        print("[!] Warning: Multiple ping options selected. Only the first one will be executed.")
        print("    Consider using -PA for comprehensive discovery or -PC for all ICMP types.")
        return False

    return True

def validate_scan_options(args):
    if hasattr(args, 'timing') and args.timing not in TIMING_TEMPLATES:
        print(f"[!] Invalid timing template: {args.timing}")
        print(f"    Available: {', '.join(TIMING_TEMPLATES.keys())}")
        return False

    return True

def main():
    parser = argparse.ArgumentParser(
        description="My Super Simple Network Scanner"
    )

    parser.add_argument("-sS", action="store_true", help="SYN scan (stealth, requires root)")
    parser.add_argument("-sT", action="store_true", help="TCP Connect scan (reliable, no root needed)")
    parser.add_argument("-sU", action="store_true", help="UDP scan (with service detection)")
    parser.add_argument("-sn", action="store_true", help="Host discovery (no port scan)")
    
    parser.add_argument("--parallel", action="store_true", help="Parallel scanning with configurable timing")
    parser.add_argument("--stealth", action="store_true", help="Stealth scan with evasion techniques") 
    parser.add_argument("--adaptive", action="store_true", help="Adaptive scan (auto-adjusts to network)")
    parser.add_argument("--advanced-tcp", action="store_true", help="Advanced TCP Connect with full handshake")
    parser.add_argument("--enhanced-udp", action="store_true", help="Enhanced UDP scan with multiple attempts")
    parser.add_argument("-PE", action="store_true", help="ICMP Echo Ping (enhanced with RTT measurement)")
    parser.add_argument("-PP", action="store_true", help="ICMP Timestamp Ping (alternative when Echo blocked)")
    parser.add_argument("-PM", action="store_true", help="ICMP Address Mask Ping (stealth option)")
    parser.add_argument("-PI", action="store_true", help="ICMP Information Ping (legacy systems)")
    parser.add_argument("-PC", action="store_true", help="Comprehensive ICMP Ping (all ICMP types)")
    
    parser.add_argument("-PS", action="store_true", help="TCP SYN Ping to given ports (enhanced with RTT)")
    parser.add_argument("-PSE", action="store_true", help="Enhanced TCP SYN Ping (multiple ports)")
    parser.add_argument("-PU", action="store_true", help="UDP Ping to common UDP ports")
    parser.add_argument("-PR", action="store_true", help="ARP Ping (for local network discovery)")
    parser.add_argument("-PA", action="store_true", help="Advanced host discovery (combine all methods)")
    
    parser.add_argument("-T", type=int, choices=range(6), help="Timing template (0=paranoid, 1=sneaky, 2=polite, 3=normal, 4=aggressive, 5=insane)")
    parser.add_argument("--timing", choices=list(TIMING_TEMPLATES.keys()), default="normal", help="Named timing template")
    
    parser.add_argument("-O", action="store_true", help="Enable OS detection")
    
    parser.add_argument("-p", "--ports", type=str, 
                       help="Ports to scan. Supports: individual (80,443), ranges (80-443), "
                            "service names (http,ssh), protocol prefixes (T:80,U:53), "
                            "and categories (web,mail,database,top100). Default: top100", 
                       default=None)
    parser.add_argument("target", type=str, help="Target IP address to scan")

    args = parser.parse_args()

    if args.T is not None:
        timing_names = ["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"]
        args.timing = timing_names[args.T]
    
    timing_config = TIMING_TEMPLATES[args.timing]
    print(f"[*] Timing template: {args.timing}")
    print(f"    - Delay: {timing_config['delay']}s")
    print(f"    - Timeout: {timing_config['timeout']}s") 
    print(f"    - Max threads: {timing_config['max_threads']}")
    print()

    if not validate_ping_options(args):
        return
        
    if not validate_scan_options(args):
        return

    if args.sn and args.ports is not None:
        print("[!] Invalid argument: -sn (no port scan) cannot be used with -p (ports).")
        return
        
    advanced_scans = [args.parallel, args.stealth, args.adaptive, args.advanced_tcp, args.enhanced_udp]
    if any(advanced_scans) and not (args.sS or args.sT or args.sU):
        print("[!] Advanced scan options require a basic scan type (-sS, -sT, or -sU)")
        return

    timing_config = TIMING_TEMPLATES[args.timing]
    ping_timeout = timing_config['timeout']
    ping_count = timing_config.get('retries', 1) + 2
    
    if args.PE:
        icmp_echo_ping(args.target, count=ping_count, timeout=ping_timeout)
        return

    if args.PP:
        icmp_timestamp_ping(args.target, count=ping_count, timeout=ping_timeout)
        return

    if args.PM:
        icmp_address_mask_ping(args.target, timeout=ping_timeout)
        return

    if args.PI:
        icmp_info_ping(args.target, timeout=ping_timeout)
        return

    if args.PC:
        comprehensive_icmp_ping(args.target, timeout=ping_timeout)
        return

    if args.PU:
        udp_ping(args.target, timeout=ping_timeout)
        return

    if args.PR:
        arp_ping(args.target, timeout=ping_timeout)
        return

    if args.PA:
        advanced_host_discovery(args.target, timeout=ping_timeout)
        return

    if args.sn:
        no_port_scan(args.target, timeout=ping_timeout)
        return
    
    if args.ports is None:
        tcp_ports = get_common_ports("top100")
        udp_ports = get_common_ports("common-udp")
        print(f"[*] Using default ports: {len(tcp_ports)} TCP, {len(udp_ports)} UDP")
    else:
        try:
            tcp_ports, udp_ports = parse_ports(args.ports)
            print(f"[*] Parsed ports: {len(tcp_ports)} TCP, {len(udp_ports)} UDP")
            
            total_ports = len(tcp_ports) + len(udp_ports)
            if total_ports > 5000:
                print(f"[!] Warning: Scanning {total_ports} ports will take a very long time")
                print("    Consider using timing templates like --timing aggressive")
            elif total_ports > 1000:
                print(f"[!] Warning: Scanning {total_ports} ports may take some time")
                
        except Exception as e:
            print(f"[!] Error parsing ports '{args.ports}': {e}")
            print("    Examples: 80,443,22  or  web,mail  or  T:80-443,U:53")
            return

    scan_needs_ports = any([args.sS, args.sT, args.sU, args.parallel, args.stealth, 
                           args.adaptive, args.advanced_tcp, args.enhanced_udp])
    
    if scan_needs_ports and not tcp_ports and not udp_ports:
        print("[!] No valid ports specified for scanning")
        print("    Use -p to specify ports, or use host discovery options (-sn, -PE, etc.)")
        return

    scan_types = [args.sS, args.sT, args.sU, args.sn, args.PS, args.PSE, args.PU, args.PR, args.PA,
                  args.PE, args.PP, args.PM, args.PI, args.PC, args.parallel, args.stealth, 
                  args.adaptive, args.advanced_tcp, args.enhanced_udp]
    
    if not any(scan_types):
        print("[!] No scan type selected.")
        print("    Basic scans: -sS (SYN), -sT (TCP Connect), -sU (UDP)")
        print("    Advanced scans: --parallel, --stealth, --adaptive, --advanced-tcp, --enhanced-udp")
        print("    Host discovery: -sn (no port scan)")
        print("    ICMP pings: -PE (Echo), -PP (Timestamp), -PM (Addr Mask), -PI (Info), -PC (Comprehensive)")
        print("    Other pings: -PS (TCP SYN), -PSE (Enhanced TCP SYN), -PU (UDP), -PR (ARP), -PA (Advanced)")
        print()
        print("    Timing control:")
        print("      -T<0-5>: Template (0=paranoid, 1=sneaky, 2=polite, 3=normal, 4=aggressive, 5=insane)")  
        print("      --timing: Named template (paranoid, sneaky, polite, normal, aggressive, insane)")
        print()
        print("    Port examples: -p 80,443,22  -p web,mail  -p T:80-443,U:53  -p top100")
        print("    For detailed examples and tutorials, run: ./run_scanner.sh demo")
        exit()

    if args.enhanced_udp:
        print(f"[+] Starting Enhanced UDP scan on {args.target}")
        for port in udp_ports:
            enhanced_udp_scan(args.target, port, timing=args.timing, retries=2, verbose=True)
        return

    if args.sU:
        print(f"[+] Starting UDP scan on {args.target}")
        for port in udp_ports:
            udp_scan(args.target, port, timing=args.timing, verbose=True)

    if args.PS:
        print(f"[+] Starting Enhanced TCP SYN Ping on {args.target}")
        host_up = False
        for port in tcp_ports:
            if tcp_syn_ping(args.target, port, timeout=ping_timeout):
                host_up = True
                break
        if not host_up:
            print("[!] Host appears down or all ports filtered.")
        return

    if args.PSE:
        print(f"[+] Starting Enhanced Multi-Port TCP SYN Ping on {args.target}")
        enhanced_tcp_syn_ping(args.target, ports=tcp_ports, timeout=ping_timeout)
        return

    if args.parallel:
        scan_type = "syn" if args.sS else "connect" if args.sT else "udp"
        ports = tcp_ports if scan_type in ["syn", "connect"] else udp_ports
        parallel_port_scan(args.target, ports, scan_type=scan_type, 
                          timing=args.timing, verbose=True)
        return
    
    if args.stealth:
        ports = tcp_ports if args.sS or args.sT else udp_ports  
        stealth_scan(args.target, ports, timing=args.timing, verbose=True)
        return
    
    if args.adaptive:
        ports = tcp_ports if args.sS or args.sT else udp_ports
        adaptive_scan(args.target, ports, verbose=True)
        return
    
    if args.advanced_tcp:
        print(f"[+] Starting Advanced TCP Connect scan on {args.target}")
        for port in tcp_ports:
            advanced_tcp_connect_scan(args.target, port, timing=args.timing, verbose=True)
        return

    if args.sT:
        print(f"[+] Starting TCP connect scan on {args.target}")
        for port in tcp_ports:
            tcp_connect_scan(args.target, port, timing=args.timing, verbose=True)

    if args.sS:
        print(f"[+] Starting SYN scan on {args.target}")
        for port in tcp_ports:
            syn_scan(args.target, port, timing=args.timing, verbose=True)

    if args.O:
        print(f"[+] Starting OS detection on {args.target}")
        try:
            os_result = advanced_os_detection(args.target)
            print(f"\n[OS DETECTION RESULTS]")
            print(f"Operating System: {os_result['os']}")
            print(f"Confidence: {os_result['confidence']}%")
            if os_result['details']['ttl']:
                print(f"TTL: {os_result['details']['ttl']}")
            if os_result['details']['window_size']:
                print(f"TCP Window Size: {os_result['details']['window_size']}")
            if os_result['details']['tcp_options']:
                print(f"TCP Options: {', '.join(os_result['details']['tcp_options'])}")
        except Exception as e:
            print(f"[!] OS detection failed: {e}")

if __name__=="__main__":
    main()
