from scapy.all import IP, TCP, UDP, sr1, RandShort, ICMP, send
import socket
import time
import random
from src.service_detection import _detect_service
from collections import defaultdict
from src.timing import TimingConfig, with_timing, TIMING_TEMPLATES

@with_timing
def syn_scan(ip, port, timeout=2, verbose=True):
    if verbose:
        print(f"[.] SYN scan {ip}:{port}...", end=" ")
    
    sport = random.randint(1024, 65535)
    seq_num = random.randint(1000000, 9999999)
    syn_pkt = IP(dst=ip) / TCP(sport=sport, dport=port, flags="S", seq=seq_num)
    
    start_time = time.time()
    resp = sr1(syn_pkt, timeout=timeout, verbose=0)
    end_time = time.time()
    
    rtt = (end_time - start_time) * 1000
    
    if resp is None:
        if verbose:
            print("FILTERED (no response)")
        return {"status": "filtered", "rtt": None, "service": None}
    
    elif resp.haslayer(TCP):
        tcp_flags = resp[TCP].flags
        
        if tcp_flags == 0x12:
            service_info = _detect_service(ip, port, "tcp")
            
            if verbose:
                service_str = f" ({service_info})" if service_info else ""
                print(f"OPEN - RTT: {rtt:.1f}ms{service_str}")
            
            try:
                rst_pkt = IP(dst=ip) / TCP(
                    sport=sport, 
                    dport=port, 
                    flags="R", 
                    seq=resp[TCP].ack
                )
                sr1(rst_pkt, timeout=0.5, verbose=0)
            except:
                pass
            
            return {"status": "open", "rtt": rtt, "service": service_info}
            
        elif tcp_flags == 0x14:
            if verbose:
                print(f"CLOSED - RTT: {rtt:.1f}ms")
            return {"status": "closed", "rtt": rtt, "service": None}
            
        elif tcp_flags == 0x04:
            if verbose:
                print(f"CLOSED (RST) - RTT: {rtt:.1f}ms")
            return {"status": "closed", "rtt": rtt, "service": None}
            
        else:
            flag_names = _parse_tcp_flags(tcp_flags)
            if verbose:
                print(f"UNUSUAL ({flag_names}) - RTT: {rtt:.1f}ms")
            return {"status": "unusual", "rtt": rtt, "service": None, "flags": flag_names}
    
    elif resp.haslayer(ICMP):
        icmp_type = resp[ICMP].type
        icmp_code = resp[ICMP].code
        
        if icmp_type == 3:
            icmp_messages = {
                0: "Network Unreachable",
                1: "Host Unreachable", 
                2: "Protocol Unreachable",
                3: "Port Unreachable",
                9: "Network Admin Prohibited",
                10: "Host Admin Prohibited",
                13: "Communication Admin Prohibited"
            }
            
            message = icmp_messages.get(icmp_code, f"Unreachable (Code {icmp_code})")
            
            if icmp_code == 3:
                if verbose:
                    print(f"CLOSED (ICMP: {message}) - RTT: {rtt:.1f}ms")
                return {"status": "closed", "rtt": rtt, "service": None}
            else:
                if verbose:
                    print(f"FILTERED (ICMP: {message}) - RTT: {rtt:.1f}ms")
                return {"status": "filtered", "rtt": rtt, "service": None}
                
        else:
            if verbose:
                print(f"FILTERED (ICMP Type {icmp_type}) - RTT: {rtt:.1f}ms")
            return {"status": "filtered", "rtt": rtt, "service": None}
    
    else:
        if verbose:
            print(f"UNKNOWN response - RTT: {rtt:.1f}ms")
        return {"status": "unknown", "rtt": rtt, "service": None}

def _parse_tcp_flags(flags):
    flag_names = []
    if flags & 0x01: flag_names.append("FIN")
    if flags & 0x02: flag_names.append("SYN")
    if flags & 0x04: flag_names.append("RST")
    if flags & 0x08: flag_names.append("PSH")
    if flags & 0x10: flag_names.append("ACK")
    if flags & 0x20: flag_names.append("URG")
    if flags & 0x40: flag_names.append("ECE")
    if flags & 0x80: flag_names.append("CWR")
    return ",".join(flag_names) if flag_names else f"0x{flags:02x}"

@with_timing
def tcp_connect_scan(ip, port, timeout=3, verbose=True):
    if verbose:
        print(f"[.] TCP Connect {ip}:{port}...", end=" ")
    
    start_time = time.time()
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        end_time = time.time()
        
        rtt = (end_time - start_time) * 1000
        
        if result == 0:
            service_info = _detect_service(ip, port, "tcp", timeout=2)
            
            if verbose:
                service_str = f" ({service_info})" if service_info else ""
                print(f"OPEN - RTT: {rtt:.1f}ms{service_str}")
            
            sock.close()
            return {"status": "open", "rtt": rtt, "service": service_info}
        else:
            if verbose:
                print(f"CLOSED - RTT: {rtt:.1f}ms")
            sock.close()
            return {"status": "closed", "rtt": rtt, "service": None}
            
    except socket.timeout:
        if verbose:
            print("FILTERED (timeout)")
        return {"status": "filtered", "rtt": None, "service": None}
        
    except socket.error as e:
        end_time = time.time()
        rtt = (end_time - start_time) * 1000
        
        if e.errno == 111:
            if verbose:
                print(f"CLOSED (connection refused) - RTT: {rtt:.1f}ms")
            return {"status": "closed", "rtt": rtt, "service": None}
        elif e.errno == 113:
            if verbose:
                print(f"FILTERED (no route) - RTT: {rtt:.1f}ms")
            return {"status": "filtered", "rtt": rtt, "service": None}
        else:
            if verbose:
                print(f"ERROR ({e}) - RTT: {rtt:.1f}ms")
            return {"status": "error", "rtt": rtt, "service": None}

@with_timing
def advanced_tcp_connect_scan(ip, port, timeout=3, verbose=True):
    if verbose:
        print(f"[.] Advanced TCP Connect {ip}:{port}...", end=" ")
    
    sport = random.randint(1024, 65535)
    seq_num = random.randint(1000000, 9999999)
    
    start_time = time.time()
    syn_pkt = IP(dst=ip) / TCP(sport=sport, dport=port, flags="S", seq=seq_num)
    syn_ack = sr1(syn_pkt, timeout=timeout, verbose=0)
    
    if syn_ack is None:
        if verbose:
            print("FILTERED (no SYN-ACK)")
        return {"status": "filtered", "rtt": None, "service": None}
    
    if not syn_ack.haslayer(TCP):
        if verbose:
            print("FILTERED (no TCP response)")
        return {"status": "filtered", "rtt": None, "service": None}
    
    tcp_flags = syn_ack[TCP].flags
    
    if tcp_flags == 0x12:
        ack_pkt = IP(dst=ip) / TCP(
            sport=sport, 
            dport=port, 
            flags="A", 
            seq=syn_ack[TCP].ack, 
            ack=syn_ack[TCP].seq + 1
        )
        sr1(ack_pkt, timeout=1, verbose=0)
        
        end_time = time.time()
        rtt = (end_time - start_time) * 1000
        
        service_info = _detect_service(ip, port, "tcp")
        
        rst_pkt = IP(dst=ip) / TCP(
            sport=sport, 
            dport=port, 
            flags="R", 
            seq=ack_pkt[TCP].seq + 1
        )
        sr1(rst_pkt, timeout=1, verbose=0)
        
        if verbose:
            service_str = f" ({service_info})" if service_info else ""
            print(f"OPEN - RTT: {rtt:.1f}ms{service_str}")
        
        return {"status": "open", "rtt": rtt, "service": service_info}
        
    elif tcp_flags == 0x14:
        end_time = time.time()
        rtt = (end_time - start_time) * 1000
        
        if verbose:
            print(f"CLOSED - RTT: {rtt:.1f}ms")
        return {"status": "closed", "rtt": rtt, "service": None}
        
    else:
        end_time = time.time()
        rtt = (end_time - start_time) * 1000
        flag_names = _parse_tcp_flags(tcp_flags)
        
        if verbose:
            print(f"UNUSUAL ({flag_names}) - RTT: {rtt:.1f}ms")
        return {"status": "unusual", "rtt": rtt, "service": None, "flags": flag_names}

@with_timing
def udp_scan(ip, port, timeout=3, verbose=True):
    if verbose:
        print(f"[.] UDP scan {ip}:{port}...", end=" ")
    
    payload = _get_udp_payload(port)
    udp_pkt = IP(dst=ip) / UDP(sport=random.randint(1024, 65535), dport=port) / payload
    
    start_time = time.time()
    resp = sr1(udp_pkt, timeout=timeout, verbose=0)
    end_time = time.time()
    
    rtt = (end_time - start_time) * 1000
    
    if resp is None:
        service_info = _detect_service(ip, port, "udp")
        
        if verbose:
            print(f"OPEN|FILTERED (no response) - ({service_info})")
        return {"status": "open|filtered", "rtt": None, "service": service_info}
    
    elif resp.haslayer(UDP):
        service_info = _detect_service(ip, port, "udp")
        
        if verbose:
            service_str = f" ({service_info})" if service_info else ""
            print(f"OPEN (UDP response) - RTT: {rtt:.1f}ms{service_str}")
        return {"status": "open", "rtt": rtt, "service": service_info}
    
    elif resp.haslayer(ICMP):
        icmp_type = resp[ICMP].type
        icmp_code = resp[ICMP].code
        
        if icmp_type == 3:
            icmp_messages = {
                0: "Network Unreachable",
                1: "Host Unreachable",
                2: "Protocol Unreachable", 
                3: "Port Unreachable",
                9: "Network Admin Prohibited",
                10: "Host Admin Prohibited",
                13: "Communication Admin Prohibited"
            }
            
            message = icmp_messages.get(icmp_code, f"Unreachable (Code {icmp_code})")
            
            if icmp_code == 3:
                if verbose:
                    print(f"CLOSED (ICMP: {message}) - RTT: {rtt:.1f}ms")
                return {"status": "closed", "rtt": rtt, "service": None}
            else:
                if verbose:
                    print(f"FILTERED (ICMP: {message}) - RTT: {rtt:.1f}ms")
                return {"status": "filtered", "rtt": rtt, "service": None}
        
        elif icmp_type == 11:
            if verbose:
                print(f"FILTERED (ICMP Time Exceeded) - RTT: {rtt:.1f}ms")
            return {"status": "filtered", "rtt": rtt, "service": None}
        
        else:
            if verbose:
                print(f"FILTERED (ICMP Type {icmp_type}) - RTT: {rtt:.1f}ms")
            return {"status": "filtered", "rtt": rtt, "service": None}
    
    else:
        if verbose:
            print(f"UNKNOWN response - RTT: {rtt:.1f}ms")
        return {"status": "unknown", "rtt": rtt, "service": None}

def _get_udp_payload(port):
    payloads = {
        53: b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01',
        67: b'\x01\x01\x06\x00\x00\x00\x3d\x1d\x00\x00\x00\x00\x00\x00\x00\x00',
        69: b'\x00\x01test.txt\x00octet\x00',
        123: b'\x1b' + b'\x00' * 47,
        161: b'\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x01\x00',
        514: b'<14>test message',
        1434: b'\x02',
    }
    
    return payloads.get(port, b'test')

@with_timing
def enhanced_udp_scan(ip, port, timeout=3, retries=2, verbose=True):
    if verbose:
        print(f"[.] Enhanced UDP scan {ip}:{port}...", end=" ")
    
    responses = []
    total_rtt = 0
    
    for attempt in range(retries):
        result = udp_scan(ip, port, timeout, verbose=False)
        responses.append(result)
        
        if result["rtt"]:
            total_rtt += result["rtt"]
    
    open_responses = sum(1 for r in responses if r["status"] == "open")
    closed_responses = sum(1 for r in responses if r["status"] == "closed")
    filtered_responses = sum(1 for r in responses if r["status"] == "filtered")
    
    avg_rtt = total_rtt / len([r for r in responses if r["rtt"]]) if any(r["rtt"] for r in responses) else None
    
    if closed_responses > 0:
        final_status = "closed"
    elif open_responses > 0:
        final_status = "open"
    elif filtered_responses > 0:
        final_status = "filtered"
    else:
        final_status = "open|filtered"
    
    service_info = responses[0]["service"] if responses else None
    
    if verbose:
        rtt_str = f" - Avg RTT: {avg_rtt:.1f}ms" if avg_rtt else ""
        service_str = f" ({service_info})" if service_info else ""
        print(f"{final_status.upper()}{rtt_str}{service_str}")
    
    return {"status": final_status, "rtt": avg_rtt, "service": service_info, "attempts": retries}

def parallel_port_scan(ip, ports, scan_type="syn", timing="normal", max_threads=None, verbose=True):
    if isinstance(timing, str):
        timing_config = TimingConfig(timing)
    elif isinstance(timing, TimingConfig):
        timing_config = timing
    else:
        timing_config = TimingConfig(timing)
    
    if max_threads is None:
        max_threads = timing_config.max_threads
    
    if verbose:
        print(f"[+] Starting {scan_type.upper()} scan on {ip}")
        print(f"[+] Timing: {timing if isinstance(timing, str) else 'custom'} (threads: {max_threads})")
        print(f"[+] Scanning {len(ports)} ports...")
    
    results = {}
    scan_start = time.time()
    
    def scan_port(port):
        try:
            timing_config.apply_delay()
            
            if scan_type.lower() == "syn":
                result = syn_scan(ip, port, timeout=timing_config.timeout, verbose=verbose, apply_delay=False)
            elif scan_type.lower() == "connect":
                result = tcp_connect_scan(ip, port, timeout=timing_config.timeout, verbose=verbose, apply_delay=False)
            elif scan_type.lower() == "udp":
                result = udp_scan(ip, port, timeout=timing_config.timeout, verbose=verbose, apply_delay=False)
            else:
                result = {"status": "error", "error": "unknown scan type"}
            
            results[port] = result
            
        except Exception as e:
            results[port] = {"status": "error", "error": str(e)}
    
    if max_threads > 1:
        import concurrent.futures
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            executor.map(scan_port, ports)
    else:
        for port in ports:
            scan_port(port)
    
    scan_end = time.time()
    total_time = scan_end - scan_start
    
    if verbose:
        open_ports = [p for p, r in results.items() if r.get("status") == "open"]
        closed_ports = [p for p, r in results.items() if r.get("status") == "closed"]
        filtered_ports = [p for p, r in results.items() if r.get("status") in ["filtered", "open|filtered"]]
        
        print(f"\n[SCAN SUMMARY for {ip}]")
        print(f"Scan completed in {total_time:.2f} seconds")
        print(f"Open ports ({len(open_ports)}): {', '.join(map(str, sorted(open_ports)))}")
        if closed_ports and len(closed_ports) < 20:
            print(f"Closed ports ({len(closed_ports)}): {', '.join(map(str, sorted(closed_ports)))}")
        if filtered_ports:
            print(f"Filtered ports ({len(filtered_ports)}): {', '.join(map(str, sorted(filtered_ports)))}")
    
    return results

def stealth_scan(ip, ports, timing="sneaky", verbose=True):
    if verbose:
        print(f"[+] Stealth scan on {ip} ({len(ports)} ports)")
    
    results = {}
    timing_config = TimingConfig(timing) if isinstance(timing, str) else timing
    
    for port in ports:
        timing_config.apply_delay(jitter=True)
        extra_delay = random.uniform(0, timing_config.delay)
        time.sleep(extra_delay)
        
        sport = random.randint(10000, 65535)
        seq_num = random.randint(1000000, 9999999)
        
        if random.choice([True, False]):
            result = _fragmented_syn_scan(ip, port, sport, seq_num, timing_config.timeout, verbose)
        else:
            result = syn_scan(ip, port, timeout=timing_config.timeout, verbose=verbose, apply_delay=False)
        
        results[port] = result
    
    return results

def _fragmented_syn_scan(ip, port, sport, seq_num, timeout, verbose):
    try:
        frag1 = IP(dst=ip, flags="MF", frag=0) / TCP(sport=sport, dport=port, flags="S", seq=seq_num)[:8]
        frag2 = IP(dst=ip, frag=1) / TCP(sport=sport, dport=port, flags="S", seq=seq_num)[8:]
        
        send(frag1, verbose=0)
        resp = sr1(frag2, timeout=timeout, verbose=0)
        
        if resp and resp.haslayer(TCP):
            if resp[TCP].flags == 0x12:
                if verbose:
                    print(f"OPEN (fragmented)")
                rst = IP(dst=ip) / TCP(sport=sport, dport=port, flags="R", seq=resp[TCP].ack)
                send(rst, verbose=0)
                return {"status": "open", "method": "fragmented"}
            else:
                if verbose:
                    print(f"CLOSED (fragmented)")
                return {"status": "closed", "method": "fragmented"}
        else:
            if verbose:
                print(f"FILTERED (fragmented)")
            return {"status": "filtered", "method": "fragmented"}
            
    except Exception as e:
        if verbose:
            print(f"ERROR (fragmented): {e}")
        return {"status": "error", "error": str(e), "method": "fragmented"}

def adaptive_scan(ip, ports, verbose=True):
    from src.timing import AdaptiveTiming
    
    if verbose:
        print(f"[+] Adaptive scan on {ip}")
    
    adaptive_timing = AdaptiveTiming("normal")
    
    test_ports = ports[:min(5, len(ports))]
    test_results = []
    
    for port in test_ports:
        try:
            result = syn_scan(ip, port, timeout=2, verbose=False, apply_delay=False)
        except PermissionError:
            result = tcp_connect_scan(ip, port, timeout=2, verbose=False, apply_delay=False)
            
        if result and result.get("rtt"):
            test_results.append(result["rtt"])
            adaptive_timing.record_result(result.get("status") != "error")
    
    if test_results:
        avg_rtt = sum(test_results) / len(test_results)
        
        if avg_rtt < 10:
            timing_template = "aggressive"
        elif avg_rtt < 50:
            timing_template = "normal"
        elif avg_rtt < 200:
            timing_template = "polite"
        else:
            timing_template = "sneaky"
        
        adaptive_timing = AdaptiveTiming(timing_template)
        timing_config = adaptive_timing.get_config()
    else:
        timing_config = TimingConfig("polite")
    
    if verbose:
        if test_results:
            avg_rtt = sum(test_results) / len(test_results)
            print(f"[+] Network analysis: Avg RTT {avg_rtt:.1f}ms")
            print(f"[+] Using adaptive timing: {timing_config}")
        else:
            print(f"[+] No responses in test scan, using polite timing")
    
    remaining_ports = ports[len(test_ports):]
    
    def adaptive_scan_func(port):
        adaptive_timing.apply_delay()
        try:
            result = syn_scan(ip, port, timeout=timing_config.timeout, verbose=False, apply_delay=False)
        except PermissionError:
            result = tcp_connect_scan(ip, port, timeout=timing_config.timeout, verbose=False, apply_delay=False)
            
        adaptive_timing.record_result(result and result.get("status") != "error")
        return result
    
    results = {}
    for port in remaining_ports:
        results[port] = adaptive_scan_func(port)
    
    for i, port in enumerate(test_ports):
        if i < len(test_results):
            results[port] = {"status": "tested", "rtt": test_results[i]}
    
    return results
