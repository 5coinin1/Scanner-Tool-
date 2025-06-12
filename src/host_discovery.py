from scapy.all import IP, sr1, ICMP, TCP, UDP, ARP, Ether, RandShort, srp
import socket
import time
import random


def no_port_scan(ip, timeout=3):
    """
    Host discovery không quét cổng
    sử dụng nhiều phương thức phát hiện tự động
    """
    print(f"[+] Host Discovery for {ip} (no port scan)")
    
    # Thử các phương thức lần lượt tới khi thành công
    methods_tried = []
    
    # 1. Thử ICMP Echo (phổ biến)
    print("\n--- ICMP Echo Ping ---")
    try:
        if icmp_echo_ping(ip, count=2, timeout=timeout):
            print(f"[+] Host {ip} is UP (ICMP Echo)")
            return True
        methods_tried.append("ICMP Echo")
    except Exception as e:
        print(f"[!] ICMP Echo failed: {e}")
        methods_tried.append("ICMP Echo (failed)")
    
    # 2. Thử ARP nếu là mạng cục bộ
    if _is_local_network(ip):
        print("\n--- ARP Ping ---")
        try:
            if arp_ping(ip, timeout=timeout):
                print(f"[+] Host {ip} is UP (ARP)")
                return True
            methods_tried.append("ARP")
        except Exception as e:
            print(f"[!] ARP ping failed: {e}")
            methods_tried.append("ARP (failed)")
    
    # 3. Thử các phương thức gửi ICMP thay thế 
    print("\n--- Alternative ICMP Methods ---")
    try:
        if icmp_timestamp_ping(ip, count=1, timeout=timeout):
            print(f"[+] Host {ip} is UP (ICMP Timestamp)")
            return True
        methods_tried.append("ICMP Timestamp")
    except Exception as e:
        print(f"[!] ICMP Timestamp failed: {e}")
        methods_tried.append("ICMP Timestamp (failed)")
    
    # 4. Thử gửi TCP SYN tới các cổng phổ biến như phương án cuối 
    print("\n--- TCP SYN Ping (Last Resort) ---")
    try:
        for port in [80, 443, 22]:
            if tcp_syn_ping(ip, port, timeout=1):
                print(f"[+] Host {ip} is UP (TCP SYN)")
                return True
        methods_tried.append("TCP SYN")
    except Exception as e:
        print(f"[!] TCP SYN ping failed: {e}")
        methods_tried.append("TCP SYN (failed)")
    
    # Summary
    print(f"\n[HOST DISCOVERY SUMMARY for {ip}]")
    print(f"Host Status: DOWN/FILTERED")
    print(f"Methods tried: {', '.join(methods_tried)}")
    print(f"No responses received from {ip}")
    return False


def icmp_echo_ping(ip, count=3, timeout=2):
    """
    Enhanced ICMP Echo Ping với multiple attempts và detailed analysis
    """
    print(f"[+] ICMP Echo Ping to {ip} (sending {count} packets)...")
    
    responses = 0
    rtt_times = []
    
    for i in range(count):
        print(f"[.] ICMP Echo {i+1}/{count}...", end=" ")
        
        # Tạo ICMP Echo Request với sequence number
        pkt = IP(dst=ip) / ICMP(id=random.randint(1000, 9999), seq=i+1)
        
        start_time = time.time()
        resp = sr1(pkt, timeout=timeout, verbose=0)
        end_time = time.time()
        
        if resp is None:
            print("Timeout")
            continue
        elif resp.haslayer(ICMP):
            icmp_type = resp[ICMP].type
            icmp_code = resp[ICMP].code
            
            if icmp_type == 0:  # Echo Reply
                rtt = (end_time - start_time) * 1000  # Chuyển sang ms
                rtt_times.append(rtt)
                responses += 1
                print(f"Reply from {resp.src}: time={rtt:.1f}ms TTL={resp.ttl}")
            elif icmp_type == 3:  # Destination Unreachable
                unreachable_types = {
                    0: "Network Unreachable",
                    1: "Host Unreachable", 
                    2: "Protocol Unreachable",
                    3: "Port Unreachable",
                    9: "Network Admin Prohibited",
                    10: "Host Admin Prohibited",
                    13: "Communication Admin Prohibited"
                }
                error_msg = unreachable_types.get(icmp_code, f"Unreachable (Code {icmp_code})")
                print(f"ICMP: {error_msg}")
            elif icmp_type == 11:  # Time Exceeded
                print("ICMP: Time Exceeded (TTL expired)")
            else:
                print(f"ICMP Type {icmp_type}, Code {icmp_code}")
        elif resp.haslayer(IP):
            print(f"Non-ICMP response from {resp.src}")
        else:
            print("Unexpected response")
    
    # Summary
    packet_loss = ((count - responses) / count) * 100
    print(f"\n[ICMP PING SUMMARY for {ip}]")
    print(f"Packets: Sent = {count}, Received = {responses}, Lost = {count - responses} ({packet_loss:.0f}% loss)")
    
    if rtt_times:
        min_rtt = min(rtt_times)
        max_rtt = max(rtt_times)
        avg_rtt = sum(rtt_times) / len(rtt_times)
        print(f"Round-trip times: min={min_rtt:.1f}ms, max={max_rtt:.1f}ms, avg={avg_rtt:.1f}ms")
        return True
    else:
        print("Host appears to be down or not responding to ICMP Echo")
        return False


def tcp_syn_ping(ip, port, timeout=2):
    print(f"[.] TCP SYN Ping to {ip}:{port}...", end=" ")
    
    # Tạo SYN packet với random source port và sequence number
    sport = random.randint(1024, 65535)
    seq_num = random.randint(1000000, 9999999)
    syn_pkt = IP(dst=ip) / TCP(sport=sport, dport=port, flags="S", seq=seq_num)
    
    start_time = time.time()
    resp = sr1(syn_pkt, timeout=timeout, verbose=0)
    end_time = time.time()
    
    if resp is None:
        print("No response (filtered/dropped or host down)")
        return False
    
    rtt = (end_time - start_time) * 1000
    
    if resp.haslayer(TCP):
        tcp_flags = resp[TCP].flags
        
        if tcp_flags == 0x12:  # SYN-ACK
            print(f"Host UP! Port {port} OPEN (SYN-ACK) - RTT: {rtt:.1f}ms")
            
            # Gửi RST đóng kết nối
            try:
                rst_pkt = IP(dst=ip) / TCP(
                    sport=sport, 
                    dport=port, 
                    flags="R", 
                    seq=resp[TCP].ack, 
                    ack=resp[TCP].seq + 1
                )
                sr1(rst_pkt, timeout=0.5, verbose=0)
            except:
                pass
            
            return True
            
        elif tcp_flags == 0x14:  # RST-ACK
            print(f"Host UP! Port {port} CLOSED (RST-ACK) - RTT: {rtt:.1f}ms")
            return True
            
        elif tcp_flags == 0x04:  # RST only
            print(f"Host UP! Port {port} CLOSED (RST) - RTT: {rtt:.1f}ms")
            return True
            
        elif tcp_flags == 0x02:  # SYN only
            print(f"Host UP! Possible SYN flood protection - RTT: {rtt:.1f}ms")
            return True
            
        else:
            # Xử lí các cờ khác
            flag_names = []
            if tcp_flags & 0x01: flag_names.append("FIN")
            if tcp_flags & 0x02: flag_names.append("SYN") 
            if tcp_flags & 0x04: flag_names.append("RST")
            if tcp_flags & 0x08: flag_names.append("PSH")
            if tcp_flags & 0x10: flag_names.append("ACK")
            if tcp_flags & 0x20: flag_names.append("URG")
            
            flag_str = ",".join(flag_names) if flag_names else f"0x{tcp_flags:02x}"
            print(f"Host UP! Unexpected TCP flags: {flag_str} - RTT: {rtt:.1f}ms")
            return True
            
    elif resp.haslayer(ICMP):
        # Xử lí ICMP responses
        icmp_type = resp[ICMP].type
        icmp_code = resp[ICMP].code
        
        if icmp_type == 3:  # Destination Unreachable
            icmp_responses = {
                0: "Network Unreachable",
                1: "Host Unreachable",
                2: "Protocol Unreachable", 
                3: "Port Unreachable",
                9: "Network Admin Prohibited",
                10: "Host Admin Prohibited",
                13: "Communication Admin Prohibited"
            }
            error_msg = icmp_responses.get(icmp_code, f"Unreachable (Code {icmp_code})")
            
            if icmp_code in [1, 3, 9, 10, 13]:  # Host exists but filtered/blocked
                print(f"Host UP! {error_msg} - RTT: {rtt:.1f}ms")
                return True
            else:
                print(f"ICMP: {error_msg} - RTT: {rtt:.1f}ms")
                return False
                
        elif icmp_type == 11:  # Time Exceeded
            print(f"Host UP! ICMP Time Exceeded - RTT: {rtt:.1f}ms")
            return True
        else:
            print(f"Host UP! ICMP Type {icmp_type}, Code {icmp_code} - RTT: {rtt:.1f}ms")
            return True
            
    else:
        print(f"Unexpected response type from {resp.src} - RTT: {rtt:.1f}ms")
        return True  # Mọi phản hồi đều biểu thị Host up


def icmp_timestamp_ping(ip, count=2, timeout=2):
    """
    ICMP Timestamp Request - Phương án dự phòng khi Echo bị chặn
    """
    print(f"[+] ICMP Timestamp Ping to {ip} (sending {count} packets)...")
    
    responses = 0
    for i in range(count):
        print(f"[.] ICMP Timestamp {i+1}/{count}...", end=" ")
        
        # ICMP Type 13 = Timestamp Request
        pkt = IP(dst=ip) / ICMP(type=13, id=random.randint(1000, 9999))
        
        start_time = time.time()
        resp = sr1(pkt, timeout=timeout, verbose=0)
        end_time = time.time()
        
        if resp is None:
            print("Timeout")
            continue
        elif resp.haslayer(ICMP):
            if resp[ICMP].type == 14:  # Timestamp Reply
                rtt = (end_time - start_time) * 1000
                responses += 1
                print(f"Timestamp Reply from {resp.src}: RTT={rtt:.1f}ms")
            elif resp[ICMP].type == 3:  # Destination Unreachable
                print(f"ICMP Unreachable (Code {resp[ICMP].code})")
                if resp[ICMP].code in [9, 10, 13]:  # Admin prohibited
                    responses += 1  # Host exists but filtered
            else:
                print(f"ICMP Type {resp[ICMP].type}")
                responses += 1
        else:
            print("Non-ICMP response")
            responses += 1
    
    if responses > 0:
        print(f"[+] Host {ip} responded to ICMP Timestamp ({responses}/{count})")
        return True
    else:
        print(f"[!] No ICMP Timestamp responses from {ip}")
        return False


def icmp_address_mask_ping(ip, timeout=2):
    """
    ICMP Address Mask Request - hiếm khi bị chặn, phù hợp cho ẩn danh, kém phổ biến 
    """
    print(f"[+] ICMP Address Mask Ping to {ip}...", end=" ")
    
    # ICMP Type 17 = Address Mask Request
    pkt = IP(dst=ip) / ICMP(type=17, id=random.randint(1000, 9999))
    
    start_time = time.time()
    resp = sr1(pkt, timeout=timeout, verbose=0)
    end_time = time.time()
    
    if resp is None:
        print("No response")
        return False
    elif resp.haslayer(ICMP):
        rtt = (end_time - start_time) * 1000
        if resp[ICMP].type == 18:  # Address Mask Reply
            print(f"Address Mask Reply from {resp.src}: RTT={rtt:.1f}ms")
            return True
        elif resp[ICMP].type == 3:  # Destination Unreachable
            print(f"ICMP Unreachable (Code {resp[ICMP].code}): RTT={rtt:.1f}ms")
            return resp[ICMP].code in [9, 10, 13]  # Host exists if admin prohibited
        else:
            print(f"ICMP Type {resp[ICMP].type}: RTT={rtt:.1f}ms")
            return True
    else:
        rtt = (end_time - start_time) * 1000
        print(f"Non-ICMP response: RTT={rtt:.1f}ms")
        return True


def icmp_info_ping(ip, timeout=2):
    """
    ICMP Information Request - gần như ko còn sử dụng nhưng vài lúc vẫn hoạt động
    """
    print(f"[+] ICMP Information Ping to {ip}...", end=" ")
    
    # ICMP Type 15 = Information Request
    pkt = IP(dst=ip) / ICMP(type=15, id=random.randint(1000, 9999))
    
    start_time = time.time()
    resp = sr1(pkt, timeout=timeout, verbose=0)
    end_time = time.time()
    
    if resp is None:
        print("No response")
        return False
    elif resp.haslayer(ICMP):
        rtt = (end_time - start_time) * 1000
        if resp[ICMP].type == 16:  # Information Reply
            print(f"Information Reply from {resp.src}: RTT={rtt:.1f}ms")
            return True
        elif resp[ICMP].type == 3:  # Destination Unreachable
            print(f"ICMP Unreachable (Code {resp[ICMP].code}): RTT={rtt:.1f}ms")
            return resp[ICMP].code in [9, 10, 13]
        else:
            print(f"ICMP Type {resp[ICMP].type}: RTT={rtt:.1f}ms")
            return True
    else:
        rtt = (end_time - start_time) * 1000
        print(f"Non-ICMP response: RTT={rtt:.1f}ms")
        return True


def comprehensive_icmp_ping(ip, timeout=2):
    """
    Thử tất cả các loại ICMP ping
    """
    print(f"[+] Comprehensive ICMP Ping to {ip}")
    
    methods = [
        ("Echo", lambda: icmp_echo_ping(ip, count=2, timeout=timeout)),
        ("Timestamp", lambda: icmp_timestamp_ping(ip, count=2, timeout=timeout)),
        ("Address Mask", lambda: icmp_address_mask_ping(ip, timeout=timeout)),
        ("Information", lambda: icmp_info_ping(ip, timeout=timeout))
    ]
    
    results = {}
    host_up = False
    
    for method_name, method_func in methods:
        try:
            result = method_func()
            results[method_name] = result
            if result:
                host_up = True
        except Exception as e:
            print(f"[!] {method_name} ping failed: {e}")
            results[method_name] = False
    
    print(f"\n[COMPREHENSIVE ICMP PING SUMMARY for {ip}]")
    print(f"Host Status: {'UP' if host_up else 'DOWN/FILTERED'}")
    for method, success in results.items():
        status = "✓" if success else "✗"
        print(f"{method}: {status}")
    
    return host_up, results


def enhanced_tcp_syn_ping(ip, ports=None, timeout=2):
    """
    Enhanced TCP SYN ping với multiple ports
    """
    if ports is None:
        ports = [80, 443, 22, 21, 23, 25, 53, 110, 143, 993, 995, 3389, 5900]
    
    print(f"[+] Enhanced TCP SYN Ping to {ip} on {len(ports)} ports")
    
    open_ports = []
    closed_ports = []
    filtered_ports = []
    host_up = False
    
    for port in ports:
        result = tcp_syn_ping(ip, port, timeout)
        if result:
            host_up = True
            # chưa hoàn thiện (NEED TO DO)
            open_ports.append(port)
    
    # Summary
    print(f"\n[TCP SYN PING SUMMARY for {ip}]")
    print(f"Host Status: {'UP' if host_up else 'DOWN/FILTERED'}")
    if open_ports:
        print(f"Responsive ports: {', '.join(map(str, open_ports))}")
    
    return host_up


def udp_ping(ip, ports=None, timeout=2):
    """
    UDP Ping - gửi UDP packets đến các ports phổ biến
    Nếu nhận ICMP Port Unreachable thì host đang up
    """
    if ports is None:
        # Các UDP ports phổ biến
        ports = [53, 123, 161, 137, 138, 139, 1434, 631, 5353]
    
    print(f"[+] UDP Ping to {ip} on ports {ports}...")
    
    host_up = False
    for port in ports:
        print(f"[.] UDP ping port {port}...", end=" ")
        
        # Tạo UDP packet với payload nhỏ
        udp_pkt = IP(dst=ip) / UDP(sport=RandShort(), dport=port) / b"ping"
        resp = sr1(udp_pkt, timeout=timeout, verbose=0)
        
        if resp is None:
            print("No response (may be open/filtered)")
            continue
        elif resp.haslayer(ICMP):
            icmp_type = resp[ICMP].type
            icmp_code = resp[ICMP].code
            
            if icmp_type == 3:  # Destination Unreachable
                if icmp_code == 3:  # Port Unreachable
                    print("Host is up! (ICMP Port Unreachable)")
                    host_up = True
                elif icmp_code == 1:  # Host Unreachable
                    print("Host unreachable")
                elif icmp_code == 2:  # Protocol Unreachable
                    print("Protocol unreachable")
                elif icmp_code == 9 or icmp_code == 10:  # Admin prohibited
                    print("Admin prohibited (firewall)")
                    host_up = True  # Host exists but filtered
                else:
                    print(f"ICMP Type 3 Code {icmp_code}")
                    host_up = True
            else:
                print(f"ICMP Type {icmp_type}")
                host_up = True
        elif resp.haslayer(UDP):
            print("UDP response received (service may be open)")
            host_up = True
        else:
            print("Unexpected response")
            host_up = True
    
    if host_up:
        print(f"[+] Host {ip} appears to be up (UDP ping)")
        return True
    else:
        print(f"[!] Host {ip} appears to be down or filtered (UDP ping)")
        return False


def arp_ping(target, interface=None, timeout=2):
    """
    ARP Ping - phát hiện hosts trong cùng LAN bằng ARP requests
    Hiệu quả nhất cho local network discovery
    """
    print(f"[+] ARP Ping to {target}...")
    
    try:
        # Nếu target là single IP
        if '/' not in target and '-' not in target:
            return _arp_ping_single(target, interface, timeout)
        # Nếu target là network range
        else:
            return _arp_ping_range(target, interface, timeout)
            
    except Exception as e:
        print(f"[!] ARP ping error: {e}")
        return False


def _arp_ping_single(ip, interface, timeout):
    """ARP ping cho single IP"""
    print(f"[.] Sending ARP request to {ip}...", end=" ")
    
    # Tạo ARP request
    arp_request = ARP(op=1, pdst=ip)  # op=1 means ARP request
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    # Gửi packet và nhận response
    answered_list = srp(arp_request_broadcast, timeout=timeout, verbose=0, iface=interface)[0]
    
    if answered_list:
        for element in answered_list:
            ip_addr = element[1].psrc
            mac_addr = element[1].hwsrc
            print(f"Host {ip_addr} is up (MAC: {mac_addr})")
            return True
    else:
        print("No ARP response")
        return False


def _arp_ping_range(target_range, interface, timeout):
    """ARP ping cho network range"""
    print(f"[+] ARP scanning range: {target_range}")
    
    # Parse network range
    if '/' in target_range:
        # CIDR notation (e.g., 192.168.1.0/24)
        network = target_range
    elif '-' in target_range:
        # Range notation (e.g., 192.168.1.1-254)
        base_ip, range_part = target_range.split('-')
        start_ip = int(base_ip.split('.')[-1])
        end_ip = int(range_part)
        base = '.'.join(base_ip.split('.')[:-1])
        
        # Convert to individual IPs
        active_hosts = []
        for i in range(start_ip, end_ip + 1):
            ip = f"{base}.{i}"
            if _arp_ping_single(ip, interface, 1):  # Shorter timeout for range scan
                active_hosts.append(ip)
        
        if active_hosts:
            print(f"[+] Found {len(active_hosts)} active hosts via ARP")
            return True
        else:
            print("[!] No active hosts found via ARP")
            return False
    else:
        return _arp_ping_single(target_range, interface, timeout)
    
    # For CIDR notation
    arp_request = ARP(op=1, pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    answered_list = srp(arp_request_broadcast, timeout=timeout, verbose=0, iface=interface)[0]
    
    active_hosts = []
    for element in answered_list:
        ip_addr = element[1].psrc
        mac_addr = element[1].hwsrc
        print(f"[+] Host {ip_addr} is up (MAC: {mac_addr})")
        active_hosts.append(ip_addr)
    
    if active_hosts:
        print(f"[+] ARP scan complete. Found {len(active_hosts)} active hosts.")
        return True
    else:
        print("[!] No hosts found in ARP scan")
        return False


def advanced_host_discovery(target, methods=None, timeout=3):
    """
    Kết hợp nhiều phương pháp host discovery
    """
    if methods is None:
        methods = ['icmp', 'tcp_syn', 'udp', 'arp']
    
    print(f"[+] Advanced host discovery for {target}")
    print(f"[+] Methods: {', '.join(methods)}")
    
    results = {}
    host_up = False
    
    # ICMP Echo Ping
    if 'icmp' in methods:
        print("\n--- ICMP Echo Ping ---")
        try:
            pkt = IP(dst=target) / ICMP()
            resp = sr1(pkt, timeout=timeout, verbose=0)
            if resp and resp.haslayer(ICMP) and resp[ICMP].type == 0:
                results['icmp'] = True
                host_up = True
                print(f"[+] ICMP: Host {target} is responding")
            else:
                results['icmp'] = False
                print(f"[-] ICMP: No response from {target}")
        except:
            results['icmp'] = False
    
    # TCP SYN Ping (ports 80, 443, 22, 21)
    if 'tcp_syn' in methods:
        print("\n--- TCP SYN Ping ---")
        tcp_ports = [80, 443, 22, 21, 23, 25, 53, 110, 143]
        tcp_responses = 0
        for port in tcp_ports:
            if tcp_syn_ping(target, port):
                tcp_responses += 1
                host_up = True
        results['tcp_syn'] = tcp_responses > 0
        print(f"[+] TCP SYN: {tcp_responses}/{len(tcp_ports)} ports responded")
    
    # UDP Ping
    if 'udp' in methods:
        print("\n--- UDP Ping ---")
        results['udp'] = udp_ping(target, timeout=timeout)
        if results['udp']:
            host_up = True
    
    # ARP Ping (if target appears to be in local network)
    if 'arp' in methods:
        print("\n--- ARP Ping ---")
        try:
            # Check if target is likely in local network
            if _is_local_network(target):
                results['arp'] = arp_ping(target, timeout=timeout)
                if results['arp']:
                    host_up = True
            else:
                print("[*] Target not in local network, skipping ARP ping")
                results['arp'] = None
        except:
            results['arp'] = False
    
    # Summary
    print(f"\n[DISCOVERY SUMMARY for {target}]")
    print(f"Host Status: {'UP' if host_up else 'DOWN/FILTERED'}")
    for method, result in results.items():
        if result is not None:
            status = "✓" if result else "✗"
            print(f"{method.upper()}: {status}")
    
    return host_up, results


def _is_local_network(ip):
    """Check if IP is likely in local network"""
    try:
        # Get local IP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()
        
        # Simple check - same first 3 octets
        local_prefix = '.'.join(local_ip.split('.')[:3])
        target_prefix = '.'.join(ip.split('.')[:3])
        
        return local_prefix == target_prefix
    except:
        return False
