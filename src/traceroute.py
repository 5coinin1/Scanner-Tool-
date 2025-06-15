#!/usr/bin/env python3

import socket
import struct
import time
import select
import random
import subprocess
import platform
import re
from typing import List, Dict, Optional, Tuple

class TracerouteHop:
    def __init__(self, hop_num: int, ip: str = None, hostname: str = None, 
                 rtt1: float = None, rtt2: float = None, rtt3: float = None):
        self.hop_num = hop_num
        self.ip = ip
        self.hostname = hostname
        self.rtt1 = rtt1
        self.rtt2 = rtt2
        self.rtt3 = rtt3
        self.avg_rtt = self._calculate_avg_rtt()
        self.status = self._determine_status()
    
    def _calculate_avg_rtt(self) -> Optional[float]:
        rtts = [rtt for rtt in [self.rtt1, self.rtt2, self.rtt3] if rtt is not None]
        return sum(rtts) / len(rtts) if rtts else None
    
    def _determine_status(self) -> str:
        if self.ip is None:
            return "timeout"
        elif self.avg_rtt is not None:
            if self.avg_rtt < 10:
                return "fast"
            elif self.avg_rtt < 50:
                return "normal"
            elif self.avg_rtt < 200:
                return "slow"
            else:
                return "very_slow"
        return "unknown"
    
    def __str__(self):
        ip_str = self.ip or "*"
        hostname_str = f" ({self.hostname})" if self.hostname and self.hostname != self.ip else ""
        
        rtt_parts = []
        for rtt in [self.rtt1, self.rtt2, self.rtt3]:
            if rtt is not None:
                rtt_parts.append(f"{rtt:.1f} ms")
            else:
                rtt_parts.append("*")
        
        rtt_str = "  ".join(rtt_parts)
        return f"{self.hop_num:2d}  {ip_str}{hostname_str}  {rtt_str}"

class TracerouteResult:
    def __init__(self, target: str, max_hops: int = 30):
        self.target = target
        self.target_ip = None
        self.max_hops = max_hops
        self.method = "unknown"
        self.hops: List[TracerouteHop] = []
        self.start_time = time.time()
        self.end_time = None
        self.success = False
        self.error_message = None
    
    def add_hop(self, hop: TracerouteHop):
        
        self.hops.append(hop)
    
    def finish(self, success: bool = True, error_message: str = None):
        
        self.end_time = time.time()
        self.success = success
        self.error_message = error_message
    
    def get_duration(self) -> float:
        end = self.end_time or time.time()
        return end - self.start_time
    
    def get_final_hop(self) -> Optional[TracerouteHop]:
        if not self.hops:
            return None
        
        for hop in reversed(self.hops):
            if hop.ip:
                return hop
        return None
    
    def reached_destination(self) -> bool:
        final_hop = self.get_final_hop()
        if not final_hop:
            return False
        
        try:
            target_ip = socket.gethostbyname(self.target)
            return final_hop.ip == target_ip
        except socket.gaierror:
            return False

def traceroute_system(target: str, max_hops: int = 30, timeout: int = 5) -> TracerouteResult:
    
    result = TracerouteResult(target, max_hops)
    result.method = "system"
    
    try:
        result.target_ip = socket.gethostbyname(target)
    except:
        pass
    
    try:
        system = platform.system().lower()
        if system == "windows":
            cmd = ["tracert", "-h", str(max_hops), "-w", str(timeout * 1000), target]
        else:
            cmd = ["traceroute", "-m", str(max_hops), "-w", str(timeout), target]
        
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if process.returncode != 0:
            result.finish(False, f"Traceroute command failed: {process.stderr}")
            return result
        
        _parse_traceroute_output(process.stdout, result, system == "windows")
        result.finish(True)
        
    except subprocess.TimeoutExpired:
        result.finish(False, "Traceroute timed out")
    except FileNotFoundError:
        result.finish(False, "Traceroute command not found")
    except Exception as e:
        result.finish(False, f"Traceroute error: {e}")
    
    return result

def traceroute_icmp(target: str, max_hops: int = 30, timeout: int = 5) -> TracerouteResult:
    
    result = TracerouteResult(target, max_hops)
    result.method = "icmp"
    
    try:
        target_ip = socket.gethostbyname(target)
        result.target_ip = target_ip
    except socket.gaierror as e:
        result.finish(False, f"Cannot resolve target: {e}")
        return result
    
    try:
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_socket.settimeout(timeout)
        
        for ttl in range(1, max_hops + 1):
            hop = _send_icmp_probe(icmp_socket, target_ip, ttl, timeout)
            result.add_hop(hop)
            
            if hop.ip == target_ip:
                result.finish(True)
                break
                
            if len(result.hops) >= 3:
                last_three = result.hops[-3:]
                if all(h.ip is None for h in last_three):
                    break
        
        icmp_socket.close()
        
        if not result.success:
            result.finish(True)
            
    except PermissionError:
        result.finish(False, "ICMP traceroute requires root privileges")
    except Exception as e:
        result.finish(False, f"ICMP traceroute error: {e}")
    
    return result

def traceroute_udp(target: str, max_hops: int = 30, timeout: int = 5, 
                  start_port: int = 33434) -> TracerouteResult:
    
    result = TracerouteResult(target, max_hops)
    result.method = "udp"
    
    try:
        target_ip = socket.gethostbyname(target)
        result.target_ip = target_ip
    except socket.gaierror as e:
        result.finish(False, f"Cannot resolve target: {e}")
        return result
    
    try:
        for ttl in range(1, max_hops + 1):
            hop = _send_udp_probes(target_ip, ttl, timeout, start_port + ttl)
            result.add_hop(hop)
            
            if hop.ip == target_ip:
                result.finish(True)
                break
                
            if len(result.hops) >= 3:
                last_three = result.hops[-3:]
                if all(h.ip is None for h in last_three):
                    break
        
        if not result.success:
            result.finish(True)
            
    except Exception as e:
        result.finish(False, f"UDP traceroute error: {e}")
    
    return result

def _send_icmp_probe(icmp_socket, target_ip: str, ttl: int, timeout: int) -> TracerouteHop:
    
    hop = TracerouteHop(ttl)
    
    try:
        icmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        
        rtts = []
        ips = []
        
        for i in range(3):
            packet_id = random.randint(1, 65535)
            packet = _create_icmp_packet(packet_id, i)
            
            start_time = time.time()
            icmp_socket.sendto(packet, (target_ip, 0))
            
            ready = select.select([icmp_socket], [], [], timeout)
            if ready[0]:
                data, addr = icmp_socket.recvfrom(1024)
                end_time = time.time()
                rtt = (end_time - start_time) * 1000
                rtts.append(rtt)
                ips.append(addr[0])
            else:
                rtts.append(None)
                ips.append(None)
        
        valid_ips = [ip for ip in ips if ip]
        if valid_ips:
            hop.ip = valid_ips[0]
            try:
                hop.hostname = socket.gethostbyaddr(hop.ip)[0]
            except socket.herror:
                hop.hostname = hop.ip
        
        hop.rtt1, hop.rtt2, hop.rtt3 = rtts
        hop.avg_rtt = hop._calculate_avg_rtt()
        hop.status = hop._determine_status()
        
    except Exception as e:
        pass
    
    return hop

def _send_udp_probes(target_ip: str, ttl: int, timeout: int, port: int) -> TracerouteHop:
    
    hop = TracerouteHop(ttl)
    
    try:
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        udp_socket.settimeout(timeout)
        
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_socket.settimeout(timeout)
        
        rtts = []
        ips = []
        
        for i in range(3):
            try:
                start_time = time.time()
                udp_socket.sendto(b"traceroute probe", (target_ip, port + i))
                
                ready = select.select([icmp_socket], [], [], timeout)
                if ready[0]:
                    data, addr = icmp_socket.recvfrom(1024)
                    end_time = time.time()
                    rtt = (end_time - start_time) * 1000
                    rtts.append(rtt)
                    ips.append(addr[0])
                else:
                    rtts.append(None)
                    ips.append(None)
            except:
                rtts.append(None)
                ips.append(None)
        
        valid_ips = [ip for ip in ips if ip]
        if valid_ips:
            hop.ip = valid_ips[0]
            try:
                hop.hostname = socket.gethostbyaddr(hop.ip)[0]
            except socket.herror:
                hop.hostname = hop.ip
        
        hop.rtt1, hop.rtt2, hop.rtt3 = rtts
        hop.avg_rtt = hop._calculate_avg_rtt()
        hop.status = hop._determine_status()
        
        udp_socket.close()
        icmp_socket.close()
        
    except PermissionError:
        pass
    except Exception as e:
        pass
    
    return hop

def _create_icmp_packet(packet_id: int, sequence: int) -> bytes:
    
    header = struct.pack("!BBHHH", 8, 0, 0, packet_id, sequence)
    data = b"traceroute probe data"
    
    checksum = _calculate_checksum(header + data)
    header = struct.pack("!BBHHH", 8, 0, checksum, packet_id, sequence)
    
    return header + data

def _calculate_checksum(data: bytes) -> int:
    
    checksum = 0
    
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            word = (data[i] << 8) + data[i + 1]
        else:
            word = data[i] << 8
        checksum += word
    
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    return (~checksum) & 0xFFFF

def _parse_traceroute_output(output: str, result: TracerouteResult, is_windows: bool = False):
    
    lines = output.strip().split('\n')
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        if 'traceroute' in line.lower() or 'tracing route' in line.lower():
            continue
        if 'over a maximum' in line.lower():
            continue
            
        hop = _parse_hop_line(line, is_windows)
        if hop:
            result.add_hop(hop)

def _parse_hop_line(line: str, is_windows: bool = False) -> Optional[TracerouteHop]:
    
    if is_windows:
        match = re.match(r'\s*(\d+)\s+(?:(<?\d+)\s*ms|\*)\s+(?:(<?\d+)\s*ms|\*)\s+(?:(<?\d+)\s*ms|\*)\s+(\S+)', line)
        if match:
            hop_num = int(match.group(1))
            rtt1 = _parse_rtt(match.group(2)) if match.group(2) else None
            rtt2 = _parse_rtt(match.group(3)) if match.group(3) else None
            rtt3 = _parse_rtt(match.group(4)) if match.group(4) else None
            host = match.group(5)
            
            ip, hostname = _extract_ip_hostname(host)
            
            return TracerouteHop(hop_num, ip, hostname, rtt1, rtt2, rtt3)
    else:
        match = re.match(r'\s*(\d+)\s+(\S+(?:\s+\([^)]+\))?)\s+(.*)', line)
        if match:
            hop_num = int(match.group(1))
            host_part = match.group(2)
            timing_part = match.group(3)
            
            ip, hostname = _extract_ip_hostname(host_part)
            
            rtt_matches = re.findall(r'(\d+(?:\.\d+)?)\s*ms', timing_part)
            rtts = [float(rtt) for rtt in rtt_matches]
            
            while len(rtts) < 3:
                rtts.append(None)
            
            return TracerouteHop(hop_num, ip, hostname, rtts[0], rtts[1], rtts[2])
    
    return None

def _parse_rtt(rtt_str: str) -> Optional[float]:
    
    if not rtt_str or rtt_str == '*':
        return None
    
    if rtt_str.startswith('<'):
        return float(rtt_str[1:])
    
    try:
        return float(rtt_str)
    except ValueError:
        return None

def _extract_ip_hostname(host_str: str) -> Tuple[Optional[str], Optional[str]]:
    
    if not host_str or host_str == '*':
        return None, None
    
    match = re.match(r'(\S+)\s*\(([^)]+)\)', host_str)
    if match:
        hostname = match.group(1)
        ip = match.group(2)
        return ip, hostname
    else:
        try:
            ip = socket.gethostbyname(host_str)
            return ip, host_str if host_str != ip else None
        except socket.gaierror:
            return host_str, None

def traceroute(target: str, max_hops: int = 30, timeout: int = 5, method: str = "auto") -> TracerouteResult:
    """
    Perform traceroute using specified method
    
    Args:
        target: Target hostname or IP
        max_hops: Maximum number of hops
        timeout: Timeout per hop in seconds
        method: "auto", "system", "icmp", or "udp"
    
    Returns:
        TracerouteResult object
    """
    if method == "system":
        return traceroute_system(target, max_hops, timeout)
    elif method == "icmp":
        return traceroute_icmp(target, max_hops, timeout)
    elif method == "udp":
        return traceroute_udp(target, max_hops, timeout)
    else:
        result = traceroute_system(target, max_hops, timeout)
        if result.success:
            return result
        
        try:
            return traceroute_icmp(target, max_hops, timeout)
        except:
            pass
        
        return traceroute_udp(target, max_hops, timeout)

def trace(target: str, **kwargs) -> TracerouteResult:
    
    return traceroute(target, **kwargs)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 traceroute.py <target> [max_hops] [timeout]")
        sys.exit(1)
    
    target = sys.argv[1]
    max_hops = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    
    print(f"Traceroute to {target}, {max_hops} hops max")
    result = traceroute(target, max_hops, timeout)
    
    if result.success:
        for hop in result.hops:
            print(hop)
        print(f"\nTraceroute completed in {result.get_duration():.1f} seconds")
    else:
        print(f"Traceroute failed: {result.error_message}")
