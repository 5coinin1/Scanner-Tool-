import socket
import struct
import time
import random
from scapy.all import IP, ICMP, TCP, sr1
from collections import defaultdict

class OSFingerprint:
    def __init__(self, name, ttl_range, window_size, tcp_options=None, icmp_code=None):
        self.name = name
        self.ttl_range = ttl_range
        self.window_size = window_size
        self.tcp_options = tcp_options or []
        self.icmp_code = icmp_code
        self.confidence = 0

OS_FINGERPRINTS = [
    OSFingerprint("Windows 10/11", (128, 128), [8192, 65535], 
                 ["mss", "nop", "ws", "nop", "nop", "sackOK"], 0),
    OSFingerprint("Windows 8/8.1", (128, 128), [8192, 65535], 
                 ["mss", "nop", "ws", "nop", "nop", "sackOK"], 0),
    OSFingerprint("Windows 7", (128, 128), [8192, 65535], 
                 ["mss", "nop", "ws", "nop", "nop", "sackOK"], 0),
    OSFingerprint("Windows XP", (128, 128), [65535, 16384], 
                 ["mss", "nop", "nop", "sackOK"], 0),
    OSFingerprint("Windows Server 2019/2022", (128, 128), [8192, 65535], 
                 ["mss", "nop", "ws", "nop", "nop", "sackOK"], 0),
    
    OSFingerprint("Linux 2.6.x", (64, 64), [5840, 65535], 
                 ["mss", "sackOK", "ts", "nop", "ws"], 0),
    OSFingerprint("Linux 3.x/4.x/5.x", (64, 64), [29200, 65535], 
                 ["mss", "sackOK", "ts", "nop", "ws"], 0),
    OSFingerprint("Ubuntu Linux", (64, 64), [29200, 65535], 
                 ["mss", "sackOK", "ts", "nop", "ws"], 0),
    OSFingerprint("CentOS/RHEL", (64, 64), [29200, 65535], 
                 ["mss", "sackOK", "ts", "nop", "ws"], 0),
    
    OSFingerprint("FreeBSD", (64, 64), [65535, 33304], 
                 ["mss", "nop", "ws", "sackOK", "ts"], 0),
    OSFingerprint("OpenBSD", (255, 255), [16384, 65535], 
                 ["mss", "nop", "nop", "sackOK"], 0),
    OSFingerprint("NetBSD", (255, 255), [32768, 65535], 
                 ["mss", "nop", "nop", "sackOK"], 0),
    OSFingerprint("Solaris", (255, 255), [49640, 65535], 
                 ["nop", "ws", "nop", "nop", "ts", "nop", "nop", "sackOK"], 0),
    
    OSFingerprint("macOS Big Sur/Monterey", (64, 64), [65535, 131072], 
                 ["mss", "nop", "ws", "nop", "nop", "ts", "sackOK", "eol"], 0),
    OSFingerprint("macOS Catalina/Mojave", (64, 64), [65535, 131072], 
                 ["mss", "nop", "ws", "nop", "nop", "ts", "sackOK", "eol"], 0),
    
    OSFingerprint("Cisco IOS", (255, 255), [4128, 8760], 
                 ["mss", "nop", "nop", "sackOK"], 0),
    OSFingerprint("Juniper JunOS", (64, 64), [16384, 32768], 
                 ["mss", "nop", "nop", "sackOK"], 0),
    
    OSFingerprint("Embedded Linux", (64, 64), [5840, 29200], 
                 ["mss", "sackOK", "ts", "nop", "ws"], 0),
    OSFingerprint("VxWorks", (255, 255), [8760, 32768], 
                 ["mss"], 0),
]

class OSDetector:
    def __init__(self):
        self.results = defaultdict(int)
        self.detected_ttl = None
        self.detected_window_size = None
        self.tcp_options = []
        
    def detect_os(self, target_ip, timeout=3):
        print(f"[+] Starting OS detection for {target_ip}")
        
        self.results.clear()
        
        ttl_os = self._detect_by_ttl(target_ip, timeout)
        if ttl_os:
            self.results[ttl_os] += 3
            
        window_os = self._detect_by_tcp_window(target_ip, timeout)
        if window_os:
            self.results[window_os] += 2
            
        options_os = self._detect_by_tcp_options(target_ip, timeout)
        if options_os:
            self.results[options_os] += 2
            
        banner_os = self._detect_by_banners(target_ip, timeout)
        if banner_os:
            self.results[banner_os] += 1
            
        return self._analyze_results()
        
    def _detect_by_ttl(self, target_ip, timeout):
        try:
            icmp_pkt = IP(dst=target_ip)/ICMP()
            response = sr1(icmp_pkt, timeout=timeout, verbose=0)
            
            if response:
                ttl = response[IP].ttl
                self.detected_ttl = ttl
                print(f"[*] Detected TTL: {ttl}")
                
                for fingerprint in OS_FINGERPRINTS:
                    min_ttl, max_ttl = fingerprint.ttl_range
                    if min_ttl <= ttl <= max_ttl:
                        return fingerprint.name
                        
        except Exception as e:
            print(f"[!] TTL detection error: {e}")
            
        return None
        
    def _detect_by_tcp_window(self, target_ip, timeout):
        try:
            for port in [80, 443, 22, 21]:
                syn_pkt = IP(dst=target_ip)/TCP(dport=port, flags="S", seq=random.randint(1000, 9000))
                response = sr1(syn_pkt, timeout=timeout, verbose=0)
                
                if response and response.haslayer(TCP):
                    if response[TCP].flags == 18:
                        window = response[TCP].window
                        self.detected_window_size = window
                        print(f"[*] Detected TCP Window: {window}")
                        
                        for fingerprint in OS_FINGERPRINTS:
                            if isinstance(fingerprint.window_size, list):
                                if any(abs(window - ws) < 1000 for ws in fingerprint.window_size):
                                    return fingerprint.name
                            else:
                                if abs(window - fingerprint.window_size) < 1000:
                                    return fingerprint.name
                        break
                        
        except Exception as e:
            print(f"[!] TCP window detection error: {e}")
            
        return None
        
    def _detect_by_tcp_options(self, target_ip, timeout):
        try:
            for port in [80, 443, 22]:
                syn_pkt = IP(dst=target_ip)/TCP(
                    dport=port, 
                    flags="S", 
                    seq=random.randint(1000, 9000),
                    options=[('MSS', 1460), ('SAckOK', ''), ('Timestamp', (12345, 0)), ('NOP', None), ('WScale', 7)]
                )
                response = sr1(syn_pkt, timeout=timeout, verbose=0)
                
                if response and response.haslayer(TCP):
                    if response[TCP].flags == 18:
                        options = response[TCP].options
                        self.tcp_options = [opt[0] for opt in options if opt[0] != 'NOP']
                        print(f"[*] Detected TCP Options: {self.tcp_options}")
                        
                        for fingerprint in OS_FINGERPRINTS:
                            if fingerprint.tcp_options:
                                matches = sum(1 for opt in self.tcp_options if opt.lower() in [o.lower() for o in fingerprint.tcp_options])
                                if matches >= len(fingerprint.tcp_options) * 0.6:
                                    return fingerprint.name
                        break
                        
        except Exception as e:
            print(f"[!] TCP options detection error: {e}")
            
        return None
        
    def _detect_by_banners(self, target_ip, timeout):
        banner_signatures = {
            "Windows": ["Microsoft", "Windows", "IIS"],
            "Linux": ["Linux", "Ubuntu", "Debian", "CentOS", "Red Hat"],
            "FreeBSD": ["FreeBSD"],
            "macOS": ["Darwin", "Mac OS"],
            "Cisco IOS": ["Cisco"]
        }
        
        try:
            for port in [21, 22, 23, 25, 53, 80, 110, 143]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    result = sock.connect_ex((target_ip, port))
                    
                    if result == 0:
                        if port == 80:
                            sock.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
                        elif port == 21:
                            pass
                        elif port == 22:
                            pass
                        
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        print(f"[*] Banner from port {port}: {banner[:100]}...")
                        
                        for os_name, keywords in banner_signatures.items():
                            if any(keyword.lower() in banner.lower() for keyword in keywords):
                                sock.close()
                                return os_name
                                
                    sock.close()
                    
                except:
                    continue
                    
        except Exception as e:
            print(f"[!] Banner detection error: {e}")
            
        return None
        
    def _analyze_results(self):
        if not self.results:
            return {
                "os": "Unknown",
                "confidence": 0,
                "details": {
                    "ttl": self.detected_ttl,
                    "window_size": self.detected_window_size,
                    "tcp_options": self.tcp_options
                }
            }
            
        best_os = max(self.results.items(), key=lambda x: x[1])
        total_score = sum(self.results.values())
        confidence = (best_os[1] / total_score) * 100 if total_score > 0 else 0
        
        result = {
            "os": best_os[0],
            "confidence": round(confidence, 1),
            "details": {
                "ttl": self.detected_ttl,
                "window_size": self.detected_window_size,
                "tcp_options": self.tcp_options,
                "all_matches": dict(self.results)
            }
        }
        
        print(f"[+] OS Detection Result: {result['os']} (Confidence: {result['confidence']}%)")
        return result

def advanced_os_detection(target_ip, timeout=3):
    detector = OSDetector()
    return detector.detect_os(target_ip, timeout)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python os_detection.py <target_ip>")
        sys.exit(1)
        
    target = sys.argv[1]
    print(f"[+] Advanced OS Detection for {target}")
    result = advanced_os_detection(target)
    
    print(f"\n[RESULT] OS: {result['os']}")
    print(f"[RESULT] Confidence: {result['confidence']}%")
    print(f"[RESULT] TTL: {result['details']['ttl']}")
    print(f"[RESULT] Window Size: {result['details']['window_size']}")
    print(f"[RESULT] TCP Options: {result['details']['tcp_options']}")
