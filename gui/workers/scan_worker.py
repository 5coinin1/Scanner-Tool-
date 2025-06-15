import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from PyQt5.QtCore import QThread, pyqtSignal

from src.port_scanner import (
    syn_scan, tcp_connect_scan, udp_scan, enhanced_udp_scan,
    parallel_port_scan, adaptive_scan, stealth_scan,
    advanced_tcp_connect_scan
)
from src.timing import TIMING_TEMPLATES
from src.host_discovery import (
    no_port_scan, icmp_echo_ping, tcp_syn_ping, udp_ping, arp_ping, 
    advanced_host_discovery, icmp_timestamp_ping, icmp_address_mask_ping,
    icmp_info_ping, comprehensive_icmp_ping, enhanced_tcp_syn_ping
)
from src.os_detection import advanced_os_detection

class ScanWorker(QThread):
    result_signal = pyqtSignal(str, int, str, str, str)
    progress_signal = pyqtSignal(int)
    log_signal = pyqtSignal(str)
    os_result_signal = pyqtSignal(dict)
    host_discovery_signal = pyqtSignal(str, bool, str)
    
    def __init__(self, target, scan_types, ports, timing_template="normal", max_threads=None, enable_os_detection=False):
        super().__init__()
        self.target = target
        self.scan_types = scan_types
        self.ports = ports
        self.timing_template = timing_template
        self.max_threads = max_threads
        self.enable_os_detection = enable_os_detection
        
    def run(self):
        self.log_signal.emit(f"[+] Starting scan on {self.target}")
        self._log_scan_settings()
        
        self._run_host_discovery()
        
        if not self.ports or self._is_only_host_discovery():
            return
        
        total_ports = len(self.ports)
        completed = 0
        
        if self._run_advanced_scans(total_ports, completed):
            return
        
        self._run_individual_port_scans(total_ports)
        
        if self.enable_os_detection:
            self._run_os_detection()
            
        self.log_signal.emit("[+] Scan completed!")
    
    def _log_scan_settings(self):
        timing_config = TIMING_TEMPLATES.get(self.timing_template, TIMING_TEMPLATES["normal"])
        max_threads = self.max_threads if self.max_threads else timing_config["max_threads"]
        
        self.log_signal.emit(f"[+] Scan Configuration:")
        self.log_signal.emit(f"    - Target: {self.target}")
        self.log_signal.emit(f"    - Ports: {len(self.ports)} total")
        self.log_signal.emit(f"    - Timing template: {self.timing_template}")
        self.log_signal.emit(f"    - Timeout: {timing_config['timeout']}s")
        self.log_signal.emit(f"    - Delay: {timing_config['delay']}s")
        self.log_signal.emit(f"    - Max threads: {max_threads}")
        self.log_signal.emit(f"    - Scan types: {', '.join(self.scan_types)}")
        if self.enable_os_detection:
            self.log_signal.emit(f"    - OS Detection: enabled")
        self.log_signal.emit("")
    
    def _run_host_discovery(self):
        import time
        
        timing_config = TIMING_TEMPLATES.get(self.timing_template, TIMING_TEMPLATES["normal"])
        delay = timing_config["delay"]
        timeout = timing_config["timeout"]
        
        self.log_signal.emit(f"[+] Host discovery using timing: {self.timing_template}")
        
        discovery_methods = {
            'host_discovery': (no_port_scan, "Host Discovery"),
            'icmp_echo': (icmp_echo_ping, "ICMP Echo"),
            'icmp_timestamp': (icmp_timestamp_ping, "ICMP Timestamp"),
            'icmp_address_mask': (icmp_address_mask_ping, "ICMP Addr Mask"),
            'icmp_info': (icmp_info_ping, "ICMP Info"),
            'comprehensive_icmp': (comprehensive_icmp_ping, "Comprehensive ICMP"),
            'enhanced_tcp_syn': (enhanced_tcp_syn_ping, "Enhanced TCP SYN"),
            'udp_ping': (udp_ping, "UDP Ping"),
            'arp_ping': (arp_ping, "ARP Ping")
        }
        
        for scan_type, (func, name) in discovery_methods.items():
            if scan_type in self.scan_types:
                if delay > 0:
                    time.sleep(delay)
                
                self.log_signal.emit(f"[+] {name} ping on {self.target}")
                try:
                    if scan_type == 'tcp_syn_ping':
                        result = tcp_syn_ping(self.target, 80)
                        self.host_discovery_signal.emit("TCP SYN Ping", result, f"Port 80: {'UP' if result else 'DOWN'}")
                    elif scan_type == 'udp_ping':
                        result = func(self.target)
                        self.host_discovery_signal.emit(name, result, f"{'UP' if result else 'DOWN'}")
                    elif scan_type == 'arp_ping':
                        result = func(self.target)
                        self.host_discovery_signal.emit(name, result, f"{'UP' if result else 'DOWN'}")
                    else:
                        result = func(self.target)
                        self.host_discovery_signal.emit(name, result is not None, str(result) if result else "No response")
                except Exception as e:
                    self.host_discovery_signal.emit(name, False, f"Error: {e}")
        
        if 'advanced_discovery' in self.scan_types:
            self.log_signal.emit(f"[+] Advanced host discovery on {self.target}")
            try:
                host_up, results = advanced_host_discovery(self.target)
                self.host_discovery_signal.emit("Advanced Discovery", host_up, f"Overall: {'UP' if host_up else 'DOWN'}")
                
                for method, result in results.items():
                    if result is not None:
                        self.host_discovery_signal.emit(f"  {method.upper()}", result, f"{'UP' if result else 'DOWN'}")
            except Exception as e:
                self.host_discovery_signal.emit("Advanced Discovery", False, f"Error: {e}")
    
    def _is_only_host_discovery(self):
        host_discovery_types = ['host_discovery', 'icmp_echo', 'icmp_timestamp', 'icmp_address_mask', 
                               'icmp_info', 'comprehensive_icmp', 'tcp_syn_ping', 'enhanced_tcp_syn', 
                               'udp_ping', 'arp_ping', 'advanced_discovery']
        port_scan_types = ['syn_scan', 'tcp_connect', 'udp_scan', 'enhanced_udp', 'parallel', 'stealth', 'adaptive', 'advanced_tcp']
        
        has_host_discovery = any(scan in self.scan_types for scan in host_discovery_types)
        has_port_scan = any(scan in self.scan_types for scan in port_scan_types)
        
        return has_host_discovery and not has_port_scan
    
    def _run_advanced_scans(self, total_ports, completed):
        if 'parallel' in self.scan_types:
            return self._run_parallel_scan(total_ports, completed)
        elif 'stealth' in self.scan_types:
            return self._run_stealth_scan(total_ports, completed)
        elif 'adaptive' in self.scan_types:
            return self._run_adaptive_scan(total_ports, completed)
        return False
    
    def _run_parallel_scan(self, total_ports, completed):
        scan_type = "syn" if 'syn_scan' in self.scan_types else "connect" if 'tcp_connect' in self.scan_types else "udp"
        
        timing_config = TIMING_TEMPLATES.get(self.timing_template, TIMING_TEMPLATES["normal"])
        max_threads = self.max_threads if self.max_threads else timing_config["max_threads"]
        
        self.log_signal.emit(f"[+] Parallel scanning {len(self.ports)} ports...")
        self.log_signal.emit(f"[+] Scan type: {scan_type.upper()}")
        self.log_signal.emit(f"[+] Timing: {self.timing_template} (threads: {max_threads})")
        
        try:
            results = parallel_port_scan(self.target, self.ports, scan_type=scan_type, 
                                       timing=self.timing_template, max_threads=max_threads, verbose=False)
            
            if results:
                for port, result in results.items():
                    self._process_scan_result(port, result, "TCP" if scan_type != "udp" else "UDP")
                    completed += 1
                    progress = int((completed / total_ports) * 100)
                    self.progress_signal.emit(progress)
            else:
                for port in self.ports:
                    self.result_signal.emit(str(port), port, "SCANNED", "TCP" if scan_type != "udp" else "UDP", f"Parallel scan completed")
                    completed += 1
                    progress = int((completed / total_ports) * 100)
                    self.progress_signal.emit(progress)
        except Exception as e:
            self.log_signal.emit(f"[!] Parallel scan error: {e}")
        return True
    
    def _run_stealth_scan(self, total_ports, completed):
        from src.timing import TimingConfig
        import time
        
        timing_config = TIMING_TEMPLATES.get(self.timing_template, TIMING_TEMPLATES["normal"])
        timing_obj = TimingConfig(self.timing_template)
        
        self.log_signal.emit(f"[+] Stealth scanning {len(self.ports)} ports...")
        self.log_signal.emit(f"[+] Using stealth techniques: fragmentation, jitter, randomization")
        self.log_signal.emit(f"[+] Timing: {self.timing_template} (timeout: {timing_obj.timeout}s, delay: {timing_obj.delay}s)")
        
        try:
            results = stealth_scan(self.target, self.ports, timing=timing_obj, verbose=False)
            
            if results:
                for port, result in results.items():
                    self._process_scan_result(port, result, "TCP")
                    completed += 1
                    progress = int((completed / total_ports) * 100)
                    self.progress_signal.emit(progress)
            else:
                for port in self.ports:
                    try:
                        jitter = timing_obj.delay * 0.5
                        import random
                        actual_delay = timing_obj.delay + (random.random() * jitter)
                        if actual_delay > 0:
                            time.sleep(actual_delay)
                        
                        result = syn_scan(self.target, port, timeout=timing_obj.timeout, verbose=False)
                        self._process_scan_result(port, result, "TCP")
                    except Exception as e:
                        self.result_signal.emit(str(port), port, "ERROR", "TCP", str(e))
                    
                    completed += 1
                    progress = int((completed / total_ports) * 100)
                    self.progress_signal.emit(progress)
        except Exception as e:
            self.log_signal.emit(f"[!] Stealth scan error: {e}")
            return self._fallback_stealth_scan(total_ports, completed, timing_obj)
        
        return True
    
    def _fallback_stealth_scan(self, total_ports, completed, timing_obj):
        import time
        import random
        
        self.log_signal.emit(f"[+] Using fallback stealth mode (SYN scan with jitter)")
        
        for port in self.ports:
            try:
                jitter = timing_obj.delay * 0.5
                actual_delay = timing_obj.delay + (random.random() * jitter)
                if actual_delay > 0:
                    time.sleep(actual_delay)
                
                result = syn_scan(self.target, port, timeout=timing_obj.timeout, verbose=False)
                self._process_scan_result(port, result, "TCP")
            except Exception as e:
                self.result_signal.emit(str(port), port, "ERROR", "TCP", str(e))
            
            completed += 1
            progress = int((completed / total_ports) * 100)
            self.progress_signal.emit(progress)
        
        return True
    
    def _run_adaptive_scan(self, total_ports, completed):
        from src.timing import TimingConfig
        
        timing_config = TIMING_TEMPLATES.get(self.timing_template, TIMING_TEMPLATES["normal"])
        timing_obj = TimingConfig(self.timing_template)
        
        self.log_signal.emit(f"[+] Adaptive scanning {len(self.ports)} ports...")
        self.log_signal.emit(f"[+] Smart timing adjustment based on network response")
        self.log_signal.emit(f"[+] Base timing: {self.timing_template} (will adjust automatically)")
        
        try:
            results = adaptive_scan(self.target, self.ports, timing=timing_obj, verbose=False)
            
            if results:
                for port, result in results.items():
                    self._process_scan_result(port, result, "TCP")
                    completed += 1
                    progress = int((completed / total_ports) * 100)
                    self.progress_signal.emit(progress)
            else:
                for port in self.ports:
                    self.result_signal.emit(str(port), port, "SCANNED", "TCP", f"Adaptive scan completed (base timing: {self.timing_template})")
                    completed += 1
                    progress = int((completed / total_ports) * 100)
                    self.progress_signal.emit(progress)
        except Exception as e:
            self.log_signal.emit(f"[!] Adaptive scan error: {e}")
            self._fallback_adaptive_scan(total_ports, completed, timing_obj)
        return True
    
    def _fallback_adaptive_scan(self, total_ports, completed, timing_obj):
        import time
        
        self.log_signal.emit(f"[+] Using fallback adaptive mode (TCP connect with adjustment)")
        
        current_delay = timing_obj.delay
        current_timeout = timing_obj.timeout
        success_count = 0
        total_attempts = 0
        
        for i, port in enumerate(self.ports):
            try:
                result = tcp_connect_scan(self.target, port, timeout=current_timeout, verbose=False)
                self._process_scan_result(port, result, "TCP")
                
                if result:
                    success_count += 1
                total_attempts += 1
                
                if (i + 1) % 10 == 0 and total_attempts > 0:
                    success_rate = success_count / total_attempts
                    if success_rate > 0.8:
                        current_delay = max(0.01, current_delay * 0.9)
                        current_timeout = max(0.5, current_timeout * 0.95)
                        self.log_signal.emit(f"[+] Adaptive: High success rate, increasing speed (delay: {current_delay:.2f}s)")
                    elif success_rate < 0.3:
                        current_delay = min(5.0, current_delay * 1.2)
                        current_timeout = min(10.0, current_timeout * 1.1)
                        self.log_signal.emit(f"[+] Adaptive: Low success rate, reducing speed (delay: {current_delay:.2f}s)")
                
                if current_delay > 0:
                    time.sleep(current_delay)
                
            except Exception as e:
                self.result_signal.emit(str(port), port, "ERROR", "TCP", str(e))
            
            completed += 1
            progress = int((completed / total_ports) * 100)
            self.progress_signal.emit(progress)
    
    def _run_individual_port_scans(self, total_ports):
        import time
        
        completed = 0
        
        timing_config = TIMING_TEMPLATES.get(self.timing_template, TIMING_TEMPLATES["normal"])
        timeout = timing_config["timeout"]
        delay = timing_config["delay"]
        
        scan_functions = {
            'syn_scan': (syn_scan, "TCP"),
            'tcp_connect': (tcp_connect_scan, "TCP"),
            'advanced_tcp': (advanced_tcp_connect_scan, "TCP"),
            'udp_scan': (udp_scan, "UDP"),
            'enhanced_udp': (enhanced_udp_scan, "UDP")
        }
        
        self.log_signal.emit(f"[+] Using timing template: {self.timing_template}")
        self.log_signal.emit(f"[+] Timeout: {timeout}s, Delay: {delay}s")
        
        for port in self.ports:
            for scan_type, (func, protocol) in scan_functions.items():
                if scan_type in self.scan_types:
                    try:
                        if delay > 0:
                            time.sleep(delay)
                        
                        result = func(self.target, port, timeout=timeout, verbose=False)
                        self._process_scan_result(port, result, protocol)
                    except Exception as e:
                        self.result_signal.emit(str(port), port, "ERROR", protocol, str(e))
            
            completed += 1
            progress = int((completed / total_ports) * 100)
            self.progress_signal.emit(progress)
    
    def _process_scan_result(self, port, result, protocol):
        if isinstance(result, dict):
            status = result.get('status', 'unknown').upper()
            rtt = result.get('rtt', 0)
            service = result.get('service', '')
            extra = f"RTT: {rtt:.1f}ms" if rtt else ""
            if service:
                extra += f" | {service}"
            self.result_signal.emit(str(port), port, status, protocol, extra)
        else:
            status = "OPEN" if result else "CLOSED"
            self.result_signal.emit(str(port), port, status, protocol, "")
    
    def _run_os_detection(self):
        self.log_signal.emit("[+] Starting OS detection...")
        try:
            os_result = advanced_os_detection(self.target)
            self.os_result_signal.emit(os_result)
            self.log_signal.emit(f"[+] OS detected: {os_result['os']} ({os_result['confidence']}%)")
        except Exception as e:
            self.log_signal.emit(f"[!] OS detection failed: {e}")
