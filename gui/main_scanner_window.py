"""
Main Scanner Window
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QLabel, QProgressBar, QTabWidget
)
from PyQt5.QtCore import Qt

from gui.workers.scan_worker import ScanWorker
from gui.layouts.scan_options import ScanOptionsWidget
from gui.components.results_display import ResultsDisplayWidget
from gui.components.traceroute_display import TracerouteDisplayWidget
from utils.scan_order import parse_ports, get_common_ports, validate_port_string


class NetworkScannerGUI(QMainWindow):
    """Main Scanner GUI Window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Super Simple Scanner - GUI")
        self.setGeometry(100, 100, 1200, 800)
        
        self.scan_worker = None
        self.has_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
        self.init_ui()
        
    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        
        # Target input section
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit("127.0.0.1")
        target_layout.addWidget(self.target_input)
        main_layout.addLayout(target_layout)
        
        # Scan options section
        self.scan_options = ScanOptionsWidget(has_root=self.has_root)
        main_layout.addWidget(self.scan_options)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        
        button_layout.addWidget(self.scan_button)
        button_layout.addWidget(self.stop_button)
        main_layout.addLayout(button_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        main_layout.addWidget(self.progress_bar)
        
        # Tabbed results section
        self.tabs = QTabWidget()
        
        # Tab 1: Scan Results
        self.results_display = ResultsDisplayWidget()
        self.tabs.addTab(self.results_display, "Scan Results")
        
        # Tab 2: Traceroute
        self.traceroute_display = TracerouteDisplayWidget()
        self.tabs.addTab(self.traceroute_display, "Traceroute")
        
        main_layout.addWidget(self.tabs)
        
    def get_ports(self):
        """Get ports from UI input"""
        if self.scan_options.use_common_ports.isChecked():
            try:
                # Use appropriate common ports based on scan types
                scan_types = self.scan_options.get_scan_types()
                if any(t in scan_types for t in ['udp_scan', 'enhanced_udp']):
                    tcp_ports = get_common_ports('top100')[:15]
                    udp_ports = get_common_ports('common-udp')[:10]
                    return tcp_ports + udp_ports
                else:
                    return get_common_ports('top100')[:25]  # Top 25 common ports
            except Exception as e:
                self.results_display.add_log(f"[!] Error getting common ports: {e}")
                return [80, 443, 22, 21, 23, 25, 110, 143, 53, 445, 139, 3389, 3306, 8080]
        else:
            port_text = self.scan_options.port_input.text().strip()
            if not port_text:
                return get_common_ports('web') + [22, 21, 23]  # Default to web ports + common admin
            try:
                # Validate port string first
                is_valid, error_msg = validate_port_string(port_text)
                if not is_valid:
                    self.results_display.add_log(f"[!] Invalid port format: {error_msg}")
                    return [80, 443, 22]
                
                tcp_ports, udp_ports = parse_ports(port_text)
                
                if not tcp_ports and not udp_ports:
                    self.results_display.add_log("[!] No valid ports parsed, using defaults")
                    return [80, 443, 22]
                    
                return tcp_ports + udp_ports
                
            except Exception as e:
                self.results_display.add_log(f"[!] Error parsing ports '{port_text}': {e}")
                return [80, 443, 22]
    
    def start_scan(self):
        """Start the scan"""
        target = self.target_input.text().strip()
        if not target:
            self.results_display.add_log("[!] Please enter a target")
            return
            
        scan_types = self.scan_options.get_scan_types()
        if not scan_types and not self.scan_options.os_detection_cb.isChecked():
            self.results_display.add_log("[!] Please select at least one scan type or OS detection")
            return
            
        ports = self.get_ports()
        enable_os_detection = self.scan_options.os_detection_cb.isChecked()
        timing_template = self.scan_options.timing_combo.currentText()
        
        # Clear previous results
        self.results_display.clear_results()
        self.progress_bar.setValue(0)
        
        # Update UI state
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        # Start scan worker
        self.scan_worker = ScanWorker(target, scan_types, ports, timing_template, None, enable_os_detection)
        self.scan_worker.result_signal.connect(self.results_display.add_result)
        self.scan_worker.progress_signal.connect(self.update_progress)
        self.scan_worker.log_signal.connect(self.results_display.add_log)
        self.scan_worker.os_result_signal.connect(self.results_display.update_os_result)
        self.scan_worker.host_discovery_signal.connect(self.results_display.add_host_discovery_result)
        self.scan_worker.finished.connect(self.scan_finished)
        self.scan_worker.start()
    
    def stop_scan(self):
        """Stop the scan"""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.terminate()
            self.scan_worker.wait()
        self.scan_finished()
    
    def scan_finished(self):
        """Handle scan completion"""
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setValue(100)
    
    def update_progress(self, value):
        """Update progress bar"""
        self.progress_bar.setValue(value)
