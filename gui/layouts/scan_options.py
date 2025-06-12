"""
Scan Options Layout Components
"""
import os
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QCheckBox, QGroupBox, 
    QLabel, QComboBox, QSpinBox, QLineEdit
)

from gui.components.collapsible_box import CollapsibleBox


class ScanOptionsWidget(QWidget):
    """Widget containing all scan options"""
    
    def __init__(self, has_root=False, parent=None):
        super().__init__(parent)
        self.has_root = has_root
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Basic Scan Types
        layout.addWidget(self._create_basic_scan_group())
        
        # Advanced Scan Types  
        layout.addWidget(self._create_advanced_scan_group())
        
        # Host Discovery
        layout.addWidget(self._create_host_discovery_group())
        
        # Other Options
        layout.addWidget(self._create_other_options_group())
        
        # Port Options
        layout.addLayout(self._create_port_options())
    
    def _create_basic_scan_group(self):
        """Create basic scan types group"""
        basic_group = QGroupBox("Basic Scan Types")
        basic_layout = QHBoxLayout(basic_group)
        
        self.syn_scan_cb = QCheckBox("SYN Scan (-sS)")
        self.tcp_connect_cb = QCheckBox("TCP Connect (-sT)")
        self.udp_scan_cb = QCheckBox("UDP Scan (-sU)")
        self.enhanced_udp_cb = QCheckBox("Enhanced UDP")
        self.advanced_tcp_cb = QCheckBox("Advanced TCP")
        
        # Disable root-required features if not running as root
        if not self.has_root:
            self.syn_scan_cb.setEnabled(False)
            self.syn_scan_cb.setToolTip("Requires root privileges")
            self.tcp_connect_cb.setChecked(True)  # Default to TCP Connect if no root
        else:
            self.syn_scan_cb.setChecked(True)  # Default to SYN if root
        
        basic_layout.addWidget(self.syn_scan_cb)
        basic_layout.addWidget(self.tcp_connect_cb)
        basic_layout.addWidget(self.udp_scan_cb)
        basic_layout.addWidget(self.enhanced_udp_cb)
        basic_layout.addWidget(self.advanced_tcp_cb)
        
        return basic_group
    
    def _create_advanced_scan_group(self):
        """Create advanced scan types group"""
        advanced_group = QGroupBox("Advanced Scan Types")
        advanced_layout = QVBoxLayout(advanced_group)
        
        # Main advanced scan row
        main_advanced_row = QHBoxLayout()
        
        self.parallel_cb = QCheckBox("Parallel Scan (--parallel)")
        self.parallel_cb.setToolTip("Multi-threaded scanning for faster results\nBest for large port ranges")
        
        self.stealth_cb = QCheckBox("Stealth Scan (--stealth)")
        self.stealth_cb.setToolTip("Evasion techniques: fragmentation, jitter, randomization\nHarder to detect by IDS/IPS")
        
        self.adaptive_cb = QCheckBox("Adaptive Scan (--adaptive)")
        self.adaptive_cb.setToolTip("Smart timing adjustment based on network response\nAutomatically optimizes speed vs reliability")
        
        main_advanced_row.addWidget(self.parallel_cb)
        main_advanced_row.addWidget(self.stealth_cb)
        main_advanced_row.addWidget(self.adaptive_cb)
        advanced_layout.addLayout(main_advanced_row)
        
        # Advanced options info
        info_layout = QHBoxLayout()
        info_label = QLabel("💡 Combine with timing templates: Parallel+T4 (fast), Stealth+T1 (covert), Adaptive+T3 (balanced)")
        info_label.setStyleSheet("color: #666; font-size: 9px; font-style: italic;")
        info_label.setWordWrap(True)
        info_layout.addWidget(info_label)
        advanced_layout.addLayout(info_layout)
        
        return advanced_group
    
    def _create_host_discovery_group(self):
        """Create host discovery group with collapsible details"""
        discovery_group = QGroupBox("Host Discovery")
        discovery_layout = QVBoxLayout(discovery_group)
        
        # Main discovery row with most important options
        main_discovery_row = QHBoxLayout()
        self.host_discovery_cb = QCheckBox("Host Discovery (-sn)")
        self.comprehensive_icmp_cb = QCheckBox("Comprehensive ICMP (-PC)")
        self.advanced_discovery_cb = QCheckBox("Advanced Discovery (-PA)")
        self.arp_ping_cb = QCheckBox("ARP Ping (-PR)")
        
        # Disable comprehensive ICMP if not root
        if not self.has_root:
            self.comprehensive_icmp_cb.setEnabled(False)
            self.comprehensive_icmp_cb.setToolTip("Requires root privileges")
        
        main_discovery_row.addWidget(self.host_discovery_cb)
        main_discovery_row.addWidget(self.comprehensive_icmp_cb)
        main_discovery_row.addWidget(self.advanced_discovery_cb)
        main_discovery_row.addWidget(self.arp_ping_cb)
        
        discovery_layout.addLayout(main_discovery_row)
        
        # Collapsible section for detailed ICMP options
        icmp_detail_box = CollapsibleBox("Individual ICMP Methods (included in -PC)")
        icmp_detail_layout = QVBoxLayout()
        
        # Individual ICMP methods
        icmp_row1 = QHBoxLayout()
        self.icmp_echo_cb = QCheckBox("ICMP Echo (-PE)")
        self.icmp_timestamp_cb = QCheckBox("ICMP Timestamp (-PP)")
        self.icmp_address_mask_cb = QCheckBox("ICMP Addr Mask (-PM)")
        self.icmp_info_cb = QCheckBox("ICMP Info (-PI)")
        
        # Disable individual ICMP methods if not root
        if not self.has_root:
            for cb in [self.icmp_echo_cb, self.icmp_timestamp_cb, self.icmp_address_mask_cb, self.icmp_info_cb]:
                cb.setEnabled(False)
                cb.setToolTip("Requires root privileges")
        
        icmp_row1.addWidget(self.icmp_echo_cb)
        icmp_row1.addWidget(self.icmp_timestamp_cb)
        icmp_row1.addWidget(self.icmp_address_mask_cb)
        icmp_row1.addWidget(self.icmp_info_cb)
        
        # TCP/UDP ping methods
        ping_row2 = QHBoxLayout()
        self.tcp_syn_ping_cb = QCheckBox("TCP SYN Ping (-PS)")
        self.enhanced_tcp_syn_cb = QCheckBox("Enhanced TCP SYN (-PSE)")
        self.udp_ping_cb = QCheckBox("UDP Ping (-PU)")
        
        # Disable TCP SYN ping if not root
        if not self.has_root:
            self.tcp_syn_ping_cb.setEnabled(False)
            self.tcp_syn_ping_cb.setToolTip("Requires root privileges")
            self.enhanced_tcp_syn_cb.setEnabled(False)
            self.enhanced_tcp_syn_cb.setToolTip("Requires root privileges")
        
        ping_row2.addWidget(self.tcp_syn_ping_cb)
        ping_row2.addWidget(self.enhanced_tcp_syn_cb)
        ping_row2.addWidget(self.udp_ping_cb)
        ping_row2.addStretch()  # Add stretch to fill space
        
        icmp_detail_layout.addLayout(icmp_row1)
        icmp_detail_layout.addLayout(ping_row2)
        icmp_detail_box.setContentLayout(icmp_detail_layout)
        
        discovery_layout.addWidget(icmp_detail_box)
        
        return discovery_group
    
    def _create_other_options_group(self):
        """Create other options group"""
        from src.timing import TIMING_TEMPLATES
        
        other_group = QGroupBox("Other Options")
        other_layout = QHBoxLayout(other_group)
        
        self.os_detection_cb = QCheckBox("OS Detection (-O)")
        
        # Disable OS detection if not root
        if not self.has_root:
            self.os_detection_cb.setEnabled(False)
            self.os_detection_cb.setToolTip("Requires root privileges for raw packet analysis")
        
        # Timing Template
        other_layout.addWidget(QLabel("Timing:"))
        self.timing_combo = QComboBox()
        self.timing_combo.addItems(list(TIMING_TEMPLATES.keys()))
        self.timing_combo.setCurrentText("normal")
        self.timing_combo.currentTextChanged.connect(self._update_timing_info)
        other_layout.addWidget(self.timing_combo)
        
        # Timing info label
        self.timing_info_label = QLabel()
        self._update_timing_info("normal")
        other_layout.addWidget(self.timing_info_label)
        
        other_layout.addWidget(self.os_detection_cb)
        
        # Add privilege status indicator
        if not self.has_root:
            privilege_label = QLabel("⚠️ Limited Mode (No Root)")
            privilege_label.setStyleSheet("color: orange; font-weight: bold;")
            privilege_label.setToolTip("Some features disabled. Run with sudo for full functionality.")
            other_layout.addWidget(privilege_label)
        else:
            privilege_label = QLabel("✓ Full Mode (Root)")
            privilege_label.setStyleSheet("color: green; font-weight: bold;")
            other_layout.addWidget(privilege_label)
        
        return other_group
    
    def _create_port_options(self):
        """Create port options layout"""
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Ports:"))
        
        self.port_input = QLineEdit("80,443,22,21,23,25")
        self.port_input.setPlaceholderText("e.g., 80,443,22 or 1-1000")
        port_layout.addWidget(self.port_input)
        
        self.use_common_ports = QCheckBox("Use common ports")
        self.use_common_ports.setChecked(True)
        port_layout.addWidget(self.use_common_ports)
        
        return port_layout
    
    def get_scan_types(self):
        """Get selected scan types"""
        scan_types = []
        
        # Basic scan types
        if self.syn_scan_cb.isChecked():
            scan_types.append('syn_scan')
        if self.tcp_connect_cb.isChecked():
            scan_types.append('tcp_connect')
        if self.udp_scan_cb.isChecked():
            scan_types.append('udp_scan')
        if self.enhanced_udp_cb.isChecked():
            scan_types.append('enhanced_udp')
        if self.advanced_tcp_cb.isChecked():
            scan_types.append('advanced_tcp')
            
        # Advanced scan types
        if self.parallel_cb.isChecked():
            scan_types.append('parallel')
        if self.stealth_cb.isChecked():
            scan_types.append('stealth')
        if self.adaptive_cb.isChecked():
            scan_types.append('adaptive')
            
        # Host discovery
        if self.host_discovery_cb.isChecked():
            scan_types.append('host_discovery')
        if self.icmp_echo_cb.isChecked():
            scan_types.append('icmp_echo')
        if self.icmp_timestamp_cb.isChecked():
            scan_types.append('icmp_timestamp')
        if self.icmp_address_mask_cb.isChecked():
            scan_types.append('icmp_address_mask')
        if self.icmp_info_cb.isChecked():
            scan_types.append('icmp_info')
        if self.comprehensive_icmp_cb.isChecked():
            scan_types.append('comprehensive_icmp')
        if self.tcp_syn_ping_cb.isChecked():
            scan_types.append('tcp_syn_ping')
        if self.enhanced_tcp_syn_cb.isChecked():
            scan_types.append('enhanced_tcp_syn')
        if self.udp_ping_cb.isChecked():
            scan_types.append('udp_ping')
        if self.arp_ping_cb.isChecked():
            scan_types.append('arp_ping')
        if self.advanced_discovery_cb.isChecked():
            scan_types.append('advanced_discovery')
            
        return scan_types
    
    def _update_timing_info(self, timing_name):
        """Update timing information display"""
        from src.timing import TIMING_TEMPLATES
        
        config = TIMING_TEMPLATES.get(timing_name, TIMING_TEMPLATES["normal"])
        info_text = f"Timeout: {config['timeout']}s | Delay: {config['delay']}s | Threads: {config['max_threads']}"
        self.timing_info_label.setText(info_text)
        self.timing_info_label.setStyleSheet("color: gray; font-size: 9px;")
