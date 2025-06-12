"""
Results Display Components
"""
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QTextEdit, QLabel
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor


class ResultsDisplayWidget(QWidget):
    """Widget for displaying scan results"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
    
    def init_ui(self):
        layout = QHBoxLayout(self)
        
        # Port Scan Results
        port_results_widget = QWidget()
        port_results_layout = QVBoxLayout(port_results_widget)
        
        # OS Detection results
        self.os_result_label = QLabel("OS: Not detected")
        self.os_result_label.setStyleSheet("font-weight: bold; font-size: 12px;")
        port_results_layout.addWidget(self.os_result_label)
        
        # Port scan results table
        port_results_layout.addWidget(QLabel("Port Scan Results:"))
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["Port", "Protocol", "State", "Details"])
        self.results_table.setColumnWidth(0, 80)
        self.results_table.setColumnWidth(1, 80)
        self.results_table.setColumnWidth(2, 80)
        self.results_table.setColumnWidth(3, 130)
        
        port_results_layout.addWidget(self.results_table)
        
        # Host Discovery Results
        host_discovery_widget = QWidget()
        host_discovery_layout = QVBoxLayout(host_discovery_widget)
        
        host_discovery_layout.addWidget(QLabel("Host Discovery Results:"))
        self.host_discovery_table = QTableWidget()
        self.host_discovery_table.setColumnCount(3)
        self.host_discovery_table.setHorizontalHeaderLabels(["Method", "Status", "Details"])
        self.host_discovery_table.setColumnWidth(0, 130)
        self.host_discovery_table.setColumnWidth(1, 80)
        self.host_discovery_table.setColumnWidth(2, 160)
        
        host_discovery_layout.addWidget(self.host_discovery_table)
        
        # Log output
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(300)
        font = QFont("Courier", 9)
        self.log_output.setFont(font)
        
        # Add widgets to main layout
        layout.addWidget(port_results_widget, 1)
        layout.addWidget(host_discovery_widget, 1)
        layout.addWidget(self.log_output, 1)
    
    def add_result(self, port, port_num, status, protocol, extra_info):
        """Add a port scan result"""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        self.results_table.setItem(row, 0, QTableWidgetItem(str(port)))
        self.results_table.setItem(row, 1, QTableWidgetItem(protocol))
        self.results_table.setItem(row, 2, QTableWidgetItem(status))
        self.results_table.setItem(row, 3, QTableWidgetItem(extra_info))
        
        # Color code the status
        color = self._get_status_color(status)
        if color:
            for col in range(4):
                item = self.results_table.item(row, col)
                item.setBackground(color)
    
    def add_host_discovery_result(self, method, result, details):
        """Add a host discovery result"""
        row = self.host_discovery_table.rowCount()
        self.host_discovery_table.insertRow(row)
        
        self.host_discovery_table.setItem(row, 0, QTableWidgetItem(method))
        self.host_discovery_table.setItem(row, 1, QTableWidgetItem("UP" if result else "DOWN"))
        self.host_discovery_table.setItem(row, 2, QTableWidgetItem(details))
        
        # Color code the result
        color = QColor("#198754") if result else QColor("#dc3545")  # Bootstrap success/danger
        for col in range(3):
            item = self.host_discovery_table.item(row, col)
            item.setBackground(color)
    
    def add_log(self, message):
        """Add a log message"""
        self.log_output.append(message)
    
    def update_os_result(self, os_result):
        """Update OS detection result"""
        os_text = f"OS: {os_result['os']} (Confidence: {os_result['confidence']}%)"
        if os_result['details']['ttl']:
            os_text += f" | TTL: {os_result['details']['ttl']}"
        if os_result['details']['window_size']:
            os_text += f" | Window: {os_result['details']['window_size']}"
        
        self.os_result_label.setText(os_text)
        
        # Color code based on confidence
        if os_result['confidence'] >= 80:
            self.os_result_label.setStyleSheet("font-weight: bold; font-size: 12px; color: green;")
        elif os_result['confidence'] >= 60:
            self.os_result_label.setStyleSheet("font-weight: bold; font-size: 12px; color: orange;")
        else:
            self.os_result_label.setStyleSheet("font-weight: bold; font-size: 12px; color: red;")
    
    def clear_results(self):
        """Clear all results"""
        self.results_table.setRowCount(0)
        self.host_discovery_table.setRowCount(0)
        self.log_output.clear()
        self.os_result_label.setText("OS: Not detected")
    
    def _get_status_color(self, status):
        """Get color for status"""
        status_colors = {
            "OPEN": QColor("#198754"),      # Bootstrap success green
            "CLOSED": QColor("#ffc107"),    # Bootstrap warning yellow
            "FILTERED": QColor("#0dcaf0"),  # Bootstrap info cyan
            "ERROR": QColor("#dc3545"),     # Bootstrap danger red
            "SCANNED": QColor("#6c757d")    # Bootstrap secondary gray
        }
        return status_colors.get(status.upper())
