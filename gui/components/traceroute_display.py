"""
Traceroute Display Components - Zenmap-style traceroute visualization
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QTextEdit, QLabel, QPushButton, QLineEdit, QSpinBox, QComboBox,
    QProgressBar, QGroupBox, QGraphicsView, QGraphicsScene, QGraphicsEllipseItem,
    QGraphicsLineItem, QGraphicsTextItem
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QPointF
from PyQt5.QtGui import QFont, QColor, QPen, QBrush, QPainter

from src.traceroute import traceroute, TracerouteResult, TracerouteHop


class TracerouteWorker(QThread):
    """Worker thread for traceroute operations"""
    
    hop_signal = pyqtSignal(object)  # TracerouteHop
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(object)  # TracerouteResult
    progress_signal = pyqtSignal(int)
    
    def __init__(self, target, max_hops=30, timeout=5, method="auto"):
        super().__init__()
        self.target = target
        self.max_hops = max_hops
        self.timeout = timeout
        self.method = method
        self.running = True
    
    def run(self):
        self.log_signal.emit(f"[+] Starting traceroute to {self.target}")
        self.log_signal.emit(f"[+] Max hops: {self.max_hops}, Timeout: {self.timeout}s, Method: {self.method}")
        
        try:
            result = traceroute(self.target, self.max_hops, self.timeout, self.method)
            
            # Emit hops as they're processed
            for i, hop in enumerate(result.hops):
                if not self.running:
                    break
                self.hop_signal.emit(hop)
                progress = int((i + 1) / len(result.hops) * 100)
                self.progress_signal.emit(progress)
            
            self.finished_signal.emit(result)
            
            if result.success:
                self.log_signal.emit(f"[+] Traceroute completed in {result.get_duration():.1f} seconds")
            else:
                self.log_signal.emit(f"[!] Traceroute failed: {result.error_message}")
                
        except Exception as e:
            self.log_signal.emit(f"[!] Traceroute error: {e}")
    
    def stop(self):
        self.running = False


class TracerouteTable(QTableWidget):
    """Table widget for displaying traceroute hops"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_table()
    
    def setup_table(self):
        """Setup table structure"""
        self.setColumnCount(6)
        self.setHorizontalHeaderLabels(["Hop", "IP Address", "Hostname", "RTT 1", "RTT 2", "RTT 3"])
        
        # Set column widths
        self.setColumnWidth(0, 50)   # Hop
        self.setColumnWidth(1, 120)  # IP
        self.setColumnWidth(2, 180)  # Hostname
        self.setColumnWidth(3, 80)   # RTT 1
        self.setColumnWidth(4, 80)   # RTT 2
        self.setColumnWidth(5, 80)   # RTT 3
        
        # Set font
        font = QFont("Courier", 9)
        self.setFont(font)
    
    def add_hop(self, hop: TracerouteHop):
        """Add a hop to the table"""
        row = self.rowCount()
        self.insertRow(row)
        
        # Hop number
        self.setItem(row, 0, QTableWidgetItem(str(hop.hop_num)))
        
        # IP Address
        ip_item = QTableWidgetItem(hop.ip or "*")
        if hop.status == "fast":
            ip_item.setBackground(QColor("#198754"))  # Green
        elif hop.status == "normal":
            ip_item.setBackground(QColor("#ffc107"))  # Yellow
        elif hop.status == "slow":
            ip_item.setBackground(QColor("#fd7e14"))  # Orange
        elif hop.status == "very_slow":
            ip_item.setBackground(QColor("#dc3545"))  # Red
        else:
            ip_item.setBackground(QColor("#6c757d"))  # Gray
        
        self.setItem(row, 1, ip_item)
        
        # Hostname
        hostname = hop.hostname if hop.hostname and hop.hostname != hop.ip else ""
        self.setItem(row, 2, QTableWidgetItem(hostname))
        
        # RTTs
        for i, rtt in enumerate([hop.rtt1, hop.rtt2, hop.rtt3]):
            rtt_text = f"{rtt:.1f} ms" if rtt is not None else "*"
            rtt_item = QTableWidgetItem(rtt_text)
            
            # Color code RTT
            if rtt is not None:
                if rtt < 10:
                    rtt_item.setBackground(QColor("#198754"))  # Fast - Green
                elif rtt < 50:
                    rtt_item.setBackground(QColor("#ffc107"))  # Normal - Yellow
                elif rtt < 200:
                    rtt_item.setBackground(QColor("#fd7e14"))  # Slow - Orange
                else:
                    rtt_item.setBackground(QColor("#dc3545"))  # Very slow - Red
            
            self.setItem(row, 3 + i, rtt_item)
        
        # Auto-scroll to bottom
        self.scrollToBottom()
    
    def clear_hops(self):
        """Clear all hops from table"""
        self.setRowCount(0)


class TracerouteGraphView(QGraphicsView):
    """Graphical view of traceroute path"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene()
        self.setScene(self.scene)
        self.hops = []
        self.setup_view()
    
    def setup_view(self):
        """Setup graphics view"""
        self.setMinimumHeight(200)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setRenderHint(QPainter.Antialiasing)
    
    def add_hop(self, hop: TracerouteHop):
        """Add a hop to the graph"""
        self.hops.append(hop)
        self.redraw_graph()
    
    def redraw_graph(self):
        """Redraw the entire graph"""
        self.scene.clear()
        
        if not self.hops:
            return
        
        # Calculate positions
        width = max(600, len(self.hops) * 80)
        height = 150
        self.scene.setSceneRect(0, 0, width, height)
        
        x_step = width / (len(self.hops) + 1)
        y_center = height / 2
        
        prev_pos = None
        
        for i, hop in enumerate(self.hops):
            x = (i + 1) * x_step
            y = y_center
            
            # Draw hop node
            color = self._get_hop_color(hop)
            brush = QBrush(color)
            pen = QPen(Qt.black, 2)
            
            radius = 15
            if hop.ip:
                circle = self.scene.addEllipse(x - radius, y - radius, radius * 2, radius * 2, pen, brush)
            else:
                # Timeout - draw X
                self.scene.addLine(x - radius, y - radius, x + radius, y + radius, pen)
                self.scene.addLine(x - radius, y + radius, x + radius, y - radius, pen)
            
            # Draw hop number
            text = self.scene.addText(str(hop.hop_num), QFont("Arial", 8))
            text.setPos(x - 8, y - radius - 20)
            
            # Draw IP address
            if hop.ip:
                ip_text = self.scene.addText(hop.ip, QFont("Arial", 7))
                ip_text.setPos(x - 30, y + radius + 5)
            
            # Draw RTT
            if hop.avg_rtt is not None:
                rtt_text = f"{hop.avg_rtt:.1f}ms"
                rtt_item = self.scene.addText(rtt_text, QFont("Arial", 7))
                rtt_item.setPos(x - 20, y + radius + 20)
            
            # Draw line to previous hop
            if prev_pos and hop.ip:
                line_pen = QPen(Qt.blue, 2)
                self.scene.addLine(prev_pos[0] + radius, prev_pos[1], x - radius, y, line_pen)
            
            if hop.ip:
                prev_pos = (x, y)
    
    def _get_hop_color(self, hop: TracerouteHop) -> QColor:
        """Get color for hop based on status"""
        if hop.status == "fast":
            return QColor("#198754")  # Green
        elif hop.status == "normal":
            return QColor("#ffc107")  # Yellow
        elif hop.status == "slow":
            return QColor("#fd7e14")  # Orange
        elif hop.status == "very_slow":
            return QColor("#dc3545")  # Red
        else:
            return QColor("#6c757d")  # Gray
    
    def clear_graph(self):
        """Clear the graph"""
        self.hops.clear()
        self.scene.clear()


class TracerouteDisplayWidget(QWidget):
    """Main traceroute display widget"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.traceroute_worker = None
        self.current_result = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout(self)
        
        # Control panel
        control_group = QGroupBox("Traceroute Controls")
        control_layout = QHBoxLayout(control_group)
        
        # Target input
        control_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit("8.8.8.8")
        self.target_input.setPlaceholderText("IP address or hostname")
        control_layout.addWidget(self.target_input)
        
        # Max hops
        control_layout.addWidget(QLabel("Max Hops:"))
        self.max_hops_spin = QSpinBox()
        self.max_hops_spin.setRange(1, 64)
        self.max_hops_spin.setValue(30)
        control_layout.addWidget(self.max_hops_spin)
        
        # Timeout
        control_layout.addWidget(QLabel("Timeout:"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 30)
        self.timeout_spin.setValue(5)
        self.timeout_spin.setSuffix(" sec")
        control_layout.addWidget(self.timeout_spin)
        
        # Method
        control_layout.addWidget(QLabel("Method:"))
        self.method_combo = QComboBox()
        self.method_combo.addItems(["auto", "system", "icmp", "udp"])
        control_layout.addWidget(self.method_combo)
        
        # Start/Stop buttons
        self.start_button = QPushButton("Start Traceroute")
        self.start_button.clicked.connect(self.start_traceroute)
        control_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_traceroute)
        self.stop_button.setEnabled(False)
        control_layout.addWidget(self.stop_button)
        
        layout.addWidget(control_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Results area
        results_layout = QHBoxLayout()
        
        # Left side - Table view
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.addWidget(QLabel("Hop Details:"))
        
        self.hop_table = TracerouteTable()
        left_layout.addWidget(self.hop_table)
        
        # Summary info
        self.summary_label = QLabel("Ready to trace")
        self.summary_label.setStyleSheet("font-weight: bold; padding: 5px;")
        left_layout.addWidget(self.summary_label)
        
        results_layout.addWidget(left_widget, 1)
        
        # Right side - Graph view and log
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        right_layout.addWidget(QLabel("Route Visualization:"))
        self.graph_view = TracerouteGraphView()
        right_layout.addWidget(self.graph_view, 1)
        
        right_layout.addWidget(QLabel("Log Output:"))
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(150)
        self.log_output.setFont(QFont("Courier", 9))
        right_layout.addWidget(self.log_output)
        
        results_layout.addWidget(right_widget, 1)
        
        layout.addLayout(results_layout)
    
    def start_traceroute(self):
        """Start traceroute operation"""
        target = self.target_input.text().strip()
        if not target:
            self.log_output.append("[!] Please enter a target")
            return
        
        # Clear previous results
        self.hop_table.clear_hops()
        self.graph_view.clear_graph()
        self.log_output.clear()
        
        # Setup UI for running state
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # Start worker thread
        max_hops = self.max_hops_spin.value()
        timeout = self.timeout_spin.value()
        method = self.method_combo.currentText()
        
        self.traceroute_worker = TracerouteWorker(target, max_hops, timeout, method)
        self.traceroute_worker.hop_signal.connect(self.add_hop)
        self.traceroute_worker.log_signal.connect(self.add_log)
        self.traceroute_worker.finished_signal.connect(self.traceroute_finished)
        self.traceroute_worker.progress_signal.connect(self.progress_bar.setValue)
        self.traceroute_worker.start()
    
    def stop_traceroute(self):
        """Stop traceroute operation"""
        if self.traceroute_worker:
            self.traceroute_worker.stop()
            self.traceroute_worker.wait(3000)  # Wait up to 3 seconds
        
        self.traceroute_finished(None)
    
    def add_hop(self, hop: TracerouteHop):
        """Add a hop to displays"""
        self.hop_table.add_hop(hop)
        self.graph_view.add_hop(hop)
        
        # Update summary
        if hop.ip:
            self.summary_label.setText(f"Hop {hop.hop_num}: {hop.ip}")
    
    def add_log(self, message: str):
        """Add log message"""
        self.log_output.append(message)
    
    def traceroute_finished(self, result: TracerouteResult):
        """Handle traceroute completion"""
        # Reset UI state
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        
        if result:
            self.current_result = result
            
            # Update summary
            if result.success:
                final_hop = result.get_final_hop()
                if final_hop:
                    reached = result.reached_destination()
                    status = "Reached destination" if reached else "Max hops reached"
                    self.summary_label.setText(
                        f"{status} - {len(result.hops)} hops, "
                        f"{result.get_duration():.1f}s total"
                    )
                else:
                    self.summary_label.setText("No route found")
            else:
                self.summary_label.setText(f"Failed: {result.error_message}")
        else:
            self.summary_label.setText("Traceroute stopped")
        
        self.traceroute_worker = None
    
    def get_traceroute_result(self) -> TracerouteResult:
        """Get current traceroute result"""
        return self.current_result


if __name__ == "__main__":
    from PyQt5.QtWidgets import QApplication
    import sys
    
    app = QApplication(sys.argv)
    widget = TracerouteDisplayWidget()
    widget.show()
    sys.exit(app.exec_())
