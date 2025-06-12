"""
Scanner GUI Entry Point
"""
import sys
from PyQt5.QtWidgets import QApplication

from gui.main_scanner_window import NetworkScannerGUI


def main():
    """Main entry point for GUI"""
    app = QApplication(sys.argv)
    window = NetworkScannerGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
