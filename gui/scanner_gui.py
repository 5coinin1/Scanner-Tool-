import sys
import os
from PyQt5.QtWidgets import QApplication

from gui.main_scanner_window import NetworkScannerGUI

if not os.environ.get('XDG_RUNTIME_DIR'):
    os.environ['XDG_RUNTIME_DIR'] = '/tmp/runtime-' + str(os.getuid())

os.environ['QT_QPA_PLATFORM'] = 'xcb'
os.environ['XDG_SESSION_TYPE'] = 'x11'
os.environ['SESSION_MANAGER'] = ''

def main():
    app = QApplication(sys.argv)
    window = NetworkScannerGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
