#!/usr/bin/env python3

import sys
import os
import subprocess
from PyQt5.QtWidgets import QApplication, QMessageBox

def check_root_privileges():
    return os.geteuid() == 0

def restart_with_sudo():
    try:
        script_path = os.path.abspath(__file__)
        python_path = sys.executable
        
        subprocess.run(['sudo', python_path, script_path], check=True)
        return True
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError:
        return False

def show_privilege_dialog():
    app = QApplication(sys.argv)
    
    msg = QMessageBox()
    msg.setWindowTitle("SuperSimpleScanner - Privilege Required")
    msg.setIcon(QMessageBox.Question)
    msg.setText("Some scan types (SYN scan, ICMP ping, OS detection) require root privileges.")
    msg.setInformativeText("Do you want to restart with sudo to enable all features?")
    msg.setDetailedText(
        "Features requiring root:\n"
        "• SYN Scan (-sS)\n"
        "• ICMP Echo/Timestamp/Address Mask Ping\n"
        "• Comprehensive ICMP Ping\n"
        "• OS Detection\n"
        "• Stealth and Advanced scans\n\n"
        "Features available without root:\n"
        "• TCP Connect Scan (-sT)\n"
        "• UDP Scan (-sU)\n"
        "• Host Discovery (limited)\n"
        "• ARP Ping (local network only)"
    )
    
    msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
    msg.setDefaultButton(QMessageBox.Yes)
    
    choice = msg.exec_()
    app.quit()
    
    return choice == QMessageBox.Yes

def main():
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    
    if not check_root_privileges():
        print("[!] Warning: Not running as root")
        print("    Some scan types will be unavailable (SYN scan, ICMP ping, OS detection)")
        print("    Run with 'sudo python3 gui_launcher.py' for full functionality")
        
        if 'DISPLAY' in os.environ:
            try:
                if show_privilege_dialog():
                    print("[+] Restarting with sudo...")
                    if restart_with_sudo():
                        return
                    else:
                        print("[!] Failed to restart with sudo")
                        print("    Please run manually: sudo python3 gui_launcher.py")
                        return
                else:
                    print("[+] Continuing without root privileges")
            except Exception as e:
                print(f"[!] Error showing dialog: {e}")
                print("[+] Continuing without root privileges")
    else:
        print("[+] Running with root privileges - all features available")
    
    try:
        from gui.scanner_gui import main as gui_main
        gui_main()
    except ImportError as e:
        print(f"[!] Error importing GUI: {e}")
        print("    Make sure PyQt5 is installed: pip install PyQt5")
    except Exception as e:
        print(f"[!] Error starting GUI: {e}")

if __name__ == "__main__":
    main()
