import socket

def _detect_service(ip, port, protocol="tcp", timeout=3):
    """
    Basic service detection based on port number và banner grabbing
    """
    # Common service mappings
    tcp_services = {
        20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 143: "imap", 443: "https",
        993: "imaps", 995: "pop3s", 139: "netbios-ssn", 445: "microsoft-ds",
        3389: "ms-wbt-server", 5900: "vnc", 6000: "x11", 8080: "http-proxy"
    }
    
    udp_services = {
        53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 123: "ntp",
        161: "snmp", 162: "snmp-trap", 514: "syslog", 1434: "mssql"
    }
    
    if protocol == "tcp":
        service_name = tcp_services.get(port, f"unknown-{port}")
        
        # Try banner grabbing for common services
        if port in [21, 22, 23, 25, 80, 110, 143]:
            banner = _grab_banner(ip, port, timeout)
            if banner:
                return f"{service_name} ({banner[:30]}...)" if len(banner) > 30 else f"{service_name} ({banner})"
        
        return service_name
    
    elif protocol == "udp":
        return udp_services.get(port, f"unknown-{port}")
    
    return "unknown"


def _grab_banner(ip, port, timeout=3):
    """
    Grab service banner từ open port
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Send appropriate request based on port
        if port == 80 or port == 8080:
            sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port == 21:
            pass  # FTP sends banner immediately
        elif port == 22:
            pass  # SSH sends banner immediately
        elif port == 25:
            pass  # SMTP sends banner immediately
        
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        # Clean up banner
        if banner:
            banner = banner.replace('\r', '').replace('\n', ' ')
            return banner[:100]  # Limit length
        
    except Exception:
        pass
    
    return None