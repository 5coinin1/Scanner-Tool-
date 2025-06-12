import socket
import re

# Common port ranges and service groups
COMMON_PORT_RANGES = {
    'top100': [80, 443, 22, 21, 23, 25, 53, 110, 111, 143, 993, 995, 1723, 3306, 3389, 5900, 8080, 135, 139, 445, 1433, 1521, 3268, 389, 636, 88, 464, 593, 5985, 9389, 47001, 49664, 49665, 49666, 49667, 49668, 49669, 49670, 5432, 1521, 27017, 6379, 11211, 5984, 9200, 9300, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 7000, 7001, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8443, 8888, 9000, 9001, 9080, 9090, 9443, 10000, 10001, 10080, 161, 162, 69, 123, 137, 138, 67, 68, 546, 547, 514, 520, 1812, 1813, 1194, 500, 4500, 1701, 1723, 5060, 5061],
    'top1000': list(range(1, 1001)),
    'well-known': list(range(1, 1024)),
    'registered': list(range(1024, 49152)),
    'dynamic': list(range(49152, 65536)),
    'all': list(range(1, 65536)),
    'web': [80, 443, 8080, 8443, 8000, 8888, 9000, 9080, 9443],
    'mail': [25, 110, 143, 465, 587, 993, 995],
    'database': [1433, 1521, 3306, 5432, 27017, 6379],
    'remote': [22, 23, 3389, 5900, 5901, 5902],
    'dns': [53],
    'ftp': [20, 21],
    'common-udp': [53, 67, 68, 69, 123, 161, 162, 500, 514, 1194, 1434, 1812, 1813, 4500, 5060, 5061]
}

# Protocol-specific service mappings  
TCP_SERVICES = {
    'http': 80, 'https': 443, 'ssh': 22, 'telnet': 23, 'ftp': 21, 'smtp': 25,
    'pop3': 110, 'imap': 143, 'dns': 53, 'mysql': 3306, 'postgres': 5432,
    'rdp': 3389, 'vnc': 5900, 'redis': 6379, 'mongodb': 27017
}

UDP_SERVICES = {
    'dns': 53, 'dhcp': 67, 'tftp': 69, 'ntp': 123, 'snmp': 161, 'syslog': 514
}

def validate_port(port):
    """Validate if port number is in valid range"""
    try:
        port_num = int(port)
        if 1 <= port_num <= 65535:
            return port_num
        else:
            raise ValueError(f"Port {port_num} out of range (1-65535)")
    except ValueError as e:
        raise ValueError(f"Invalid port: {port} - {e}")

def resolve_service_name(service_name, protocol="tcp"):
    """Resolve service name to port number"""
    service_name = service_name.lower()
    
    # Check our custom mappings first
    if protocol.lower() == "tcp" and service_name in TCP_SERVICES:
        return TCP_SERVICES[service_name]
    elif protocol.lower() == "udp" and service_name in UDP_SERVICES:
        return UDP_SERVICES[service_name]
    
    # Try system service resolution
    try:
        if protocol.lower() == "tcp":
            return socket.getservbyname(service_name, "tcp")
        elif protocol.lower() == "udp":
            return socket.getservbyname(service_name, "udp")
        else:
            return socket.getservbyname(service_name)
    except OSError:
        raise ValueError(f"Unknown service name: {service_name}")

def expand_port_range(range_str):
    """Expand port range string to list of ports"""
    if '-' not in range_str:
        return [validate_port(range_str)]
    
    # Handle special case of just "-" meaning all ports
    if range_str.strip() == "-":
        return list(range(1, 65536))
    
    # Parse range like "80-443" or "-1000" or "1000-"
    parts = range_str.split('-', 1)
    
    if range_str.startswith('-'):  # "-1000"
        start = 1
        end = validate_port(parts[1]) if parts[1] else 65535
    elif range_str.endswith('-'):  # "1000-"
        start = validate_port(parts[0])
        end = 65535
    else:  # "80-443"
        start = validate_port(parts[0]) if parts[0] else 1
        end = validate_port(parts[1]) if parts[1] else 65535
    
    if start > end:
        raise ValueError(f"Invalid range: {range_str} (start > end)")
    
    return list(range(start, end + 1))

def parse_ports(port_str):
    """
    Enhanced port parsing with support for:
    - Individual ports: 80,443,22
    - Port ranges: 80-443, -1000, 1000-
    - Service names: http,https,ssh
    - Protocol prefixes: T:80,443 U:53,123
    - Special ranges: top100, web, mail, etc.
    - Mixed formats: T:80-443,U:dns,web
    
    Returns: (tcp_ports_list, udp_ports_list)
    """
    tcp_ports = set()
    udp_ports = set()
    current_protocol = "tcp"  # Default to TCP
    
    if not port_str or not port_str.strip():
        return [], []
    
    port_str = port_str.strip()
    
    # Handle special case of all ports
    if port_str == "-":
        tcp_ports.update(range(1, 65536))
        return sorted(tcp_ports), sorted(udp_ports)
    
    # Split by comma and process each part
    parts = [part.strip() for part in port_str.split(',') if part.strip()]
    
    for part in parts:
        try:
            # Check for protocol prefix (T:, U:, S:)
            if ':' in part and len(part) > 2:
                prefix = part[:2].upper()
                if prefix in ['T:', 'U:', 'S:']:
                    if prefix == 'T:':
                        current_protocol = "tcp"
                    elif prefix == 'U:':
                        current_protocol = "udp"
                    elif prefix == 'S:':
                        current_protocol = "sctp"  # For future use
                    part = part[2:]
            
            # Handle common port range names
            if part.lower() in COMMON_PORT_RANGES:
                ports = COMMON_PORT_RANGES[part.lower()]
            # Handle port ranges
            elif '-' in part:
                ports = expand_port_range(part)
            # Handle single port or service name
            else:
                try:
                    # Try as port number first
                    ports = [validate_port(part)]
                except ValueError:
                    # Try as service name
                    try:
                        port_num = resolve_service_name(part, current_protocol)
                        ports = [port_num]
                    except ValueError as e:
                        print(f"[!] {e}")
                        continue
            
            # Add ports to appropriate set
            if current_protocol == "tcp":
                tcp_ports.update(ports)
            elif current_protocol == "udp":
                udp_ports.update(ports)
            # Note: SCTP support can be added in the future
                
        except ValueError as e:
            print(f"[!] Error parsing '{part}': {e}")
            continue
        except Exception as e:
            print(f"[!] Unexpected error parsing '{part}': {e}")
            continue
    
    return sorted(list(tcp_ports)), sorted(list(udp_ports))

def get_common_ports(category="top100"):
    """Get common ports by category"""
    return COMMON_PORT_RANGES.get(category.lower(), [])

def format_port_list(ports, max_display=10):
    """Format port list for display with optional truncation"""
    if not ports:
        return "None"
    
    if len(ports) <= max_display:
        return ",".join(map(str, ports))
    else:
        displayed = ",".join(map(str, ports[:max_display]))
        return f"{displayed}... (+{len(ports) - max_display} more)"

def port_to_service(port, protocol="tcp"):
    """Convert port number to service name if known"""
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        # Check our custom mappings
        if protocol == "tcp":
            for service, port_num in TCP_SERVICES.items():
                if port_num == port:
                    return service
        elif protocol == "udp":
            for service, port_num in UDP_SERVICES.items():
                if port_num == port:
                    return service
        return f"unknown-{port}"

def validate_port_string(port_str):
    """Validate port string format before parsing"""
    if not port_str or not isinstance(port_str, str):
        return False, "Port string cannot be empty"
    
    # Allow more characters for service names and ranges
    invalid_chars = set('@#$%^&*()+=[]{}|\\;\'\"<>?/~`')
    if any(c in invalid_chars for c in port_str):
        return False, "Invalid characters in port string"
    
    return True, "Valid"

