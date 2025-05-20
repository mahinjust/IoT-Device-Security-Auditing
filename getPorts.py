import socket

# Custom service mapping for known IoT ports
PORT_SERVICE_MAPPING = {
    80: "http",
    443: "https",
    554: "rtsp",
    8000: "http",
    8008: "http",
    8080: "http",
    8081: "http",
    8082: "http",
    8883: "mqtt",
    5228: "gcm",
    5678: "http",
    9100: "ipp",
    515: "printer",
    631: "ipp",
    1883: "mqtt",
    7000: "upnp",
    1900: "upnp",
    2020: "unknown_service",  # Added mapping for your unknown port
    9999: "unknown_service"  # Added mapping for your unknown port
}

def scan_ports(target_ip):
    port_info = []
    for port in range(1, 10000):  # or 65536 for full range
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.01)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                service = get_service(port)
                port_info.append({
                    'port': port,
                    'state': 'open',
                    'service': service
                })
            sock.close()
        except:
            pass
    return port_info

def get_service(port):
    # Check custom mapping first
    if port in PORT_SERVICE_MAPPING:
        return PORT_SERVICE_MAPPING[port]
    
    # Default socket lookup
    try:
        return socket.getservbyport(port, 'tcp')
    except:
        return 'Unknown Port'

def scan_port_withServices(target_ip):
    print(f"Starting scan on {target_ip}...\n")
    print(f"{'PORT':<10} {'STATE':<10} SERVICE")
    
    port_info = scan_ports(target_ip)  # Get detailed port info
    
    # Display each port with state and service
    for info in port_info:
        print(f"{info['port']}/tcp".ljust(10), info['state'].ljust(10), info['service'])

    print("\nScan completed.")

if __name__ == "__main__":
    target_ip = input("Enter IP address: ")
    scan_port_withServices(target_ip)
