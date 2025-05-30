import socket

# Default service lookup from the system's /etc/services file
def get_service(port):
    try:
        # First try to get the service name using socket.getservbyport
        return socket.getservbyport(port, 'tcp')
    except:
        # If the service is not found, return 'Unknown Port'
        return 'Unknown Port'

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
