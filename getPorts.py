import socket
import concurrent.futures
import time

# Default service lookup from the system's /etc/services file
def get_service(port):
    try:
        # First try to get the service name using socket.getservbyport
        return socket.getservbyport(port, 'tcp')
    except:
        # If the service is not found, return 'Unknown Port'
        return 'Unknown Port'

# Scan a single port for a given target IP
def scan_port(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Increase timeout to handle slow responses
        result = sock.connect_ex((target_ip, port))  # Return 0 if connection is successful
        if result == 0:
            service = get_service(port)
            return {
                'port': port,
                'state': 'open',
                'service': service
            }
        sock.close()
    except (socket.error, TimeoutError):
        return None

# Scan multiple ports concurrently using ThreadPoolExecutor
def scan_ports(target_ip, port_range=(1, 10000)):
    port_info = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:  # Using up to 100 threads
        futures = []
        for port in range(port_range[0], port_range[1]):  # Scan the range of ports
            futures.append(executor.submit(scan_port, target_ip, port))
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                port_info.append(result)

    return port_info

# Display the results in a formatted table
def scan_port_withServices(target_ip):
    print(f"Starting scan on {target_ip}...\n")
    print(f"{'PORT':<10} {'STATE':<10} SERVICE")

    start_time = time.time()
    port_info = scan_ports(target_ip)  # Get detailed port info
    scan_duration = time.time() - start_time

    # Display each port with state and service
    for info in port_info:
        print(f"{info['port']}/tcp".ljust(10), info['state'].ljust(10), info['service'])

    print(f"\nScan completed in {scan_duration:.2f} seconds.")

if __name__ == "__main__":
    target_ip = input("Enter IP address: ")
    scan_port_withServices(target_ip)
