# Importing necessary modules
import socket # For low-level networking (TCP/UDP socket operations)
import concurrent.futures # For parallel (multithreaded) port scanning
import json # For loading IANA service-port mappings

# Load the IANA services JSON file into a Python dictionary
with open("iana_services.json") as f:
    IANA_SERVICES = json.load(f)  # Format: {"80/tcp": "http", "53/udp": "dns", ...}

# Function to get the service name from IANA list based on port and protocol
def get_service(port, protocol):
    key = f"{port}/{protocol}" # Example: "80/tcp"
    return IANA_SERVICES.get(key, "Unknown") # Return matched service or "Unknown" if not found

# Scan a TCP port on a given IP
def scan_tcp_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:  # Create a TCP socket
            sock.settimeout(0.5) # Set timeout to 0.5 seconds to avoid hanging
            result = sock.connect_ex((ip, port))  # Try to connect to IP:port; returns 0 if successful
            if result == 0: # Port is open
                return {
                    "port": port,
                    "state": "open",
                    "protocol": "tcp",
                    "service": get_service(port, "tcp")  # Match service name from IANA list
                }
    except:
        return None  # On exception, skip this port

# Scan a UDP port on a given IP
def scan_udp_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock: # Create a UDP socket
            sock.settimeout(0.5)
            sock.sendto(b"", (ip, port)) # Send empty packet
            sock.recvfrom(1024)  # Try to receive response (not always reliable)
            return {
                "port": port,
                "state": "open",
                "protocol": "udp",
                "service": get_service(port, "udp") # Match service name
            }
    except:
        return None  # Treat as closed or filtered if no response or error

# Function to scan both TCP and UDP ports within a specified range on a given IP
def scan_ports(ip, port_range=(1, 1000)):
    open_ports = [] # List to collect results
    # Use ThreadPoolExecutor to scan multiple ports concurrently for faster performance
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        # Submit TCP scan jobs
        tcp_futures = [executor.submit(scan_tcp_port, ip, port) for port in range(port_range[0], port_range[1]+1)]
        # Submit UDP scan jobs
        udp_futures = [executor.submit(scan_udp_port, ip, port) for port in range(port_range[0], port_range[1]+1)]
    # Process results as soon as each future completes
        for future in concurrent.futures.as_completed(tcp_futures + udp_futures):
            result = future.result()
            if result: # If port is open and scan successful
                open_ports.append(result)
    return open_ports # Return all open port info

# Function to display scan results in formatted table
def display_ports(ports):
    if not ports:
        print("No open ports found.")
        return
    # Print table headers
    print(f"\n{'Port':<8}{'State':<10}{'Protocol':<10}{'Service'}")
    # Print each port's information in sorted order
    for p in sorted(ports, key=lambda x: (x['port'], x['protocol'])):
        print(f"{p['port']:<8}{p['state']:<10}{p['protocol']:<10}{p['service']}")

# If this script is run directly (not imported)
if __name__ == "__main__":
    ip = input("Enter IP to scan: ").strip() # Get target IP address from user
    ports = scan_ports(ip, (1, 10000))  # Scan ports 1 to 10000; you can adjust range
    display_ports(ports) # Show formatted results
