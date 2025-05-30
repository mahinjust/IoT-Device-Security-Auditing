import os
import socket
import struct
import netifaces
import allIP
import findMacAddress
import findVendor
import getPorts
import getOS
import getDeviceType

def format_ports(ports):
    # Create a formatted string for displaying table headers and port details
    port_details = f"{'Port':<10} {'State':<10} {'Service'}\n"  # Adding table headers
    for port_info in ports:
        port_details += f"{port_info['port']:<10} {port_info['state']:<10} {port_info['service']}\n"
    return port_details

def get_gateway_ip():
    """Get the default gateway IP from the routing table."""
    response = os.popen("ip route").readlines()
    for line in response:
        if "default" in line:
            return line.split()[2]
    return None

def get_ip_class(ip):
    """Determine the class of an IP address (A, B, or C)."""
    first_octet = int(ip.split('.')[0])  # Get the first octet
    if 0 <= first_octet <= 127:
        return "Class A"
    elif 128 <= first_octet <= 191:
        return "Class B"
    elif 192 <= first_octet <= 223:
        return "Class C"
    else:
        return "Unknown"

def get_interface_for_gateway(gateway_ip):
    """Find the interface details (ip, netmask, cidr) for the gateway."""
    for interface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            for link in addrs[netifaces.AF_INET]:
                ip = link.get('addr')
                netmask = link.get('netmask')
                if not ip or not netmask:
                    continue
                # Calculate network address
                ip_bin = struct.unpack('!I', socket.inet_aton(ip))[0]
                mask_bin = struct.unpack('!I', socket.inet_aton(netmask))[0]
                network = ip_bin & mask_bin
                gw_bin = struct.unpack('!I', socket.inet_aton(gateway_ip))[0]
                if (gw_bin & mask_bin) == network:
                    # Convert netmask to CIDR
                    cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
                    return ip, netmask, cidr
    return None, None, None

if __name__ == "__main__":
    # 1. Get the gateway IP from the system
    gateway_ip = get_gateway_ip()
    if not gateway_ip:
        print("Could not determine gateway IP.")
        exit(1)
    
    # 2. Determine the class of the gateway IP
    ip_class = get_ip_class(gateway_ip)
    print(f"Gateway IP: {gateway_ip}")
    print(f"Class Breakdown: {ip_class}\n")
    
    # 3. Get network details for the gateway interface
    ip, netmask, cidr = get_interface_for_gateway(gateway_ip)
    if not cidr:
        print("Could not determine CIDR for the gateway interface.")
        exit(1)
    
    # 4. Build the network string for scanning
    # If your scan_network expects "192.168.0.1/24" style, use interface IP with CIDR
    network = f"{ip}/{cidr}"
    
    # 5. Get the connected devices' IPs using the allIP scan_network method
    ips = allIP.scan_network(network)
    
    # Remove the gateway IP from the list of connected devices (to avoid scanning the gateway itself)
    ips = [ip_addr for ip_addr in ips if ip_addr != gateway_ip]
    
    # Display only the connected devices (excluding the gateway)
    print("Connected Devices Ips:")
    for ip_addr in ips:
        print(ip_addr)
    
    print("\nScanning Devices:\n")
    
    # Loop through each connected IP address and print their details
    for ip_addr in ips:
        print(f"Scanning IP: {ip_addr}")

        # Fetching details for each IP address
        mac = findMacAddress.get_mac(ip_addr).upper()
        print(f"MAC Address: {mac}")

        vendor = findVendor.get_vendor(mac)
        print(f"Vendor: {vendor}")

        os_info = getOS.detect_os(ip_addr)
        print(f"Operating System: {os_info}")

        # Get the detailed port info (open ports, state, and services)
        ports = getPorts.scan_ports(ip_addr)
        
        # Format and print the ports with services and states
        formatted_ports = format_ports(ports)
        print(f"Port Information:\n{formatted_ports}")

        # Get the device type using the getDeviceType function
        dtype = getDeviceType.guess_type(vendor, ports)
        print(f"Device Type: {dtype}")
        
        print("-" * 40)  # Separator between IPs for better readability

    # Ending statement
    print("\nMade by Md. Ashav Noman Mahin.")
