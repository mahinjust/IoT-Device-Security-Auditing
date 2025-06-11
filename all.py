import os
import socket
import struct
import netifaces
import findMacAddress
import findVendor
import getPorts
import getOS
import getDeviceType
import subprocess
import scapy.all as scapy
from concurrent.futures import ThreadPoolExecutor

def format_ports(ports):
    """Create a formatted string for displaying table headers and port details."""
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
    """Determine the class of an IP address (A, B, C, D, E)."""
    first_octet = int(ip.split('.')[0])  # Get the first octet
    if 0 <= first_octet <= 127:
        return "Class A"
    elif 128 <= first_octet <= 191:
        return "Class B"
    elif 192 <= first_octet <= 223:
        return "Class C"
    elif 224 <= first_octet <= 239:
        return "Class D (Multicast)"
    elif 240 <= first_octet <= 255:
        return "Class E (Reserved)"
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

def ping_ip(ip, count=3, timeout=1):  # Reduced timeout for faster response
    """Ping an IP address to check if it's reachable."""
    try:
        response = subprocess.run(
            ['ping', '-c', str(count), '-W', str(timeout), ip],  # Ping 'count' packets with timeout
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if response.returncode == 0:  # If ping was successful
            return True
        else:
            return False
    except Exception as e:
        print(f"Error pinging {ip}: {e}")
        return False

def arp_scan_network(ip_range):
    """ARP scan to find all devices in a network range."""
    devices = []
    try:
        # Use Scapy to send ARP request to the network
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
        for element in answered_list:
            devices.append(element[1].psrc)  # IP address of the device
    except Exception as e:
        print(f"Error performing ARP scan: {e}")
    return devices

def icmp_ping_scan_parallel(network_range):
    """Ping all devices in a network range using ICMP in parallel."""
    reachable_ips = []
    
    # Function to be used in parallel for checking reachability
    def ping_device(ip):
        is_reachable = ping_ip(ip)  # Check if the device is reachable using ping
        return ip, is_reachable  # Return both IP and reachability
    
    try:
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(ping_device, ip) for ip in network_range]  # Submit all tasks
            for future in futures:
                ip, is_reachable = future.result()  # Unpack the result (ip and reachability)
                if is_reachable:
                    reachable_ips.append(ip)
    except Exception as e:
        print(f"Error during parallel ICMP scan: {e}")
    
    return reachable_ips

def save_connected_ips_to_file(ip_list):
    """Save the list of reachable IPs to a file."""
    with open("connected_ips.txt", "w") as file:
        for ip in ip_list:
            file.write(f"{ip}\n")

def get_network_range(ip, cidr):
    """Generate a range of IPs based on the given network and CIDR."""
    network = ip.split(".")
    network_base = f"{network[0]}.{network[1]}.{network[2]}."
    range_start = 1
    range_end = 254  # For most home networks

    return [f"{network_base}{i}" for i in range(range_start, range_end + 1)]

if __name__ == "__main__":
    # 1. Get the gateway IP from the system
    gateway_ip = get_gateway_ip()
    if not gateway_ip:
        print("Could not determine gateway IP.")
        exit(1)
    
    # 2. Determine the class of the gateway IP
    ip_class = get_ip_class(gateway_ip)
    print(f"Default Gateway IP: {gateway_ip}")
    print(f"Host Class Breakdown: {ip_class}\n")
    
    # 3. Get network details for the gateway interface
    ip, netmask, cidr = get_interface_for_gateway(gateway_ip)
    if not cidr:
        print("Could not determine CIDR for the gateway interface.")
        exit(1)
    
    # 4. Build the network string for scanning
    network_range = get_network_range(ip, cidr)
    
    # 5. Get all the devices' IPs using the ARP scan method (more reliable for detecting all devices)
    all_devices_ips = arp_scan_network(f"{ip.split('.')[0]}.{ip.split('.')[1]}.{ip.split('.')[2]}.1/24")
    
    # Use ICMP ping scan to ensure we catch devices not responding to ARP
    all_devices_ips.extend(icmp_ping_scan_parallel(network_range))
    
    # Remove duplicates from the list of IPs
    all_devices_ips = list(set(all_devices_ips))
    
    # Display only the reachable connected devices (excluding the gateway)
    print("Connected Devices Ips List:")
    for ip_addr in all_devices_ips:
        if ip_addr != gateway_ip:  # Avoid listing the gateway
            print(ip_addr)
    
    # Save the connected devices' IPs to a file
    save_connected_ips_to_file(all_devices_ips)
    print("\nConnected devices IPs have been saved to 'connected_ips.txt'.\n")
    
    print("\nScanning Connected Devices One by One:\n")
    
    # Loop through each reachable IP address and print their details
    for ip_addr in all_devices_ips:
        if ip_addr == gateway_ip:  # Skip the gateway itself
            continue
        print(f"Scanning IP Address: {ip_addr}")

        # Fetching details for each IP address
        mac = findMacAddress.get_mac(ip_addr).upper()
        print(f"MAC Address: {mac}")

        vendor = findVendor.get_vendor(mac)
        print(f"Vendor Name: {vendor}")

        os_info = getOS.detect_os(ip_addr)
        print(f"Operating System: {os_info}")

        # Get the detailed port info (open ports, state, and services)
        ports = getPorts.scan_ports(ip_addr)

        # Check if no ports are open and show the appropriate message
        if not ports:
            print("Port Information: No open ports were found!")
            dtype = "Unknown"  # Set device type to Unknown if no ports
        else:
            # Format and print the ports with services and states
            formatted_ports = format_ports(ports)
            print(f"Port Information:\n{formatted_ports}")

            # Get the device type using the getDeviceType function
            dtype = getDeviceType.guess_type(vendor, ports)
            if not dtype:  # If no device type could be guessed, set it to Unknown
                dtype = "Unknown"
        
        print(f"Device Type: {dtype}")
        
        print("-" * 40)  # Separator between IPs for better readability

# Ending statement
print("\nMade by Md. Ashav Noman Mahin.")
