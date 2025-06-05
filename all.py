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
import subprocess
import platform
import scapy.all as scapy

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

def ping_ip(ip, count=3, timeout=2):
    """Ping an IP address to check if it's reachable. Ping at least 'count' times."""
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

def ipv6_scan_network(ip_range):
    """IPv6 scan to find all devices in a network range."""
    devices = []
    try:
        # Use Scapy to send ICMPv6 Echo Request to the network
        icmpv6_request = scapy.ICMPv6EchoRequest()
        ipv6_request = scapy.IPv6(dst=ip_range)/icmpv6_request
        answered_list = scapy.srp6(ipv6_request, timeout=5, verbose=False)[0]
        for element in answered_list:
            devices.append(element[1].psrc)  # IPv6 address of the device
    except Exception as e:
        print(f"Error performing IPv6 scan: {e}")
    return devices

def save_connected_ips_to_file(ip_list):
    """Save the list of reachable IPs to a file."""
    with open("connected_ips.txt", "w") as file:
        for ip in ip_list:
            file.write(f"{ip}\n")

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
    network = f"{ip}/{cidr}"
    
    # 5. Get all the devices' IPs using the ARP scan method (more reliable for detecting all devices)
    all_devices_ips = arp_scan_network(f"{ip.split('.')[0]}.{ip.split('.')[1]}.{ip.split('.')[2]}.1/24")
    # Optionally use IPv6 scanning
    all_devices_ips.extend(ipv6_scan_network("fe80::/10"))
    
    # Display only the reachable connected devices (excluding the gateway)
    print("Connected Devices Ips:")
    for ip_addr in all_devices_ips:
        if ip_addr != gateway_ip:  # Avoid listing the gateway
            print(ip_addr)
    
    # Save the connected devices' IPs to a file
    save_connected_ips_to_file(all_devices_ips)
    print("\nConnected devices IPs have been saved to 'connected_ips.txt'.\n")
    
    print("\nScanning Devices:\n")
    
    # Loop through each reachable IP address and print their details
    for ip_addr in all_devices_ips:
        if ip_addr == gateway_ip:  # Skip the gateway itself
            continue
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
