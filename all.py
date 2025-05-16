import os
import allIP
import findMacAddress
import findVendor
import getPorts
import getOS
import getDeviceType

if __name__ == "__main__":
    # Get the gateway IP from the system
    response = os.popen("ip route").readlines()
    gateway_ip = ""
    
    # Find the correct gateway IP line and extract the gateway
    for line in response:
        if "default" in line:
            gateway_ip = line.split()[2] + "/24"
            break
    
    # Get the connected devices' IPs using the allIP scan_network method
    ips = allIP.scan_network(gateway_ip)
    
    # Loop through each connected IP address and print their details
    for ip in ips:
        print(f"Scanning IP: {ip}")

        # Fetching details for each IP address
        mac = findMacAddress.get_mac(ip).upper()
        print(f"MAC Address: {mac}")

        vendor = findVendor.get_vendor(mac)
        print(f"Vendor: {vendor}")

        os = getOS.detect_os(ip)
        print(f"Operating System: {os}")

        ports = getPorts.scan_ports(ip)
        print(f"Open Ports: {ports}")

        dtype = getDeviceType.guess_type(vendor, ports)
        print(f"Device Type: {dtype}")
        print("-" * 40)  # Separator between IPs for better readability
