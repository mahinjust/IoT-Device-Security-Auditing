import os
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

    print("\n")
    
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

        # Get the detailed port info (open ports, state, and services)
        ports = getPorts.scan_ports(ip)
       
        # Format and print the ports with services and states
        formatted_ports = format_ports(ports)
        print(f"Port Information:\n{formatted_ports}")

        # Update this line to use the new logic in getDeviceType
        dtype = getDeviceType.guess_type(vendor, ports)
        print(f"Device Type: {dtype}")
        print("-" * 40)  # Separator between IPs for better readability

    # Ending statement
    print("\nMade by Md. Ashav Noman Mahin.")
