import json
import getPorts
import findMacAddress
import findVendor

# Load the JSON file containing device data
def load_device_data():
    with open('device_type_database.json', 'r') as file:
        data = json.load(file)
    return data

# Function to check device type based on ports and vendor
def guess_type(vendor, ports):
    data = load_device_data()
    
    matching_device = None
    match_counts = {}
   
    # Check based on multiple port matches (at least 2 or more ports should match)
    for device in data['devices']:
        # Track how many matching ports we have
        match_count = sum(1 for port in device['ports'] if any(port == p['port'] for p in ports))

        # If 2 or more ports match, consider it a match
        if match_count >= 2:
            matching_device = device
            break

    # If no match, default to "Unknown"
    return matching_device['device_type'] if matching_device else "Unknown"

if __name__ == "__main__":
    ip = input("Enter IP address: ").strip()
    print("Start Scanning.....\n")

    print(f"IP Address: {ip}")
    mac = findMacAddress.get_mac(ip).upper()
    print(f"MAC Address: {mac}")
    if not mac:
        print("Device Type: Unknown")

    vendor = findVendor.get_vendor(mac)
    print(f"Vendor: {vendor}")

    ports = getPorts.scan_ports(ip)
    print(f"Open Ports: {ports}")
    
    dtype = guess_type(vendor, ports)
    print(f"Device Type: {dtype}")
