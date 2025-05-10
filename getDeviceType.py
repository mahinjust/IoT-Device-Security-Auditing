import json
import getPorts
import findMacAddress
import findVendor

# Load the JSON file containing device data
def load_device_data():
    with open('device_type_database.json', 'r') as file:
        data = json.load(file)
    return data

# Function to check device type based on ports
def guess_type(ports):
    data = load_device_data()

    for device in data['devices']:
        # Check if any port in the device matches the given ports
        if any(port in ports for port in device['ports']):
            return device['device_type']
    
    return "Unknown"

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
    
    dtype = guess_type(ports)
    print(f"Device Type: {dtype}")
