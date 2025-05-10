import getDefaultGetway
import findMacAddress
import findVendor
import getPorts
import getOS
import getTTL
import getDeviceType

if __name__ == "__main__":
    ip = input("Enter IP address: ").strip()
    print("Start Scanning.....\n")

    print(f"IP Address: {ip}")
    
    try:
        mac = findMacAddress.get_mac(ip).upper()
        print(f"MAC Address: {mac}")
    except Exception as e:
        print(f"Error finding MAC address: {e}")

    try:
        ttl = getTTL.get_ttl(ip)
        print(f"TTL: {ttl}")
    except Exception as e:
        print(f"Error finding TTL: {e}")

    try:
        vendor = findVendor.get_vendor(mac)
        print(f"Vendor: {vendor}")
    except Exception as e:
        print(f"Error finding vendor information: {e}")

    try:
        os = getOS.detect_os(ip)
        print(f"Operating System: {os}")
    except Exception as e:
        print(f"Error detecting OS: {e}")

    try:
        # Get open ports and Nmap output
        open_ports, nmap_output = getPorts.scan_ports(ip)
        print(f"Open Ports: {open_ports}")
        print("\nNmap Output (Service Detection by Mahin):")
        print(nmap_output)
    except Exception as e:
        print(f"Error scanning ports: {e}")

    try:
        dtype = getDeviceType.guess_type(open_ports)
        print(f"Device Type: {dtype}")
    except Exception as e:
        print(f"Error detecting device type: {e}")
    
    print("\nMade by Tarik & Mahin.")  # Add your name at the end for fun
