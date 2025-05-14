import getDefaultGetway
import findMacAddress
import findVendor
import getPorts
import getOS
import getDeviceType

if __name__ == "__main__":
    ip = input("Enter IP address: ").strip()
    print("Hold tight, this might take a while... Don’t worry, we're not hacking... yet!\n")

    print(f"IP Address: {ip}")
    
    try:
        mac = findMacAddress.get_mac(ip).upper()
        print(f"MAC Address: {mac}")
    except Exception as e:
        print(f"Error finding MAC address: {e}")

    try:
        vendor = findVendor.get_vendor(mac)
        print(f"Vendor Name: {vendor}")
    except Exception as e:
        print(f"Error finding vendor information: {e}")

    try:
        os = getOS.detect_os(ip)
        print(f"Operating System: {os}")
    except Exception as e:
        print(f"Error detecting OS: {e}")

    try:
        # Get open ports and filtered Nmap output (tabular format)
        open_ports, output = getPorts.scan_ports(ip)
        print("\nRunning Service Detection:")
        print(output)  # This prints the cleaned, formatted table of open ports and services
    except Exception as e:
        print(f"Error scanning ports: {e}")

    try:
        dtype = getDeviceType.guess_type(open_ports)
        print(f"Device Type: {dtype}")
    except Exception as e:
        print(f"Error detecting device type: {e}")

    print("\nMade by Md. Ashav Noman Mahin.") 
