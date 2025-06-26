import scapy.all as scapy # Scapy is a packet crafting and sniffing tool for network tasks.

def get_mac(ip):
    """
    Sends an ARP request to the given IP and returns the MAC address.
    If the MAC address is locally administered (random), it warns about it.
    """
    try:
        arp_request = scapy.ARP(pdst=ip) # Build ARP request for the given IP. pdst stands for "protocol destination" — here, it's the target IP address.
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # Set destination to broadcast MAC. dst="ff:ff:ff:ff:ff:ff" is a broadcast address, meaning "send this frame to all devices on the LAN."
        answered_list = scapy.srp(broadcast / arp_request, timeout=1, verbose=False)[0] #  Send ARP and receive responses. scapy.srp() = "Send and Receive Packets at Layer 2" (Ethernet level).

        if answered_list: # If response received.
            mac = answered_list[0][1].hwsrc # Extract MAC address. hwsrc stands for Hardware Source Address. It's the MAC address of the device that replied to the ARP request.

            # Convert the first octet to binary and check the second least significant bit (LAA flag)
            first_octet = int(mac.split(":")[0], 16)
            is_locally_administered = bool(first_octet & 0b00000010)

            if is_locally_administered:
                print(f"Warning: {mac} appears to be a *random (locally administered)* MAC address.")

            return mac
        else:
            print(f"Error: No MAC address found for IP {ip}. Device may be offline or not respond to ARP.")
            return "MAC Address not found"

    except Exception as e:
        print(f"Exception occurred while retrieving MAC for {ip}: {e}")
        return "MAC Address not found"

# Test the script directly (optional)
if __name__ == "__main__":
    ip_address = input("Enter IP address: ")
    mac = get_mac(ip_address)
    print(f"MAC Address: {mac}")
