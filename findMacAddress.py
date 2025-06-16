import scapy.all as scapy # Import Scapy library with alias 'scapy'.

def get_mac(ip): # Defines a function named get_mac that takes one argument ip.
    arp_request = scapy.ARP(pdst=ip) # Create an ARP request packet with destination IP set to 'ip'.
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # Create an Ethernet frame with destination MAC as broadcast (to all devices).
    answered_list = scapy.srp(broadcast/arp_request, timeout=1, verbose=False)[0] # Send the combined packet (Ethernet frame + ARP request) and capture responses.
    # timeout=1 second, verbose=False to suppress output.
    # If we received any response.
    if answered_list:
        return answered_list[0][1].hwsrc # Return the MAC address from the first response.
    else:
        return "MAC Address not found" # No response received; return a message indicating MAC not found.

if __name__ == "__main__":
    # Input IP address
    ip_address = input("Enter IP address: ")
    mac_address = get_mac(ip_address) # Call the get_mac function to get MAC address for the given IP
    print(mac_address)
