import scapy.all as scapy

def get_mac(ip):
    # Send ARP request to get MAC address
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    answered_list = scapy.srp(broadcast/arp_request, timeout=1, verbose=False)[0]
    # If the response is received, return the MAC address
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return "MAC Address not found"

if __name__ == "__main__":
    # Input IP address
    ip_address = input("Enter IP address: ")
    mac_address = get_mac(ip_address)
    print(mac_address)

