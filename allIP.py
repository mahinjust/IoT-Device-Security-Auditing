import os
import scapy.all as scapy

def scan_network(ip):
    arp_request = scapy.ARP(pdst=ip)
    #Creating Ethernet Broadcast Frame
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # combined Ethernet frame 
    answered_list = scapy.srp(broadcast/arp_request, timeout=1, verbose=False)[0]
    #element[1] refers to the response packet.
    #lement[1].psrc retrieves the source IP address
    return [element[1].psrc for element in answered_list]

response = os.popen("ip route").read()
gateway_ip = response.split()[2] + "/24"
# gateway_ip = "172.24.41.1/24"
print(f"Getway IP: {gateway_ip}\n")

ips = scan_network(gateway_ip)

for ip in ips:
    print(ip)


