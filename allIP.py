import os
import scapy.all as scapy

def scan_network(ip):
    arp_request = scapy.ARP(pdst=ip)
    # Creating Ethernet Broadcast Frame
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # combined Ethernet frame 
    answered_list = scapy.srp(broadcast/arp_request, timeout=1, verbose=False)[0]
    # element[1] refers to the response packet.
    # element[1].psrc retrieves the source IP address
    return [element[1].psrc for element in answered_list]
