import os
import scapy.all as scapy
response = os.popen("ip route").read()
gateway_ip = response.split()[2]
print(gateway_ip)


