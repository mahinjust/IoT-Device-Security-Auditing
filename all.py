import os # Imports the built-in os module, which provides functions to interact with the operating system (e.g., file and directory operations, environment variables).
import findMacAddress
import findVendor
import getPorts
import getOS
import getDeviceType
import subprocess # Imports the built-in subprocess module, which allows running external system commands and getting their output within the Python script.
from concurrent.futures import ThreadPoolExecutor # Imports ThreadPoolExecutor from concurrent.futures, which is used for multithreading. It allows running functions concurrently in separate threads — useful for faster network scanning.
import netifaces # Imports the third-party module netifaces, used to retrieve network interface information such as IP addresses, gateways, etc.
import ipaddress # Imports the built-in ipaddress module, which allows working with IP addresses and networks — useful for subnetting, IP validation, and iteration over IP ranges.

def get_gateway_ip(): # Defines a function named get_gateway_ip that takes no arguments.
    response = os.popen("ip route").readlines() # Uses os.popen() to run the shell command ip route, which shows the routing table on Linux systems. readlines() reads the command output as a list of lines (each line is a string).
    for line in response: # Starts a loop to iterate over each line of the command output.
        if line.startswith("default"): # Checks if the line begins with the word "default".
            return line.split()[2] # Splits the line into words (by whitespace) and returns the third word (index 2), which is the gateway IP address. 
    return None

def get_ip_class(ip): # Defines a function named get_ip_class that takes one argument ip (a string representing an IPv4 address).
    first_octet = int(ip.split('.')[0]) # Splits the IP address string by the dot (.), takes the first segment (the first octet), and converts it to an integer.
    if 0 <= first_octet <= 127: # Checks if the first octet is between 0 and 127 inclusive; if yes, returns "Class A".
        return "Class A"
    elif 128 <= first_octet <= 191: # Checks if the first octet is between 128 and 191; if yes, returns "Class B".
        return "Class B"
    elif 192 <= first_octet <= 223: # Checks if the first octet is between 192 and 223; if yes, returns "Class C".
        return "Class C"
    elif 224 <= first_octet <= 239: # Checks if the first octet is between 224 and 239; if yes, returns "Class D (Multicast)"
        return "Class D (Multicast)"
    elif 240 <= first_octet <= 255: # Checks if the first octet is between 240 and 255; if yes, returns "Class E (Reserved)".
        return "Class E (Reserved)"
    return "Unknown"

def get_interface_for_gateway(gateway_ip):
    for iface in netifaces.interfaces(): # Look at all the network connections my computer has (for example, Wi-Fi or Ethernet).
        addrs = netifaces.ifaddresses(iface) #For each connection, get all its addresses and info.
        if netifaces.AF_INET in addrs: #Check if this connection has an IPv4 address (normal internet IP).
            for link in addrs[netifaces.AF_INET]: # There might be more than one IP on this connection, so look at each one.
                ip = link.get('addr') # Get the IP address of your computer on this connection.
                netmask = link.get('netmask') # Get the subnet mask, which tells how big the network is.
                if not ip or not netmask: # If IP or netmask is missing, skip this address and check the next one.
                    continue
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False) # Use the IP and netmask to figure out the full network your computer is in.
                if ipaddress.IPv4Address(gateway_ip) in network: # Check if the gateway’s IP address belongs to this network.
                    return ip, netmask, network.prefixlen # If yes, return your computer’s IP, the netmask, and the size of the network (CIDR).
    return None, None, None

def get_network_hosts(interface_ip, cidr): # This is a function that takes your device’s IP and the size of the network.
    network = ipaddress.IPv4Network(f"{interface_ip}/{cidr}", strict=False) # Creates an IPv4 network object from the given IP address and CIDR. strict=False allows the IP to be any address in the subnet, not necessarily the network address itself.
    return [str(ip) for ip in network.hosts()] # Returns a list of all possible host IP addresses in the network as strings. network.hosts() generates all usable IPs, excluding network and broadcast addresses.

def ping_ip(ip, count=3, timeout=1): # Defines a function called ping_ip that takes an IP address (ip) and optional parameters: count (default 3): how many times to send a ping. timeout (default 1 second): how long to wait for each reply.
    try: # Starts a block where the code tries to do something that might fail. The result of running the command is stored in res.
        res = subprocess.run(
            ['ping', '-c', str(count), '-W', str(timeout), ip], # Runs the system’s ping command.-c <count>: send <count> ping requests. -W <timeout>: wait <timeout> seconds for a reply each time. ip: the target IP address.
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL # hide the output so nothing prints on screen.
        )
        return res.returncode == 0 # Returns True if ping was successful (exit code 0 means success), otherwise False.
    except Exception: # If any error happens during the ping, the program will handle it here.
        return False

def icmp_ping_scan_parallel(network_hosts, workers=50): #This defines a function that will try to ping a list of IP addresses (network_hosts) in parallel. workers=50 means it will use up to 50 threads (workers) to speed up the process.
    reachable = [] # Creates an empty list to store the IPs that respond to the ping.
    def _ping(ip): return (ip, ping_ip(ip)) # Defines a small helper function that takes an IP, pings it using your earlier ping_ip() function. and returns a tuple like: ('192.168.1.10', True or False)
    with ThreadPoolExecutor(max_workers=workers) as ex: # Creates a pool of worker threads to run tasks in parallel. ex is the executor object managing the threads.
        for ip, ok in ex.map(_ping, network_hosts): # Runs the _ping() function on each IP in the list at the same time using the thread pool. ex.map() returns the results in order as (ip, True/False).
            if ok:
                reachable.append(ip) # If ping was successful (ok == True), add the IP to the reachable list.
    return reachable

def save_connected_ips(ip_list, filename='connected_ips.txt'): # Defines a function named save_connected_ips. ip_list: a list of IP addresses (usually the reachable/active ones). filename: the name of the file to save the list.
    with open(filename, 'w') as f: # Opens the file for writing. If the file already exists, it will overwrite it. with ensures the file is properly closed after writing.
        f.write("\n".join(ip_list)) # Joins all IPs from the list into a single string, with each IP on a new line, then writes it to the file.

def format_ports(ports): # Defines a function called format_ports, which takes a list of port dictionaries as input.
    header = f"{'Port':<10} {'State':<10} Service" # Creates a header row with column titles: Port, State, and Service, aligned to the left with spacing.
    lines = [header] # Initializes a list lines with the header as its first item.
    for p in ports: # Loops through each item (p) in the ports list. Each item is expected to be a dictionary with keys: 'port', 'state', and 'service'.
        lines.append(f"{p['port']:<10} {p['state']:<10} {p['service']}") # Formats each port entry into a string and adds it to the lines list.
    return "\n".join(lines) # Joins all lines into a single string with new lines in between, and returns it.

if __name__ == '__main__': # Ensures this code runs only when the script is executed directly (not imported as a module).

    gw = get_gateway_ip() # Gets the default gateway IP (usually our router's IP address).
    if not gw:
        print("Could not determine gateway IP.")
        exit(1) # If no gateway is found, shows an error and exits the program.

    cls = get_ip_class(gw)
    print(f"Default Gateway: {gw} ({cls})\n") # Determines the class (A, B, C...) of the IP and prints the gateway with its class.

    iface_ip, netmask, cidr = get_interface_for_gateway(gw) # Gets the local interface IP, subnet mask, and CIDR prefix for the gateway network.
    if not cidr:
        print("Could not determine network on interface.")
        exit(1) # If it couldn't determine the network range, it exits.

    hosts = get_network_hosts(iface_ip, cidr)
    print(f"Scanning network {iface_ip}/{cidr} ({len(hosts)} hosts)...") # Generates a list of all possible host IPs in the network and prints the scan info.

    live_ips = icmp_ping_scan_parallel(hosts) # Pings all hosts in the network in parallel and collects only those that respond.
    live_ips = sorted(set(live_ips)) # Removes duplicates (if any) and sorts the list of live IPs.

    print("\nConnected Devices IPs:")
    for ip in live_ips:
        if ip == gw: continue
        print(ip) # Prints all reachable device IPs, excluding the gateway.
    save_connected_ips(live_ips)
    print(f"\nSaved {len(live_ips)} IPs to 'connected_ips.txt'.\n") # Saves the live IPs to a file for future reference.

    print("Detailed Scanning (One by One):")
    for ip in live_ips:
        if ip == gw: continue # Starts scanning each connected device one by one, skipping the gateway.
        print(f"\n-- {ip} --")
        mac = findMacAddress.get_mac(ip).upper()
        print(f"MAC Address: {mac}") # Gets and prints the MAC address of the device.
        vendor = findVendor.get_vendor(mac)
        print(f"Vendor Name: {vendor}") # Finds the device manufacturer based on MAC and prints it.
        os_info = getOS.detect_os(ip)
        print(f"OS Details: {os_info}") # Tries to detect the operating system of the device and prints it.
        ports = getPorts.scan_ports(ip) # Scans for open ports on the device.
        if ports:
            print("Ports Information:\n" + format_ports(ports))
            dtype = getDeviceType.guess_type(vendor, ports) or 'Unknown'
        else:
            print("Ports: None open")
            dtype = 'Unknown' # If open ports are found, shows port info and guesses device type; otherwise marks as unknown.
        print(f"Device Type: {dtype}")
        print("-------------------------")

    print("\nMade by Md. Ashav Noman Mahin.")
