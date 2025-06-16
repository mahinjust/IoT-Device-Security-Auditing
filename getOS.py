import subprocess # To execute system commands like 'ping' and capture their output.
import requests # For making HTTP requests to external services.
import socket # For network-related tasks like hostname resolution, opening sockets, etc.
import netifaces # To get detailed info on network interfaces (IP, subnet, gateway).
import os # To interact with the OS (e.g., file handling, path ops, or executing shell commands).

def run(cmd): # Executes a shell command and returns its output as a string. Silently returns an empty string if the command fails.
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()  # Run the command, suppress errors, decode and strip output.
    except:
        return "" # On error, return empty string.

def is_host_up(ip):
    return os.system(f"ping -c 2 -W 2 {ip} > /dev/null 2>&1") == 0 # Returns True if the given IP responds to 2 ping attempts within 2 seconds each. Uses os.system and suppresses output for silent checking.

def nmap_os(ip): # Attempts to detect the operating system of the given IP using nmap. Uses 'sudo nmap -O' with a timeout of 7 seconds. Returns the OS description string if found, otherwise None.
    out = run(f"timeout 7 sudo nmap -O {ip}")
    for line in out.splitlines():
        if "Too many fingerprints" in line:
            return None # OS detection failed due to ambiguity.
        if "OS details" in line or "Running:" in line:
            return line.split(":", 1)[-1].strip() # Extract and return the OS description.
    return None # No OS info found.

def xprobe2_os(ip):
    out = run(f"timeout 4 xprobe2 {ip}") # Uses xprobe2 to detect the operating system of a given IP. Times out after 4 seconds.
    for line in out.splitlines():
        if "Operating system:" in line: # Extract and return the OS description after the colon.
            return line.split(":", 1)[-1].strip()
    return None # Return None if OS info wasn't found.

def get_default_interface(): # Returns the name of the default network interface for IPv4 traffic. Falls back to 'eth0' if no default is found.
    gws = netifaces.gateways() # Get all configured gateways.
    default = gws.get('default') # Get the default gateway entry.
    return default[netifaces.AF_INET][1] if default and netifaces.AF_INET in default else 'eth0'  # Check if there's a default gateway for IPv4 and return its interface name.

def p0f_os(ip):
    iface = get_default_interface() # Get the default network interface (e.g., eth0 or enp3s0).
    out = run(f"timeout 4 p0f -i {iface} -s {ip}") # Run p0f on the given IP using the selected interface, limit execution to 4 seconds.
    for line in out.splitlines(): # Process each line of the output.
        if "os =" in line.lower(): # Look for lines that mention OS.
            return line.split("=", 1)[-1].strip() # Extract the OS name.
    return None # Return None if no OS info was found

def http_header_os(ip):
    try:
        headers = requests.get(f"http://{ip}", timeout=3).headers  # Send an HTTP GET request to the target IP on port 80 (default HTTP port).
        server = headers.get("Server", "") # Try to retrieve the 'Server' header, which often contains server/OS info.
        return server.strip() if server else None  # Return the value if it exists, otherwise return None.
    except:
        return None # If the host doesn't respond, or isn't running a web server, return None.

def banner_grabbing(ip, port=80):
    try:
        with socket.create_connection((ip, port), timeout=2) as sock: # Connect to the target IP and port with 2s timeout.
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n") # Send a minimal HTTP HEAD request.
            banner = sock.recv(512).decode(errors="ignore") # Receive up to 512 bytes of response.
            lines = [line for line in banner.splitlines() if "Server:" in line or "Linux" in line or "Windows" in line] # Filter lines containing server or OS hints.
            return lines[0].replace("Server:", "").strip() if lines else None  # Return cleaned first matched line or None.
    except:
        return None # On any error (timeout, refused, etc.), return None.

def ttl_os_guess(ip):
    out = run(f"ping -c 1 -W 1 {ip}") # Run ping command once with 1 second timeout.
    for line in out.splitlines(): # Check each line for TTL information.
        if "ttl=" in line:
            try:
                val = int(line.split("ttl=")[-1].split()[0]) # Extract TTL value after "ttl=".
                if val >= 120: # OS guessing logic based on TTL value.
                    return "Windows"
                elif val <= 64:
                    return "Linux"
                else:
                    return "Unknown"
            except:
                return None # If parsing fails, return None.
    return None  # If no ttl found, return None.

def detect_os(ip):
    if not is_host_up(ip): # Check if host responds to ping.
        return "Host unreachable or not responding."
# List of OS detection methods to try in order.
    methods = [
        xprobe2_os, # Passive OS fingerprinting via xprobe2.
        p0f_os, # Passive OS fingerprinting via p0f.
        http_header_os, # Detect OS from HTTP Server headers.
        banner_grabbing, # Banner grabbing on port 80.
        ttl_os_guess, # OS guess from TTL in ping response.
        nmap_os  # Active OS detection using nmap (slow).
    ]

    for method in methods: # Try each detection method.
        result = method(ip)
        if result and len(result.split()) > 1: # Check if result is meaningful and has at least two words.
            words = result.split()
            return f"{words[0]} {words[1]}" # Return the first two words as OS guess (e.g. "Windows 10").
    
    return "OS not detected!" # No OS detected after all methods.
# Only run the code inside this block if this script is executed directly, not if it’s imported as a module.
if __name__ == "__main__": # Ask user to enter an IP address, remove any extra spaces.
    ip = input("Enter IP: ").strip() # Call detect_os with that IP and print the result.
    print(detect_os(ip))
