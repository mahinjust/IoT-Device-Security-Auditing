import subprocess
import re
import requests
import socket

def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
    except Exception as e:
        return f"Error running command: {e}"

def clean_os_string(raw):
    """Extract and normalize OS name + version."""
    patterns = [
        r'Windows \d+(?: \w+)?',        # Windows 10, Windows 11 Pro
        r'Linux \d+\.\d+',             # Linux 2.6
        r'Linux',                      # Generic Linux
        r'Mac OS X \d+\.\d+',          # Mac OS X 10.15
        r'FreeBSD \d+\.\d+',
        r'Solaris',
        r'Unix',
        r'Android \d+',
        r'iOS \d+',
    ]

    for pat in patterns:
        match = re.search(pat, raw, re.IGNORECASE)
        if match:
            return match.group(0).strip()

    # Fallback to trimmed raw string
    return raw.split(",")[0].strip()

def nmap_os(ip):
    """Use Nmap for OS detection."""
    out = run(f"sudo nmap -O {ip}")
    if out:
        for line in out.splitlines():
            if "OS details" in line or "Running" in line:
                return clean_os_string(line)
    return None

def xprobe2_os(ip):
    """Use xprobe2 for OS detection."""
    out = run(f"xprobe2 {ip}")
    m = re.search(r"Operating system: (.+)", out)
    if m:
        return clean_os_string(m.group(1))
    return None

def ttl_os_guess(ip):
    """Guess OS based on TTL value from ICMP ping response."""
    out = run(f"ping -c 1 {ip}")
    ttl = re.search(r"ttl=(\d+)", out)
    if ttl:
        val = int(ttl.group(1))
        if val >= 120:
            return "Windows (likely)"
        elif val <= 64:
            return "Linux/Unix (likely)"
        else:
            return "Unknown OS (based on TTL)"
    return None

def p0f_os(ip):
    """Use p0f for passive OS detection."""
    out = run(f"p0f -i eth0 -s {ip}")
    match = re.search(r"OS:\s*(.+)", out)
    if match:
        return clean_os_string(match.group(1))
    return None

def http_header_os(ip):
    """Attempt to detect OS using HTTP headers."""
    try:
        url = f"http://{ip}"
        headers = requests.get(url, timeout=5).headers
        # Look for known OS signatures in headers
        for header in headers:
            if "Server" in header:
                return clean_os_string(headers["Server"])
    except requests.exceptions.RequestException:
        return None

def banner_grabbing(ip, port=80):
    """Try to grab banners from a service to detect OS details."""
    try:
        sock = socket.socket()
        sock.settimeout(3)  # Set a timeout for the connection
        sock.connect((ip, port))  # Connect to the IP and port
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")  # Send a simple HTTP HEAD request
        banner = sock.recv(1024).decode('utf-8', errors='ignore')  # Receive the banner
        return clean_os_string(banner)  # Clean and return the banner information
    except Exception as e:
        return None

def detect_os(ip):
    """Detect OS using multiple methods, prioritizing more accurate ones."""
    results = []
    checks = [
        nmap_os,        # First, try Nmap OS detection
        xprobe2_os,     # Then try xprobe2 for OS detection
        p0f_os,         # p0f for passive OS detection
        http_header_os, # HTTP header-based OS detection
        ttl_os_guess,   # Finally, try TTL-based guess
        lambda ip: banner_grabbing(ip, 80)  # Try banner grabbing on HTTP (port 80)
    ]
    
    for check in checks:
        try:
            res = check(ip)
            if res:
                results.append(res)
        except Exception as e:
            results.append(f"Error in {check.__name__}: {e}")
    
    # If multiple results are found, choose the most specific one
    if results:
        # Prioritize Nmap results over others
        for result in results:
            if "Running" in result or "OS details" in result:
                return [result]  # Return Nmap's result first if present
        
        # If no Nmap result, return the best available result
        return results[:1]  # Return just the first non-conflicting result

    return ["OS not detected."]  # If no results, return default

if __name__ == "__main__":
    ip = input("Enter IP: ").strip()
    print("\nStarting OS finding...\n")
    for line in detect_os(ip):
        print(line)
