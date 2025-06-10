import subprocess
import re

def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
    except Exception as e:
        return f"Error running command: {e}"

def nmap_os(ip):
    """Use Nmap for OS detection."""
    out = run(f"sudo nmap -O {ip}")
    m = re.search(r"(OS details:.*|Running:.*)", out)
    if m:
        os_info = m.group(0)
        # Extract OS version details if present
        os_match = re.search(r"Running: (.+)", os_info)
        if os_match:
            return os_match.group(1)
        return os_info
    return None

def xprobe2_os(ip):
    """Use xprobe2 for OS detection."""
    out = run(f"xprobe2 {ip}")
    m = re.search(r"Operating system: (.+)", out)
    if m:
        return f"xprobe2: {m.group(1)}"
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

def detect_os(ip):
    """Detect OS using multiple methods, prioritizing more accurate ones."""
    results = []
    checks = [
        nmap_os,        # First, try Nmap OS detection
        xprobe2_os,     # Then try xprobe2 for OS detection
        ttl_os_guess,   # Finally, try TTL-based guess
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
