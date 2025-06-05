import subprocess, re

def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
    except Exception as e:
        return f"Error running command: {e}"

def nmap_os(ip):
    """Use Nmap for OS detection."""
    out = run(f"sudo nmap -O {ip}")
    m = re.search(r"(OS details:.*|Running:.*)", out)
    return m.group(0) if m else None

def xprobe2_os(ip):
    """Use xprobe2 for OS detection."""
    out = run(f"xprobe2 {ip}")
    m = re.search(r"Operating system: (.+)", out)
    return f"xprobe2: {m.group(1)}" if m else None

def ttl_os_guess(ip):
    """Guess OS based on TTL value from ICMP ping response."""
    out = run(f"ping -c 1 {ip}")
    ttl = re.search(r"ttl=(\d+)", out)
    if ttl:
        val = int(ttl.group(1))
        guess = "Windows" if val >= 120 else "Linux/Unix" if val <= 64 else "Unknown"
        return f"OS: {guess}"
    return None

def detect_os(ip):
    """Detect OS using multiple methods."""
    results = []
    checks = [
        nmap_os,
        xprobe2_os,
        ttl_os_guess,
    ]
    
    for check in checks:
        try:
            res = check(ip)
            if res:
                results.append(res)
        except Exception as e:
            results.append(f"Error in {check.__name__}: {e}")
    
    return results if results else ["OS not detected."]

if __name__ == "__main__":
    ip = input("Enter IP: ").strip()
    print("\nStarting OS finding...\n")
    for line in detect_os(ip):
        print(line)
