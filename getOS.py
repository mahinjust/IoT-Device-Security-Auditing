import subprocess, re

def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
    except:
        return ""

def nmap_os(ip):
    # print("1. Nmap OS detection...")
    out = run(f"sudo nmap -O {ip}")
    m = re.search(r"(OS details:.*|Running:.*)", out)
    return m.group(0) if m else None

def snmp_os(ip):
    # print("2. SNMP check...")
    out = run(f"snmpget -v 2c -c public {ip} 1.3.6.1.2.1.1.1.0")
    return f"SNMP: {out}" if out else None

def xprobe2_os(ip):
    # print("3. xprobe2 OS ...")
    out = run(f"xprobe2 {ip}")
    m = re.search(r"Operating system: (.+)", out)
    return f"xprobe2: {m.group(1)}" if m else None

def ttl_os_guess(ip):
    # print("4. TTL OS Guess...")
    out = run(f"ping -c 1 {ip}")
    ttl = re.search(r"ttl=(\d+)", out)
    if ttl:
        val = int(ttl.group(1))
        guess = "Windows" if val >= 120 else "Linux/Unix" if val <= 64 else "Unknown"
        return f" OS: {guess}"
    return None

def detect_os(ip):
    results = []
    checks = [
        nmap_os,
        snmp_os,
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
    print("\n Starting OS finding...\n")
    for line in detect_os(ip):
        print(line)
