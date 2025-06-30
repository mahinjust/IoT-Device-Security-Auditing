import subprocess

def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
    except:
        return ""

def detect_firewall(ip):
    """
    Hybrid firewall detection using:
    - ICMP error behavior via UDP scan
    - TCP ACK scan (detects stateful firewalls)
    
    Returns:
        - 'Active' if any filtering is detected
        - 'Not active' if all checks pass
        - 'Unknown' if inconclusive
        - 'Unreachable or silent host' if no response at all
    """

    # ---------- 1. ICMP-based detection ----------
    icmp_result = run(f"timeout 8 sudo nmap -sU -p 33434 {ip}").lower()

    # ---------- 2. TCP ACK scan ----------
    ack_result = run(f"timeout 8 sudo nmap -sA -p 80 {ip}").lower()

    # ---------- Additional check: Host is silent or unreachable ----------
    if not icmp_result and not ack_result:
        return "Unreachable or silent host (could be offline or behind a stealth firewall)"

    # ---------- Heuristic decision ----------
    if ("open|filtered" in icmp_result) or ("filtered" in ack_result):
        return "Active"
    elif ("port unreachable" in icmp_result or "closed" in icmp_result) and ("unfiltered" in ack_result):
        return "Not active"
    else:
        return "Unknown"

# Test
if __name__ == "__main__":
    ip = input("Enter IP: ").strip()
    print(detect_firewall(ip))
