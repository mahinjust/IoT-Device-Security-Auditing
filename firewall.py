import subprocess
# Utility function to run a shell command and safely get its output.
def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
    except:
        return "" # Return empty string if the command fails

def detect_firewall(ip):
    """
    Detects a firewall using ICMP error behavior.
    Logic:
    - If no ICMP port unreachable → likely a firewall.
    - If ICMP unreachable, → no firewall.
    """
    # Use UDP scan to provoke ICMP errors (port unreachable)
    result = run(f"timeout 8 sudo nmap -sU -p 33434 {ip}")  # 33434 often unused, triggers ICMP error
    result = result.lower()

    if "open|filtered" in result:
        return "Active"  # Likely being silently filtered by firewall
    elif "port unreachable" in result or "closed" in result:
        return "Not active"  # ICMP error = no firewall
    else:
        return "Unknown"

# Test block
if __name__ == "__main__":
    ip = input("Enter IP: ").strip()
    print(detect_firewall(ip))
