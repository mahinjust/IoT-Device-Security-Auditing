import subprocess # Importing subprocess to run shell commands from Python.

def run(cmd): # Define a function to run shell commands safely.
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()  # Run the shell command, suppress errors, decode output from bytes to string, remove whitespace.
    except:
        return ""  # If the command fails or throws an error, return an empty string.

def detect_firewall(ip): # Uses an ACK scan (-sA) against ports 1‑1000 to guess whether a host is protected by a stateful firewall. Returns 'Active', 'Not active', or 'Unknown'.
    result = run(f"timeout 6 sudo nmap -sA -p 1-1000 {ip}")  # Run nmap with a 6‑second cap; needs sudo for raw packets

    if "filtered" in result.lower():
        return "Active"
    elif "unfiltered" in result.lower():
        return "Not active"
    else:
        return "Unknown"   # Heuristic: filtered ⇒ firewall; unfiltered ⇒ likely none.

# Test block (only runs if executed directly)
if __name__ == "__main__":
    ip = input("Enter IP: ").strip()
    print(detect_firewall(ip))
