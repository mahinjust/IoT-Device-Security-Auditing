import subprocess

def run_nmap_command(command):
    try:
        # Run the nmap command and capture output
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout
    except Exception as e:
        return f"Error running Nmap command: {e}"

def scan_ports(target_ip):
    # Run nmap command for open ports and version detection
    nmap_output = run_nmap_command(["nmap", "-sV", target_ip])
    open_ports = []
    
    # Parse the Nmap output for open ports
    for line in nmap_output.splitlines():
        if "/tcp" in line and "open" in line:
            port_info = line.split()
            port = port_info[0].split("/")[0]
            open_ports.append(port)
    
    return open_ports, nmap_output  # Return both open ports and full Nmap output

