import subprocess

def run_command(command):
    try:
        # Run the command and capture output
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout
    except Exception as e:
        return f"Error running command: {e}"

def scan_ports(target_ip):
    # Run command for open ports and version detection
    output = run_command(["nmap", "-sV", target_ip])

    open_ports = []
    filtered_output = []

    # First, keep the scan report, host status, and closed ports summary
    for line in output.splitlines():
        if "Nmap scan report for" in line or "Host is up" in line or "Not shown" in line:
            filtered_output.append(line)

    # Add the headers to the table
    filtered_output.append(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<20} {'VERSION':<50}")

    # Now keep only the open ports and services in a tabular format
    for line in output.splitlines():
        if "/tcp" in line and "open" in line:
            port_info = line.split()
            port = port_info[0]  # Keep full port (e.g., 2000/tcp)
            service = port_info[2]
            version = " ".join(port_info[3:])

            open_ports.append(port)
            # Format the output in a tabular format with fixed column widths
            filtered_output.append(f"{port:<10} {'open':<10} {service:<20} {version:<50}")

    # Return open ports and formatted table output
    return open_ports, '\n'.join(filtered_output)
