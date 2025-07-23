import subprocess

def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip().lower()
    except:
        return ""

def detect_firewall(ip):
    print(f"\nScanning {ip}...\n")

    # -- ICMP Ping Test --
    print("[*] ICMP Ping Test")
    ping = run(f"ping -c 2 -W 2 {ip}")
    icmp_blocked = "0 received" in ping or "100% packet loss" in ping

    # -- UDP 53 (DNS) --
    print("[*] UDP Scan on Port 53 (DNS)")
    udp_dns = run(f"sudo nmap -sU -p 53 --reason --open {ip}")

    # -- UDP 33434 (traceroute) --
    print("[*] UDP Scan on Port 33434 (Traceroute)")
    udp_trace = run(f"sudo nmap -sU -p 33434 --reason {ip}")

    # -- TCP ACK (SPI/firewall test) --
    print("[*] TCP ACK Scan on Port 22,80,443 (SPI Firewall Detection)")
    tcp_ack = run(f"sudo nmap -sA -p 22,80,443 --reason {ip}")

    # -- TCP SYN (common ports) --
    print("[*] TCP SYN Scan on Ports 22, 80, 443")
    tcp_syn = run(f"sudo nmap -sS -p 22,80,443 --reason {ip}")

    # -- TCP NULL scan --
    print("[*] TCP NULL Scan on Port 22,80,443")
    tcp_null = run(f"sudo nmap -sN -p 22,80,443 {ip}")

    # -- TCP Xmas scan --
    print("[*] TCP Xmas Scan on Port 22,80,443")
    tcp_xmas = run(f"sudo nmap -sX -p 22,80,443 {ip}")

    # -- TCP FIN scan --
    print("[*] TCP FIN Scan on Port 22,80,443")
    tcp_fin = run(f"sudo nmap -sF -p 22,80,443 {ip}")

    # Analyze
    firewall_flags = []

    if icmp_blocked:
        firewall_flags.append("ICMP Blocked")

    if "filtered" in udp_dns or "open|filtered" in udp_dns:
        firewall_flags.append("UDP Port 53 Filtered (Possible DNS Firewall)")

    if "filtered" in udp_trace:
        firewall_flags.append("UDP Port 33434 Filtered (Traceroute Blocked)")

    if "filtered" in tcp_ack:
        firewall_flags.append("TCP ACK Filtered (SPI Firewall Possible)")

    if "filtered" in tcp_syn:
        firewall_flags.append("TCP SYN Filtered (Ports 22, 80, 443)")

    if any("filtered" in scan for scan in [tcp_null, tcp_xmas, tcp_fin]):
        firewall_flags.append("Stealth Scan Blocked (NULL/Xmas/FIN)")

    if "open" in tcp_syn and not firewall_flags:
        return "Firewall Likely Not Active"

    if firewall_flags:
        return f"Firewall Active: {', '.join(set(firewall_flags))}"

    return "Inconclusive or Silent Host"

# -------- MAIN --------
if __name__ == "__main__":
    target_ip = input("Enter Target IP: ").strip()
    result = detect_firewall(target_ip)
    print(f"\n[+] Detection Result: {result}")
