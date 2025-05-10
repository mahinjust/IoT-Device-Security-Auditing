import subprocess
import re

def get_ttl(ip):
    try:
        result = subprocess.check_output(["ping", "-c", "1", ip], stderr=subprocess.DEVNULL).decode()
        ttl = re.search(r"ttl=(\d+)", result.lower())
        return int(ttl.group(1)) if ttl else None
    except:
        return None
    

if __name__ == "__main__":
    ip = input("Enter IP: ").strip()
    ttl = get_ttl(ip)
    print(f"TTL Value is: {ttl}")