import os

OUI_FILE = "oui.txt"

def load_oui():
    vendors = {}
    if not os.path.exists(OUI_FILE):
        print("OUI file not found.")
        return vendors
    with open(OUI_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "(hex)" in line:
                parts = line.strip().split()
                if len(parts) >= 3:
                    mac = parts[0].replace("-", ":").upper()
                    vendor = " ".join(parts[2:])
                    vendors[mac] = vendor
    return vendors

def get_vendor(mac):
    vendors = load_oui()
    return vendors.get(":".join(mac.split(":")[:3]).upper(), "Unknown")

if __name__ == "__main__":
    mac = input("Enter MAC address: ").strip()
    print(get_vendor(mac))
