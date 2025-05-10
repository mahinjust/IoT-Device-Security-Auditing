import os
import getPorts

def main():
    getIP = input("Enter IP address: ")
    getPorts.scan_port(getIP)  # This function prints its output


if __name__ == "__main__":
    main()
