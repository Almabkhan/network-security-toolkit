#!/usr/bin/env python3
"""
Port Scanner - Educational Tool
Scans open ports on target host
"""

import socket
import sys
from datetime import datetime

class PortScanner:
    def __init__(self, target):
        self.target = target
        self.open_ports = []
        
    def scan_port(self, port):
        """Scan single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                service = self.get_service_name(port)
                print(f"[+] Port {port}: OPEN ({service})")
                self.open_ports.append(port)
        except:
            pass
    
    def get_service_name(self, port):
        """Get common service name"""
        services = {
            20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
            445: "SMB", 993: "IMAPS", 995: "POP3S", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt"
        }
        return services.get(port, "Unknown")
    
    def scan_common_ports(self):
        """Scan most common ports"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
                        443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900,
                        6379, 8080, 8443, 27017]
        
        print(f"\n[*] Scanning target: {self.target}")
        print(f"[*] Started at: {datetime.now()}\n")
        
        for port in common_ports:
            self.scan_port(port)
        
        print(f"\n[+] Found {len(self.open_ports)} open ports")
        return self.open_ports
    
    def scan_port_range(self, start, end):
        """Scan range of ports"""
        print(f"\n[*] Scanning target: {self.target}")
        print(f"[*] Scanning ports: {start}-{end}")
        print(f"[*] Started at: {datetime.now()}\n")
        
        for port in range(start, end + 1):
            self.scan_port(port)
        
        print(f"\n[+] Found {len(self.open_ports)} open ports")
        return self.open_ports

def main():
    print("="*60)
    print("📡 NETWORK SECURITY TOOLKIT - Port Scanner")
    print("="*60)
    
    target = input("\nEnter target IP: ").strip()
    
    print("\n📌 Options:")
    print("1. Scan common ports")
    print("2. Scan port range")
    
    choice = input("\nEnter choice (1-2): ").strip()
    
    scanner = PortScanner(target)
    
    if choice == "1":
        scanner.scan_common_ports()
    elif choice == "2":
        start = int(input("Enter start port: "))
        end = int(input("Enter end port: "))
        scanner.scan_port_range(start, end)
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()