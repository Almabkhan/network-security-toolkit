#!/usr/bin/env python3
"""
Network Scanner - Educational Tool
Scans network for live hosts and open ports
"""

import socket
import ipaddress
import threading
from datetime import datetime

class NetworkScanner:
    def __init__(self, network):
        self.network = network
        self.live_hosts = []
        self.open_ports = {}
        
    def ping_host(self, ip):
        """Check if host is alive"""
        try:
            socket.setdefaulttimeout(1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((str(ip), 80))
            sock.close()
            
            if result == 0:
                print(f"[+] Host {ip} is alive")
                self.live_hosts.append(str(ip))
                return True
        except:
            pass
        return False
    
    def scan_network(self):
        """Scan entire network for live hosts"""
        print(f"\n[*] Scanning network: {self.network}")
        print(f"[*] Started at: {datetime.now()}\n")
        
        network = ipaddress.ip_network(self.network, strict=False)
        threads = []
        
        for ip in network.hosts():
            thread = threading.Thread(target=self.ping_host, args=(ip,))
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join()
        
        print(f"\n[+] Found {len(self.live_hosts)} live hosts")
        return self.live_hosts

def main():
    print("="*60)
    print("📡 NETWORK SECURITY TOOLKIT - Network Scanner")
    print("="*60)
    
    network = input("\nEnter network (e.g., 192.168.1.0/24): ").strip()
    
    scanner = NetworkScanner(network)
    scanner.scan_network()
    
    if scanner.live_hosts:
        print("\n📊 Live Hosts:")
        for host in scanner.live_hosts:
            print(f"   • {host}")

if __name__ == "__main__":
    main()