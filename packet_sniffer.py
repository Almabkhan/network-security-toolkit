#!/usr/bin/env python3
"""
Packet Sniffer - Educational Tool
Captures and analyzes network packets
"""

import socket
import struct
import textwrap

class PacketSniffer:
    def __init__(self):
        self.connection = None
        
    def create_socket(self):
        """Create raw socket for packet capture"""
        try:
            self.connection = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.ntohs(3)
            )
            return True
        except:
            print("[!] Raw sockets require root/admin privileges")
            return False
    
    def parse_ethernet_header(self, packet):
        """Parse Ethernet header"""
        eth_header = packet[:14]
        eth = struct.unpack("!6s6sH", eth_header)
        
        dest_mac = ":".join(format(x, "02x") for x in eth[0])
        src_mac = ":".join(format(x, "02x") for x in eth[1])
        protocol = socket.ntohs(eth[2])
        
        return dest_mac, src_mac, protocol
    
    def parse_ip_header(self, packet):
        """Parse IP header"""
        ip_header = packet[14:34]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
        
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        ttl = iph[5]
        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dest_ip = socket.inet_ntoa(iph[9])
        
        return version, ihl, ttl, protocol, src_ip, dest_ip
    
    def start_sniffing(self, count=10):
        """Start packet capture"""
        if not self.create_socket():
            return
        
        print(f"\n[*] Starting packet capture ({count} packets)...")
        print("[*] Press Ctrl+C to stop\n")
        
        packets = []
        
        try:
            for i in range(count):
                packet, addr = self.connection.recvfrom(65536)
                
                dest_mac, src_mac, eth_proto = self.parse_ethernet_header(packet)
                
                print(f"\n📦 Packet #{i+1}")
                print(f"   Source MAC: {src_mac}")
                print(f"   Dest MAC: {dest_mac}")
                
                if eth_proto == 8:  # IP Protocol
                    version, ihl, ttl, proto, src_ip, dest_ip = self.parse_ip_header(packet)
                    
                    print(f"   Source IP: {src_ip}")
                    print(f"   Dest IP: {dest_ip}")
                    print(f"   Protocol: {proto} (TCP/UDP/ICMP)")
                    print(f"   TTL: {ttl}")
                
                packets.append(packet)
                
        except KeyboardInterrupt:
            print("\n\n[!] Stopping capture")
        
        print(f"\n[+] Captured {len(packets)} packets")
        return packets

def main():
    print("="*60)
    print("📡 NETWORK SECURITY TOOLKIT - Packet Sniffer")
    print("="*60)
    print("\n⚠️  Requires root/admin privileges!\n")
    
    sniffer = PacketSniffer()
    
    try:
        count = int(input("Number of packets to capture (default 10): ") or "10")
        sniffer.start_sniffing(count)
    except ValueError:
        print("[!] Invalid input")

if __name__ == "__main__":
    main()