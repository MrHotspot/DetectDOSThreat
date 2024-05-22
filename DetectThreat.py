from scapy.all import sniff, IPv6, IP, TCP
from collections import defaultdict
import time
import re

syn_packets = defaultdict(list)

def detect_dos_attack(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        tcp_flags = packet[TCP].flags
        if tcp_flags == 'S':
            current_time = time.time()
            syn_packets[ip_src].append(current_time)
            syn_packets[ip_src] = [timestamp for timestamp in syn_packets[ip_src] if current_time - timestamp < 10]
            if len(syn_packets[ip_src]) > 5:
                print(f"ALERT: Potential DoS attack detected from {ip_src} - multiple SYN packets in 10 seconds.")
    elif packet.haslayer(IPv6) and packet.haslayer(TCP):
        ip_src = packet[IPv6].src
        tcp_flags = packet[TCP].flags
        if tcp_flags == 'S':
            current_time = time.time()
            syn_packets[ip_src].append(current_time)
            syn_packets[ip_src] = [timestamp for timestamp in syn_packets[ip_src] if current_time - timestamp < 10]
            if len(syn_packets[ip_src]) > 5:
                print(f"ALERT: Potential DoS attack detected from {ip_src} - multiple SYN packets in 10 seconds.")

def start_sniffing(interface):
    print(f"Starting packet sniffing on {interface}...")
    sniff(filter="tcp", iface=interface, prn=detect_dos_attack, store=0)

if __name__ == "__main__":
    print("╔════════════════════════════════════════════════════════════════╗")
    print("║                Welcome to Detect Threat v1.0                   ║")
    print("║                          Made by YS                            ║")
    print("║              ██████ PRESS ENTER TO CONTINUE ██████             ║")
    print("╚════════════════════════════════════════════════════════════════╝")
    input()

    while True:
        interface = input("Please enter the network interface: ")
        if re.search("[a-zA-Z]", interface) and re.search("[0-9]", interface):
            break
        else:
            print("Invalid input. The interface name must contain both letters and numbers.")
    start_sniffing(interface)
