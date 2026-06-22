from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time

INTERFACE = "enp0s3"

ATTACKER_IP = "192.168.56.3"
VICTIM_IP = "192.168.56.2"

DOS_THRESHOLD = 50
DOS_TIME_WINDOW = 5

PORT_SCAN_THRESHOLD = 10
PORT_SCAN_TIME_WINDOW = 10

packet_count = defaultdict(list)
scan_tracker = defaultdict(list)

def detect_dos(src_ip, dst_ip):
    current_time = time.time()

    packet_count[src_ip].append(current_time)

    packet_count[src_ip] = [
        t for t in packet_count[src_ip]
        if current_time - t <= DOS_TIME_WINDOW
    ]

    count = len(packet_count[src_ip])

    if src_ip == ATTACKER_IP and dst_ip == VICTIM_IP and count > DOS_THRESHOLD:
        print("\n" + "=" * 50)
        print("[ALERT] DOS ATTACK DETECTED")
        print(f"ATTACKER IP: {src_ip}")
        print(f"TARGET IP: {dst_ip}")
        print(f"PACKETS IN {DOS_TIME_WINDOW} SECONDS: {count}")
        print("=" * 50 + "\n")

def detect_port_scan(packet, src_ip):
    current_time = time.time()
    dst_port = packet[TCP].dport

    scan_tracker[src_ip].append((dst_port, current_time))

    scan_tracker[src_ip] = [
        (port, t)
        for port, t in scan_tracker[src_ip]
        if current_time - t <= PORT_SCAN_TIME_WINDOW
    ]

    unique_ports = {port for port, t in scan_tracker[src_ip]}

    if src_ip == ATTACKER_IP and len(unique_ports) > PORT_SCAN_THRESHOLD:
        print("\n" + "=" * 50)
        print("[ALERT] PORT SCAN DETECTED")
        print(f"ATTACKER IP: {src_ip}")
        print(f"PORTS SCANNED: {len(unique_ports)}")
        print("=" * 50 + "\n")

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        print(f"Packet from {src_ip} to {dst_ip}")

        detect_dos(src_ip, dst_ip)

        if packet.haslayer(TCP):
            detect_port_scan(packet, src_ip)

print("Combined IPS Detector Started...")
sniff(iface=INTERFACE, prn=packet_callback, store=False)
