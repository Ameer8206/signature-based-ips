from scapy.all import sniff, IP
from collections import defaultdict
import time

INTERFACE = "enp0s3"
DOS_THRESHOLD = 50
TIME_WINDOW = 5

packet_count = defaultdict(list)

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        current_time = time.time()

        packet_count[src_ip].append(current_time)

        packet_count[src_ip] = [
            t for t in packet_count[src_ip]
            if current_time - t <= TIME_WINDOW
        ]

        print(f"Packet from {src_ip} | Count: {len(packet_count[src_ip])}")

        if len(packet_count[src_ip]) > DOS_THRESHOLD:
            print("\n[ALERT] Possible DoS attack detected!")
            print(f"Attacker IP: {src_ip}\n")

print("IPS DoS Detector Started...")
sniff(iface=INTERFACE, prn=packet_callback, store=False)
