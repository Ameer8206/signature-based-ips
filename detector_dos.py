from scapy.all import sniff, IP
from collections import defaultdict
import time

INTERFACE = "enp0s3"
ATTACKER_IP = "192.168.56.3"
VICTIM_IP = "192.168.56.2"

DOS_THRESHOLD = 50
TIME_WINDOW = 5

packet_count = defaultdict(list)

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        current_time = time.time()

        packet_count[src_ip].append(current_time)

        packet_count[src_ip] = [
            t for t in packet_count[src_ip]
            if current_time - t <= TIME_WINDOW
        ]

        count = len(packet_count[src_ip])

        print(f"Packet from {src_ip} to {dst_ip} | Count: {count}")

        if src_ip == ATTACKER_IP and dst_ip == VICTIM_IP and count > DOS_THRESHOLD:
            print("\n" + "=" * 50)
            print("[ALERT] DOS ATTACK DETECTED")
            print(f"ATTACKER IP: {src_ip}")
            print(f"TARGET IP: {dst_ip}")
            print(f"PACKETS IN {TIME_WINDOW} SECONDS: {count}")
            print("=" * 50 + "\n")

print("IPS DoS Detector Started...")
sniff(iface=INTERFACE, prn=packet_callback, store=False)
