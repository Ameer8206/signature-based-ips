from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time

INTERFACE = "enp0s3"
TIME_WINDOW = 10
PORT_THRESHOLD = 10

scan_tracker = defaultdict(list)

def packet_callback(packet):

    if packet.haslayer(IP) and packet.haslayer(TCP):

        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        current_time = time.time()

        scan_tracker[src_ip].append((dst_port, current_time))

        scan_tracker[src_ip] = [
            (port, t)
            for port, t in scan_tracker[src_ip]
            if current_time - t <= TIME_WINDOW
        ]

        unique_ports = {
            port for port, t in scan_tracker[src_ip]
        }

        print(
            f"{src_ip} -> Port {dst_port} "
            f"(Unique Ports: {len(unique_ports)})"
        )

        if src_ip == "192.168.56.3" and len(unique_ports) > PORT_THRESHOLD:

            print("\n" + "=" * 50)
            print("[ALERT] PORT SCAN DETECTED")
            print(f"ATTACKER: {src_ip}")
            print(f"PORTS SCANNED: {len(unique_ports)}")
            print("=" * 50 + "\n")

print("IPS Port Scan Detector Started...")
sniff(iface=INTERFACE, prn=packet_callback, store=False)
