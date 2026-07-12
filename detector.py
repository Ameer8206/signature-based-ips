from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time
from blocker import block_ip
from logger import log_alert

logged_dos = set()
logged_portscan = set()

INTERFACE = "enp0s3"
ATTACKER_IP = "192.168.56.3"
VICTIM_IP = "192.168.56.2"
DOS_THRESHOLD = 50
DOS_TIME_WINDOW = 5
PORT_SCAN_THRESHOLD = 10
PORT_SCAN_TIME_WINDOW = 10

packet_count = defaultdict(list)
scan_tracker = defaultdict(list)


def detect_dos(packet, src_ip, dst_ip):
    """Detects DoS flooding by tracking SYN packet rate from the attacker to the victim
    within a rolling time window, and triggers a block if the threshold is exceeded."""
    if not packet.haslayer(TCP):
        return
    if src_ip != ATTACKER_IP or dst_ip != VICTIM_IP or packet[TCP].flags != "S":
        return

    current_time = time.time()
    flow_key = (src_ip, dst_ip)
    packet_count[flow_key].append(current_time)
    packet_count[flow_key] = [
        t for t in packet_count[flow_key]
        if current_time - t <= DOS_TIME_WINDOW
    ]
    count = len(packet_count[flow_key])

    if count > DOS_THRESHOLD and src_ip not in logged_dos:
        logged_dos.add(src_ip)
        block_ip(src_ip)
        log_alert("DOS ATTACK", src_ip, dst_ip)
        print("\n" + "=" * 50)
        print("[ALERT] DOS ATTACK DETECTED")
        print(f"ATTACKER IP: {src_ip}")
        print(f"TARGET IP: {dst_ip}")
        print(f"SYN PACKETS IN {DOS_TIME_WINDOW} SECONDS: {count}")
        print("=" * 50 + "\n")


def detect_port_scan(packet, src_ip):
    """Detects port scanning by tracking the number of unique destination ports
    contacted by a source IP within a rolling time window."""
    if not packet.haslayer(TCP):
        return

    current_time = time.time()
    dst_port = packet[TCP].dport
    scan_tracker[src_ip].append((dst_port, current_time))
    scan_tracker[src_ip] = [
        (port, t)
        for port, t in scan_tracker[src_ip]
        if current_time - t <= PORT_SCAN_TIME_WINDOW
    ]
    unique_ports = {port for port, t in scan_tracker[src_ip]}

    if src_ip == ATTACKER_IP and len(unique_ports) > PORT_SCAN_THRESHOLD and src_ip not in logged_portscan:
        logged_portscan.add(src_ip)
        block_ip(src_ip)
        log_alert("PORT SCAN", src_ip, VICTIM_IP)
        print("\n" + "=" * 50)
        print("[ALERT] PORT SCAN DETECTED")
        print(f"ATTACKER IP: {src_ip}")
        print(f"PORTS SCANNED: {len(unique_ports)}")
        print("=" * 50 + "\n")


def packet_callback(packet):
      """Callback invoked for every sniffed packet; extracts IP info and runs
    both DoS and port scan detection checks."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Packet from {src_ip} to {dst_ip}")
        detect_dos(packet, src_ip, dst_ip)
        if packet.haslayer(TCP):
            detect_port_scan(packet, src_ip)


print("Combined IPS Detector Started...")
sniff(iface=INTERFACE, prn=packet_callback, store=False)
