from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

print("IPS Started...")
sniff(iface="enp0s3", prn=packet_callback, store=False)
