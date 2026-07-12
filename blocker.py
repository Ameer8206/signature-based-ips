import subprocess

blocked_ips = set()

def block_ip(ip_address):
    """Blocks a given IP address by inserting an iptables DROP rule,
    and tracks already-blocked IPs to avoid duplicate rules.""" 
    if ip_address in blocked_ips:
        print(f"[INFO] {ip_address} is already blocked.")
        return

    command = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]

    try:
        subprocess.run(command, check=True)
        blocked_ips.add(ip_address)
        print(f"[BLOCKED] IP address blocked: {ip_address}")
    except subprocess.CalledProcessError:
        print(f"[ERROR] Failed to block IP address: {ip_address}")

