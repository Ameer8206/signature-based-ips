from datetime import datetime
import os

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "alerts.log")

def log_alert(attack_type, attacker_ip, target_ip="N/A"):
    os.makedirs(LOG_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_entry = (
        f"{timestamp} | {attack_type} | "
        f"Attacker: {attacker_ip} | Target: {target_ip}\n"
    )

    with open(LOG_FILE, "a") as file:
        file.write(log_entry)

    print(f"[LOGGED] {log_entry.strip()}")
