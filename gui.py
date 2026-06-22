import tkinter as tk
from tkinter import ttk
import os

LOG_FILE = "logs/alerts.log"

root = tk.Tk()
root.title("Signature-Based IPS Dashboard")
root.geometry("900x500")
root.configure(bg="#0f172a")

title = tk.Label(
    root,
    text="Signature-Based Intrusion Prevention System",
    font=("Arial", 20, "bold"),
    bg="#0f172a",
    fg="#38bdf8"
)
title.pack(pady=15)

status_frame = tk.Frame(root, bg="#0f172a")
status_frame.pack(pady=5)

status_label = tk.Label(
    status_frame,
    text="STATUS: MONITORING ACTIVE",
    font=("Arial", 13, "bold"),
    bg="#16a34a",
    fg="white",
    padx=20,
    pady=8
)
status_label.pack()
summary_frame = tk.Frame(root, bg="#0f172a")
summary_frame.pack(pady=10)

dos_label = tk.Label(summary_frame, text="DOS Attacks: 0", bg="#7f1d1d", fg="white", font=("Arial", 11, "bold"), padx=15, pady=6)
dos_label.pack(side="left", padx=8)

scan_label = tk.Label(summary_frame, text="Port Scans: 0", bg="#1e3a8a", fg="white", font=("Arial", 11, "bold"), padx=15, pady=6)
scan_label.pack(side="left", padx=8)

total_label = tk.Label(summary_frame, text="Total Alerts: 0", bg="#334155", fg="white", font=("Arial", 11, "bold"), padx=15, pady=6)
total_label.pack(side="left", padx=8)

table_frame = tk.Frame(root, bg="#0f172a")
table_frame.pack(fill="both", expand=True, padx=20, pady=20)

columns = ("time", "attack", "attacker", "target", "status")

tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=12)

tree.heading("time", text="Time")
tree.heading("attack", text="Attack Type")
tree.heading("attacker", text="Attacker IP")
tree.heading("target", text="Target IP")
tree.heading("status", text="Status")

tree.column("time", width=160)
tree.column("attack", width=160)
tree.column("attacker", width=150)
tree.column("target", width=150)
tree.column("status", width=120)

tree.tag_configure("dos", background="#7f1d1d", foreground="#fee2e2")
tree.tag_configure("portscan", background="#1e3a8a", foreground="#dbeafe")
tree.tag_configure("normal", background="#1e293b", foreground="white")
tree.pack(fill="both", expand=True)

style = ttk.Style()
style.theme_use("clam")
style.configure(
    "Treeview",
    background="#1e293b",
    foreground="white",
    rowheight=28,
    fieldbackground="#1e293b",
    font=("Arial", 11)
)
style.configure(
    "Treeview.Heading",
    background="#2563eb",
    foreground="white",
    font=("Arial", 11, "bold")
)

summary_label = tk.Label(
    root,
    text="Waiting for security events...",
    font=("Arial", 11),
    bg="#0f172a",
    fg="#cbd5e1"
)
summary_label.pack(pady=10)

seen_lines = set()

def load_alerts():
    global seen_lines

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as file:
            lines = file.readlines()

        for line in lines:
            if line not in seen_lines:
                seen_lines.add(line)

                parts = line.strip().split("|")

                if len(parts) >= 4:
                    time_value = parts[0].strip()
                    attack_type = parts[1].strip()
                    attacker = parts[2].replace("Attacker:", "").strip()
                    target = parts[3].replace("Target:", "").strip()

                if "DOS" in attack_type.upper():
                    tag = "dos"
                elif "PORT" in attack_type.upper() or "SCAN" in attack_type.upper():
                    tag = "portscan"
                else:
                    tag = "normal"

                tree.insert(
                    "",
                    "end",
                    values=(time_value, attack_type, attacker, target, "BLOCKED"),
                    tags=(tag,)
                )


        total_alerts = len(seen_lines)
        dos_count = sum(1 for line in seen_lines if "DOS" in line.upper())
        scan_count = sum(1 for line in seen_lines if "PORT" in line.upper() or "SCAN" in line.upper())

        dos_label.config(text=f"DOS Attacks: {dos_count}")
        scan_label.config(text=f"Port Scans: {scan_count}")
        total_label.config(text=f"Total Alerts: {len(seen_lines)}")
        summary_label.config(
            text=f"Total Alerts Logged: {total_alerts} | Last Updated Automatically"
        )

    root.after(2000, load_alerts)

load_alerts()
root.mainloop()
