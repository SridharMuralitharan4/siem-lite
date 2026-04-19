import socket
import re
from datetime import datetime
from collections import defaultdict

HOST = "0.0.0.0"
PORT = 9999

log_file = "siem_logs.txt"

# Track seen events (to prevent duplicates)
seen_events = set()

# Stats
stats = {
    "high": 0,
    "medium": 0,
    "low": 0,
    "total": 0
}

process_count = defaultdict(int)
parent_count = defaultdict(int)
chain_count = defaultdict(int)

# -----------------------------
# Timestamp Extraction
# -----------------------------
def extract_timestamp(log_block):
    match = re.search(r'utctime:\s*([0-9\-:\. ]+)', log_block.lower())
    if match:
        try:
            return datetime.strptime(match.group(1).strip(), "%Y-%m-%d %H:%M:%S.%f")
        except:
            return datetime.now()
    return datetime.now()

# -----------------------------
# Extract Process Info
# -----------------------------
def extract_process_info(log):
    image = re.search(r'image:\s*(.*)', log, re.IGNORECASE)
    parent = re.search(r'parentimage:\s*(.*)', log, re.IGNORECASE)

    image = image.group(1).strip() if image else "unknown"
    parent = parent.group(1).strip() if parent else "unknown"

    return image.lower(), parent.lower()

# -----------------------------
# Risk Scoring
# -----------------------------
def calculate_risk(image, parent, log):
    score = 0
    reasons = []

    if "powershell.exe" in image:
        score += 1
        reasons.append("PowerShell activity (+1)")

    if "powershell.exe" in parent:
        score += 2
        reasons.append("Script engine parent (+2)")

    if "powershell" in parent and "notepad.exe" in image:
        score += 1
        reasons.append("PowerShell spawning process (+1)")

    if "temp" in image or "appdata" in image:
        score += 2
        reasons.append("Suspicious path (+2)")

    if "system32" in parent and ("users" in image or "appdata" in image):
        score += 2
        reasons.append("System -> user path (+2)")

    return score, reasons

# -----------------------------
# Classify Risk
# -----------------------------
def classify(score):
    if score >= 7:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    else:
        return "LOW"

# -----------------------------
# Save to File
# -----------------------------
def save_event(timestamp, process, parent, score, level, chain):
    with open(log_file, "a") as f:
        f.write(f"\nTIME: {timestamp}\n")
        f.write(f"PROCESS: {parent} -> {process}\n")
        f.write(f"[CHAIN] {chain}\n")
        f.write(f"[RISK SCORE] {score}\n")
        f.write(f"{level} ALERT\n")
        f.write("="*40 + "\n")

# -----------------------------
# Process Logs
# -----------------------------
def process_log(data):
    global stats

    timestamp = extract_timestamp(data)
    image, parent = extract_process_info(data)

    # Dedup key
    event_id = f"{parent}->{image}"
    if event_id in seen_events:
        return
    seen_events.add(event_id)

    score, reasons = calculate_risk(image, parent, data)
    level = classify(score)

    # Update stats
    stats["total"] += 1
    stats[level.lower()] += 1

    process_count[image] += 1
    parent_count[parent] += 1

    chain = f"{parent} -> {image}"
    chain_count[chain] += 1

    # Console output
    print("\n--- PROCESS CHAINS ---")
    print(f"PROCESS: {parent} -> {image}")

    for r in reasons:
        print(f"[+] {r}")

    print(f"[RISK SCORE] {score}")
    print(f"{level} ALERT")
    print("="*40)

    # Save
    save_event(timestamp, image, parent, score, level, chain)

# -----------------------------
# Dashboard Print
# -----------------------------
def print_dashboard():
    print("\n===== SIEM DASHBOARD =====")
    print(f"Total Events: {stats['total']}")
    print(f"High Alerts: {stats['high']}")
    print(f"Medium Alerts: {stats['medium']}")
    print(f"Low Events: {stats['low']}")

    print("\n--- TOP PROCESSES ---")
    for k, v in sorted(process_count.items(), key=lambda x: x[1], reverse=True)[:3]:
        print(f"{k} : {v}")

    print("\n--- TOP PARENTS ---")
    for k, v in sorted(parent_count.items(), key=lambda x: x[1], reverse=True)[:3]:
        print(f"{k} : {v}")

    print("\n--- TOP CHAINS ---")
    for k, v in sorted(chain_count.items(), key=lambda x: x[1], reverse=True)[:3]:
        print(f"{k} : {v}")

# -----------------------------
# Server
# -----------------------------
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)

    print("[+] SIEM Listener started... Waiting for logs...")

    while True:
        conn, addr = server.accept()
        print(f"\n[+] Connection from {addr}")

        data = conn.recv(65535).decode(errors="ignore")
        conn.close()

        process_log(data)
        print_dashboard()

# -----------------------------
# Run
# -----------------------------
if __name__ == "__main__":
    start_server()
