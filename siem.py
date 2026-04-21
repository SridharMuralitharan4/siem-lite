import socket
from datetime import datetime

HOST = "0.0.0.0"
PORT = 9999

LOG_FILE = "siem_logs.txt"


def extract_process(data):
    lines = data.split("\n")

    image = ""
    command = ""

    for line in lines:
        line = line.strip()

        if line.startswith("Image:"):
            image = line.replace("Image:", "").strip()

        if line.startswith("CommandLine:"):
            command = line.replace("CommandLine:", "").strip()

    return f"{image} {command}".strip()


def detect_threat(process):
    p = process.lower()

    # ✅ ignore noise
    trusted = [
        "wmiprvse.exe",
        "wmiadap.exe",
        "trustedinstaller.exe",
        "svchost.exe",
        "taskhostw.exe",
        "services.exe"
    ]

    for t in trusted:
        if t in p:
            return 1, "LOW"

    # 🔴 HIGH
    if "encodedcommand" in p or "-enc" in p:
        return 9, "HIGH"

    if "powershell" in p and "cmd" in p:
        return 8, "HIGH"

    # 🟠 MEDIUM
    if "powershell" in p:
        return 5, "MEDIUM"

    if "cmd.exe" in p:
        return 4, "MEDIUM"

    # 🟢 LOW
    return 2, "LOW"


def handle_client(conn):
    try:
        data = conn.recv(4096).decode(errors="ignore")
    except:
        conn.close()
        return

    conn.close()

    if not data.strip():
        return

    # 🔥 extract only meaningful part
    process_line = extract_process(data)

    score, level = detect_threat(process_line)

    log_entry = f"""TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
PROCESS: {process_line}
[RISK SCORE] {score}
{level} ALERT

"""

    print(log_entry)

    with open(LOG_FILE, "a") as f:
        f.write(log_entry)


def start_server():
    s = socket.socket()
    s.bind((HOST, PORT))
    s.listen(5)

    print(f"[+] SIEM listening on {HOST}:{PORT}")

    while True:
        conn, addr = s.accept()
        handle_client(conn)


if __name__ == "__main__":
    start_server()
