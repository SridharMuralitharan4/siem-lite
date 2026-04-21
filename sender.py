import socket
import time

# 🔧 CHANGE THIS to your server IP (Ubuntu or VPS later)
HOST = "127.0.0.1"
PORT = 9999

def send_log(data):
    try:
        s = socket.socket()
        s.connect((HOST, PORT))
        s.send(data.encode())
        s.close()
    except Exception as e:
        print("Connection failed:", e)


while True:
    # 🔥 Example simulated log
    log = f"""
TIME: {time.strftime("%Y-%m-%d %H:%M:%S")}
PROCESS: powershell.exe -> cmd.exe
[RISK SCORE] 8
HIGH ALERT
"""

    send_log(log)
    print("Log sent...")
    time.sleep(5)
