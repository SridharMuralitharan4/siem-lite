import socket
import time

HOST = "127.0.0.1"
PORT = 9999

attacks = [
    """TIME: 2026-04-20 10:12:01
PROCESS: powershell.exe -> powershell.exe -enc ZQBjAGgAbwAgAGgAYQBjAGsAZQBkAA==
[RISK SCORE] 9
HIGH ALERT
""",
    """TIME: 2026-04-20 10:13:45
PROCESS: cmd.exe -> powershell.exe -> notepad.exe
[RISK SCORE] 8
HIGH ALERT
""",
    """TIME: 2026-04-20 10:14:10
PROCESS: explorer.exe -> powershell.exe
[RISK SCORE] 5
MEDIUM ALERT
"""
]

def send_log(log):
    s = socket.socket()
    s.connect((HOST, PORT))
    s.send(log.encode())
    s.close()

i = 0
while True:
    send_log(attacks[i % len(attacks)])
    print("Sent attack log")
    i += 1
    time.sleep(5)
