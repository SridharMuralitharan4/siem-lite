import requests
import time

print("=== SIEM HTTP Agent ===")

URL = input("Enter SIEM Server URL (example: https://your-app.onrender.com): ").strip()

endpoint = f"{URL}/log"

attacks = [
    """Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
CommandLine: powershell -EncodedCommand ZQBjAGgAbwAgIkhBQ0tFRCI=""",

    """Image: C:\\Windows\\System32\\cmd.exe
CommandLine: cmd.exe /c powershell -EncodedCommand ZQBjAGgAbwAgIkhBQ0tFRCI=""",

    """Image: C:\\Windows\\explorer.exe
CommandLine: explorer.exe"""
]

i = 0

while True:
    log = attacks[i % len(attacks)]

    try:
        r = requests.post(endpoint, json={"log": log})
        print("[+] Sent:", r.json())
    except Exception as e:
        print("[!] Failed:", e)

    i += 1
    time.sleep(5)
