import requests

print("=== SIEM HTTP Agent ===")

URL = input("Enter SIEM Server URL: ").strip()
endpoint = f"{URL}/log"

while True:
    print("\n1. Normal Activity")
    print("2. Medium Activity")
    print("3. HIGH Attack (Encoded PowerShell)")
    print("4. Exit")

    choice = input("Select: ").strip()

    if choice == "1":
        log = """Image: C:\\Windows\\explorer.exe
CommandLine: explorer.exe"""

    elif choice == "2":
        log = """Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
CommandLine: powershell Get-Process"""

    elif choice == "3":
        log = """Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
CommandLine: powershell -EncodedCommand ZQBjAGgAbwAgIkhBQ0tFRCI="""

    elif choice == "4":
        break

    else:
        print("Invalid")
        continue

    try:
        r = requests.post(endpoint, json={"log": log})
        print("[+] Sent:", r.json())
    except Exception as e:
        print("[!] Failed:", e)
