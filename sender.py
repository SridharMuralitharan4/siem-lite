import requests

print("=== SIEM HTTP Agent ===")

URL = input("Enter SIEM Server URL: ").strip()
USER = input("Enter your user name (example: user1): ").strip()

endpoint = f"{URL}/log"

while True:
    print("\n1. Normal")
    print("2. Medium")
    print("3. HIGH Attack")
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
        continue

    try:
        r = requests.post(endpoint, json={"log": log, "user": USER})
        print("[+] Sent:", r.json())
    except Exception as e:
        print("[!] Failed:", e)
