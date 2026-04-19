import sys

LOG_FILE = "siem_logs.txt"


def read_logs():
    try:
        with open(LOG_FILE, "r") as f:
            return f.read().split("========================================")
    except:
        print("No log file found.")
        return []


def extract_process(log):
    for line in log.split("\n"):
        if line.startswith("PROCESS:"):
            return line.strip()
    return None


def filter_logs(level):
    logs = read_logs()
    filtered = []
    seen = set()

    for log in logs:
        process = extract_process(log)

        if not process or process in seen:
            continue

        if level.lower() in log.lower():
            filtered.append(log)
            seen.add(process)

    return filtered


def show_logs(logs):
    if not logs:
        print("No matching logs found.\n")
        return

    for log in logs:
        print(log.strip())
        print("=" * 40)


def summary():
    logs = read_logs()

    unique_events = {}
    
    for log in logs:
        process = extract_process(log)

        if not process:
            continue

        # store latest version of that process event
        unique_events[process] = log.lower()

    high = 0
    medium = 0
    low = 0

    for log in unique_events.values():
        if "high alert" in log:
            high += 1
        elif "medium alert" in log:
            medium += 1
        elif "low" in log:
            low += 1

    print("\n====== LOG SUMMARY (UNIQUE EVENTS) ======")
    print(f"High Alerts  : {high}")
    print(f"Medium Alerts: {medium}")
    print(f"Low Events   : {low}")
    print("========================================\n")


def help_menu():
    print("""
Usage:
  python3 viewer.py all        → Show all unique logs
  python3 viewer.py high       → Show HIGH alerts
  python3 viewer.py medium     → Show MEDIUM alerts
  python3 viewer.py low        → Show LOW events
  python3 viewer.py summary    → Show summary
""")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        help_menu()
        sys.exit()

    cmd = sys.argv[1].lower()

    if cmd == "all":
        logs = filter_logs("")  # show all unique
        show_logs(logs)

    elif cmd in ["high", "medium", "low"]:
        logs = filter_logs(cmd)
        show_logs(logs)

    elif cmd == "summary":
        summary()

    else:
        help_menu()
