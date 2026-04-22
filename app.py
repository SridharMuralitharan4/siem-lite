from flask import Flask, render_template, request, jsonify, redirect, session
from collections import Counter, defaultdict
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = "secret123"  # simple for demo

LOG_FILE = "siem_logs.txt"

user_stats = defaultdict(lambda: {"HIGH": 0, "MEDIUM": 0, "LOW": 0})


def extract_process(data):
    lines = data.split("\n")
    image, command = "", ""

    for line in lines:
        if line.startswith("Image:"):
            image = line.replace("Image:", "").strip()
        if line.startswith("CommandLine:"):
            command = line.replace("CommandLine:", "").strip()

    return f"{image} {command}".strip()


def detect_threat(process):
    p = process.lower()

    trusted = [
        "wmiprvse.exe", "wmiadap.exe", "trustedinstaller.exe",
        "svchost.exe", "taskhostw.exe", "services.exe"
    ]

    for t in trusted:
        if t in p:
            return 1, "LOW"

    if "encodedcommand" in p or "-enc" in p:
        return 9, "HIGH"

    if "powershell" in p and "cmd" in p:
        return 8, "HIGH"

    if "powershell" in p:
        return 5, "MEDIUM"

    if "cmd.exe" in p:
        return 4, "MEDIUM"

    return 2, "LOW"


# 🔥 LOGIN PAGE
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        if username:
            session["user"] = username
            return redirect("/")
    return render_template("login.html")


# 🔥 LOG RECEIVER
@app.route("/log", methods=["POST"])
def receive_log():
    data = request.json.get("log", "")
    user = request.json.get("user", "unknown")

    process_line = extract_process(data)
    score, level = detect_threat(process_line)

    user_stats[user][level] += 1

    log_entry = f"""TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
USER: {user}
PROCESS: {process_line}
[RISK SCORE] {score}
{level} ALERT

"""

    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

    return jsonify({"status": "received"})


def parse_logs(current_user):
    events = []

    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
    except:
        return []

    current = {}

    for line in lines:
        line = line.strip()

        if line.startswith("TIME:"):
            if current and current.get("user") == current_user:
                events.append(current)
            current = {}
            current["timestamp"] = line.replace("TIME:", "").strip()

        elif line.startswith("USER:"):
            current["user"] = line.replace("USER:", "").strip()

        elif line.startswith("PROCESS:"):
            current["process"] = line.replace("PROCESS:", "").strip()

        elif "[RISK SCORE]" in line:
            score = int(line.split()[-1])
            current["score"] = score

            if score >= 7:
                current["level"] = "HIGH"
            elif score >= 4:
                current["level"] = "MEDIUM"
            else:
                current["level"] = "LOW"

    if current and current.get("user") == current_user:
        events.append(current)

    return events


# 🔥 DASHBOARD
@app.route("/")
def index():
    if "user" not in session:
        return redirect("/login")

    current_user = session["user"]

    events = parse_logs(current_user)

    high = len([e for e in events if e["level"] == "HIGH"])
    medium = len([e for e in events if e["level"] == "MEDIUM"])
    low = len([e for e in events if e["level"] == "LOW"])

    processes = [e["process"].split("\\")[-1] for e in events]
    top_processes = Counter(processes).most_common(5)

    top_threats = sorted(events, key=lambda x: x.get("score", 0), reverse=True)[:5]

    return render_template(
        "index.html",
        events=events,
        high=high,
        medium=medium,
        low=low,
        top_processes=top_processes,
        top_threats=top_threats,
        user=current_user
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
