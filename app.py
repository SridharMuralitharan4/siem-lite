from flask import Flask, render_template, request
from collections import Counter
from datetime import datetime
import os

app = Flask(__name__)

LOG_FILE = "siem_logs.txt"


def parse_logs():
    events = []
    seen = set()

    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
    except:
        return []

    current = {}

    for line in lines:
        line = line.strip()

        if line.startswith("TIME:"):
            if current:
                key = (current.get("process"), current.get("timestamp"))
                if key not in seen:
                    events.append(current)
                    seen.add(key)
            current = {}
            current["timestamp"] = line.replace("TIME:", "").strip()

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

    if current:
        key = (current.get("process"), current.get("timestamp"))
        if key not in seen:
            events.append(current)

    return events


@app.route("/")
def index():
    query = request.args.get("q", "").lower()
    level_filter = request.args.get("level")

    events = parse_logs()

    if query:
        events = [e for e in events if query in e["process"].lower()]

    if level_filter:
        events = [e for e in events if e["level"] == level_filter]

    high = len([e for e in events if e["level"] == "HIGH"])
    medium = len([e for e in events if e["level"] == "MEDIUM"])
    low = len([e for e in events if e["level"] == "LOW"])

    process_names = [e["process"].split("\\")[-1] for e in events]
    process_count = Counter(process_names)
    top_processes = process_count.most_common(5)

    top_threats = sorted(events, key=lambda x: x.get("score", 0), reverse=True)[:5]

    return render_template(
        "index.html",
        events=events,
        high=high,
        medium=medium,
        low=low,
        query=query,
        top_processes=top_processes,
        top_threats=top_threats
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
