# 🔐 SIEM-lite: Real-Time Log Monitoring & Threat Detection

A lightweight SIEM (Security Information and Event Management) system built using Python and Flask to simulate real-world security monitoring.

---

## 🚀 Features

- 📡 Real-time log ingestion via socket listener
- 🔗 Process chain correlation
- ⚠️ Risk scoring engine (Low / Medium / High)
- 📊 Interactive dashboard (Flask + Chart.js)
- 🔍 Search & filter logs
- 📈 Analytics (Top processes, alert distribution)
- 🧠 Threat summary (Top threats detection)

---

## 🛠️ Tech Stack

- Python
- Flask
- Chart.js
- Linux (Ubuntu VM)

---

## 🧪 How It Works

1. `siem.py` listens for incoming logs from a Windows machine
2. Logs are parsed and risk-scored
3. Events are stored in `siem_logs.txt`
4. `app.py` reads logs and serves dashboard UI
5. `viewer.py` allows CLI-based log inspection

---

## ▶️ Setup & Run

```bash
# create virtual env
python3 -m venv siem-env
source siem-env/bin/activate

# install dependencies
pip install -r requirements.txt

# run SIEM listener
python3 siem.py

# run dashboard
python3 app.py



#open
http://127.0.0.1:5000
