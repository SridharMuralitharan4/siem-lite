# 🚨 SIEM Lite — Cloud-Based Threat Detection Dashboard

A lightweight cloud-hosted SIEM (Security Information and Event Management) system built using Python and Flask.

This project simulates real-world SOC workflows by collecting logs from distributed Windows agents, analyzing suspicious activity, classifying threats, and visualizing alerts through a live dashboard.

---

# 🔥 Features

## ✅ Log Ingestion

* Collects logs from Windows endpoints
* HTTP-based log transmission
* Distributed agent architecture
* Cloud-hosted ingestion server

## ✅ Threat Detection

* Detects suspicious PowerShell activity
* Detects encoded PowerShell commands
* Risk scoring system
* Threat classification:

  * HIGH
  * MEDIUM
  * LOW

## ✅ Dashboard & Analytics

* Real-time dashboard visualization
* Pie chart analytics
* Process frequency analytics
* Top threats section
* Per-user log tracking

## ✅ Multi-User Support

* User login system
* Session-based access
* User-specific log visibility
* Isolated dashboard views

## ✅ Attack Simulation

* Interactive attack simulation menu
* Manual trigger for:

  * Normal activity
  * Medium alerts
  * High-severity attacks

---

# 🧠 Architecture

```text
Windows Agent (sender.py)
        ↓
HTTP POST Requests
        ↓
Flask SIEM Server (Render Cloud)
        ↓
Detection Engine + Risk Scoring
        ↓
Dashboard Visualization
```

---

# ⚙️ Technologies Used

* Python
* Flask
* HTML/CSS
* Chart.js
* Render Cloud Platform
* Git & GitHub

---

# 📸 Screenshots

## 🔐 Login Page

Provides simple multi-user access control.

## 📊 SIEM Dashboard

Displays:

* Threat levels
* Real-time alerts
* Process analytics
* User activity

---

# 🚀 Deployment

The project is deployed publicly using Render.

Live Demo:

```text
https://siem-lite.onrender.com
```

---

# 📂 Project Structure

```text
siem-lite/
│
├── app.py
├── sender.py
├── requirements.txt
├── Procfile
├── siem_logs.txt
│
├── templates/
│   ├── index.html
│   └── login.html
│
└── screenshots/
    ├── dashboard.png
    └── login.png
```

---

# ▶️ Running Locally

## Clone Repository

```bash
git clone https://github.com/SridharMuralitharan4/siem-lite.git
cd siem-lite
```

## Install Requirements

```bash
pip install -r requirements.txt
```

## Run Server

```bash
python app.py
```

---

# 🛰️ Running the Agent

```bash
python sender.py
```

The agent will:

* Ask for server URL
* Ask for username
* Allow interactive attack simulation

---

# 🔥 Example Simulated Attack

```powershell
powershell -EncodedCommand ZQBjAGgAbwAgIkhBQ0tFRCI=
```

This triggers:

* HIGH alert classification
* Increased risk score
* Dashboard visualization

---

# 🎯 Learning Outcomes

This project helped in understanding:

* SIEM fundamentals
* Log ingestion pipelines
* Threat detection logic
* Risk scoring systems
* Cloud deployment workflows
* Distributed system architecture
* Multi-user dashboard design

---

# ⚠️ Disclaimer

This project is created strictly for educational and defensive cybersecurity purposes.

---

# 👨‍💻 Author

Sridhar Muralitharan

GitHub:

```text
https://github.com/SridharMuralitharan4
```
