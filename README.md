# SIEM Project

## Overview

This is a Flask-based Windows SIEM dashboard that collects event logs, detects suspicious activity, stores alerts in SQLite, and shows the results in a web console.

Version 3 extends the original endpoint SIEM into a centralized multi-device SIEM with agent registration, heartbeat monitoring, and centralized log ingestion.

## Features

- Windows Event Log collection
- Threat detection and duplicate alert prevention
- Email alerts for MEDIUM, HIGH, and CRITICAL events
- SQLite storage
- Dashboard, Logs, Alerts, Analytics, Reports, Devices, Cases, Incidents, and more
- CSV and PDF export
- Background monitoring for several host and security signals
- Central API endpoints for agent registration, heartbeat, and log ingestion

## Requirements

- Python 3.10 or newer
- Windows
- Administrator access for reliable Security log collection

## Install

1. Open a terminal in the project folder.
2. Create a virtual environment:

```bash
python -m venv venv
```

3. Activate it:

```bash
venv\Scripts\activate
```

4. Install dependencies:

```bash
pip install -r requirements.txt
```

## Email Setup

Email alerts use Gmail SMTP with TLS and read settings from `config.py` / environment variables.

Set these before running the app:

```powershell
$env:SIEM_SMTP_SERVER="smtp.gmail.com"
$env:SIEM_SMTP_PORT="587"
$env:SIEM_SENDER_EMAIL="your-gmail-address@gmail.com"
$env:SIEM_SENDER_PASSWORD="your-16-character-gmail-app-password"
$env:SIEM_RECEIVER_EMAIL="security-team@example.com"
$env:SIEM_AGENT_API_KEY="choose-a-long-private-shared-key"
```

Optional:

```powershell
$env:SIEM_EMAIL_ENABLED="1"
$env:SIEM_AGENT_ENABLED="1"
```

## Run

Start the application with:

```bash
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

The server listens on port `5000` on all network interfaces by default. On the server computer, use its LAN address to open the dashboard from another computer, for example `http://192.168.1.10:5000`.

## Centralized Multi-System Testing

Use one Windows machine as the **SIEM server** and one or more other Windows machines as **endpoints**. All machines must be on the same trusted LAN for this test.

### 1. Start the central server

On the server computer, set one private shared agent key and start the dashboard:

```powershell
$env:SIEM_AGENT_API_KEY="choose-a-long-private-shared-key"
python app.py
```

Find the server's IPv4 LAN address:

```powershell
ipconfig
```

For example, if the IPv4 address is `192.168.1.10`, endpoints will connect to `http://192.168.1.10:5000`.

Allow incoming TCP port `5000` through Windows Firewall on the server. Do not expose this development server directly to the public internet.

### 2. Prepare an endpoint machine

Copy the project folder to a second Windows computer, create and activate its virtual environment, and install the same requirements:

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Set the server address and the **same** shared API key used by the server:

```powershell
$env:SIEM_AGENT_SERVER_ADDRESS="http://192.168.1.10:5000"
$env:SIEM_AGENT_API_KEY="choose-a-long-private-shared-key"
```

Run this command on the endpoint to verify the connection and send one harmless sample log:

```powershell
python agent.py --sample
```

The response should contain `"success": true`. In the central dashboard, open **Devices** to see the endpoint and **Logs** to see the `Agent Sample` event.

### 3. Collect real endpoint logs

Run the endpoint agent as Administrator:

```powershell
python agent.py
```

The agent registers the machine, sends a heartbeat every 30 seconds, and sends supported new Windows Event Viewer entries from the Security, System, and Application channels every 30 seconds. Stop it with `Ctrl+C`.

To generate test activity, make a normal, authorized change on the endpoint, such as starting an application, creating a local test account, or causing a failed test sign-in. Open **Logs**, **Alerts**, **Devices**, and **Agent Status** on the central dashboard to confirm that the hostname and device are recorded.

### Troubleshooting Centralized Testing

- `Connection refused` or timeout: confirm the server is running, use `http` rather than `https`, check the server IP, and allow TCP port `5000` in Windows Firewall.
- `Unauthorized`: the `SIEM_AGENT_API_KEY` value must match on the server and every endpoint.
- `pywin32 is not installed`: activate the endpoint virtual environment and run `pip install -r requirements.txt`.
- No Security events: run the endpoint PowerShell window as Administrator. The agent will still collect accessible System and Application events.

## Default Login

The app seeds local users on first run.

- Admin: `admin / admin123`
- Analyst: `analyst / analyst123`
- Viewer: `viewer / viewer123`

You can change these through the environment variables in `config.py`.

## Database

The SQLite database is created automatically at:

```text
data/siem.db
```

If you update the schema and need a fresh start, stop the app and delete that file. It will be recreated on the next launch.

## Main Pages

- Dashboard
- Logs
- Alerts
- Email History
- Reports
- Analytics
- Devices
- Incidents
- Cases
- IOC Scanner
- File Integrity
- Registry Monitor
- Process Monitor
- USB Monitor
- Network Monitor
- Sysmon
- Performance
- Users

## Notes

- Run the app as Administrator for best Security log visibility.
- If Windows Security logs do not appear, make sure the app has permission to read them.
- Email alerts are only sent for MEDIUM, HIGH, and CRITICAL alerts.
- The centralized API accepts agent traffic through `POST /api/agents/register`, `POST /api/agents/heartbeat`, and `POST /api/logs` using the shared API key.
