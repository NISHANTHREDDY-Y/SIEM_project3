import csv
import hashlib
import ipaddress
import json
import re
import shutil
import subprocess
import threading

from config import NETWORK_BACKGROUND_ENABLED, NETWORK_COMMON_PORTS, NETWORK_SCAN_INTERVAL, NETWORK_SUSPICIOUS_PORTS
from database import get_network_state, initialize_database, insert_alert, upsert_network_state
from recommendations import format_recommendation, get_recommendation
from utils import event_fingerprint, now_string


_monitor_thread = None
_monitor_lock = threading.Lock()
_monitor_stop = threading.Event()

initialize_database()


def _read_netstat():
    try:
        output = subprocess.check_output(["netstat", "-ano"], text=True, encoding="utf-8", errors="replace", shell=False)
    except Exception as exc:
        return {"status": "Error", "error": str(exc), "connections": []}

    connections = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("Active Connections") or line.startswith("Proto") or line.startswith("TCP") and "State" in line:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0].upper()
        local = parts[1]
        remote = parts[2]
        if proto == "TCP" and len(parts) >= 5:
            state = parts[3].upper()
            pid = parts[4]
        elif proto == "UDP":
            state = "UDP"
            pid = parts[3]
        else:
            continue

        connections.append({
            "protocol": proto,
            "local": local,
            "remote": remote,
            "state": state,
            "pid": int(pid) if pid.isdigit() else 0,
        })
    return {"status": "OK", "error": "", "connections": connections}


def _read_process_map():
    commands = [
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-Process | Select-Object Name,Id | ConvertTo-Csv -NoTypeInformation",
        ],
        ["tasklist"],
    ]

    for command in commands:
        try:
            output = subprocess.check_output(command, text=True, encoding="utf-8", errors="replace", shell=False)
            if command[0].lower().startswith("powershell"):
                mapping = {}
                for row in csv.reader(output.splitlines()):
                    if len(row) < 2:
                        continue
                    name = row[0].strip()
                    pid = row[1].strip()
                    if pid.isdigit():
                        mapping[int(pid)] = name
                return mapping

            mapping = {}
            for line in output.splitlines():
                if not line or line.startswith("Image Name") or line.startswith("="):
                    continue
                match = re.match(r"^(?P<name>.+?)\s+(?P<pid>\d+)\s+", line)
                if match:
                    mapping[int(match.group("pid"))] = match.group("name").strip()
            return mapping
        except Exception:
            continue
    return {}


def _split_address(value):
    value = value.strip()
    if value in {"*:*", "*", "0.0.0.0:0"}:
        return "*", 0
    if value.startswith("[") and "]" in value:
        host, port = value.rsplit("]:", 1)
        return host.lstrip("["), int(port) if port.isdigit() else 0
    if ":" not in value:
        return value, 0
    host, port = value.rsplit(":", 1)
    return host, int(port) if port.isdigit() else 0


def _is_public_ip(host):
    if not host or host in {"*", "0.0.0.0", "::", "::1", "127.0.0.1"}:
        return False
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_global
    except ValueError:
        return False


def _risk_for_connection(proto, remote_host, remote_port, state):
    score = 0
    reasons = []
    threat = "Normal Network Connection"

    if state == "LISTENING":
        return "INFO", threat, "Listening locally.", 5

    if _is_public_ip(remote_host):
        score += 35
        reasons.append("External IP address detected.")
        threat = "External Network Connection"

    if remote_port in NETWORK_SUSPICIOUS_PORTS:
        score += 45
        reasons.append(f"Remote port {remote_port} is commonly abused.")
        threat = "Suspicious Network Connection"
    elif remote_port not in NETWORK_COMMON_PORTS and remote_port > 0:
        score += 15
        reasons.append(f"Remote port {remote_port} is uncommon.")

    if proto == "UDP" and _is_public_ip(remote_host):
        score += 15
        reasons.append("Public UDP traffic merits review.")

    if state == "ESTABLISHED" and score >= 35:
        score += 15
        reasons.append("Connection is active.")

    if score >= 70:
        return "CRITICAL", threat, " ".join(reasons) or "High-risk connection.", score
    if score >= 40:
        return "HIGH", threat, " ".join(reasons) or "Network connection deserves review.", score
    if score >= 20:
        return "MEDIUM", threat, " ".join(reasons) or "External traffic observed.", score
    return "INFO", threat, " ".join(reasons) or "Local connection observed.", score


def _raise_network_alert(connection, threat, severity, reason):
    process_name = connection["process_name"] or "SYSTEM"
    rec = get_recommendation(threat)
    detail = (
        f"{connection['protocol']} {connection['local_address']} -> {connection['remote_address']} "
        f"({connection['state']}) PID {connection['pid']} {reason}"
    )
    return insert_alert(
        severity,
        detail,
        username=process_name,
        source="Network Monitor",
        recommendation=format_recommendation(threat),
        threat=threat,
        computer="",
        event_id=0,
        mitre=rec["mitre"],
        alert_key=event_fingerprint(
            "network-monitor",
            connection["protocol"],
            connection["local_address"],
            connection["remote_address"],
            str(connection["pid"]),
            connection["state"],
        ),
        timestamp=now_string(),
    )


def scan_network():
    snapshot = _read_netstat()
    timestamp = now_string()
    if snapshot["status"] != "OK":
        print(f"[NETWORK] {snapshot['error']}")
        return [{
            "protocol": "N/A",
            "local_address": "",
            "local_port": 0,
            "remote_address": "",
            "remote_port": 0,
            "state": "Unavailable",
            "pid": 0,
            "process_name": "",
            "status": "Unavailable",
            "risk_level": "MEDIUM",
            "threat": "Network Monitor Unavailable",
            "reason": snapshot["error"],
            "last_seen": timestamp,
            "alerted": False,
        }]

    process_map = _read_process_map()
    existing = {row["signature"]: row for row in get_network_state()}
    results = []

    for conn in snapshot["connections"]:
        local_host, local_port = _split_address(conn["local"])
        remote_host, remote_port = _split_address(conn["remote"])
        process_name = process_map.get(conn["pid"], "")
        risk_level, threat, reason, score = _risk_for_connection(conn["protocol"], remote_host, remote_port, conn["state"])
        status = "Baseline"
        alerted = False
        signature = event_fingerprint(conn["protocol"], conn["local"], conn["remote"], conn["state"], str(conn["pid"]))
        state_row = existing.get(signature)

        if state_row is None:
            status = "Baseline"
        else:
            status = "Observed"

        last_hash = hashlib.sha256(json.dumps({
            "protocol": conn["protocol"],
            "local": conn["local"],
            "remote": conn["remote"],
            "state": conn["state"],
            "pid": conn["pid"],
            "process_name": process_name,
        }, sort_keys=True).encode("utf-8")).hexdigest()

        if risk_level in {"HIGH", "CRITICAL"} and (state_row is None or state_row["risk_level"] != risk_level):
            alert = _raise_network_alert({
                "protocol": conn["protocol"],
                "local_address": conn["local"],
                "remote_address": conn["remote"],
                "state": conn["state"],
                "pid": conn["pid"],
                "process_name": process_name,
            }, threat, risk_level, reason)
            alerted = alert is not None
            print(f"[NETWORK] Alert: {conn['protocol']} {conn['remote']} ({risk_level})")

        upsert_network_state(
            signature,
            conn["protocol"],
            conn["local"],
            local_port,
            remote_host,
            remote_port,
            conn["state"],
            conn["pid"],
            process_name,
            last_hash,
            json.dumps({
                "protocol": conn["protocol"],
                "local": conn["local"],
                "remote": conn["remote"],
                "state": conn["state"],
                "pid": conn["pid"],
                "process_name": process_name,
                "score": score,
            }, sort_keys=True),
            timestamp,
            status,
            risk_level,
            "",
        )
        results.append({
            "signature": signature,
            "protocol": conn["protocol"],
            "local_address": local_host,
            "local_port": local_port,
            "remote_address": remote_host,
            "remote_port": remote_port,
            "state": conn["state"],
            "pid": conn["pid"],
            "process_name": process_name or "Unknown",
            "status": status if risk_level == "INFO" else "Suspicious",
            "risk_level": risk_level,
            "threat": threat,
            "reason": reason,
            "last_seen": timestamp,
            "alerted": alerted,
        })

    return sorted(results, key=lambda row: (row["risk_level"] not in {"HIGH", "CRITICAL"}, row["remote_address"], row["remote_port"]))


def _monitor_loop():
    print("[NETWORK] Background monitor started")
    while not _monitor_stop.is_set():
        scan_network()
        _monitor_stop.wait(NETWORK_SCAN_INTERVAL)
    print("[NETWORK] Background monitor stopped")


def start_background_network_monitor():
    global _monitor_thread
    if not NETWORK_BACKGROUND_ENABLED:
        print("[NETWORK] Background monitor disabled")
        return False

    with _monitor_lock:
        if _monitor_thread and _monitor_thread.is_alive():
            return True
        _monitor_stop.clear()
        _monitor_thread = threading.Thread(target=_monitor_loop, name="siem-network-monitor", daemon=True)
        _monitor_thread.start()
        return True


def stop_background_network_monitor():
    _monitor_stop.set()
    thread = None
    with _monitor_lock:
        thread = _monitor_thread
    if thread and thread.is_alive():
        thread.join(timeout=2)
