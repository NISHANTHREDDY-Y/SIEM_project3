import csv
import hashlib
import json
import shutil
import subprocess
import threading

from config import PROCESS_BACKGROUND_ENABLED, PROCESS_SCAN_INTERVAL, PROCESS_SUSPICIOUS_NAMES
from database import get_process_state, initialize_database, insert_alert, upsert_process_state
from recommendations import format_recommendation, get_recommendation
from utils import event_fingerprint, now_string


_monitor_thread = None
_monitor_lock = threading.Lock()
_monitor_stop = threading.Event()

initialize_database()

SUSPICIOUS_HINTS = {
    "powershell.exe": ("PowerShell Abuse", "HIGH"),
    "cmd.exe": ("Command Shell Spawn", "MEDIUM"),
    "wmic.exe": ("WMIC Execution", "HIGH"),
    "rundll32.exe": ("Suspicious Rundll32", "HIGH"),
    "psexec.exe": ("Remote Execution Tool", "CRITICAL"),
    "mshta.exe": ("HTA Execution", "CRITICAL"),
    "cscript.exe": ("Script Host Execution", "HIGH"),
    "wscript.exe": ("Script Host Execution", "HIGH"),
    "regsvr32.exe": ("Regsvr32 Abuse", "HIGH"),
}


def _process_running():
    return shutil.which("tasklist") is not None


def _read_processes():
    commands = [
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-Process | Select-Object Name,Id,Path | ConvertTo-Csv -NoTypeInformation",
        ],
        ["tasklist", "/fo", "csv", "/nh"],
    ]

    output = None
    last_error = ""
    for command in commands:
        try:
            output = subprocess.check_output(
                command,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
            )
            break
        except Exception as exc:
            last_error = str(exc)

    if output is None:
        if not _process_running():
            return {"status": "Unavailable", "error": "No supported process listing command available", "processes": []}
        return {"status": "Error", "error": last_error or "Process listing failed", "processes": []}

    processes = []
    for row in csv.reader(output.splitlines()):
        if len(row) < 2:
            continue
        name = row[0].strip()
        pid = row[1].strip()
        processes.append({
            "name": name,
            "pid": int(pid) if pid.isdigit() else 0,
            "user": "",
            "command_line": row[2].strip() if len(row) > 2 else "",
            "window_title": "",
        })
    return {"status": "OK", "error": "", "processes": processes}


def _is_suspicious(process):
    lowered = process["name"].lower()
    hint = SUSPICIOUS_HINTS.get(lowered)
    if hint:
        return hint
    if lowered in PROCESS_SUSPICIOUS_NAMES:
        return ("Suspicious Process", "HIGH")
    if process["window_title"] and any(token in process["window_title"].lower() for token in ("powershell", "cmd", "script", "vbs")):
        return ("Suspicious Window Title", "MEDIUM")
    return None


def _raise_process_alert(process, threat, severity, reason):
    rec = get_recommendation(threat)
    detail = f"{process['name']} (PID {process['pid']}) detected. {reason}"
    alert = insert_alert(
        severity,
        detail,
        username=process["user"] or "SYSTEM",
        source="Process Monitor",
        recommendation=format_recommendation(threat),
        threat=threat,
        computer="",
        event_id=0,
        mitre=rec["mitre"],
        alert_key=event_fingerprint("process-monitor", process["name"].lower(), str(process["pid"])),
        timestamp=now_string(),
    )
    return alert


def scan_processes():
    snapshot = _read_processes()
    timestamp = now_string()
    if snapshot["status"] != "OK":
        print(f"[PROCESS] {snapshot['error']}")
        return [{
            "name": "Process Monitor",
            "pid": 0,
            "user": "",
            "command_line": "",
            "window_title": "",
            "status": snapshot["status"],
            "severity": "MEDIUM",
            "threat": "Process Monitor Unavailable",
            "reason": snapshot["error"],
            "last_seen": timestamp,
            "alerted": False,
        }]

    existing = {row["name"]: row for row in get_process_state()}
    results = []
    for process in snapshot["processes"]:
        suspicious = _is_suspicious(process)
        state = existing.get(process["name"])
        status = "Running"
        severity = "INFO"
        threat = ""
        reason = "Currently running."
        alerted = False

        if suspicious:
            threat, severity = suspicious
            status = "Suspicious"
            reason = f"Matches watchlist: {process['name']}."
            if state is None or int(state["last_pid"]) != int(process["pid"]):
                alert = _raise_process_alert(process, threat, severity, reason)
                alerted = alert is not None
                print(f"[PROCESS] Alert: {process['name']} ({process['pid']})")

        hash_basis = json.dumps(process, sort_keys=True)
        last_hash = hashlib.sha256(hash_basis.encode("utf-8")).hexdigest()
        previous_status = state["status"] if state else "Baseline"
        occurrences = (state["occurrences"] if state else 0) + 1
        upsert_process_state(
            process["name"],
            process["pid"],
            process["command_line"] or process["window_title"] or "",
            timestamp,
            status if suspicious else "Running",
            occurrences,
            process["user"] or "",
            "",
        )
        results.append({
            "name": process["name"],
            "pid": process["pid"],
            "user": process["user"] or "",
            "command_line": process["command_line"] or "",
            "window_title": process["window_title"] or "",
            "status": status if suspicious else ("Baseline" if previous_status == "Baseline" else "Running"),
            "severity": severity,
            "threat": threat or "Normal Process",
            "reason": reason,
            "last_seen": timestamp,
            "hash": last_hash,
            "alerted": alerted,
        })
    return sorted(results, key=lambda row: (row["status"] != "Suspicious", row["name"].lower()))


def _monitor_loop():
    print("[PROCESS] Background monitor started")
    while not _monitor_stop.is_set():
        scan_processes()
        _monitor_stop.wait(PROCESS_SCAN_INTERVAL)
    print("[PROCESS] Background monitor stopped")


def start_background_process_monitor():
    global _monitor_thread
    if not PROCESS_BACKGROUND_ENABLED:
        print("[PROCESS] Background monitor disabled")
        return False

    with _monitor_lock:
        if _monitor_thread and _monitor_thread.is_alive():
            return True
        _monitor_stop.clear()
        _monitor_thread = threading.Thread(target=_monitor_loop, name="siem-process-monitor", daemon=True)
        _monitor_thread.start()
        return True


def stop_background_process_monitor():
    _monitor_stop.set()
    thread = None
    with _monitor_lock:
        thread = _monitor_thread
    if thread and thread.is_alive():
        thread.join(timeout=2)
