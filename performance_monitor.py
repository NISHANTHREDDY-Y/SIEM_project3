import json
import subprocess
import threading

from config import (
    PERFORMANCE_BACKGROUND_ENABLED,
    PERFORMANCE_CPU_CRITICAL,
    PERFORMANCE_CPU_HIGH,
    PERFORMANCE_DISK_CRITICAL,
    PERFORMANCE_DISK_HIGH,
    PERFORMANCE_MEMORY_CRITICAL_MB,
    PERFORMANCE_MEMORY_LOW_MB,
    PERFORMANCE_SCAN_INTERVAL,
)
from database import get_performance_state, initialize_database, insert_alert, upsert_performance_state
from recommendations import format_recommendation, get_recommendation
from utils import event_fingerprint, now_string


_monitor_thread = None
_monitor_lock = threading.Lock()
_monitor_stop = threading.Event()

initialize_database()


def _get_counters():
    command = (
        "$counters = @("
        "'\\Processor(_Total)\\% Processor Time',"
        "'\\Memory\\Available MBytes',"
        "'\\PhysicalDisk(_Total)\\% Disk Time',"
        "'\\Network Interface(*)\\Bytes Total/sec'"
        ");"
        "Get-Counter -Counter $counters -SampleInterval 1 -MaxSamples 1 | "
        "Select-Object -ExpandProperty CounterSamples | "
        "Select-Object Path,CookedValue | ConvertTo-Json -Compress"
    )

    try:
        output = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", command],
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
        )
    except Exception as exc:
        return {"status": "Error", "error": str(exc), "samples": []}

    if not output.strip():
        return {"status": "Error", "error": "No performance counter output", "samples": []}

    try:
        parsed = json.loads(output)
    except Exception as exc:
        return {"status": "Error", "error": f"Failed to parse performance counters: {exc}", "samples": []}

    if isinstance(parsed, dict):
        parsed = [parsed]

    return {"status": "OK", "error": "", "samples": parsed}


def _safe_float(value):
    try:
        return float(value)
    except Exception:
        return 0.0


def _normalize_path(path):
    lowered = str(path or "").lower()
    if lowered.startswith("\\\\"):
        parts = lowered.split("\\", 3)
        if len(parts) >= 4:
            return "\\" + parts[3]
    return lowered


def _cpu_status(value):
    if value >= PERFORMANCE_CPU_CRITICAL:
        return "Critical"
    if value >= PERFORMANCE_CPU_HIGH:
        return "High"
    return "Normal"


def _memory_status(value):
    if value <= PERFORMANCE_MEMORY_CRITICAL_MB:
        return "Critical"
    if value <= PERFORMANCE_MEMORY_LOW_MB:
        return "High"
    return "Normal"


def _disk_status(value):
    if value >= PERFORMANCE_DISK_CRITICAL:
        return "Critical"
    if value >= PERFORMANCE_DISK_HIGH:
        return "High"
    return "Normal"


def _network_status(value):
    if value >= 100_000_000:
        return "High"
    if value >= 25_000_000:
        return "Medium"
    return "Normal"


def _raise_performance_alert(metric, severity, detail, threshold):
    threat = f"Performance {metric}"
    rec = get_recommendation(threat)
    return insert_alert(
        severity,
        detail,
        username="SYSTEM",
        source="Performance Monitor",
        recommendation=format_recommendation(threat),
        threat=threat,
        computer="",
        event_id=0,
        mitre=rec["mitre"],
        alert_key=event_fingerprint("performance-monitor", metric, threshold),
        timestamp=now_string(),
    )


def scan_performance():
    snapshot = _get_counters()
    timestamp = now_string()
    if snapshot["status"] != "OK":
        print(f"[PERFORMANCE] {snapshot['error']}")
        return [{
            "metric": "Performance Monitor",
            "value": 0,
            "unit": "",
            "status": "Unavailable",
            "detail": snapshot["error"],
            "threshold": "",
            "last_seen": timestamp,
            "alerted": False,
        }]

    samples = snapshot["samples"]
    sample_map = {}
    for sample in samples:
        path = _normalize_path(sample.get("Path", ""))
        sample_map[path] = _safe_float(sample.get("CookedValue", 0))

    cpu = sample_map.get(r"\processor(_total)\% processor time", 0.0)
    memory_available = sample_map.get(r"\memory\available mbytes", 0.0)
    disk = sample_map.get(r"\physicaldisk(_total)\% disk time", 0.0)
    network_samples = [value for path, value in sample_map.items() if path.startswith(r"\network interface(") and path.endswith(r"\bytes total/sec")]
    network_total = sum(network_samples)

    metrics = [
        {
            "metric": "CPU",
            "value": cpu,
            "unit": "%",
            "status": _cpu_status(cpu),
            "detail": f"Processor load is {cpu:.1f}%",
            "threshold": f"{PERFORMANCE_CPU_HIGH:.0f}% / {PERFORMANCE_CPU_CRITICAL:.0f}%",
        },
        {
            "metric": "Memory",
            "value": memory_available,
            "unit": "MB",
            "status": _memory_status(memory_available),
            "detail": f"{memory_available:.0f} MB available",
            "threshold": f"{PERFORMANCE_MEMORY_LOW_MB:.0f}MB / {PERFORMANCE_MEMORY_CRITICAL_MB:.0f}MB",
        },
        {
            "metric": "Disk",
            "value": disk,
            "unit": "%",
            "status": _disk_status(disk),
            "detail": f"Disk busy time is {disk:.1f}%",
            "threshold": f"{PERFORMANCE_DISK_HIGH:.0f}% / {PERFORMANCE_DISK_CRITICAL:.0f}%",
        },
        {
            "metric": "Network",
            "value": network_total,
            "unit": "B/s",
            "status": _network_status(network_total),
            "detail": f"Estimated throughput is {network_total:,.0f} B/s",
            "threshold": "25MB/s / 100MB/s",
        },
    ]

    results = []
    for item in metrics:
        alerted = False
        severity = "INFO"
        if item["metric"] == "CPU" and item["status"] in {"High", "Critical"}:
            severity = "HIGH" if item["status"] == "High" else "CRITICAL"
        elif item["metric"] == "Memory" and item["status"] in {"High", "Critical"}:
            severity = "HIGH" if item["status"] == "High" else "CRITICAL"
        elif item["metric"] == "Disk" and item["status"] in {"High", "Critical"}:
            severity = "HIGH" if item["status"] == "High" else "CRITICAL"

        if severity != "INFO":
            alert = _raise_performance_alert(
                item["metric"],
                severity,
                f"{item['metric']} performance warning: {item['detail']}",
                item["threshold"],
            )
            alerted = alert is not None
            print(f"[PERFORMANCE] Alert: {item['metric']} {item['status']}")

        upsert_performance_state(
            item["metric"],
            item["value"],
            item["unit"],
            item["status"],
            item["detail"],
            item["threshold"],
            timestamp,
            "",
        )
        results.append({
            **item,
            "last_seen": timestamp,
            "alerted": alerted,
        })

    return results


def _monitor_loop():
    print("[PERFORMANCE] Background monitor started")
    while not _monitor_stop.is_set():
        scan_performance()
        _monitor_stop.wait(PERFORMANCE_SCAN_INTERVAL)
    print("[PERFORMANCE] Background monitor stopped")


def start_background_performance_monitor():
    global _monitor_thread
    if not PERFORMANCE_BACKGROUND_ENABLED:
        print("[PERFORMANCE] Background monitor disabled")
        return False

    with _monitor_lock:
        if _monitor_thread and _monitor_thread.is_alive():
            return True
        _monitor_stop.clear()
        _monitor_thread = threading.Thread(target=_monitor_loop, name="siem-performance-monitor", daemon=True)
        _monitor_thread.start()
        return True


def stop_background_performance_monitor():
    _monitor_stop.set()
    thread = None
    with _monitor_lock:
        thread = _monitor_thread
    if thread and thread.is_alive():
        thread.join(timeout=2)
