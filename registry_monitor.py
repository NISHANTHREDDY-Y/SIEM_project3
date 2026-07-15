import hashlib
import json
import threading

from config import REGISTRY_BACKGROUND_ENABLED, REGISTRY_SCAN_INTERVAL, REGISTRY_TARGETS
from database import get_registry_state, initialize_database, insert_alert, upsert_registry_state
from recommendations import format_recommendation, get_recommendation
from utils import event_fingerprint, now_string


try:
    import winreg
except ImportError:
    winreg = None


_monitor_thread = None
_monitor_lock = threading.Lock()
_monitor_stop = threading.Event()

initialize_database()

_ROOTS = {
    "HKCU": getattr(winreg, "HKEY_CURRENT_USER", None) if winreg else None,
    "HKLM": getattr(winreg, "HKEY_LOCAL_MACHINE", None) if winreg else None,
}


def _parse_target(path):
    if "\\" not in path:
        return None, None
    root_name, sub_path = path.split("\\", 1)
    return _ROOTS.get(root_name.upper()), sub_path


def _read_key_snapshot(path):
    root, sub_path = _parse_target(path)
    if winreg is None:
        return {"status": "Unavailable", "error": "winreg is not available on this platform"}
    if root is None:
        return {"status": "Error", "error": "Unsupported registry root"}

    try:
        key = winreg.OpenKey(root, sub_path, 0, winreg.KEY_READ)
    except FileNotFoundError:
        return {"status": "Missing", "error": "Registry key not found"}
    except OSError as exc:
        if getattr(exc, "winerror", None) in {2, 5}:
            return {"status": "Unavailable", "error": str(exc)}
        raise

    values = {}
    index = 0
    while True:
        try:
            name, value, value_type = winreg.EnumValue(key, index)
            values[name] = {"value": value, "type": int(value_type)}
            index += 1
        except OSError:
            break
    try:
        subkeys = winreg.QueryInfoKey(key)[0]
    except OSError:
        subkeys = 0
    winreg.CloseKey(key)
    snapshot = json.dumps({"values": values, "subkeys": subkeys}, sort_keys=True, default=str)
    return {
        "status": "OK",
        "snapshot": snapshot,
        "hash": hashlib.sha256(snapshot.encode("utf-8")).hexdigest(),
        "value_count": len(values),
        "subkeys": subkeys,
    }


def _raise_registry_alert(path, severity, threat, detail, alert_key_suffix):
    rec = get_recommendation(threat)
    alert = insert_alert(
        severity,
        detail,
        username="SYSTEM",
        source="Registry Monitor",
        recommendation=format_recommendation(threat),
        threat=threat,
        computer="",
        event_id=0,
        mitre=rec["mitre"],
        alert_key=event_fingerprint("registry-monitor", path, alert_key_suffix),
        timestamp=now_string(),
    )
    return alert


def _scan_target(path):
    timestamp = now_string()
    current_row = next((row for row in get_registry_state() if row["path"] == path), None)
    snapshot = _read_key_snapshot(path)

    if snapshot["status"] != "OK":
        status = snapshot["status"]
        error = snapshot.get("error", "")
        if current_row is None:
            upsert_registry_state(path, "", 0, "", timestamp, status, error)
            print(f"[REGISTRY] Baseline unavailable: {path} ({error})")
            return {"path": path, "status": status, "changed": False, "last_seen": timestamp, "value_count": 0, "snapshot": "", "error": error}

        if current_row["status"] != status or (error and error != current_row["last_error"]):
            severity = "MEDIUM" if status == "Unavailable" else "HIGH"
            threat = "Registry Access Failure" if status == "Unavailable" else "Registry Key Missing"
            detail = f"Registry target {path} is no longer readable: {error}"
            alert = _raise_registry_alert(path, severity, threat, detail, error or status)
            print(f"[REGISTRY] Alert: {path} -> {status} ({error})")
            upsert_registry_state(path, current_row["last_hash"], current_row["value_count"], current_row["last_snapshot"], timestamp, status, error)
            return {
                "path": path,
                "status": status,
                "changed": True,
                "last_seen": timestamp,
                "value_count": current_row["value_count"],
                "snapshot": current_row["last_snapshot"],
                "error": error,
                "alert_id": alert["id"] if alert else None,
            }

        upsert_registry_state(path, current_row["last_hash"], current_row["value_count"], current_row["last_snapshot"], timestamp, status, error)
        return {
            "path": path,
            "status": status,
            "changed": False,
            "last_seen": timestamp,
            "value_count": current_row["value_count"],
            "snapshot": current_row["last_snapshot"],
            "error": error,
        }

    if current_row is None:
        upsert_registry_state(path, snapshot["hash"], snapshot["value_count"], snapshot["snapshot"], timestamp, "Baseline", "")
        print(f"[REGISTRY] Baseline captured: {path}")
        return {
            "path": path,
            "status": "Baseline",
            "changed": False,
            "last_seen": timestamp,
            "value_count": snapshot["value_count"],
            "snapshot": snapshot["snapshot"],
            "error": "",
        }

    if current_row["last_hash"] and current_row["last_hash"] != snapshot["hash"]:
        threat = "Registry Modified"
        severity = "HIGH"
        detail = f"Registry target changed: {path}"
        alert = _raise_registry_alert(path, severity, threat, detail, snapshot["hash"])
        print(f"[REGISTRY] Modification detected: {path}")
        upsert_registry_state(path, snapshot["hash"], snapshot["value_count"], snapshot["snapshot"], timestamp, "Modified", "")
        return {
            "path": path,
            "status": "Modified",
            "changed": True,
            "last_seen": timestamp,
            "value_count": snapshot["value_count"],
            "snapshot": snapshot["snapshot"],
            "error": "",
            "alert_id": alert["id"] if alert else None,
        }

    upsert_registry_state(path, snapshot["hash"], snapshot["value_count"], snapshot["snapshot"], timestamp, "Clean", "")
    return {
        "path": path,
        "status": "Clean",
        "changed": False,
        "last_seen": timestamp,
        "value_count": snapshot["value_count"],
        "snapshot": snapshot["snapshot"],
        "error": "",
    }


def scan_registry():
    results = []
    for target in REGISTRY_TARGETS:
        try:
            results.append(_scan_target(target))
        except Exception as exc:
            print(f"[REGISTRY] Error scanning {target}: {exc}")
            results.append({
                "path": target,
                "status": "Error",
                "changed": False,
                "last_seen": now_string(),
                "value_count": 0,
                "snapshot": "",
                "error": str(exc),
            })
    return results


def _monitor_loop():
    print("[REGISTRY] Background monitor started")
    while not _monitor_stop.is_set():
        scan_registry()
        _monitor_stop.wait(REGISTRY_SCAN_INTERVAL)
    print("[REGISTRY] Background monitor stopped")


def start_background_registry_monitor():
    global _monitor_thread
    if not REGISTRY_BACKGROUND_ENABLED:
        print("[REGISTRY] Background monitor disabled")
        return False

    with _monitor_lock:
        if _monitor_thread and _monitor_thread.is_alive():
            return True
        _monitor_stop.clear()
        _monitor_thread = threading.Thread(target=_monitor_loop, name="siem-registry-monitor", daemon=True)
        _monitor_thread.start()
        return True


def stop_background_registry_monitor():
    _monitor_stop.set()
    thread = None
    with _monitor_lock:
        thread = _monitor_thread
    if thread and thread.is_alive():
        thread.join(timeout=2)
