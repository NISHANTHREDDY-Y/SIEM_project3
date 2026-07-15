import hashlib
import json
import threading

from config import USB_BACKGROUND_ENABLED, USB_SCAN_INTERVAL, USB_TARGETS
from database import get_usb_state, initialize_database, insert_alert, upsert_usb_state
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


def _enumerate_key(root, sub_path, depth=0, max_depth=2):
    try:
        key = winreg.OpenKey(root, sub_path, 0, winreg.KEY_READ)
    except FileNotFoundError:
        return {"status": "Missing", "error": "Registry key not found"}
    except OSError as exc:
        if getattr(exc, "winerror", None) in {2, 5}:
            return {"status": "Unavailable", "error": str(exc)}
        raise

    values = {}
    value_index = 0
    while True:
        try:
            name, value, value_type = winreg.EnumValue(key, value_index)
            values[name] = {"value": value, "type": int(value_type)}
            value_index += 1
        except OSError:
            break

    items = []
    try:
        subkey_count = winreg.QueryInfoKey(key)[0]
    except OSError:
        subkey_count = 0
    if depth < max_depth:
        for idx in range(subkey_count):
            try:
                subkey_name = winreg.EnumKey(key, idx)
                child = _enumerate_key(root, f"{sub_path}\\{subkey_name}", depth + 1, max_depth)
                items.append({"name": subkey_name, "child": child})
            except OSError:
                continue
    winreg.CloseKey(key)
    return {
        "status": "OK",
        "values": values,
        "children": items,
        "subkeys": subkey_count,
    }


def _build_snapshot(path):
    root, sub_path = _parse_target(path)
    if winreg is None:
        return {"status": "Unavailable", "error": "winreg is not available on this platform"}
    if root is None:
        return {"status": "Error", "error": "Unsupported registry root"}

    tree = _enumerate_key(root, sub_path)
    if tree["status"] != "OK":
        return tree

    snapshot = json.dumps(tree, sort_keys=True, default=str)
    children = tree.get("children", [])
    return {
        "status": "OK",
        "snapshot": snapshot,
        "hash": hashlib.sha256(snapshot.encode("utf-8")).hexdigest(),
        "device_count": len(children),
        "device_names": [child["name"] for child in children],
    }


def _raise_usb_alert(path, severity, threat, detail, alert_key_suffix):
    rec = get_recommendation(threat)
    return insert_alert(
        severity,
        detail,
        username="SYSTEM",
        source="USB Monitor",
        recommendation=format_recommendation(threat),
        threat=threat,
        computer="",
        event_id=0,
        mitre=rec["mitre"],
        alert_key=event_fingerprint("usb-monitor", path, alert_key_suffix),
        timestamp=now_string(),
    )


def _scan_target(path):
    timestamp = now_string()
    current_row = next((row for row in get_usb_state() if row["path"] == path), None)
    snapshot = _build_snapshot(path)

    if snapshot["status"] != "OK":
        status = snapshot["status"]
        error = snapshot.get("error", "")
        if current_row is None:
            upsert_usb_state(path, "", 0, "", timestamp, status, error)
            print(f"[USB] Baseline unavailable: {path} ({error})")
            return {"path": path, "status": status, "device_count": 0, "last_seen": timestamp, "snapshot": "", "error": error, "changed": False}

        if current_row["status"] != status or (error and error != current_row["last_error"]):
            severity = "MEDIUM" if status == "Unavailable" else "HIGH"
            threat = "USB Monitoring Unavailable" if status == "Unavailable" else "USB Device Key Missing"
            detail = f"USB target {path} is no longer readable: {error}"
            alert = _raise_usb_alert(path, severity, threat, detail, error or status)
            print(f"[USB] Alert: {path} -> {status} ({error})")
            upsert_usb_state(path, current_row["last_hash"], current_row["device_count"], current_row["last_snapshot"], timestamp, status, error)
            return {
                "path": path,
                "status": status,
                "device_count": current_row["device_count"],
                "last_seen": timestamp,
                "snapshot": current_row["last_snapshot"],
                "error": error,
                "changed": True,
                "alert_id": alert["id"] if alert else None,
            }

        upsert_usb_state(path, current_row["last_hash"], current_row["device_count"], current_row["last_snapshot"], timestamp, status, error)
        return {
            "path": path,
            "status": status,
            "device_count": current_row["device_count"],
            "last_seen": timestamp,
            "snapshot": current_row["last_snapshot"],
            "error": error,
            "changed": False,
        }

    if current_row is None:
        upsert_usb_state(path, snapshot["hash"], snapshot["device_count"], snapshot["snapshot"], timestamp, "Baseline", "")
        print(f"[USB] Baseline captured: {path}")
        return {
            "path": path,
            "status": "Baseline",
            "device_count": snapshot["device_count"],
            "last_seen": timestamp,
            "snapshot": snapshot["snapshot"],
            "error": "",
            "changed": False,
        }

    changed = current_row["last_hash"] and current_row["last_hash"] != snapshot["hash"]
    if changed:
        direction = "Inserted" if snapshot["device_count"] > int(current_row["device_count"] or 0) else "Removed"
        threat = f"USB Device {direction}"
        severity = "HIGH" if direction == "Inserted" else "MEDIUM"
        detail = f"USB registry state changed at {path}. Device count {current_row['device_count']} -> {snapshot['device_count']}."
        alert = _raise_usb_alert(path, severity, threat, detail, snapshot["hash"])
        print(f"[USB] Change detected: {path} ({direction})")
        upsert_usb_state(path, snapshot["hash"], snapshot["device_count"], snapshot["snapshot"], timestamp, "Modified", "")
        return {
            "path": path,
            "status": "Modified",
            "device_count": snapshot["device_count"],
            "last_seen": timestamp,
            "snapshot": snapshot["snapshot"],
            "error": "",
            "changed": True,
            "alert_id": alert["id"] if alert else None,
        }

    upsert_usb_state(path, snapshot["hash"], snapshot["device_count"], snapshot["snapshot"], timestamp, "Clean", "")
    return {
        "path": path,
        "status": "Clean",
        "device_count": snapshot["device_count"],
        "last_seen": timestamp,
        "snapshot": snapshot["snapshot"],
        "error": "",
        "changed": False,
    }


def scan_usb():
    results = []
    for target in USB_TARGETS:
        try:
            results.append(_scan_target(target))
        except Exception as exc:
            print(f"[USB] Error scanning {target}: {exc}")
            results.append({
                "path": target,
                "status": "Error",
                "device_count": 0,
                "last_seen": now_string(),
                "snapshot": "",
                "error": str(exc),
                "changed": False,
            })
    return results


def _monitor_loop():
    print("[USB] Background monitor started")
    while not _monitor_stop.is_set():
        scan_usb()
        _monitor_stop.wait(USB_SCAN_INTERVAL)
    print("[USB] Background monitor stopped")


def start_background_usb_monitor():
    global _monitor_thread
    if not USB_BACKGROUND_ENABLED:
        print("[USB] Background monitor disabled")
        return False

    with _monitor_lock:
        if _monitor_thread and _monitor_thread.is_alive():
            return True
        _monitor_stop.clear()
        _monitor_thread = threading.Thread(target=_monitor_loop, name="siem-usb-monitor", daemon=True)
        _monitor_thread.start()
        return True


def stop_background_usb_monitor():
    _monitor_stop.set()
    thread = None
    with _monitor_lock:
        thread = _monitor_thread
    if thread and thread.is_alive():
        thread.join(timeout=2)
