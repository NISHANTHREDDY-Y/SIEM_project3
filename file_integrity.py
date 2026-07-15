import hashlib
import os
import threading
from datetime import datetime

from config import BASE_DIR, FILE_INTEGRITY_BACKGROUND_ENABLED, FILE_INTEGRITY_SCAN_INTERVAL, FILE_INTEGRITY_TARGETS
from database import get_file_integrity_state, initialize_database, insert_alert, upsert_file_integrity_state
from recommendations import format_recommendation, get_recommendation
from utils import event_fingerprint, now_string


_monitor_thread = None
_monitor_lock = threading.Lock()
_monitor_stop = threading.Event()

initialize_database()


def _resolve_target(path):
    return path if os.path.isabs(path) else os.path.join(BASE_DIR, path)


def _hash_file(path):
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _scan_target(path):
    resolved = _resolve_target(path)
    timestamp = now_string()
    current_row = next((row for row in get_file_integrity_state() if row["path"] == resolved), None)

    if not os.path.exists(resolved):
        if current_row is None:
            upsert_file_integrity_state(resolved, "", 0, "", timestamp, "Missing")
            print(f"[FILE-INTEGRITY] Baseline missing file: {resolved}")
            return {"path": resolved, "status": "Missing", "changed": False, "size": 0, "hash": "", "last_modified": "", "last_seen": timestamp}

        if current_row["status"] != "Missing":
            threat = "File Integrity Missing"
            severity = "CRITICAL"
            recommendation = format_recommendation(threat)
            rec = get_recommendation(threat)
            alert = insert_alert(
                severity,
                f"Monitored file is missing: {resolved}",
                username="SYSTEM",
                source="File Integrity Monitor",
                recommendation=recommendation,
                threat=threat,
                computer="",
                event_id=0,
                mitre=rec["mitre"],
                alert_key=event_fingerprint("file-integrity-missing", resolved),
                timestamp=timestamp,
            )
            print(f"[FILE-INTEGRITY] Missing file alert: {resolved}")
            upsert_file_integrity_state(resolved, current_row["last_hash"], current_row["last_size"], current_row["last_modified"], timestamp, "Missing")
            return {
                "path": resolved,
                "status": "Missing",
                "changed": True,
                "alert_id": alert["id"] if alert else None,
                "size": 0,
                "hash": current_row["last_hash"],
                "last_modified": current_row["last_modified"],
                "last_seen": timestamp,
            }

        upsert_file_integrity_state(resolved, current_row["last_hash"], current_row["last_size"], current_row["last_modified"], timestamp, "Missing")
        return {
            "path": resolved,
            "status": "Missing",
            "changed": False,
            "size": 0,
            "hash": current_row["last_hash"],
            "last_modified": current_row["last_modified"],
            "last_seen": timestamp,
        }

    current_hash, current_size = _hash_file(resolved)
    last_modified = datetime.fromtimestamp(os.path.getmtime(resolved)).strftime("%Y-%m-%d %H:%M:%S")

    if current_row is None:
        upsert_file_integrity_state(resolved, current_hash, current_size, last_modified, timestamp, "Baseline")
        print(f"[FILE-INTEGRITY] Baseline captured: {resolved}")
        return {
            "path": resolved,
            "status": "Baseline",
            "changed": False,
            "size": current_size,
            "hash": current_hash,
            "last_modified": last_modified,
            "last_seen": timestamp,
        }

    if current_row["last_hash"] and current_row["last_hash"] != current_hash:
        threat = "File Integrity Modified"
        severity = "HIGH"
        recommendation = format_recommendation(threat)
        rec = get_recommendation(threat)
        alert = insert_alert(
            severity,
            f"Monitored file changed: {resolved}",
            username="SYSTEM",
            source="File Integrity Monitor",
            recommendation=recommendation,
            threat=threat,
            computer="",
            event_id=0,
            mitre=rec["mitre"],
            alert_key=event_fingerprint("file-integrity", resolved, current_hash),
            timestamp=timestamp,
        )
        print(f"[FILE-INTEGRITY] Modification detected: {resolved}")
        upsert_file_integrity_state(resolved, current_hash, current_size, last_modified, timestamp, "Modified")
        return {
            "path": resolved,
            "status": "Modified",
            "changed": True,
            "alert_id": alert["id"] if alert else None,
            "size": current_size,
            "hash": current_hash,
            "last_modified": last_modified,
            "last_seen": timestamp,
        }

    upsert_file_integrity_state(resolved, current_hash, current_size, last_modified, timestamp, "Clean")
    return {
        "path": resolved,
        "status": "Clean",
        "changed": False,
        "size": current_size,
        "hash": current_hash,
        "last_modified": last_modified,
        "last_seen": timestamp,
    }


def scan_file_integrity():
    results = []
    for target in FILE_INTEGRITY_TARGETS:
        try:
            results.append(_scan_target(target))
        except Exception as exc:
            print(f"[FILE-INTEGRITY] Error scanning {target}: {exc}")
            results.append({
                "path": _resolve_target(target),
                "status": "Error",
                "changed": False,
                "error": str(exc),
                "size": 0,
                "hash": "",
                "last_modified": "",
                "last_seen": now_string(),
            })
    return results


def _monitor_loop():
    print("[FILE-INTEGRITY] Background monitor started")
    while not _monitor_stop.is_set():
        scan_file_integrity()
        _monitor_stop.wait(FILE_INTEGRITY_SCAN_INTERVAL)
    print("[FILE-INTEGRITY] Background monitor stopped")


def start_background_file_integrity_monitor():
    global _monitor_thread
    if not FILE_INTEGRITY_BACKGROUND_ENABLED:
        print("[FILE-INTEGRITY] Background monitor disabled")
        return False

    with _monitor_lock:
        if _monitor_thread and _monitor_thread.is_alive():
            return True
        _monitor_stop.clear()
        _monitor_thread = threading.Thread(target=_monitor_loop, name="siem-file-integrity", daemon=True)
        _monitor_thread.start()
        return True


def stop_background_file_integrity_monitor():
    _monitor_stop.set()
    thread = None
    with _monitor_lock:
        thread = _monitor_thread
    if thread and thread.is_alive():
        thread.join(timeout=2)
