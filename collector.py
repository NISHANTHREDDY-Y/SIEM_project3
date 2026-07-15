import threading
import time
import socket
from datetime import datetime

try:
    import win32evtlog
except ImportError:
    win32evtlog = None

from config import (
    COLLECTOR_BACKGROUND_ENABLED,
    COLLECTOR_CHANNELS,
    COLLECTOR_LIMIT_PER_CHANNEL,
    COLLECTOR_SCAN_INTERVAL,
    SYSMON_CHANNEL,
    SYSMON_SUPPORT_ENABLED,
)
from database import (
    get_collector_health,
    get_collector_status,
    get_logs,
    insert_log,
    update_collector_health,
    update_collector_state_with_stats,
)
from detector import detect_threats
from utils import first_meaningful_username, normalize_timestamp

SUPPORTED_EVENTS = {
    4624: ("Successful Login", "INFO"),
    4625: ("Failed Login", "MEDIUM"),
    4634: ("User Logoff", "INFO"),
    4647: ("User Initiated Logoff", "INFO"),
    4672: ("Privilege Escalation", "HIGH"),
    4688: ("Process Created", "LOW"),
    4689: ("Process Exited", "INFO"),
    4697: ("Service Installed", "HIGH"),
    4698: ("Scheduled Task Created", "MEDIUM"),
    4702: ("Scheduled Task Updated", "MEDIUM"),
    4719: ("Audit Policy Changed", "HIGH"),
    4720: ("New User", "HIGH"),
    4722: ("User Enabled", "MEDIUM"),
    4723: ("Password Change Attempt", "MEDIUM"),
    4724: ("Password Reset Attempt", "HIGH"),
    4725: ("User Disabled", "MEDIUM"),
    4726: ("Deleted User", "HIGH"),
    4732: ("Group Membership Changes", "HIGH"),
    4740: ("Account Locked", "HIGH"),
    4768: ("Kerberos TGT Request", "INFO"),
    4769: ("Kerberos Service Ticket", "INFO"),
    4771: ("Kerberos Failure", "MEDIUM"),
    4776: ("NTLM Authentication", "LOW"),
    5140: ("Network Share Access", "LOW"),
    5156: ("Firewall Allowed Connection", "INFO"),
    5158: ("Firewall Bound Port", "LOW"),
    6005: ("System Startup", "INFO"),
    6006: ("System Shutdown", "INFO"),
    6008: ("Unexpected Shutdown", "HIGH"),
    7031: ("Service Crash", "MEDIUM"),
    7034: ("Service Crash", "MEDIUM"),
    7045: ("New Service Installed", "HIGH"),
    1000: ("Application Crash", "MEDIUM"),
    1001: ("Application Hang", "LOW"),
    1026: (".NET Runtime Exception", "MEDIUM"),
    1102: ("Audit Log Cleared", "CRITICAL"),
}

SYSMON_EVENTS = {
    1: ("Sysmon Process Create", "MEDIUM"),
    3: ("Sysmon Network Connection", "MEDIUM"),
    5: ("Sysmon Process Terminated", "INFO"),
    7: ("Sysmon Image Loaded", "LOW"),
    11: ("Sysmon File Created", "LOW"),
    12: ("Sysmon Registry Object Added/Deleted", "HIGH"),
    13: ("Sysmon Registry Value Set", "HIGH"),
    22: ("Sysmon DNS Query", "MEDIUM"),
    23: ("Sysmon File Deleted", "HIGH"),
    25: ("Sysmon Process Tampering", "CRITICAL"),
}

_collector_thread = None
_collector_lock = threading.Lock()
_scan_lock = threading.Lock()
_collector_stop = threading.Event()


def _event_payload(event, channel):
    event_id = event.EventID & 0xFFFF
    if channel == SYSMON_CHANNEL and event_id in SYSMON_EVENTS:
        event_type, severity = SYSMON_EVENTS[event_id]
    else:
        event_type, severity = SUPPORTED_EVENTS[event_id]
    strings = list(getattr(event, "StringInserts", []) or [])
    username = first_meaningful_username(strings)
    computer = getattr(event, "ComputerName", "") or ""
    hostname = computer or socket.gethostname()
    device_id = hostname or computer or "local-endpoint"
    message = " | ".join(str(item) for item in strings if item)
    return {
        "timestamp": normalize_timestamp(event.TimeGenerated),
        "event_type": event_type,
        "username": username,
        "source": channel,
        "severity": severity,
        "computer": computer,
        "hostname": hostname,
        "device_id": device_id,
        "ip_address": "",
        "agent_version": "server-collector",
        "channel": channel,
        "event_id": event_id,
        "message": message[:4000],
        "raw_event": message[:8000],
        "record_number": getattr(event, "RecordNumber", 0) or 0,
    }


def _channels_to_scan():
    channels = list(COLLECTOR_CHANNELS)
    if SYSMON_SUPPORT_ENABLED and SYSMON_CHANNEL not in channels:
        channels.append(SYSMON_CHANNEL)
    return channels


def collect_windows_logs_once():
    with _scan_lock:
        started_at = datetime.now()
        per_channel = {}
        total_inserted = 0
        total_seen = 0
        errors = 0
        last_error = ""

        if win32evtlog is None:
            msg = "pywin32 is not available"
            update_collector_health("Unavailable", 0, started_at.strftime("%Y-%m-%d %H:%M:%S"), 0, 0, 1, msg)
            return {"status": "unavailable", "message": msg, "collected": 0, "errors": 1}

        state = {row["channel"]: row["last_record_number"] for row in get_collector_status()}

        for channel in _channels_to_scan():
            last_seen = state.get(channel, 0) or 0
            max_record = last_seen
            inserted = 0
            seen = 0
            handle = None
            channel_error = ""
            try:
                handle = win32evtlog.OpenEventLog(None, channel)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                while seen < COLLECTOR_LIMIT_PER_CHANNEL:
                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                    if not events:
                        break
                    for event in events:
                        record_number = getattr(event, "RecordNumber", 0) or 0
                        if record_number <= last_seen:
                            continue
                        event_id = event.EventID & 0xFFFF
                        if event_id not in SUPPORTED_EVENTS:
                            continue
                        payload = _event_payload(event, channel)
                        if insert_log(**payload):
                            inserted += 1
                            total_inserted += 1
                        total_seen += 1
                        seen += 1
                        max_record = max(max_record, record_number)
                        if seen >= COLLECTOR_LIMIT_PER_CHANNEL:
                            break
            except Exception as exc:
                channel_error = str(exc)
                last_error = channel_error
                if channel != SYSMON_CHANNEL:
                    errors += 1
                per_channel[channel] = {"inserted": inserted, "seen": seen, "error": str(exc), "last_record_number": max_record}
            finally:
                if handle is not None:
                    try:
                        win32evtlog.CloseEventLog(handle)
                    except Exception:
                        pass
                update_collector_state_with_stats(channel, max_record, inserted, channel_error)
                per_channel.setdefault(channel, {"inserted": inserted, "seen": seen, "last_record_number": max_record})

        duration_seconds = max((datetime.now() - started_at).total_seconds(), 0.001)
        events_per_minute = (total_seen / duration_seconds) * 60.0
        status = "Running" if errors == 0 else "RunningWithErrors"
        update_collector_health(
            status,
            1,
            started_at.strftime("%Y-%m-%d %H:%M:%S"),
            duration_seconds,
            events_per_minute,
            errors,
            last_error,
        )

        return {
            "status": status,
            "collected": total_inserted,
            "seen": total_seen,
            "errors": errors,
            "last_error": last_error,
            "channels": per_channel,
            "started_at": started_at.strftime("%Y-%m-%d %H:%M:%S"),
            "events_per_minute": events_per_minute,
            "duration_seconds": duration_seconds,
        }


def collect_windows_logs():
    return collect_windows_logs_once()


def get_collector_health_snapshot():
    row = get_collector_health()
    if row is None:
        return {
            "status": "Stopped",
            "running": 0,
            "last_scan": "",
            "last_duration": 0,
            "events_per_minute": 0,
            "errors": 0,
            "last_error": "",
            "updated_at": "",
        }
    return dict(row)


def _collector_loop():
    update_collector_health("Running", 1, "", 0, 0, 0, "")
    while not _collector_stop.is_set():
        try:
            collect_windows_logs_once()
            detect_threats(get_logs(500))
        except Exception as exc:
            update_collector_health("RunningWithErrors", 1, "", 0, 0, 1, str(exc))
        _collector_stop.wait(COLLECTOR_SCAN_INTERVAL)
    update_collector_health("Stopped", 0, "", 0, 0, 0, "")


def start_background_collector():
    global _collector_thread
    if not COLLECTOR_BACKGROUND_ENABLED:
        update_collector_health("Disabled", 0, "", 0, 0, 0, "")
        return False

    with _collector_lock:
        if _collector_thread and _collector_thread.is_alive():
            return True
        _collector_stop.clear()
        _collector_thread = threading.Thread(target=_collector_loop, name="siem-collector", daemon=True)
        _collector_thread.start()
        return True


def stop_background_collector():
    _collector_stop.set()
    thread = None
    with _collector_lock:
        thread = _collector_thread
    if thread and thread.is_alive():
        thread.join(timeout=2)
