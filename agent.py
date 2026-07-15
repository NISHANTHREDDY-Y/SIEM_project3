"""Lightweight Windows endpoint agent for the centralized SIEM server."""

import argparse
import json
import platform
import socket
import time
import urllib.error
import urllib.request

try:
    import win32evtlog
except ImportError:
    win32evtlog = None

from config import AGENT_API_KEY, AGENT_DEFAULT_INTERVAL, AGENT_HEARTBEAT_INTERVAL, AGENT_SERVER_ADDRESS, APP_VERSION
from utils import first_meaningful_username, normalize_timestamp, now_string

SUPPORTED_EVENTS = {
    4624: ("Successful Login", "INFO"), 4625: ("Failed Login", "MEDIUM"),
    4672: ("Privilege Escalation", "HIGH"), 4688: ("Process Created", "LOW"),
    4697: ("Service Installed", "HIGH"), 4698: ("Scheduled Task Created", "MEDIUM"),
    4719: ("Audit Policy Changed", "HIGH"), 4720: ("New User", "HIGH"),
    4724: ("Password Reset Attempt", "HIGH"), 4726: ("Deleted User", "HIGH"),
    4740: ("Account Locked", "HIGH"), 6008: ("Unexpected Shutdown", "HIGH"),
    7031: ("Service Crash", "MEDIUM"), 7034: ("Service Crash", "MEDIUM"),
    7045: ("New Service Installed", "HIGH"), 1000: ("Application Crash", "MEDIUM"),
    1001: ("Application Hang", "LOW"), 1026: (".NET Runtime Exception", "MEDIUM"),
    1102: ("Audit Log Cleared", "CRITICAL"),
}
CHANNELS = ("Security", "System", "Application")
_last_record_numbers = {}


def _local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except socket.gaierror:
        return ""


def _identity(hostname=None, device_id=None, ip_address="", mac_address="", operating_system=""):
    hostname = hostname or socket.gethostname()
    return {
        "hostname": hostname, "computer_name": hostname, "device_id": device_id or hostname,
        "ip_address": ip_address or _local_ip(), "mac_address": mac_address,
        "operating_system": operating_system or f"{platform.system()} {platform.release()}",
        "agent_version": APP_VERSION,
    }


def _request(path, payload, timeout=15):
    url = AGENT_SERVER_ADDRESS.rstrip("/") + path
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json", "X-API-Key": AGENT_API_KEY},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def register_agent(**identity):
    payload = _identity(**identity)
    payload["registered_at"] = now_string()
    return _request("/api/agents/register", payload)


def send_heartbeat(**identity):
    payload = _identity(**identity)
    payload["heartbeat_at"] = now_string()
    return _request("/api/agents/heartbeat", payload)


def send_logs(logs, **identity):
    payload = _identity(**identity)
    payload["logs"] = list(logs or [])
    payload["sent_at"] = now_string()
    return _request("/api/logs", payload)


def collect_windows_events(limit_per_channel=75):
    """Read only supported new Windows Event Viewer entries from this endpoint."""
    if win32evtlog is None:
        raise RuntimeError("pywin32 is not installed. Run: pip install -r requirements.txt")

    events_to_send = []
    hostname = socket.gethostname()
    for channel in CHANNELS:
        handle = None
        try:
            handle = win32evtlog.OpenEventLog(None, channel)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            last_record = _last_record_numbers.get(channel, 0)
            highest_record = last_record
            seen = 0
            while seen < limit_per_channel:
                batch = win32evtlog.ReadEventLog(handle, flags, 0)
                if not batch:
                    break
                for event in batch:
                    record_number = getattr(event, "RecordNumber", 0) or 0
                    if record_number <= last_record:
                        continue
                    highest_record = max(highest_record, record_number)
                    event_id = event.EventID & 0xFFFF
                    if event_id not in SUPPORTED_EVENTS:
                        continue
                    event_type, severity = SUPPORTED_EVENTS[event_id]
                    inserts = list(getattr(event, "StringInserts", []) or [])
                    message = " | ".join(str(item) for item in inserts if item)
                    events_to_send.append({
                        "timestamp": normalize_timestamp(event.TimeGenerated), "event_id": event_id,
                        "event_type": event_type, "severity": severity,
                        "username": first_meaningful_username(inserts), "source": channel,
                        "channel": channel, "computer": getattr(event, "ComputerName", "") or hostname,
                        "hostname": hostname, "device_id": hostname, "record_number": record_number,
                        "message": message[:4000], "raw_event": message[:8000],
                    })
                    seen += 1
                    if seen >= limit_per_channel:
                        break
            _last_record_numbers[channel] = highest_record
        except Exception as exc:
            print(f"[AGENT] Cannot read {channel}: {exc}")
        finally:
            if handle is not None:
                try:
                    win32evtlog.CloseEventLog(handle)
                except Exception:
                    pass
    return events_to_send


def send_sample_payload():
    return send_logs([{
        "timestamp": now_string(), "event_type": "Agent Sample", "username": "SYSTEM",
        "source": "Agent", "severity": "INFO", "message": "Sample payload from a centralized SIEM endpoint.",
        "event_id": 0,
    }])


def run_agent():
    print(f"[AGENT] Starting endpoint agent. Server: {AGENT_SERVER_ADDRESS}")
    try:
        print(f"[AGENT] Registered: {register_agent()}")
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"[AGENT] Registration failed: {exc}")

    next_heartbeat = 0
    while True:
        try:
            now = time.monotonic()
            if now >= next_heartbeat:
                print(f"[AGENT] Heartbeat: {send_heartbeat()}")
                next_heartbeat = now + AGENT_HEARTBEAT_INTERVAL
            logs = collect_windows_events()
            if logs:
                result = send_logs(logs)
                print(f"[AGENT] Sent {len(logs)} event(s): {result}")
            else:
                print("[AGENT] No new supported Windows events.")
        except (urllib.error.URLError, TimeoutError) as exc:
            print(f"[AGENT] Server connection failed: {exc}")
        except Exception as exc:
            print(f"[AGENT] Collection error: {exc}")
        time.sleep(AGENT_DEFAULT_INTERVAL)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SIEM centralized endpoint agent")
    parser.add_argument("--sample", action="store_true", help="Send one sample event and exit")
    args = parser.parse_args()
    try:
        if args.sample:
            print(send_sample_payload())
        else:
            run_agent()
    except KeyboardInterrupt:
        print("\n[AGENT] Stopped.")
