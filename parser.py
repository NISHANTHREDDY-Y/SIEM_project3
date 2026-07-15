from utils import clean_username


def parse_log(log_line):
    parts = log_line.strip().split()
    if len(parts) < 3:
        return None

    timestamp = " ".join(parts[:2]) if len(parts) > 3 else parts[0]
    event_type = parts[2] if len(parts) > 3 else parts[1]
    data = {
        "timestamp": timestamp,
        "event_type": event_type,
        "username": "SYSTEM",
        "source": "Imported",
        "severity": "INFO",
        "computer": "",
        "channel": "Imported",
        "event_id": 0,
        "message": log_line.strip(),
        "raw_event": log_line.strip(),
    }

    for item in parts[3:]:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        key = key.lower().strip()
        value = value.strip()
        if key in {"user", "username", "account"}:
            data["username"] = clean_username(value)
        elif key in {"ip", "source", "host", "computer"}:
            data["source"] = value
            data["computer"] = value
        elif key in {"severity", "level"}:
            data["severity"] = value.upper()
        elif key in {"event_id", "eventid", "id"} and value.isdigit():
            data["event_id"] = int(value)

    return data
