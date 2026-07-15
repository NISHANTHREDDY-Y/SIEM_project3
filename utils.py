import hashlib
import re
from datetime import datetime

GARBAGE_USERS = {
    "",
    "-",
    "0",
    "unknown",
    "anonymous logon",
    "application-specific",
    "machine-default",
    "none",
    "null",
}

SID_RE = re.compile(r"^S-\d-\d+-(\d+-?)+$", re.IGNORECASE)
GUID_RE = re.compile(r"^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$", re.IGNORECASE)
PATH_RE = re.compile(r"(^[a-z]:\\|^\\\\|/|\.exe$|\.dll$|\.sys$)", re.IGNORECASE)


def now_string():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_timestamp(value):
    if not value:
        return now_string()
    if hasattr(value, "Format"):
        return value.Format()
    return str(value)


def clean_username(value, fallback="SYSTEM"):
    if value is None:
        return fallback

    candidate = str(value).strip().strip("'\"")
    if "\\" in candidate and not candidate.startswith("\\\\"):
        candidate = candidate.split("\\")[-1]
    if "@" in candidate and len(candidate) < 80:
        candidate = candidate.split("@")[0]

    lowered = candidate.lower()
    if lowered in GARBAGE_USERS:
        return fallback
    if SID_RE.match(candidate) or GUID_RE.match(candidate):
        return fallback
    if PATH_RE.search(candidate):
        return fallback
    if len(candidate) > 48:
        return fallback
    if not re.search(r"[a-zA-Z]", candidate):
        return fallback

    return candidate


def first_meaningful_username(values, fallback="SYSTEM"):
    priority = []
    for value in values or []:
        cleaned = clean_username(value, "")
        if not cleaned:
            continue
        if cleaned.upper() in {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}:
            priority.append(cleaned)
            continue
        return cleaned
    return priority[0] if priority else fallback


def event_fingerprint(*parts):
    text = "|".join(str(part or "") for part in parts)
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def severity_badge_class(severity):
    return f"sev-{str(severity or 'INFO').lower()}"
