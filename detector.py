from collections import Counter, defaultdict

import json

from database import create_incident, get_alert_by_id, get_connection, insert_alert, get_incidents
from email_alert import send_email_alert
from recommendations import format_recommendation, get_recommendation
from utils import event_fingerprint, now_string


def _event_id(log):
    try:
        return int(log["event_id"] or 0)
    except Exception:
        return 0


def _text(log):
    return f"{log['event_type']} {log['message'] if 'message' in log.keys() else ''}".lower()


def _rule_for_log(log):
    event_id = _event_id(log)
    event = log["event_type"]
    username = log["username"] or "SYSTEM"
    text = _text(log)

    rules = {
        4624: ("Successful Login", "INFO"),
        4625: ("Failed Login", "MEDIUM"),
        4672: ("Privilege Escalation", "HIGH"),
        4719: ("Audit Policy Changed", "HIGH"),
        4720: ("New User", "HIGH"),
        4722: ("User Enabled", "MEDIUM"),
        4723: ("Password Change Attempt", "MEDIUM"),
        4724: ("Password Reset Attempt", "HIGH"),
        4725: ("User Disabled", "MEDIUM"),
        4726: ("Deleted User", "HIGH"),
        4732: ("Group Membership Changes", "HIGH"),
        4740: ("Account Locked", "HIGH"),
        4771: ("Kerberos Failure", "MEDIUM"),
        4776: ("NTLM Authentication", "LOW"),
        6008: ("Unexpected Shutdown", "HIGH"),
        7031: ("Service Crash", "MEDIUM"),
        7034: ("Service Crash", "MEDIUM"),
        7045: ("New Service Installed", "HIGH"),
        1000: ("Application Crash", "MEDIUM"),
        1001: ("Application Crash", "LOW"),
        1026: ("Application Crash", "MEDIUM"),
        1102: ("Audit Log Cleared", "CRITICAL"),
    }

    if event_id in rules:
        threat, severity = rules[event_id]
    elif "powershell" in text:
        threat, severity = "PowerShell Related Events", "MEDIUM"
    elif "firewall" in text or event_id in {5156, 5158}:
        threat, severity = "Firewall Related Events", "LOW"
    elif "remote" in text or "rdp" in text:
        threat, severity = "Remote Login", "MEDIUM"
    elif "crash" in event.lower() or "exception" in event.lower():
        threat, severity = "Application Crash", "MEDIUM"
    else:
        return None

    if username.lower() in {"administrator", "admin"} and severity in {"INFO", "LOW", "MEDIUM"}:
        threat, severity = "Administrator Login", "MEDIUM"

    return threat, severity


def _store_alert(log, threat, severity):
    rec = get_recommendation(threat)
    recommendation = format_recommendation(threat)
    message = f"{threat} detected for {log['username']} on {log['source']}"
    hostname = log["hostname"] if "hostname" in log.keys() else log["computer"] if "computer" in log.keys() else ""
    device_id = log["device_id"] if "device_id" in log.keys() else ""
    ip_address = log["ip_address"] if "ip_address" in log.keys() else ""
    agent_version = log["agent_version"] if "agent_version" in log.keys() else ""
    identity_host = hostname or (log["computer"] if "computer" in log.keys() else "")
    alert = insert_alert(
        severity,
        message,
        username=log["username"],
        source=log["source"],
        recommendation=recommendation,
        threat=threat,
        computer=log["computer"] if "computer" in log.keys() else "",
        hostname=hostname,
        device_id=device_id,
        ip_address=ip_address,
        agent_version=agent_version,
        event_id=_event_id(log),
        mitre=rec["mitre"],
        alert_key=event_fingerprint(threat, log["username"], log["source"], device_id or identity_host, identity_host, _event_id(log)),
        timestamp=now_string(),
    )
    if alert and alert.get("is_new") and severity in {"MEDIUM", "HIGH", "CRITICAL"} and not alert["email_sent"]:
        sent = send_email_alert(alert, rec)
        return sent
    return False


def detect_threats(logs):
    failures_by_user = defaultdict(list)
    failures_by_source = defaultdict(set)
    generated = 0

    for log in logs:
        rule = _rule_for_log(log)
        if rule:
            threat, severity = rule
            if severity != "INFO":
                if _store_alert(log, threat, severity):
                    generated += 1
            elif threat == "Successful Login":
                _store_alert(log, threat, severity)

        if _event_id(log) == 4625 or "failed" in log["event_type"].lower():
            failures_by_user[log["username"]].append(log)
            failures_by_source[log["source"]].add(log["username"])

    for username, events in failures_by_user.items():
        if len(events) >= 3:
            threat = "Multiple Failed Logins"
            severity = "HIGH" if len(events) < 8 else "CRITICAL"
            _store_alert(events[0], threat, severity)
        if len(events) >= 8:
            _store_alert(events[0], "Brute Force", "CRITICAL")

    for source, users in failures_by_source.items():
        if len(users) >= 5:
            sample = next((log for log in logs if log["source"] == source), None)
            if sample:
                _store_alert(sample, "Password Spray", "CRITICAL")

    _correlate_incidents()

    return generated


def _correlate_incidents():
    conn = get_connection()
    alerts = conn.execute("""
        SELECT *
        FROM alerts
        WHERE severity IN ('MEDIUM', 'HIGH', 'CRITICAL')
        ORDER BY id DESC
        LIMIT 200
    """).fetchall()
    conn.close()

    grouped = {}
    for alert in alerts:
        key = f"{alert['username']}|{alert['source']}"
        grouped.setdefault(key, []).append(alert)

    for key, items in grouped.items():
        threats = {item["threat"] for item in items}
        ids = [item["id"] for item in items]
        if {"Multiple Failed Logins", "Administrator Login", "Privilege Escalation"} & threats:
            severity = "CRITICAL" if "Privilege Escalation" in threats else "HIGH"
            title = f"Correlated Incident for {items[0]['username']}"
            description = "Correlated authentication and privilege activity detected across multiple alerts."
            notes = "Auto-generated by the SIEM correlation engine."
            correlation_key = event_fingerprint(key, ",".join(sorted(threats)), severity)
            if not any(inc["correlation_key"] == correlation_key for inc in get_incidents(100)):
                create_incident(
                    title=title,
                    severity=severity,
                    status="Open",
                    assigned_analyst="",
                    description=description,
                    notes=notes,
                    linked_alert_ids=ids,
                    correlation_key=correlation_key,
                )
