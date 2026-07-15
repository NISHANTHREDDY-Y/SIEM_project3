import os
import sqlite3
import json
from datetime import datetime, timedelta

from config import DATA_DIR, DB_PATH
from utils import event_fingerprint, now_string
from werkzeug.security import generate_password_hash

os.makedirs(DATA_DIR, exist_ok=True)


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _columns(cursor, table):
    cursor.execute(f"PRAGMA table_info({table})")
    return {row["name"] for row in cursor.fetchall()}


def _add_column(cursor, table, name, definition):
    if name not in _columns(cursor, table):
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def initialize_database():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            username TEXT NOT NULL DEFAULT 'SYSTEM',
            source TEXT NOT NULL DEFAULT 'Unknown',
            computer TEXT DEFAULT '',
            hostname TEXT DEFAULT '',
            device_id TEXT DEFAULT '',
            ip_address TEXT DEFAULT '',
            agent_version TEXT DEFAULT '',
            channel TEXT DEFAULT '',
            event_id INTEGER DEFAULT 0,
            severity TEXT DEFAULT 'INFO',
            message TEXT DEFAULT '',
            raw_event TEXT DEFAULT '',
            record_number INTEGER DEFAULT 0,
            fingerprint TEXT UNIQUE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            threat TEXT NOT NULL,
            message TEXT NOT NULL,
            username TEXT DEFAULT 'SYSTEM',
            source TEXT DEFAULT 'Unknown',
            computer TEXT DEFAULT '',
            hostname TEXT DEFAULT '',
            device_id TEXT DEFAULT '',
            ip_address TEXT DEFAULT '',
            agent_version TEXT DEFAULT '',
            event_id INTEGER DEFAULT 0,
            recommendation TEXT DEFAULT '',
            mitre TEXT DEFAULT '',
            email_sent INTEGER DEFAULT 0,
            alert_key TEXT UNIQUE,
            count INTEGER DEFAULT 1,
            last_seen TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS email_history(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            receiver TEXT,
            severity TEXT,
            threat TEXT,
            subject TEXT,
            status TEXT,
            alert_id INTEGER,
            error TEXT DEFAULT ''
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL UNIQUE,
            hostname TEXT NOT NULL,
            computer_name TEXT DEFAULT '',
            operating_system TEXT DEFAULT '',
            ip_address TEXT DEFAULT '',
            mac_address TEXT DEFAULT '',
            agent_version TEXT DEFAULT '',
            status TEXT DEFAULT 'Offline',
            heartbeat TEXT DEFAULT '',
            registration_time TEXT NOT NULL,
            last_seen TEXT DEFAULT '',
            total_logs INTEGER DEFAULT 0,
            total_alerts INTEGER DEFAULT 0,
            risk_score INTEGER DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS app_settings(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS collector_state(
            channel TEXT PRIMARY KEY,
            last_record_number INTEGER DEFAULT 0,
            last_run TEXT,
            last_error TEXT DEFAULT '',
            total_events INTEGER DEFAULT 0,
            total_scans INTEGER DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS collector_health(
            id INTEGER PRIMARY KEY CHECK (id = 1),
            status TEXT DEFAULT 'Stopped',
            running INTEGER DEFAULT 0,
            last_scan TEXT DEFAULT '',
            last_duration REAL DEFAULT 0,
            events_per_minute REAL DEFAULT 0,
            errors INTEGER DEFAULT 0,
            last_error TEXT DEFAULT '',
            updated_at TEXT DEFAULT ''
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_integrity_state(
            path TEXT PRIMARY KEY,
            last_hash TEXT DEFAULT '',
            last_size INTEGER DEFAULT 0,
            last_modified TEXT DEFAULT '',
            last_seen TEXT DEFAULT '',
            status TEXT DEFAULT 'Baseline'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS registry_state(
            path TEXT PRIMARY KEY,
            last_hash TEXT DEFAULT '',
            value_count INTEGER DEFAULT 0,
            last_snapshot TEXT DEFAULT '',
            last_seen TEXT DEFAULT '',
            status TEXT DEFAULT 'Baseline',
            last_error TEXT DEFAULT ''
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS process_state(
            name TEXT PRIMARY KEY,
            last_pid INTEGER DEFAULT 0,
            last_command_line TEXT DEFAULT '',
            last_seen TEXT DEFAULT '',
            status TEXT DEFAULT 'Baseline',
            occurrences INTEGER DEFAULT 0,
            last_user TEXT DEFAULT '',
            last_error TEXT DEFAULT ''
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usb_state(
            path TEXT PRIMARY KEY,
            last_hash TEXT DEFAULT '',
            device_count INTEGER DEFAULT 0,
            last_snapshot TEXT DEFAULT '',
            last_seen TEXT DEFAULT '',
            status TEXT DEFAULT 'Baseline',
            last_error TEXT DEFAULT ''
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_state(
            signature TEXT PRIMARY KEY,
            protocol TEXT DEFAULT '',
            local_address TEXT DEFAULT '',
            local_port INTEGER DEFAULT 0,
            remote_address TEXT DEFAULT '',
            remote_port INTEGER DEFAULT 0,
            state TEXT DEFAULT '',
            pid INTEGER DEFAULT 0,
            process_name TEXT DEFAULT '',
            last_hash TEXT DEFAULT '',
            last_snapshot TEXT DEFAULT '',
            last_seen TEXT DEFAULT '',
            status TEXT DEFAULT 'Baseline',
            risk_level TEXT DEFAULT 'INFO',
            last_error TEXT DEFAULT ''
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS performance_state(
            metric TEXT PRIMARY KEY,
            value REAL DEFAULT 0,
            unit TEXT DEFAULT '',
            status TEXT DEFAULT 'Normal',
            detail TEXT DEFAULT '',
            threshold TEXT DEFAULT '',
            last_seen TEXT DEFAULT '',
            last_error TEXT DEFAULT ''
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS app_users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            display_name TEXT DEFAULT '',
            active INTEGER DEFAULT 1,
            last_login TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT DEFAULT '',
            details TEXT DEFAULT '',
            ip_address TEXT DEFAULT '',
            status TEXT DEFAULT 'SUCCESS'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL DEFAULT 'Security Incident',
            severity TEXT NOT NULL DEFAULT 'MEDIUM',
            status TEXT NOT NULL DEFAULT 'Open',
            assigned_analyst TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            closed_at TEXT DEFAULT '',
            description TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            linked_alert_ids TEXT DEFAULT '[]',
            correlation_key TEXT UNIQUE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL DEFAULT 'Investigation Case',
            owner TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'Open',
            evidence TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            timeline TEXT DEFAULT '',
            related_alert_ids TEXT DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    for name, definition in {
        "severity": "TEXT DEFAULT 'INFO'",
        "computer": "TEXT DEFAULT ''",
        "hostname": "TEXT DEFAULT ''",
        "device_id": "TEXT DEFAULT ''",
        "ip_address": "TEXT DEFAULT ''",
        "agent_version": "TEXT DEFAULT ''",
        "channel": "TEXT DEFAULT ''",
        "event_id": "INTEGER DEFAULT 0",
        "message": "TEXT DEFAULT ''",
        "raw_event": "TEXT DEFAULT ''",
        "record_number": "INTEGER DEFAULT 0",
        "fingerprint": "TEXT",
    }.items():
        _add_column(cursor, "logs", name, definition)

    for name, definition in {
        "timestamp": "TEXT",
        "threat": "TEXT DEFAULT ''",
        "username": "TEXT DEFAULT 'SYSTEM'",
        "source": "TEXT DEFAULT 'Unknown'",
        "computer": "TEXT DEFAULT ''",
        "hostname": "TEXT DEFAULT ''",
        "device_id": "TEXT DEFAULT ''",
        "ip_address": "TEXT DEFAULT ''",
        "agent_version": "TEXT DEFAULT ''",
        "event_id": "INTEGER DEFAULT 0",
        "recommendation": "TEXT DEFAULT ''",
        "mitre": "TEXT DEFAULT ''",
        "email_sent": "INTEGER DEFAULT 0",
        "alert_key": "TEXT",
        "count": "INTEGER DEFAULT 1",
        "last_seen": "TEXT",
    }.items():
        _add_column(cursor, "alerts", name, definition)

    for name, definition in {
        "threat": "TEXT DEFAULT ''",
        "alert_id": "INTEGER",
        "error": "TEXT DEFAULT ''",
    }.items():
        _add_column(cursor, "email_history", name, definition)

    for name, definition in {
        "computer_name": "TEXT DEFAULT ''",
        "operating_system": "TEXT DEFAULT ''",
        "ip_address": "TEXT DEFAULT ''",
        "mac_address": "TEXT DEFAULT ''",
        "agent_version": "TEXT DEFAULT ''",
        "status": "TEXT DEFAULT 'Offline'",
        "heartbeat": "TEXT DEFAULT ''",
        "registration_time": "TEXT",
        "last_seen": "TEXT DEFAULT ''",
        "total_logs": "INTEGER DEFAULT 0",
        "total_alerts": "INTEGER DEFAULT 0",
        "risk_score": "INTEGER DEFAULT 0",
    }.items():
        _add_column(cursor, "devices", name, definition)

    for name, definition in {
        "value": "TEXT NOT NULL DEFAULT ''",
        "updated_at": "TEXT NOT NULL",
    }.items():
        _add_column(cursor, "app_settings", name, definition)

    for name, definition in {
        "last_error": "TEXT DEFAULT ''",
        "total_events": "INTEGER DEFAULT 0",
        "total_scans": "INTEGER DEFAULT 0",
    }.items():
        _add_column(cursor, "collector_state", name, definition)

    for name, definition in {
        "title": "TEXT DEFAULT 'Security Incident'",
        "severity": "TEXT DEFAULT 'MEDIUM'",
        "status": "TEXT DEFAULT 'Open'",
        "assigned_analyst": "TEXT DEFAULT ''",
        "created_at": "TEXT",
        "closed_at": "TEXT DEFAULT ''",
        "description": "TEXT DEFAULT ''",
        "notes": "TEXT DEFAULT ''",
        "linked_alert_ids": "TEXT DEFAULT '[]'",
        "correlation_key": "TEXT",
    }.items():
        _add_column(cursor, "incidents", name, definition)

    for name, definition in {
        "title": "TEXT DEFAULT 'Investigation Case'",
        "owner": "TEXT DEFAULT ''",
        "status": "TEXT DEFAULT 'Open'",
        "evidence": "TEXT DEFAULT ''",
        "notes": "TEXT DEFAULT ''",
        "timeline": "TEXT DEFAULT ''",
        "related_alert_ids": "TEXT DEFAULT '[]'",
        "created_at": "TEXT",
        "updated_at": "TEXT",
    }.items():
        _add_column(cursor, "cases", name, definition)

    for name, definition in {
        "status": "TEXT DEFAULT 'Stopped'",
        "running": "INTEGER DEFAULT 0",
        "last_scan": "TEXT DEFAULT ''",
        "last_duration": "REAL DEFAULT 0",
        "events_per_minute": "REAL DEFAULT 0",
        "errors": "INTEGER DEFAULT 0",
        "last_error": "TEXT DEFAULT ''",
        "updated_at": "TEXT DEFAULT ''",
    }.items():
        _add_column(cursor, "collector_health", name, definition)

    for name, definition in {
        "last_hash": "TEXT DEFAULT ''",
        "last_size": "INTEGER DEFAULT 0",
        "last_modified": "TEXT DEFAULT ''",
        "last_seen": "TEXT DEFAULT ''",
        "status": "TEXT DEFAULT 'Baseline'",
    }.items():
        _add_column(cursor, "file_integrity_state", name, definition)

    for name, definition in {
        "last_hash": "TEXT DEFAULT ''",
        "value_count": "INTEGER DEFAULT 0",
        "last_snapshot": "TEXT DEFAULT ''",
        "last_seen": "TEXT DEFAULT ''",
        "status": "TEXT DEFAULT 'Baseline'",
        "last_error": "TEXT DEFAULT ''",
    }.items():
        _add_column(cursor, "registry_state", name, definition)

    for name, definition in {
        "last_pid": "INTEGER DEFAULT 0",
        "last_command_line": "TEXT DEFAULT ''",
        "last_seen": "TEXT DEFAULT ''",
        "status": "TEXT DEFAULT 'Baseline'",
        "occurrences": "INTEGER DEFAULT 0",
        "last_user": "TEXT DEFAULT ''",
        "last_error": "TEXT DEFAULT ''",
    }.items():
        _add_column(cursor, "process_state", name, definition)

    for name, definition in {
        "last_hash": "TEXT DEFAULT ''",
        "device_count": "INTEGER DEFAULT 0",
        "last_snapshot": "TEXT DEFAULT ''",
        "last_seen": "TEXT DEFAULT ''",
        "status": "TEXT DEFAULT 'Baseline'",
        "last_error": "TEXT DEFAULT ''",
    }.items():
        _add_column(cursor, "usb_state", name, definition)

    for name, definition in {
        "protocol": "TEXT DEFAULT ''",
        "local_address": "TEXT DEFAULT ''",
        "local_port": "INTEGER DEFAULT 0",
        "remote_address": "TEXT DEFAULT ''",
        "remote_port": "INTEGER DEFAULT 0",
        "state": "TEXT DEFAULT ''",
        "pid": "INTEGER DEFAULT 0",
        "process_name": "TEXT DEFAULT ''",
        "last_hash": "TEXT DEFAULT ''",
        "last_snapshot": "TEXT DEFAULT ''",
        "last_seen": "TEXT DEFAULT ''",
        "status": "TEXT DEFAULT 'Baseline'",
        "risk_level": "TEXT DEFAULT 'INFO'",
        "last_error": "TEXT DEFAULT ''",
    }.items():
        _add_column(cursor, "network_state", name, definition)

    for name, definition in {
        "value": "REAL DEFAULT 0",
        "unit": "TEXT DEFAULT ''",
        "status": "TEXT DEFAULT 'Normal'",
        "detail": "TEXT DEFAULT ''",
        "threshold": "TEXT DEFAULT ''",
        "last_seen": "TEXT DEFAULT ''",
        "last_error": "TEXT DEFAULT ''",
    }.items():
        _add_column(cursor, "performance_state", name, definition)

    for name, definition in {
        "display_name": "TEXT DEFAULT ''",
        "active": "INTEGER DEFAULT 1",
        "last_login": "TEXT DEFAULT ''",
        "created_at": "TEXT",
        "updated_at": "TEXT",
    }.items():
        _add_column(cursor, "app_users", name, definition)

    for name, definition in {
        "resource": "TEXT DEFAULT ''",
        "details": "TEXT DEFAULT ''",
        "ip_address": "TEXT DEFAULT ''",
        "status": "TEXT DEFAULT 'SUCCESS'",
    }.items():
        _add_column(cursor, "audit_logs", name, definition)

    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_logs_user ON logs(username)",
        "CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source)",
        "CREATE INDEX IF NOT EXISTS idx_logs_event_id ON logs(event_id)",
        "CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_logs_fingerprint ON logs(fingerprint)",
        "CREATE INDEX IF NOT EXISTS idx_alert_severity ON alerts(severity)",
        "CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON alerts(timestamp)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_key ON alerts(alert_key)",
        "CREATE INDEX IF NOT EXISTS idx_email_alert ON email_history(alert_id)",
        "CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_device_id ON devices(device_id)",
        "CREATE INDEX IF NOT EXISTS idx_file_integrity_status ON file_integrity_state(status)",
        "CREATE INDEX IF NOT EXISTS idx_registry_status ON registry_state(status)",
        "CREATE INDEX IF NOT EXISTS idx_process_status ON process_state(status)",
        "CREATE INDEX IF NOT EXISTS idx_usb_status ON usb_state(status)",
        "CREATE INDEX IF NOT EXISTS idx_network_status ON network_state(status)",
        "CREATE INDEX IF NOT EXISTS idx_network_risk ON network_state(risk_level)",
        "CREATE INDEX IF NOT EXISTS idx_performance_status ON performance_state(status)",
        "CREATE INDEX IF NOT EXISTS idx_settings_updated ON app_settings(updated_at)",
    ]
    for statement in indexes:
        cursor.execute(statement)

    cursor.execute("UPDATE logs SET severity='INFO' WHERE severity IS NULL OR severity=''")
    cursor.execute("UPDATE alerts SET timestamp=? WHERE timestamp IS NULL OR timestamp=''", (now_string(),))
    cursor.execute("UPDATE alerts SET username='SYSTEM' WHERE username IS NULL OR username=''")
    cursor.execute("UPDATE alerts SET source='Unknown' WHERE source IS NULL OR source=''")
    cursor.execute("UPDATE alerts SET threat = message WHERE threat = '' OR threat IS NULL")
    cursor.execute("UPDATE alerts SET last_seen = timestamp WHERE last_seen IS NULL OR last_seen=''")
    cursor.execute("UPDATE logs SET hostname = COALESCE(hostname, computer, source, '') WHERE hostname IS NULL OR hostname=''")
    cursor.execute("UPDATE logs SET device_id = COALESCE(device_id, hostname, computer, source, 'local-endpoint') WHERE device_id IS NULL OR device_id=''")
    cursor.execute("UPDATE logs SET ip_address = COALESCE(ip_address, '') WHERE ip_address IS NULL")
    cursor.execute("UPDATE logs SET agent_version = COALESCE(agent_version, '') WHERE agent_version IS NULL")
    cursor.execute("UPDATE alerts SET hostname = COALESCE(hostname, computer, source, '') WHERE hostname IS NULL OR hostname=''")
    cursor.execute("UPDATE alerts SET device_id = COALESCE(device_id, hostname, computer, source, 'local-endpoint') WHERE device_id IS NULL OR device_id=''")
    cursor.execute("UPDATE alerts SET ip_address = COALESCE(ip_address, '') WHERE ip_address IS NULL")
    cursor.execute("UPDATE alerts SET agent_version = COALESCE(agent_version, '') WHERE agent_version IS NULL")
    cursor.execute("""
        INSERT OR IGNORE INTO collector_health(id, status, running, last_scan, last_duration, events_per_minute, errors, last_error, updated_at)
        VALUES(1, 'Stopped', 0, '', 0, 0, 0, '', ?)
    """, (now_string(),))
    for key, value in {
        "agent_interval": "30",
        "heartbeat_interval": "30",
        "server_address": "",
        "enabled_sources": "Security,System,Application,Sysmon,Process,Registry,USB,FileIntegrity,Performance",
    }.items():
        cursor.execute("""
            INSERT OR IGNORE INTO app_settings(key, value, updated_at)
            VALUES(?,?,?)
        """, (key, value, now_string()))

    _seed_default_users(cursor)

    conn.commit()
    conn.close()


def _seed_default_users(cursor):
    defaults = [
        ("admin", "Administrator", "Full access"),
        ("analyst", "SOC Analyst", "Tactical investigation"),
        ("viewer", "Viewer", "Read-only access"),
    ]
    from config import (
        DEFAULT_ADMIN_PASSWORD,
        DEFAULT_ADMIN_USERNAME,
        DEFAULT_ANALYST_PASSWORD,
        DEFAULT_ANALYST_USERNAME,
        DEFAULT_VIEWER_PASSWORD,
        DEFAULT_VIEWER_USERNAME,
    )

    seed_values = [
        (DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_PASSWORD, "Administrator", "Administrator"),
        (DEFAULT_ANALYST_USERNAME, DEFAULT_ANALYST_PASSWORD, "SOC Analyst", "SOC Analyst"),
        (DEFAULT_VIEWER_USERNAME, DEFAULT_VIEWER_PASSWORD, "Viewer", "Viewer"),
    ]
    for username, password, role, display_name in seed_values:
        if not password:
            continue
        now = now_string()
        cursor.execute("""
            INSERT OR IGNORE INTO app_users(username, password_hash, role, display_name, active, last_login, created_at, updated_at)
            VALUES(?,?,?,?,1,'',?,?)
        """, (username, generate_password_hash(password), role, display_name, now, now))


def _json_list(value):
    if not value:
        return []
    if isinstance(value, list):
        return value
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []


def get_user_account(username):
    conn = get_connection()
    row = conn.execute("SELECT * FROM app_users WHERE username=?", (username,)).fetchone()
    conn.close()
    return row


def list_users():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM app_users ORDER BY role DESC, username").fetchall()
    conn.close()
    return rows


def touch_last_login(username):
    conn = get_connection()
    conn.execute("UPDATE app_users SET last_login=?, updated_at=? WHERE username=?", (now_string(), now_string(), username))
    conn.commit()
    conn.close()


def insert_audit_log(actor, action, resource="", details="", ip_address="", status="SUCCESS"):
    conn = get_connection()
    conn.execute("""
        INSERT INTO audit_logs(timestamp, actor, action, resource, details, ip_address, status)
        VALUES(?,?,?,?,?,?,?)
    """, (now_string(), actor or "Unknown", action, resource, details, ip_address, status))
    conn.commit()
    conn.close()


def get_audit_logs(limit=100):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows


def get_app_settings():
    conn = get_connection()
    rows = conn.execute("SELECT key, value FROM app_settings").fetchall()
    conn.close()
    return {row["key"]: row["value"] for row in rows}


def get_app_setting(key, default=""):
    conn = get_connection()
    row = conn.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


def set_app_setting(key, value):
    conn = get_connection()
    conn.execute("""
        INSERT INTO app_settings(key, value, updated_at)
        VALUES(?,?,?)
        ON CONFLICT(key) DO UPDATE SET
            value=excluded.value,
            updated_at=excluded.updated_at
    """, (key, str(value or ""), now_string()))
    conn.commit()
    conn.close()


def _device_identity(hostname="", device_id="", computer="", source="", ip_address=""):
    hostname = (hostname or "").strip()
    device_id = (device_id or "").strip()
    computer = (computer or "").strip()
    source = (source or "").strip()
    ip_address = (ip_address or "").strip()
    identity = device_id or hostname or computer
    if not identity and ip_address:
        identity = f"ip:{ip_address}"
    if not identity:
        identity = source or "local-endpoint"
    if not hostname:
        hostname = computer or source or "Local Endpoint"
    if not device_id:
        device_id = identity
    return hostname, device_id


def _risk_score_for_severity(severity):
    return {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 4,
        "HIGH": 8,
        "CRITICAL": 12,
    }.get(str(severity or "").upper(), 1)


def register_device(device_id, hostname, computer_name="", operating_system="", ip_address="", mac_address="", agent_version="", status="Offline", heartbeat="", registration_time=None, last_seen="", total_logs=0, total_alerts=0, risk_score=0):
    registration_time = registration_time or now_string()
    hostname = hostname or computer_name or "Unknown"
    conn = get_connection()
    conn.execute("""
        INSERT INTO devices(
            device_id, hostname, computer_name, operating_system, ip_address, mac_address,
            agent_version, status, heartbeat, registration_time, last_seen, total_logs,
            total_alerts, risk_score
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(device_id) DO UPDATE SET
            hostname=excluded.hostname,
            computer_name=excluded.computer_name,
            operating_system=COALESCE(NULLIF(excluded.operating_system, ''), devices.operating_system),
            ip_address=COALESCE(NULLIF(excluded.ip_address, ''), devices.ip_address),
            mac_address=COALESCE(NULLIF(excluded.mac_address, ''), devices.mac_address),
            agent_version=COALESCE(NULLIF(excluded.agent_version, ''), devices.agent_version),
            status=excluded.status,
            heartbeat=excluded.heartbeat,
            last_seen=COALESCE(NULLIF(excluded.last_seen, ''), excluded.heartbeat, devices.last_seen),
            total_logs=devices.total_logs + excluded.total_logs,
            total_alerts=devices.total_alerts + excluded.total_alerts,
            risk_score=MAX(devices.risk_score, excluded.risk_score, devices.risk_score + excluded.risk_score)
    """, (
        device_id,
        hostname,
        computer_name or hostname,
        operating_system or "",
        ip_address or "",
        mac_address or "",
        agent_version or "",
        status or "Offline",
        heartbeat or "",
        registration_time,
        last_seen or heartbeat or "",
        int(total_logs or 0),
        int(total_alerts or 0),
        int(risk_score or 0),
    ))
    conn.commit()
    conn.close()


def update_device_heartbeat(device_id, hostname="", computer_name="", operating_system="", ip_address="", mac_address="", agent_version="", last_seen=None, status="Online"):
    last_seen = last_seen or now_string()
    hostname, resolved_device_id = _device_identity(hostname, device_id, computer_name, "", ip_address)
    register_device(
        resolved_device_id,
        hostname,
        computer_name=computer_name or hostname,
        operating_system=operating_system,
        ip_address=ip_address,
        mac_address=mac_address,
        agent_version=agent_version,
        status=status,
        heartbeat=last_seen,
        last_seen=last_seen,
    )


def insert_log(timestamp, event_type, username, source, severity="INFO", computer="", hostname="", device_id="", ip_address="", agent_version="", channel="", event_id=0, message="", raw_event="", record_number=0):
    hostname, resolved_device_id = _device_identity(hostname, device_id, computer, source, ip_address)
    fingerprint = event_fingerprint(timestamp, event_type, username, source, resolved_device_id, computer or hostname, event_id, record_number)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR IGNORE INTO logs(
            timestamp, event_type, username, source, severity, computer, hostname, device_id,
            ip_address, agent_version, channel, event_id, message, raw_event, record_number, fingerprint
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (timestamp, event_type, username, source, severity, computer, hostname, resolved_device_id, ip_address, agent_version, channel, event_id, message, raw_event, record_number, fingerprint))
    inserted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    if inserted:
        register_device(
            resolved_device_id,
            hostname,
            computer_name=computer or hostname,
            operating_system="",
            ip_address=ip_address,
            agent_version=agent_version,
            status="Online",
            heartbeat=timestamp,
            last_seen=timestamp,
            total_logs=1,
        )
    return inserted


def insert_alert(severity, message, username="SYSTEM", source="Unknown", recommendation="", email_sent=0, threat=None, computer="", hostname="", device_id="", ip_address="", agent_version="", event_id=0, mitre="", alert_key=None, timestamp=None):
    timestamp = timestamp or now_string()
    threat = threat or message
    hostname, resolved_device_id = _device_identity(hostname, device_id, computer, source, ip_address)
    alert_key = alert_key or event_fingerprint(threat, username, source, resolved_device_id, computer or hostname, event_id)
    conn = get_connection()
    cursor = conn.cursor()
    existing = cursor.execute("SELECT id FROM alerts WHERE alert_key=?", (alert_key,)).fetchone()
    cursor.execute("""
        INSERT INTO alerts(
            timestamp, severity, threat, message, username, source, computer,
            hostname, device_id, ip_address, agent_version, event_id, recommendation, mitre,
            email_sent, alert_key, count, last_seen
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(alert_key) DO UPDATE SET
            count = count + 1,
            last_seen = excluded.timestamp,
            severity = excluded.severity,
            recommendation = excluded.recommendation,
            mitre = excluded.mitre,
            hostname = COALESCE(NULLIF(excluded.hostname, ''), alerts.hostname),
            device_id = COALESCE(NULLIF(excluded.device_id, ''), alerts.device_id),
            ip_address = COALESCE(NULLIF(excluded.ip_address, ''), alerts.ip_address),
            agent_version = COALESCE(NULLIF(excluded.agent_version, ''), alerts.agent_version)
    """, (timestamp, severity, threat, message, username, source, computer, hostname, resolved_device_id, ip_address, agent_version, event_id, recommendation, mitre, email_sent, alert_key, 1, timestamp))
    cursor.execute("SELECT * FROM alerts WHERE alert_key=?", (alert_key,))
    row = dict(cursor.fetchone())
    row["is_new"] = existing is None
    conn.commit()
    conn.close()
    if row.get("device_id") or row.get("hostname"):
        register_device(
            row.get("device_id") or resolved_device_id,
            row.get("hostname") or hostname,
            computer_name=row.get("computer") or hostname,
            ip_address=row.get("ip_address") or ip_address,
            agent_version=row.get("agent_version") or agent_version,
            status="Online",
            heartbeat=timestamp,
            last_seen=timestamp,
            total_alerts=1,
            risk_score=_risk_score_for_severity(severity),
        )
    return row


def mark_alert_email_sent(alert_id):
    conn = get_connection()
    conn.execute("UPDATE alerts SET email_sent=1 WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()


def insert_email_history(receiver, severity, subject, status, threat="", alert_id=None, error=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO email_history(timestamp, receiver, severity, threat, subject, status, alert_id, error)
        VALUES(?,?,?,?,?,?,?,?)
    """, (now_string(), receiver, severity, threat, subject, status, alert_id, error))
    conn.commit()
    conn.close()


def _query_logs(where="", params=(), limit=250, offset=0):
    conn = get_connection()
    query = f"SELECT * FROM logs {where} ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?"
    rows = conn.execute(query, (*params, limit, offset)).fetchall()
    conn.close()
    return rows


def get_logs(limit=250, offset=0):
    return _query_logs(limit=limit, offset=offset)


def search_logs(keyword="", severity="", username="", source="", event_type="", date_from="", date_to="", limit=250, offset=0):
    clauses = ["1=1"]
    params = []
    if keyword:
        like = f"%{keyword}%"
        clauses.append("(event_type LIKE ? OR username LIKE ? OR source LIKE ? OR computer LIKE ? OR hostname LIKE ? OR device_id LIKE ? OR ip_address LIKE ? OR agent_version LIKE ? OR message LIKE ? OR raw_event LIKE ?)")
        params.extend([like] * 10)
    if severity:
        clauses.append("severity=?")
        params.append(severity)
    if username:
        clauses.append("username LIKE ?")
        params.append(f"%{username}%")
    if source:
        clauses.append("(source LIKE ? OR computer LIKE ? OR channel LIKE ?)")
        params.extend([f"%{source}%"] * 3)
    if event_type:
        clauses.append("(event_type LIKE ? OR event_id=?)")
        params.extend([f"%{event_type}%", int(event_type) if str(event_type).isdigit() else -1])
    if date_from:
        clauses.append("timestamp>=?")
        params.append(date_from)
    if date_to:
        clauses.append("timestamp<=?")
        params.append(date_to)
    return _query_logs("WHERE " + " AND ".join(clauses), params, limit, offset)


def filter_logs(severity=None, source=None):
    return search_logs(severity=severity or "", source=source or "")


def get_alerts(limit=250):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM alerts ORDER BY last_seen DESC, timestamp DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows


def search_alerts(keyword="", severity="", username="", source=""):
    conn = get_connection()
    clauses = ["1=1"]
    params = []
    if keyword:
        like = f"%{keyword}%"
        clauses.append("(threat LIKE ? OR message LIKE ? OR recommendation LIKE ? OR username LIKE ? OR source LIKE ? OR computer LIKE ? OR hostname LIKE ? OR device_id LIKE ? OR ip_address LIKE ? OR agent_version LIKE ?)")
        params.extend([like] * 10)
    if severity:
        clauses.append("severity=?")
        params.append(severity)
    if username:
        clauses.append("username LIKE ?")
        params.append(f"%{username}%")
    if source:
        clauses.append("(source LIKE ? OR computer LIKE ?)")
        params.extend([f"%{source}%"] * 2)
    rows = conn.execute("SELECT * FROM alerts WHERE " + " AND ".join(clauses) + " ORDER BY last_seen DESC", params).fetchall()
    conn.close()
    return rows


def get_users():
    conn = get_connection()
    rows = conn.execute("""
        SELECT
            l.username,
            COUNT(l.id) AS event_count,
            MAX(l.timestamp) AS last_activity,
            COALESCE(a.threat_count, 0) AS threat_count,
            SUM(CASE l.severity WHEN 'CRITICAL' THEN 12 WHEN 'HIGH' THEN 8 WHEN 'MEDIUM' THEN 4 WHEN 'LOW' THEN 2 ELSE 1 END)
                + COALESCE(a.threat_count, 0) * 5 AS risk_score
        FROM logs l
        LEFT JOIN (
            SELECT username, COUNT(*) AS threat_count
            FROM alerts
            GROUP BY username
        ) a ON a.username = l.username
        WHERE lower(l.username) NOT IN ('unknown','application-specific','machine-default','0','-')
        GROUP BY l.username
        ORDER BY risk_score DESC, event_count DESC
    """).fetchall()
    conn.close()
    return rows


def get_email_history(limit=100):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM email_history ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows


def search_email_history(receiver="", severity="", threat="", status="", limit=100):
    conn = get_connection()
    clauses = ["1=1"]
    params = []
    if receiver:
        clauses.append("receiver LIKE ?")
        params.append(f"%{receiver}%")
    if severity:
        clauses.append("severity=?")
        params.append(severity)
    if threat:
        clauses.append("threat LIKE ?")
        params.append(f"%{threat}%")
    if status:
        clauses.append("status=?")
        params.append(status)
    rows = conn.execute(
        "SELECT * FROM email_history WHERE " + " AND ".join(clauses) + " ORDER BY id DESC LIMIT ?",
        (*params, limit),
    ).fetchall()
    conn.close()
    return rows


def get_dashboard_totals():
    conn = get_connection()
    totals = {
        "logs": conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0],
        "alerts": conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
        "emails": conn.execute("SELECT COUNT(*) FROM email_history").fetchone()[0],
        "users": conn.execute("SELECT COUNT(DISTINCT username) FROM logs WHERE lower(username) NOT IN ('unknown','application-specific','machine-default','0','-')").fetchone()[0],
        "sources": conn.execute("SELECT COUNT(DISTINCT COALESCE(NULLIF(computer,''), source)) FROM logs").fetchone()[0],
        "emails_sent": conn.execute("SELECT COUNT(*) FROM email_history WHERE status='SENT'").fetchone()[0],
        "devices": conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
        "online_devices": conn.execute("SELECT COUNT(*) FROM devices WHERE status='Online'").fetchone()[0],
        "offline_devices": conn.execute("SELECT COUNT(*) FROM devices WHERE status='Offline'").fetchone()[0],
    }
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        totals[f"{severity.lower()}_alerts"] = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity=?", (severity,)).fetchone()[0]
    conn.close()
    return totals


def get_alert_statistics():
    conn = get_connection()
    rows = conn.execute("SELECT severity, COUNT(*) AS total FROM alerts GROUP BY severity").fetchall()
    conn.close()
    return rows


def get_severity_statistics():
    conn = get_connection()
    rows = conn.execute("SELECT severity, COUNT(*) AS total FROM logs GROUP BY severity ORDER BY total DESC").fetchall()
    conn.close()
    return rows


def get_event_statistics(limit=10):
    conn = get_connection()
    rows = conn.execute("SELECT event_type, COUNT(*) AS total FROM logs GROUP BY event_type ORDER BY total DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows


def get_top_users(limit=10):
    conn = get_connection()
    rows = conn.execute("""
        SELECT username, COUNT(*) AS total
        FROM logs
        WHERE lower(username) NOT IN ('unknown','application-specific','machine-default','0','-')
        GROUP BY username
        ORDER BY total DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return rows


def get_top_sources(limit=10):
    conn = get_connection()
    rows = conn.execute("""
        SELECT COALESCE(NULLIF(computer,''), source) AS source, COUNT(*) AS total
        FROM logs
        GROUP BY COALESCE(NULLIF(computer,''), source)
        ORDER BY total DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return rows


def get_device_inventory(limit=250):
    conn = get_connection()
    device_rows = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC, registration_time DESC LIMIT ?", (limit,)).fetchall()
    log_stats = conn.execute("""
        SELECT
            COALESCE(NULLIF(device_id,''), NULLIF(hostname,''), NULLIF(computer,''), NULLIF(source,''), 'local-endpoint') AS device_key,
            COUNT(*) AS log_count,
            COUNT(DISTINCT username) AS users,
            MAX(timestamp) AS last_seen,
            MAX(COALESCE(NULLIF(ip_address,''), '')) AS ip_address,
            MAX(COALESCE(NULLIF(agent_version,''), '')) AS agent_version
        FROM logs
        GROUP BY 1
    """).fetchall()
    alert_stats = conn.execute("""
        SELECT
            COALESCE(NULLIF(device_id,''), NULLIF(hostname,''), NULLIF(computer,''), NULLIF(source,''), 'local-endpoint') AS device_key,
            COUNT(*) AS alert_count
        FROM alerts
        GROUP BY 1
    """).fetchall()
    conn.close()
    log_map = {row["device_key"]: dict(row) for row in log_stats}
    alert_map = {row["device_key"]: row["alert_count"] for row in alert_stats}
    rows = []
    seen_keys = set()
    for device in device_rows:
        key = device["device_id"] or device["hostname"] or device["computer_name"] or "local-endpoint"
        seen_keys.add(key)
        log_row = log_map.get(key, {})
        alert_count = int(alert_map.get(key, 0))
        last_seen = device["last_seen"] or log_row.get("last_seen", "") or device["heartbeat"] or device["registration_time"]
        status = device["status"] or "Offline"
        if last_seen:
            try:
                parsed = datetime.strptime(last_seen[:19], "%Y-%m-%d %H:%M:%S")
                age_minutes = (datetime.now() - parsed).total_seconds() / 60.0
                if age_minutes <= 60:
                    status = "Online"
                elif age_minutes <= 1440:
                    status = "Idle"
                else:
                    status = "Offline"
            except Exception:
                pass
        rows.append({
            "device_id": device["device_id"],
            "hostname": device["hostname"],
            "computer_name": device["computer_name"],
            "operating_system": device["operating_system"] or "Unknown",
            "ip_address": device["ip_address"] or log_row.get("ip_address", "") or "Unknown",
            "mac_address": device["mac_address"],
            "agent_version": device["agent_version"] or log_row.get("agent_version", ""),
            "status": status,
            "heartbeat": device["heartbeat"],
            "registration_time": device["registration_time"],
            "last_seen": last_seen,
            "log_count": int(log_row.get("log_count", device["total_logs"] or 0)),
            "alert_count": alert_count or int(device["total_alerts"] or 0),
            "users": int(log_row.get("users", 0)),
            "risk_score": int(device["risk_score"] or 0) + alert_count * 5 + int(log_row.get("log_count", 0) // 10),
        })
    for key, log_row in log_map.items():
        if key in seen_keys:
            continue
        alert_count = int(alert_map.get(key, 0))
        last_seen = log_row.get("last_seen", "")
        rows.append({
            "device_id": key,
            "hostname": key if key != "local-endpoint" else "Local Endpoint",
            "computer_name": key,
            "operating_system": "Unknown",
            "ip_address": log_row.get("ip_address", "") or "Unknown",
            "mac_address": "",
            "agent_version": log_row.get("agent_version", ""),
            "status": "Online" if last_seen else "Offline",
            "heartbeat": last_seen,
            "registration_time": last_seen or now_string(),
            "last_seen": last_seen,
            "log_count": int(log_row.get("log_count", 0)),
            "alert_count": alert_count,
            "users": int(log_row.get("users", 0)),
            "risk_score": alert_count * 5 + int(log_row.get("log_count", 0) // 10),
        })
    return rows


def get_threat_statistics(limit=10):
    conn = get_connection()
    rows = conn.execute("SELECT threat, COUNT(*) AS total FROM alerts GROUP BY threat ORDER BY total DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows


def get_threat_trend(days=7):
    conn = get_connection()
    start = (datetime.now() - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    rows = conn.execute("""
        SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS total
        FROM alerts
        WHERE substr(timestamp, 1, 10) >= ?
        GROUP BY day
        ORDER BY day
    """, (start,)).fetchall()
    conn.close()
    return rows


def get_executive_overview(days=30):
    conn = get_connection()
    start = (datetime.now() - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    recent = conn.execute(
        """
        SELECT severity, COUNT(*) AS total
        FROM alerts
        WHERE substr(timestamp, 1, 10) >= ?
        GROUP BY severity
        """,
        (start,),
    ).fetchall()
    severity_counts = {row["severity"]: row["total"] for row in recent}
    critical = int(severity_counts.get("CRITICAL", 0))
    high = int(severity_counts.get("HIGH", 0))
    medium = int(severity_counts.get("MEDIUM", 0))
    low = int(severity_counts.get("LOW", 0))
    total_recent = critical + high + medium + low

    top_threat = conn.execute(
        """
        SELECT threat, COUNT(*) AS total
        FROM alerts
        WHERE substr(timestamp, 1, 10) >= ?
        GROUP BY threat
        ORDER BY total DESC, threat ASC
        LIMIT 1
        """,
        (start,),
    ).fetchone()
    top_user = conn.execute(
        """
        SELECT username, COUNT(*) AS total
        FROM logs
        WHERE substr(timestamp, 1, 10) >= ?
          AND lower(username) NOT IN ('unknown','application-specific','machine-default','0','-')
        GROUP BY username
        ORDER BY total DESC, username ASC
        LIMIT 1
        """,
        (start,),
    ).fetchone()
    open_incidents = conn.execute(
        "SELECT COUNT(*) FROM incidents WHERE lower(status) != 'closed'"
    ).fetchone()[0]
    active_cases = conn.execute(
        "SELECT COUNT(*) FROM cases WHERE lower(status) != 'closed'"
    ).fetchone()[0]
    monthly_trend = conn.execute(
        """
        SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS total
        FROM alerts
        WHERE substr(timestamp, 1, 10) >= ?
        GROUP BY day
        ORDER BY day
        """,
        (start,),
    ).fetchall()
    conn.close()

    weighted_risk = critical * 12 + high * 8 + medium * 4 + low
    weighted_risk += open_incidents * 5
    weighted_risk += min(total_recent // 10, 10)
    security_score = max(0, 100 - min(weighted_risk, 95))
    if security_score >= 85:
        posture = "Strong"
    elif security_score >= 70:
        posture = "Guarded"
    elif security_score >= 50:
        posture = "Watch"
    else:
        posture = "Elevated"

    return {
        "security_score": security_score,
        "posture": posture,
        "recent_alerts": total_recent,
        "critical_alerts": critical,
        "high_alerts": high,
        "medium_alerts": medium,
        "low_alerts": low,
        "open_incidents": int(open_incidents),
        "active_cases": int(active_cases),
        "top_threat": top_threat["threat"] if top_threat else "None",
        "top_threat_total": int(top_threat["total"]) if top_threat else 0,
        "top_user": top_user["username"] if top_user else "None",
        "top_user_total": int(top_user["total"]) if top_user else 0,
        # Flask JSON responses cannot serialize sqlite3.Row instances.
        "monthly_trend": [dict(row) for row in monthly_trend],
    }


def get_hourly_events():
    conn = get_connection()
    rows = conn.execute("""
        SELECT substr(timestamp, 12, 2) AS hour, COUNT(*) AS total
        FROM logs
        WHERE length(timestamp) >= 13
        GROUP BY hour
        ORDER BY hour
    """).fetchall()
    conn.close()
    return rows


def get_login_summary():
    conn = get_connection()
    success = conn.execute("SELECT COUNT(*) FROM logs WHERE event_type LIKE '%SUCCESS%' OR event_id=4624").fetchone()[0]
    failed = conn.execute("SELECT COUNT(*) FROM logs WHERE event_type LIKE '%FAILED%' OR event_id=4625").fetchone()[0]
    conn.close()
    return {"success": success, "failed": failed}


def get_collector_status():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM collector_state ORDER BY channel").fetchall()
    conn.close()
    return rows


def get_collector_health():
    conn = get_connection()
    row = conn.execute("SELECT * FROM collector_health WHERE id=1").fetchone()
    conn.close()
    return row


def get_incidents(limit=100):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows


def get_incident(incident_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    conn.close()
    return row


def create_incident(title, severity, status, assigned_analyst, description, notes, linked_alert_ids, correlation_key=None):
    conn = get_connection()
    created_at = now_string()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO incidents(title, severity, status, assigned_analyst, created_at, closed_at, description, notes, linked_alert_ids, correlation_key)
        VALUES(?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(correlation_key) DO UPDATE SET
            severity=excluded.severity,
            status=excluded.status,
            assigned_analyst=COALESCE(excluded.assigned_analyst, incidents.assigned_analyst),
            description=COALESCE(excluded.description, incidents.description),
            notes=COALESCE(excluded.notes, incidents.notes),
            linked_alert_ids=COALESCE(excluded.linked_alert_ids, incidents.linked_alert_ids),
            closed_at=CASE WHEN excluded.status='Closed' THEN excluded.closed_at ELSE incidents.closed_at END
    """, (title, severity, status, assigned_analyst, created_at, "" if status != "Closed" else created_at, description, notes, json.dumps(linked_alert_ids or []), correlation_key))
    conn.commit()
    conn.close()


def update_incident_status(incident_id, status, assigned_analyst=None, notes=None, description=None):
    conn = get_connection()
    row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if row is None:
        conn.close()
        return False
    closed_at = now_string() if status == "Closed" else (row["closed_at"] or "")
    conn.execute("""
        UPDATE incidents
        SET status=?,
            assigned_analyst=COALESCE(?, assigned_analyst),
            notes=COALESCE(?, notes),
            description=COALESCE(?, description),
            closed_at=?
        WHERE id=?
    """, (status, assigned_analyst, notes, description, closed_at, incident_id))
    conn.commit()
    conn.close()
    return True


def get_cases(limit=100):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM cases ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows


def create_case(title, owner, status, evidence, notes, timeline, related_alert_ids):
    conn = get_connection()
    now = now_string()
    conn.execute("""
        INSERT INTO cases(title, owner, status, evidence, notes, timeline, related_alert_ids, created_at, updated_at)
        VALUES(?,?,?,?,?,?,?,?,?)
    """, (title, owner, status, evidence, notes, timeline, json.dumps(related_alert_ids or []), now, now))
    conn.commit()
    conn.close()


def update_case(case_id, status=None, owner=None, evidence=None, notes=None, timeline=None, related_alert_ids=None):
    conn = get_connection()
    now = now_string()
    row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if row is None:
        conn.close()
        return False
    conn.execute("""
        UPDATE cases
        SET status=COALESCE(?, status),
            owner=COALESCE(?, owner),
            evidence=COALESCE(?, evidence),
            notes=COALESCE(?, notes),
            timeline=COALESCE(?, timeline),
            related_alert_ids=COALESCE(?, related_alert_ids),
            updated_at=?
        WHERE id=?
    """, (status, owner, evidence, notes, timeline, json.dumps(related_alert_ids) if related_alert_ids is not None else None, now, case_id))
    conn.commit()
    conn.close()
    return True


def link_alerts_to_incident(incident_id, alert_ids):
    row = get_incident(incident_id)
    if row is None:
        return False
    current = set(_json_list(row["linked_alert_ids"]))
    current.update(int(a) for a in alert_ids if str(a).isdigit())
    severity = row["severity"]
    title = row["title"]
    description = row["description"]
    notes = row["notes"]
    status = row["status"]
    assigned_analyst = row["assigned_analyst"]
    closed_at = row["closed_at"]
    conn = get_connection()
    conn.execute("""
        UPDATE incidents
        SET linked_alert_ids=?, severity=?, title=?, description=?, notes=?, status=?, assigned_analyst=?, closed_at=?
        WHERE id=?
    """, (json.dumps(sorted(current)), severity, title, description, notes, status, assigned_analyst, closed_at, incident_id))
    conn.commit()
    conn.close()
    return True


def get_alert_by_id(alert_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    conn.close()
    return row


def get_alert_timeline(alert_id, limit=20):
    alert = get_alert_by_id(alert_id)
    if alert is None:
        return None

    conn = get_connection()
    timeline = conn.execute("""
        SELECT *
        FROM logs
        WHERE
            username = ?
            OR source = ?
            OR event_id = ?
            OR hostname = ?
            OR device_id = ?
            OR computer = ?
            OR ip_address = ?
        ORDER BY timestamp DESC, id DESC
        LIMIT ?
    """, (alert["username"], alert["source"], alert["event_id"], alert["hostname"], alert["device_id"], alert["computer"], alert["ip_address"], limit)).fetchall()

    email_history = conn.execute("""
        SELECT *
        FROM email_history
        WHERE alert_id = ?
        ORDER BY id DESC
    """, (alert_id,)).fetchall()
    conn.close()

    return {
        "alert": alert,
        "timeline": timeline,
        "email_history": email_history,
    }


def update_collector_state(channel, last_record_number):
    conn = get_connection()
    conn.execute("""
        INSERT INTO collector_state(channel, last_record_number, last_run, total_events, total_scans, last_error)
        VALUES(?,?,?,?,?,?)
        ON CONFLICT(channel) DO UPDATE SET
            last_record_number=MAX(collector_state.last_record_number, excluded.last_record_number),
            last_run=excluded.last_run,
            total_events=collector_state.total_events + excluded.total_events,
            total_scans=collector_state.total_scans + excluded.total_scans,
            last_error=excluded.last_error
    """, (channel, last_record_number or 0, now_string(), 0, 1, ""))
    conn.commit()
    conn.close()


def update_collector_state_with_stats(channel, last_record_number, events_seen, error=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO collector_state(channel, last_record_number, last_run, last_error, total_events, total_scans)
        VALUES(?,?,?,?,?,?)
        ON CONFLICT(channel) DO UPDATE SET
            last_record_number=MAX(collector_state.last_record_number, excluded.last_record_number),
            last_run=excluded.last_run,
            last_error=excluded.last_error,
            total_events=collector_state.total_events + excluded.total_events,
            total_scans=collector_state.total_scans + excluded.total_scans
    """, (channel, last_record_number or 0, now_string(), error or "", int(events_seen or 0), 1))
    conn.commit()
    conn.close()


def update_collector_health(status, running, last_scan, last_duration, events_per_minute, errors, last_error=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO collector_health(id, status, running, last_scan, last_duration, events_per_minute, errors, last_error, updated_at)
        VALUES(1,?,?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET
            status=excluded.status,
            running=excluded.running,
            last_scan=excluded.last_scan,
            last_duration=excluded.last_duration,
            events_per_minute=excluded.events_per_minute,
            errors=excluded.errors,
            last_error=excluded.last_error,
            updated_at=excluded.updated_at
    """, (status, int(bool(running)), last_scan or "", float(last_duration or 0), float(events_per_minute or 0), int(errors or 0), last_error or "", now_string()))
    conn.commit()
    conn.close()


def database_info():
    totals = get_dashboard_totals()
    totals["emails"] = len(get_email_history())
    return totals


def reset_demo_database():
    conn = get_connection()
    cursor = conn.cursor()
    for table in ("logs", "alerts", "email_history", "devices", "collector_state", "file_integrity_state", "registry_state", "process_state", "usb_state", "network_state", "performance_state"):
        cursor.execute(f"DELETE FROM {table}")
        cursor.execute("DELETE FROM sqlite_sequence WHERE name=?", (table,))
    conn.commit()
    conn.close()


def clear_logs(reset_ids=True):
    conn = get_connection()
    conn.execute("DELETE FROM logs")
    if reset_ids:
        conn.execute("DELETE FROM sqlite_sequence WHERE name='logs'")
    conn.commit()
    conn.close()


def clear_alerts(reset_ids=True):
    conn = get_connection()
    conn.execute("DELETE FROM alerts")
    if reset_ids:
        conn.execute("DELETE FROM sqlite_sequence WHERE name='alerts'")
    conn.commit()
    conn.close()


def clear_email_history(reset_ids=True):
    conn = get_connection()
    conn.execute("DELETE FROM email_history")
    if reset_ids:
        conn.execute("DELETE FROM sqlite_sequence WHERE name='email_history'")
    conn.commit()
    conn.close()


def get_file_integrity_state():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM file_integrity_state ORDER BY path").fetchall()
    conn.close()
    return rows


def upsert_file_integrity_state(path, last_hash="", last_size=0, last_modified="", last_seen="", status="Baseline"):
    conn = get_connection()
    conn.execute("""
        INSERT INTO file_integrity_state(path, last_hash, last_size, last_modified, last_seen, status)
        VALUES(?,?,?,?,?,?)
        ON CONFLICT(path) DO UPDATE SET
            last_hash=excluded.last_hash,
            last_size=excluded.last_size,
            last_modified=excluded.last_modified,
            last_seen=excluded.last_seen,
            status=excluded.status
    """, (path, last_hash, int(last_size or 0), last_modified, last_seen, status))
    conn.commit()
    conn.close()


def get_registry_state():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM registry_state ORDER BY path").fetchall()
    conn.close()
    return rows


def upsert_registry_state(path, last_hash="", value_count=0, last_snapshot="", last_seen="", status="Baseline", last_error=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO registry_state(path, last_hash, value_count, last_snapshot, last_seen, status, last_error)
        VALUES(?,?,?,?,?,?,?)
        ON CONFLICT(path) DO UPDATE SET
            last_hash=excluded.last_hash,
            value_count=excluded.value_count,
            last_snapshot=excluded.last_snapshot,
            last_seen=excluded.last_seen,
            status=excluded.status,
            last_error=excluded.last_error
    """, (path, last_hash, int(value_count or 0), last_snapshot, last_seen, status, last_error))
    conn.commit()
    conn.close()


def get_process_state():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM process_state ORDER BY status DESC, name").fetchall()
    conn.close()
    return rows


def upsert_process_state(name, last_pid=0, last_command_line="", last_seen="", status="Baseline", occurrences=0, last_user="", last_error=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO process_state(name, last_pid, last_command_line, last_seen, status, occurrences, last_user, last_error)
        VALUES(?,?,?,?,?,?,?,?)
        ON CONFLICT(name) DO UPDATE SET
            last_pid=excluded.last_pid,
            last_command_line=excluded.last_command_line,
            last_seen=excluded.last_seen,
            status=excluded.status,
            occurrences=excluded.occurrences,
            last_user=excluded.last_user,
            last_error=excluded.last_error
    """, (name, int(last_pid or 0), last_command_line, last_seen, status, int(occurrences or 0), last_user, last_error))
    conn.commit()
    conn.close()


def get_usb_state():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM usb_state ORDER BY path").fetchall()
    conn.close()
    return rows


def upsert_usb_state(path, last_hash="", device_count=0, last_snapshot="", last_seen="", status="Baseline", last_error=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO usb_state(path, last_hash, device_count, last_snapshot, last_seen, status, last_error)
        VALUES(?,?,?,?,?,?,?)
        ON CONFLICT(path) DO UPDATE SET
            last_hash=excluded.last_hash,
            device_count=excluded.device_count,
            last_snapshot=excluded.last_snapshot,
            last_seen=excluded.last_seen,
            status=excluded.status,
            last_error=excluded.last_error
    """, (path, last_hash, int(device_count or 0), last_snapshot, last_seen, status, last_error))
    conn.commit()
    conn.close()


def get_network_state():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM network_state ORDER BY status DESC, risk_level DESC, remote_address, remote_port").fetchall()
    conn.close()
    return rows


def upsert_network_state(signature, protocol="", local_address="", local_port=0, remote_address="", remote_port=0, state="", pid=0, process_name="", last_hash="", last_snapshot="", last_seen="", status="Baseline", risk_level="INFO", last_error=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO network_state(signature, protocol, local_address, local_port, remote_address, remote_port, state, pid, process_name, last_hash, last_snapshot, last_seen, status, risk_level, last_error)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(signature) DO UPDATE SET
            protocol=excluded.protocol,
            local_address=excluded.local_address,
            local_port=excluded.local_port,
            remote_address=excluded.remote_address,
            remote_port=excluded.remote_port,
            state=excluded.state,
            pid=excluded.pid,
            process_name=excluded.process_name,
            last_hash=excluded.last_hash,
            last_snapshot=excluded.last_snapshot,
            last_seen=excluded.last_seen,
            status=excluded.status,
            risk_level=excluded.risk_level,
            last_error=excluded.last_error
    """, (signature, protocol, local_address, int(local_port or 0), remote_address, int(remote_port or 0), state, int(pid or 0), process_name, last_hash, last_snapshot, last_seen, status, risk_level, last_error))
    conn.commit()
    conn.close()


def get_performance_state():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM performance_state ORDER BY metric").fetchall()
    conn.close()
    return rows


def upsert_performance_state(metric, value=0, unit="", status="Normal", detail="", threshold="", last_seen="", last_error=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO performance_state(metric, value, unit, status, detail, threshold, last_seen, last_error)
        VALUES(?,?,?,?,?,?,?,?)
        ON CONFLICT(metric) DO UPDATE SET
            value=excluded.value,
            unit=excluded.unit,
            status=excluded.status,
            detail=excluded.detail,
            threshold=excluded.threshold,
            last_seen=excluded.last_seen,
            last_error=excluded.last_error
    """, (metric, float(value or 0), unit, status, detail, threshold, last_seen, last_error))
    conn.commit()
    conn.close()


def close_database():
    pass


if __name__ == "__main__":
    initialize_database()
    print(database_info())
