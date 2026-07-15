from flask import Flask, Response, flash, g, jsonify, redirect, render_template, request, session, url_for

from auth import authenticate_user, can_manage, login_required, login_user, load_current_user, logout_user, role_required
from collector import collect_windows_logs, get_collector_health_snapshot, start_background_collector
from config import (
    AGENT_API_KEY,
    AGENT_DEFAULT_INTERVAL,
    AGENT_ENABLED,
    AGENT_ENABLED_SOURCES,
    AGENT_HEARTBEAT_INTERVAL,
    AGENT_SERVER_ADDRESS,
    APP_VERSION,
    EMAIL_ENABLED,
    SECRET_KEY,
    SIEM_HOST,
    SIEM_PORT,
    SYSMON_CHANNEL,
)
from file_integrity import scan_file_integrity, start_background_file_integrity_monitor
from ioc_scanner import scan_indicators
from process_monitor import scan_processes, start_background_process_monitor
from performance_monitor import scan_performance, start_background_performance_monitor
from network_monitor import scan_network, start_background_network_monitor
from registry_monitor import scan_registry, start_background_registry_monitor
from usb_monitor import scan_usb, start_background_usb_monitor
from database import (
    get_alert_statistics,
    get_alerts,
    get_alert_timeline,
    create_case,
    create_incident,
    get_app_setting,
    get_app_settings,
    get_cases,
    get_collector_status,
    get_dashboard_totals,
    get_device_inventory,
    get_email_history,
    get_event_statistics,
    get_incidents,
    get_hourly_events,
    get_login_summary,
    get_logs,
    get_executive_overview,
    get_severity_statistics,
    get_threat_statistics,
    get_threat_trend,
    get_top_sources,
    get_top_users,
    get_users,
    initialize_database,
    insert_audit_log,
    insert_log,
    list_users,
    register_device,
    search_alerts,
    search_email_history,
    search_logs,
    set_app_setting,
    update_case,
    update_incident_status,
    update_device_heartbeat,
)
from detector import detect_threats
from email_alert import send_test_email
from recommendations import get_recommendation
from report_generator import rows_to_csv, rows_to_pdf
from utils import now_string

app = Flask(__name__)
app.secret_key = SECRET_KEY
initialize_database()
_background_started = False
_file_integrity_started = False
_registry_started = False
_process_started = False
_usb_started = False
_network_started = False
_performance_started = False
PUBLIC_ENDPOINTS = {"login", "static", "api_agent_register", "api_agent_heartbeat", "api_logs", "api_config", "api_devices"}


def refresh_pipeline():
    collect_windows_logs()
    logs = get_logs(500)
    detect_threats(logs)


def ensure_background_services():
    global _background_started
    if not _background_started:
        _background_started = start_background_collector()


def ensure_file_integrity_monitor():
    global _file_integrity_started
    if not _file_integrity_started:
        _file_integrity_started = start_background_file_integrity_monitor()


def ensure_registry_monitor():
    global _registry_started
    if not _registry_started:
        _registry_started = start_background_registry_monitor()


def ensure_process_monitor():
    global _process_started
    if not _process_started:
        _process_started = start_background_process_monitor()


def ensure_usb_monitor():
    global _usb_started
    if not _usb_started:
        _usb_started = start_background_usb_monitor()


def ensure_network_monitor():
    global _network_started
    if not _network_started:
        _network_started = start_background_network_monitor()


def ensure_performance_monitor():
    global _performance_started
    if not _performance_started:
        _performance_started = start_background_performance_monitor()


@app.before_request
def _bootstrap_background_services():
    load_current_user()
    ensure_background_services()
    ensure_file_integrity_monitor()
    ensure_registry_monitor()
    ensure_process_monitor()
    ensure_usb_monitor()
    ensure_network_monitor()
    ensure_performance_monitor()
    if request.endpoint in PUBLIC_ENDPOINTS:
        return None
    if g.get("current_user") is None:
        return redirect(url_for("login", next=request.path))


def chart_pair(rows, label_key, value_key="total"):
    return {
        "labels": [row[label_key] for row in rows],
        "values": [row[value_key] for row in rows],
    }


def parse_id_list(raw_value):
    if not raw_value:
        return []
    return [int(value.strip()) for value in str(raw_value).split(",") if value.strip().isdigit()]


def get_effective_agent_settings():
    settings = get_app_settings()
    enabled_sources = settings.get("enabled_sources") or ",".join(AGENT_ENABLED_SOURCES)
    return {
        "agent_interval": int(settings.get("agent_interval") or AGENT_DEFAULT_INTERVAL),
        "heartbeat_interval": int(settings.get("heartbeat_interval") or AGENT_HEARTBEAT_INTERVAL),
        "server_address": settings.get("server_address") or AGENT_SERVER_ADDRESS,
        "enabled_sources": [item.strip() for item in enabled_sources.split(",") if item.strip()],
    }


def _agent_request_authorized():
    if not AGENT_ENABLED:
        return False
    api_key = request.headers.get("X-API-Key", "")
    auth_header = request.headers.get("Authorization", "")
    bearer = ""
    if auth_header.lower().startswith("bearer "):
        bearer = auth_header.split(" ", 1)[1].strip()
    return api_key == AGENT_API_KEY or bearer == AGENT_API_KEY


def _agent_identity(payload):
    hostname = payload.get("hostname") or payload.get("computer_name") or payload.get("computer") or "Unknown"
    device_id = payload.get("device_id") or hostname
    return {
        "device_id": device_id,
        "hostname": hostname,
        "computer_name": payload.get("computer_name") or payload.get("computer") or hostname,
        "operating_system": payload.get("operating_system", ""),
        "ip_address": payload.get("ip_address", ""),
        "mac_address": payload.get("mac_address", ""),
        "agent_version": payload.get("agent_version", APP_VERSION),
    }


def _normalize_agent_logs(payload):
    if isinstance(payload.get("logs"), list):
        records = payload["logs"]
    elif isinstance(payload.get("log"), dict):
        records = [payload["log"]]
    else:
        records = [payload]

    device = _agent_identity(payload)
    normalized = []
    for entry in records:
        item = dict(entry or {})
        item.setdefault("hostname", item.get("computer") or device["hostname"])
        item.setdefault("device_id", item.get("device_id") or device["device_id"])
        item.setdefault("computer", item.get("computer") or device["computer_name"])
        item.setdefault("ip_address", item.get("ip_address") or device["ip_address"])
        item.setdefault("agent_version", item.get("agent_version") or device["agent_version"])
        item.setdefault("source", item.get("source") or payload.get("source") or "Agent")
        item.setdefault("severity", item.get("severity") or "INFO")
        item.setdefault("timestamp", item.get("timestamp") or now_string())
        normalized.append(item)
    return device, normalized


@app.route("/")
@login_required
def dashboard():
    ensure_background_services()
    totals = get_dashboard_totals()
    executive = get_executive_overview()
    logs = get_logs(25)
    alerts = get_alerts(20)
    return render_template(
        "dashboard.html",
        totals=totals,
        executive=executive,
        logs=logs,
        alerts=alerts,
        email_enabled=EMAIL_ENABLED,
        collector_status=get_collector_status(),
        threat_trend=chart_pair(get_threat_trend(), "day"),
        monthly_threat_trend=chart_pair(executive["monthly_trend"], "day"),
        severity_chart=chart_pair(get_alert_statistics(), "severity"),
        top_users=chart_pair(get_top_users(8), "username"),
        top_sources=chart_pair(get_top_sources(8), "source"),
        event_chart=chart_pair(get_event_statistics(8), "event_type"),
        login_summary=get_login_summary(),
        collector_health=get_collector_health_snapshot(),
        email_test_status=request.args.get("email_test"),
        email_test_message=request.args.get("email_message"),
    )


@app.route("/logs")
@login_required
def logs_page():
    logs = search_logs(
        keyword=request.args.get("q", ""),
        severity=request.args.get("severity", ""),
        username=request.args.get("username", ""),
        source=request.args.get("source", ""),
        event_type=request.args.get("event_type", ""),
        date_from=request.args.get("date_from", ""),
        date_to=request.args.get("date_to", ""),
        limit=250,
    )
    return render_template("logs.html", logs=logs, filters=request.args)


@app.route("/alerts")
@login_required
def alerts_page():
    alerts = search_alerts(
        keyword=request.args.get("q", ""),
        severity=request.args.get("severity", ""),
        username=request.args.get("username", ""),
        source=request.args.get("source", ""),
    )
    recommendations = {alert["id"]: get_recommendation(alert["threat"]) for alert in alerts}
    return render_template("alerts.html", alerts=alerts, recommendations=recommendations, filters=request.args)


@app.route("/alerts/<int:alert_id>")
@login_required
def alert_detail(alert_id):
    detail = get_alert_timeline(alert_id)
    if detail is None:
        return redirect(url_for("alerts_page"))
    recommendation = get_recommendation(detail["alert"]["threat"])
    return render_template("alert_detail.html", detail=detail, recommendation=recommendation)


@app.route("/email-history")
@login_required
def email_history_page():
    history = search_email_history(
        receiver=request.args.get("receiver", ""),
        severity=request.args.get("severity", ""),
        threat=request.args.get("threat", ""),
        status=request.args.get("status", ""),
        limit=250,
    )
    totals = get_dashboard_totals()
    return render_template("email_history.html", history=history, totals=totals, filters=request.args)


@app.route("/analytics")
@login_required
def analytics_page():
    logs = get_logs(500)
    alerts = get_alerts(500)
    return render_template(
        "analytics.html",
        logs=logs,
        alerts=alerts,
        totals=get_dashboard_totals(),
        threat_trend=chart_pair(get_threat_trend(14), "day"),
        severity_distribution=chart_pair(get_alert_statistics(), "severity"),
        log_severity=chart_pair(get_severity_statistics(), "severity"),
        user_activity=chart_pair(get_top_users(10), "username"),
        hourly_events=chart_pair(get_hourly_events(), "hour"),
        event_types=chart_pair(get_event_statistics(10), "event_type"),
        top_sources=chart_pair(get_top_sources(10), "source"),
        threat_stats=chart_pair(get_threat_statistics(10), "threat"),
    )


@app.route("/reports")
@login_required
def reports_page():
    totals = get_dashboard_totals()
    executive = get_executive_overview()
    alerts = get_alerts(100)
    logs = get_logs(100)
    threat_stats = get_threat_statistics(10)
    return render_template(
        "reports.html",
        totals=totals,
        executive=executive,
        alerts=alerts,
        logs=logs,
        threat_trend=chart_pair(get_threat_trend(14), "day"),
        severity_chart=chart_pair(get_alert_statistics(), "severity"),
        top_users=chart_pair(get_top_users(8), "username"),
        top_sources=chart_pair(get_top_sources(8), "source"),
        threat_stats=chart_pair(threat_stats, "threat"),
        login_summary=get_login_summary(),
        executive_monthly=chart_pair(executive["monthly_trend"], "day"),
    )


@app.route("/users")
@login_required
def users_page():
    users = get_users()
    return render_template("users.html", users=users, top_users=get_top_users(10), app_users=list_users())


@app.route("/ioc-scanner", methods=["GET", "POST"])
@login_required
def ioc_scanner_page():
    raw_input = ""
    results = []
    summary = {"Safe": 0, "Suspicious": 0, "Malicious": 0}
    if request.method == "POST":
        raw_input = request.form.get("ioc_input", "")
        results = scan_indicators(raw_input)
        for row in results:
            summary[row["verdict"]] = summary.get(row["verdict"], 0) + 1
    return render_template("ioc_scanner.html", raw_input=raw_input, results=results, summary=summary)


@app.route("/devices")
@login_required
def devices_page():
    devices = get_device_inventory()
    online = sum(1 for device in devices if device["status"] == "Online")
    idle = sum(1 for device in devices if device["status"] == "Idle")
    offline = sum(1 for device in devices if device["status"] == "Offline")
    return render_template(
        "devices.html",
        devices=devices,
        totals={"online": online, "idle": idle, "offline": offline, "total": len(devices)},
    )


@app.route("/agent-status")
@login_required
def agent_status_page():
    devices = get_device_inventory()
    health = get_collector_health_snapshot()
    return render_template(
        "agent_status.html",
        devices=devices[:50],
        totals={
            "connected": len(devices),
            "online": sum(1 for device in devices if device["status"] == "Online"),
            "offline": sum(1 for device in devices if device["status"] == "Offline"),
            "idle": sum(1 for device in devices if device["status"] == "Idle"),
        },
        health=health,
        settings=get_effective_agent_settings(),
    )


@app.route("/settings", methods=["GET", "POST"])
@role_required("Administrator")
def settings_page():
    if request.method == "POST":
        set_app_setting("agent_interval", request.form.get("agent_interval", str(AGENT_DEFAULT_INTERVAL)))
        set_app_setting("heartbeat_interval", request.form.get("heartbeat_interval", str(AGENT_HEARTBEAT_INTERVAL)))
        set_app_setting("server_address", request.form.get("server_address", AGENT_SERVER_ADDRESS))
        set_app_setting("enabled_sources", request.form.get("enabled_sources", ",".join(AGENT_ENABLED_SOURCES)))
        flash("Centralized agent settings updated.", "success")
        insert_audit_log(g.current_user["username"], "Update Settings", "Configuration", "Agent settings updated", request.remote_addr or "", "SUCCESS")
        return redirect(url_for("settings_page"))

    settings = get_effective_agent_settings()
    return render_template("settings.html", settings=settings, raw_settings=get_app_settings())


@app.route("/file-integrity")
@login_required
def file_integrity_page():
    results = scan_file_integrity()
    return render_template("file_integrity.html", results=results, monitored=len(results))


@app.route("/registry-monitor")
@login_required
def registry_monitor_page():
    results = scan_registry()
    summary = {
        "clean": sum(1 for row in results if row["status"] == "Clean"),
        "baseline": sum(1 for row in results if row["status"] == "Baseline"),
        "problem": sum(1 for row in results if row["status"] in {"Modified", "Missing", "Error"}),
    }
    return render_template("registry_monitor.html", results=results, monitored=len(results), summary=summary)


@app.route("/process-monitor")
@login_required
def process_monitor_page():
    results = scan_processes()
    summary = {
        "running": sum(1 for row in results if row["status"] == "Running"),
        "suspicious": sum(1 for row in results if row["status"] == "Suspicious"),
        "baseline": sum(1 for row in results if row["status"] == "Baseline"),
        "total": len(results),
    }
    return render_template("process_monitor.html", results=results, summary=summary, monitored=len(results))


@app.route("/usb-monitor")
@login_required
def usb_monitor_page():
    results = scan_usb()
    summary = {
        "baseline": sum(1 for row in results if row["status"] == "Baseline"),
        "clean": sum(1 for row in results if row["status"] == "Clean"),
        "modified": sum(1 for row in results if row["status"] == "Modified"),
        "problem": sum(1 for row in results if row["status"] in {"Missing", "Unavailable", "Error"}),
    }
    return render_template("usb_monitor.html", results=results, summary=summary, monitored=len(results))


@app.route("/network-monitor")
@login_required
def network_monitor_page():
    results = scan_network()
    summary = {
        "total": len(results),
        "suspicious": sum(1 for row in results if row["risk_level"] in {"HIGH", "CRITICAL"}),
        "established": sum(1 for row in results if row["state"] == "ESTABLISHED"),
        "listening": sum(1 for row in results if row["state"] == "LISTENING"),
        "external": sum(1 for row in results if row["risk_level"] in {"MEDIUM", "HIGH", "CRITICAL"}),
    }
    return render_template("network_monitor.html", results=results, summary=summary, monitored=len(results))


@app.route("/performance")
@login_required
def performance_page():
    results = scan_performance()
    summary = {
        "normal": sum(1 for row in results if row["status"] == "Normal"),
        "high": sum(1 for row in results if row["status"] == "High"),
        "critical": sum(1 for row in results if row["status"] == "Critical"),
        "unavailable": sum(1 for row in results if row["status"] == "Unavailable"),
    }
    return render_template("performance.html", results=results, summary=summary, monitored=len(results))


@app.route("/sysmon")
@login_required
def sysmon_page():
    logs = search_logs(source=SYSMON_CHANNEL, limit=250)
    summary = {
        "total": len(logs),
        "process_create": sum(1 for row in logs if "Process Create" in row["event_type"]),
        "network": sum(1 for row in logs if "Network Connection" in row["event_type"]),
        "file": sum(1 for row in logs if "File" in row["event_type"]),
        "registry": sum(1 for row in logs if "Registry" in row["event_type"]),
        "dns": sum(1 for row in logs if "DNS" in row["event_type"]),
    }
    return render_template("sysmon.html", logs=logs, summary=summary, monitored=len(logs))


@app.route("/incidents", methods=["GET", "POST"])
@login_required
def incidents_page():
    if request.method == "POST":
        if not can_manage():
            flash("You do not have permission to create incidents.", "error")
            return redirect(url_for("incidents_page"))
        create_incident(
            title=request.form.get("title", "Security Incident"),
            severity=request.form.get("severity", "MEDIUM"),
            status=request.form.get("status", "Open"),
            assigned_analyst=request.form.get("assigned_analyst", ""),
            description=request.form.get("description", ""),
            notes=request.form.get("notes", ""),
            linked_alert_ids=parse_id_list(request.form.get("linked_alert_ids", "")),
            correlation_key=request.form.get("correlation_key") or None,
        )
        return redirect(url_for("incidents_page"))

    return render_template(
        "incidents.html",
        incidents=get_incidents(),
        alerts=get_alerts(50),
    )


@app.route("/incidents/<int:incident_id>/update", methods=["POST"])
@login_required
def update_incident_route(incident_id):
    if not can_manage():
        flash("You do not have permission to update incidents.", "error")
        return redirect(url_for("incidents_page"))
    update_incident_status(
        incident_id,
        request.form.get("status", "Open"),
        assigned_analyst=request.form.get("assigned_analyst"),
        notes=request.form.get("notes"),
        description=request.form.get("description"),
    )
    return redirect(url_for("incidents_page"))


@app.route("/cases", methods=["GET", "POST"])
@login_required
def cases_page():
    if request.method == "POST":
        if not can_manage():
            flash("You do not have permission to create cases.", "error")
            return redirect(url_for("cases_page"))
        create_case(
            title=request.form.get("title", "Investigation Case"),
            owner=request.form.get("owner", ""),
            status=request.form.get("status", "Open"),
            evidence=request.form.get("evidence", ""),
            notes=request.form.get("notes", ""),
            timeline=request.form.get("timeline", ""),
            related_alert_ids=parse_id_list(request.form.get("related_alert_ids", "")),
        )
        return redirect(url_for("cases_page"))

    return render_template(
        "cases.html",
        cases=get_cases(),
        alerts=get_alerts(50),
    )


@app.route("/cases/<int:case_id>/update", methods=["POST"])
@login_required
def update_case_route(case_id):
    if not can_manage():
        flash("You do not have permission to update cases.", "error")
        return redirect(url_for("cases_page"))
    update_case(
        case_id,
        status=request.form.get("status"),
        owner=request.form.get("owner"),
        evidence=request.form.get("evidence"),
        notes=request.form.get("notes"),
        timeline=request.form.get("timeline"),
        related_alert_ids=parse_id_list(request.form.get("related_alert_ids", "")) if request.form.get("related_alert_ids") else None,
    )
    return redirect(url_for("cases_page"))


@app.route("/search")
@login_required
def global_search():
    keyword = request.args.get("q", "")
    return render_template(
        "logs.html",
        logs=search_logs(keyword=keyword, limit=250),
        filters={"q": keyword},
        global_search=True,
    )


@app.route("/api/dashboard")
@login_required
def dashboard_api():
    executive = get_executive_overview()
    return jsonify({
        "totals": get_dashboard_totals(),
        "executive": executive,
        "latest_alerts": [dict(alert) for alert in get_alerts(10)],
        "threat_trend": chart_pair(get_threat_trend(), "day"),
        "monthly_threat_trend": chart_pair(executive["monthly_trend"], "day"),
        "severity": chart_pair(get_alert_statistics(), "severity"),
        "top_users": chart_pair(get_top_users(8), "username"),
        "top_sources": chart_pair(get_top_sources(8), "source"),
        "events": chart_pair(get_event_statistics(8), "event_type"),
        "login_summary": get_login_summary(),
    })


@app.route("/api/config")
def api_config():
    if not _agent_request_authorized():
        return jsonify({"error": "Unauthorized"}), 401
    settings = get_effective_agent_settings()
    return jsonify({
        "app_version": APP_VERSION,
        "server_address": settings["server_address"],
        "default_interval": settings["agent_interval"],
        "heartbeat_interval": settings["heartbeat_interval"],
        "enabled_sources": settings["enabled_sources"],
        "email_enabled": EMAIL_ENABLED,
    })


@app.route("/api/devices")
def api_devices():
    if not _agent_request_authorized():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "devices": [dict(device) for device in get_device_inventory(500)],
        "totals": get_dashboard_totals(),
    })


@app.route("/api/agents/register", methods=["POST"])
def api_agent_register():
    if not _agent_request_authorized():
        return jsonify({"error": "Unauthorized"}), 401
    payload = request.get_json(silent=True) or {}
    device = _agent_identity(payload)
    register_device(
        device["device_id"],
        device["hostname"],
        computer_name=device["computer_name"],
        operating_system=device["operating_system"],
        ip_address=device["ip_address"],
        mac_address=device["mac_address"],
        agent_version=device["agent_version"],
        status="Online",
        heartbeat=now_string(),
        last_seen=now_string(),
    )
    insert_audit_log("AGENT", "Register", "Device", f"{device['hostname']}|{device['device_id']}", payload.get("ip_address", ""), "SUCCESS")
    return jsonify({"success": True, "device": device, "server_time": now_string()})


@app.route("/api/agents/heartbeat", methods=["POST"])
def api_agent_heartbeat():
    if not _agent_request_authorized():
        return jsonify({"error": "Unauthorized"}), 401
    payload = request.get_json(silent=True) or {}
    device = _agent_identity(payload)
    update_device_heartbeat(
        device["device_id"],
        hostname=device["hostname"],
        computer_name=device["computer_name"],
        operating_system=device["operating_system"],
        ip_address=device["ip_address"],
        mac_address=device["mac_address"],
        agent_version=device["agent_version"],
        last_seen=now_string(),
        status="Online",
    )
    insert_audit_log("AGENT", "Heartbeat", "Device", f"{device['hostname']}|{device['device_id']}", payload.get("ip_address", ""), "SUCCESS")
    return jsonify({"success": True, "server_time": now_string()})


@app.route("/api/logs", methods=["POST"])
def api_logs():
    if not _agent_request_authorized():
        return jsonify({"error": "Unauthorized"}), 401
    payload = request.get_json(silent=True) or {}
    device, records = _normalize_agent_logs(payload)
    inserted = 0
    errors = []
    register_device(
        device["device_id"],
        device["hostname"],
        computer_name=device["computer_name"],
        operating_system=device["operating_system"],
        ip_address=device["ip_address"],
        mac_address=device["mac_address"],
        agent_version=device["agent_version"],
        status="Online",
        heartbeat=now_string(),
        last_seen=now_string(),
    )
    for record in records:
        try:
            if insert_log(
                timestamp=record.get("timestamp", now_string()),
                event_type=record.get("event_type", "Agent Event"),
                username=record.get("username", "SYSTEM"),
                source=record.get("source", "Agent"),
                severity=record.get("severity", "INFO"),
                computer=record.get("computer", device["computer_name"]),
                hostname=record.get("hostname", device["hostname"]),
                device_id=record.get("device_id", device["device_id"]),
                ip_address=record.get("ip_address", device["ip_address"]),
                agent_version=record.get("agent_version", device["agent_version"]),
                channel=record.get("channel", record.get("source", "Agent")),
                event_id=int(record.get("event_id", 0) or 0),
                message=record.get("message", ""),
                raw_event=record.get("raw_event", record.get("message", "")),
                record_number=int(record.get("record_number", 0) or 0),
            ):
                inserted += 1
        except Exception as exc:
            errors.append(str(exc))
    if inserted:
        detect_threats(get_logs(500))
    insert_audit_log("AGENT", "Log Receive", "API", f"{device['hostname']} inserted={inserted}", payload.get("ip_address", ""), "SUCCESS" if not errors else "FAILED")
    return jsonify({
        "success": True,
        "inserted": inserted,
        "received": len(records),
        "errors": errors,
        "device": device,
        "server_time": now_string(),
    })


@app.route("/collect")
@role_required("Administrator", "SOC Analyst")
def collect_now():
    insert_audit_log(g.current_user["username"], "Collect", "Collector", "Manual collect requested", request.remote_addr or "", "SUCCESS")
    refresh_pipeline()
    return redirect(url_for("dashboard"))


@app.route("/api/collector-health")
@login_required
def collector_health_api():
    ensure_background_services()
    return jsonify(get_collector_health_snapshot())


@app.route("/send-test-email", methods=["POST"])
@role_required("Administrator", "SOC Analyst")
def send_test_email_route():
    sent, detail = send_test_email()
    insert_audit_log(g.current_user["username"], "Email Test", "Email", detail, request.remote_addr or "", "SUCCESS" if sent else "FAILED")
    return redirect(url_for(
        "dashboard",
        email_test="success" if sent else "failure",
        email_message=detail,
    ))


@app.route("/export/<kind>/<fmt>")
@role_required("Administrator", "SOC Analyst")
def export_data(kind, fmt):
    insert_audit_log(g.current_user["username"], "Export", kind.title(), f"Format={fmt}", request.remote_addr or "", "SUCCESS")
    if kind == "alerts":
        rows = search_alerts(keyword=request.args.get("q", ""), severity=request.args.get("severity", ""))
        fields = ["id", "timestamp", "last_seen", "severity", "threat", "username", "source", "computer", "event_id", "email_sent", "count", "mitre", "recommendation"]
        title = "SIEM Alerts Report"
        summary_lines = [
            f"Total alerts: {len(rows)}",
            f"Critical alerts: {sum(1 for row in rows if str(row.get('severity', '')).upper() == 'CRITICAL')}",
            f"High alerts: {sum(1 for row in rows if str(row.get('severity', '')).upper() == 'HIGH')}",
        ]
        if rows:
            summary_lines.append(f"Top threat: {rows[0].get('threat', 'Unknown')}")
    else:
        rows = search_logs(
            keyword=request.args.get("q", ""),
            severity=request.args.get("severity", ""),
            username=request.args.get("username", ""),
            source=request.args.get("source", ""),
            event_type=request.args.get("event_type", ""),
            date_from=request.args.get("date_from", ""),
            date_to=request.args.get("date_to", ""),
            limit=1000,
        )
        fields = ["id", "timestamp", "event_id", "event_type", "severity", "username", "source", "computer", "channel", "message"]
        title = "SIEM Logs Report"
        summary_lines = [
            f"Total logs: {len(rows)}",
            f"Unique sources: {len({row.get('source', '') for row in rows if row.get('source')})}",
            f"Unique users: {len({row.get('username', '') for row in rows if row.get('username')})}",
        ]

    if fmt == "pdf":
        payload = rows_to_pdf(title, rows, fields, summary_lines=summary_lines)
        return Response(payload, mimetype="application/pdf", headers={"Content-Disposition": f"attachment; filename={kind}.pdf"})

    payload = rows_to_csv(rows, fields)
    return Response(payload, mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={kind}.csv"})


@app.context_processor
def inject_globals():
    current_user = g.get("current_user")
    return {
        "email_history": get_email_history(10),
        "current_user": current_user,
        "can_manage": bool(current_user and current_user.get("role") in {"Administrator", "SOC Analyst"}),
        "can_admin": bool(current_user and current_user.get("role") == "Administrator"),
    }


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.get("current_user") is not None:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "")
        user = authenticate_user(username, request.form.get("password", ""))
        if user:
            login_user(user, request.remote_addr or "")
            flash(f"Welcome back, {user['username']}.", "success")
            next_url = request.args.get("next") or url_for("dashboard")
            return redirect(next_url)
        insert_audit_log(username or "Unknown", "Login Failed", "Authentication", "Invalid credentials", request.remote_addr or "", "FAILED")
        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


if __name__ == "__main__":
    ensure_background_services()
    app.run(host=SIEM_HOST, port=SIEM_PORT, debug=True)
