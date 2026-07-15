DEFAULT_COMMANDS = [
    "whoami /all",
    "net user <username>",
    "wevtutil qe Security /q:\"*[System[(EventID=<event_id>)]]\" /f:text /c:10",
]

RECOMMENDATIONS = {
    "Failed Login": {
        "description": "A Windows authentication attempt failed.",
        "why": "The password may be wrong, the account may be targeted, or a service may be using stale credentials.",
        "immediate_action": "Confirm whether the user attempted to sign in and review the source host.",
        "recommended_fix": "Reset the password if suspicious and remove stale saved credentials.",
        "long_term_defense": "Enable account lockout policy, MFA where possible, and alert on repeated failures.",
        "mitre": "T1110 - Brute Force",
        "commands": ["net user <username>", "wevtutil qe Security /q:\"*[System[(EventID=4625)]]\" /f:text /c:20"],
    },
    "Multiple Failed Logins": {
        "description": "Several failed sign-ins were seen for the same user in a short window.",
        "why": "This often happens during password guessing or misconfigured services.",
        "immediate_action": "Temporarily lock or monitor the account and check the source workstation.",
        "recommended_fix": "Reset credentials and remove suspicious sessions.",
        "long_term_defense": "Tune lockout thresholds and monitor failed login velocity.",
        "mitre": "T1110 - Brute Force",
        "commands": ["net accounts", "net user <username> /domain"],
    },
    "Brute Force": {
        "description": "A high volume of failed authentication attempts suggests brute force activity.",
        "why": "An attacker may be trying many passwords against one account.",
        "immediate_action": "Disable the affected account if activity is unauthorized.",
        "recommended_fix": "Reset the password, review recent successful logins, and block the source.",
        "long_term_defense": "Use MFA, account lockout, and IP-based conditional access.",
        "mitre": "T1110 - Brute Force",
        "commands": ["net user <username> /active:no", "netsh advfirewall firewall show rule name=all"],
    },
    "Password Spray": {
        "description": "Failures across multiple accounts can indicate password spraying.",
        "why": "Attackers often try one common password across many users to avoid lockouts.",
        "immediate_action": "Identify affected users and block the source address or host.",
        "recommended_fix": "Force password resets for impacted accounts.",
        "long_term_defense": "Ban common passwords and require MFA.",
        "mitre": "T1110.003 - Password Spraying",
        "commands": ["net accounts", "Get-LocalUser | Select Name,Enabled"],
    },
    "Successful Login": {
        "description": "A successful Windows logon was recorded.",
        "why": "Normal activity unless the account, source, or time is unusual.",
        "immediate_action": "Validate unusual privileged or remote sessions.",
        "recommended_fix": "No action required for expected activity.",
        "long_term_defense": "Baseline normal user activity and alert on deviations.",
        "mitre": "T1078 - Valid Accounts",
        "commands": ["query user", "whoami /groups"],
    },
    "Administrator Login": {
        "description": "Activity from an administrator-equivalent account was detected.",
        "why": "Privileged accounts create higher operational risk and are commonly targeted.",
        "immediate_action": "Confirm the admin action was authorized.",
        "recommended_fix": "Review group membership and recent privilege use.",
        "long_term_defense": "Use separate admin accounts and just-in-time administration.",
        "mitre": "T1078.002 - Domain Accounts",
        "commands": ["net localgroup administrators", "whoami /priv"],
    },
    "Privilege Escalation": {
        "description": "Special privileges were assigned or used.",
        "why": "This can be legitimate admin work or a sign of privilege escalation.",
        "immediate_action": "Review the account, logon session, and parent activity.",
        "recommended_fix": "Remove unnecessary privileges and investigate recent process creation.",
        "long_term_defense": "Implement least privilege and privileged access monitoring.",
        "mitre": "T1068 - Exploitation for Privilege Escalation",
        "commands": ["whoami /priv", "net localgroup administrators"],
    },
    "Account Locked": {
        "description": "A Windows account was locked.",
        "why": "Repeated failed sign-ins exceeded the configured policy.",
        "immediate_action": "Contact the account owner and review failed login sources.",
        "recommended_fix": "Unlock only after confirming legitimacy.",
        "long_term_defense": "Monitor lockout sources and stale service credentials.",
        "mitre": "T1110 - Brute Force",
        "commands": ["net user <username>", "wevtutil qe Security /q:\"*[System[(EventID=4740)]]\" /f:text /c:10"],
    },
    "Audit Log Cleared": {
        "description": "The Windows audit log was cleared.",
        "why": "Log clearing can be administrative maintenance or attacker anti-forensics.",
        "immediate_action": "Treat as high priority unless tied to approved maintenance.",
        "recommended_fix": "Preserve remaining logs and investigate the account that cleared them.",
        "long_term_defense": "Forward logs to centralized storage and restrict log management rights.",
        "mitre": "T1070.001 - Clear Windows Event Logs",
        "commands": ["wevtutil gli Security", "auditpol /get /category:*"],
    },
    "New Service Installed": {
        "description": "A service was installed on the host.",
        "why": "Services are often used for persistence or legitimate software deployment.",
        "immediate_action": "Validate the service name, path, publisher, and installer.",
        "recommended_fix": "Disable and remove unauthorized services.",
        "long_term_defense": "Monitor service creation and enforce application control.",
        "mitre": "T1543.003 - Windows Service",
        "commands": ["sc query", "sc qc <service_name>"],
    },
    "Application Crash": {
        "description": "An application crash or .NET exception was observed.",
        "why": "Crashes may be stability issues, exploit attempts, or failed tooling.",
        "immediate_action": "Review the crashing process and recent changes.",
        "recommended_fix": "Patch or reinstall the affected application.",
        "long_term_defense": "Monitor recurring crashes and protect high-risk applications.",
        "mitre": "T1499 - Endpoint Denial of Service",
        "commands": ["wevtutil qe Application /f:text /c:20"],
    },
    "Unexpected Shutdown": {
        "description": "The host shut down unexpectedly.",
        "why": "Power loss, crash, tampering, or system failure may have occurred.",
        "immediate_action": "Check system health and nearby security events.",
        "recommended_fix": "Resolve driver, power, or hardware issues and investigate suspicious timing.",
        "long_term_defense": "Centralize logs and monitor endpoint health.",
        "mitre": "T1529 - System Shutdown/Reboot",
        "commands": ["wevtutil qe System /q:\"*[System[(EventID=6008)]]\" /f:text /c:10"],
    },
}


def get_recommendation(threat):
    data = RECOMMENDATIONS.get(threat, {})
    return {
        "threat": threat,
        "description": data.get("description", "A security-relevant event was detected by the SIEM."),
        "why": data.get("why", "The event matched a monitored Windows security condition."),
        "immediate_action": data.get("immediate_action", "Review the event context and validate whether the activity is expected."),
        "recommended_fix": data.get("recommended_fix", "Contain the source if suspicious and document the investigation."),
        "long_term_defense": data.get("long_term_defense", "Continue collecting logs and tune alerts against normal activity."),
        "mitre": data.get("mitre", "T1087 - Account Discovery"),
        "commands": data.get("commands", DEFAULT_COMMANDS),
    }


def format_recommendation(threat):
    rec = get_recommendation(threat)
    commands = "\n".join(f"- {command}" for command in rec["commands"])
    return (
        f"Threat: {rec['threat']}\n"
        f"Description: {rec['description']}\n"
        f"Why it happened: {rec['why']}\n"
        f"Immediate Action: {rec['immediate_action']}\n"
        f"Recommended Fix: {rec['recommended_fix']}\n"
        f"Long-term Defense: {rec['long_term_defense']}\n"
        f"MITRE ATT&CK: {rec['mitre']}\n"
        f"Investigation Commands:\n{commands}"
    )
