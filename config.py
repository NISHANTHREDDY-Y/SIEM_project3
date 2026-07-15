import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_DIR = os.path.join(BASE_DIR, "logs")
DB_PATH = os.path.join(DATA_DIR, "siem.db")

COLLECTOR_CHANNELS = ("Security", "System", "Application")
COLLECTOR_LIMIT_PER_CHANNEL = int(os.getenv("SIEM_COLLECTOR_LIMIT", "75"))
COLLECTOR_SCAN_INTERVAL = int(os.getenv("SIEM_COLLECTOR_SCAN_INTERVAL", "30"))
COLLECTOR_BACKGROUND_ENABLED = os.getenv("SIEM_COLLECTOR_BACKGROUND_ENABLED", "1") == "1"
SYSMON_SUPPORT_ENABLED = os.getenv("SIEM_SYSMON_SUPPORT_ENABLED", "1") == "1"
SYSMON_CHANNEL = os.getenv("SIEM_SYSMON_CHANNEL", "Microsoft-Windows-Sysmon/Operational")
FILE_INTEGRITY_SCAN_INTERVAL = int(os.getenv("SIEM_FILE_INTEGRITY_SCAN_INTERVAL", "60"))
FILE_INTEGRITY_BACKGROUND_ENABLED = os.getenv("SIEM_FILE_INTEGRITY_BACKGROUND_ENABLED", "1") == "1"
FILE_INTEGRITY_TARGETS = tuple(
    item.strip()
    for item in os.getenv(
        "SIEM_FILE_INTEGRITY_TARGETS",
        "app.py,database.py,detector.py,email_alert.py,collector.py,config.py,recommendations.py,report_generator.py,utils.py",
    ).split(",")
    if item.strip()
)
REGISTRY_SCAN_INTERVAL = int(os.getenv("SIEM_REGISTRY_SCAN_INTERVAL", "75"))
REGISTRY_BACKGROUND_ENABLED = os.getenv("SIEM_REGISTRY_BACKGROUND_ENABLED", "1") == "1"
REGISTRY_TARGETS = tuple(
    item.strip()
    for item in os.getenv(
        "SIEM_REGISTRY_TARGETS",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run,HKLM\Software\Microsoft\Windows\CurrentVersion\Run,HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System,HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System",
    ).split(",")
    if item.strip()
)
PROCESS_SCAN_INTERVAL = int(os.getenv("SIEM_PROCESS_SCAN_INTERVAL", "60"))
PROCESS_BACKGROUND_ENABLED = os.getenv("SIEM_PROCESS_BACKGROUND_ENABLED", "1") == "1"
PROCESS_SUSPICIOUS_NAMES = tuple(
    item.strip().lower()
    for item in os.getenv(
        "SIEM_PROCESS_SUSPICIOUS_NAMES",
        "powershell.exe,cmd.exe,wmic.exe,rundll32.exe,psexec.exe,mshta.exe,cscript.exe,wscript.exe,regsvr32.exe",
    ).split(",")
    if item.strip()
)
USB_SCAN_INTERVAL = int(os.getenv("SIEM_USB_SCAN_INTERVAL", "90"))
USB_BACKGROUND_ENABLED = os.getenv("SIEM_USB_BACKGROUND_ENABLED", "1") == "1"
USB_TARGETS = tuple(
    item.strip()
    for item in os.getenv(
        "SIEM_USB_TARGETS",
        r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR,HKLM\SYSTEM\CurrentControlSet\Enum\USB",
    ).split(",")
    if item.strip()
)
NETWORK_SCAN_INTERVAL = int(os.getenv("SIEM_NETWORK_SCAN_INTERVAL", "60"))
NETWORK_BACKGROUND_ENABLED = os.getenv("SIEM_NETWORK_BACKGROUND_ENABLED", "1") == "1"
NETWORK_SUSPICIOUS_PORTS = {
    int(port)
    for port in os.getenv(
        "SIEM_NETWORK_SUSPICIOUS_PORTS",
        "22,23,25,110,135,139,143,445,3389,4444,5555,6666,8080,8443,9001,1337,31337",
    ).split(",")
    if port.strip().isdigit()
}
NETWORK_COMMON_PORTS = {
    int(port)
    for port in os.getenv(
        "SIEM_NETWORK_COMMON_PORTS",
        "53,80,123,139,389,443,445,465,587,993,995,1433,1521,3306,3389",
    ).split(",")
    if port.strip().isdigit()
}
PERFORMANCE_SCAN_INTERVAL = int(os.getenv("SIEM_PERFORMANCE_SCAN_INTERVAL", "60"))
PERFORMANCE_BACKGROUND_ENABLED = os.getenv("SIEM_PERFORMANCE_BACKGROUND_ENABLED", "1") == "1"
PERFORMANCE_CPU_HIGH = float(os.getenv("SIEM_PERFORMANCE_CPU_HIGH", "90"))
PERFORMANCE_CPU_CRITICAL = float(os.getenv("SIEM_PERFORMANCE_CPU_CRITICAL", "95"))
PERFORMANCE_MEMORY_LOW_MB = float(os.getenv("SIEM_PERFORMANCE_MEMORY_LOW_MB", "1024"))
PERFORMANCE_MEMORY_CRITICAL_MB = float(os.getenv("SIEM_PERFORMANCE_MEMORY_CRITICAL_MB", "512"))
PERFORMANCE_DISK_HIGH = float(os.getenv("SIEM_PERFORMANCE_DISK_HIGH", "80"))
PERFORMANCE_DISK_CRITICAL = float(os.getenv("SIEM_PERFORMANCE_DISK_CRITICAL", "95"))
DEMO_MODE = os.getenv("SIEM_DEMO_MODE", "0") == "1"

APP_VERSION = os.getenv("SIEM_APP_VERSION", "3.0")

SECRET_KEY = os.getenv("SIEM_SECRET_KEY", "siem-demo-secret-key")

DEFAULT_ADMIN_USERNAME = os.getenv("SIEM_ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.getenv("SIEM_ADMIN_PASSWORD", "admin123")
DEFAULT_ANALYST_USERNAME = os.getenv("SIEM_ANALYST_USERNAME", "analyst")
DEFAULT_ANALYST_PASSWORD = os.getenv("SIEM_ANALYST_PASSWORD", "analyst123")
DEFAULT_VIEWER_USERNAME = os.getenv("SIEM_VIEWER_USERNAME", "viewer")
DEFAULT_VIEWER_PASSWORD = os.getenv("SIEM_VIEWER_PASSWORD", "viewer123")

SMTP_SERVER = os.getenv("SIEM_SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SIEM_SMTP_PORT", "587"))
SENDER_EMAIL = os.getenv("SIEM_SENDER_EMAIL", "")
SENDER_PASSWORD = os.getenv("SIEM_SENDER_PASSWORD", "")
RECEIVER_EMAIL = os.getenv("SIEM_RECEIVER_EMAIL", "")

EMAIL_ENABLED = os.getenv("SIEM_EMAIL_ENABLED", "1") == "1"
EMAIL_ALERT_LEVELS = {"MEDIUM", "HIGH", "CRITICAL"}

AGENT_ENABLED = os.getenv("SIEM_AGENT_ENABLED", "1") == "1"
AGENT_API_KEY = os.getenv("SIEM_AGENT_API_KEY", "siem-agent-key")
AGENT_DEFAULT_INTERVAL = int(os.getenv("SIEM_AGENT_DEFAULT_INTERVAL", "30"))
AGENT_HEARTBEAT_INTERVAL = int(os.getenv("SIEM_AGENT_HEARTBEAT_INTERVAL", "30"))
AGENT_ENABLED_SOURCES = tuple(
    item.strip()
    for item in os.getenv(
        "SIEM_AGENT_ENABLED_SOURCES",
        "Security,System,Application,Sysmon,Process,Registry,USB,FileIntegrity,Performance",
    ).split(",")
    if item.strip()
)
AGENT_SERVER_ADDRESS = os.getenv("SIEM_AGENT_SERVER_ADDRESS", "http://127.0.0.1:5000")

# Bind to all local interfaces by default so LAN agents can reach the SIEM.
SIEM_HOST = os.getenv("SIEM_HOST", "0.0.0.0")
SIEM_PORT = int(os.getenv("SIEM_PORT", "5000"))

SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}
