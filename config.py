"""
NDACS - Network Defense Automated Cyber Synthesizer
Central configuration. Every value can be overridden with an environment
variable of the same name prefixed with NDACS_ (e.g. NDACS_DB_URL).
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Load settings from .env (works under sudo, which drops your shell's exported variables)
_envfile = BASE_DIR / ".env"
if _envfile.exists():
    for _line in _envfile.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))


def _env(name, default, cast=str):
    val = os.environ.get("NDACS_" + name)
    if val is None:
        return default
    if cast is bool:
        return val.strip().lower() in ("1", "true", "yes", "on")
    return cast(val)


# ---------------------------------------------------------------- paths
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"                 # put CICIDS2017 CSVs here
PROCESSED_DIR = DATA_DIR / "processed"     # output of prepare_dataset.py
MODEL_DIR = BASE_DIR / "models"            # trained model + scaler + meta
REPORT_DIR = BASE_DIR / "reports"          # charts / metrics for the presentation
LOG_DIR = BASE_DIR / "logs"
THREAT_INTEL_CSV = DATA_DIR / "threat_intel.csv"   # flows captured from attackers (for retraining)

# ---------------------------------------------------------------- database
# MySQL example: mysql+pymysql://ndacs:ndacs123@localhost/ndacs
# Falls back to SQLite automatically if MySQL is unreachable.
DB_URL = _env("DB_URL", f"sqlite:///{BASE_DIR / 'ndacs.db'}")

# ---------------------------------------------------------------- dashboard
DASHBOARD_HOST = _env("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT = _env("DASHBOARD_PORT", 5000, int)
DASHBOARD_USER = _env("DASHBOARD_USER", "admin")
DASHBOARD_PASSWORD = _env("DASHBOARD_PASSWORD", "ndacs@123")   # change before demo!
SECRET_KEY = _env("SECRET_KEY", "change-this-secret-key-for-production")

# ---------------------------------------------------------------- capture
INTERFACE = _env("INTERFACE", None)        # None = scapy default interface
FLOW_IDLE_TIMEOUT = _env("FLOW_IDLE_TIMEOUT", 5.0, float)      # seconds without packets -> flow ends
FLOW_ACTIVE_TIMEOUT = _env("FLOW_ACTIVE_TIMEOUT", 30.0, float) # long flows are cut & analysed every N s
MAX_ACTIVE_FLOWS = _env("MAX_ACTIVE_FLOWS", 100000, int)

# ---------------------------------------------------------------- detection
ALERT_THRESHOLD = _env("ALERT_THRESHOLD", 0.70, float)   # min model confidence to raise an alert
BLOCK_THRESHOLD = _env("BLOCK_THRESHOLD", 0.90, float)   # min confidence to take automatic action
ALERT_DEDUP_SECONDS = _env("ALERT_DEDUP_SECONDS", 30, int)
EXPLAIN_ALERTS = _env("EXPLAIN_ALERTS", True, bool)
EXPLAINER = _env("EXPLAINER", "shap")      # shap | lime | occlusion

# Behaviour / signature rules (work even without the ML model)
PORTSCAN_PORTS = _env("PORTSCAN_PORTS", 25, int)          # distinct dst ports ...
PORTSCAN_WINDOW = _env("PORTSCAN_WINDOW", 10, int)        # ... within N seconds
SYNFLOOD_SYNS = _env("SYNFLOOD_SYNS", 300, int)
SYNFLOOD_WINDOW = _env("SYNFLOOD_WINDOW", 5, int)
BRUTEFORCE_CONNS = _env("BRUTEFORCE_CONNS", 15, int)
BRUTEFORCE_WINDOW = _env("BRUTEFORCE_WINDOW", 30, int)
AUTH_PORTS = {21, 22, 23, 3389, 2121, 2222, 2323}

# ---------------------------------------------------------------- response
# dry-run : log the action only (safe default)
# block   : iptables DROP for the attacker IP
# redirect: send scanners / brute-forcers to the honeypot, block everything else
RESPONSE_MODE = _env("RESPONSE_MODE", "dry-run")
BLOCK_DURATION_MIN = _env("BLOCK_DURATION_MIN", 30, int)
WHITELIST = set(filter(None, _env("WHITELIST", "127.0.0.1,10.0.2.2,10.0.2.3").split(",")))

# ---------------------------------------------------------------- honeypot
HONEYPOT_ENABLED = _env("HONEYPOT_ENABLED", True, bool)
HONEYPOT_BIND = _env("HONEYPOT_BIND", "0.0.0.0")
HONEYPOT_PORTS = {             # service -> port the fake service listens on
    "ssh": _env("HP_SSH_PORT", 2222, int),
    "ftp": _env("HP_FTP_PORT", 2121, int),
    "telnet": _env("HP_TELNET_PORT", 2323, int),
    "http": _env("HP_HTTP_PORT", 8081, int),
}
# real service port -> honeypot port (used by 'redirect' mode)
REDIRECT_MAP = {22: HONEYPOT_PORTS["ssh"], 21: HONEYPOT_PORTS["ftp"],
                23: HONEYPOT_PORTS["telnet"], 80: HONEYPOT_PORTS["http"]}
COWRIE_JSON_LOG = _env("COWRIE_JSON_LOG", "")   # e.g. /opt/cowrie/var/log/cowrie/cowrie.json

# ---------------------------------------------------------------- severity / policy
SEVERITY = {
    "PortScan": "medium",
    "DoS": "high",
    "DDoS": "high",
    "BruteForce": "high",
    "WebAttack": "high",
    "Bot": "critical",
    "Infiltration": "critical",
    "SYN-Flood": "high",
    "Honeypot-Contact": "medium",
}
# what to do with each attack class when confidence >= BLOCK_THRESHOLD
ACTION_POLICY = {
    "PortScan": "redirect",
    "BruteForce": "redirect",
    "DoS": "block",
    "DDoS": "block",
    "SYN-Flood": "block",
    "WebAttack": "block",
    "Bot": "block",
    "Infiltration": "block",
    "Honeypot-Contact": "monitor",
}

for _d in (DATA_DIR, RAW_DIR, PROCESSED_DIR, MODEL_DIR, REPORT_DIR, LOG_DIR):
    _d.mkdir(parents=True, exist_ok=True)
