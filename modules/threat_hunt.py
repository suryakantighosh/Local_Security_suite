"""
threat_hunt.py — Local Security Suite
---------------------------------------
Hunts for suspicious patterns in running processes, system logs, scheduled tasks,
and network listeners. Detects known offensive tools, brute-force attempts,
SSH abuse, unusual listening ports, and suspicious cron/scheduled task payloads.

Flag   : --threat-hunt
Entry  : run(config: dict) -> dict
"""

import os
import platform
import re
import subprocess
import sys
from datetime import datetime
from typing import Any

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore

from colorama import Fore, Style
from tabulate import tabulate


# ─────────────────────────────────────────────────────────────────────────────
#  PLATFORM HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _is_linux() -> bool:
    return platform.system() == "Linux"


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _is_darwin() -> bool:
    return platform.system() == "Darwin"


# ─────────────────────────────────────────────────────────────────────────────
#  SEVERITY CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

SEV_CRITICAL = "Critical"
SEV_HIGH     = "High"
SEV_MEDIUM   = "Medium"
SEV_LOW      = "Low"

_SEV_COLOUR = {
    SEV_CRITICAL: Fore.RED + Style.BRIGHT,
    SEV_HIGH:     Fore.RED,
    SEV_MEDIUM:   Fore.YELLOW,
    SEV_LOW:      Fore.CYAN,
}

# Known malicious / offensive process names (exact and partial matches)
_MALICIOUS_PROC_NAMES: list[tuple[str, str, str]] = [
    # (fragment_to_match, severity, description)
    ("mimikatz",       SEV_CRITICAL, "Credential dumper — active credential theft in progress"),
    ("meterpreter",    SEV_CRITICAL, "Metasploit meterpreter session — active compromise"),
    ("cobaltstrike",   SEV_CRITICAL, "CobaltStrike C2 beacon — advanced persistent threat"),
    ("beacon.x64",     SEV_CRITICAL, "CobaltStrike beacon binary detected"),
    ("beacon.x86",     SEV_CRITICAL, "CobaltStrike beacon binary detected"),
    ("empire",         SEV_CRITICAL, "PowerShell Empire post-exploitation framework"),
    ("msfconsole",     SEV_HIGH,     "Metasploit console — exploitation framework running"),
    ("msfvenom",       SEV_HIGH,     "Metasploit payload generator"),
    ("nc",             SEV_HIGH,     "Netcat — potential backdoor or reverse shell"),
    ("ncat",           SEV_HIGH,     "Ncat — potential reverse shell tool"),
    ("netcat",         SEV_HIGH,     "Netcat — potential backdoor or reverse shell"),
    ("socat",          SEV_HIGH,     "Socat relay — can be used as a persistent backdoor"),
    ("ngrok",          SEV_HIGH,     "Ngrok tunnel — internal services exposed to internet"),
    ("frpc",           SEV_HIGH,     "FRP reverse tunnel client — C2 pivoting tool"),
    ("chisel",         SEV_HIGH,     "Chisel TCP tunnel — post-exploitation pivoting"),
    ("ligolo",         SEV_HIGH,     "Ligolo tunneling — offensive pivoting tool"),
    ("pwncat",         SEV_HIGH,     "Pwncat — advanced reverse shell handler"),
    ("revshell",       SEV_HIGH,     "Reverse shell binary detected"),
    ("nmap",           SEV_MEDIUM,   "Nmap port scanner — active reconnaissance"),
    ("masscan",        SEV_HIGH,     "Masscan — high-speed port scanner, offensive recon"),
    ("hydra",          SEV_HIGH,     "Hydra brute-force tool running"),
    ("medusa",         SEV_HIGH,     "Medusa brute-force tool running"),
    ("aircrack",       SEV_HIGH,     "Aircrack-ng — Wi-Fi cracking active"),
    ("hashcat",        SEV_MEDIUM,   "Hashcat password cracker running"),
    ("john",           SEV_MEDIUM,   "John the Ripper password cracker running"),
    ("sqlmap",         SEV_HIGH,     "SQLMap — active SQL injection exploitation"),
    ("wfuzz",          SEV_MEDIUM,   "WFuzz web fuzzer running"),
    ("gobuster",       SEV_MEDIUM,   "Gobuster directory brute-forcer running"),
    ("ffuf",           SEV_MEDIUM,   "FFUF web fuzzer running"),
    ("dirbuster",      SEV_MEDIUM,   "DirBuster web directory brute-forcer"),
    ("nikto",          SEV_MEDIUM,   "Nikto web vulnerability scanner running"),
    ("linpeas",        SEV_HIGH,     "LinPEAS privilege escalation script running"),
    ("winpeas",        SEV_HIGH,     "WinPEAS privilege escalation script running"),
    ("pspy",           SEV_MEDIUM,   "Pspy process snooper — privilege escalation recon"),
    ("tcpdump",        SEV_LOW,      "Packet capture active — possible traffic interception"),
    ("wireshark",      SEV_LOW,      "Wireshark packet capture — traffic interception risk"),
    ("tshark",         SEV_LOW,      "TShark packet capture — traffic interception risk"),
]

# Suspicious command-line patterns (regex → severity, description)
_SUSPICIOUS_CMDLINE_PATTERNS: list[tuple[str, str, str]] = [
    (r"base64\s+-d",           SEV_HIGH,   "Base64 decode piped — common payload obfuscation"),
    (r"bash\s+-i",             SEV_HIGH,   "Interactive bash flag — reverse shell pattern"),
    (r"sh\s+-i",               SEV_HIGH,   "Interactive sh flag — reverse shell pattern"),
    (r"/dev/tcp/",             SEV_HIGH,   "TCP redirect via /dev/tcp — bash reverse shell"),
    (r"/dev/udp/",             SEV_HIGH,   "UDP redirect — reverse shell pattern"),
    (r"python.*-c.*socket",    SEV_HIGH,   "Python one-liner socket — reverse shell"),
    (r"perl.*-e.*socket",      SEV_HIGH,   "Perl one-liner socket — reverse shell"),
    (r"ruby.*-e.*socket",      SEV_HIGH,   "Ruby one-liner socket — reverse shell"),
    (r"exec.*\d+<>/dev/tcp",   SEV_HIGH,   "exec redirect via /dev/tcp — reverse shell"),
    (r"curl.*\|\s*(ba)?sh",    SEV_HIGH,   "Piping curl to shell — remote code execution"),
    (r"wget.*\|\s*(ba)?sh",    SEV_HIGH,   "Piping wget to shell — remote code execution"),
    (r"curl.*-o.*&&.*chmod",   SEV_HIGH,   "Download-and-execute pattern"),
    (r"chmod\s+\+x.*&&\s*\./", SEV_MEDIUM, "Chmod then execute — potential dropper"),
    (r"nohup.*&$",             SEV_LOW,    "Daemonised background process — persistence indicator"),
    (r"crontab\s+-[el]",       SEV_MEDIUM, "Crontab modification in progress"),
    (r"at\s+now",              SEV_MEDIUM, "Immediate scheduled task — persistence mechanism"),
    (r"schtasks.*\/create",    SEV_MEDIUM, "Windows scheduled task creation"),
    (r"reg\s+add.*run",        SEV_HIGH,   "Registry run key modification — Windows persistence"),
    (r"powershell.*-enc",      SEV_HIGH,   "Encoded PowerShell command — obfuscated execution"),
    (r"powershell.*bypass",    SEV_HIGH,   "PowerShell execution policy bypass"),
    (r"powershell.*hidden",    SEV_HIGH,   "Hidden PowerShell window — evasion tactic"),
    (r"invoke-expression",     SEV_HIGH,   "PowerShell IEX — remote script execution"),
    (r"invoke-webrequest",     SEV_MEDIUM, "PowerShell web download"),
    (r"downloadstring",        SEV_HIGH,   "PowerShell DownloadString — fileless execution"),
    (r"wmic.*process.*call.*create", SEV_HIGH, "WMIC process creation — lateral movement"),
    (r"certutil.*-decode",     SEV_HIGH,   "Certutil decode — LOLBin payload extraction"),
    (r"certutil.*-urlcache",   SEV_HIGH,   "Certutil download — LOLBin file download"),
    (r"bitsadmin.*transfer",   SEV_HIGH,   "BITSAdmin transfer — LOLBin download"),
    (r"mshta\s+http",          SEV_HIGH,   "MSHTA remote URL — LOLBin execution"),
    (r"regsvr32.*scrobj",      SEV_HIGH,   "COM scriptlet execution — LOLBin bypass"),
]

# Suspicious cron / scheduled-task payload patterns
_SUSPICIOUS_TASK_PATTERNS: list[tuple[str, str]] = [
    (r"curl\s+",     "Download via curl in scheduled task"),
    (r"wget\s+",     "Download via wget in scheduled task"),
    (r"bash\s+-i",   "Reverse shell in scheduled task"),
    (r"nc\s+-",      "Netcat in scheduled task"),
    (r"python.*-c",  "Python one-liner in scheduled task"),
    (r"base64",      "Base64-encoded payload in scheduled task"),
    (r"/tmp/\S+\.sh", "Shell script from /tmp in scheduled task"),
    (r"\.\.\/\.\.",  "Path traversal in scheduled task"),
    (r"chmod\s+\+x", "Chmod +x in scheduled task — dropper pattern"),
    (r"powershell.*-enc", "Encoded PowerShell in scheduled task"),
]

# Log files to parse (Linux)
_LINUX_LOG_FILES: list[str] = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog",
    "/var/log/messages",
]

# Ports above this threshold are suspicious unless in a known range
_HIGH_PORT_THRESHOLD = 49000


# ─────────────────────────────────────────────────────────────────────────────
#  EVENT FACTORY
# ─────────────────────────────────────────────────────────────────────────────

def _make_event(source: str, severity: str, description: str,
                detail: str = "", timestamp: str = "") -> dict:
    """Return a normalised threat event dict."""
    return {
        "source":      source,
        "severity":    severity,
        "description": description,
        "detail":      detail[:300],
        "timestamp":   timestamp or datetime.now().isoformat(timespec="seconds"),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  HUNT 1 — MALICIOUS PROCESS NAMES
# ─────────────────────────────────────────────────────────────────────────────

def _hunt_processes() -> list[dict]:
    """Flag running processes matching known offensive/malicious tool names."""
    events: list[dict] = []

    if not psutil:
        events.append(_make_event(
            source="Process Hunt",
            severity=SEV_LOW,
            description="psutil not available — process hunt skipped",
        ))
        return events

    try:
        procs = list(psutil.process_iter(["pid", "name", "cmdline", "username"]))
    except (psutil.AccessDenied, Exception) as exc:
        events.append(_make_event(
            source="Process Hunt",
            severity=SEV_LOW,
            description=f"Process enumeration partially failed: {exc}",
        ))
        procs = []

    matched_names: set[str] = set()

    for proc in procs:
        try:
            pname = (proc.info.get("name") or "").lower()
            cmdline_parts = proc.info.get("cmdline") or []
            cmdline = " ".join(cmdline_parts).lower()
            pid = proc.info.get("pid", "?")
            user = proc.info.get("username") or "unknown"

            # Check name fragments
            for fragment, sev, desc in _MALICIOUS_PROC_NAMES:
                if fragment in pname and fragment not in matched_names:
                    matched_names.add(fragment)
                    events.append(_make_event(
                        source="Process Hunt",
                        severity=sev,
                        description=desc,
                        detail=f"PID: {pid}  Name: {pname}  User: {user}",
                    ))

            # Check suspicious cmdline patterns
            if cmdline:
                for pattern, sev, desc in _SUSPICIOUS_CMDLINE_PATTERNS:
                    try:
                        if re.search(pattern, cmdline, re.IGNORECASE):
                            events.append(_make_event(
                                source="Process Cmdline",
                                severity=sev,
                                description=desc,
                                detail=f"PID: {pid}  CMD: {cmdline[:150]}",
                            ))
                            break  # One match per process is enough
                    except re.error:
                        continue

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue

    return events


# ─────────────────────────────────────────────────────────────────────────────
#  HUNT 2 — LINUX LOG PARSING
# ─────────────────────────────────────────────────────────────────────────────

# Compiled patterns for log parsing
_FAILED_LOGIN_RE    = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)", re.I)
_INVALID_USER_RE    = re.compile(r"Invalid user (\S+) from ([\d.]+)", re.I)
_SUDO_ABUSE_RE      = re.compile(r"sudo.*COMMAND.*=.*", re.I)
_ROOT_LOGIN_RE      = re.compile(r"Accepted.*for root from ([\d.a-fA-F:]+)", re.I)
_BRUTE_THRESHOLD    = 5   # failed logins from same IP to flag as brute force


def _hunt_linux_logs() -> list[dict]:
    """Parse Linux auth/syslog for suspicious patterns."""
    events: list[dict] = []
    if not _is_linux():
        return events

    # Find which log file is available
    log_path: str = ""
    for candidate in _LINUX_LOG_FILES:
        if os.path.isfile(candidate):
            log_path = candidate
            break

    if not log_path:
        events.append(_make_event(
            source="Linux Logs",
            severity=SEV_LOW,
            description="No auth log found — try running as root for full access",
        ))
        return events

    try:
        # Read last 5000 lines to avoid memory issues on large logs
        result = subprocess.run(
            ["tail", "-n", "5000", log_path],
            capture_output=True, text=True, timeout=15
        )
        lines = result.stdout.splitlines()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()[-5000:]
        except OSError as exc:
            events.append(_make_event(
                source="Linux Logs",
                severity=SEV_LOW,
                description=f"Cannot read {log_path}: {exc}",
            ))
            return events

    # Count failed logins per IP
    failed_by_ip: dict[str, int] = {}
    failed_by_user: dict[str, int] = {}

    for line in lines:
        # Failed password / invalid user
        m = _FAILED_LOGIN_RE.search(line) or _INVALID_USER_RE.search(line)
        if m:
            user_field = m.group(1)
            ip_field   = m.group(2)
            failed_by_ip[ip_field]     = failed_by_ip.get(ip_field, 0) + 1
            failed_by_user[user_field] = failed_by_user.get(user_field, 0) + 1
            continue

        # Successful root login
        m = _ROOT_LOGIN_RE.search(line)
        if m:
            events.append(_make_event(
                source="Linux Logs",
                severity=SEV_HIGH,
                description="Successful root SSH login detected",
                detail=f"Source IP: {m.group(1)}  Log: {line.strip()[:120]}",
            ))
            continue

        # Sudo abuse (sudo to root / suspicious commands)
        if _SUDO_ABUSE_RE.search(line):
            if any(x in line.lower() for x in
                   ["/bin/bash", "/bin/sh", "chmod 777", "nc ", "/tmp/", "wget ", "curl "]):
                events.append(_make_event(
                    source="Linux Logs",
                    severity=SEV_HIGH,
                    description="Suspicious sudo command detected",
                    detail=line.strip()[:180],
                ))

    # Report brute-force IPs
    for ip, count in sorted(failed_by_ip.items(), key=lambda x: -x[1]):
        if count >= _BRUTE_THRESHOLD:
            events.append(_make_event(
                source="Linux Logs",
                severity=SEV_HIGH if count >= 20 else SEV_MEDIUM,
                description=f"SSH brute-force attempt from {ip} ({count} failures)",
                detail=f"IP: {ip}  Failed attempts: {count}  Log: {log_path}",
            ))

    # Report targeted usernames
    for user, count in sorted(failed_by_user.items(), key=lambda x: -x[1]):
        if count >= _BRUTE_THRESHOLD and user in ("root", "admin", "administrator", "ubuntu", "ec2-user"):
            events.append(_make_event(
                source="Linux Logs",
                severity=SEV_MEDIUM,
                description=f"High-value username targeted in login attempts: '{user}' ({count}×)",
                detail=f"User: {user}  Failed attempts: {count}",
            ))

    if not events:
        events.append(_make_event(
            source="Linux Logs",
            severity=SEV_LOW,
            description=f"No suspicious patterns found in {log_path} (last 5000 lines)",
        ))

    return events


# ─────────────────────────────────────────────────────────────────────────────
#  HUNT 3 — WINDOWS EVENT LOG (Event ID 4625)
# ─────────────────────────────────────────────────────────────────────────────

def _hunt_windows_eventlog() -> list[dict]:
    """Parse Windows Security event log for failed login events (4625)."""
    events: list[dict] = []
    if not _is_windows():
        return events

    script = (
        "try { "
        "$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} "
        "-MaxEvents 200 -ErrorAction Stop | "
        "Select-Object TimeCreated, "
        "@{N='User';E={$_.Properties[5].Value}}, "
        "@{N='Domain';E={$_.Properties[6].Value}}, "
        "@{N='IP';E={$_.Properties[19].Value}} | "
        "ConvertTo-Json -Compress; "
        "Write-Output $events "
        "} catch { Write-Output '[]' }"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=30
        )
        out = result.stdout.strip()
        if not out or out == "[]":
            return events

        import json as _json
        try:
            raw = _json.loads(out)
            if isinstance(raw, dict):
                raw = [raw]

            ip_counts: dict[str, int] = {}
            user_counts: dict[str, int] = {}
            for entry in raw:
                ip   = str(entry.get("IP", "-")).strip()
                user = str(entry.get("User", "-")).strip()
                if ip and ip not in ("-", "::1", "127.0.0.1"):
                    ip_counts[ip]     = ip_counts.get(ip, 0) + 1
                if user:
                    user_counts[user] = user_counts.get(user, 0) + 1

            for ip, count in sorted(ip_counts.items(), key=lambda x: -x[1]):
                if count >= _BRUTE_THRESHOLD:
                    events.append(_make_event(
                        source="Windows Event Log",
                        severity=SEV_HIGH if count >= 20 else SEV_MEDIUM,
                        description=f"Possible brute-force from {ip} ({count} failed logins, Event 4625)",
                        detail=f"IP: {ip}  Failure count: {count}",
                    ))

            for user, count in sorted(user_counts.items(), key=lambda x: -x[1]):
                if count >= _BRUTE_THRESHOLD and user.lower() in (
                        "administrator", "admin", "guest", "user"):
                    events.append(_make_event(
                        source="Windows Event Log",
                        severity=SEV_MEDIUM,
                        description=f"High-value Windows account targeted: '{user}' ({count}× failures)",
                        detail=f"Account: {user}  Count: {count}",
                    ))

        except (_json.JSONDecodeError, Exception):
            pass

    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return events


# ─────────────────────────────────────────────────────────────────────────────
#  HUNT 4 — SUSPICIOUS CRON JOBS (Linux)
# ─────────────────────────────────────────────────────────────────────────────

def _hunt_cron_jobs() -> list[dict]:
    """Scan cron files for suspicious payload patterns."""
    events: list[dict] = []
    if not (_is_linux() or _is_darwin()):
        return events

    cron_locations: list[str] = [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron",
    ]

    cron_files: list[str] = []
    for loc in cron_locations:
        if os.path.isfile(loc):
            cron_files.append(loc)
        elif os.path.isdir(loc):
            try:
                for entry in os.scandir(loc):
                    if entry.is_file():
                        cron_files.append(entry.path)
            except (PermissionError, OSError):
                pass

    if not cron_files:
        return events

    for cf in cron_files:
        try:
            with open(cf, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                for pattern, desc in _SUSPICIOUS_TASK_PATTERNS:
                    try:
                        if re.search(pattern, stripped, re.IGNORECASE):
                            events.append(_make_event(
                                source="Cron Jobs",
                                severity=SEV_HIGH,
                                description=desc,
                                detail=f"File: {cf}  Entry: {stripped[:160]}",
                            ))
                            break
                    except re.error:
                        continue
        except (PermissionError, OSError):
            continue

    return events


# ─────────────────────────────────────────────────────────────────────────────
#  HUNT 5 — SUSPICIOUS SCHEDULED TASKS (Windows)
# ─────────────────────────────────────────────────────────────────────────────

def _hunt_scheduled_tasks() -> list[dict]:
    """Scan Windows scheduled tasks for suspicious payloads."""
    events: list[dict] = []
    if not _is_windows():
        return events

    script = (
        "Get-ScheduledTask | "
        "ForEach-Object { "
        "  $task = $_; "
        "  $actions = $task.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }; "
        "  [PSCustomObject]@{ "
        "    Name=$task.TaskName; "
        "    Path=$task.TaskPath; "
        "    Actions=($actions -join '|') "
        "  } "
        "} | ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=30
        )
        out = result.stdout.strip()
        if not out or out in ("null", "[]"):
            return events

        import json as _json
        try:
            tasks = _json.loads(out)
            if isinstance(tasks, dict):
                tasks = [tasks]
            for task in tasks:
                actions_str = (task.get("Actions") or "").lower()
                if not actions_str:
                    continue
                for pattern, desc in _SUSPICIOUS_TASK_PATTERNS:
                    try:
                        if re.search(pattern, actions_str, re.IGNORECASE):
                            events.append(_make_event(
                                source="Scheduled Tasks",
                                severity=SEV_HIGH,
                                description=desc,
                                detail=(
                                    f"Task: {task.get('Name','?')}  "
                                    f"Path: {task.get('Path','?')}  "
                                    f"Action: {actions_str[:130]}"
                                ),
                            ))
                            break
                    except re.error:
                        continue
        except (_json.JSONDecodeError, Exception):
            pass

    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return events


# ─────────────────────────────────────────────────────────────────────────────
#  HUNT 6 — UNUSUAL LISTENING PORTS
# ─────────────────────────────────────────────────────────────────────────────

def _hunt_unusual_ports() -> list[dict]:
    """Flag any ports listening above the high-port threshold."""
    events: list[dict] = []

    if not psutil:
        return events

    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status not in ("LISTEN",) and conn.status != getattr(psutil, "CONN_LISTEN", "LISTEN"):
                continue
            if not conn.laddr:
                continue
            port = conn.laddr.port
            if port > _HIGH_PORT_THRESHOLD:
                proc_name = "unknown"
                try:
                    if conn.pid:
                        proc_name = psutil.Process(conn.pid).name()
                except Exception:
                    pass
                events.append(_make_event(
                    source="Unusual Ports",
                    severity=SEV_MEDIUM,
                    description=f"Unusual high port listening: {port} (process: {proc_name})",
                    detail=f"Port: {port}  PID: {conn.pid}  Process: {proc_name}  Addr: {conn.laddr.ip}:{port}",
                ))
    except (psutil.AccessDenied, PermissionError):
        events.append(_make_event(
            source="Unusual Ports",
            severity=SEV_LOW,
            description="Insufficient privileges to enumerate all listening ports",
        ))
    except Exception:
        pass

    return events


# ─────────────────────────────────────────────────────────────────────────────
#  HUNT 7 — RECENTLY MODIFIED SYSTEM BINARIES (Linux)
# ─────────────────────────────────────────────────────────────────────────────

def _hunt_recently_modified_bins() -> list[dict]:
    """Check for system binaries modified in the last 24 hours."""
    events: list[dict] = []
    if not _is_linux():
        return events

    try:
        result = subprocess.run(
            ["find", "/bin", "/sbin", "/usr/bin", "/usr/sbin",
             "-newer", "/proc/1", "-type", "f"],
            capture_output=True, text=True, timeout=20
        )
        modified = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        if modified:
            events.append(_make_event(
                source="File System",
                severity=SEV_HIGH,
                description=f"{len(modified)} system binary/binaries modified recently — possible rootkit",
                detail="\n".join(modified[:15]),
            ))
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return events


# ─────────────────────────────────────────────────────────────────────────────
#  COLLECT ALL EVENTS
# ─────────────────────────────────────────────────────────────────────────────

def _collect_events() -> list[dict]:
    """Run all threat-hunting checks and return combined events list."""
    events: list[dict] = []

    hunts = [
        _hunt_processes,
        _hunt_linux_logs,
        _hunt_windows_eventlog,
        _hunt_cron_jobs,
        _hunt_scheduled_tasks,
        _hunt_unusual_ports,
        _hunt_recently_modified_bins,
    ]

    for hunt_fn in hunts:
        try:
            results = hunt_fn()
            events.extend(results)
        except Exception:
            pass

    return events


# ─────────────────────────────────────────────────────────────────────────────
#  OUTPUT / PRINT
# ─────────────────────────────────────────────────────────────────────────────

def _colour_sev(sev: str) -> str:
    colour = _SEV_COLOUR.get(sev, "")
    return f"{colour}{sev}{Style.RESET_ALL}"


def _print_results(events: list[dict], config: dict) -> None:
    """Print formatted threat-hunting report to stdout."""
    verbose = config.get("verbose", False)

    counts = {SEV_CRITICAL: 0, SEV_HIGH: 0, SEV_MEDIUM: 0, SEV_LOW: 0}
    for e in events:
        sev = e.get("severity", SEV_LOW)
        counts[sev] = counts.get(sev, 0) + 1

    print()
    print(f"{Fore.CYAN}{'═' * 72}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  LOCAL SECURITY SUITE — Threat Hunt{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  "
          f"Platform: {platform.system()} {platform.release()}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═' * 72}{Style.RESET_ALL}")
    print()

    # Only keep actionable findings for display (filter out info-level clean messages
    # if there are real findings too)
    real_events = [e for e in events if e["severity"] != SEV_LOW]
    display_events = real_events if real_events else events

    if not display_events:
        print(f"{Fore.GREEN}  ✔  No threats detected.{Style.RESET_ALL}")
        print()
        return

    sev_order = {SEV_CRITICAL: 0, SEV_HIGH: 1, SEV_MEDIUM: 2, SEV_LOW: 3}
    sorted_events = sorted(display_events, key=lambda x: sev_order.get(x["severity"], 9))

    # Group by source
    sources: dict[str, list[dict]] = {}
    for e in sorted_events:
        src = e.get("source", "General")
        sources.setdefault(src, []).append(e)

    for src, src_events in sources.items():
        print(f"{Fore.WHITE}{Style.BRIGHT}  ▶ {src}{Style.RESET_ALL}")
        rows = []
        for e in src_events:
            rows.append([
                _colour_sev(e["severity"]),
                e["description"][:70] + ("…" if len(e["description"]) > 70 else ""),
            ])
        print(tabulate(rows, headers=["Severity", "Event"], tablefmt="simple",
                       colalign=("left", "left")))
        if verbose:
            for e in src_events:
                if e.get("detail"):
                    print(f"    {Fore.WHITE}Detail:{Style.RESET_ALL} {e['detail'][:200]}")
        print()

    # Summary
    print(f"{Fore.CYAN}{'─' * 72}{Style.RESET_ALL}")
    c  = counts[SEV_CRITICAL]
    h  = counts[SEV_HIGH]
    m  = counts[SEV_MEDIUM]
    lo = counts[SEV_LOW]
    print(
        f"  Total events: {len(events)}  |  "
        f"{Fore.RED + Style.BRIGHT}{c} Critical{Style.RESET_ALL}  "
        f"{Fore.RED}{h} High{Style.RESET_ALL}  "
        f"{Fore.YELLOW}{m} Medium{Style.RESET_ALL}  "
        f"{Fore.CYAN}{lo} Low{Style.RESET_ALL}"
    )
    print(f"{Fore.CYAN}{'═' * 72}{Style.RESET_ALL}")
    print()


def _save_output(result: dict, config: dict) -> None:
    """Write module result to disk when --output was provided."""
    import json as _json

    output_path: str = config.get("output_path", "")
    output_format: str = config.get("output_format", "text")
    if not output_path:
        return

    try:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        if output_format == "json":
            with open(output_path, "w", encoding="utf-8") as fh:
                _json.dump(result, fh, indent=2, default=str)
        else:
            lines: list[str] = [
                "Local Security Suite — Threat Hunt Report",
                f"Generated : {datetime.now().isoformat(timespec='seconds')}",
                f"Platform  : {platform.system()} {platform.release()}",
                "=" * 72,
                "",
            ]
            sev_order = {SEV_CRITICAL: 0, SEV_HIGH: 1, SEV_MEDIUM: 2, SEV_LOW: 3}
            for e in sorted(result.get("findings", []),
                            key=lambda x: sev_order.get(x["severity"], 9)):
                lines.append(f"[{e['severity']:8}] [{e['source']}] {e['description']}")
                if e.get("detail"):
                    lines.append(f"             Detail: {e['detail']}")
                lines.append("")
            lines.append(f"Summary: {result.get('summary', '')}")
            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines))
        print(f"{Fore.GREEN}  ✔  Output saved → {output_path}{Style.RESET_ALL}")
    except OSError as exc:
        print(f"{Fore.RED}  ✖  Could not save output: {exc}{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def run(config: dict) -> dict:
    """
    Threat Hunting entry point.

    Args:
        config: dict with keys output_format, output_path, verbose, target

    Returns:
        {"status": "ok"|"error", "findings": [...], "summary": "..."}
    """
    events = _collect_events()
    _print_results(events, config)

    counts = {SEV_CRITICAL: 0, SEV_HIGH: 0, SEV_MEDIUM: 0, SEV_LOW: 0}
    for e in events:
        sev = e.get("severity", SEV_LOW)
        counts[sev] = counts.get(sev, 0) + 1

    summary = (
        f"{len(events)} threat events — "
        f"{counts[SEV_CRITICAL]} Critical, "
        f"{counts[SEV_HIGH]} High, "
        f"{counts[SEV_MEDIUM]} Medium, "
        f"{counts[SEV_LOW]} Low"
    )

    result: dict[str, Any] = {
        "status":    "ok",
        "module":    "threat_hunt",
        "platform":  platform.system(),
        "findings":  events,
        "summary":   summary,
        "counts":    counts,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }

    _save_output(result, config)
    return result
