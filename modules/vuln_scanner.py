"""
vuln_scanner.py — Local Security Suite
---------------------------------------
Identifies common vulnerabilities on the local host including open risky ports,
outdated software versions, weak file permissions, world-readable sensitive files,
and running processes with known risky names.

Flag   : --vuln-scan
Entry  : run(config: dict) -> dict
"""

import os
import platform
import re
import socket
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

SEV_HIGH   = "High"
SEV_MEDIUM = "Medium"
SEV_LOW    = "Low"
SEV_INFO   = "Info"

_SEV_COLOUR = {
    SEV_HIGH:   Fore.RED,
    SEV_MEDIUM: Fore.YELLOW,
    SEV_LOW:    Fore.CYAN,
    SEV_INFO:   Fore.WHITE,
}

# Risky ports: service name → (port, severity, reason)
_RISKY_PORTS: dict[int, tuple[str, str, str]] = {
    21:    ("FTP",          SEV_HIGH,   "Unencrypted file transfer — credentials sent in plaintext"),
    22:    ("SSH",          SEV_LOW,    "Remote shell access — ensure key-only auth and no root login"),
    23:    ("Telnet",       SEV_HIGH,   "Completely unencrypted — replace with SSH immediately"),
    25:    ("SMTP",         SEV_MEDIUM, "Mail relay port — can be abused for spam if misconfigured"),
    80:    ("HTTP",         SEV_LOW,    "Unencrypted web traffic — consider enforcing HTTPS"),
    443:   ("HTTPS",        SEV_INFO,   "Encrypted web traffic — verify certificate validity"),
    3306:  ("MySQL",        SEV_HIGH,   "Database exposed on network — should be localhost-only"),
    5432:  ("PostgreSQL",   SEV_HIGH,   "Database exposed on network — should be localhost-only"),
    6379:  ("Redis",        SEV_HIGH,   "Redis often has no auth by default — critical if exposed"),
    27017: ("MongoDB",      SEV_HIGH,   "MongoDB exposed — often misconfigured with no authentication"),
    445:   ("SMB",          SEV_HIGH,   "Windows file sharing — frequent ransomware attack vector"),
    139:   ("NetBIOS",      SEV_MEDIUM, "Legacy Windows networking — should be disabled if unused"),
    3389:  ("RDP",          SEV_HIGH,   "Remote Desktop — brute-force and BlueKeep target"),
    5900:  ("VNC",          SEV_HIGH,   "Remote desktop — often poorly secured, no encryption by default"),
    8080:  ("HTTP-Alt",     SEV_LOW,    "Alternative HTTP port — development server may be exposed"),
    8443:  ("HTTPS-Alt",    SEV_LOW,    "Alternative HTTPS port — verify this is intentional"),
    11211: ("Memcached",    SEV_HIGH,   "Memcached exposed — amplification DDoS and data leak risk"),
    2181:  ("Zookeeper",    SEV_MEDIUM, "ZooKeeper exposed — coordinate service should not be public"),
    9200:  ("Elasticsearch",SEV_HIGH,   "Elasticsearch exposed — default has no auth, data leak risk"),
    5984:  ("CouchDB",      SEV_HIGH,   "CouchDB web API exposed — default Futon admin is open"),
}

# Known risky process name fragments
_RISKY_PROCESSES: list[tuple[str, str, str]] = [
    ("nc",           SEV_HIGH,   "Netcat — common backdoor/reverse shell tool"),
    ("ncat",         SEV_HIGH,   "Ncat (nmap suite) — used for reverse shells"),
    ("netcat",       SEV_HIGH,   "Netcat — common backdoor/reverse shell tool"),
    ("nmap",         SEV_MEDIUM, "Port scanner — could indicate reconnaissance activity"),
    ("masscan",      SEV_HIGH,   "High-speed port scanner — offensive recon tool"),
    ("metasploit",   SEV_HIGH,   "Metasploit framework — exploitation platform"),
    ("msfconsole",   SEV_HIGH,   "Metasploit console — exploitation platform"),
    ("msfvenom",     SEV_HIGH,   "Metasploit payload generator"),
    ("mimikatz",     SEV_HIGH,   "Credential dumper — Windows post-exploitation tool"),
    ("cobaltstrike", SEV_HIGH,   "Commercial C2 framework — advanced persistent threat tool"),
    ("beacon",       SEV_HIGH,   "CobaltStrike beacon — C2 implant"),
    ("empire",       SEV_HIGH,   "PowerShell Empire — post-exploitation framework"),
    ("powersploit",  SEV_HIGH,   "PowerSploit — PowerShell offensive framework"),
    ("hydra",        SEV_HIGH,   "Brute-force tool — password cracking"),
    ("john",         SEV_MEDIUM, "John the Ripper — password cracker"),
    ("hashcat",      SEV_MEDIUM, "Hashcat — GPU password cracker"),
    ("sqlmap",       SEV_HIGH,   "SQL injection automation tool"),
    ("nikto",        SEV_MEDIUM, "Web vulnerability scanner"),
    ("wfuzz",        SEV_MEDIUM, "Web fuzzing tool"),
    ("dirbuster",    SEV_MEDIUM, "Web directory brute-forcer"),
    ("gobuster",     SEV_MEDIUM, "Web directory brute-forcer"),
    ("aircrack",     SEV_HIGH,   "Wi-Fi cracking tool"),
    ("wireshark",    SEV_LOW,    "Packet sniffer — legitimate but flag for awareness"),
    ("tcpdump",      SEV_LOW,    "Packet capture — could indicate traffic interception"),
    ("ngrok",        SEV_HIGH,   "Tunnel service — can expose internal services to internet"),
    ("frpc",         SEV_HIGH,   "FRP client — reverse tunnel tool often used in attacks"),
    ("chisel",       SEV_HIGH,   "Fast TCP tunnel — common post-exploitation tunneling tool"),
    ("socat",        SEV_MEDIUM, "Multipurpose relay — can create reverse shells"),
    ("pspy",         SEV_MEDIUM, "Process monitor — used for privilege escalation recon"),
    ("linpeas",      SEV_HIGH,   "Linux privilege escalation script"),
    ("winpeas",      SEV_HIGH,   "Windows privilege escalation script"),
]

# Sensitive files and their expected permissions (Linux)
_SENSITIVE_FILES_LINUX: list[tuple[str, str, str]] = [
    ("/etc/shadow",       "000 or 640", SEV_HIGH),
    ("/etc/passwd",       "644",        SEV_LOW),
    ("/etc/sudoers",      "440",        SEV_HIGH),
    ("/etc/ssh/sshd_config", "600",     SEV_MEDIUM),
    ("/root/.ssh/authorized_keys", "600", SEV_HIGH),
    ("/etc/crontab",      "644",        SEV_LOW),
]


# ─────────────────────────────────────────────────────────────────────────────
#  FINDING FACTORY
# ─────────────────────────────────────────────────────────────────────────────

def _make_finding(name: str, severity: str, description: str,
                  detail: str = "", category: str = "") -> dict:
    """Return a normalised vulnerability finding dict."""
    return {
        "name":        name,
        "severity":    severity,
        "description": description,
        "detail":      detail,
        "category":    category,
        "timestamp":   datetime.now().isoformat(timespec="seconds"),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 1 — OPEN RISKY PORTS
# ─────────────────────────────────────────────────────────────────────────────

def _check_open_ports() -> list[dict]:
    """Probe common risky ports via socket and cross-reference with psutil."""
    findings: list[dict] = []
    open_ports: set[int] = set()

    # Primary: psutil net_connections for accuracy
    if psutil:
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status in ("LISTEN", "ESTABLISHED") or conn.status == psutil.CONN_LISTEN:
                    if conn.laddr:
                        open_ports.add(conn.laddr.port)
        except (psutil.AccessDenied, PermissionError):
            pass  # Fall through to socket probe
        except Exception:
            pass

    # Fallback / supplement: raw socket connect probe
    for port in _RISKY_PORTS:
        if port in open_ports:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    open_ports.add(port)
        except OSError:
            pass

    for port in sorted(open_ports):
        if port in _RISKY_PORTS:
            service, sev, reason = _RISKY_PORTS[port]
            # Try to get owning process name
            proc_name = "unknown"
            if psutil:
                try:
                    for conn in psutil.net_connections(kind="inet"):
                        if conn.laddr and conn.laddr.port == port and conn.pid:
                            proc_name = psutil.Process(conn.pid).name()
                            break
                except Exception:
                    pass
            findings.append(_make_finding(
                name=f"Open risky port {port}/{service}",
                severity=sev,
                description=reason,
                detail=f"Port {port} is open — process: {proc_name}",
                category="Open Ports",
            ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 2 — PYTHON VERSION
# ─────────────────────────────────────────────────────────────────────────────

def _check_python_version() -> list[dict]:
    """Flag if the running Python version is end-of-life."""
    findings: list[dict] = []
    major, minor = sys.version_info[:2]
    version_str = f"{major}.{minor}.{sys.version_info[2]}"

    # EOL versions as of 2025: 3.7 and below
    eol_versions = [(3, 7), (3, 6), (3, 5), (3, 4), (3, 3), (3, 2), (3, 1), (3, 0), (2, 7)]
    is_eol = (major, minor) in eol_versions

    if is_eol:
        findings.append(_make_finding(
            name="End-of-Life Python version",
            severity=SEV_HIGH,
            description=f"Python {version_str} is past end-of-life and receives no security patches",
            detail="Upgrade to Python 3.9+ (3.11+ recommended)",
            category="Outdated Software",
        ))
    elif minor < 9:
        findings.append(_make_finding(
            name="Outdated Python version",
            severity=SEV_MEDIUM,
            description=f"Python {version_str} is not the latest stable branch",
            detail="Consider upgrading to Python 3.11+ for security improvements",
            category="Outdated Software",
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 3 — SSH VERSION (Linux)
# ─────────────────────────────────────────────────────────────────────────────

def _check_ssh_version() -> list[dict]:
    """Check OpenSSH version on Linux for known-old releases."""
    findings: list[dict] = []
    if not (_is_linux() or _is_darwin()):
        return findings

    try:
        result = subprocess.run(
            ["ssh", "-V"],
            capture_output=True, text=True, timeout=5
        )
        output = (result.stderr or result.stdout).strip()
        match = re.search(r"OpenSSH[_\s](\d+\.\d+)", output)
        if match:
            ver = float(match.group(1))
            if ver < 8.0:
                findings.append(_make_finding(
                    name="Outdated OpenSSH version",
                    severity=SEV_HIGH,
                    description=f"OpenSSH {match.group(1)} is outdated and may contain known CVEs",
                    detail="Upgrade to OpenSSH 9.x — multiple critical fixes since 8.0",
                    category="Outdated Software",
                ))
            elif ver < 9.0:
                findings.append(_make_finding(
                    name="Ageing OpenSSH version",
                    severity=SEV_MEDIUM,
                    description=f"OpenSSH {match.group(1)} — consider upgrading to 9.x",
                    detail=output,
                    category="Outdated Software",
                ))
        else:
            findings.append(_make_finding(
                name="SSH version undetectable",
                severity=SEV_LOW,
                description="Could not parse SSH version — manual check recommended",
                detail=output,
                category="Outdated Software",
            ))
    except FileNotFoundError:
        pass  # ssh not installed — not a finding
    except (subprocess.TimeoutExpired, OSError, Exception) as exc:
        findings.append(_make_finding(
            name="SSH version check failed",
            severity=SEV_LOW,
            description=f"Unable to determine SSH version: {exc}",
            category="Outdated Software",
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 4 — WORLD-READABLE /etc/shadow (Linux)
# ─────────────────────────────────────────────────────────────────────────────

def _check_shadow_permissions() -> list[dict]:
    """Check that /etc/shadow is not world-readable."""
    findings: list[dict] = []
    if not _is_linux():
        return findings

    shadow_path = "/etc/shadow"
    try:
        if not os.path.exists(shadow_path):
            return findings
        mode = os.stat(shadow_path).st_mode & 0o777
        mode_str = oct(mode)
        # World-readable means others bits (last octal digit) >= 4
        if mode & 0o004:
            findings.append(_make_finding(
                name="/etc/shadow is world-readable",
                severity=SEV_HIGH,
                description="Any local user can read password hashes — immediate privilege escalation risk",
                detail=f"Current permissions: {mode_str}  Expected: 000 or 640",
                category="File Permissions",
            ))
        elif mode & 0o040:
            findings.append(_make_finding(
                name="/etc/shadow group-readable (non-shadow group)",
                severity=SEV_MEDIUM,
                description="/etc/shadow is readable by its group — verify group is 'shadow'",
                detail=f"Current permissions: {mode_str}",
                category="File Permissions",
            ))
    except (PermissionError, OSError):
        pass  # Cannot stat — likely correct (root-only)

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 5 — WEAK PERMISSIONS ON KEY CONFIG FILES (Linux)
# ─────────────────────────────────────────────────────────────────────────────

def _check_config_file_permissions() -> list[dict]:
    """Check permissions on sensitive Linux config files."""
    findings: list[dict] = []
    if not _is_linux():
        return findings

    for filepath, expected, sev in _SENSITIVE_FILES_LINUX:
        try:
            if not os.path.exists(filepath):
                continue
            mode = os.stat(filepath).st_mode & 0o777
            mode_str = oct(mode)
            # Flag if world-writable (others write bit set)
            if mode & 0o002:
                findings.append(_make_finding(
                    name=f"World-writable sensitive file: {filepath}",
                    severity=SEV_HIGH,
                    description=f"{filepath} is world-writable — any user can modify it",
                    detail=f"Current: {mode_str}  Expected: {expected}",
                    category="File Permissions",
                ))
            # Flag if world-readable on highly sensitive files
            elif filepath in ("/etc/shadow", "/etc/sudoers", "/root/.ssh/authorized_keys"):
                if mode & 0o004:
                    findings.append(_make_finding(
                        name=f"World-readable sensitive file: {filepath}",
                        severity=sev,
                        description=f"{filepath} should not be readable by all users",
                        detail=f"Current: {mode_str}  Expected: {expected}",
                        category="File Permissions",
                    ))
        except (PermissionError, OSError):
            continue

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 6 — RISKY RUNNING PROCESSES
# ─────────────────────────────────────────────────────────────────────────────

def _check_risky_processes() -> list[dict]:
    """Scan running processes for known offensive/risky tool names."""
    findings: list[dict] = []
    if not psutil:
        findings.append(_make_finding(
            name="Process scan unavailable",
            severity=SEV_LOW,
            description="psutil not installed — cannot enumerate running processes",
            category="Running Processes",
        ))
        return findings

    try:
        running = {p.pid: p.name().lower() for p in psutil.process_iter(["pid", "name"])}
    except (psutil.AccessDenied, Exception):
        findings.append(_make_finding(
            name="Process enumeration denied",
            severity=SEV_LOW,
            description="Insufficient privileges to enumerate all running processes",
            category="Running Processes",
        ))
        return findings

    matched: set[str] = set()
    for pid, pname in running.items():
        for risky_name, sev, reason in _RISKY_PROCESSES:
            if risky_name in pname and risky_name not in matched:
                matched.add(risky_name)
                findings.append(_make_finding(
                    name=f"Risky process running: {pname}",
                    severity=sev,
                    description=reason,
                    detail=f"PID: {pid}  Process name: {pname}",
                    category="Running Processes",
                ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 7 — WINDOWS DEFENDER / ANTIVIRUS STATUS
# ─────────────────────────────────────────────────────────────────────────────

def _check_windows_defender() -> list[dict]:
    """Check Windows Defender real-time protection status via PowerShell."""
    findings: list[dict] = []
    if not _is_windows():
        return findings

    script = (
        "try { "
        "$status = Get-MpComputerStatus; "
        "Write-Output $status.RealTimeProtectionEnabled "
        "} catch { Write-Output 'ERROR' }"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=15
        )
        out = result.stdout.strip().lower()
        if out == "false":
            findings.append(_make_finding(
                name="Windows Defender real-time protection disabled",
                severity=SEV_HIGH,
                description="Real-time antivirus protection is OFF — system is unprotected against malware",
                detail="Enable via Windows Security → Virus & threat protection",
                category="Antivirus / EDR",
            ))
        elif out == "error" or result.returncode != 0:
            findings.append(_make_finding(
                name="Windows Defender status unknown",
                severity=SEV_LOW,
                description="Could not query Windows Defender status",
                detail=result.stderr.strip()[:200],
                category="Antivirus / EDR",
            ))
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 8 — UNQUOTED SERVICE PATHS (Windows)
# ─────────────────────────────────────────────────────────────────────────────

def _check_unquoted_service_paths() -> list[dict]:
    """Detect Windows services with unquoted paths containing spaces."""
    findings: list[dict] = []
    if not _is_windows():
        return findings

    script = (
        "Get-WmiObject Win32_Service | "
        "Where-Object { $_.PathName -notmatch '\"' -and $_.PathName -match ' ' } | "
        "Select-Object Name, PathName | ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=20
        )
        out = result.stdout.strip()
        if out and out not in ("null", "[]", ""):
            import json as _json
            try:
                services = _json.loads(out)
                if isinstance(services, dict):
                    services = [services]
                for svc in services[:10]:  # cap at 10
                    findings.append(_make_finding(
                        name=f"Unquoted service path: {svc.get('Name','?')}",
                        severity=SEV_HIGH,
                        description="Unquoted service path with spaces allows privilege escalation via path hijacking",
                        detail=f"Path: {svc.get('PathName','?')[:120]}",
                        category="Windows Services",
                    ))
            except Exception:
                pass
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 9 — SUID/SGID BINARIES (Linux)
# ─────────────────────────────────────────────────────────────────────────────

def _check_suid_binaries() -> list[dict]:
    """Find SUID/SGID binaries outside of standard system paths."""
    findings: list[dict] = []
    if not _is_linux():
        return findings

    # Known legitimate SUID binaries — anything outside this list is suspicious
    _EXPECTED_SUID = {
        "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/su",
        "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/chfn",
        "/usr/bin/chsh", "/usr/bin/mount", "/usr/bin/umount",
        "/usr/bin/pkexec", "/usr/lib/openssh/ssh-keysign",
        "/usr/sbin/pppd", "/bin/ping", "/bin/mount", "/bin/su",
        "/bin/umount", "/sbin/unix_chkpwd",
    }

    try:
        result = subprocess.run(
            ["find", "/usr", "/bin", "/sbin", "/tmp", "/home",
             "-perm", "/6000", "-type", "f"],
            capture_output=True, text=True, timeout=20
        )
        found_suspicious: list[str] = []
        for line in result.stdout.splitlines():
            fpath = line.strip()
            if fpath and fpath not in _EXPECTED_SUID:
                found_suspicious.append(fpath)

        if found_suspicious:
            findings.append(_make_finding(
                name=f"Unexpected SUID/SGID binaries found ({len(found_suspicious)})",
                severity=SEV_HIGH,
                description="SUID/SGID binaries outside standard paths can be used for local privilege escalation",
                detail="\n".join(found_suspicious[:15]),
                category="File Permissions",
            ))
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 10 — WRITABLE PATH ENTRIES (Linux)
# ─────────────────────────────────────────────────────────────────────────────

def _check_writable_path_dirs() -> list[dict]:
    """Check if any directory in $PATH is world-writable."""
    findings: list[dict] = []
    if not (_is_linux() or _is_darwin()):
        return findings

    path_env = os.environ.get("PATH", "")
    writable: list[str] = []
    for entry in path_env.split(":"):
        entry = entry.strip()
        if not entry or not os.path.isdir(entry):
            continue
        try:
            mode = os.stat(entry).st_mode & 0o777
            if mode & 0o002:
                writable.append(entry)
        except OSError:
            continue

    if writable:
        findings.append(_make_finding(
            name="World-writable directory in $PATH",
            severity=SEV_HIGH,
            description="World-writable PATH entries allow trojan binary injection",
            detail="Writable entries: " + ", ".join(writable),
            category="File Permissions",
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  COLLECT ALL FINDINGS
# ─────────────────────────────────────────────────────────────────────────────

def _collect_findings() -> list[dict]:
    """Run all vulnerability checks and return combined findings list."""
    findings: list[dict] = []

    checks = [
        _check_open_ports,
        _check_python_version,
        _check_ssh_version,
        _check_shadow_permissions,
        _check_config_file_permissions,
        _check_risky_processes,
        _check_windows_defender,
        _check_unquoted_service_paths,
        _check_suid_binaries,
        _check_writable_path_dirs,
    ]

    for check_fn in checks:
        try:
            results = check_fn()
            findings.extend(results)
        except Exception:
            pass  # Each check is independently guarded

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  OUTPUT / PRINT
# ─────────────────────────────────────────────────────────────────────────────

def _colour_sev(sev: str) -> str:
    colour = _SEV_COLOUR.get(sev, "")
    return f"{colour}{sev}{Style.RESET_ALL}"


def _print_results(findings: list[dict], config: dict) -> None:
    """Print a formatted vulnerability report to stdout."""
    verbose = config.get("verbose", False)

    counts = {SEV_HIGH: 0, SEV_MEDIUM: 0, SEV_LOW: 0, SEV_INFO: 0}
    for f in findings:
        counts[f.get("severity", SEV_INFO)] = counts.get(f.get("severity", SEV_INFO), 0) + 1

    print()
    print(f"{Fore.CYAN}{'═' * 72}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  LOCAL SECURITY SUITE — Vulnerability Scanner{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  "
          f"Platform: {platform.system()} {platform.release()}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═' * 72}{Style.RESET_ALL}")
    print()

    if not findings:
        print(f"{Fore.GREEN}  ✔  No vulnerabilities detected.{Style.RESET_ALL}")
        print()
        return

    # Sort by severity order
    sev_order = {SEV_HIGH: 0, SEV_MEDIUM: 1, SEV_LOW: 2, SEV_INFO: 3}
    sorted_findings = sorted(findings, key=lambda x: sev_order.get(x["severity"], 9))

    # Group by category
    categories: dict[str, list[dict]] = {}
    for f in sorted_findings:
        cat = f.get("category", "General")
        categories.setdefault(cat, []).append(f)

    for cat, cat_findings in categories.items():
        print(f"{Fore.WHITE}{Style.BRIGHT}  ▶ {cat}{Style.RESET_ALL}")
        rows = []
        for f in cat_findings:
            rows.append([
                _colour_sev(f["severity"]),
                f["name"],
                f["description"][:65] + ("…" if len(f["description"]) > 65 else ""),
            ])
        print(tabulate(rows, headers=["Severity", "Vulnerability", "Description"],
                       tablefmt="simple", colalign=("left", "left", "left")))
        if verbose:
            for f in cat_findings:
                if f.get("detail"):
                    print(f"    {Fore.WHITE}Detail:{Style.RESET_ALL} {f['detail']}")
        print()

    # Summary bar
    print(f"{Fore.CYAN}{'─' * 72}{Style.RESET_ALL}")
    h = counts[SEV_HIGH]
    m = counts[SEV_MEDIUM]
    lo = counts[SEV_LOW]
    i = counts[SEV_INFO]
    print(
        f"  Total findings: {len(findings)}  |  "
        f"{Fore.RED}{h} High{Style.RESET_ALL}  "
        f"{Fore.YELLOW}{m} Medium{Style.RESET_ALL}  "
        f"{Fore.CYAN}{lo} Low{Style.RESET_ALL}  "
        f"{Fore.WHITE}{i} Info{Style.RESET_ALL}"
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
                f"Local Security Suite — Vulnerability Scan Report",
                f"Generated: {datetime.now().isoformat(timespec='seconds')}",
                f"Platform : {platform.system()} {platform.release()}",
                "=" * 72,
                "",
            ]
            sev_order = {SEV_HIGH: 0, SEV_MEDIUM: 1, SEV_LOW: 2, SEV_INFO: 3}
            for f in sorted(result.get("findings", []),
                            key=lambda x: sev_order.get(x["severity"], 9)):
                lines.append(f"[{f['severity']:6}] {f['name']}")
                lines.append(f"         {f['description']}")
                if f.get("detail"):
                    lines.append(f"         Detail: {f['detail']}")
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
    Vulnerability Scanner entry point.

    Args:
        config: dict with keys output_format, output_path, verbose, target

    Returns:
        {"status": "ok"|"error", "findings": [...], "summary": "..."}
    """
    findings = _collect_findings()
    _print_results(findings, config)

    counts = {SEV_HIGH: 0, SEV_MEDIUM: 0, SEV_LOW: 0, SEV_INFO: 0}
    for f in findings:
        sev = f.get("severity", SEV_INFO)
        counts[sev] = counts.get(sev, 0) + 1

    summary = (
        f"{len(findings)} vulnerabilities found — "
        f"{counts[SEV_HIGH]} High, "
        f"{counts[SEV_MEDIUM]} Medium, "
        f"{counts[SEV_LOW]} Low, "
        f"{counts[SEV_INFO]} Info"
    )

    result: dict[str, Any] = {
        "status":   "ok",
        "module":   "vuln_scanner",
        "platform": platform.system(),
        "findings": findings,
        "summary":  summary,
        "counts":   counts,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }

    _save_output(result, config)
    return result
