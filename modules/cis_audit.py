"""
modules/cis_audit.py
=====================
CIS Benchmark Compliance Checker for Local Security Suite.

Checks system configuration against a subset of CIS Benchmark controls.
Supports both Linux (Ubuntu/Kali/Debian) and Windows 10/11.

Entry point:
    run(config: dict) -> dict

Control categories covered:
    1.  Password minimum length policy
    2.  Password complexity policy
    3.  Password expiry / max age policy
    4.  Guest account disabled
    5.  Firewall enabled (ufw on Linux / Windows Firewall on Windows)
    6.  SSH root login disabled              [Linux only]
    7.  Audit daemon running                 [Linux] / Event Log running [Windows]
    8.  World-writable files in temp dirs
    9.  Cron job permissions                 [Linux] / Task Scheduler check [Windows]
    10. Automatic updates enabled
    11. Core dumps disabled                  [Linux] / WER disabled [Windows]
    12. Unused / risky services disabled
"""

import os
import platform
import re
import subprocess
import sys
from datetime import datetime
from typing import Any

from colorama import Fore, Style
from tabulate import tabulate

# ─────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────

RISKY_SERVICES_LINUX = [
    "telnet", "rsh", "rlogin", "rexec",
    "tftp", "finger", "chargen", "daytime",
    "echo", "discard", "talk", "ntalk",
]

RISKY_SERVICES_WINDOWS = [
    "telnet", "RemoteRegistry", "Fax",
    "XblAuthManager", "XboxNetApiSvc",
]

PASS_LABEL  = f"{Fore.GREEN}PASS{Style.RESET_ALL}"
FAIL_LABEL  = f"{Fore.RED}FAIL{Style.RESET_ALL}"
WARN_LABEL  = f"{Fore.YELLOW}WARN{Style.RESET_ALL}"
SKIP_LABEL  = f"{Fore.YELLOW}SKIP{Style.RESET_ALL}"


# ─────────────────────────────────────────────
#  Internal helpers — platform detection
# ─────────────────────────────────────────────

def _is_linux() -> bool:
    return platform.system() == "Linux"


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _is_darwin() -> bool:
    return platform.system() == "Darwin"


def _run_cmd(args: list[str], timeout: int = 10) -> tuple[int, str, str]:
    """
    Run a subprocess command safely (no shell=True).

    Returns:
        (returncode, stdout, stderr)
    """
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        return -1, "", f"Command not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out: {' '.join(args)}"
    except Exception as exc:  # noqa: BLE001
        return -1, "", str(exc)


def _read_file(path: str) -> str:
    """Read a text file and return its contents, or empty string on failure."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


# ─────────────────────────────────────────────
#  Control builders
# ─────────────────────────────────────────────

def _make_control(
    cid: str,
    name: str,
    result: str,          # "PASS" | "FAIL" | "WARN" | "SKIP"
    detail: str,
    recommendation: str,
) -> dict:
    """Return a normalised control result dict."""
    return {
        "id":             cid,
        "name":           name,
        "result":         result,
        "detail":         detail,
        "recommendation": recommendation,
    }


# ─────────────────────────────────────────────
#  LINUX CONTROLS
# ─────────────────────────────────────────────

def _linux_password_min_length() -> dict:
    """CIS 5.4.1 — Password minimum length ≥ 14."""
    content = _read_file("/etc/security/pwquality.conf")
    if not content:
        content = _read_file("/etc/pam.d/common-password")

    match = re.search(r"minlen\s*=\s*(\d+)", content)
    if match:
        length = int(match.group(1))
        if length >= 14:
            return _make_control(
                "1", "Password Min Length",
                "PASS", f"minlen = {length}",
                "No action needed.",
            )
        return _make_control(
            "1", "Password Min Length",
            "FAIL", f"minlen = {length} (required ≥ 14)",
            "Set minlen = 14 in /etc/security/pwquality.conf",
        )
    return _make_control(
        "1", "Password Min Length",
        "WARN", "minlen not explicitly configured",
        "Set minlen = 14 in /etc/security/pwquality.conf",
    )


def _linux_password_complexity() -> dict:
    """CIS 5.4.1 — Password complexity (pam_pwquality minclass or dcredit/ucredit)."""
    content = _read_file("/etc/security/pwquality.conf")
    has_complexity = bool(
        re.search(r"minclass\s*=\s*[3-4]", content)
        or (re.search(r"dcredit\s*=\s*-", content) and re.search(r"ucredit\s*=\s*-", content))
    )
    if has_complexity:
        return _make_control(
            "2", "Password Complexity",
            "PASS", "Complexity requirements configured in pwquality.conf",
            "No action needed.",
        )
    return _make_control(
        "2", "Password Complexity",
        "FAIL", "Complexity not enforced in /etc/security/pwquality.conf",
        "Set minclass = 4 (or dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1) in pwquality.conf",
    )


def _linux_password_max_age() -> dict:
    """CIS 5.4.1 — PASS_MAX_DAYS ≤ 365."""
    content = _read_file("/etc/login.defs")
    match = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", content, re.MULTILINE)
    if match:
        days = int(match.group(1))
        if days <= 365:
            return _make_control(
                "3", "Password Max Age",
                "PASS", f"PASS_MAX_DAYS = {days}",
                "No action needed.",
            )
        return _make_control(
            "3", "Password Max Age",
            "FAIL", f"PASS_MAX_DAYS = {days} (required ≤ 365)",
            "Set PASS_MAX_DAYS 365 in /etc/login.defs",
        )
    return _make_control(
        "3", "Password Max Age",
        "WARN", "PASS_MAX_DAYS not found in /etc/login.defs",
        "Set PASS_MAX_DAYS 365 in /etc/login.defs",
    )


def _linux_guest_account() -> dict:
    """CIS — No guest account in /etc/passwd."""
    content = _read_file("/etc/passwd")
    if re.search(r"^guest:", content, re.MULTILINE):
        return _make_control(
            "4", "Guest Account Disabled",
            "FAIL", "Guest account found in /etc/passwd",
            "Run: userdel guest",
        )
    return _make_control(
        "4", "Guest Account Disabled",
        "PASS", "No guest account found",
        "No action needed.",
    )


def _linux_firewall() -> dict:
    """CIS 3.5 — ufw or iptables active."""
    rc, stdout, _ = _run_cmd(["ufw", "status"])
    if rc == 0 and "active" in stdout.lower():
        return _make_control(
            "5", "Firewall Enabled",
            "PASS", "ufw is active",
            "No action needed.",
        )

    # Fallback: check iptables has non-default rules
    rc2, stdout2, _ = _run_cmd(["iptables", "-L", "-n"])
    if rc2 == 0 and stdout2.count("\n") > 8:
        return _make_control(
            "5", "Firewall Enabled",
            "PASS", "iptables rules detected",
            "No action needed.",
        )

    return _make_control(
        "5", "Firewall Enabled",
        "FAIL", "No active firewall detected (ufw inactive or not installed)",
        "Run: sudo ufw enable",
    )


def _linux_ssh_root_login() -> dict:
    """CIS 5.2.10 — PermitRootLogin no in sshd_config."""
    content = _read_file("/etc/ssh/sshd_config")
    if not content:
        return _make_control(
            "6", "SSH Root Login Disabled",
            "SKIP", "/etc/ssh/sshd_config not found (SSH may not be installed)",
            "Install openssh-server and set PermitRootLogin no",
        )
    match = re.search(r"^\s*PermitRootLogin\s+(\S+)", content, re.MULTILINE | re.IGNORECASE)
    if match and match.group(1).lower() in ("no", "prohibit-password"):
        return _make_control(
            "6", "SSH Root Login Disabled",
            "PASS", f"PermitRootLogin = {match.group(1)}",
            "No action needed.",
        )
    current = match.group(1) if match else "not set (defaults to yes)"
    return _make_control(
        "6", "SSH Root Login Disabled",
        "FAIL", f"PermitRootLogin = {current}",
        "Set 'PermitRootLogin no' in /etc/ssh/sshd_config, then: sudo systemctl restart sshd",
    )


def _linux_auditd() -> dict:
    """CIS 4.1 — auditd service running."""
    rc, stdout, _ = _run_cmd(["systemctl", "is-active", "auditd"])
    if rc == 0 and stdout.strip() == "active":
        return _make_control(
            "7", "Audit Daemon Running",
            "PASS", "auditd service is active",
            "No action needed.",
        )
    return _make_control(
        "7", "Audit Daemon Running",
        "FAIL", f"auditd is not active (status: {stdout or 'unknown'})",
        "Run: sudo apt install auditd && sudo systemctl enable --now auditd",
    )


def _linux_world_writable_files() -> dict:
    """CIS 6.1.10 — No world-writable files in /tmp."""
    rc, stdout, _ = _run_cmd(
        ["find", "/tmp", "-xdev", "-type", "f", "-perm", "-0002"],
        timeout=15,
    )
    if rc == 0 and stdout.strip():
        files = stdout.strip().split("\n")
        return _make_control(
            "8", "World-Writable Files in /tmp",
            "FAIL", f"{len(files)} world-writable file(s) found",
            "Review and chmod o-w on each listed file.",
        )
    return _make_control(
        "8", "World-Writable Files in /tmp",
        "PASS", "No world-writable files found in /tmp",
        "No action needed.",
    )


def _linux_cron_permissions() -> dict:
    """CIS 5.1.2 — /etc/crontab owned by root, not world-writable."""
    path = "/etc/crontab"
    try:
        stat = os.stat(path)
        world_writable = bool(stat.st_mode & 0o002)
        root_owned     = (stat.st_uid == 0)
        if root_owned and not world_writable:
            return _make_control(
                "9", "Cron Job Permissions",
                "PASS", "/etc/crontab is root-owned and not world-writable",
                "No action needed.",
            )
        issues = []
        if not root_owned:
            issues.append(f"owner UID={stat.st_uid} (expected 0)")
        if world_writable:
            issues.append("world-writable bit set")
        return _make_control(
            "9", "Cron Job Permissions",
            "FAIL", "; ".join(issues),
            "Run: sudo chown root:root /etc/crontab && sudo chmod og-rwx /etc/crontab",
        )
    except OSError as exc:
        return _make_control(
            "9", "Cron Job Permissions",
            "WARN", f"Could not stat /etc/crontab: {exc}",
            "Ensure /etc/crontab exists and is root-owned.",
        )


def _linux_auto_updates() -> dict:
    """CIS — unattended-upgrades or dnf-automatic enabled."""
    rc, stdout, _ = _run_cmd(["systemctl", "is-active", "unattended-upgrades"])
    if rc == 0 and stdout.strip() == "active":
        return _make_control(
            "10", "Automatic Updates Enabled",
            "PASS", "unattended-upgrades is active",
            "No action needed.",
        )
    # Fallback check via dpkg
    rc2, _, _ = _run_cmd(["dpkg", "-s", "unattended-upgrades"])
    if rc2 == 0:
        return _make_control(
            "10", "Automatic Updates Enabled",
            "WARN", "unattended-upgrades installed but service not active",
            "Run: sudo systemctl enable --now unattended-upgrades",
        )
    return _make_control(
        "10", "Automatic Updates Enabled",
        "FAIL", "unattended-upgrades not installed or not active",
        "Run: sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades",
    )


def _linux_core_dumps() -> dict:
    """CIS 1.5.1 — Core dumps disabled via /etc/security/limits.conf."""
    content = _read_file("/etc/security/limits.conf")
    if re.search(r"^\s*\*\s+hard\s+core\s+0", content, re.MULTILINE):
        return _make_control(
            "11", "Core Dumps Disabled",
            "PASS", "'* hard core 0' found in /etc/security/limits.conf",
            "No action needed.",
        )
    # Also check sysctl
    rc, stdout, _ = _run_cmd(["sysctl", "fs.suid_dumpable"])
    if rc == 0 and "= 0" in stdout:
        return _make_control(
            "11", "Core Dumps Disabled",
            "PASS", "fs.suid_dumpable = 0",
            "No action needed.",
        )
    return _make_control(
        "11", "Core Dumps Disabled",
        "FAIL", "Core dumps may be enabled",
        "Add '* hard core 0' to /etc/security/limits.conf and set fs.suid_dumpable=0 in /etc/sysctl.conf",
    )


def _linux_risky_services() -> dict:
    """CIS 2.x — Risky legacy services should be disabled."""
    active = []
    for svc in RISKY_SERVICES_LINUX:
        rc, stdout, _ = _run_cmd(["systemctl", "is-active", svc])
        if rc == 0 and stdout.strip() == "active":
            active.append(svc)

    if not active:
        return _make_control(
            "12", "Risky Services Disabled",
            "PASS", f"None of the checked legacy services are active: {', '.join(RISKY_SERVICES_LINUX)}",
            "No action needed.",
        )
    return _make_control(
        "12", "Risky Services Disabled",
        "FAIL", f"Active risky service(s): {', '.join(active)}",
        f"Run: sudo systemctl disable --now {' '.join(active)}",
    )


# ─────────────────────────────────────────────
#  WINDOWS CONTROLS
# ─────────────────────────────────────────────

def _win_run_ps(script: str, timeout: int = 15) -> tuple[int, str]:
    """Execute a PowerShell snippet and return (returncode, stdout)."""
    rc, stdout, stderr = _run_cmd(
        ["powershell", "-NonInteractive", "-NoProfile", "-Command", script],
        timeout=timeout,
    )
    return rc, stdout


def _win_password_min_length() -> dict:
    """Check Windows local password policy min length."""
    rc, stdout = _win_run_ps(
        "(Get-LocalUser | Select-Object -First 1) ; "
        "net accounts | Select-String 'Minimum password length'"
    )
    match = re.search(r"Minimum password length\s+(\d+)", stdout, re.IGNORECASE)
    if match:
        length = int(match.group(1))
        if length >= 14:
            return _make_control(
                "1", "Password Min Length",
                "PASS", f"Minimum password length = {length}",
                "No action needed.",
            )
        return _make_control(
            "1", "Password Min Length",
            "FAIL", f"Minimum password length = {length} (required ≥ 14)",
            "Set via: net accounts /minpwlen:14",
        )
    return _make_control(
        "1", "Password Min Length",
        "WARN", "Could not retrieve password policy",
        "Run 'net accounts' and verify Minimum password length ≥ 14",
    )


def _win_password_complexity() -> dict:
    """Check Windows password complexity requirement."""
    rc, stdout = _win_run_ps("net accounts | Select-String 'complexity'")
    if not stdout:
        # Try secedit approach
        rc2, stdout2 = _win_run_ps(
            "secedit /export /cfg $env:TEMP\\secpol.cfg /quiet ; "
            "Select-String 'PasswordComplexity' $env:TEMP\\secpol.cfg"
        )
        stdout = stdout2

    if re.search(r"PasswordComplexity\s*=\s*1", stdout, re.IGNORECASE):
        return _make_control(
            "2", "Password Complexity",
            "PASS", "Password complexity is enabled",
            "No action needed.",
        )
    return _make_control(
        "2", "Password Complexity",
        "FAIL", "Password complexity not confirmed as enabled",
        "Enable via Local Security Policy → Password Policy → Password must meet complexity requirements",
    )


def _win_password_max_age() -> dict:
    """Check Windows PASS_MAX_DAYS equivalent."""
    rc, stdout = _win_run_ps("net accounts | Select-String 'Maximum password age'")
    match = re.search(r"Maximum password age \(days\)\s+(\d+|Never)", stdout, re.IGNORECASE)
    if match:
        val = match.group(1)
        if val.lower() == "never":
            return _make_control(
                "3", "Password Max Age",
                "FAIL", "Maximum password age = Never (passwords never expire)",
                "Set via: net accounts /maxpwage:365",
            )
        if int(val) <= 365:
            return _make_control(
                "3", "Password Max Age",
                "PASS", f"Maximum password age = {val} days",
                "No action needed.",
            )
        return _make_control(
            "3", "Password Max Age",
            "FAIL", f"Maximum password age = {val} days (required ≤ 365)",
            "Set via: net accounts /maxpwage:365",
        )
    return _make_control(
        "3", "Password Max Age",
        "WARN", "Could not determine maximum password age",
        "Run 'net accounts' and ensure Maximum password age ≤ 365",
    )


def _win_guest_account() -> dict:
    """Check that the built-in Guest account is disabled."""
    rc, stdout = _win_run_ps(
        "(Get-LocalUser -Name 'Guest').Enabled"
    )
    val = stdout.strip().lower()
    if val == "false":
        return _make_control(
            "4", "Guest Account Disabled",
            "PASS", "Built-in Guest account is disabled",
            "No action needed.",
        )
    if val == "true":
        return _make_control(
            "4", "Guest Account Disabled",
            "FAIL", "Built-in Guest account is ENABLED",
            "Run: Disable-LocalUser -Name 'Guest'",
        )
    return _make_control(
        "4", "Guest Account Disabled",
        "WARN", "Could not determine Guest account status",
        "Run: Get-LocalUser -Name 'Guest' | Disable-LocalUser",
    )


def _win_firewall() -> dict:
    """Check Windows Firewall is enabled on all profiles."""
    rc, stdout = _win_run_ps(
        "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Csv -NoTypeInformation"
    )
    if rc != 0 or not stdout:
        return _make_control(
            "5", "Firewall Enabled",
            "WARN", "Could not query Windows Firewall profiles",
            "Manually verify Windows Defender Firewall is enabled for all profiles.",
        )
    disabled = [
        line for line in stdout.splitlines()
        if "False" in line
    ]
    if disabled:
        profiles = [l.split(",")[0].strip('"') for l in disabled]
        return _make_control(
            "5", "Firewall Enabled",
            "FAIL", f"Firewall disabled on: {', '.join(profiles)}",
            "Run: Set-NetFirewallProfile -All -Enabled True",
        )
    return _make_control(
        "5", "Firewall Enabled",
        "PASS", "Windows Firewall enabled on all profiles",
        "No action needed.",
    )


def _win_event_log() -> dict:
    """Windows equivalent of auditd — Windows Event Log service running."""
    rc, stdout = _win_run_ps(
        "(Get-Service -Name 'EventLog').Status"
    )
    if stdout.strip().lower() == "running":
        return _make_control(
            "7", "Event Log Service Running",
            "PASS", "Windows Event Log service is Running",
            "No action needed.",
        )
    return _make_control(
        "7", "Event Log Service Running",
        "FAIL", f"Windows Event Log service status: {stdout.strip() or 'unknown'}",
        "Run: Start-Service EventLog",
    )


def _win_world_writable_temp() -> dict:
    """Check for world-writable files in C:\\Temp or %TEMP%."""
    temp_dirs = [r"C:\Temp", os.environ.get("TEMP", "")]
    found = []
    for d in temp_dirs:
        if not d or not os.path.isdir(d):
            continue
        try:
            for root, _, files in os.walk(d):
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        # On Windows, check if Everyone has write via icacls
                        rc, out = _win_run_ps(
                            f"(Get-Acl '{fp}').Access | Where-Object {{$_.IdentityReference -match 'Everyone' -and $_.FileSystemRights -match 'Write'}}"
                        )
                        if out.strip():
                            found.append(fp)
                    except Exception:  # noqa: BLE001
                        pass
        except OSError:
            pass

    if found:
        return _make_control(
            "8", "World-Writable Files in Temp",
            "FAIL", f"{len(found)} world-writable file(s) found in temp dirs",
            "Review file ACLs and remove Everyone:Write permissions.",
        )
    return _make_control(
        "8", "World-Writable Files in Temp",
        "PASS", "No obvious world-writable files found in temp directories",
        "No action needed.",
    )


def _win_task_scheduler() -> dict:
    """Check for suspicious scheduled tasks with curl/wget/powershell download patterns."""
    rc, stdout = _win_run_ps(
        "Get-ScheduledTask | Where-Object {$_.Actions.Execute -ne $null} | "
        "Select-Object TaskName, @{N='Execute';E={$_.Actions.Execute}} | "
        "ConvertTo-Csv -NoTypeInformation"
    )
    suspicious_patterns = [r"wget", r"curl", r"bash\s+-i", r"IEX", r"Invoke-Expression", r"DownloadString"]
    flagged = []
    for line in stdout.splitlines():
        for pat in suspicious_patterns:
            if re.search(pat, line, re.IGNORECASE):
                flagged.append(line.strip())
                break

    if flagged:
        return _make_control(
            "9", "Suspicious Scheduled Tasks",
            "FAIL", f"{len(flagged)} suspicious task(s) found",
            "Review and disable suspicious tasks via Task Scheduler or Unregister-ScheduledTask.",
        )
    return _make_control(
        "9", "Suspicious Scheduled Tasks",
        "PASS", "No obviously suspicious scheduled tasks detected",
        "No action needed.",
    )


def _win_auto_updates() -> dict:
    """Check Windows Update automatic updates status via registry."""
    rc, stdout = _win_run_ps(
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' "
        "-ErrorAction SilentlyContinue | Select-Object NoAutoUpdate,AUOptions | ConvertTo-Csv -NoTypeInformation"
    )
    no_auto = re.search(r"NoAutoUpdate.*?(\d)", stdout)
    if no_auto and no_auto.group(1) == "1":
        return _make_control(
            "10", "Automatic Updates Enabled",
            "FAIL", "NoAutoUpdate = 1 (automatic updates disabled via policy)",
            "Enable Windows Update in Settings → Windows Update → Advanced Options",
        )
    rc2, stdout2 = _win_run_ps("(Get-Service -Name 'wuauserv').Status")
    if stdout2.strip().lower() == "running":
        return _make_control(
            "10", "Automatic Updates Enabled",
            "PASS", "Windows Update service (wuauserv) is running",
            "No action needed.",
        )
    return _make_control(
        "10", "Automatic Updates Enabled",
        "WARN", "Could not confirm automatic updates status",
        "Verify in Settings → Windows Update that automatic updates are enabled.",
    )


def _win_error_reporting() -> dict:
    """CIS — Disable Windows Error Reporting (WER) equivalent of core dumps."""
    rc, stdout = _win_run_ps(
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting' "
        "-Name Disabled -ErrorAction SilentlyContinue | Select-Object Disabled | ConvertTo-Csv -NoTypeInformation"
    )
    if re.search(r"Disabled.*1", stdout, re.IGNORECASE):
        return _make_control(
            "11", "Windows Error Reporting Disabled",
            "PASS", "WER Disabled = 1",
            "No action needed.",
        )
    return _make_control(
        "11", "Windows Error Reporting Disabled",
        "FAIL", "Windows Error Reporting is not disabled",
        "Set HKLM:\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\Disabled = 1",
    )


def _win_risky_services() -> dict:
    """Check that known risky/unnecessary Windows services are not running."""
    active = []
    for svc in RISKY_SERVICES_WINDOWS:
        rc, stdout = _win_run_ps(f"(Get-Service -Name '{svc}' -ErrorAction SilentlyContinue).Status")
        if stdout.strip().lower() == "running":
            active.append(svc)

    if active:
        return _make_control(
            "12", "Risky Services Disabled",
            "FAIL", f"Active risky service(s): {', '.join(active)}",
            f"Run: Stop-Service {' | '.join(active)}  then  Set-Service -StartupType Disabled",
        )
    return _make_control(
        "12", "Risky Services Disabled",
        "PASS", f"None of the checked services are running: {', '.join(RISKY_SERVICES_WINDOWS)}",
        "No action needed.",
    )


# ─────────────────────────────────────────────
#  DARWIN (macOS) CONTROLS  — best-effort subset
# ─────────────────────────────────────────────

def _darwin_controls() -> list[dict]:
    """Return a reduced but honest set of CIS checks for macOS."""
    controls = []

    # Firewall
    rc, stdout, _ = _run_cmd(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    if rc == 0 and "enabled" in stdout.lower():
        controls.append(_make_control("5", "Firewall Enabled", "PASS", stdout.strip(), "No action needed."))
    else:
        controls.append(_make_control("5", "Firewall Enabled", "FAIL", "Application Firewall not enabled",
                                       "Enable via System Preferences → Security & Privacy → Firewall"))

    # SSH root login (macOS uses same sshd_config path)
    ssh_content = _read_file("/etc/ssh/sshd_config")
    match = re.search(r"^\s*PermitRootLogin\s+(\S+)", ssh_content, re.MULTILINE | re.IGNORECASE)
    if match and match.group(1).lower() in ("no", "prohibit-password"):
        controls.append(_make_control("6", "SSH Root Login Disabled", "PASS",
                                       f"PermitRootLogin = {match.group(1)}", "No action needed."))
    else:
        controls.append(_make_control("6", "SSH Root Login Disabled", "FAIL",
                                       "PermitRootLogin not explicitly set to 'no'",
                                       "Set 'PermitRootLogin no' in /etc/ssh/sshd_config"))

    # Auto updates
    rc2, stdout2, _ = _run_cmd(["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"])
    if rc2 == 0 and stdout2.strip() == "1":
        controls.append(_make_control("10", "Automatic Updates Enabled", "PASS", "AutomaticCheckEnabled = 1", "No action needed."))
    else:
        controls.append(_make_control("10", "Automatic Updates Enabled", "FAIL",
                                       "Automatic Software Update check not enabled",
                                       "Enable in System Preferences → Software Update → Automatically keep my Mac up to date"))

    # Guest account
    rc3, stdout3, _ = _run_cmd(["dscl", ".", "-read", "/Users/Guest", "AuthenticationAuthority"])
    if rc3 != 0:
        controls.append(_make_control("4", "Guest Account Disabled", "PASS", "Guest account does not exist", "No action needed."))
    else:
        controls.append(_make_control("4", "Guest Account Disabled", "FAIL", "Guest account is present",
                                       "Disable via System Preferences → Users & Groups → Guest User"))

    # Mark remaining controls as SKIP for Darwin
    for cid, name in [("1", "Password Min Length"), ("2", "Password Complexity"),
                      ("3", "Password Max Age"), ("7", "Audit Daemon"),
                      ("8", "World-Writable Files"), ("9", "Cron Permissions"),
                      ("11", "Core Dumps"), ("12", "Risky Services")]:
        controls.append(_make_control(cid, name, "SKIP",
                                       "Automated check not implemented for macOS",
                                       "Review CIS macOS Benchmark manually."))
    return controls


# ─────────────────────────────────────────────
#  Orchestrator — collect all controls
# ─────────────────────────────────────────────

def _collect_controls() -> list[dict]:
    """Run all platform-appropriate CIS controls and return list of results."""
    system = platform.system()

    if system == "Linux":
        return [
            _linux_password_min_length(),
            _linux_password_complexity(),
            _linux_password_max_age(),
            _linux_guest_account(),
            _linux_firewall(),
            _linux_ssh_root_login(),
            _linux_auditd(),
            _linux_world_writable_files(),
            _linux_cron_permissions(),
            _linux_auto_updates(),
            _linux_core_dumps(),
            _linux_risky_services(),
        ]

    if system == "Windows":
        return [
            _win_password_min_length(),
            _win_password_complexity(),
            _win_password_max_age(),
            _win_guest_account(),
            _win_firewall(),
            _win_event_log(),          # control 7 (no SSH on Windows)
            _win_world_writable_temp(),
            _win_task_scheduler(),
            _win_auto_updates(),
            _win_error_reporting(),
            _win_risky_services(),
        ]

    if system == "Darwin":
        return _darwin_controls()

    return [_make_control("0", "Platform Detection", "FAIL",
                          f"Unsupported platform: {system}",
                          "Run on Linux, Windows, or macOS.")]


# ─────────────────────────────────────────────
#  Output / Display
# ─────────────────────────────────────────────

_RESULT_COLOUR = {
    "PASS": Fore.GREEN,
    "FAIL": Fore.RED,
    "WARN": Fore.YELLOW,
    "SKIP": Fore.YELLOW,
}


def _colour_result(result: str) -> str:
    colour = _RESULT_COLOUR.get(result, "")
    return f"{colour}{result}{Style.RESET_ALL}"


def _print_results(controls: list[dict], score: float, config: dict) -> None:
    """Print a formatted table of control results to stdout."""
    rows = []
    for ctrl in controls:
        rows.append([
            ctrl["id"],
            ctrl["name"],
            _colour_result(ctrl["result"]),
            ctrl["detail"],
        ])

    headers = ["ID", "Control", "Result", "Detail"]
    print(tabulate(rows, headers=headers, tablefmt="rounded_outline"))

    total  = len(controls)
    passed = sum(1 for c in controls if c["result"] == "PASS")
    failed = sum(1 for c in controls if c["result"] == "FAIL")
    warned = sum(1 for c in controls if c["result"] in ("WARN", "SKIP"))

    colour = Fore.GREEN if score >= 80 else (Fore.YELLOW if score >= 50 else Fore.RED)
    print(f"\n{colour}  Compliance Score : {score:.1f}%{Style.RESET_ALL}")
    print(f"  Total Controls   : {total}")
    print(f"  {Fore.GREEN}Passed{Style.RESET_ALL}           : {passed}")
    print(f"  {Fore.RED}Failed{Style.RESET_ALL}           : {failed}")
    print(f"  {Fore.YELLOW}Warn / Skip{Style.RESET_ALL}      : {warned}")

    if config.get("verbose"):
        print(f"\n{'─'*54}\n  RECOMMENDATIONS\n{'─'*54}")
        for ctrl in controls:
            if ctrl["result"] in ("FAIL", "WARN"):
                print(f"  [{ctrl['id']}] {ctrl['name']}")
                print(f"      → {ctrl['recommendation']}\n")


# ─────────────────────────────────────────────
#  Module Entry Point
# ─────────────────────────────────────────────

def run(config: dict) -> dict:
    """
    Execute all CIS Benchmark controls for the current platform.

    Args:
        config: Shared config dict with keys:
                output_format, output_path, verbose, target

    Returns:
        {
            "status":   "ok" | "error",
            "findings": [ list of control dicts ],
            "summary":  "X/Y controls passed (Z%)"
        }
    """
    print(f"{Fore.CYAN}[*] Platform : {platform.system()} {platform.release()}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Running CIS Benchmark checks …{Style.RESET_ALL}\n")

    try:
        controls = _collect_controls()
    except Exception as exc:  # noqa: BLE001
        return {
            "status":   "error",
            "findings": [],
            "summary":  f"CIS audit failed with unexpected error: {exc}",
        }

    total  = len(controls)
    passed = sum(1 for c in controls if c["result"] == "PASS")
    score  = (passed / total * 100) if total > 0 else 0.0

    _print_results(controls, score, config)

    # Serialisable findings (strip ANSI for JSON/file output)
    serialisable = [
        {
            "id":             c["id"],
            "name":           c["name"],
            "result":         c["result"],
            "detail":         c["detail"],
            "recommendation": c["recommendation"],
        }
        for c in controls
    ]

    return {
        "status":   "ok",
        "findings": serialisable,
        "summary":  f"{passed}/{total} controls passed ({score:.1f}% compliance)",
    }
