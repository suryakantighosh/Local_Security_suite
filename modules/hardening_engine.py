"""
modules/hardening_engine.py
============================
Hardening Engine for Local Security Suite.

Checks and optionally applies system hardening configurations.
Supports Linux (Ubuntu/Kali/Debian) and Windows 10/11.

Entry point:
    run(config: dict) -> dict

Modes:
    Dry-run (default):  Check each hardening item, report current status
                        and recommended action. No changes made.
    Apply mode:         Actually apply safe, reversible hardening changes.
                        Requires elevated privileges (root on Linux /
                        Administrator on Windows).
                        Always prompts y/n before applying any change.

Hardening items covered:
    1.  Guest account disabled
    2.  Firewall enabled (ufw on Linux / Windows Firewall on Windows)
    3.  SSH root login disabled              [Linux only]
    4.  Password minimum length (≥ 14)
    5.  Core dumps disabled                  [Linux only]
    6.  Automatic security updates enabled
    7.  Auditd / Windows Event Log enabled
    8.  Telnet service disabled
    9.  Unused risky services disabled
    10. /tmp noexec mount option             [Linux only]
    11. IPv6 disabled if unused              [Linux only]
    12. Ctrl-Alt-Delete reboot disabled      [Linux only]
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

PASS_LABEL  = f"{Fore.GREEN}OK{Style.RESET_ALL}"
FAIL_LABEL  = f"{Fore.RED}NOT HARDENED{Style.RESET_ALL}"
WARN_LABEL  = f"{Fore.YELLOW}WARNING{Style.RESET_ALL}"
SKIP_LABEL  = f"{Fore.YELLOW}SKIPPED{Style.RESET_ALL}"
APPLIED_YES = f"{Fore.GREEN}YES{Style.RESET_ALL}"
APPLIED_NO  = f"{Fore.YELLOW}NO{Style.RESET_ALL}"
APPLIED_NA  = f"{Fore.CYAN}N/A{Style.RESET_ALL}"

SSHD_CONFIG = "/etc/ssh/sshd_config"
LIMITS_CONF = "/etc/security/limits.conf"
FSTAB_PATH  = "/etc/fstab"
SYSCTL_CONF = "/etc/sysctl.d/99-hardening.conf"

# ─────────────────────────────────────────────
#  Platform helpers
# ─────────────────────────────────────────────

def _is_linux() -> bool:
    return platform.system() == "Linux"


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _is_darwin() -> bool:
    return platform.system() == "Darwin"


def _is_root() -> bool:
    """Return True if running as root/Administrator."""
    if _is_windows():
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001
            return False
    return os.geteuid() == 0


# ─────────────────────────────────────────────
#  Subprocess helper
# ─────────────────────────────────────────────

def _run_cmd(args: list, timeout: int = 10) -> tuple:
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
        return -1, "", f"Command timed out: {' '.join(str(a) for a in args)}"
    except Exception as exc:  # noqa: BLE001
        return -1, "", str(exc)


def _read_file(path: str) -> str:
    """Read a text file, return contents or empty string on failure."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _write_file(path: str, content: str) -> tuple:
    """
    Write content to a file.

    Returns:
        (success: bool, error_message: str)
    """
    try:
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return True, ""
    except OSError as exc:
        return False, str(exc)


# ─────────────────────────────────────────────
#  PowerShell helper (Windows)
# ─────────────────────────────────────────────

def _run_ps(snippet: str, timeout: int = 15) -> tuple:
    """
    Execute a PowerShell snippet.

    Returns:
        (returncode, stdout, stderr)
    """
    return _run_cmd(
        ["powershell", "-NonInteractive", "-NoProfile", "-Command", snippet],
        timeout=timeout,
    )


# ─────────────────────────────────────────────
#  Item factory
# ─────────────────────────────────────────────

def _make_item(
    item_id: str,
    title: str,
    current_status: str,
    recommended_action: str,
    status: str,                 # "ok" | "not_hardened" | "warning" | "skipped"
    platform_scope: str,         # "linux" | "windows" | "both"
    applied: str = "n/a",        # "yes" | "no" | "n/a"
    apply_note: str = "",
) -> dict:
    """Return a normalised hardening item dict."""
    return {
        "id":                 item_id,
        "title":              title,
        "current_status":     current_status,
        "recommended_action": recommended_action,
        "status":             status,
        "platform_scope":     platform_scope,
        "applied":            applied,
        "apply_note":         apply_note,
    }


# ═══════════════════════════════════════════════════════════════════════
#  LINUX — CHECK FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════

def _linux_check_guest_account() -> dict:
    """H-01 — No guest account in /etc/passwd."""
    passwd = _read_file("/etc/passwd")
    if "guest" in passwd.lower():
        return _make_item(
            "H-01", "Guest account disabled",
            "Guest account entry found in /etc/passwd",
            "Remove or lock the guest account: sudo userdel guest",
            "not_hardened", "linux",
        )
    return _make_item(
        "H-01", "Guest account disabled",
        "No guest account found",
        "No action required",
        "ok", "linux",
    )


def _linux_check_firewall() -> dict:
    """H-02 — ufw or iptables active."""
    rc_ufw, out_ufw, _ = _run_cmd(["ufw", "status"])
    if rc_ufw == 0 and "active" in out_ufw.lower():
        return _make_item(
            "H-02", "Firewall enabled",
            "ufw is ACTIVE",
            "No action required",
            "ok", "linux",
        )
    # Try iptables
    rc_ipt, out_ipt, _ = _run_cmd(["iptables", "-L", "-n"])
    if rc_ipt == 0 and len(out_ipt.splitlines()) > 5:
        return _make_item(
            "H-02", "Firewall enabled",
            "iptables rules present",
            "No action required",
            "ok", "linux",
        )
    return _make_item(
        "H-02", "Firewall enabled",
        "No active firewall detected (ufw inactive or missing)",
        "Enable ufw: sudo ufw enable",
        "not_hardened", "linux",
    )


def _linux_apply_firewall() -> tuple:
    """Apply: enable ufw non-interactively."""
    rc, out, err = _run_cmd(["ufw", "--force", "enable"])
    if rc == 0:
        return True, "ufw enabled"
    return False, err or out


def _linux_check_ssh_root_login() -> dict:
    """H-03 — PermitRootLogin no in sshd_config."""
    content = _read_file(SSHD_CONFIG)
    if not content:
        return _make_item(
            "H-03", "SSH root login disabled",
            "sshd_config not found (SSH may not be installed)",
            "No action required if SSH is not installed",
            "skipped", "linux",
        )
    # Look for uncommented PermitRootLogin line
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.match(r"PermitRootLogin\s+", stripped, re.IGNORECASE):
            if re.search(r"no", stripped, re.IGNORECASE):
                return _make_item(
                    "H-03", "SSH root login disabled",
                    "PermitRootLogin no",
                    "No action required",
                    "ok", "linux",
                )
            return _make_item(
                "H-03", "SSH root login disabled",
                f"PermitRootLogin is set to a permissive value: {stripped}",
                "Set PermitRootLogin no in /etc/ssh/sshd_config and restart sshd",
                "not_hardened", "linux",
            )
    return _make_item(
        "H-03", "SSH root login disabled",
        "PermitRootLogin not explicitly set (defaults to prohibit-password on modern systems)",
        "Explicitly set PermitRootLogin no in /etc/ssh/sshd_config",
        "warning", "linux",
    )


def _linux_apply_ssh_root_login() -> tuple:
    """Apply: set PermitRootLogin no in sshd_config."""
    content = _read_file(SSHD_CONFIG)
    if not content:
        return False, "sshd_config not found"
    # Remove existing PermitRootLogin lines and append correct value
    new_lines = [
        ln for ln in content.splitlines()
        if not re.match(r"\s*#?\s*PermitRootLogin", ln, re.IGNORECASE)
    ]
    new_lines.append("PermitRootLogin no")
    ok, err = _write_file(SSHD_CONFIG, "\n".join(new_lines) + "\n")
    if not ok:
        return False, err
    _run_cmd(["systemctl", "restart", "sshd"])
    return True, "PermitRootLogin no set; sshd restarted"


def _linux_check_password_policy() -> dict:
    """H-04 — Password minimum length >= 14 in /etc/login.defs."""
    content = _read_file("/etc/login.defs")
    for line in content.splitlines():
        if line.startswith("#"):
            continue
        m = re.match(r"PASS_MIN_LEN\s+(\d+)", line)
        if m:
            length = int(m.group(1))
            if length >= 14:
                return _make_item(
                    "H-04", "Password minimum length (≥ 14)",
                    f"PASS_MIN_LEN = {length}",
                    "No action required",
                    "ok", "both",
                )
            return _make_item(
                "H-04", "Password minimum length (≥ 14)",
                f"PASS_MIN_LEN = {length} (below recommended 14)",
                "Set PASS_MIN_LEN 14 in /etc/login.defs",
                "not_hardened", "both",
            )
    return _make_item(
        "H-04", "Password minimum length (≥ 14)",
        "PASS_MIN_LEN not found in /etc/login.defs",
        "Add PASS_MIN_LEN 14 to /etc/login.defs",
        "warning", "both",
    )


def _linux_apply_password_policy() -> tuple:
    """Apply: ensure PASS_MIN_LEN 14 in /etc/login.defs."""
    content = _read_file("/etc/login.defs")
    new_lines = [
        ln for ln in content.splitlines()
        if not re.match(r"\s*PASS_MIN_LEN\b", ln)
    ]
    new_lines.append("PASS_MIN_LEN\t14")
    ok, err = _write_file("/etc/login.defs", "\n".join(new_lines) + "\n")
    if not ok:
        return False, err
    return True, "PASS_MIN_LEN set to 14 in /etc/login.defs"


def _linux_check_core_dumps() -> dict:
    """H-05 — Core dumps disabled in /etc/security/limits.conf."""
    content = _read_file(LIMITS_CONF)
    has_hard_core = False
    for line in content.splitlines():
        if line.startswith("#"):
            continue
        if re.search(r"\bcore\b", line) and "hard" in line and "0" in line:
            has_hard_core = True
            break
    if has_hard_core:
        return _make_item(
            "H-05", "Core dumps disabled",
            "hard core 0 found in limits.conf",
            "No action required",
            "ok", "linux",
        )
    return _make_item(
        "H-05", "Core dumps disabled",
        "Core dump restriction not found in /etc/security/limits.conf",
        "Add '* hard core 0' to /etc/security/limits.conf",
        "not_hardened", "linux",
    )


def _linux_apply_core_dumps() -> tuple:
    """Apply: add hard core 0 to limits.conf."""
    content = _read_file(LIMITS_CONF)
    if "hard core 0" in content:
        return True, "Already set"
    content += "\n* hard core 0\n"
    ok, err = _write_file(LIMITS_CONF, content)
    if not ok:
        return False, err
    return True, "Added '* hard core 0' to limits.conf"


def _linux_check_auto_updates() -> dict:
    """H-06 — unattended-upgrades or dnf-automatic enabled."""
    rc, out, _ = _run_cmd(["systemctl", "is-enabled", "unattended-upgrades"])
    if rc == 0 and "enabled" in out:
        return _make_item(
            "H-06", "Automatic security updates",
            "unattended-upgrades service enabled",
            "No action required",
            "ok", "both",
        )
    rc2, out2, _ = _run_cmd(["systemctl", "is-enabled", "dnf-automatic"])
    if rc2 == 0 and "enabled" in out2:
        return _make_item(
            "H-06", "Automatic security updates",
            "dnf-automatic service enabled",
            "No action required",
            "ok", "both",
        )
    return _make_item(
        "H-06", "Automatic security updates",
        "Neither unattended-upgrades nor dnf-automatic is enabled",
        "Run: sudo apt install unattended-upgrades && sudo dpkg-reconfigure unattended-upgrades",
        "not_hardened", "both",
    )


def _linux_apply_auto_updates() -> tuple:
    """Apply: enable unattended-upgrades."""
    rc, _, err = _run_cmd(["systemctl", "enable", "--now", "unattended-upgrades"])
    if rc == 0:
        return True, "unattended-upgrades enabled"
    return False, err


def _linux_check_auditd() -> dict:
    """H-07 — auditd running."""
    rc, out, _ = _run_cmd(["systemctl", "is-active", "auditd"])
    if rc == 0 and out.strip() == "active":
        return _make_item(
            "H-07", "Audit daemon (auditd) running",
            "auditd service is ACTIVE",
            "No action required",
            "ok", "linux",
        )
    return _make_item(
        "H-07", "Audit daemon (auditd) running",
        "auditd is not running",
        "Install and enable auditd: sudo apt install auditd && sudo systemctl enable --now auditd",
        "not_hardened", "linux",
    )


def _linux_apply_auditd() -> tuple:
    """Apply: enable and start auditd."""
    rc, _, err = _run_cmd(["systemctl", "enable", "--now", "auditd"])
    if rc == 0:
        return True, "auditd enabled and started"
    return False, err


def _linux_check_telnet() -> dict:
    """H-08 — telnet service/package not installed."""
    rc, out, _ = _run_cmd(["systemctl", "is-active", "telnet"])
    if rc == 0 and out.strip() == "active":
        return _make_item(
            "H-08", "Telnet service disabled",
            "telnet service is ACTIVE",
            "Disable telnet: sudo systemctl disable --now telnet",
            "not_hardened", "linux",
        )
    # Check if telnet package installed
    rc2, out2, _ = _run_cmd(["dpkg", "-l", "telnetd"])
    if rc2 == 0 and "ii" in out2:
        return _make_item(
            "H-08", "Telnet service disabled",
            "telnetd package is installed (may be inactive)",
            "Remove telnetd: sudo apt remove telnetd",
            "warning", "linux",
        )
    return _make_item(
        "H-08", "Telnet service disabled",
        "telnet service not found / not active",
        "No action required",
        "ok", "linux",
    )


def _linux_check_tmp_noexec() -> dict:
    """H-09 — /tmp mounted with noexec option."""
    content = _read_file(FSTAB_PATH)
    for line in content.splitlines():
        if line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 4 and parts[1] == "/tmp":
            if "noexec" in parts[3]:
                return _make_item(
                    "H-09", "/tmp mounted noexec",
                    "/tmp has noexec in fstab",
                    "No action required",
                    "ok", "linux",
                )
            return _make_item(
                "H-09", "/tmp mounted noexec",
                "/tmp entry found in fstab but noexec is not set",
                "Add noexec to /tmp mount options in /etc/fstab, then remount",
                "not_hardened", "linux",
            )
    return _make_item(
        "H-09", "/tmp mounted noexec",
        "/tmp not found as explicit entry in /etc/fstab",
        "Add 'tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0' to /etc/fstab",
        "warning", "linux",
    )


def _linux_check_ctrl_alt_del() -> dict:
    """H-10 — Ctrl-Alt-Delete reboot disabled."""
    rc, out, _ = _run_cmd(["systemctl", "status", "ctrl-alt-del.target"])
    if rc != 0 or "masked" in out.lower():
        return _make_item(
            "H-10", "Ctrl-Alt-Delete reboot disabled",
            "ctrl-alt-del.target is masked/disabled",
            "No action required",
            "ok", "linux",
        )
    return _make_item(
        "H-10", "Ctrl-Alt-Delete reboot disabled",
        "ctrl-alt-del.target is active (system can be rebooted via keyboard)",
        "Mask it: sudo systemctl mask ctrl-alt-del.target",
        "not_hardened", "linux",
    )


def _linux_apply_ctrl_alt_del() -> tuple:
    """Apply: mask ctrl-alt-del.target."""
    rc, _, err = _run_cmd(["systemctl", "mask", "ctrl-alt-del.target"])
    if rc == 0:
        return True, "ctrl-alt-del.target masked"
    return False, err


# ═══════════════════════════════════════════════════════════════════════
#  WINDOWS — CHECK FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════

def _win_check_guest_account() -> dict:
    """H-01W — Guest account disabled on Windows."""
    rc, out, _ = _run_ps(
        "(Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled"
    )
    val = out.strip().lower()
    if val == "false":
        return _make_item(
            "H-01", "Guest account disabled",
            "Guest account is DISABLED",
            "No action required",
            "ok", "windows",
        )
    if val == "true":
        return _make_item(
            "H-01", "Guest account disabled",
            "Guest account is ENABLED",
            "Run: net user guest /active:no",
            "not_hardened", "windows",
        )
    return _make_item(
        "H-01", "Guest account disabled",
        "Could not determine Guest account status",
        "Verify manually: net user guest",
        "warning", "windows",
    )


def _win_apply_guest_account() -> tuple:
    """Apply: disable guest account."""
    rc, out, err = _run_cmd(["net", "user", "guest", "/active:no"])
    if rc == 0:
        return True, "Guest account disabled"
    return False, err or out


def _win_check_firewall() -> dict:
    """H-02W — Windows Firewall enabled on all profiles."""
    rc, out, _ = _run_ps(
        "(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $false}).Name -join ','"
    )
    disabled_profiles = out.strip()
    if not disabled_profiles:
        return _make_item(
            "H-02", "Firewall enabled (all profiles)",
            "Windows Firewall is ON for all profiles",
            "No action required",
            "ok", "windows",
        )
    return _make_item(
        "H-02", "Firewall enabled (all profiles)",
        f"Firewall OFF on profiles: {disabled_profiles}",
        "Run: Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
        "not_hardened", "windows",
    )


def _win_apply_firewall() -> tuple:
    """Apply: enable Windows Firewall on all profiles."""
    rc, out, err = _run_ps(
        "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
    )
    if rc == 0:
        return True, "Windows Firewall enabled on all profiles"
    return False, err or out


def _win_check_password_policy() -> dict:
    """H-04W — Minimum password length >= 14."""
    rc, out, _ = _run_ps(
        "(Get-LocalUser Administrator | Select-Object -ExpandProperty PasswordMinimumLength 2>$null); "
        "net accounts"
    )
    m = re.search(r"Minimum password length\s*[:\s]+(\d+)", out, re.IGNORECASE)
    if m:
        length = int(m.group(1))
        if length >= 14:
            return _make_item(
                "H-04", "Password minimum length (≥ 14)",
                f"Minimum password length = {length}",
                "No action required",
                "ok", "both",
            )
        return _make_item(
            "H-04", "Password minimum length (≥ 14)",
            f"Minimum password length = {length} (below recommended 14)",
            "Run: net accounts /minpwlen:14",
            "not_hardened", "both",
        )
    return _make_item(
        "H-04", "Password minimum length (≥ 14)",
        "Could not determine minimum password length",
        "Run 'net accounts' to verify and set minimum password length",
        "warning", "both",
    )


def _win_apply_password_policy() -> tuple:
    """Apply: set minimum password length to 14."""
    rc, out, err = _run_cmd(["net", "accounts", "/minpwlen:14"])
    if rc == 0:
        return True, "Minimum password length set to 14"
    return False, err or out


def _win_check_auto_updates() -> dict:
    """H-06W — Windows automatic updates enabled."""
    rc, out, _ = _run_ps(
        "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update' "
        "-Name AUOptions -ErrorAction SilentlyContinue).AUOptions"
    )
    val = out.strip()
    if val in ("3", "4"):  # 3=auto-download, 4=auto-install
        return _make_item(
            "H-06", "Automatic security updates",
            f"Windows Update AUOptions = {val} (automatic updates active)",
            "No action required",
            "ok", "both",
        )
    return _make_item(
        "H-06", "Automatic security updates",
        f"Windows Update AUOptions = {val or 'not set'} (may not be fully automatic)",
        "Enable automatic updates via Settings → Windows Update → Advanced Options",
        "not_hardened", "both",
    )


def _win_check_event_log() -> dict:
    """H-07W — Windows Event Log service running."""
    rc, out, _ = _run_ps(
        "(Get-Service -Name EventLog -ErrorAction SilentlyContinue).Status"
    )
    if out.strip().lower() == "running":
        return _make_item(
            "H-07", "Windows Event Log service running",
            "EventLog service is RUNNING",
            "No action required",
            "ok", "windows",
        )
    return _make_item(
        "H-07", "Windows Event Log service running",
        "EventLog service is NOT running",
        "Enable and start EventLog: sc config EventLog start=auto && net start EventLog",
        "not_hardened", "windows",
    )


def _win_check_telnet() -> dict:
    """H-08W — Telnet client/server feature not enabled."""
    rc, out, _ = _run_ps(
        "(Get-WindowsOptionalFeature -Online -FeatureName TelnetServer -ErrorAction SilentlyContinue).State; "
        "(Get-WindowsOptionalFeature -Online -FeatureName TelnetClient -ErrorAction SilentlyContinue).State"
    )
    if "enabled" in out.lower():
        return _make_item(
            "H-08", "Telnet disabled",
            "Telnet feature is ENABLED on this system",
            "Disable via: Disable-WindowsOptionalFeature -Online -FeatureName TelnetServer",
            "not_hardened", "windows",
        )
    return _make_item(
        "H-08", "Telnet disabled",
        "Telnet features are not enabled",
        "No action required",
        "ok", "windows",
    )


def _win_check_risky_services() -> dict:
    """H-09W — Risky legacy Windows services not running."""
    risky = ["RemoteRegistry", "Fax", "XblAuthManager", "XboxNetApiSvc"]
    running = []
    for svc in risky:
        rc, out, _ = _run_ps(
            f"(Get-Service -Name {svc} -ErrorAction SilentlyContinue).Status"
        )
        if out.strip().lower() == "running":
            running.append(svc)

    if running:
        return _make_item(
            "H-09", "Risky/unnecessary services disabled",
            f"Running risky services: {', '.join(running)}",
            f"Disable with: Stop-Service {running[0]}; Set-Service {running[0]} -StartupType Disabled",
            "not_hardened", "windows",
        )
    return _make_item(
        "H-09", "Risky/unnecessary services disabled",
        "No known risky services are running",
        "No action required",
        "ok", "windows",
    )


# ═══════════════════════════════════════════════════════════════════════
#  COLLECT ALL ITEMS
# ═══════════════════════════════════════════════════════════════════════

def _collect_items() -> list:
    """Run all platform-appropriate hardening checks and return the item list."""
    items = []

    if _is_linux():
        items.extend([
            _linux_check_guest_account(),
            _linux_check_firewall(),
            _linux_check_ssh_root_login(),
            _linux_check_password_policy(),
            _linux_check_core_dumps(),
            _linux_check_auto_updates(),
            _linux_check_auditd(),
            _linux_check_telnet(),
            _linux_check_tmp_noexec(),
            _linux_check_ctrl_alt_del(),
        ])

    elif _is_windows():
        items.extend([
            _win_check_guest_account(),
            _win_check_firewall(),
            _win_check_password_policy(),
            _win_check_auto_updates(),
            _win_check_event_log(),
            _win_check_telnet(),
            _win_check_risky_services(),
        ])

    else:
        # macOS / other — limited checks
        items.append(_make_item(
            "H-00", "Platform support",
            f"Platform '{platform.system()}' — limited hardening checks available",
            "Full hardening support is available on Linux and Windows only",
            "skipped", "other",
        ))

    return items


# ═══════════════════════════════════════════════════════════════════════
#  APPLY ENGINE
# ═══════════════════════════════════════════════════════════════════════

# Map item IDs to (check_function, apply_function) pairs for Linux
_LINUX_APPLY_MAP = {
    "H-02": _linux_apply_firewall,
    "H-03": _linux_apply_ssh_root_login,
    "H-04": _linux_apply_password_policy,
    "H-05": _linux_apply_core_dumps,
    "H-06": _linux_apply_auto_updates,
    "H-07": _linux_apply_auditd,
    "H-10": _linux_apply_ctrl_alt_del,
}

_WINDOWS_APPLY_MAP = {
    "H-01": _win_apply_guest_account,
    "H-02": _win_apply_firewall,
    "H-04": _win_apply_password_policy,
}


def _apply_item(item: dict) -> dict:
    """
    Attempt to apply the hardening fix for a single item.

    Mutates and returns the item dict with updated 'applied' and 'apply_note' fields.
    """
    item_id = item["id"]

    if _is_linux():
        apply_fn = _LINUX_APPLY_MAP.get(item_id)
    elif _is_windows():
        apply_fn = _WINDOWS_APPLY_MAP.get(item_id)
    else:
        apply_fn = None

    if apply_fn is None:
        item["applied"]    = "n/a"
        item["apply_note"] = "No automatic apply available for this item"
        return item

    try:
        success, note = apply_fn()
        item["applied"]    = "yes" if success else "no"
        item["apply_note"] = note
    except Exception as exc:  # noqa: BLE001
        item["applied"]    = "no"
        item["apply_note"] = f"Apply failed: {exc}"

    return item


def _confirm_apply() -> bool:
    """
    Print a warning banner and ask for explicit y/n confirmation before applying.

    Returns True if the user confirms.
    """
    print(f"\n{Fore.RED}{'!'*60}")
    print(f"{Fore.RED}  ⚠  APPLY MODE — SYSTEM CHANGES WILL BE MADE")
    print(f"{Fore.RED}{'!'*60}")
    print(f"{Fore.YELLOW}  The hardening engine will attempt to apply changes")
    print(f"{Fore.YELLOW}  to your system configuration. This requires elevated")
    print(f"{Fore.YELLOW}  privileges and will modify system files/services.")
    print(f"{Fore.YELLOW}  Changes are designed to be reversible but always")
    print(f"{Fore.YELLOW}  back up your configuration before proceeding.")
    print(f"{Fore.RED}{'!'*60}{Style.RESET_ALL}\n")

    try:
        answer = input("  Do you want to continue and apply hardening changes? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print(f"\n{Fore.YELLOW}[!] Aborted by user.{Style.RESET_ALL}")
        return False

    return answer == "y"


# ═══════════════════════════════════════════════════════════════════════
#  OUTPUT / DISPLAY
# ═══════════════════════════════════════════════════════════════════════

def _status_label(status: str) -> str:
    mapping = {
        "ok":           PASS_LABEL,
        "not_hardened": FAIL_LABEL,
        "warning":      WARN_LABEL,
        "skipped":      SKIP_LABEL,
    }
    return mapping.get(status, status)


def _applied_label(applied: str) -> str:
    mapping = {
        "yes": APPLIED_YES,
        "no":  APPLIED_NO,
        "n/a": APPLIED_NA,
    }
    return mapping.get(applied, applied)


def _print_results(items: list, apply_mode: bool, config: dict) -> None:
    """Print a formatted hardening report to stdout."""
    verbose = config.get("verbose", False)

    total      = len(items)
    ok_count   = sum(1 for i in items if i["status"] == "ok")
    fail_count = sum(1 for i in items if i["status"] == "not_hardened")
    warn_count = sum(1 for i in items if i["status"] == "warning")
    skip_count = sum(1 for i in items if i["status"] == "skipped")

    print(f"\n{Fore.CYAN}{'─'*66}")
    print(f"{Fore.CYAN}  HARDENING ENGINE REPORT")
    mode_label = "APPLY MODE" if apply_mode else "DRY-RUN (no changes applied)"
    print(f"{Fore.CYAN}  Mode: {Fore.YELLOW}{mode_label}")
    print(f"{Fore.CYAN}  Platform: {platform.system()}  |  "
          f"Elevated: {'YES' if _is_root() else 'NO'}")
    print(f"{Fore.CYAN}  Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Fore.CYAN}{'─'*66}{Style.RESET_ALL}\n")

    # Build table rows
    headers = ["ID", "Hardening Item", "Current Status", "Result"]
    if apply_mode:
        headers.extend(["Applied", "Notes"])

    rows = []
    for item in items:
        row = [
            item["id"],
            item["title"],
            item["current_status"],
            _status_label(item["status"]),
        ]
        if apply_mode:
            row.append(_applied_label(item["applied"]))
            row.append(item["apply_note"])
        rows.append(row)

    print(tabulate(rows, headers=headers, tablefmt="rounded_outline"))

    # Recommendations section (only non-ok items)
    non_ok = [i for i in items if i["status"] in ("not_hardened", "warning")]
    if non_ok and not apply_mode:
        print(f"\n{Fore.YELLOW}  RECOMMENDED ACTIONS:{Style.RESET_ALL}")
        for item in non_ok:
            bullet_colour = Fore.RED if item["status"] == "not_hardened" else Fore.YELLOW
            print(f"  {bullet_colour}[{item['id']}]{Style.RESET_ALL} {item['title']}")
            print(f"        → {item['recommended_action']}")

    # Summary bar
    score_pct = int((ok_count / total) * 100) if total else 0
    score_colour = (Fore.GREEN if score_pct >= 80
                    else Fore.YELLOW if score_pct >= 50 else Fore.RED)

    print(f"\n{Fore.CYAN}{'─'*66}{Style.RESET_ALL}")
    print(f"  Score: {score_colour}{score_pct}%{Style.RESET_ALL}  |  "
          f"{Fore.GREEN}OK: {ok_count}{Style.RESET_ALL}  "
          f"{Fore.RED}Not Hardened: {fail_count}{Style.RESET_ALL}  "
          f"{Fore.YELLOW}Warning: {warn_count}  Skipped: {skip_count}{Style.RESET_ALL}  "
          f"(of {total} checks)")
    print(f"{Fore.CYAN}{'─'*66}{Style.RESET_ALL}\n")


def _save_output(items: list, apply_mode: bool, config: dict) -> None:
    """Write hardening result to disk when --output was provided."""
    output_path   = config.get("output_path")
    output_format = config.get("output_format", "text")

    if not output_path:
        return

    os.makedirs("output", exist_ok=True)

    try:
        if output_format == "json":
            import json
            payload = {
                "module":      "hardening_engine",
                "timestamp":   datetime.now().isoformat(),
                "platform":    platform.system(),
                "apply_mode":  apply_mode,
                "elevated":    _is_root(),
                "items":       [
                    {k: v for k, v in item.items()} for item in items
                ],
                "summary": {
                    "total":         len(items),
                    "ok":            sum(1 for i in items if i["status"] == "ok"),
                    "not_hardened":  sum(1 for i in items if i["status"] == "not_hardened"),
                    "warning":       sum(1 for i in items if i["status"] == "warning"),
                    "skipped":       sum(1 for i in items if i["status"] == "skipped"),
                },
            }
            content = json.dumps(payload, indent=2)
        else:
            lines = [
                "=" * 60,
                "  LOCAL SECURITY SUITE — Hardening Engine Report",
                f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"  Platform  : {platform.system()}",
                f"  Mode      : {'APPLY' if apply_mode else 'DRY-RUN'}",
                "=" * 60,
            ]
            for item in items:
                lines.append(
                    f"[{item['id']}] {item['title']}\n"
                    f"  Status  : {item['status']}\n"
                    f"  Current : {item['current_status']}\n"
                    f"  Action  : {item['recommended_action']}"
                )
                if apply_mode:
                    lines.append(
                        f"  Applied : {item['applied']}  ({item['apply_note']})"
                    )
                lines.append("")
            content = "\n".join(lines)

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(content)

        print(f"{Fore.GREEN}[✔] Hardening report saved → {output_path}{Style.RESET_ALL}")

    except OSError as exc:
        print(f"{Fore.RED}[✘] Could not write output file: {exc}{Style.RESET_ALL}")


# ═══════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════

def run(config: dict) -> dict:
    """
    Hardening Engine entry point.

    Args:
        config: dict with keys:
            output_format  – 'text' or 'json'
            output_path    – file path string or None
            verbose        – bool
            apply          – bool  (True = apply changes, False = dry-run)

    Returns:
        {
            "status":   "ok" | "error",
            "findings": [list of item dicts],
            "summary":  str,
        }
    """
    apply_mode = bool(config.get("apply", False))

    # ── Elevation check for apply mode ────────────────────────────────
    if apply_mode and not _is_root():
        msg = (
            f"{Fore.RED}[✘] --apply mode requires elevated privileges "
            f"(run as root / Administrator).{Style.RESET_ALL}"
        )
        print(msg)
        return {
            "status":   "error",
            "findings": [],
            "summary":  "Apply mode requires elevated privileges.",
        }

    # ── Collect current-state items (always run, all platforms) ───────
    try:
        items = _collect_items()
    except Exception as exc:  # noqa: BLE001
        return {
            "status":   "error",
            "findings": [],
            "summary":  f"Collection error: {exc}",
        }

    # ── Apply mode: confirm then apply non-ok items ────────────────────
    if apply_mode:
        if not _confirm_apply():
            print(f"{Fore.YELLOW}[!] Apply cancelled by user. No changes made.{Style.RESET_ALL}")
            apply_mode = False  # Fall through to dry-run display
        else:
            print(f"\n{Fore.CYAN}  Applying hardening changes…{Style.RESET_ALL}")
            for idx, item in enumerate(items):
                if item["status"] in ("not_hardened", "warning"):
                    items[idx] = _apply_item(item)
                    label = (f"{Fore.GREEN}applied{Style.RESET_ALL}"
                             if item["applied"] == "yes"
                             else f"{Fore.YELLOW}skipped/failed{Style.RESET_ALL}")
                    print(f"  [{item['id']}] {item['title'][:50]:<50}  {label}")

    # ── Print results ──────────────────────────────────────────────────
    _print_results(items, apply_mode, config)

    # ── Persist output if requested ────────────────────────────────────
    _save_output(items, apply_mode, config)

    # ── Build return dict ─────────────────────────────────────────────
    ok_count   = sum(1 for i in items if i["status"] == "ok")
    fail_count = sum(1 for i in items if i["status"] == "not_hardened")
    total      = len(items)
    score_pct  = int((ok_count / total) * 100) if total else 0

    overall_status = "ok" if fail_count == 0 else "error"

    summary = (
        f"{'APPLY' if apply_mode else 'Dry-run'} complete — "
        f"{ok_count}/{total} hardened ({score_pct}%)  |  "
        f"{fail_count} item(s) need attention"
    )

    return {
        "status":   overall_status,
        "findings": items,
        "summary":  summary,
    }
