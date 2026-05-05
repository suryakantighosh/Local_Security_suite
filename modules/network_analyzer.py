"""
modules/network_analyzer.py
============================
Network Analyzer for Local Security Suite.

Enumerates all active network connections and open ports on the local host
using psutil.  Flags connections to known suspicious ports and non-local
remote addresses.

Entry point:
    run(config: dict) -> dict

What it reports:
    1. All open/listening ports with process name + PID
    2. All active TCP/UDP connections with remote address, state, owning process
    3. Flags connections to risky ports or non-RFC-1918 remote addresses
    4. Summary: total open ports, total active connections, suspicious count

config keys used:
    output_format (str)  : "text" | "json"
    output_path   (str)  : Optional file path for saving output.
    verbose       (bool) : Print per-connection detail.
"""

import os
import platform
import socket

from colorama import Fore, Style
from tabulate import tabulate

try:
    import psutil
    _PSUTIL_OK = True
except ImportError:
    _PSUTIL_OK = False

# ─────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────

# Ports that warrant a flag regardless of direction
SUSPICIOUS_PORTS = {
    21:    "FTP (plain-text)",
    22:    "SSH",
    23:    "Telnet (plain-text)",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP (plain-text)",
    110:   "POP3",
    135:   "MS-RPC",
    139:   "NetBIOS",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    512:   "rexec",
    513:   "rlogin",
    514:   "rsh / Syslog",
    1433:  "MSSQL",
    1521:  "Oracle DB",
    2375:  "Docker (unencrypted)",
    2376:  "Docker TLS",
    3306:  "MySQL",
    3389:  "RDP",
    4444:  "Metasploit default",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis (no-auth default)",
    6666:  "IRC / C2 common",
    6667:  "IRC",
    8080:  "HTTP-alt",
    8443:  "HTTPS-alt",
    9200:  "Elasticsearch",
    27017: "MongoDB (no-auth default)",
    31337: "Back Orifice / elite",
    49152: "Ephemeral range start",
}

# Ports that are HIGH severity when found open/connected
HIGH_RISK_PORTS = {
    23, 512, 513, 514,
    4444, 6666, 6667, 31337,
    2375,         # Docker unencrypted
    6379,         # Redis unauthenticated
    27017,        # MongoDB unauthenticated
    9200,         # Elasticsearch unauthenticated
}

# RFC 1918 private + loopback prefixes — connections to these are normal
_PRIVATE_PREFIXES = (
    "127.", "10.", "192.168.",
    "::1", "::ffff:127.",
    "0.0.0.0",
)

# psutil status values that represent an actively established session
_ACTIVE_STATES = {"ESTABLISHED", "CLOSE_WAIT", "FIN_WAIT1", "FIN_WAIT2"}

# Threshold above which a listening port number is flagged as unusual
_HIGH_PORT_THRESHOLD = 49000


# ─────────────────────────────────────────────
#  Internal helpers — platform detection
# ─────────────────────────────────────────────

def _is_linux() -> bool:
    return platform.system() == "Linux"


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _is_darwin() -> bool:
    return platform.system() == "Darwin"


# ─────────────────────────────────────────────
#  Internal helpers — process info
# ─────────────────────────────────────────────

def _pid_to_name(pid: int) -> str:
    """Return the process name for *pid*, or 'unknown' if not accessible."""
    if pid is None or pid == 0:
        return "system/kernel"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return f"PID:{pid}"


def _addr_str(addr) -> str:
    """Format a psutil _common.addr as 'host:port', or '-' if None."""
    if addr is None:
        return "-"
    host = addr.ip if addr.ip else "*"
    return f"{host}:{addr.port}"


def _is_external(ip: str) -> bool:
    """Return True when *ip* is a non-private, non-loopback address."""
    if not ip:
        return False
    for prefix in _PRIVATE_PREFIXES:
        if ip.startswith(prefix):
            return False
    return True


# ─────────────────────────────────────────────
#  Internal helpers — collection
# ─────────────────────────────────────────────

def _collect_connections() -> tuple[list, list, list]:
    """
    Enumerate all network connections and open sockets via psutil.

    Returns:
        listening     : list of dicts for LISTEN-state sockets (open ports)
        active        : list of dicts for established / active connections
        suspicious    : list of dicts flagged as noteworthy
    """
    listening  = []
    active     = []
    suspicious = []

    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        # On macOS/Windows without elevation psutil may return a partial list
        # Retry with kind="tcp" as a fallback
        try:
            conns = psutil.net_connections(kind="tcp")
        except Exception:  # noqa: BLE001
            conns = []

    for conn in conns:
        laddr  = conn.laddr
        raddr  = conn.raddr
        status = conn.status or "NONE"
        pid    = conn.pid
        pname  = _pid_to_name(pid)
        lport  = laddr.port if laddr else None
        rip    = raddr.ip   if raddr else ""
        rport  = raddr.port if raddr else None

        severity = "INFO"

        # ── Classify the connection ───────────────────────────────────────────
        is_susp = False

        # Flagged by port
        if lport in SUSPICIOUS_PORTS or rport in SUSPICIOUS_PORTS:
            is_susp  = True
            port_key = lport if lport in SUSPICIOUS_PORTS else rport
            severity = "HIGH" if port_key in HIGH_RISK_PORTS else "MEDIUM"

        # Unusual high listening port
        if status == "LISTEN" and lport and lport > _HIGH_PORT_THRESHOLD:
            is_susp  = True
            severity = max(severity, "LOW")   # doesn't downgrade an existing HIGH

        # External remote address on an active session
        if status in _ACTIVE_STATES and _is_external(rip):
            is_susp = True
            severity = max(
                severity,
                "HIGH" if (rport in HIGH_RISK_PORTS) else "MEDIUM",
            )

        record = {
            "local":    _addr_str(laddr),
            "remote":   _addr_str(raddr) if raddr else "-",
            "status":   status,
            "pid":      pid or "-",
            "process":  pname,
            "severity": severity,
            "note":     (
                SUSPICIOUS_PORTS.get(lport, "")
                or SUSPICIOUS_PORTS.get(rport, "")
                or ("External remote" if _is_external(rip) else "")
                or (f"High port {lport}" if lport and lport > _HIGH_PORT_THRESHOLD else "")
            ),
        }

        if status == "LISTEN":
            listening.append(record)
        else:
            active.append(record)

        if is_susp:
            suspicious.append(record)

    # Sort deterministically
    listening.sort(key=lambda x: x["local"])
    active.sort(key=lambda x: (x["status"], x["local"]))
    suspicious.sort(key=lambda x: x["severity"], reverse=True)

    return listening, active, suspicious


def _collect_interface_stats() -> list:
    """
    Return a compact list of network interface summaries (bytes in/out, errors).
    """
    stats = []
    try:
        io = psutil.net_io_counters(pernic=True)
        for iface, counters in sorted(io.items()):
            stats.append({
                "interface":    iface,
                "bytes_sent":   counters.bytes_sent,
                "bytes_recv":   counters.bytes_recv,
                "packets_sent": counters.packets_sent,
                "packets_recv": counters.packets_recv,
                "errin":        counters.errin,
                "errout":       counters.errout,
                "dropin":       counters.dropin,
                "dropout":      counters.dropout,
            })
    except Exception:  # noqa: BLE001
        pass
    return stats


# ─────────────────────────────────────────────
#  Output / Display
# ─────────────────────────────────────────────

_SEV_COLOUR = {
    "HIGH":   Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW":    Fore.YELLOW,
    "INFO":   Fore.WHITE,
}


def _colour_sev(sev: str) -> str:
    colour = _SEV_COLOUR.get(sev, "")
    return f"{colour}{sev}{Style.RESET_ALL}"


def _print_results(
    listening: list,
    active: list,
    suspicious: list,
    ifaces: list,
    config: dict,
) -> None:
    """Print a formatted report of all network connections to stdout."""
    verbose = config.get("verbose", False)

    print()
    print(f"{Fore.CYAN}{'─'*54}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  NETWORK ANALYZER — Scan Report{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─'*54}{Style.RESET_ALL}")
    print(f"  Platform   : {platform.system()} {platform.release()}")
    print(f"  Hostname   : {socket.gethostname()}")
    print()

    # ── Listening / open ports ────────────────────────────────────────────────
    print(f"{Fore.CYAN}  OPEN / LISTENING PORTS ({len(listening)}){Style.RESET_ALL}")
    if listening:
        rows = [
            [
                e["local"],
                e["process"],
                e["pid"],
                _colour_sev(e["severity"]) if e["severity"] != "INFO" else e["severity"],
                e["note"] or "-",
            ]
            for e in listening
        ]
        print(tabulate(
            rows,
            headers=["Local Address", "Process", "PID", "Severity", "Note"],
            tablefmt="rounded_outline",
        ))
    else:
        print(f"  {Fore.YELLOW}  (no listening sockets found — may need elevated privileges){Style.RESET_ALL}")
    print()

    # ── Active connections ────────────────────────────────────────────────────
    if verbose or active:
        print(f"{Fore.CYAN}  ACTIVE CONNECTIONS ({len(active)}){Style.RESET_ALL}")
        if active:
            rows = [
                [
                    e["local"],
                    e["remote"],
                    e["status"],
                    e["process"],
                    e["pid"],
                    _colour_sev(e["severity"]) if e["severity"] != "INFO" else e["severity"],
                ]
                for e in (active if verbose else active[:20])
            ]
            print(tabulate(
                rows,
                headers=["Local", "Remote", "State", "Process", "PID", "Severity"],
                tablefmt="rounded_outline",
            ))
            if not verbose and len(active) > 20:
                print(
                    f"  {Fore.YELLOW}  … {len(active)-20} more connections "
                    f"(use --verbose to see all){Style.RESET_ALL}"
                )
        print()

    # ── Suspicious connections ────────────────────────────────────────────────
    if suspicious:
        print(f"{Fore.RED}  [!] SUSPICIOUS / FLAGGED ({len(suspicious)}){Style.RESET_ALL}")
        rows = [
            [
                e["local"],
                e["remote"],
                e["status"],
                e["process"],
                _colour_sev(e["severity"]),
                e["note"] or "-",
            ]
            for e in suspicious
        ]
        print(tabulate(
            rows,
            headers=["Local", "Remote", "State", "Process", "Severity", "Reason"],
            tablefmt="rounded_outline",
        ))
        print()

    # ── Interface stats (verbose only) ────────────────────────────────────────
    if verbose and ifaces:
        print(f"{Fore.CYAN}  NETWORK INTERFACES{Style.RESET_ALL}")
        rows = [
            [
                i["interface"],
                f"{i['bytes_sent']:,}",
                f"{i['bytes_recv']:,}",
                i["errin"] + i["errout"],
                i["dropin"] + i["dropout"],
            ]
            for i in ifaces
        ]
        print(tabulate(
            rows,
            headers=["Interface", "Bytes Sent", "Bytes Recv", "Errors", "Drops"],
            tablefmt="rounded_outline",
        ))
        print()

    # ── Summary ───────────────────────────────────────────────────────────────
    high_count = sum(1 for s in suspicious if s["severity"] == "HIGH")
    med_count  = sum(1 for s in suspicious if s["severity"] == "MEDIUM")

    overall = (
        Fore.RED    if high_count > 0 else
        Fore.YELLOW if med_count  > 0 else
        Fore.GREEN
    )
    print(
        f"  Summary  :  {overall}Open ports: {len(listening)}{Style.RESET_ALL}  |  "
        f"Active connections: {len(active)}  |  "
        f"{Fore.RED if high_count else Fore.YELLOW if med_count else Fore.GREEN}"
        f"Suspicious: {len(suspicious)} "
        f"(High: {high_count}  Med: {med_count}){Style.RESET_ALL}"
    )
    print()

    if config.get("verbose") and suspicious:
        print(f"\n{'─'*54}\n  RECOMMENDATIONS\n{'─'*54}")
        for entry in suspicious:
            if entry["severity"] in ("HIGH", "MEDIUM"):
                note = entry["note"] or "flagged port/address"
                print(
                    f"  [{entry['severity']}]  {entry['local']}  →  {entry['remote']}\n"
                    f"      Process: {entry['process']}  ({note})\n"
                    f"      Action : Investigate or terminate this connection / service.\n"
                )


def _save_output(result: dict, config: dict) -> None:
    """Write module result to disk when --output was provided."""
    output_path = config.get("output_path")
    if not output_path:
        return

    fmt = config.get("output_format", "text").lower()
    try:
        os.makedirs(
            os.path.dirname(os.path.abspath(output_path)) or ".",
            exist_ok=True,
        )
        if fmt == "json":
            content = __import__("json").dumps(result, indent=2, default=str)
        else:
            lines = [
                "=" * 60,
                "  NETWORK ANALYZER REPORT",
                f"  Status   : {result['status']}",
                f"  Summary  : {result['summary']}",
                "=" * 60,
            ]
            findings = result.get("findings", {})
            for section in ("listening", "suspicious"):
                items = findings.get(section, [])
                lines.append(f"\n[{section.upper()}] ({len(items)} entries)")
                for item in items:
                    lines.append(
                        f"  {item.get('local','-'):<26} "
                        f"{item.get('remote','-'):<26} "
                        f"{item.get('process','-')}"
                    )
            content = "\n".join(lines)

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"{Fore.GREEN}[✔] Output saved → {output_path}{Style.RESET_ALL}")
    except OSError as exc:
        print(f"{Fore.RED}[✘] Could not write output file: {exc}{Style.RESET_ALL}")


# ─────────────────────────────────────────────
#  Module Entry Point
# ─────────────────────────────────────────────

def run(config: dict) -> dict:
    """
    Enumerate all open ports and active network connections.

    Args:
        config: Shared config dict with keys:
                output_format, output_path, verbose, target (unused here).

    Returns:
        {
            "status":   "ok" | "error",
            "findings": {
                "listening":   [...],
                "active":      [...],
                "suspicious":  [...],
                "interfaces":  [...],
                "open_port_count":    int,
                "active_conn_count":  int,
                "suspicious_count":   int,
            },
            "summary": "...",
        }
    """
    if not _PSUTIL_OK:
        msg = "psutil is not installed. Run: pip install psutil"
        print(f"{Fore.RED}[✘] {msg}{Style.RESET_ALL}")
        return {"status": "error", "findings": {}, "summary": msg}

    print(
        f"{Fore.CYAN}[*] Platform : {platform.system()} "
        f"{platform.release()}{Style.RESET_ALL}"
    )
    print(f"{Fore.CYAN}[*] Enumerating network connections …{Style.RESET_ALL}\n")

    try:
        listening, active, suspicious = _collect_connections()
    except Exception as exc:  # noqa: BLE001
        msg = f"Failed to enumerate connections: {exc}"
        print(f"{Fore.RED}[✘] {msg}{Style.RESET_ALL}")
        return {"status": "error", "findings": {}, "summary": msg}

    try:
        ifaces = _collect_interface_stats()
    except Exception:  # noqa: BLE001
        ifaces = []

    _print_results(listening, active, suspicious, ifaces, config)

    high_count = sum(1 for s in suspicious if s["severity"] == "HIGH")
    med_count  = sum(1 for s in suspicious if s["severity"] == "MEDIUM")

    summary = (
        f"Open ports: {len(listening)} | "
        f"Active connections: {len(active)} | "
        f"Suspicious: {len(suspicious)} "
        f"(High: {high_count}, Medium: {med_count})"
    )

    # Strip ANSI colour codes from severity field for JSON/file serialisation
    def _clean(records: list) -> list:
        cleaned = []
        for r in records:
            c = dict(r)
            # severity is plain text in the source dict — safe to keep
            cleaned.append(c)
        return cleaned

    result = {
        "status":   "ok",
        "findings": {
            "listening":          _clean(listening),
            "active":             _clean(active),
            "suspicious":         _clean(suspicious),
            "interfaces":         ifaces,
            "open_port_count":    len(listening),
            "active_conn_count":  len(active),
            "suspicious_count":   len(suspicious),
        },
        "summary": summary,
    }

    _save_output(result, config)
    return result
