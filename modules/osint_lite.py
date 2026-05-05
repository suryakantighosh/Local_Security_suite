"""
osint_lite.py — Local Security Suite
---------------------------------------
Gathers basic open-source intelligence on a target domain or IP address.
Performs DNS enumeration, WHOIS lookup, HTTP header analysis, reverse DNS,
and basic port probing — fully offline-compatible for DNS/port checks,
network-required for WHOIS and HTTP headers.

Flag   : --osint
Entry  : run(config: dict) -> dict
Requires --target <domain|ip>
"""

import ipaddress
import json as _json
import os
import platform
import re
import socket
import subprocess
import sys
from datetime import datetime
from typing import Any

from colorama import Fore, Style
from tabulate import tabulate

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

try:
    import whois as _whois_lib
    _WHOIS_AVAILABLE = True
except ImportError:
    _WHOIS_AVAILABLE = False

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# Ports to probe on the target
_PROBE_PORTS: list[tuple[int, str]] = [
    (21,  "FTP"),
    (22,  "SSH"),
    (25,  "SMTP"),
    (53,  "DNS"),
    (80,  "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (465, "SMTPS"),
    (587, "SMTP Submission"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (3306,"MySQL"),
    (5432,"PostgreSQL"),
    (6379,"Redis"),
    (8080,"HTTP-Alt"),
    (8443,"HTTPS-Alt"),
    (27017,"MongoDB"),
]

# HTTP security headers to check (header → description if missing)
_SECURITY_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "HSTS missing — site vulnerable to protocol downgrade",
    "X-Frame-Options":           "Clickjacking protection missing",
    "X-Content-Type-Options":    "MIME sniffing protection missing",
    "Content-Security-Policy":   "CSP missing — XSS protection not enforced",
    "X-XSS-Protection":          "Legacy XSS filter header missing",
    "Referrer-Policy":           "Referrer policy not set",
    "Permissions-Policy":        "Permissions policy not set",
}

# Headers that reveal server info
_INFO_HEADERS: list[str] = [
    "Server", "X-Powered-By", "X-AspNet-Version",
    "X-Generator", "X-Drupal-Cache", "X-WordPress-Version",
]

_SOCKET_TIMEOUT = 3.0   # seconds per port probe
_HTTP_TIMEOUT   = 8     # seconds for HTTP requests


# ─────────────────────────────────────────────────────────────────────────────
#  TARGET VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

def _is_ip(target: str) -> bool:
    """Return True if target is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _validate_target(target: str) -> str:
    """Strip protocol prefix and trailing slashes; raise ValueError if empty."""
    if not target:
        raise ValueError("--target is required for --osint. Example: --target google.com")
    target = re.sub(r"^https?://", "", target, flags=re.I)
    target = target.split("/")[0].strip()
    if not target:
        raise ValueError("Invalid target — provide a domain name or IP address")
    return target


# ─────────────────────────────────────────────────────────────────────────────
#  RESULT FACTORY
# ─────────────────────────────────────────────────────────────────────────────

def _section(title: str, data: Any, status: str = "ok") -> dict:
    """Return a normalised OSINT section dict."""
    return {
        "section":    title,
        "status":     status,
        "data":       data,
        "timestamp":  datetime.now().isoformat(timespec="seconds"),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 1 — DNS RECORDS
# ─────────────────────────────────────────────────────────────────────────────

def _dns_lookup(target: str) -> dict:
    """Query A, MX, NS, TXT, AAAA, CNAME records for target domain."""
    if _is_ip(target):
        return _section("DNS Records", {"note": "Target is an IP — DNS forward lookup skipped"})

    if not _DNS_AVAILABLE:
        return _section("DNS Records", {"error": "dnspython not installed — run: pip install dnspython"},
                        status="error")

    records: dict[str, list[str]] = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(target, rtype, lifetime=5)
            records[rtype] = [str(r) for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass  # Not present — not an error
        except dns.exception.Timeout:
            records[rtype] = ["(timeout)"]
        except Exception:
            pass

    if not records:
        return _section("DNS Records", {"note": f"No DNS records found for {target}"}, status="warn")

    return _section("DNS Records", records)


# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 2 — REVERSE DNS
# ─────────────────────────────────────────────────────────────────────────────

def _reverse_dns(target: str) -> dict:
    """Perform reverse DNS lookup."""
    results: dict[str, Any] = {}

    # If domain — resolve to IPs first, then reverse each
    ips_to_reverse: list[str] = []

    if _is_ip(target):
        ips_to_reverse = [target]
    else:
        try:
            answers = socket.getaddrinfo(target, None)
            ips_to_reverse = list({a[4][0] for a in answers})[:5]
        except socket.gaierror as exc:
            return _section("Reverse DNS", {"error": f"Could not resolve {target}: {exc}"}, status="error")

    results["resolved_ips"] = ips_to_reverse
    ptr_records: dict[str, str] = {}

    for ip in ips_to_reverse:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            ptr_records[ip] = hostname
        except (socket.herror, socket.gaierror, OSError):
            ptr_records[ip] = "(no PTR record)"

    results["ptr_records"] = ptr_records
    return _section("Reverse DNS", results)


# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 3 — WHOIS
# ─────────────────────────────────────────────────────────────────────────────

def _whois_lookup(target: str) -> dict:
    """Perform WHOIS lookup using python-whois."""
    if not _WHOIS_AVAILABLE:
        return _section("WHOIS", {"error": "python-whois not installed — run: pip install python-whois"},
                        status="error")

    try:
        w = _whois_lib.whois(target)
        # Extract key fields only — full whois can be huge
        data: dict[str, Any] = {}
        fields = [
            "domain_name", "registrar", "creation_date", "expiration_date",
            "updated_date", "name_servers", "status", "emails",
            "dnssec", "country", "org",
        ]
        for field in fields:
            val = getattr(w, field, None)
            if val is None:
                continue
            if isinstance(val, list):
                # Deduplicate and stringify
                seen: set[str] = set()
                clean: list[str] = []
                for v in val:
                    s = str(v).strip()
                    if s not in seen:
                        seen.add(s)
                        clean.append(s)
                data[field] = clean if len(clean) > 1 else (clean[0] if clean else None)
            else:
                data[field] = str(val).strip()

        if not data:
            return _section("WHOIS", {"note": "No WHOIS data returned"}, status="warn")

        return _section("WHOIS", data)

    except Exception as exc:
        return _section("WHOIS", {"error": f"WHOIS lookup failed: {exc}"}, status="error")


# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 4 — HTTP HEADERS
# ─────────────────────────────────────────────────────────────────────────────

def _http_headers(target: str) -> dict:
    """Fetch HTTP/HTTPS response headers and analyse security posture."""
    if not _REQUESTS_AVAILABLE:
        return _section("HTTP Headers",
                        {"error": "requests not installed — run: pip install requests"},
                        status="error")

    results: dict[str, Any] = {}
    session = _requests.Session()
    session.max_redirects = 5

    headers_got: dict[str, str] = {}
    url_used = ""

    # Try HTTPS first, fall back to HTTP
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        try:
            resp = session.head(
                url,
                timeout=_HTTP_TIMEOUT,
                allow_redirects=True,
                verify=True,
                headers={"User-Agent": "LocalSecuritySuite/1.0 (security audit)"},
            )
            headers_got = dict(resp.headers)
            url_used    = resp.url
            results["status_code"]    = resp.status_code
            results["final_url"]      = url_used
            results["redirect_count"] = len(resp.history)
            break
        except _requests.exceptions.SSLError as exc:
            results["ssl_error"] = str(exc)[:120]
            # Try without verify
            try:
                resp = session.head(
                    url, timeout=_HTTP_TIMEOUT, allow_redirects=True,
                    verify=False,
                    headers={"User-Agent": "LocalSecuritySuite/1.0 (security audit)"},
                )
                headers_got = dict(resp.headers)
                url_used    = resp.url
                results["status_code"] = resp.status_code
                results["final_url"]   = url_used
                results["ssl_warning"] = "SSL certificate verification failed"
                break
            except Exception:
                continue
        except (_requests.exceptions.ConnectionError,
                _requests.exceptions.Timeout, Exception):
            continue

    if not headers_got:
        return _section("HTTP Headers",
                        {"error": f"Could not connect to {target} on HTTP or HTTPS"},
                        status="error")

    # Info-revealing headers
    info: dict[str, str] = {}
    for h in _INFO_HEADERS:
        val = headers_got.get(h) or headers_got.get(h.lower())
        if val:
            info[h] = val
    if info:
        results["server_info_headers"] = info

    # Security header analysis
    missing: list[str] = []
    present: list[str] = []
    for header, msg in _SECURITY_HEADERS.items():
        found = headers_got.get(header) or headers_got.get(header.lower())
        if found:
            present.append(f"{header}: {found[:80]}")
        else:
            missing.append(f"MISSING — {msg}")

    results["security_headers_present"] = present
    results["security_headers_missing"]  = missing

    # All headers (trimmed)
    results["all_headers"] = {
        k: v[:120] for k, v in headers_got.items()
    }

    return _section("HTTP Headers", results)


# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 5 — PORT PROBE
# ─────────────────────────────────────────────────────────────────────────────

def _port_probe(target: str) -> dict:
    """Probe common ports on the target via TCP connect."""
    # Resolve domain to IP first
    resolve_ip = target
    if not _is_ip(target):
        try:
            resolve_ip = socket.gethostbyname(target)
        except socket.gaierror as exc:
            return _section("Port Probe",
                            {"error": f"Could not resolve {target}: {exc}"},
                            status="error")

    open_ports:   list[dict] = []
    closed_ports: list[int]  = []

    for port, service in _PROBE_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(_SOCKET_TIMEOUT)
                result = s.connect_ex((resolve_ip, port))
                if result == 0:
                    open_ports.append({"port": port, "service": service, "state": "open"})
                else:
                    closed_ports.append(port)
        except (socket.timeout, OSError):
            closed_ports.append(port)

    return _section("Port Probe", {
        "target_ip":    resolve_ip,
        "open_ports":   open_ports,
        "closed_count": len(closed_ports),
        "probed_total": len(_PROBE_PORTS),
    })


# ─────────────────────────────────────────────────────────────────────────────
#  COLLECT ALL SECTIONS
# ─────────────────────────────────────────────────────────────────────────────

def _collect_osint(target: str) -> list[dict]:
    """Run all OSINT checks and return list of section results."""
    sections: list[dict] = []

    checks = [
        lambda: _dns_lookup(target),
        lambda: _reverse_dns(target),
        lambda: _whois_lookup(target),
        lambda: _http_headers(target),
        lambda: _port_probe(target),
    ]

    for check_fn in checks:
        try:
            sections.append(check_fn())
        except Exception as exc:
            sections.append(_section("Unknown", {"error": str(exc)}, status="error"))

    return sections


# ─────────────────────────────────────────────────────────────────────────────
#  OUTPUT / PRINT
# ─────────────────────────────────────────────────────────────────────────────

def _print_section_dns(data: dict) -> None:
    if "error" in data or "note" in data:
        msg = data.get("error") or data.get("note")
        print(f"    {Fore.YELLOW}{msg}{Style.RESET_ALL}")
        return
    rows = []
    for rtype, vals in data.items():
        if isinstance(vals, list):
            for v in vals:
                rows.append([rtype, v[:80]])
        else:
            rows.append([rtype, str(vals)[:80]])
    if rows:
        print(tabulate(rows, headers=["Type", "Value"], tablefmt="simple"))


def _print_section_reverse(data: dict) -> None:
    if "error" in data:
        print(f"    {Fore.YELLOW}{data['error']}{Style.RESET_ALL}")
        return
    ips = data.get("resolved_ips", [])
    ptrs = data.get("ptr_records", {})
    if ips:
        print(f"    Resolved IPs : {', '.join(ips)}")
    for ip, ptr in ptrs.items():
        print(f"    PTR {ip:>15} → {ptr}")


def _print_section_whois(data: dict) -> None:
    if "error" in data or "note" in data:
        msg = data.get("error") or data.get("note")
        print(f"    {Fore.YELLOW}{msg}{Style.RESET_ALL}")
        return
    rows = []
    for field, val in data.items():
        if isinstance(val, list):
            rows.append([field, "\n".join(str(v)[:60] for v in val[:3])])
        else:
            rows.append([field, str(val)[:80]])
    if rows:
        print(tabulate(rows, headers=["Field", "Value"], tablefmt="simple"))


def _print_section_http(data: dict, verbose: bool = False) -> None:
    if "error" in data:
        print(f"    {Fore.YELLOW}{data['error']}{Style.RESET_ALL}")
        return

    sc = data.get("status_code", "?")
    fu = data.get("final_url", "")
    print(f"    Status: {sc}   Final URL: {fu}")

    if data.get("ssl_warning"):
        print(f"    {Fore.YELLOW}⚠  {data['ssl_warning']}{Style.RESET_ALL}")
    if data.get("ssl_error"):
        print(f"    {Fore.YELLOW}SSL: {data['ssl_error'][:100]}{Style.RESET_ALL}")

    # Server info headers
    info = data.get("server_info_headers", {})
    if info:
        print(f"\n    {Fore.YELLOW}Server Info Headers (reveals technology):{Style.RESET_ALL}")
        for h, v in info.items():
            print(f"      {h}: {v}")

    # Missing security headers
    missing = data.get("security_headers_missing", [])
    if missing:
        print(f"\n    {Fore.RED}Missing Security Headers:{Style.RESET_ALL}")
        for m in missing:
            print(f"      ✖ {m}")

    # Present security headers
    present = data.get("security_headers_present", [])
    if present:
        print(f"\n    {Fore.GREEN}Security Headers Present:{Style.RESET_ALL}")
        for p in present:
            print(f"      ✔ {p}")

    if verbose:
        all_h = data.get("all_headers", {})
        if all_h:
            print(f"\n    {Fore.WHITE}All Headers:{Style.RESET_ALL}")
            for h, v in all_h.items():
                print(f"      {h}: {v[:80]}")


def _print_section_ports(data: dict) -> None:
    if "error" in data:
        print(f"    {Fore.YELLOW}{data['error']}{Style.RESET_ALL}")
        return

    ip = data.get("target_ip", "?")
    print(f"    Target IP: {ip}")
    open_ports = data.get("open_ports", [])
    if not open_ports:
        print(f"    {Fore.GREEN}No open ports found in probe set.{Style.RESET_ALL}")
        return

    rows = [[str(p["port"]), p["service"], f"{Fore.RED}OPEN{Style.RESET_ALL}"]
            for p in open_ports]
    print(tabulate(rows, headers=["Port", "Service", "State"], tablefmt="simple"))
    print(f"    Closed/filtered: {data.get('closed_count', 0)} of {data.get('probed_total', 0)} probed")


_SECTION_PRINTERS = {
    "DNS Records":  _print_section_dns,
    "Reverse DNS":  _print_section_reverse,
    "WHOIS":        _print_section_whois,
    "HTTP Headers": _print_section_http,
    "Port Probe":   _print_section_ports,
}


def _print_results(target: str, sections: list[dict], config: dict) -> None:
    """Print full OSINT report to stdout."""
    verbose = config.get("verbose", False)

    print()
    print(f"{Fore.CYAN}{'═' * 72}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  LOCAL SECURITY SUITE — OSINT Lite{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Target : {target}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═' * 72}{Style.RESET_ALL}")

    for sec in sections:
        title  = sec.get("section", "Unknown")
        data   = sec.get("data", {})
        status = sec.get("status", "ok")

        status_icon = (
            f"{Fore.GREEN}✔{Style.RESET_ALL}" if status == "ok" else
            f"{Fore.YELLOW}⚠{Style.RESET_ALL}" if status == "warn" else
            f"{Fore.RED}✖{Style.RESET_ALL}"
        )

        print()
        print(f"{Fore.WHITE}{Style.BRIGHT}  ▶ {title}  {status_icon}{Style.RESET_ALL}")
        print(f"  {'─' * 68}")

        printer = _SECTION_PRINTERS.get(title)
        if printer:
            if title == "HTTP Headers":
                printer(data, verbose)
            else:
                printer(data)
        else:
            print(f"    {data}")

    print()
    print(f"{Fore.CYAN}{'═' * 72}{Style.RESET_ALL}")
    print()


def _save_output(target: str, sections: list[dict], result: dict, config: dict) -> None:
    """Write OSINT result to disk when --output was provided."""
    output_path:   str = config.get("output_path", "")
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
                "Local Security Suite — OSINT Lite Report",
                f"Target    : {target}",
                f"Generated : {datetime.now().isoformat(timespec='seconds')}",
                "=" * 72,
                "",
            ]
            for sec in sections:
                lines.append(f"[{sec['section']}]  status={sec['status']}")
                data = sec.get("data", {})
                if isinstance(data, dict):
                    for k, v in data.items():
                        lines.append(f"  {k}: {v}")
                else:
                    lines.append(f"  {data}")
                lines.append("")
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
    OSINT Lite entry point.

    Args:
        config: dict with keys output_format, output_path, verbose, target

    Returns:
        {"status": "ok"|"error", "findings": [...], "summary": "..."}
    """
    raw_target: str = config.get("target", "").strip()

    try:
        target = _validate_target(raw_target)
    except ValueError as exc:
        msg = str(exc)
        print(f"{Fore.RED}  ✖  {msg}{Style.RESET_ALL}")
        return {
            "status":   "error",
            "module":   "osint_lite",
            "findings": [],
            "summary":  msg,
        }

    sections = _collect_osint(target)
    _print_results(target, sections, config)

    # Build findings list for unified multi-module output
    findings: list[dict] = []
    for sec in sections:
        data = sec.get("data", {})
        # Flag missing HTTP security headers as findings
        if sec["section"] == "HTTP Headers" and isinstance(data, dict):
            for missing in data.get("security_headers_missing", []):
                findings.append({
                    "name":      f"Missing header ({sec['section']})",
                    "severity":  "Low",
                    "description": missing,
                    "category":  "HTTP Security",
                })
            for info_h, val in data.get("server_info_headers", {}).items():
                findings.append({
                    "name":      f"Server info exposed: {info_h}",
                    "severity":  "Low",
                    "description": f"{info_h}: {val}",
                    "category":  "Information Disclosure",
                })
        # Flag open risky ports
        if sec["section"] == "Port Probe" and isinstance(data, dict):
            for p in data.get("open_ports", []):
                findings.append({
                    "name":      f"Open port on target: {p['port']}/{p['service']}",
                    "severity":  "Medium",
                    "description": f"Port {p['port']} ({p['service']}) is open on {target}",
                    "category":  "External Exposure",
                })

    summary = (
        f"OSINT scan complete for {target} — "
        f"{len(sections)} sections gathered, {len(findings)} findings"
    )

    result: dict[str, Any] = {
        "status":    "ok",
        "module":    "osint_lite",
        "target":    target,
        "sections":  sections,
        "findings":  findings,
        "summary":   summary,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }

    _save_output(target, sections, result, config)
    return result
