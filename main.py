"""
Local Security Suite — main.py
================================
Core CLI entry point for the Local Security Suite.
Uses argparse to route flags to the appropriate security modules.

Usage:
    python main.py --cis-audit
    python main.py --vuln-scan --format json --output output/report.json
    python main.py --cis-audit --net-analyze --verbose
    python main.py --osint --target google.com
    python main.py --baseline --target ./modules
    python main.py --file-integrity --target ./modules
    python main.py --harden
    python main.py --harden --apply
"""

import argparse
import json
import os
import sys
from datetime import datetime

import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

# ─────────────────────────────────────────────
#  Banner
# ─────────────────────────────────────────────

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════╗
║        LOCAL SECURITY SUITE  v1.0                    ║
║        SRM Institute of Science and Technology       ║
║        Department of Networking and Communications   ║
╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# ─────────────────────────────────────────────
#  Output Helpers
# ─────────────────────────────────────────────

def ensure_output_dir() -> None:
    """Create the output/ directory if it does not already exist."""
    os.makedirs("output", exist_ok=True)


def save_output(data: dict, output_path: str, output_format: str) -> None:
    """
    Persist combined module results to disk.

    Args:
        data:          The aggregated result dict from all modules run.
        output_path:   File path provided via --output.
        output_format: 'text' or 'json'.
    """
    ensure_output_dir()
    try:
        if output_format == "json":
            content = json.dumps(data, indent=2, default=str)
        else:
            lines = [
                "=" * 60,
                f"  LOCAL SECURITY SUITE — Report",
                f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "=" * 60,
            ]
            for module_name, result in data.items():
                lines.append(f"\n[MODULE] {module_name.upper()}")
                lines.append("-" * 40)
                if isinstance(result, dict):
                    lines.append(f"Status  : {result.get('status', 'N/A')}")
                    lines.append(f"Summary : {result.get('summary', 'N/A')}")
                    findings = result.get("findings", [])
                    if findings:
                        lines.append("Findings:")
                        for f in findings:
                            lines.append(f"  {f}")
                else:
                    lines.append(str(result))
            content = "\n".join(lines)

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(content)

        print(f"{Fore.GREEN}[✔] Output saved → {output_path}")
    except OSError as exc:
        print(f"{Fore.RED}[✘] Could not write output file: {exc}")


# ─────────────────────────────────────────────
#  Module Loader (lazy import to keep startup fast)
# ─────────────────────────────────────────────

def _load_module(module_name: str):
    """
    Dynamically import a module from the modules/ package.
    Returns the module object, or None on import failure.
    """
    import importlib
    try:
        return importlib.import_module(f"modules.{module_name}")
    except ImportError as exc:
        print(f"{Fore.RED}[✘] Failed to load module '{module_name}': {exc}")
        return None


# ─────────────────────────────────────────────
#  Module Runner
# ─────────────────────────────────────────────

def run_module(module_name: str, func_name: str, config: dict) -> dict:
    """
    Load and execute a single module function.

    Args:
        module_name: Module file name without .py (e.g. 'cis_audit').
        func_name:   Function to call inside that module ('run' or 'run_baseline').
        config:      Shared config dict passed into the module.

    Returns:
        Result dict: {"status": ..., "findings": [...], "summary": ...}
    """
    mod = _load_module(module_name)
    if mod is None:
        return {"status": "error", "findings": [], "summary": f"Module '{module_name}' could not be loaded."}

    func = getattr(mod, func_name, None)
    if func is None:
        return {
            "status": "error",
            "findings": [],
            "summary": f"Function '{func_name}' not found in module '{module_name}'.",
        }

    print(f"\n{Fore.CYAN}{'─'*54}")
    print(f"{Fore.CYAN}  Running: {module_name.upper().replace('_', ' ')}  [{func_name}]")
    print(f"{Fore.CYAN}{'─'*54}{Style.RESET_ALL}")

    try:
        result = func(config)
        if not isinstance(result, dict):
            return {"status": "error", "findings": [], "summary": "Module returned invalid result type."}
        return result
    except Exception as exc:  # noqa: BLE001
        print(f"{Fore.RED}[✘] Unexpected error in module '{module_name}': {exc}")
        return {"status": "error", "findings": [], "summary": str(exc)}


# ─────────────────────────────────────────────
#  Argument Parser
# ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Construct and return the full argparse CLI parser."""

    parser = argparse.ArgumentParser(
        prog="main.py",
        description=(
            "Local Security Suite — Offline Python CLI Security Toolkit\n"
            "SRM Institute of Science and Technology\n"
            "Department of Networking and Communications\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # CIS Benchmark audit (JSON output)
  python main.py --cis-audit --format json --output output/cis.json

  # Vulnerability scan
  python main.py --vuln-scan

  # Threat hunting (verbose)
  python main.py --threat-hunt --verbose

  # Create file integrity baseline
  python main.py --baseline --target ./modules

  # Run file integrity check against saved baseline
  python main.py --file-integrity --target ./modules

  # Network connection analyzer
  python main.py --net-analyze

  # OSINT on a domain/IP
  python main.py --osint --target google.com

  # Hardening check (dry-run, default)
  python main.py --harden

  # Hardening with changes applied (requires elevated privileges)
  python main.py --harden --apply

  # Multi-module combined run with JSON report
  python main.py --cis-audit --net-analyze --format json --output output/combined.json
        """,
    )

    # ── Module flags ──────────────────────────────────────────
    module_group = parser.add_argument_group("Security Modules")

    module_group.add_argument(
        "--cis-audit",
        action="store_true",
        help="Run CIS Benchmark compliance checks (Linux + Windows).",
    )
    module_group.add_argument(
        "--vuln-scan",
        action="store_true",
        help="Scan local host for common vulnerabilities (open ports, weak perms, risky processes).",
    )
    module_group.add_argument(
        "--threat-hunt",
        action="store_true",
        help="Hunt for suspicious processes, log patterns, and scheduled tasks.",
    )
    module_group.add_argument(
        "--file-integrity",
        action="store_true",
        help="Compare current directory hashes against saved baseline (use --target to specify dir).",
    )
    module_group.add_argument(
        "--baseline",
        action="store_true",
        help="Create a SHA-256 hash baseline for a directory (use --target to specify dir).",
    )
    module_group.add_argument(
        "--net-analyze",
        action="store_true",
        help="Enumerate all open ports and active network connections.",
    )
    module_group.add_argument(
        "--osint",
        action="store_true",
        help="Gather OSINT on a domain or IP: DNS, WHOIS, HTTP headers, open ports (requires --target).",
    )
    module_group.add_argument(
        "--harden",
        action="store_true",
        help="Run hardening engine in dry-run mode (check only, no changes applied).",
    )

    # ── Sub-mode flags ────────────────────────────────────────
    submode_group = parser.add_argument_group("Sub-modes")

    submode_group.add_argument(
        "--apply",
        action="store_true",
        help="Used with --harden: actually apply hardening changes (requires elevated privileges).",
    )

    # ── Shared options ────────────────────────────────────────
    options_group = parser.add_argument_group("Options")

    options_group.add_argument(
        "--target",
        metavar="TARGET",
        default=None,
        help="Target directory (for --baseline, --file-integrity) or domain/IP (for --osint).",
    )
    options_group.add_argument(
        "--output",
        metavar="PATH",
        default=None,
        help="Save output to this file path (e.g. output/report.json).",
    )
    options_group.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format: 'text' (default) or 'json'.",
    )
    options_group.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output for all modules.",
    )

    return parser


# ─────────────────────────────────────────────
#  Validation
# ─────────────────────────────────────────────

def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """
    Validate argument combinations and surface clear error messages.
    Exits the process if validation fails.
    """
    # At least one module flag must be provided
    module_flags = [
        args.cis_audit, args.vuln_scan, args.threat_hunt,
        args.file_integrity, args.baseline, args.net_analyze,
        args.osint, args.harden,
    ]
    if not any(module_flags):
        parser.print_help()
        print(f"\n{Fore.RED}[✘] No module flag specified. Pass at least one module flag (e.g. --cis-audit).{Style.RESET_ALL}")
        sys.exit(1)

    # --osint requires --target
    if args.osint and not args.target:
        print(f"{Fore.RED}[✘] --osint requires a --target (domain or IP address).{Style.RESET_ALL}")
        sys.exit(1)

    # --apply without --harden is meaningless
    if args.apply and not args.harden:
        print(f"{Fore.YELLOW}[!] --apply flag has no effect without --harden.{Style.RESET_ALL}")

    # --file-integrity and --baseline are mutually exclusive
    if args.file_integrity and args.baseline:
        print(f"{Fore.RED}[✘] --file-integrity and --baseline cannot be used together.{Style.RESET_ALL}")
        sys.exit(1)


# ─────────────────────────────────────────────
#  Main Entry Point
# ─────────────────────────────────────────────
def user_manual():
    print(f'''
usage: main.py [-h] [--cis-audit] [--vuln-scan] [--threat-hunt] [--file-integrity] [--baseline] [--net-analyze]
               [--osint] [--harden] [--apply] [--target TARGET] [--output PATH] [--format (text,json)] [--verbose]

Local Security Suite — Offline Python CLI Security Toolkit
SRM Institute of Science and Technology
Department of Networking and Communications

optional arguments:
  -h, --help            show this help message and exit

Security Modules:
  --cis-audit           Run CIS Benchmark compliance checks (Linux + Windows).
  --vuln-scan           Scan local host for common vulnerabilities (open ports, weak perms, risky processes).
  --threat-hunt         Hunt for suspicious processes, log patterns, and scheduled tasks.
  --file-integrity      Compare current directory hashes against saved baseline (use --target to specify dir).
  --baseline            Create a SHA-256 hash baseline for a directory (use --target to specify dir).
  --net-analyze         Enumerate all open ports and active network connections.
  --osint               Gather OSINT on a domain or IP: DNS, WHOIS, HTTP headers, open ports (requires --target).
  --harden              Run hardening engine in dry-run mode (check only, no changes applied).

Sub-modes:
  --apply               Used with --harden: actually apply hardening changes (requires elevated privileges).

Options:
  --target TARGET       Target directory (for --baseline, --file-integrity) or domain/IP (for --osint).
  --output PATH         Save output to this file path (e.g. output/report.json).
  --format (text,json)  Output format: 'text' (default) or 'json'.
  --verbose             Enable verbose output for all modules.

EXAMPLES:
  # CIS Benchmark audit (JSON output)
  python main.py --cis-audit --format json --output output/cis.json

  # Vulnerability scan
  python main.py --vuln-scan

  # Threat hunting (verbose)
  python main.py --threat-hunt --verbose

  # Create file integrity baseline
  python main.py --baseline --target ./modules

  # Run file integrity check against saved baseline
  python main.py --file-integrity --target ./modules

  # Network connection analyzer
  python main.py --net-analyze

  # OSINT on a domain/IP
  python main.py --osint --target google.com

  # Hardening check (dry-run, default)
  python main.py --harden

  # Hardening with changes applied (requires elevated privileges)
  python main.py --harden --apply

  # Multi-module combined run with JSON report
  python main.py --cis-audit --net-analyze --format json --output output/combined.json
          ''')
    return


def main() -> None:
    """Parse CLI arguments, build shared config, dispatch to all requested modules in a loop."""

    print(BANNER)
    user_manual()
    parser = build_parser()

    while True:
        try:
            user_input = input("\nEnter arguments (or 'q' to quit): ").strip()

            if user_input.lower() == 'q':
                print("Exiting...")
                break

            # Convert input string into argument list
            args = parser.parse_args(user_input.split())
            validate_args(args, parser)

            # ── Build shared config dict ──────────────────────────────
            config = {
                "output_format": args.format,
                "output_path":   args.output,
                "verbose":       args.verbose,
                "target":        args.target,
                "apply":         args.apply,
            }

            if config["verbose"]:
                print(f"{Fore.YELLOW}[i] Verbose mode ON")
                print(f"{Fore.YELLOW}[i] Output format : {config['output_format']}")
                print(f"{Fore.YELLOW}[i] Output path   : {config['output_path'] or 'stdout only'}")
                print(f"{Fore.YELLOW}[i] Target        : {config['target'] or 'N/A'}")

            # ── Dispatch table ───────────────────────────────────────
            dispatch: list[tuple[bool, str, str]] = [
                (args.cis_audit,      "cis_audit",         "run"),
                (args.vuln_scan,      "vuln_scanner",       "run"),
                (args.threat_hunt,    "threat_hunt",        "run"),
                (args.baseline,       "file_integrity",     "run_baseline"),
                (args.file_integrity, "file_integrity",     "run"),
                (args.net_analyze,    "network_analyzer",   "run"),
                (args.osint,          "osint_lite",         "run"),
                (args.harden,         "hardening_engine",   "run"),
            ]

            # ── Run modules ──────────────────────────────────────────
            ensure_output_dir()
            all_results: dict[str, dict] = {}
            any_error = False

            for flag_active, module_name, func_name in dispatch:
                if not flag_active:
                    continue

                result = run_module(module_name, func_name, config)
                all_results[module_name] = result

                if result.get("status") == "error":
                    any_error = True

            # ── Print summary ────────────────────────────────────────
            print(f"\n{Fore.CYAN}{'═'*54}")
            print(f"{Fore.CYAN}  RUN COMPLETE — {len(all_results)} module(s) executed")
            print(f"{Fore.CYAN}{'═'*54}{Style.RESET_ALL}")

            for module_name, result in all_results.items():
                status = result.get("status", "unknown")
                summary = result.get("summary", "")
                colour = Fore.GREEN if status == "ok" else Fore.RED
                label = "✔" if status == "ok" else "✘"
                print(f"  {colour}[{label}] {module_name:<22} → {summary}{Style.RESET_ALL}")

            # ── Save output ─────────────────────────────────────────
            if args.output:
                save_output(all_results, args.output, args.format)

        except SystemExit:
            # Prevent argparse from exiting the loop
            print("Invalid arguments. Try again.")
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    main()