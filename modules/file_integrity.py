"""
modules/file_integrity.py
==========================
File Integrity Monitor for Local Security Suite.

Provides two operating modes:

  --baseline mode  : Walk a target directory, compute SHA-256 + MD5 hashes for
                     every file, and persist the result as a JSON baseline at
                     output/fim_baseline.json.

  --file-integrity : Re-hash the same directory, compare against the saved
                     baseline, and report new / modified / deleted files with
                     their old and new hash values.

Entry points:
    run_baseline(config: dict) -> dict
    run(config: dict)          -> dict

config keys used:
    target        (str)  : Directory to monitor. Defaults to current directory.
    output_format (str)  : "text" | "json"
    output_path   (str)  : Optional file path for saving output.
    verbose       (bool) : Enable per-file hashing progress output.
"""

import datetime
import hashlib
import json
import os
import platform

from colorama import Fore, Style
from tabulate import tabulate

# ─────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────

BASELINE_FILENAME = "fim_baseline.json"
OUTPUT_DIR        = "output"

# Severity thresholds (number of changes)
_SEV_LOW    = 3
_SEV_MEDIUM = 10


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
#  Internal helpers — hashing
# ─────────────────────────────────────────────

def _hash_file(filepath: str) -> dict:
    """
    Compute SHA-256 and MD5 hashes for a single file.

    Returns a dict with keys 'sha256', 'md5', 'size', or None if the file
    cannot be read (permission error, race condition, etc.).
    """
    sha256 = hashlib.sha256()
    md5    = hashlib.md5()
    size   = 0
    try:
        with open(filepath, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                sha256.update(chunk)
                md5.update(chunk)
                size += len(chunk)
        return {
            "sha256": sha256.hexdigest(),
            "md5":    md5.hexdigest(),
            "size":   size,
        }
    except (PermissionError, OSError, IOError):
        return None


def _walk_directory(root: str, verbose: bool) -> dict:
    """
    Recursively walk *root* and return a mapping of relative path → hash info.

    Files that cannot be read are skipped with an optional warning.
    """
    hashes = {}
    abs_root = os.path.abspath(root)

    for dirpath, _dirnames, filenames in os.walk(abs_root):
        for filename in filenames:
            abs_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(abs_path, abs_root)

            result = _hash_file(abs_path)
            if result is None:
                if verbose:
                    print(
                        f"{Fore.YELLOW}[SKIP]{Style.RESET_ALL} "
                        f"Cannot read: {rel_path}"
                    )
                continue

            hashes[rel_path] = result
            if verbose:
                print(
                    f"{Fore.CYAN}[HASH]{Style.RESET_ALL} "
                    f"{rel_path}  sha256={result['sha256'][:16]}…"
                )

    return hashes


# ─────────────────────────────────────────────
#  Internal helpers — baseline I/O
# ─────────────────────────────────────────────

def _baseline_path() -> str:
    """Return the full path to the baseline JSON file."""
    return os.path.join(OUTPUT_DIR, BASELINE_FILENAME)


def _save_baseline(abs_target: str, hashes: dict) -> str:
    """
    Persist the baseline dict to output/fim_baseline.json.

    Returns the path it was written to.  Raises OSError on failure.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    payload = {
        "created":    datetime.datetime.utcnow().isoformat() + "Z",
        "target":     abs_target,
        "file_count": len(hashes),
        "files":      hashes,
    }
    path = _baseline_path()
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return path


def _load_baseline() -> dict:
    """
    Load an existing baseline.

    Returns the full baseline dict.
    Raises FileNotFoundError when no baseline exists yet.
    """
    path = _baseline_path()
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"No baseline found at '{path}'. "
            "Run --baseline first to create one."
        )
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        raise OSError(f"Could not parse baseline file: {exc}") from exc


# ─────────────────────────────────────────────
#  Internal helpers — diff engine
# ─────────────────────────────────────────────

def _diff_hashes(baseline_files: dict, current_files: dict) -> dict:
    """
    Compare *baseline_files* against *current_files*.

    Returns:
        {
            "modified": [ {path, old_sha256, new_sha256, old_md5, new_md5,
                           old_size, new_size}, … ],
            "new":      [ {path, sha256, md5, size}, … ],
            "deleted":  [ {path, sha256, md5, size}, … ],
        }
    """
    baseline_keys = set(baseline_files.keys())
    current_keys  = set(current_files.keys())

    modified = [
        {
            "path":      path,
            "old_sha256": baseline_files[path]["sha256"],
            "new_sha256": current_files[path]["sha256"],
            "old_md5":    baseline_files[path]["md5"],
            "new_md5":    current_files[path]["md5"],
            "old_size":   baseline_files[path]["size"],
            "new_size":   current_files[path]["size"],
        }
        for path in sorted(baseline_keys & current_keys)
        if baseline_files[path]["sha256"] != current_files[path]["sha256"]
    ]

    new_files = [
        {
            "path":   path,
            "sha256": current_files[path]["sha256"],
            "md5":    current_files[path]["md5"],
            "size":   current_files[path]["size"],
        }
        for path in sorted(current_keys - baseline_keys)
    ]

    deleted_files = [
        {
            "path":   path,
            "sha256": baseline_files[path]["sha256"],
            "md5":    baseline_files[path]["md5"],
            "size":   baseline_files[path]["size"],
        }
        for path in sorted(baseline_keys - current_keys)
    ]

    return {
        "modified": modified,
        "new":      new_files,
        "deleted":  deleted_files,
    }


def _severity(total_changes: int) -> str:
    """Map a count of changes to a severity label."""
    if total_changes == 0:
        return "CLEAN"
    if total_changes <= _SEV_LOW:
        return "LOW"
    if total_changes <= _SEV_MEDIUM:
        return "MEDIUM"
    return "HIGH"


# ─────────────────────────────────────────────
#  Output / Display
# ─────────────────────────────────────────────

def _print_baseline_result(hashes: dict, abs_target: str, saved_path: str) -> None:
    """Print a short confirmation after a baseline is written."""
    print()
    print(f"{Fore.CYAN}{'─'*54}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  FILE INTEGRITY — Baseline Created{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─'*54}{Style.RESET_ALL}")
    print(f"  Target directory : {abs_target}")
    print(f"  Files hashed     : {len(hashes)}")
    print(f"  Saved to         : {saved_path}")
    print(f"{Fore.GREEN}  [✔] Baseline created successfully.{Style.RESET_ALL}")
    print()


def _print_results(diff: dict, meta: dict, config: dict) -> None:
    """
    Render the integrity-check diff to the terminal.

    Colours:  Green = no changes   Red = modified/deleted   Yellow = new files
    """
    modified  = diff["modified"]
    new_files = diff["new"]
    deleted   = diff["deleted"]
    total     = len(modified) + len(new_files) + len(deleted)
    sev       = _severity(total)

    print()
    print(f"{Fore.CYAN}{'─'*54}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  FILE INTEGRITY — Scan Report{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─'*54}{Style.RESET_ALL}")
    print(f"  Target    : {meta['target']}")
    print(f"  Baseline  : {meta['baseline_created']}")
    print(f"  Scan time : {meta['scan_time']}")
    print(f"  Files now : {meta['current_count']}   |   Baseline : {meta['baseline_count']}")
    print()

    if total == 0:
        print(
            f"{Fore.GREEN}  [✔] No changes detected. "
            f"System integrity intact.{Style.RESET_ALL}"
        )
        print()
        return

    # ── Modified ─────────────────────────────────────────────────────────────
    if modified:
        print(f"{Fore.RED}  [✖] MODIFIED FILES ({len(modified)}){Style.RESET_ALL}")
        rows = [
            [
                e["path"],
                e["old_sha256"][:16] + "…",
                e["new_sha256"][:16] + "…",
                e["old_size"],
                e["new_size"],
            ]
            for e in modified
        ]
        print(tabulate(
            rows,
            headers=["Path", "Old SHA256", "New SHA256", "Old Bytes", "New Bytes"],
            tablefmt="rounded_outline",
        ))
        print()

    # ── New files ─────────────────────────────────────────────────────────────
    if new_files:
        print(f"{Fore.YELLOW}  [+] NEW FILES ({len(new_files)}){Style.RESET_ALL}")
        rows = [
            [e["path"], e["sha256"][:16] + "…", e["size"]]
            for e in new_files
        ]
        print(tabulate(
            rows,
            headers=["Path", "SHA256", "Bytes"],
            tablefmt="rounded_outline",
        ))
        print()

    # ── Deleted files ─────────────────────────────────────────────────────────
    if deleted:
        print(f"{Fore.RED}  [-] DELETED FILES ({len(deleted)}){Style.RESET_ALL}")
        rows = [
            [e["path"], e["sha256"][:16] + "…", e["size"]]
            for e in deleted
        ]
        print(tabulate(
            rows,
            headers=["Path", "SHA256", "Bytes"],
            tablefmt="rounded_outline",
        ))
        print()

    # ── Summary ───────────────────────────────────────────────────────────────
    sev_colour = Fore.RED if sev in ("HIGH", "MEDIUM") else Fore.YELLOW
    print(
        f"  Summary  :  {sev_colour}{total} change(s){Style.RESET_ALL}  |  "
        f"Severity: {sev_colour}{sev}{Style.RESET_ALL}  |  "
        f"Modified: {len(modified)}  "
        f"New: {len(new_files)}  "
        f"Deleted: {len(deleted)}"
    )
    print()

    if config.get("verbose"):
        print(f"\n{'─'*54}\n  RECOMMENDATIONS\n{'─'*54}")
        for entry in modified:
            print(
                f"  [MODIFIED]  {entry['path']}\n"
                f"      Old: {entry['old_sha256']}\n"
                f"      New: {entry['new_sha256']}\n"
            )
        for entry in deleted:
            print(f"  [DELETED]   {entry['path']} — restore from backup or investigate.\n")
        for entry in new_files:
            print(f"  [NEW]       {entry['path']} — verify this file is authorised.\n")


def _save_output(result: dict, config: dict) -> None:
    """
    Write module result to disk when --output was provided.
    Handles both text and JSON formats.
    """
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
            content = json.dumps(result, indent=2, default=str)
        else:
            findings = result.get("findings", {})
            lines = [
                "=" * 60,
                "  FILE INTEGRITY MONITOR REPORT",
                f"  Status   : {result['status']}",
                f"  Summary  : {result['summary']}",
                "=" * 60,
            ]
            for category, items in findings.items():
                if isinstance(items, list):
                    lines.append(f"\n[{category.upper()}]")
                    for item in items:
                        if isinstance(item, dict):
                            lines.append(f"  {item.get('path', str(item))}")
                        else:
                            lines.append(f"  {item}")
            content = "\n".join(lines)

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"{Fore.GREEN}[✔] Output saved → {output_path}{Style.RESET_ALL}")
    except OSError as exc:
        print(f"{Fore.RED}[✘] Could not write output file: {exc}{Style.RESET_ALL}")


# ─────────────────────────────────────────────
#  Module Entry Points
# ─────────────────────────────────────────────

def run_baseline(config: dict) -> dict:
    """
    Baseline mode (--baseline flag).

    Walk the target directory, hash every file, and persist the baseline.

    Args:
        config: Shared config dict (target, output_format, output_path, verbose).

    Returns:
        {
            "status":   "ok" | "error",
            "findings": {"files": [list of relative paths]},
            "summary":  "...",
        }
    """
    target  = config.get("target") or os.getcwd()
    verbose = config.get("verbose", False)

    if not os.path.isdir(target):
        msg = f"Target is not a directory: '{target}'"
        print(f"{Fore.RED}[✘] {msg}{Style.RESET_ALL}")
        return {"status": "error", "findings": {}, "summary": msg}

    abs_target = os.path.abspath(target)
    print(
        f"{Fore.CYAN}[*] Building baseline for:{Style.RESET_ALL} {abs_target}"
    )

    try:
        hashes = _walk_directory(abs_target, verbose)
    except Exception as exc:  # noqa: BLE001
        msg = f"Failed to walk directory: {exc}"
        print(f"{Fore.RED}[✘] {msg}{Style.RESET_ALL}")
        return {"status": "error", "findings": {}, "summary": msg}

    if not hashes:
        msg = "No readable files found in target directory."
        print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")
        return {"status": "ok", "findings": {"files": []}, "summary": msg}

    try:
        saved_path = _save_baseline(abs_target, hashes)
    except OSError as exc:
        msg = f"Could not save baseline: {exc}"
        print(f"{Fore.RED}[✘] {msg}{Style.RESET_ALL}")
        return {"status": "error", "findings": {}, "summary": msg}

    _print_baseline_result(hashes, abs_target, saved_path)

    result = {
        "status":   "ok",
        "findings": {"files": sorted(hashes.keys())},
        "summary":  (
            f"Baseline created: {len(hashes)} file(s) in '{abs_target}'. "
            f"Saved to '{saved_path}'."
        ),
    }
    _save_output(result, config)
    return result


def run(config: dict) -> dict:
    """
    Integrity-check mode (--file-integrity flag).

    Re-hash the target directory and compare against the stored baseline.

    Args:
        config: Shared config dict (target, output_format, output_path, verbose).

    Returns:
        {
            "status":   "ok" | "error",
            "findings": {
                "modified": [...],
                "new":      [...],
                "deleted":  [...],
                "meta":     {...},
                "severity": "CLEAN" | "LOW" | "MEDIUM" | "HIGH",
                "total_changes": int,
            },
            "summary": "...",
        }
    """
    target  = config.get("target") or os.getcwd()
    verbose = config.get("verbose", False)

    if not os.path.isdir(target):
        msg = f"Target is not a directory: '{target}'"
        print(f"{Fore.RED}[✘] {msg}{Style.RESET_ALL}")
        return {"status": "error", "findings": {}, "summary": msg}

    abs_target = os.path.abspath(target)

    # ── Load baseline ─────────────────────────────────────────────────────────
    try:
        baseline = _load_baseline()
    except FileNotFoundError as exc:
        print(f"{Fore.RED}[✘] {exc}{Style.RESET_ALL}")
        return {"status": "error", "findings": {}, "summary": str(exc)}
    except OSError as exc:
        msg = str(exc)
        print(f"{Fore.RED}[✘] {msg}{Style.RESET_ALL}")
        return {"status": "error", "findings": {}, "summary": msg}

    baseline_files = baseline.get("files", {})

    print(
        f"{Fore.CYAN}[*] Scanning:{Style.RESET_ALL} {abs_target}  "
        f"(baseline from {baseline.get('created', '?')})"
    )

    # ── Re-hash current state ─────────────────────────────────────────────────
    try:
        current_files = _walk_directory(abs_target, verbose)
    except Exception as exc:  # noqa: BLE001
        msg = f"Failed to walk directory: {exc}"
        print(f"{Fore.RED}[✘] {msg}{Style.RESET_ALL}")
        return {"status": "error", "findings": {}, "summary": msg}

    # ── Diff ──────────────────────────────────────────────────────────────────
    diff = _diff_hashes(baseline_files, current_files)

    meta = {
        "target":           abs_target,
        "baseline_target":  baseline.get("target", "unknown"),
        "baseline_created": baseline.get("created", "unknown"),
        "scan_time":        datetime.datetime.utcnow().isoformat() + "Z",
        "baseline_count":   len(baseline_files),
        "current_count":    len(current_files),
    }

    _print_results(diff, meta, config)

    total = len(diff["modified"]) + len(diff["new"]) + len(diff["deleted"])
    sev   = _severity(total)

    if total == 0:
        summary = (
            f"Integrity check PASSED — "
            f"{len(current_files)} file(s) matched the baseline exactly."
        )
    else:
        summary = (
            f"Integrity check FAILED — {total} change(s) detected "
            f"(Modified: {len(diff['modified'])}, "
            f"New: {len(diff['new'])}, "
            f"Deleted: {len(diff['deleted'])}). "
            f"Severity: {sev}."
        )

    result = {
        "status":   "ok",
        "findings": {
            "modified":      diff["modified"],
            "new":           diff["new"],
            "deleted":       diff["deleted"],
            "meta":          meta,
            "severity":      sev,
            "total_changes": total,
        },
        "summary": summary,
    }
    _save_output(result, config)
    return result
