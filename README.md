# 🛡️ Local Security Suite

> **Offline Python CLI Security Toolkit**  
> SRM Institute of Science and Technology — Department of Networking and Communications

A modular, offline-capable security toolkit that runs entirely on your local machine. Covers CIS benchmarking, vulnerability scanning, threat hunting, file integrity monitoring, network analysis, OSINT reconnaissance, and system hardening — all from a single CLI entry point.

---

## 📁 Project Structure

```
local_security_suite/
├── main.py                  # CLI entry point (argparse router)
├── requirements.txt         # Python dependencies
└── modules/
    ├── __init__.py
    ├── cis_audit.py         # CIS Benchmark compliance checks
    ├── file_integrity.py    # SHA-256 baseline + integrity verification
    ├── hardening_engine.py  # System hardening (dry-run + apply)
    ├── network_analyzer.py  # Open ports & active connections
    ├── osint_lite.py        # DNS, WHOIS, HTTP headers, port recon
    ├── threat_hunt.py       # Suspicious processes, log patterns, scheduled tasks
    └── vuln_scanner.py      # Local vulnerability scanning
```

---

## ⚙️ Requirements

- Python 3.8+
- Windows or Linux
- Some modules require **elevated privileges** (Administrator / sudo) for full results

### Dependencies

```
psutil>=5.9.0
dnspython>=2.3.0
python-whois>=0.8.0
requests>=2.28.0
colorama>=0.4.6
tabulate>=0.9.0
```

---

## 🚀 Installation

```bash
# 1. Clone or download the project
cd local_security_suite

# 2. (Recommended) Create a virtual environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 🖥️ Usage

```
python main.py [MODULE FLAG(S)] [OPTIONS]
```

### Module Flags

| Flag | Description |
|------|-------------|
| `--cis-audit` | Run CIS Benchmark compliance checks (Linux + Windows) |
| `--vuln-scan` | Scan local host for open ports, weak permissions, risky processes |
| `--threat-hunt` | Hunt for suspicious processes, log patterns, and scheduled tasks |
| `--file-integrity` | Compare current directory hashes against a saved baseline |
| `--baseline` | Create a SHA-256 hash baseline for a directory |
| `--net-analyze` | Enumerate all open ports and active network connections |
| `--osint` | Gather OSINT on a domain or IP (requires `--target`) |
| `--harden` | Run hardening engine in dry-run mode (no changes applied) |

### Sub-mode Flags

| Flag | Description |
|------|-------------|
| `--apply` | Used with `--harden`: actually apply hardening changes (requires elevated privileges) |

### Options

| Flag | Description |
|------|-------------|
| `--target TARGET` | Target directory (for `--baseline`, `--file-integrity`) or domain/IP (for `--osint`) |
| `--output PATH` | Save output to a file (e.g. `output/report.json`) |
| `--format {text,json}` | Output format — `text` (default) or `json` |
| `--verbose` | Enable verbose output for all modules |

---

## 💡 Examples

```bash
# CIS Benchmark audit (save as JSON)
python main.py --cis-audit --format json --output output/cis.json

# Vulnerability scan
python main.py --vuln-scan

# Threat hunting (verbose mode)
python main.py --threat-hunt --verbose

# Create a file integrity baseline for a directory
python main.py --baseline --target ./modules

# Check file integrity against the saved baseline
python main.py --file-integrity --target ./modules

# Network connection analyzer
python main.py --net-analyze

# OSINT on a domain or IP
python main.py --osint --target google.com

# Hardening check (dry-run, no changes)
python main.py --harden

# Apply hardening changes (requires admin/sudo)
python main.py --harden --apply

# Multi-module combined run with JSON report
python main.py --cis-audit --net-analyze --format json --output output/combined.json
```

---

## 📦 Output

- Results are printed to the terminal with color-coded status indicators.
- Use `--output <path>` to persist results to disk.
- Use `--format json` for machine-readable output suitable for further processing or integration.
- Output files are saved inside an `output/` directory (created automatically if it doesn't exist).

---

## 🔒 Privilege Notes

| Module | Elevated Privileges Required? |
|--------|-------------------------------|
| `--cis-audit` | Recommended (some checks need admin) |
| `--vuln-scan` | Recommended |
| `--threat-hunt` | Recommended |
| `--harden --apply` | **Required** (writes system settings) |
| `--file-integrity` / `--baseline` | Only if scanning protected directories |
| `--net-analyze` | Recommended (some connections may be hidden) |
| `--osint` | No (network only) |

On **Windows**, run as Administrator:
```
Right-click → "Run as administrator" → python main.py ...
```

On **Linux/macOS**:
```bash
sudo python main.py --harden --apply
```

---

## 🧩 Module Overview

### `cis_audit.py`
Evaluates the system against CIS Benchmark controls covering account policies, audit policies, service configurations, and OS hardening settings. Works on both Windows and Linux.

### `vuln_scanner.py`
Scans for locally exposed vulnerabilities: risky open ports, world-writable files, weak process permissions, and missing patches.

### `threat_hunt.py`
Hunts for indicators of compromise: suspicious running processes, anomalous scheduled tasks, log pattern matching, and autoruns.

### `file_integrity.py`
Generates SHA-256 checksums of a target directory as a baseline, then detects additions, deletions, and modifications on subsequent runs.

### `network_analyzer.py`
Lists all open TCP/UDP ports and active connections with owning process information via `psutil`.

### `osint_lite.py`
Performs passive reconnaissance on a domain or IP address: DNS record enumeration, WHOIS lookup, HTTP header fingerprinting, and open port probing.

### `hardening_engine.py`
Checks system configuration against hardening best practices. In dry-run mode (`--harden`), it reports issues only. With `--apply`, it makes the recommended changes.

---

## 📄 License

This project was developed as a minor project for academic purposes at SRM Institute of Science and Technology.
