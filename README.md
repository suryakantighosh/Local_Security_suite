# Local Security Suite

> Offline-first security assessment toolkit for local systems, labs, and edge environments

Local Security Suite is a modular command-line tool designed to help engineers and administrators assess host security posture without depending on cloud services, agents, or complex infrastructure. The project brings together CIS-style hardening checks, vulnerability review, threat hunting, file integrity monitoring, network inspection, and lightweight OSINT into a single, approachable workflow.

<img width="1536" height="1024" alt="Overall Architecture" src="https://github.com/user-attachments/assets/a9e9fd33-fa50-41b6-9148-b5036e048c6f" />

## Why this project exists

Security assessment often requires a collection of disconnected tools, each focused on a narrow problem. Local Security Suite exists to reduce that friction by offering a unified local-first experience for common security tasks such as:

- verifying baseline hardening posture
- identifying exposed services and risky network activity
- spotting suspicious process and log patterns
- comparing file-state changes over time
- conducting lightweight reconnaissance against a target domain or IP

The system is intentionally practical: it prioritizes local visibility, offline compatibility, and clear operational reporting over heavy infrastructure requirements.

## Problem statement

Teams working in constrained environments often need a lightweight way to answer three questions quickly:

1. Is this host configured securely?
2. Is anything suspicious running or exposed?
3. Has the system changed unexpectedly since the last review?

Local Security Suite is designed to help answer those questions with minimal setup and no dependency on a remote control plane.

## Professional overview

Local Security Suite is a research-oriented security toolkit with a strong emphasis on transparency, simplicity, and auditability. It is well-suited for:

- security lab environments
- small business IT operations
- incident response preparation
- local compliance reviews
- hands-on security training

The project is not intended to replace a full enterprise SIEM or endpoint platform. Instead, it provides a focused operational layer for local assessment and review.

## Architecture overview

The repository follows a straightforward architecture:

- a CLI entry point parses user intent and shared options
- modular assessment engines collect evidence from the local host or a target network
- results are normalized into structured findings and returned as terminal output or JSON
- optional report files can be persisted for later review or downstream processing

This separation keeps the toolkit easy to extend while preserving a clean operational model.

## Key capabilities

- CIS-oriented host hardening checks
- vulnerability and exposure review
- threat hunting for suspicious processes and patterns
- file integrity baseline creation and change detection
- local network connection and open-port analysis
- passive OSINT-style reconnaissance for domains and IPs
- optional hardening actions for supported systems

## Technology stack

- Python 3.8+
- argparse for command-line orchestration
- colorama and tabulate for terminal presentation
- psutil for process and network inspection
- dnspython, python-whois, and requests for lightweight reconnaissance
- JSON output for structured reporting

## Directory structure

```text
local_security_suite/
├── main.py
├── requirements.txt
├── modules/
│   ├── cis_audit.py
│   ├── file_integrity.py
│   ├── hardening_engine.py
│   ├── network_analyzer.py
│   ├── osint_lite.py
│   ├── threat_hunt.py
│   └── vuln_scanner.py
├── output/
└── README.md
```

## Installation

```bash
git clone <repository-url>
cd local_security_suite
python -m venv .venv
source .venv/bin/activate
# Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Quick start

Run the toolkit with one or more modules enabled:

```bash
python main.py --cis-audit
python main.py --vuln-scan
python main.py --threat-hunt
python main.py --baseline --target ./modules
python main.py --file-integrity --target ./modules
python main.py --net-analyze
python main.py --osint --target google.com
python main.py --harden
```

## Configuration

The CLI supports a small number of shared options:

| Option | Purpose |
|---|---|
| `--cis-audit` | Run CIS-style host configuration checks |
| `--vuln-scan` | Review common local exposure and vulnerability indicators |
| `--threat-hunt` | Hunt for suspicious processes, commands, and persistence patterns |
| `--file-integrity` | Compare a target directory to a saved baseline |
| `--baseline` | Create a new file-integrity baseline |
| `--net-analyze` | Inspect open ports and active network connections |
| `--osint` | Gather passive reconnaissance data for a domain or IP |
| `--harden` | Review hardening recommendations and optionally apply them |
| `--apply` | Enable hardening changes in apply mode |
| `--target` | Configure the target directory or domain/IP |
| `--output` | Persist a report to disk |
| `--format` | Choose text or JSON output |
| `--verbose` | Enable additional detail in reports |

## Environment variables

No required environment variables are needed for normal operation. The toolkit is designed to function with local system access and optional network reachability where relevant. Any saved output location is provided through CLI arguments rather than a hidden configuration layer.

## Running the toolkit

### Basic usage

```bash
python main.py --cis-audit --format json --output output/cis.json
```

### Combined assessment

```bash
python main.py --cis-audit --net-analyze --format json --output output/combined.json
```

### Hardening review

```bash
python main.py --harden
```

### Apply hardening changes

> Administrative or root privileges are strongly recommended when using apply mode.

```bash
python main.py --harden --apply
```

## Docker deployment

Container deployment is not yet bundled in this repository, but the project is well suited to a lightweight Python container model. A future packaging step would likely use a slim Python image, install the runtime dependencies from the requirements file, and run the CLI inside a containerized environment for repeatable local or test deployments.

## API overview

This repository currently exposes a terminal-first interface rather than a network API. The public interaction model is:

- command-line invocation
- structured module execution
- console reporting or JSON output
- optional file-based persistence for downstream analysis

## Workflow

1. Select one or more assessment modules.
2. Provide a target directory, host, or domain as needed.
3. Review the findings returned by the toolkit.
4. Persist results for later comparison or incident response use.
5. Optionally apply hardening actions where appropriate and with proper privileges.

<img width="1536" height="1024" alt="Dataflow Pipeline" src="https://github.com/user-attachments/assets/28ea4b43-d2b1-42b3-bbbf-c9b161415082" />


## Security model

<img width="1536" height="1024" alt="Assesment Module Map" src="https://github.com/user-attachments/assets/18932d93-9016-4daf-9569-5d39357b5170" />

The toolkit is designed for local assessment and does not require a remote service registration or telemetry channel. It is intentionally conservative in scope:

- it reads system state and reports findings
- it avoids unnecessary network dependencies for core local checks
- it recommends privileged execution for operations that modify configuration
- it is best used in a controlled environment with appropriate administrative access

## Performance and scalability

The current implementation is optimized for single-host and small-lab use rather than large-scale fleet deployment. It performs lightweight local inspection and is suitable for manual reviews, lab exercises, and operational triage. Future iterations may expand the architecture for distributed collection, policy-based execution, and richer reporting pipelines.

## Roadmap

Planned evolution includes:

- container packaging and repeatable deployment workflows
- richer report schemas and export formats
- stronger policy-driven hardening workflows
- remote or distributed collection support
- integration hooks for enterprise workflow tools

## Screenshots and example output

The toolkit is designed to produce rich terminal output and machine-readable reports. For public-facing documentation, the most valuable visuals include:

- a CIS audit summary view
- a threat-hunting findings table
- a network exposure report
- a file-integrity change summary

A set of publication-ready architecture diagrams for this repository is provided in the documentation directory.

## Architecture section

The project is best understood as a modular local assessment platform:

- a CLI front end drives the experience
- independent modules collect evidence from the host or network
- findings are normalized and reported consistently
- results can be saved for later review or expansion

For detailed visual architecture specifications, see the diagram documentation in the docs folder.
<img width="1536" height="1024" alt="Flow Control" src="https://github.com/user-attachments/assets/3298fc29-1812-44c9-87b5-14bd5553bb06" />
<img width="1536" height="1024" alt="command Execution flow" src="https://github.com/user-attachments/assets/8d36865e-aa48-409f-b5a8-8e8701d7eed1" />

## Contributing

Contributions are welcome. Suggested improvements include:

- better cross-platform coverage
- additional hardening checks
- more structured report schemas
- documentation enhancements
- example use cases and sample outputs

Please open an issue or submit a pull request with a clear explanation of the proposed change.

## License

This repository is distributed under the MIT License. See the LICENSE file for details.

## Acknowledgements

This project was created as part of a security-focused academic and practical learning effort and is intended to support safe, responsible assessment workflows. It is designed to help engineers and students understand common local security operations in a structured way.
