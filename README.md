# Linux Security Audit Toolkit

A Python-based defensive security tool for collecting basic Linux system information and auditing selected SSH daemon authentication settings. Generates JSON, plain-text, and PDF reports with findings, evidence, severity levels, and recommendations.

## Overview

Linux Security Audit Toolkit is a command-line utility designed to support basic Linux security reviews. It helps administrators and security learners inspect selected SSH authentication settings and produce reports for further review.

The toolkit is designed for defensive security assessment and does not modify system configuration.

## Features

- **System information collection** — collects hostname, operating system, architecture, Python version, and disk usage.
- **SSH configuration auditing** — checks selected authentication-related settings.
- **Effective SSH auditing** — supports checking effective settings through `sshd -T`.
- **Multiple report formats** — generates JSON, readable plain-text, and PDF reports.
- **Actionable findings** — includes status, severity, evidence, and recommendations.
- **Output file support** — saves reports to a specified path.
- **Input validation** — handles missing and empty SSH configuration files.
- **Automated tests** — includes unit tests for audit logic, CLI validation, and report generation.

### Supported SSH Settings

| Setting | Purpose |
|---|---|
| `PermitRootLogin` | Reviews SSH root login policy |
| `PasswordAuthentication` | Reviews password-based SSH authentication |
| `PubkeyAuthentication` | Reviews public-key SSH authentication |

## Requirements

- Python 3.10 or newer.
- Dependencies listed in `requirements.txt`.
- A readable SSH configuration file for file-based auditing.
- OpenSSH `sshd` installed for effective SSH auditing.
- Elevated privileges may be required to inspect effective SSH settings.

Commands below assume a Linux environment or Ubuntu under Windows Subsystem for Linux (WSL).

## Installation

### 1. Clone or open the project

If you have cloned the repository, navigate to its directory:

```bash
cd linux-security-audit-toolkit
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Usage

Run commands from the project directory with the virtual environment activated.

### Basic system report

Collect basic system information and generate the default JSON report:

```bash
python audit.py
```

### Audit a supplied SSH configuration file

```bash
python audit.py --ssh-config tests/sample_sshd_config
```

### Save a JSON report

```bash
python audit.py --ssh-config tests/sample_sshd_config --output reports/sample-report.json
```

### Generate a plain-text report

```bash
python audit.py --ssh-config tests/sample_sshd_config --format text
```

Save the text report to a file:

```bash
python audit.py --ssh-config tests/sample_sshd_config --format text --output reports/ssh-audit.txt
```

### Generate a PDF report

```bash
python audit.py --ssh-config tests/sample_sshd_config --format pdf --output reports/sample-ssh-audit.pdf
```

PDF generation requires an output path supplied through `--output`.

### Audit effective SSH settings

On a system with OpenSSH `sshd` installed, run:

```bash
sudo .venv/bin/python audit.py --effective-ssh
```

Save the effective SSH audit as a PDF:

```bash
sudo .venv/bin/python audit.py --effective-ssh --format pdf --output reports/effective-ssh-audit.pdf
```

Use either `--ssh-config` or `--effective-ssh`, not both.

### Output formats

| Format | CLI option | Description |
|---|---|---|
| JSON | `--format json` | Structured, machine-readable output |
| Text | `--format text` | Readable plain-text report |
| PDF | `--format pdf` | Formatted report document |

JSON is the default output format.

## Running Tests

Run the full automated test suite:

```bash
python -m unittest discover -s tests -v
```

The tests cover system information collection, SSH auditing, command-line validation, report serialization, and PDF/text report generation.

The PDF tests use `pypdf` to validate the generated document and inspect its extracted text.

## Understanding Findings

The toolkit uses finding statuses and severity levels to help prioritize review.

- **`PASS`** — the selected check matches the tool's current rule.
- **`REVIEW`** — the setting or result requires further review.
- **`HIGH`, `MEDIUM`, `INFO`** — indicate the assigned finding severity.

A finding is a recommendation for investigation. It is not, by itself, proof that a system is secure or compromised.

## Limitations

- Only selected SSH authentication settings are checked.
- File-based auditing examines the supplied configuration file and does not fully resolve `Include` directives, `Match` blocks, or all OpenSSH configuration semantics.
- Effective auditing uses `sshd -T` and reports settings exposed by that command for the selected configuration. It is not a complete security audit.
- Results depend on the environment and permissions under which the tool runs.
- The toolkit does not modify SSH configuration or start or restart the SSH service.
- PDF reports may contain host and system information. Review generated reports before sharing them externally.

## Safety and Responsible Use

Use this tool only on systems you own or are explicitly authorized to assess.

Review findings in context and confirm operational requirements before making security configuration changes. Do not treat the output as a substitute for a comprehensive security assessment.

## Project Status

**Status:** Early development.

The current implementation supports system information collection, selected SSH authentication checks, and JSON, plain-text, and PDF reports.

Potential future improvements include additional security checks, expanded platform testing, and broader SSH configuration coverage.

## Contributing

Contributions, bug reports, and suggestions are welcome. When submitting a change, include a clear description of the issue or improvement and run the automated test suite.

## License

No license has been specified yet. Add a license before distributing or reusing this project under explicit open-source terms.
