# Linux Security Audit Toolkit

A Python-based security auditing tool that collects basic system information
and reviews selected SSH daemon configuration settings.

## Features

- Collects system information, including hostname, operating system,
  architecture, Python version, and disk usage.
- Audits selected SSH settings:
  - `PermitRootLogin`
  - `PasswordAuthentication`
- Reports findings with status, severity, evidence, and recommendations.
- Outputs reports as JSON to the console or a specified file.
- Validates missing and empty SSH configuration files.
- Includes automated unit tests.

## Requirements

- Python 3.10 or newer
- Windows, Linux, or macOS for running the Python tool
- An SSH daemon configuration file for SSH auditing

## Usage

Run the basic system audit:

```powershell
python audit.py
## Usage (continued)

Audit a sample SSH configuration:

```powershell
python audit.py --ssh-config tests/sample_sshd_config
```

Save the report as JSON:

```powershell
python audit.py --ssh-config tests/sample_sshd_config --output reports/sample-report.json
```

Run the test suite:

```powershell
python -m unittest discover -s tests -v
```

## Example Findings

- `PASS` — a setting matches the check's expected policy.
- `REVIEW` — a setting needs further investigation.
- `HIGH`, `MEDIUM`, or `INFO` — the finding's assigned severity.

These are preliminary configuration checks, not a complete security assessment.

## Limitations

- SSH auditing examines selected settings in the supplied file.
- It does not resolve `Include` directives, fully evaluate `Match` blocks, or determine the effective configuration of a running SSH daemon.
- Verify findings against the target system's actual configuration.
- The tool does not modify system settings.

## Safety

This tool is intended for authorized defensive security auditing. Review findings before making configuration changes.

## Project Status

Early development. Additional checks, expanded test coverage, and improved SSH configuration analysis are planned.