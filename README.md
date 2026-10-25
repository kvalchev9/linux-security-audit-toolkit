# Linux Security Audit Toolkit

A Python-based defensive security tool that collects basic system information and audits selected SSH daemon authentication settings. It produces JSON, readable plain-text, and PDF reports.

## Features

- Collects hostname, operating system, architecture, Python version, and disk usage.
- Audits selected SSH settings:
  - `PermitRootLogin`
  - `PasswordAuthentication`
  - `PubkeyAuthentication`
- Supports auditing a supplied SSH configuration file.
- Supports checking effective SSH settings using `sshd -T`.
- Reports findings with status, severity, evidence, and recommendations.
- Generates JSON, plain-text, and PDF reports.
- Saves reports to a specified output file.
- Validates missing and empty configuration files.
- Includes automated unit tests for audit logic and report generation.

## Requirements

- Python 3.10 or newer.
- Dependencies listed in `requirements.txt`.
- For file-based auditing, a readable SSH configuration file.
- For effective SSH auditing, OpenSSH `sshd` must be installed.
- Elevated privileges may be required to read the effective SSH configuration.

## Installation

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

If you use Windows Subsystem for Linux (WSL), run these commands in your Ubuntu terminal, from the project directory.

## Usage

### Basic system report

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

### Generate a readable text report

```bash
python audit.py --ssh-config tests/sample_sshd_config --format text
```

### Save a text report

```bash
python audit.py --ssh-config tests/sample_sshd_config --format text --output reports/ssh-audit.txt
```

### Generate a PDF report

```bash
python audit.py --ssh-config tests/sample_sshd_config --format pdf --output reports/sample-ssh-audit.pdf
```

PDF output requires an output path supplied through `--output`.

### Audit effective SSH settings

```bash
sudo .venv/bin/python audit.py --effective-ssh
```

### Save an effective SSH audit as PDF

```bash
sudo .venv/bin/python audit.py --effective-ssh --format pdf --output reports/effective-ssh-audit.pdf
```

Use either `--ssh-config` or `--effective-ssh`, not both.

JSON is the default output format. Supported formats are `json`, `text`, and `pdf`.

## Running Tests

Run the full test suite:

```bash
python -m unittest discover -s tests -v
```

The PDF tests use `pypdf` to validate the generated document and inspect its extracted text.

## Understanding Findings

- `PASS` means the selected check matches the tool's current rule.
- `REVIEW` means the setting should be reviewed by an administrator.
- `HIGH`, `MEDIUM`, and `INFO` describe the assigned finding severity.

A finding is a recommendation for investigation, not proof that a system is secure or compromised.

## Limitations

- Only selected SSH authentication settings are checked.
- File-based auditing examines the supplied file and does not fully resolve `Include` directives, `Match` blocks, or all OpenSSH configuration semantics.
- Effective auditing uses `sshd -T`; it reports the settings exposed by that command for the selected configuration, but is not a complete security audit.
- Results depend on the environment and permissions in which the tool runs.
- The tool does not modify SSH configuration or start the SSH service.
- PDF reports contain system information collected from the environment where the audit runs. Review the report before sharing it externally.

## Safety

Use this tool only on systems you own or are authorized to assess. Review findings and confirm operational requirements before changing settings.

## Project Status

Early development. Current report formats are JSON, text, and PDF. Future work may include additional security checks and expanded platform testing.
