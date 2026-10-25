# Linux Security Audit Toolkit

A Python-based defensive security tool that collects basic system
information and audits selected SSH daemon authentication settings.
It produces structured JSON or readable plain-text reports.

## Features

- Collects hostname, operating system, architecture, Python version,
  and disk usage.
- Audits selected SSH settings:
  - `PermitRootLogin`
  - `PasswordAuthentication`
  - `PubkeyAuthentication`
- Supports auditing a supplied SSH configuration file.
- Supports checking effective SSH settings using `sshd -T`.
- Reports findings with status, severity, evidence, and recommendations.
- Outputs JSON or plain-text reports to the console or a file.
- Validates missing and empty configuration files.
- Includes automated unit tests.

## Requirements

- Python 3.10 or newer.
- For file-based auditing, a readable SSH configuration file.
- For effective SSH auditing, OpenSSH `sshd` must be installed.
- Elevated privileges may be required to read the effective SSH configuration.

## Usage

### Basic system report

```bash
python3 audit.py
```

### Audit a supplied SSH configuration file

```bash
python3 audit.py --ssh-config tests/sample_sshd_config
```

### Save a JSON report

```bash
python3 audit.py --ssh-config tests/sample_sshd_config --output reports/sample-report.json
```

### Audit effective SSH settings

```bash
sudo python3 audit.py --effective-ssh
```

### Generate a readable text report

```bash
sudo python3 audit.py --effective-ssh --format text
```

### Save a text report

```bash
sudo python3 audit.py --effective-ssh --format text --output reports/ssh-audit.txt
```

Use either `--ssh-config` or `--effective-ssh`, not both.
JSON is the default output format. Supported formats are `json` and `text`.

### Run tests

```bash
python3 -m unittest discover -s tests -v
```

## Understanding Findings

- `PASS` means the selected check matches the tool's current rule.
- `REVIEW` means the setting should be reviewed by an administrator.
- `HIGH`, `MEDIUM`, and `INFO` describe the assigned finding severity.

A finding is a recommendation for investigation, not proof that a system
is secure or compromised.

## Limitations

- Only selected SSH authentication settings are checked.
- File-based auditing examines the supplied file and does not fully resolve
  `Include` directives, `Match` blocks, or all OpenSSH configuration semantics.
- Effective auditing uses `sshd -T`; it reports the settings exposed by that
  command for the selected configuration, but is not a complete security audit.
- Results depend on the environment and permissions in which the tool runs.
- The tool does not modify SSH configuration or start the SSH service.

## Safety

Use this tool only on systems you own or are authorized to assess.
Review findings and confirm operational requirements before changing settings.

## Project Status

Early development. Future work may include additional security checks,
more report formats, and expanded platform testing.
