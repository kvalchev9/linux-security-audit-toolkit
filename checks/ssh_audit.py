from pathlib import Path


def parse_sshd_config_text(text: str) -> dict:
    """Parse selected SSH daemon settings from configuration text."""
    settings = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        parts = line.split(None, 1)

        if len(parts) != 2:
            continue

        key, value = parts
        key = key.lower()

        if key in {"permitrootlogin", "passwordauthentication"}:
            settings[key] = value.strip().lower()

    return settings


def audit_ssh_config_text(text: str) -> list[dict]:
    """Return findings for selected SSH settings."""
    settings = parse_sshd_config_text(text)
    findings = []

    root_login = settings.get("permitrootlogin")

    if root_login is None:
        findings.append({
            "check": "ssh_permit_root_login",
            "status": "REVIEW",
            "severity": "MEDIUM",
            "evidence": "PermitRootLogin is not explicitly configured.",
            "recommendation": (
                "Review the effective SSH configuration and explicitly "
                "set an appropriate PermitRootLogin policy."
            ),
        })
    elif root_login in {"yes", "without-password", "prohibit-password"}:
        status = "REVIEW" if root_login == "yes" else "PASS"
        severity = "HIGH" if root_login == "yes" else "INFO"

        findings.append({
            "check": "ssh_permit_root_login",
            "status": status,
            "severity": severity,
            "evidence": f"PermitRootLogin {root_login}",
            "recommendation": (
                "Disable direct root SSH login where operationally possible."
                if root_login == "yes"
                else "Confirm that direct root access matches the intended policy."
            ),
        })
    elif root_login == "no":
        findings.append({
            "check": "ssh_permit_root_login",
            "status": "PASS",
            "severity": "INFO",
            "evidence": "PermitRootLogin no",
            "recommendation": "Keep this setting under configuration management.",
        })
    else:
        findings.append({
            "check": "ssh_permit_root_login",
            "status": "REVIEW",
            "severity": "MEDIUM",
            "evidence": f"Unrecognized value: {root_login}",
            "recommendation": "Validate the value against the target OpenSSH version.",
        })

    password_auth = settings.get("passwordauthentication")

    if password_auth == "yes":
        findings.append({
            "check": "ssh_password_authentication",
            "status": "REVIEW",
            "severity": "MEDIUM",
            "evidence": "PasswordAuthentication yes",
            "recommendation": (
                "Review whether password-based SSH authentication is required "
                "and enforce appropriate access controls."
            ),
        })
    elif password_auth == "no":
        findings.append({
            "check": "ssh_password_authentication",
            "status": "PASS",
            "severity": "INFO",
            "evidence": "PasswordAuthentication no",
            "recommendation": "Verify that the approved alternative authentication works.",
        })
    else:
        findings.append({
            "check": "ssh_password_authentication",
            "status": "REVIEW",
            "severity": "MEDIUM",
            "evidence": (
                f"PasswordAuthentication {password_auth}"
                if password_auth is not None
                else "PasswordAuthentication is not explicitly configured."
            ),
            "recommendation": (
                "Review the effective SSH configuration, including defaults "
                "and any Match blocks."
            ),
        })

    return findings


def audit_ssh_config_file(path: str | Path) -> list[dict]:
    """Audit a local SSH configuration file without modifying it."""
    config_path = Path(path)
    text = config_path.read_text(encoding="utf-8", errors="replace")
    return audit_ssh_config_text(text)
