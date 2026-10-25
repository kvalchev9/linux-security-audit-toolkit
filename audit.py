import argparse
import json
import platform
import shutil
import getpass
import sys
from pathlib import Path
from datetime import datetime, timezone

from checks.ssh_audit import audit_effective_sshd_config, audit_ssh_config_file


def collect_system_info():
    disk = shutil.disk_usage(Path.home())

    return {
        "hostname": platform.node(),
        "operating_system": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "current_user": getpass.getuser(),
        "home_directory": str(Path.home()),
        "disk_total_gb": round(disk.total / (1024 ** 3), 2),
        "disk_free_gb": round(disk.free / (1024 ** 3), 2),
    }


def build_report(ssh_config_path=None):
    findings = []

    if ssh_config_path is not None:
        findings = audit_ssh_config_file(ssh_config_path)

    summary = {
        "total_findings": len(findings),
        "pass": sum(item["status"] == "PASS" for item in findings),
        "review": sum(item["status"] == "REVIEW" for item in findings),
        "high": sum(item["severity"] == "HIGH" for item in findings),
        "medium": sum(item["severity"] == "MEDIUM" for item in findings),
        "info": sum(item["severity"] == "INFO" for item in findings),
    }

    return {
        "tool": "Linux Security Audit Toolkit",
        "report_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "system": collect_system_info(),
        "summary": summary,
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Linux Security Audit Toolkit"
    )
    parser.add_argument(
        "--ssh-config",
        help="Path to a local SSH configuration file to audit",
    )
    parser.add_argument(
        "--effective-ssh",
        action="store_true",
        help="Audit effective SSH daemon settings using sshd -T",
    )
    parser.add_argument(
        "--output",
        help="Optional path to save the JSON report",
    )
    args = parser.parse_args()

    if args.ssh_config:
        config_path = Path(args.ssh_config)

        if not config_path.is_file():
            print(
                f"ERROR: SSH configuration file not found: {config_path}",
                file=sys.stderr,
            )
            return 2

        try:
            if not config_path.read_bytes():
                print(
                    "ERROR: SSH configuration file is empty.",
                    file=sys.stderr,
                )
                return 2
        except OSError as exc:
            print(
                f"ERROR: Cannot read SSH configuration file: {exc}",
                file=sys.stderr,
            )
            return 2

    try:
        if args.effective_ssh and args.ssh_config:
            print(
                "ERROR: Use either --effective-ssh or --ssh-config, not both.",
                file=sys.stderr,
            )
            return 2

        if args.effective_ssh:
            findings = audit_effective_sshd_config()
            report = build_report()
            report["findings"] = findings
            report["summary"] = {
                "total_findings": len(findings),
                "pass": sum(item["status"] == "PASS" for item in findings),
                "review": sum(item["status"] == "REVIEW" for item in findings),
                "high": sum(item["severity"] == "HIGH" for item in findings),
                "medium": sum(item["severity"] == "MEDIUM" for item in findings),
                "info": sum(item["severity"] == "INFO" for item in findings),
            }
        else:
            report = build_report(args.ssh_config)
        output = json.dumps(report, indent=2, ensure_ascii=False)

        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(output + "\n", encoding="utf-8")
            print(f"Report saved to: {output_path}")
        else:
            print(output)

    except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
        print(f"ERROR: Audit failed: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
