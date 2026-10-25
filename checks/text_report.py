from datetime import datetime


def format_text_report(report: dict) -> str:
    """Format an audit report as readable plain text."""
    system = report["system"]
    summary = report["summary"]
    findings = report["findings"]

    lines = [
        report["tool"],
        "=" * len(report["tool"]),
        f"Generated at: {report['generated_at']}",
        "",
        "SYSTEM INFORMATION",
        "-" * 18,
        f"Hostname: {system['hostname']}",
        f"Operating system: {system['operating_system']}",
        f"OS release: {system['os_release']}",
        f"Architecture: {system['architecture']}",
        f"Python version: {system['python_version']}",
        "",
        "AUDIT SUMMARY",
        "-" * 13,
        f"Total findings: {summary['total_findings']}",
        f"PASS: {summary['pass']}",
        f"REVIEW: {summary['review']}",
        f"HIGH: {summary['high']}",
        f"MEDIUM: {summary['medium']}",
        f"INFO: {summary['info']}",
        "",
        "FINDINGS",
        "-" * 8,
    ]

    if not findings:
        lines.append("No findings were generated.")
    else:
        for index, finding in enumerate(findings, start=1):
            lines.extend([
                "",
                f"{index}. {finding['check']}",
                f"   Status: {finding['status']}",
                f"   Severity: {finding['severity']}",
                f"   Evidence: {finding['evidence']}",
                f"   Recommendation: {finding['recommendation']}",
            ])

    return "\n".join(lines) + "\n"
