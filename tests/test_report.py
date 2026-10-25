import json
import tempfile
import unittest
from pathlib import Path

from audit import build_report


class TestAuditReport(unittest.TestCase):

    def test_report_contains_metadata_and_system_info(self):
        report = build_report()

        self.assertEqual(
            report["tool"],
            "Linux Security Audit Toolkit",
        )
        self.assertIn("generated_at", report)
        self.assertIn("system", report)
        self.assertIn("findings", report)
        self.assertIsInstance(report["findings"], list)

    def test_report_includes_ssh_findings(self):
        config = (
            "PermitRootLogin yes\n"
            "PasswordAuthentication yes\n"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "sshd_config"
            config_path.write_text(config, encoding="utf-8")

            report = build_report(config_path)

        findings = {
            item["check"]: item
            for item in report["findings"]
        }

        self.assertEqual(
            findings["ssh_permit_root_login"]["severity"],
            "HIGH",
        )
        self.assertEqual(
            findings["ssh_password_authentication"]["status"],
            "REVIEW",
        )

    def test_report_can_be_serialized_as_json(self):
        report = build_report()
        serialized = json.dumps(report)
        restored = json.loads(serialized)

        self.assertEqual(
            restored["tool"],
            "Linux Security Audit Toolkit",
        )

    def test_summary_counts_findings_correctly(self):
        report = build_report("tests/sample_sshd_config")
        summary = report["summary"]

        self.assertEqual(summary["total_findings"], 2)
        self.assertEqual(summary["pass"], 0)
        self.assertEqual(summary["review"], 2)
        self.assertEqual(summary["high"], 1)
        self.assertEqual(summary["medium"], 1)
        self.assertEqual(summary["info"], 0)

    def test_summary_is_zero_without_ssh_config(self):
        report = build_report()
        summary = report["summary"]

        self.assertEqual(summary["total_findings"], 0)
        self.assertEqual(summary["pass"], 0)
        self.assertEqual(summary["review"], 0)
        self.assertEqual(summary["high"], 0)
        self.assertEqual(summary["medium"], 0)
        self.assertEqual(summary["info"], 0)
if __name__ == "__main__":
    unittest.main()
