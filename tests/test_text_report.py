import unittest

from checks.text_report import format_text_report


class TestTextReport(unittest.TestCase):
    def setUp(self):
        self.report = {
            "tool": "Linux Security Audit Toolkit",
            "generated_at": "2026-10-25T12:00:00+00:00",
            "system": {
                "hostname": "test-host",
                "operating_system": "Linux",
                "os_release": "test-release",
                "architecture": "x86_64",
                "python_version": "3.14.4",
            },
            "summary": {
                "total_findings": 1,
                "pass": 0,
                "review": 1,
                "high": 1,
                "medium": 0,
                "info": 0,
            },
            "findings": [
                {
                    "check": "ssh_permit_root_login",
                    "status": "REVIEW",
                    "severity": "HIGH",
                    "evidence": "PermitRootLogin yes",
                    "recommendation": "Disable direct root SSH login.",
                }
            ],
        }

    def test_includes_system_and_summary(self):
        output = format_text_report(self.report)

        self.assertIn("Hostname: test-host", output)
        self.assertIn("Total findings: 1", output)
        self.assertIn("HIGH: 1", output)

    def test_includes_finding_and_recommendation(self):
        output = format_text_report(self.report)

        self.assertIn("PermitRootLogin yes", output)
        self.assertIn("Disable direct root SSH login.", output)
        self.assertIn("Status: REVIEW", output)

    def test_handles_empty_findings(self):
        self.report["findings"] = []
        output = format_text_report(self.report)

        self.assertIn("No findings were generated.", output)
        self.assertIn("Total findings: 1", output)


if __name__ == "__main__":
    unittest.main()
