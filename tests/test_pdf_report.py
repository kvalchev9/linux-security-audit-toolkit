import tempfile
import unittest
from pathlib import Path

from pypdf import PdfReader

from checks.pdf_report import format_pdf_report


class TestPDFReport(unittest.TestCase):
    def setUp(self):
        self.report = {
            "tool": "Linux Security Audit Toolkit",
            "report_version": "1.0",
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
                    "recommendation": (
                        "Disable direct root SSH login where possible."
                    ),
                }
            ],
        }

    def test_generates_valid_pdf(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "report.pdf"

            format_pdf_report(self.report, output_path)

            self.assertTrue(output_path.is_file())
            self.assertGreater(output_path.stat().st_size, 0)

            with output_path.open("rb") as pdf_file:
                self.assertEqual(pdf_file.read(5), b"%PDF-")

    def test_pdf_contains_report_content(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "report.pdf"

            format_pdf_report(self.report, output_path)

            reader = PdfReader(str(output_path))
            extracted_text = "\n".join(
                page.extract_text() or "" for page in reader.pages
            )

            self.assertIn("Linux Security Audit Toolkit", extracted_text)
            self.assertIn("ssh_permit_root_login", extracted_text)
            self.assertIn("PermitRootLogin yes", extracted_text)
            self.assertIn("Scope and Limitations", extracted_text)


if __name__ == "__main__":
    unittest.main()
