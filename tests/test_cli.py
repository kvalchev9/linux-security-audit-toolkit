import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_SCRIPT = PROJECT_ROOT / "audit.py"


class TestCLIValidation(unittest.TestCase):

    def run_audit(self, config_path):
        return subprocess.run(
            [
                sys.executable,
                str(AUDIT_SCRIPT),
                "--ssh-config",
                str(config_path),
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )

    def test_missing_config_returns_exit_code_2(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            missing = Path(temp_dir) / "missing.conf"
            result = self.run_audit(missing)

        self.assertEqual(result.returncode, 2)
        self.assertIn("not found", result.stderr)

    def test_empty_config_returns_exit_code_2(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            empty = Path(temp_dir) / "empty.conf"
            empty.write_text("", encoding="utf-8")
            result = self.run_audit(empty)

        self.assertEqual(result.returncode, 2)
        self.assertIn("empty", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
