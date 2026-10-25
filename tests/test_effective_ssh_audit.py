import subprocess
import unittest
from unittest.mock import patch, Mock

from checks.ssh_audit import audit_effective_sshd_config


class TestEffectiveSSHAudit(unittest.TestCase):
    @patch("subprocess.run")
    def test_audits_effective_settings(self, mock_run):
        mock_run.return_value = Mock(
            returncode=0,
            stdout=(
                "permitrootlogin no\n"
                "passwordauthentication no\n"
                "pubkeyauthentication yes\n"
            ),
            stderr="",
        )

        findings = audit_effective_sshd_config(
            config_path="/tmp/sshd_config",
            sshd_path="/usr/sbin/sshd",
        )

        self.assertEqual(len(findings), 3)
        self.assertTrue(all(item["status"] == "PASS" for item in findings))
        mock_run.assert_called_once_with(
            ["/usr/sbin/sshd", "-T", "-f", "/tmp/sshd_config"],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )

    @patch("subprocess.run")
    def test_raises_error_when_sshd_fails(self, mock_run):
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="configuration error",
        )

        with self.assertRaisesRegex(RuntimeError, "configuration error"):
            audit_effective_sshd_config()

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired("sshd", 15))
    def test_raises_error_on_timeout(self, mock_run):
        with self.assertRaisesRegex(RuntimeError, "Unable to run sshd -T"):
            audit_effective_sshd_config()


if __name__ == "__main__":
    unittest.main()
