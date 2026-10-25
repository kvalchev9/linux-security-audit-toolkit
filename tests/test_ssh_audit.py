import unittest
from checks.ssh_audit import (
    parse_sshd_config_text,
    audit_ssh_config_text,
)


class TestSSHConfigParser(unittest.TestCase):

    def test_parses_supported_settings(self):
        text = """
PermitRootLogin no
PasswordAuthentication yes
"""
        result = parse_sshd_config_text(text)

        self.assertEqual(result["permitrootlogin"], "no")
        self.assertEqual(result["passwordauthentication"], "yes")

    def test_ignores_comments(self):
        text = """
# PermitRootLogin yes
PasswordAuthentication no
"""
        result = parse_sshd_config_text(text)

        self.assertNotIn("permitrootlogin", result)
        self.assertEqual(result["passwordauthentication"], "no")

    def test_flags_root_login_yes(self):
        findings = audit_ssh_config_text(
            "PermitRootLogin yes\nPasswordAuthentication no\n"
        )

        root_check = next(
            f for f in findings
            if f["check"] == "ssh_permit_root_login"
        )

        self.assertEqual(root_check["status"], "REVIEW")
        self.assertEqual(root_check["severity"], "HIGH")

    def test_passes_root_login_no(self):
        findings = audit_ssh_config_text(
            "PermitRootLogin no\nPasswordAuthentication no\n"
        )

        root_check = next(
            f for f in findings
            if f["check"] == "ssh_permit_root_login"
        )

        self.assertEqual(root_check["status"], "PASS")

    def test_flags_password_authentication(self):
        findings = audit_ssh_config_text(
            "PermitRootLogin no\nPasswordAuthentication yes\n"
        )

        password_check = next(
            f for f in findings
            if f["check"] == "ssh_password_authentication"
        )

        self.assertEqual(password_check["status"], "REVIEW")

    def test_missing_settings_are_reviewed(self):
        findings = audit_ssh_config_text("# No active settings\n")

        self.assertEqual(len(findings), 2)
        self.assertTrue(
            all(f["status"] == "REVIEW" for f in findings)
        )


if __name__ == "__main__":
    unittest.main()
