import unittest
from checks.ssh_audit import (
    parse_sshd_config_text,
    audit_ssh_config_text,
)


class TestSSHInvalidValues(unittest.TestCase):

    def test_invalid_root_login_value_is_reviewed(self):
        findings = audit_ssh_config_text(
            "PermitRootLogin maybe\nPasswordAuthentication no\n"
        )

        root_check = next(
            f for f in findings
            if f["check"] == "ssh_permit_root_login"
        )

        self.assertEqual(root_check["status"], "REVIEW")
        self.assertIn("Unrecognized value", root_check["evidence"])

    def test_invalid_password_auth_value_is_reviewed(self):
        findings = audit_ssh_config_text(
            "PermitRootLogin no\nPasswordAuthentication maybe\n"
        )

        password_check = next(
            f for f in findings
            if f["check"] == "ssh_password_authentication"
        )

        self.assertEqual(password_check["status"], "REVIEW")
        self.assertIn("maybe", password_check["evidence"])

    def test_case_insensitive_settings(self):
        result = parse_sshd_config_text(
            "permitrootlogin NO\npasswordauthentication YES\n"
        )

        self.assertEqual(result["permitrootlogin"], "no")
        self.assertEqual(result["passwordauthentication"], "yes")


if __name__ == "__main__":
    unittest.main()
