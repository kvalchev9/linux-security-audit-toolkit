import unittest
from audit import collect_system_info


class TestSystemInfo(unittest.TestCase):

    def test_returns_dictionary(self):
        result = collect_system_info()
        self.assertIsInstance(result, dict)

    def test_required_fields_exist(self):
        result = collect_system_info()

        required_fields = [
            "hostname",
            "operating_system",
            "os_release",
            "architecture",
            "python_version",
            "current_user",
            "home_directory",
            "disk_total_gb",
            "disk_free_gb",
        ]

        for field in required_fields:
            with self.subTest(field=field):
                self.assertIn(field, result)

    def test_disk_values_are_valid(self):
        result = collect_system_info()

        self.assertGreater(result["disk_total_gb"], 0)
        self.assertGreaterEqual(result["disk_free_gb"], 0)
        self.assertLessEqual(
            result["disk_free_gb"],
            result["disk_total_gb"],
        )

    def test_python_version_is_present(self):
        result = collect_system_info()
        self.assertTrue(result["python_version"])


if __name__ == "__main__":
    unittest.main()
