import unittest

from audit_engine.rule_engine import evaluate_rules


class TestRuleEngine(unittest.TestCase):
    def setUp(self):
        self.ir = {
            "source": {"vendor": "cisco_ios", "file": "test.cfg"},
            "device": {"hostname": "R-TEST"},
            "management": {"http_enabled": False},
        }
        self.rule = {
            "id": "DEMO-1", "title": "HTTP disabled", "benchmark_ref": None,
            "status": "demo", "ir_path": "management.http_enabled",
            "operator": "equals", "expected": False,
            "remediation": "no ip http server",
        }

    def _first(self, *, allow_demo=True):
        return evaluate_rules(self.ir, [self.rule], allow_demo=allow_demo)["findings"][0]

    def test_pass_when_false(self):
        self.assertEqual(self._first()["status"], "PASS")

    def test_fail_when_true(self):
        self.ir["management"]["http_enabled"] = True
        self.assertEqual(self._first()["status"], "FAIL")
        self.assertEqual(self._first()["remediation"], "no ip http server")

    def test_unknown_when_missing_or_none(self):
        self.ir["management"].pop("http_enabled")
        self.assertEqual(self._first()["status"], "UNKNOWN")
        self.ir["management"]["http_enabled"] = None
        self.assertEqual(self._first()["status"], "UNKNOWN")

    def test_demo_requires_explicit_permission(self):
        self.assertEqual(self._first(allow_demo=False)["status"], "NOT_EVALUATED")

    def test_no_arbitrary_path_to_secret(self):
        self.rule["ir_path"] = "management.local_accounts"
        with self.assertRaises(ValueError):
            self._first()

    def test_reject_non_cisco_ir(self):
        self.ir["source"]["vendor"] = "juniper_junos"
        with self.assertRaises(ValueError):
            self._first()


if __name__ == "__main__":
    unittest.main()
