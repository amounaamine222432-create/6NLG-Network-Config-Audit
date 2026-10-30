"""Verify held-out checker rejects exact duplicates and incompatible inputs."""

import json
import tempfile
import unittest
from pathlib import Path

from scripts.validate_holdout_v66 import check_holdout


class HeldoutCheckV66(unittest.TestCase):
    def test_exact_duplicate_is_flagged(self):
        with tempfile.TemporaryDirectory() as dirname:
            root = Path(dirname)
            base = root / "baseline.cfg"
            fresh = root / "copy.cfg"
            body = "version 15.9\nhostname R\ninterface Loopback0\n ip address 192.0.2.1 255.255.255.255\n"
            base.write_text(body)
            fresh.write_text(body)
            report = check_holdout([fresh], [base])
            self.assertEqual(report[0]["status"], "duplicate")

    def test_xr_is_rejected_as_ios(self):
        with tempfile.TemporaryDirectory() as dirname:
            root = Path(dirname)
            base = root / "baseline.cfg"
            candidate = root / "xr.cfg"
            base.write_text("version 15.9\nhostname R\n")
            candidate.write_text("!! IOS XR Configuration 26.1.1\nhostname PE\n")
            report = check_holdout([candidate], [base])
            self.assertEqual(report[0]["status"], "incompatible_or_unknown_dialect")

    def test_report_has_no_configuration_secrets(self):
        with tempfile.TemporaryDirectory() as dirname:
            root = Path(dirname)
            base = root / "baseline.cfg"
            candidate = root / "ce.cfg"
            base.write_text("version 15.9\nhostname BASE\n")
            candidate.write_text(
                "version 15.9\nhostname CE\n"
                "username admin secret 0 SECRET_NE_JAMAIS_EXPORTER\n"
            )
            report = check_holdout([candidate], [base])
            self.assertEqual(report[0]["status"], "passed")
            self.assertNotIn("SECRET_NE_JAMAIS_EXPORTER", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
