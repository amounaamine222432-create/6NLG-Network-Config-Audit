"""Contrat Flask Junos v2.4 : couverture combinée et inventaire de politiques."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path
import re
import unittest

from webapp import create_app


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures_juniper_v24"


class JuniperFlaskUnionV24Tests(unittest.TestCase):
    def test_four_files_share_report_with_combined_coverage(self):
        files = sorted(p for p in FIXTURES.iterdir() if p.name[:2] in {"01", "02", "03", "04"})
        self.assertEqual(len(files), 4)
        app = create_app({"TESTING": True, "SECRET_KEY": "coverage-union-v24"})
        client = app.test_client()
        page = client.get("/")
        token = re.search(rb'<meta name="csrf-token" content="([^"]+)"', page.data).group(1).decode()
        response = client.post(
            "/api/analyze",
            data={"vendor": "juniper_junos",
                  "files": [(BytesIO(path.read_bytes()), path.name) for path in files]},
            headers={"X-CSRF-Token": token}, content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        payload = response.get_json()
        self.assertEqual(payload["metrics"]["devices"], 4)
        self.assertEqual(payload["metrics"]["unknowns"], 0)
        self.assertTrue(all(device["coverage"]["combined_unmodeled"] == 0
                            for device in payload["devices"]))
        self.assertTrue(all(device["status"] == "a_verifier" for device in payload["devices"]))

        ir_resp = client.get(payload["downloads"]["ir"])
        self.assertEqual(ir_resp.status_code, 200)
        irs = {item["ir"]["source"]["file"]: item["ir"]
               for item in ir_resp.get_json()["devices"]}
        core = irs["04_JUNOS_COMPLET_ROUTAGE_VRF.conf"]
        self.assertEqual(core["policies"]["junos_prefix_lists"][0]["name"], "LAB-PREFIXES")
        self.assertEqual(core["diagnostics"]["source_only_counts"]["combined_unmodeled_leaves"], 0)

        report = client.get(payload["downloads"]["html"])
        self.assertEqual(report.status_code, 200)
        text = report.get_data(as_text=True)
        self.assertIn("Couverture combinée", text)
        self.assertIn("junos_prefix_lists", text)
        self.assertIn("source_nat_rules", str(irs["02_SRX_ACL_NAT_display_set.txt"]))


if __name__ == "__main__":
    unittest.main()
