"""Contrats d'intégration de l'interface Flask Juniper avec l'IR v2.3."""

from __future__ import annotations

from io import BytesIO
import os
from pathlib import Path
import re
import unittest

from webapp import create_app


SAMPLE_SET = """set system host-name R-SRX-EXEMPLE
set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24
set interfaces pp0 unit 0 ppp-options pap local-name PRIVATE_USER_818
set interfaces pp0 unit 0 ppp-options pap local-password PRIVATE_PASS_818
set interfaces pp0 unit 0 pppoe-options service-name PRIVATE_ISP_818
set interfaces pp0 unit 0 pppoe-options underlying-interface ge-0/0/0.0
set routing-options static route 0.0.0.0/0 next-hop pp0.0
set security zones security-zone TRUST interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh
set security flow tcp-mss all-tcp mss 1452
set protocols stp
"""

SAMPLE_HIERARCHICAL = """system {
  host-name R-JUNOS-01;
}
interfaces {
  ge-0/0/0 {
    unit 0 {
      family inet {
        address 198.51.100.1/30;
      }
    }
  }
}
protocols {
  ospf {
    area 0.0.0.0 {
      interface ge-0/0/0.0;
    }
  }
}
"""


class JuniperFlaskTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app({"TESTING": True, "SECRET_KEY": "juniper-integration-tests"})
        self.client = self.app.test_client()
        home = self.client.get("/")
        self.assertEqual(home.status_code, 200)
        self.assertIn(b'option value="juniper_junos"', home.data)
        self.token = re.search(rb'<meta name="csrf-token" content="([^"]+)"', home.data).group(1).decode()

    def submit(self, filename: str, config: str, vendor: str = "juniper_junos"):
        return self.client.post(
            "/api/analyze", data={"vendor": vendor, "files": [(BytesIO(config.encode()), filename)]},
            headers={"X-CSRF-Token": self.token}, content_type="multipart/form-data",
        )

    def test_display_set_has_parser_ir_and_bilan_without_secrets(self):
        response = self.submit("router.cfg", SAMPLE_SET)
        self.assertEqual(response.status_code, 200, response.get_json())
        result = response.json
        self.assertEqual(result["vendor"], "juniper_junos")
        self.assertEqual(result["metrics"]["devices"], 1)
        self.assertEqual(result["devices"][0]["hostname"], "R-SRX-EXEMPLE")
        self.assertEqual(result["devices"][0]["format"], "junos_display_set")
        for kind in ("parsing", "ir", "html", "summary"):
            body = self.client.get(result["downloads"][kind])
            self.assertEqual(body.status_code, 200)
            self.assertIn("attachment", body.headers["Content-Disposition"])
            text = body.get_data(as_text=True)
            for secret in ("PRIVATE_USER_818", "PRIVATE_PASS_818", "PRIVATE_ISP_818"):
                self.assertNotIn(secret, text)
        preview = self.client.get(f'/api/view/{result["run_id"]}/parsing').json
        self.assertEqual(preview["devices"][0]["parsed"]["parser"], "clijson")
        self.assertIn("interfaces", preview["devices"][0]["parsed"]["sections_leaf_counts"])
        ir = self.client.get(f'/api/view/{result["run_id"]}/ir').json["devices"][0]["ir"]
        self.assertEqual(ir["source"]["file"], "router.cfg")
        self.assertEqual(ir["schema_version"], "2.0.0")
        self.assertTrue(ir["junos_details"]["auxiliary"]["security"]["zones"])
        html = self.client.get(f'/api/view/{result["run_id"]}/html').get_data(as_text=True)
        for expected in ("Bilan technique", "Interfaces et adressage", "Protocoles et routage",
                         "VRF et politiques", "Sécurité SRX", "192.0.2.1/24"):
            self.assertIn(expected, html)

    def test_hierarchical_conf_and_vendor_differentiation(self):
        response = self.submit("router.conf", SAMPLE_HIERARCHICAL)
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.json["devices"][0]["format"], "junos_hierarchical")
        self.assertGreaterEqual(response.json["metrics"]["interfaces"], 1)

    def test_rejects_wrong_vendor_and_ambiguous_input(self):
        self.assertEqual(self.submit("router.cfg", SAMPLE_SET, vendor="other").status_code, 400)
        self.assertEqual(self.submit("router.conf", SAMPLE_HIERARCHICAL, vendor="cisco_ios").status_code, 422)
        self.assertEqual(self.submit("router.cfg", "delete interfaces ge-0/0/0").status_code, 422)

    def test_markdown_is_supported_but_explicitly_partial(self):
        text = "## SRX demonstration\n" + SAMPLE_SET + "\nExample only.\n"
        response = self.submit("config.md", text)
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.json["devices"][0]["status"], "a_verifier")
        ir = self.client.get(response.json["downloads"]["ir"]).json
        self.assertEqual(ir["devices"][0]["ir"]["diagnostics"]["status"], "partial")
        report = self.client.get(response.json["downloads"]["html"]).get_data(as_text=True)
        self.assertIn("Document d&#39;exemple", report)

    def test_downloads_and_previews_are_private(self):
        response = self.submit("config.cfg", SAMPLE_SET)
        self.assertEqual(response.status_code, 200)
        payload = response.json
        outsider = create_app({"TESTING": True, "SECRET_KEY": "other-secret"}).test_client()
        for kind in ("html", "ir", "summary", "parsing"):
            self.assertEqual(outsider.get(payload["downloads"][kind]).status_code, 404)
        self.assertEqual(outsider.get(f'/api/view/{payload["run_id"]}/html').status_code, 404)

    def test_external_batfish_config_html_if_available(self):
        root = Path(os.environ.get("JUNIPER_BATFISH_DIR", "../juniper_sources/batfish-lab-validation/"
                                   "snapshots/junos_evpn_type5/source/configs"))
        candidate = root / "router1.cfg"
        if not candidate.exists():
            self.skipTest("Corpus Batfish externe absent")
        response = self.submit("router1.cfg", candidate.read_text(encoding="utf-8"))
        self.assertEqual(response.status_code, 200, response.get_json())
        payload = response.json
        report = self.client.get(payload["downloads"]["html"])
        self.assertEqual(report.status_code, 200)
        self.assertIn("Bilan technique", report.get_data(as_text=True))
        self.assertEqual(payload["devices"][0]["vendor"], "juniper_junos")


if __name__ == "__main__":
    unittest.main()
