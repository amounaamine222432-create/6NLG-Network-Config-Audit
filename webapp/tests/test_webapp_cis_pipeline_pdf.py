"""Unified Cisco pipeline: evidence-based comparisons and two secure PDFs."""

from io import BytesIO
from pathlib import Path
import re
import unittest

from webapp import create_app


ROOT = Path(__file__).resolve().parents[2]


class CiscoPipelinePdfTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app({"TESTING": True, "SECRET_KEY": "pipeline-pdf-tests"}).test_client()
        home = self.client.get("/")
        self.assertIn(b'cisParsingPdf', home.data)
        self.assertIn(b'cisAuditPdf', home.data)
        self.csrf = re.search(rb'<meta name="csrf-token" content="([^\"]+)"', home.data).group(1).decode()

    def audit(self, fixture: str, *, complete: bool, external: str = ""):
        data = (ROOT / "data" / "cis_phase5" / fixture).read_bytes()
        return self.client.post("/api/cis/audit", data={
            "file": (BytesIO(data), fixture), "profile": "L2",
            "assume_complete": "true" if complete else "false",
            "external_interface": external,
        }, content_type="multipart/form-data", headers={"X-CSRF-Token": self.csrf})

    def test_two_pdfs_are_downloadable_and_not_legacy_exports(self):
        response = self.audit("router_non_compliant.cfg", complete=True,
                              external="GigabitEthernet0/0")
        self.assertEqual(response.status_code, 200, response.json)
        body = response.json
        self.assertEqual(body["report"]["counts"]["FAIL"], 33)
        for kind in ("parsing_pdf", "cis_pdf"):
            file_response = self.client.get(body["downloads"][kind])
            self.assertEqual(file_response.status_code, 200)
            self.assertEqual(file_response.mimetype, "application/pdf")
            self.assertTrue(file_response.data.startswith(b"%PDF-"))
            self.assertGreater(len(file_response.data), 10000)
            self.assertIn("attachment", file_response.headers["Content-Disposition"])
            self.assertEqual(file_response.headers["Cache-Control"], "no-store")
        self.assertEqual(self.client.get(f'/api/download/{body["run_id"]}/cis_pdf').status_code, 404)
        foreign = create_app({"TESTING": True, "SECRET_KEY": "different"}).test_client()
        self.assertEqual(foreign.get(body["downloads"]["cis_pdf"]).status_code, 404)

    def test_parsing_and_normalization_precede_audit_and_share_source(self):
        body = self.audit("router_compliant.cfg", complete=True,
                          external="GigabitEthernet0/0").json
        pipeline = body["pipeline"]
        self.assertEqual(pipeline["parsing"]["hostname"], body["report"]["hostname"])
        self.assertEqual(pipeline["parsing"]["counts"]["interfaces"], 2)
        self.assertEqual(pipeline["parsing"]["counts"]["ospf"], 1)
        self.assertEqual(pipeline["normalization"]["part_count"], 59)
        self.assertEqual(pipeline["normalization"]["mapped_cis_rule_count"], 39)
        self.assertEqual(len(pipeline["normalization"]["inventory"]), 59)

    def test_each_cis_rule_has_expected_observed_and_remediation(self):
        body = self.audit("router_non_compliant.cfg", complete=True,
                          external="GigabitEthernet0/0").json
        findings = body["report"]["findings"]
        self.assertEqual(len(findings), 39)
        for finding in findings:
            self.assertTrue(finding["benchmark_expected"], finding["rule_id"])
            self.assertTrue(finding["observed_summary"], finding["rule_id"])
            for field in ("technical_analysis", "security_impact", "source_location",
                          "ios_config_observed", "remediation_example",
                          "remediation_caution", "verification_command"):
                self.assertTrue(finding[field], (finding["rule_id"], field))
            if finding["status"] == "FAIL":
                self.assertTrue(finding["remediation"])
        aaa = next(f for f in findings if f["cis_control_id"] == "1.1.1")
        self.assertIn("Valeur IR: non", aaa["observed_summary"])
        ssh = next(f for f in findings if f["cis_control_id"] == "2.1.1.2")
        self.assertIn("Version SSH: 1", ssh["observed_summary"])
        vty = next(f for f in findings if f["cis_control_id"] == "1.2.2")
        self.assertIn("transport input telnet", vty["ios_config_observed"])
        self.assertIn("Telnet", vty["security_impact"])
        self.assertIn("transport input ssh", vty["remediation_example"])
        self.assertIn("show running-config", vty["verification_command"])
        html = self.client.get(body["html_preview"]).get_data(as_text=True)
        self.assertIn("Exigence du contrôle CIS", html)
        self.assertIn("Observation extraite de l'IR", html)
        self.assertIn("Analyse de l'écart", html)
        self.assertIn("Impact de sécurité", html)
        self.assertIn("Vérification en lecture seule", html)

    def test_partial_input_remains_unknown_with_both_reports(self):
        body = self.audit("router_partial.cfg", complete=False).json
        self.assertEqual(body["report"]["counts"]["UNKNOWN"], 38)
        for kind in ("parsing_pdf", "cis_pdf"):
            self.assertTrue(self.client.get(body["downloads"][kind]).data.startswith(b"%PDF-"))

    def test_source_provenance_and_actual_acl_names_from_ir(self):
        body = self.audit("router_non_compliant.cfg", complete=True,
                          external="GigabitEthernet0/0").json
        findings = {f["cis_control_id"]: f for f in body["report"]["findings"]}
        vty = findings["1.2.2"]
        self.assertTrue(any(a["line"] == 44 and a["scope"] == "début de bloc"
                            for a in vty["source_anchors"]))
        self.assertIn("ligne 44", vty["source_location"])
        mgmt = findings["1.2.4"]
        self.assertIn("show ip access-lists MGMT-OPEN", mgmt["verification_command"])
        self.assertTrue(any(a["line"] == 35 and a["scope"] == "ligne de règle ACL"
                            for a in mgmt["source_anchors"]))
        wan_acl = findings["3.2.1"]
        self.assertIn("show ip access-lists WAN-OPEN", wan_acl["verification_command"])
        self.assertNotIn("show ip access-lists WAN-IN", wan_acl["verification_command"])
        self.assertTrue(any(a["line"] == 38 for a in wan_acl["source_anchors"]))
        wan_interface = findings["3.2.2"]
        self.assertIn("show ip interface GigabitEthernet0/0", wan_interface["verification_command"])
        self.assertTrue(any(a["line"] == 19 and a["scope"] == "début de bloc"
                            for a in wan_interface["source_anchors"]))
        html = self.client.get(body["html_preview"]).get_data(as_text=True)
        self.assertIn("L38 · ACL WAN-OPEN", html)
        self.assertIn("show ip access-lists WAN-OPEN", html)

    def test_compliant_and_partial_verdicts_unchanged(self):
        compliant = self.audit("router_compliant.cfg", complete=True,
                               external="GigabitEthernet0/0").json["report"]
        self.assertEqual(compliant["counts"]["PASS"], 36)
        self.assertEqual(compliant["counts"]["NOT_APPLICABLE"], 3)
        findings = {f["cis_control_id"]: f for f in compliant["findings"]}
        self.assertIn("show ip access-lists MGMT-VTY", findings["1.2.4"]["verification_command"])
        self.assertIn("show ip access-lists WAN-IN", findings["3.2.1"]["verification_command"])
        partial = self.audit("router_partial.cfg", complete=False).json["report"]
        self.assertEqual(partial["counts"]["PASS"], 1)
        self.assertEqual(partial["counts"]["UNKNOWN"], 38)


if __name__ == "__main__":
    unittest.main()
