"""Phase 6: the 39 CIS controls are linked to the existing Flask parsing/IR workflow."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path
import re
import unittest

from webapp import create_app


ROOT = Path(__file__).resolve().parents[2]


class FlaskCisPhase6Tests(unittest.TestCase):
    def setUp(self):
        self.client = create_app({"TESTING": True, "SECRET_KEY": "test-phase6-only"}).test_client()
        home = self.client.get("/")
        self.assertEqual(home.status_code, 200)
        html = home.get_data(as_text=True)
        self.assertIn('id="cis-audit"', html)
        # Current UI audits an already parsed/normalized device rather than
        # accepting a second independent file upload in its CIS panel.
        self.assertIn('id="cisSourceSelect"', html)
        self.assertIn('id="cisForm"', html)
        self.assertIn('id="cisSourceIrJson"', html)
        self.assertIn('id="cisPreviewLink"', html)
        self.assertIn('id="cisCompleteConfig"', html)
        self.assertNotIn('id="cisFileInput"', html)
        self.assertIn('id="cisResults"', html)
        self.assertIn('data-tab="normalization"', html)  # existing features retained
        self.csrf = re.search(r'<meta name="csrf-token" content="([^"]+)"', html).group(1)

    def upload(self, fixture="router_compliant.cfg", *, profile="L2", complete=True,
               external="GigabitEthernet0/0", csrf=None, filename=None, data=None):
        body = data if data is not None else (ROOT / "data" / "cis_phase5" / fixture).read_bytes()
        fields = {
            "file": (BytesIO(body), filename or fixture),
            "profile": profile,
            "assume_complete": "true" if complete else "false",
        }
        if external is not None:
            fields["external_interface"] = external
        return self.client.post("/api/cis/audit", data=fields, content_type="multipart/form-data",
                                headers={"X-CSRF-Token": self.csrf if csrf is None else csrf})

    def test_three_phase5_cases_remain_identical(self):
        for fixture, complete, external, expected in (
            ("router_compliant.cfg", True, "GigabitEthernet0/0", (36, 0, 0, 3)),
            ("router_non_compliant.cfg", True, "GigabitEthernet0/0", (2, 33, 0, 4)),
            ("router_partial.cfg", False, None, (1, 0, 38, 0)),
        ):
            with self.subTest(fixture=fixture):
                response = self.upload(fixture, complete=complete, external=external)
                self.assertEqual(response.status_code, 200, response.get_json())
                body = response.json
                self.assertEqual(body["report"]["implemented_rule_count"], 39)
                self.assertEqual(tuple(body["report"]["counts"][status]
                                       for status in ("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE")), expected)
                self.assertEqual(len(body["summary"]["groups"]), 3)
                self.assertEqual(sum(group["total"] for group in body["summary"]["groups"]), 39)

    def test_report_is_distinct_and_downloads_have_protected_access(self):
        body = self.upload().json
        self.assertTrue(body["ok"])
        self.assertEqual(body["summary"]["assessed"], 36)
        self.assertEqual(body["summary"]["pass_percent_of_assessed"], 100.0)
        for kind in ("json", "html"):
            response = self.client.get(body["downloads"][kind])
            self.assertEqual(response.status_code, 200)
            self.assertIn("attachment", response.headers["Content-Disposition"])
            self.assertNotIn("LAB_ONLY_NTP", response.get_data(as_text=True))
            self.assertNotIn("LAB_ONLY_OSPF", response.get_data(as_text=True))
            self.assertNotIn("LAB_ONLY_EIGRP", response.get_data(as_text=True))
        html = self.client.get(body["html_preview"])
        self.assertEqual(html.status_code, 200)
        self.assertIn("text/html", html.content_type)
        self.assertIn("CONFIGURATION SECURITY POSTURE", html.get_data(as_text=True))
        self.assertIn("Preuve technique structurée", html.get_data(as_text=True))
        self.assertEqual(html.headers["X-Frame-Options"], "SAMEORIGIN")
        self.assertIn("script-src 'none'", html.headers["Content-Security-Policy"])
        self.assertEqual(self.client.get(f'/api/view/{body["run_id"]}/html').status_code, 404)
        self.assertEqual(self.client.get(f'/api/download/{body["run_id"]}/html').status_code, 404)
        another = create_app({"TESTING": True, "SECRET_KEY": "separate"}).test_client()
        self.assertEqual(another.get(body["html_preview"]).status_code, 404)
        self.assertEqual(another.get(body["downloads"]["json"]).status_code, 404)

    def test_explicit_completeness_only_and_L1_is_selectable(self):
        partial = self.upload("router_partial.cfg", complete=False, external=None).json
        self.assertEqual(partial["report"]["counts"]["UNKNOWN"], 38)
        level1 = self.upload(profile="L1").json
        self.assertGreater(level1["report"]["counts"]["NOT_SELECTED"], 0)
        self.assertLess(level1["summary"]["selected"], 39)

    def test_web_form_forwards_completeness_to_the_cis_api(self):
        """The current browser workflow must not silently force partial mode."""
        js = (ROOT / "webapp/static/js/cis_audit.js").read_text(encoding="utf-8")
        self.assertIn('$("cisCompleteConfig").checked ? "true" : "false"', js)
        self.assertIn('payload.append("assume_complete"', js)
        full = self.upload("router_compliant.cfg", complete=True).json
        partial = self.upload("router_compliant.cfg", complete=False).json
        self.assertTrue(full["report"]["complete_config_assumed"])
        self.assertFalse(partial["report"]["complete_config_assumed"])

    def test_input_and_csrf_validation(self):
        self.assertEqual(self.upload(csrf="wrong").status_code, 403)
        self.assertEqual(self.upload(filename="router.yaml").status_code, 422)
        self.assertEqual(self.upload(data=b"\x00garbage").status_code, 422)
        self.assertEqual(self.upload(data=b"X" * (1024 * 1024 + 1)).status_code, 422)
        self.assertEqual(self.upload(profile="L9").status_code, 400)
        self.assertEqual(self.upload(external="NonexistentInterface").status_code, 400)
        xr = b"!! IOS XR Configuration 7.3.2\nhostname R-XR\ninterface Loopback0\n ipv4 address 10.0.0.1 255.255.255.255\n"
        self.assertEqual(self.upload(data=xr).status_code, 422)

    def test_existing_pipeline_still_serves_its_reports(self):
        cis = self.upload().json
        fixture = (ROOT / "data" / "cis_phase5" / "router_compliant.cfg").read_bytes()
        legacy = self.client.post("/api/analyze", data={"files": [(BytesIO(fixture), "legacy.cfg")]},
                                  content_type="multipart/form-data", headers={"X-CSRF-Token": self.csrf})
        self.assertEqual(legacy.status_code, 200, legacy.get_json())
        for kind in ("html", "parsing", "ir", "summary"):
            self.assertEqual(self.client.get(legacy.json["downloads"][kind]).status_code, 200)
        self.assertEqual(self.client.get(cis["html_preview"]).status_code, 200)


if __name__ == "__main__":
    unittest.main()
