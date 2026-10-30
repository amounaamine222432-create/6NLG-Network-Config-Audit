"""Validation de l'intégration Flask dans le dépôt Network Config Audit."""

from io import BytesIO
import re
import unittest

from webapp import create_app


SAMPLE = """!
version 15.2
hostname R-TEST-FLASK
!
interface GigabitEthernet0/0
 description WAN Link
 ip address 192.0.2.1 255.255.255.0
 no shutdown
!
router ospf 10
 network 192.0.2.0 0.0.0.255 area 0
!
snmp-server community SensitiveCanary987 RO
logging host 198.51.100.3
end
"""

SAMPLE_ADVANCED = """!
version 15.9
hostname R-BILAN-02
!
interface GigabitEthernet0/0
 ip address 10.10.10.1 255.255.255.0
 ip nat inside
 no shutdown
!
interface GigabitEthernet0/1
 ip address 203.0.113.1 255.255.255.252
 ip nat outside
 no shutdown
!
router bgp 65001
 bgp router-id 10.10.10.1
 neighbor 203.0.113.2 remote-as 65002
 network 10.10.10.0 mask 255.255.255.0
!
ip access-list standard NAT_ACL
 permit 10.10.10.0 0.0.0.255
!
ip dhcp pool USERS
 network 10.10.10.0 255.255.255.0
 default-router 10.10.10.1
 dns-server 192.0.2.53
 lease 1
!
ip nat inside source list NAT_ACL interface GigabitEthernet0/1 overload
end
"""


class WebAppTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app({"TESTING": True, "SECRET_KEY": "only-for-tests"}).test_client()
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Votre r", response.data)
        match = re.search(rb'<meta name="csrf-token" content="([^"]+)"', response.data)
        self.assertIsNotNone(match)
        self.csrf = match.group(1).decode("ascii")

    def submit(self, *files, csrf=None):
        streams = [(BytesIO(body.encode("utf-8")), name) for name, body in files]
        try:
            return self.client.post(
                "/api/analyze",
                data={"files": streams},
                content_type="multipart/form-data",
                headers={"X-CSRF-Token": self.csrf if csrf is None else csrf},
            )
        finally:
            for stream, _name in streams:
                stream.close()

    def test_health_and_dashboard_assets(self):
        health = self.client.get("/api/health")
        self.assertEqual(health.json["mode"], "static_local")
        with self.client.get("/static/css/app.css") as stylesheet:
            self.assertEqual(stylesheet.status_code, 200)
        with self.client.get("/static/js/app.js") as javascript:
            self.assertEqual(javascript.status_code, 200)

    def test_existing_cisco_parser_normalizer_and_report_are_used(self):
        response = self.submit(("edge.cfg", SAMPLE))
        self.assertEqual(response.status_code, 200, response.get_json())
        payload = response.get_json()
        self.assertEqual(payload["metrics"]["devices"], 1)
        self.assertEqual(payload["devices"][0]["hostname"], "R-TEST-FLASK")
        self.assertGreaterEqual(payload["metrics"]["interfaces"], 1)
        self.assertEqual(payload["devices"][0]["coverage"]["global_unknown"], 0)
        self.assertNotIn("SensitiveCanary987", response.get_data(as_text=True))
        for kind in ("html", "ir", "summary", "parsing"):
            report = self.client.get(payload["downloads"][kind])
            self.assertEqual(report.status_code, 200)
            self.assertIn("attachment", report.headers["Content-Disposition"])
            self.assertNotIn("SensitiveCanary987", report.get_data(as_text=True))
        ir = self.client.get(payload["downloads"]["ir"]).get_json()
        self.assertEqual(len(ir["devices"]), 1)
        self.assertEqual(ir["devices"][0]["ir"]["device"]["hostname"], "R-TEST-FLASK")

    def test_parsing_ir_and_html_visible_in_the_dashboard(self):
        response = self.submit(("edge.cfg", SAMPLE), ("complex.cfg", SAMPLE_ADVANCED))
        self.assertEqual(response.status_code, 200, response.get_json())
        payload = response.json
        dashboard = self.client.get("/").get_data(as_text=True)
        for tab in ('data-tab="overview"', 'data-tab="parsing"', 'data-tab="normalization"', 'data-tab="report"'):
            self.assertIn(tab, dashboard)
        self.assertIn('id="downloadParsing"', dashboard)
        self.assertIn('data-tab="overview" role="tab" aria-selected="true"', dashboard)

        parsing = self.client.get(f'/api/view/{payload["run_id"]}/parsing')
        self.assertEqual(parsing.status_code, 200)
        self.assertIn("application/json", parsing.content_type)
        self.assertEqual(len(parsing.json["devices"]), 2)
        self.assertEqual(parsing.json["devices"][0]["parsed"]["hostname"], "R-TEST-FLASK")
        self.assertEqual(parsing.json["devices"][0]["parsed"]["interfaces"][0]["ipv4_addresses"][0],
                         {"address": "192.0.2.1", "mask": "255.255.255.0"})
        self.assertEqual(parsing.json["devices"][1]["parsed"]["bgp_processes"][0]["local_as"], "65001")

        ir = self.client.get(f'/api/view/{payload["run_id"]}/ir')
        self.assertEqual(ir.status_code, 200)
        self.assertEqual(ir.json["devices"][0]["ir"]["device"]["hostname"], "R-TEST-FLASK")

        preview = self.client.get(f'/api/view/{payload["run_id"]}/html')
        self.assertEqual(preview.status_code, 200)
        self.assertIn("text/html", preview.content_type)
        self.assertIn("Bilan technique", preview.get_data(as_text=True))
        self.assertEqual(preview.headers["X-Frame-Options"], "SAMEORIGIN")
        self.assertIn("frame-ancestors 'self'", preview.headers["Content-Security-Policy"])
        self.assertIn("script-src 'none'", preview.headers["Content-Security-Policy"])
        self.assertEqual(ir.headers["X-Frame-Options"], "DENY")

    def test_batch_upload_preserves_all_results(self):
        response = self.submit(("one.cfg", SAMPLE), ("two.txt", SAMPLE.replace("R-TEST-FLASK", "R-TEST-02")))
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.json["metrics"]["devices"], 2)

    def test_html_report_contains_complete_technical_inventory(self):
        payload = self.submit(("edge.cfg", SAMPLE), ("complex.cfg", SAMPLE_ADVANCED)).json
        self.assertTrue(payload["ok"])
        report = self.client.get(payload["downloads"]["html"]).get_data(as_text=True)
        for expected in (
            "Bilan technique", "Interfaces réseau et adressage", "192.0.2.1/24",
            "router ospf 10", "network 192.0.2.0 0.0.0.255 area 0",
            "router bgp 65001", "neighbor 203.0.113.2 remote-as 65002",
            "ip dhcp pool USERS", "ip nat inside source list NAT_ACL",
            "ip access-list standard NAT_ACL", "Supervision SNMP",
            "logging host 198.51.100.3", "Contrôles d'audit et recommandations",
        ):
            self.assertIn(expected, report)
        self.assertNotIn("SensitiveCanary987", report)

    def test_report_escapes_untrusted_configuration_descriptions(self):
        malicious = SAMPLE.replace("WAN Link", "<img src=x onerror=alert(1)>")
        payload = self.submit(("bad-name.cfg", malicious)).json
        report = self.client.get(payload["downloads"]["html"]).get_data(as_text=True)
        self.assertNotIn("<img src=x", report)
        self.assertIn("&lt;img", report)

    def test_bgp_snmp_and_account_secrets_not_in_any_export(self):
        protected = SAMPLE_ADVANCED.replace(
            " neighbor 203.0.113.2 remote-as 65002",
            " neighbor 203.0.113.2 remote-as 65002\n neighbor 203.0.113.2 password CanaryBGP432",
        ).replace(
            "ip nat inside source list NAT_ACL interface GigabitEthernet0/1 overload",
            "ip nat inside source list NAT_ACL interface GigabitEthernet0/1 overload\n"
            "snmp-server community CanarySNMP432 RW\n"
            "username labadmin secret 0 CanaryUser432",
        )
        response = self.submit(("protected.cfg", protected))
        self.assertEqual(response.status_code, 200, response.get_json())
        payload = response.json
        for kind in ("html", "ir", "summary", "parsing"):
            content = self.client.get(payload["downloads"][kind]).get_data(as_text=True)
            for secret in ("CanaryBGP432", "CanarySNMP432", "CanaryUser432"):
                self.assertNotIn(secret, content)
        for kind in ("html", "ir", "parsing"):
            content = self.client.get(f'/api/view/{payload["run_id"]}/{kind}').get_data(as_text=True)
            for secret in ("CanaryBGP432", "CanarySNMP432", "CanaryUser432"):
                self.assertNotIn(secret, content)

    def test_bad_csrf_rejected(self):
        response = self.submit(("edge.cfg", SAMPLE), csrf="not-a-valid-token")
        self.assertEqual(response.status_code, 403)

    def test_invalid_extension_and_missing_input_rejected(self):
        self.assertEqual(self.submit(("private.yaml", SAMPLE)).status_code, 422)
        self.assertEqual(self.submit().status_code, 400)

    def test_large_input_rejected_without_persisting(self):
        response = self.submit(("big.cfg", SAMPLE + "!" * (1024 * 1024)))
        self.assertEqual(response.status_code, 422)

    def test_xr_is_not_accepted_as_classic_ios(self):
        xr = "!! IOS XR Configuration 7.3.2\nhostname R-XR\ninterface Loopback0\n ipv4 address 10.0.0.1 255.255.255.255\n"
        response = self.submit(("xr.cfg", xr))
        self.assertEqual(response.status_code, 422)

    def test_partial_batch_produces_results_and_rejections(self):
        xr = "!! IOS XR Configuration 7.3.2\nhostname R-XR\ninterface Loopback0\n ipv4 address 10.0.0.1 255.255.255.255\n"
        response = self.submit(("edge.cfg", SAMPLE), ("xr.cfg", xr))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["metrics"]["devices"], 1)
        self.assertEqual(len(response.json["file_errors"]), 1)

    def test_downloads_are_session_scoped(self):
        result = self.submit(("edge.cfg", SAMPLE)).json
        another = create_app({"TESTING": True, "SECRET_KEY": "other-session"}).test_client()
        self.assertEqual(another.get(result["downloads"]["html"]).status_code, 404)
        for kind in ("html", "ir", "parsing", "summary"):
            self.assertEqual(another.get(f'/api/view/{result["run_id"]}/{kind}').status_code, 404)
        self.assertEqual(self.client.get(f'/api/view/{result["run_id"]}/summary').status_code, 404)


if __name__ == "__main__":
    unittest.main()
