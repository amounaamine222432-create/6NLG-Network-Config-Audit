"""V76 safeguards: line navigation, redacted HTML and before/after UI."""
from pathlib import Path
import importlib.util
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("cis_failure_summary_v76", ROOT / "webapp/cis_failure_summary.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
guidance_spec = importlib.util.spec_from_file_location("cis_explanations_v76", ROOT / "webapp/cis_explanations.py")
guidance = importlib.util.module_from_spec(guidance_spec)
guidance_spec.loader.exec_module(guidance)


class Phase3V76Tests(unittest.TestCase):
    def test_remediation_html_escapes_untrusted_text_and_has_anchors(self):
        result = module.failure_summary_html({"hostname": "R1<script>", "findings": [{
            "status": "FAIL", "cis_control_id": "1.2.9", "title": "<img src=x>",
            "risk_level": "HIGH", "observed_summary": "telnet<bad>",
            "source_anchors": [{"line": 42, "scope": "ligne de directive"}],
            "remediation": "transport input ssh", "remediation_example": "line vty 0 4\n transport input ssh",
            "verification_command": "show running-config | section line vty"}]})
        self.assertIn(b"L42", result)
        self.assertIn(b"transport input ssh", result)
        self.assertIn(b"&lt;script&gt;", result)
        self.assertNotIn(b"<img src=x>", result)

    def test_report_links_real_source_line_and_highlights_only_fail_directives(self):
        template = (ROOT / "webapp/templates/report_cis_ios.html").read_text()
        self.assertIn('id="src-L{{ line.number }}"', template)
        self.assertIn('href="#src-L{{ anchor.line }}"', template)
        self.assertIn('source-alert', template)
        self.assertIn('ligne de directive', template)

    def test_compare_section_is_removed_without_affecting_audit(self):
        script = (ROOT / "webapp/static/js/cis_audit.js").read_text()
        page = (ROOT / "webapp/templates/index.html").read_text()
        css = (ROOT / "webapp/static/css/cis_audit.css").read_text()
        self.assertNotIn("cisAfterFile", page)
        self.assertNotIn("cisCompareBtn", script)
        self.assertNotIn("cis-compare-panel", css)
        self.assertIn('id="cisRules"', page)
        self.assertIn('data.downloads.failures_html', script)

    def test_contextual_vty_ranges_without_untrusted_commands(self):
        finding = {"status": "FAIL", "observed_summary": "Telnet actif",
                   "evidence": {"vty_lines": [
                       {"line_id": "vty 0 4"}, {"line_id": "vty 5 15"},
                       {"line_id": "vty 0 4; reload"}]}}
        guidance.enrich_explanation(finding, "vty_ssh_only")
        self.assertIn("line vty 5 15", finding["remediation_example"])
        self.assertNotIn("reload", finding["remediation_example"])


if __name__ == "__main__":
    unittest.main()
