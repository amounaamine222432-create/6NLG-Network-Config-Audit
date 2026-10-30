"""Tests sans benchmark CIS réel (préserve les droits sur les documents)."""

from pathlib import Path
import tempfile
import unittest

from audit_engine.benchmark_importer import extract_candidates_from_pages, extract_pdf


class TestBenchmarkImporter(unittest.TestCase):
    def test_deduplicates_toc_and_prefers_complete_section(self):
        document = extract_candidates_from_pages(
            [
                "Table of Contents\n1.1.1 Ensure HTTP service is disabled\nPage 8\n",
                "1.1.1 Ensure HTTP service is disabled (Automated)\n"
                "Description:\nExample only\nAudit:\nCheck configuration\n"
                "Remediation:\nDisable HTTP service\n",
            ],
            source_name="synthetic.pdf", sha256="test", product="Cisco IOS",
            benchmark_version="TEST ONLY",
        )
        self.assertEqual(document["candidate_count"], 1)
        candidate = document["candidates"][0]
        self.assertEqual(candidate["control_id"], "1.1.1")
        self.assertEqual(candidate["source_page"], 2)
        self.assertEqual(candidate["audit_text"], "Check configuration")
        self.assertEqual(candidate["remediation_text"], "Disable HTTP service")
        self.assertEqual(candidate["status"], "review_required")
        self.assertEqual(candidate["extraction_confidence"], "high")

    def test_ignores_non_control_headings(self):
        document = extract_candidates_from_pages(
            ["2.4 Ensure test command is set\nDescription:\nExample only"],
            source_name="synthetic.pdf", sha256="test", product="Cisco IOS",
            benchmark_version="TEST ONLY",
        )
        self.assertEqual(document["candidate_count"], 0)
        self.assertEqual(document["skipped_heading_count"], 1)
        self.assertEqual(document["skipped_heading_ids"], ["2.4"])

    def test_real_pdf_text_layer_roundtrip(self):
        try:
            import fitz
        except ImportError:
            self.skipTest("PyMuPDF non disponible")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "synthetic.pdf"
            with fitz.open() as document:
                page = document.new_page()
                page.insert_text(
                    (72, 72),
                    "1.1.1 Ensure HTTP service is disabled\nAudit:\n"
                    "Inspect config\nRemediation:\nDisable HTTP service",
                )
                document.save(path)
            result = extract_pdf(path, product="Cisco IOS", benchmark_version="TEST")
            self.assertEqual(result["candidate_count"], 1)
            self.assertEqual(result["candidates"][0]["audit_text"], "Inspect config")

    def test_create_rule_verb_is_accepted(self):
        document = extract_candidates_from_pages(
            ["2.4.1 Create loopback interface (Automated)\nAudit:\nInspect\n"
             "Remediation:\nConfigure loopback"],
            source_name="synthetic.pdf", sha256="test", product="Cisco IOS",
            benchmark_version="TEST ONLY",
        )
        self.assertEqual(document["candidate_count"], 1)


if __name__ == "__main__":
    unittest.main()
