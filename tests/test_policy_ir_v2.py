"""Compatibilité v2, régression v1 et sémantique Cisco/Junos explicite."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

from jsonschema import Draft202012Validator

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from normalizers.policy_ir_v2 import normalize_juniper_junos_v2, upgrade_cisco_ir_v1_to_v2  # noqa: E402


def _batfish() -> Path:
    return Path(os.getenv("JUNIPER_BATFISH_DIR") or PROJECT.parent / "juniper_sources" /
                "batfish-lab-validation" / "snapshots" / "junos_evpn_type5" / "source" / "configs")


def _junosphere() -> Path:
    return Path(os.getenv("JUNIPER_JUNOSPHERE_DIR") or PROJECT.parent / "juniper_sources" / "junosphere")


class PolicyIRV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = Draft202012Validator(json.loads(
            (PROJECT / "schemas" / "network_device_ir_v2.schema.json").read_text(encoding="utf-8")))

    def test_junos_batfish_six_schema_and_policy_semantics(self):
        files = sorted(_batfish().glob("*.cfg"))
        if not files:
            self.skipTest("Corpus Batfish externe manquant")
        self.assertEqual(len(files), 6)
        for path in files:
            with self.subTest(file=path.name):
                ir = normalize_juniper_junos_v2(path)
                self.assertFalse(list(self.schema.iter_errors(ir)))
                self.assertEqual(ir["schema_version"], "2.0.0")
                self.assertTrue(all(p["vendor_semantics"] == "junos"
                                    for p in ir["policies"]["route_policies"]))
                self.assertEqual(ir["diagnostics"]["status"], "partial")

    def test_junosphere_eighteen_schema(self):
        if not _junosphere().exists():
            self.skipTest("Corpus Junosphere externe manquant")
        files = [p for p in _junosphere().glob("*/configset/*.conf") if p.stat().st_size]
        self.assertEqual(len(files), 18)
        for path in files:
            self.assertFalse(list(self.schema.iter_errors(normalize_juniper_junos_v2(path))))

    def test_route_filter_orlonger_and_direct_then_accept(self):
        sample = _batfish() / "node1-1.cfg"
        if not sample.exists():
            self.skipTest("Fichier node1-1.cfg absent")
        ir = normalize_juniper_junos_v2(sample)
        export = next(p for p in ir["policies"]["route_policies"] if p["name"] == "export-underlay")
        term = export["terms"][0]
        self.assertEqual(term["name"], "loopbacks")
        self.assertIn({"kind": "route_filter", "prefix": "172.16.0.0/24", "modifier": "orlonger",
                       "source": {"line": None}}, term["conditions"])
        self.assertEqual([x["kind"] for x in term["actions"]], ["accept"])

    def test_community_set_and_references(self):
        sample = _batfish() / "node1-1.cfg"
        if not sample.exists():
            self.skipTest("Fichier node1-1.cfg absent")
        ir = normalize_juniper_junos_v2(sample)
        community = next(x for x in ir["policies"]["community_sets"] if x["name"] == "TENANT-A-RT")
        self.assertEqual(community["members"], ["target:65000:10000"])
        policy = next(p for p in ir["policies"]["route_policies"] if p["name"] == "TENANT-A-export")
        self.assertEqual(policy["terms"][0]["actions"][0]["kind"], "community_add")

    def test_unsupported_rule_is_not_falsely_normalized(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "unknown.conf"
            path.write_text("policy-options {\n policy-statement P {\n  term T {\n"
                            "   from { some-new-match cannot-model; }\n"
                            "   then { unsupported-action go; }\n  }\n }\n}\n", encoding="utf-8")
            ir = normalize_juniper_junos_v2(path)
            term = ir["policies"]["route_policies"][0]["terms"][0]
            self.assertTrue(term["unmodeled_condition_count"] or term["unmodeled_action_count"])
            self.assertEqual(term["actions"], [])

    def test_cisco_migration_keeps_semantics_distinct(self):
        from copy import deepcopy
        # IR v1 minimale valable pour le *convertisseur* (test indépendant
        # de la structure exacte des règles du parseur Cisco).
        original = {
            "schema_version": "1.0.0", "source": {"vendor": "cisco_ios"},
            "policies": {"route_maps": [{"name": "OUT", "entries": [{
                "sequence": 10, "action": "permit", "source": {"line": None},
                "operations": [{"operation": "match_prefix_list", "references": ["PFX"]}],
                "unmodeled_statement_count": 1,
            }]}]},
            "diagnostics": {"notes": []},
        }
        snapshot = deepcopy(original)
        converted = upgrade_cisco_ir_v1_to_v2(original)
        self.assertEqual(original, snapshot)
        policy = converted["policies"]["route_policies"][0]
        self.assertEqual(policy["vendor_semantics"], "cisco_ios")
        self.assertEqual(policy["terms"][0]["actions"][0]["kind"], "cisco_permit")
        self.assertEqual(policy["terms"][0]["unmodeled_statement_count"], 1)


if __name__ == "__main__":
    unittest.main()
