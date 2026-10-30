"""Tests structurels de l'adaptateur sur corpus Junos *réel* et indépendant.

Les clones publics ne sont pas copiés dans le dépôt pour respecter leur
provenance. Définir JUNIPER_BATFISH_DIR et JUNIPER_JUNOSPHERE_DIR, ou placer
les clones dans ../juniper_sources comme sur le poste du projet.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from normalizers.juniper_ir_adapter import normalize_juniper_junos  # noqa: E402


def _repo() -> Path:
    return PROJECT


def _batfish() -> Path:
    if os.getenv("JUNIPER_BATFISH_DIR"):
        return Path(os.environ["JUNIPER_BATFISH_DIR"])
    return _repo().parent / "juniper_sources" / "batfish-lab-validation" / "snapshots" / "junos_evpn_type5" / "source" / "configs"


def _junosphere() -> Path:
    if os.getenv("JUNIPER_JUNOSPHERE_DIR"):
        return Path(os.environ["JUNIPER_JUNOSPHERE_DIR"])
    return _repo().parent / "juniper_sources" / "junosphere"


class JuniperIRV1ExternalCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema = PROJECT / "schemas" / "network_device_ir_v1.schema.json"
        if not schema.exists():
            schema = PROJECT.parent / "cisco_coverage_v67" / "schemas" / "network_device_ir_v1.schema.json"
        cls.validator = Draft202012Validator(json.loads(schema.read_text(encoding="utf-8")))

    def test_six_batfish_evpn_files(self):
        folder = _batfish()
        if not folder.exists():
            self.skipTest("Télécharger le corpus Batfish ou définir JUNIPER_BATFISH_DIR")
        files = sorted(folder.glob("*.cfg"))
        self.assertEqual(len(files), 6)
        for file in files:
            with self.subTest(file=file.name):
                ir = normalize_juniper_junos(file)
                self.assertEqual(list(self.validator.iter_errors(ir)), [])
                self.assertEqual(ir["source"]["vendor"], "juniper_junos")
                self.assertTrue(ir["interfaces"])
                self.assertTrue(ir["routing"]["bgp"])
                self.assertEqual(ir["diagnostics"]["status"], "partial")
                counts = ir["diagnostics"]["source_only_counts"]
                self.assertEqual(counts["config_leaves"], counts["normalized_leaves"] + counts["unmodeled_leaves"])
                self.assertTrue(all(i["operational_state"] is None for i in ir["interfaces"]))
                self.assertNotIn("encrypted-password", json.dumps(ir))

    def test_bgp_group_preserves_different_asn(self):
        sample = _batfish() / "node1-1.cfg"
        if not sample.exists():
            self.skipTest("Fichier Batfish node1-1.cfg manquant")
        ir = normalize_juniper_junos(sample)
        groups = {p["junos_group"]: p["local_as"] for p in ir["routing"]["bgp"]}
        self.assertEqual(groups["underlay"], 65001)
        self.assertEqual(groups["overlay"], 65000)
        self.assertIn("evpn", next(p for p in ir["routing"]["bgp"] if p["junos_group"] == "overlay")["address_families"])
        self.assertIn("TENANT-A", {v["name"] for v in ir["vrfs"]})
        self.assertEqual(next(v for v in ir["vrfs"] if v["name"] == "TENANT-A")["route_distinguisher"], "172.16.0.1:10000")

    def test_inline_static_next_hop_discard_and_interface_cidr(self):
        sample = _batfish() / "edge1.cfg"
        if not sample.exists():
            self.skipTest("Fichier Batfish edge1.cfg manquant")
        ir = normalize_juniper_junos(sample)
        routes = ir["routing"]["static_routes"]
        self.assertEqual(next(r for r in routes if r["prefix"] == "192.168.99.0/24")["junos_action"], "discard")
        self.assertEqual(next(r for r in routes if r["vrf"] == "mgmt_junos")["next_hop"], "10.0.0.2")
        ip = next(i for i in ir["interfaces"] if i["name"] == "ge-0/0/1.0")
        self.assertEqual(ip["ipv4_addresses"][0]["cidr"], "10.99.0.1/31")
        self.assertIsNone(ip["admin_enabled"])

    def test_junosphere_ospf_area_is_not_cisco_network_selector(self):
        sample = _junosphere() / "ospf-ldp" / "configset" / "br-s-r1.conf"
        if not sample.exists():
            self.skipTest("Fichier Junosphere OSPF manquant")
        ir = normalize_juniper_junos(sample)
        ospf = ir["routing"]["ospf"][0]
        self.assertEqual(ospf["process_id_applicability"], "not_applicable_junos")
        self.assertEqual(ospf["process_id"], "")
        self.assertEqual(ospf["network_selectors"], [])
        self.assertIn("lo0.0", ospf["junos_interfaces_by_area"][0]["interfaces"])

    def test_eighteen_nonempty_junosphere(self):
        folder = _junosphere()
        if not folder.exists():
            self.skipTest("Télécharger junosphere ou définir JUNIPER_JUNOSPHERE_DIR")
        files = sorted(p for p in folder.glob("*/configset/*.conf") if p.stat().st_size)
        self.assertEqual(len(files), 18)
        ospf_count = 0
        for file in files:
            ir = normalize_juniper_junos(file)
            self.assertEqual(list(self.validator.iter_errors(ir)), [], file.name)
            ospf_count += bool(ir["routing"]["ospf"])
        self.assertEqual(ospf_count, 8)

    def test_srx_set_format_uses_external_parser(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as temp:
            path = Path(temp) / "srx.set.txt"
            path.write_text("set system host-name lab\nset interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/30\n")
            ir = normalize_juniper_junos(path)
            self.assertEqual(ir["source"]["parser_schema_version"], "clijson-0.6.1")
            self.assertEqual(ir["device"]["hostname"], "lab")
            self.assertEqual(ir["interfaces"][0]["ipv4_addresses"][0]["cidr"], "192.0.2.1/30")
            self.assertFalse(list(self.validator.iter_errors(ir)))

    def test_secrets_and_operational_state_not_exported(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as temp:
            path = Path(temp) / "secret.conf"
            path.write_text('system {\n host-name TEST;\n root-authentication {\n  encrypted-password "never-export-this-hash";\n }\n}\n'
                            'interfaces { ge-0/0/1 { unit 0 { family inet { address 198.51.100.1/30; } } } }\n',
                            encoding="utf-8")
            ir = normalize_juniper_junos(path)
            serialized = json.dumps(ir)
            self.assertNotIn("never-export-this-hash", serialized)
            self.assertEqual(ir["device"]["hostname"], "TEST")
            self.assertTrue(all(i["operational_state"] is None for i in ir["interfaces"]))

    def test_safe_taxonomy_does_not_expose_dynamic_identifiers(self):
        from collections import Counter
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as temp:
            path = Path(temp) / "secrets.conf"
            path.write_text('policy-options {\n policy-statement PRIVATE-CLIENT-NAME {\n'
                            '  term PRIVATE-TERM {\n   from {\n    route-filter 192.0.2.0/24 exact;\n'
                            '   }\n  }\n }\n}\n', encoding="utf-8")
            gaps = Counter()
            normalize_juniper_junos(path, unmodeled_inventory=gaps)
            serialized = json.dumps(gaps)
            self.assertNotIn("PRIVATE-CLIENT-NAME", serialized)
            self.assertNotIn("PRIVATE-TERM", serialized)
            self.assertNotIn("192.0.2", serialized)
            self.assertTrue(any(k.startswith("policy-options.policy-statement") for k in gaps))


if __name__ == "__main__":
    unittest.main()
