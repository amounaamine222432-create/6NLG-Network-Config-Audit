"""Régressions réelles, limites de couverture et protection des secrets Junos."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from jsonschema import Draft202012Validator

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from normalizers.policy_ir_v2 import normalize_juniper_junos_v2  # noqa: E402


BATFISH = Path(os.getenv("JUNIPER_BATFISH_DIR") or PROJECT.parent / "juniper_sources" /
               "batfish-lab-validation" / "snapshots" / "junos_evpn_type5" / "source" / "configs")
JUNOSPHERE = Path(os.getenv("JUNIPER_JUNOSPHERE_DIR") or PROJECT.parent / "juniper_sources" / "junosphere")


class JuniperFunctionalIRV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = Draft202012Validator(json.loads(
            (PROJECT / "schemas" / "network_device_ir_v2.schema.json").read_text(encoding="utf-8")))

    def test_evpn_bgp_bfd_and_interfaces(self):
        file = BATFISH / "node1-1.cfg"
        if not file.exists():
            self.skipTest("Fixture Batfish manquante")
        ir = normalize_juniper_junos_v2(file)
        self.assertFalse(list(self.validator.iter_errors(ir)))
        features = ir["junos_details"]
        underlay = next(g for g in features["protocols"]["bgp"]["groups"] if g["name"] == "underlay")
        self.assertEqual(underlay["bfd"]["minimum_interval_ms"], 350)
        self.assertEqual(underlay["bfd"]["multiplier"], 3)
        self.assertTrue(underlay["mtu_discovery_configured"])
        self.assertEqual(features["protocols"]["evpn"]["encapsulation"], "vxlan")
        self.assertEqual(features["protocols"]["evpn"]["extended_vni_list"]["all"], True)
        self.assertTrue(any(x["name"] == "ge-0/0/6.0" and
                            x["families"]["ethernet_switching"]["interface_mode"] == "trunk"
                            for x in features["interfaces"]))
        self.assertTrue(any(x["name"] == "TENANT-A" and
                            x["evpn"]["irb_symmetric_routing_vni"] == 50000
                            for x in features["routing_instances"]))

    def test_junosphere_mpls_isis_and_security(self):
        path = JUNOSPHERE / "isis-rsvp" / "configset" / "br-s-r1.conf"
        if not path.exists():
            self.skipTest("Fixture Junosphere manquante")
        ir = normalize_juniper_junos_v2(path)
        self.assertFalse(list(self.validator.iter_errors(ir)))
        f = ir["junos_details"]
        self.assertIn(2, f["protocols"]["isis"]["disabled_levels"])
        self.assertTrue(any(x["name"] == "lo0.0" and x["passive_configured"]
                            for x in f["protocols"]["isis"]["interfaces"]))
        self.assertEqual(len(f["protocols"]["rsvp"]["interfaces"]), 2)
        self.assertTrue(any(x["family"] == "inet6" and x["configured_mode"] == "packet-based"
                            for x in f["auxiliary"]["security"]["forwarding_family_modes"]))

    def test_multiple_bgp_export_policies_not_collapsed(self):
        path = JUNOSPHERE / "isis-rsvp" / "configset" / "br-b2-r1.conf"
        if not path.exists():
            self.skipTest("Fixture Junosphere manquante")
        ir = normalize_juniper_junos_v2(path)
        groups = ir["junos_details"]["protocols"]["bgp"]["groups"]
        customer = next(x for x in groups if x["name"] == "customer-65512")
        self.assertEqual(customer["export_policies"], ["EXPORT-CUSTOMER", "REJECT-ALL"])
        self.assertFalse(list(self.validator.iter_errors(ir)))

    def test_ospf_authentication_is_redacted(self):
        path = JUNOSPHERE / "ospf-ldp" / "configset" / "br-b1-r1.conf"
        if not path.exists():
            self.skipTest("Fixture Junosphere manquante")
        ir = normalize_juniper_junos_v2(path)
        data = json.dumps(ir, ensure_ascii=False)
        self.assertNotIn("$9$", data)
        ospf = ir["junos_details"]["protocols"]["ospf"]
        self.assertTrue(ospf["traffic_engineering_configured"])
        self.assertEqual(ospf["reference_bandwidth_configured"], "100g")
        self.assertTrue(any(x.get("authentication", {}).get("secret_redacted") is True
                            for area in ospf["areas"] for x in area["interfaces"]))

    def test_malformed_bfd_must_remain_unmodeled(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "bad.cfg"
            path.write_text("protocols { bgp { group TEST { bfd-liveness-detection {\n"
                            " minimum-interval 0; multiplier -1; session-mode unknown;\n"
                            " } } } }\n", encoding="utf-8")
            ir = normalize_juniper_junos_v2(path)
            group = ir["junos_details"]["protocols"]["bgp"]["groups"][0]
            self.assertNotIn("bfd", group)
            self.assertGreater(ir["diagnostics"]["source_only_counts"]
                               ["junos_v2_feature_unmodeled_by_section"]["protocols"], 0)

    def test_unknown_protocol_not_silently_claimed(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "opaque.cfg"
            path.write_text("protocols { bgp { invented-protocol-options confidential; } }\n",
                            encoding="utf-8")
            ir = normalize_juniper_junos_v2(path)
            self.assertGreater(ir["diagnostics"]["source_only_counts"]
                               ["junos_v2_feature_unmodeled_by_section"]["protocols"], 0)
            self.assertNotIn("confidential", json.dumps(ir))

    def test_route_filter_prefix_length_range(self):
        path = JUNOSPHERE / "isis-rsvp" / "configset" / "cst-c1-r1.conf"
        if not path.exists():
            self.skipTest("Fixture Junosphere manquante")
        ir = normalize_juniper_junos_v2(path)
        conditions = [c for p in ir["policies"]["route_policies"] for term in p["terms"]
                      for c in term["conditions"]]
        self.assertTrue(any(x["kind"] == "route_filter" and
                            x["modifier"] == "prefix-length-range" and
                            x["min_prefix_length"] == 1 for x in conditions))
        self.assertFalse(list(self.validator.iter_errors(ir)))

    def test_evaluator_keeps_identical_filenames_from_distinct_sources(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("source_a", "source_b"):
                directory = root / name
                directory.mkdir()
                (directory / "router.cfg").write_text(
                    "system { host-name test; }\ninterfaces { lo0 { unit 0 { family inet { address 10.0.0.1/32; } } } }\n",
                    encoding="utf-8")
            out = root / "out"
            cli = subprocess.run([
                sys.executable, str(PROJECT / "scripts" / "evaluate_ir_v2_policies.py"),
                "--junos", str(root / "source_a"), str(root / "source_b"),
                "--schema", str(PROJECT / "schemas" / "network_device_ir_v2.schema.json"),
                "--output-dir", str(out), "--json-summary", str(root / "summary.json"),
                "--strict-schema",
            ], capture_output=True, text=True, check=False)
            self.assertEqual(cli.returncode, 0, cli.stderr)
            summary = json.loads((root / "summary.json").read_text())
            self.assertEqual(summary["files"], 2)
            self.assertEqual(len(list(out.glob("*.ir_v2.json"))), 2)

    def test_evaluator_rejects_missing_corpus(self):
        with TemporaryDirectory() as temp:
            cli = subprocess.run([
                sys.executable, str(PROJECT / "scripts" / "evaluate_ir_v2_policies.py"),
                "--junos", str(Path(temp) / "missing"),
            ], capture_output=True, text=True, check=False)
            self.assertNotEqual(cli.returncode, 0)
            self.assertIn("introuvable", cli.stderr)


if __name__ == "__main__":
    unittest.main()
