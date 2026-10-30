"""Parité d'inventaire Cisco / Juniper sur l'export de parsing uniquement."""

from __future__ import annotations

from io import BytesIO
import json
from pathlib import Path
import re
from tempfile import TemporaryDirectory
import unittest

from normalizers.junos_tree_loader import load_junos_tree
from webapp import create_app
from webapp.juniper_parsed_preview import safe_junos_parsed_preview


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures_juniper_v24"


class JuniperParsingV25Tests(unittest.TestCase):
    def setUp(self):
        self.app = create_app({"TESTING": True, "SECRET_KEY": "v25-parsing-preview"})
        self.client = self.app.test_client()
        home = self.client.get("/")
        self.token = re.search(rb'<meta name="csrf-token" content="([^"]+)"', home.data).group(1).decode()

    def _import(self, files):
        return self.client.post(
            "/api/analyze",
            data={"vendor": "juniper_junos",
                  "files": [(BytesIO(path.read_bytes()), path.name) for path in files]},
            headers={"X-CSRF-Token": self.token}, content_type="multipart/form-data",
        )

    def test_four_inputs_have_detailed_parsing_and_downloads(self):
        files = sorted(FIXTURES.glob("0*"))
        self.assertEqual(len(files), 4)
        response = self._import(files)
        self.assertEqual(response.status_code, 200, response.get_json())
        payload = response.get_json()
        self.assertEqual(payload["metrics"]["devices"], 4)
        parsed_package = self.client.get(payload["downloads"]["parsing"]).get_json()
        parsed = {item["parsed"]["file"]: item["parsed"] for item in parsed_package["devices"]}

        base = parsed["01_JUNOS_BASE.conf"]
        self.assertEqual(base["hostname"], "JN-BASE-01")
        self.assertEqual(len(base["interfaces"]), 3)
        self.assertIn("192.0.2.1/30", base["interfaces"][0]["ipv4_addresses"])
        self.assertEqual(base["static_routes"][0]["prefix"], "0.0.0.0/0")

        srx = parsed["02_SRX_ACL_NAT_display_set.txt"]
        self.assertEqual(srx["parser"], "clijson")
        self.assertEqual(len(srx["security_zones"]), 2)
        self.assertEqual(len(srx["security_policies"]), 2)
        self.assertEqual(srx["nat_rules"][0]["translation"], "interface")

        routing = parsed["03_JUNOS_OSPF_BGP.conf"]
        self.assertEqual(len(routing["ospf_processes"][0]["areas"]), 1)
        self.assertEqual(routing["bgp_processes"][0]["neighbors"][0]["remote_as"], 64513)
        self.assertIn("IMPORT-ISP", routing["bgp_processes"][0]["import_policies"])

        core = parsed["04_JUNOS_COMPLET_ROUTAGE_VRF.conf"]
        self.assertEqual(core["objects_structured"], 80)
        self.assertEqual(len(core["interfaces"]), 5)
        self.assertEqual(len(core["static_routes"]), 2)
        self.assertEqual(core["routing_instances"][0]["name"], "CLIENT-BLUE")
        self.assertEqual(core["bgp_processes"][0]["neighbors"][0]["remote_as"], 64521)
        self.assertEqual(core["ospf_processes"][0]["process_id_applicability"], "not_applicable_junos")
        self.assertIn("mpls", core["additional_protocols"])
        self.assertEqual(core["prefix_lists"][0]["prefixes"], ["192.168.44.0/24"])
        self.assertEqual(core["route_policies"][0]["terms"][0]["conditions"][0]["kind"], "prefix-list")
        self.assertEqual(core["interfaces"][0]["source_line"], None)

        for kind in ("parsing", "ir", "html", "summary"):
            self.assertEqual(self.client.get(payload["downloads"][kind]).status_code, 200)

    def test_preview_uses_parser_ast_and_redacts_secrets(self):
        conf = """system {
          host-name R-JUNOS-SECRET;
          services { ssh; }
          login {
            user INTERNAL_SENSITIVE_USERNAME {
              authentication {
                encrypted-password \"PRIVATE_LOGIN_HASH_4242\";
              }
            }
          }
        }
        interfaces {
          ge-0/0/0 {
            description \"PRIVATE_INTERFACE_NOTE_4242\";
            unit 0 {
              family inet { address 192.0.2.12/30; }
            }
          }
        }
        protocols {
          bgp {
            group TEST-PEER {
              type external;
              peer-as 64522;
              authentication-key \"PRIVATE_BGP_SECRET_4242\";
              neighbor 203.0.113.7;
            }
          }
        }
        """
        with TemporaryDirectory() as directory:
            path = Path(directory) / "secret.conf"
            path.write_text(conf, encoding="utf-8")
            preview = safe_junos_parsed_preview(load_junos_tree(path), path.name)
        text = json.dumps(preview)
        for secret in ("PRIVATE_LOGIN_HASH_4242", "PRIVATE_INTERFACE_NOTE_4242",
                       "PRIVATE_BGP_SECRET_4242", "INTERNAL_SENSITIVE_USERNAME"):
            self.assertNotIn(secret, text)
        self.assertEqual(preview["bgp_processes"][0]["neighbors"][0]["remote_as"], 64522)
        self.assertTrue(preview["bgp_processes"][0]["neighbors"][0]["authentication_configured"])
        self.assertTrue(preview["interfaces"][0]["description_configured"])

    def test_actual_firewall_filter_is_distinct_from_srx_security_policy(self):
        conf = """firewall {
          family inet {
            filter INPUT-FILTER {
              term ALLOW-HTTPS {
                from {
                  source-address 192.0.2.0/24;
                  protocol tcp;
                  destination-port 443;
                }
                then accept;
              }
              term DENY-REST { then discard; }
            }
          }
        }
        """
        with TemporaryDirectory() as directory:
            path = Path(directory) / "filter.conf"
            path.write_text(conf, encoding="utf-8")
            preview = safe_junos_parsed_preview(load_junos_tree(path), path.name)
        self.assertEqual(len(preview["access_lists"]), 1)
        acl = preview["access_lists"][0]
        self.assertEqual(acl["terms"][0]["destination_ports"], [443])
        self.assertEqual(acl["terms"][0]["action"], "accept")
        self.assertEqual(preview["security_policies"], [])

    def test_invalid_ip_not_exported_as_valid_address(self):
        conf = """interfaces {
          ge-0/0/0 {
            unit 0 {
              family inet {
                address 999.0.0.1/33;
              }
            }
          }
        }
        """
        with TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.conf"
            path.write_text(conf, encoding="utf-8")
            preview = safe_junos_parsed_preview(load_junos_tree(path), path.name)
        self.assertEqual(preview["interfaces"][0]["ipv4_addresses"], [])
        self.assertGreater(preview["sections_leaf_counts"].get("interfaces", 0), 0)

    def test_vrf_protocols_are_not_hidden_by_global_inventory(self):
        conf = """routing-options {
          autonomous-system 64512;
        }
        routing-instances {
          TENANT-RED {
            instance-type virtual-router;
            protocols {
              bgp {
                group PEERING {
                  type external;
                  peer-as 64513;
                  neighbor 198.51.100.10;
                }
              }
              ospf {
                area 0.0.0.0 {
                  interface ge-0/0/1.100;
                }
              }
            }
          }
        }
        """
        with TemporaryDirectory() as directory:
            path = Path(directory) / "vrf.conf"
            path.write_text(conf, encoding="utf-8")
            preview = safe_junos_parsed_preview(load_junos_tree(path), path.name)
        self.assertEqual(preview["protocols_present"], ["bgp", "ospf"])
        self.assertEqual(preview["bgp_processes"], [])
        tenant = preview["routing_instances"][0]
        self.assertEqual(tenant["name"], "TENANT-RED")
        self.assertEqual(tenant["bgp_processes"][0]["neighbors"][0]["remote_as"], 64513)
        self.assertEqual(tenant["ospf_processes"][0]["areas"][0]["id"], "0.0.0.0")


if __name__ == "__main__":
    unittest.main()
