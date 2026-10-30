"""Compare Cisco parser AND IR to independently seeded golden facts."""
import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def present(category, value):
    return f"{category}={value}"


def parse_facts(p):
    facts = []
    add = lambda c, v: facts.append(present(c, v))
    add("hostname", p.get("hostname"))
    add("ios", p.get("global_settings", {}).get("ios_version"))
    src = p.get("global_settings", {}).get("ip_source_route_enabled")
    if src is not None:
        add("source_route", str(src).lower())
    aaa = p.get("global_settings", {}).get("aaa_new_model_enabled")
    if aaa is not None:
        add("aaa", str(aaa).lower())
    for cmd in p.get("global_settings", {}).get("ssh_commands", []):
        if cmd.startswith("ip ssh version "):
            add("ssh_version", cmd.split()[-1])
    for inf in p.get("interfaces", []):
        for address in inf.get("ipv4_addresses", []):
            import ipaddress
            cidr = ipaddress.IPv4Interface(f"{address['address']}/{address['mask']}")
            add("interface", f"{inf['name']}|{cidr.with_prefixlen}")
    for route in p.get("static_routes", []):
        import ipaddress
        prefix = ipaddress.IPv4Network(f"{route['destination']}/{route['mask']}", strict=False)
        add("route", f"{prefix.with_prefixlen}|{route.get('next_hop')}")
    for line in p.get("lines", []):
        ident = line["identifier"]
        timeout = line.get("exec_timeout") or []
        if timeout:
            add("timeout", f"{ident}|{int(timeout[0])*60+(int(timeout[1]) if len(timeout)>1 else 0)}")
        if line.get("login_method"):
            add("login", f"{ident}|{line['login_method']}")
        for tr in line.get("transport_input", []):
            add("transport", f"{ident}|{tr}")
    for banner in p.get("banners", []):
        add("banner", banner["kind"])
    for snmp in p.get("snmp", {}).get("communities", []):
        add("snmp_access", snmp["access"])
    buff = p.get("syslog", {}).get("buffered")
    if isinstance(buff, dict) and buff.get("size_bytes") is not None:
        add("syslog_buffer", str(buff["size_bytes"]))
    for target in p.get("syslog", {}).get("hosts", []):
        add("syslog_host", target.get("host"))
    for server in p.get("ntp", {}).get("servers", []):
        add("ntp_server", server.get("target"))
    return [x for x in facts if not x.endswith("=None")]


def ir_facts(p):
    facts = []
    add = lambda c, v: facts.append(present(c, v))
    add("hostname", p["device"].get("hostname"))
    add("ios", p["device"]["platform"].get("version"))
    src = p["services"]["ip_stack"].get("source_route_enabled")
    if src is not None:
        add("source_route", str(src).lower())
    aaa = p["management"].get("aaa_new_model_enabled")
    if aaa is not None:
        add("aaa", str(aaa).lower())
    if p["management"].get("ssh_version") is not None:
        add("ssh_version", str(p["management"]["ssh_version"]))
    for inf in p.get("interfaces", []):
        for address in inf.get("ipv4_addresses", []):
            add("interface", f"{inf['name']}|{address['cidr']}")
    for route in p["routing"].get("static_routes", []):
        add("route", f"{route['prefix']}|{route.get('next_hop')}")
    for line in p["management"].get("terminal_lines", []):
        ident = line["line_id"]
        timeout = line.get("exec_timeout") or []
        if timeout:
            add("timeout", f"{ident}|{int(timeout[0])*60+(int(timeout[1]) if len(timeout)>1 else 0)}")
        if line.get("login_method"):
            add("login", f"{ident}|{line['login_method']}")
        for tr in line.get("transport_input", []):
            add("transport", f"{ident}|{tr}")
    for banner in p["management"].get("banners", []):
        add("banner", banner["kind"])
    for snmp in p["services"]["snmp"].get("communities", []):
        add("snmp_access", snmp["access"].upper())
    buff = p["services"]["syslog"].get("buffered")
    if isinstance(buff, dict) and buff.get("size_bytes") is not None:
        add("syslog_buffer", str(buff["size_bytes"]))
    for target in p["services"]["syslog"].get("targets", []):
        add("syslog_host", target.get("address"))
    for server in p["services"]["ntp"].get("servers", []):
        add("ntp_server", server.get("target"))
    return [x for x in facts if not x.endswith("=None")]


def score(expected, actual):
    a, b = Counter(expected), Counter(actual)
    tp = sum((a & b).values())
    fn = sum((a - b).values())
    fp = sum((b - a).values())
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision,
            "recall": recall, "f1": f1, "missed": list((a-b).elements()),
            "invented": list((b-a).elements())}


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("--project", type=Path, required=True,
                     help="Root of network-config-audit repository")
    cli.add_argument("--out", type=Path, default=ROOT / "results")
    args = cli.parse_args()
    sys.path.insert(0, str(args.project.resolve()))
    sys.path.insert(0, str((args.project / "parsers").resolve()))
    from cisco_parser import parse_cisco_ios
    from normalizers.cisco_normalizer import normalize_cisco_ios
    args.out.mkdir(parents=True, exist_ok=True)
    rows = []
    aggregate = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    for cfg in sorted((ROOT / "configs").glob("*.cfg")):
        reference = json.loads((ROOT / "gold" / (cfg.name + ".json")).read_text())["facts"]
        parsed = parse_cisco_ios(cfg.read_text())
        ir = normalize_cisco_ios(parsed)
        for stage, actual in (("parsing", parse_facts(parsed)), ("ir", ir_facts(ir))):
            result = score(reference, actual)
            row = {"case": cfg.name, "stage": stage, **result}
            rows.append(row)
            for key in ("tp", "fp", "fn"):
                aggregate[stage][key] += result[key]
    with (args.out / "details.json").open("w") as f:
        json.dump(rows, f, indent=2)
    summary = {}
    for stage, counts in aggregate.items():
        tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
        precision = tp / (tp+fp) if tp+fp else 1
        recall = tp / (tp+fn) if tp+fn else 1
        summary[stage] = {**counts, "precision": precision, "recall": recall,
                          "f1": 2*precision*recall/(precision+recall) if precision+recall else 0}
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    for stage, values in summary.items():
        print(stage, "TP", values["tp"], "FP", values["fp"], "FN", values["fn"],
              "Precision", f"{values['precision']:.2%}", "Recall", f"{values['recall']:.2%}",
              "F1", f"{values['f1']:.2%}")
    print("Details:", args.out / "details.json")


if __name__ == "__main__":
    main()
