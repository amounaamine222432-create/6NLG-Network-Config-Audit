#!/usr/bin/env python3
"""6NLG phase 4: repeatable, fail-closed validation; no device access.

Run from repository root: python scripts/validate_phase4.py
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
from html import escape
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "parsers"))
DEFAULT_CASES = ROOT / "validation_phase4" / "fixtures"
CATALOGUE = ROOT / "benchmarks/rules/cisco_ios/cis_ios15_v4.1.1_phase5_lab.json"
EXPECTED = {
    "01_ADRESSAGE_ROUTAGE_CONFLITS.cfg": ((5, 21, 3, 10), {"ROUTE_CONFLICT": "REVIEW", "INVALID_DEFAULT_GATEWAY": "REVIEW", "OVERLAPPING_INTERFACE_SUBNETS": "REVIEW"}),
    "02_ACL_MASQUAGE_CONTRADICTIONS.cfg": ((7, 18, 4, 10), {"ACL_RULE_SHADOWING": "FAIL", "UNUSED_ACL": "REVIEW", "UNDEFINED_ACL_BINDING": "FAIL"}),
    "03_OSPF_BGP_INCOHERENCES.cfg": ((4, 24, 4, 7), {"OSPF_MD5_KEY_COHERENCE": "REVIEW", "BGP_PEER_REACHABILITY": "REVIEW"}),
    "04_VLAN_NAT_DHCP_ANOMALIES.cfg": ((4, 21, 4, 10), {"OVERLAPPING_DHCP_POOLS": "REVIEW", "UNDECLARED_ACCESS_VLAN": "FAIL", "NAT_STATIC_GLOBAL_COLLISION": "FAIL"}),
    "05_PARTIEL_AMBIGU_INCOMPLET.cfg": ((0, 0, 39, 0), {"UNDEFINED_ACL_BINDING": "REVIEW"}),
    "06_REFERENCE_DURCIE_COMPLEXE.cfg": ((21, 11, 1, 6), {}),
}


def suite(name: str, command: list[str]) -> dict:
    try:
        done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=150,
                              env=__import__("os").environ.copy() | {"PYTHONPATH": f"{ROOT}:{ROOT / 'parsers'}"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"name": name, "status": "BLOCKED", "error": str(exc), "tests": 0}
    output = (done.stdout + "\n" + done.stderr)[-6000:]
    count = re.search(r"Ran (\d+) tests?", output)
    status = "PASS" if done.returncode == 0 and count and int(count.group(1)) > 0 else "FAIL"
    return {"name": name, "status": status, "tests": int(count.group(1)) if count else 0,
            "exit_code": done.returncode, "log_tail": output}


def pipeline(cases_dir: Path) -> dict:
    try:
        from parsers.cisco_parser import parse_cisco_ios
        from normalizers.cisco_normalizer import normalize_cisco_ios
        from audit_engine.cis15_engine import audit_cis_ios15
        from audit_engine.network_coherence import audit_network_coherence
        catalogue = json.loads(CATALOGUE.read_text(encoding="utf-8"))
        ids = [r["control_id"] for r in catalogue["rules"]]
        if len(ids) != 39 or len(set(ids)) != 39:
            return {"name": "Pipeline de bout en bout (6 cas)", "status": "FAIL", "error": "Catalogue: 39 identifiants CIS uniques requis"}
        cases = []
        for filename, (counts_expected, checks) in EXPECTED.items():
            path = cases_dir / filename
            raw = path.read_bytes()
            parsed = parse_cisco_ios(raw.decode("utf-8-sig"))
            ir = normalize_cisco_ios(parsed, source_file=filename, sha256=hashlib.sha256(raw).hexdigest())
            complete = not filename.startswith("05_")
            audit = audit_cis_ios15(ir, catalogue, profile="L2", complete_config=complete, parsed=parsed,
                                    audit_context={"external_interfaces": ["GigabitEthernet0/0"]})
            findings = audit.get("findings", [])
            observed_ids = [f.get("cis_control_id") for f in findings]
            counts = Counter(f.get("status") for f in findings)
            actual = tuple(counts.get(k, 0) for k in ("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"))
            network = audit_network_coherence(ir, complete_config=complete)
            net_map = {f["rule_id"]: f["status"] for f in network.get("findings", [])}
            differences = {k: {"expected": v, "actual": net_map.get(k)} for k, v in checks.items() if net_map.get(k) != v}
            # Source matching is an essential chain invariant.
            issues = []
            if len(observed_ids) != 39 or set(observed_ids) != set(ids) or len(set(observed_ids)) != 39:
                issues.append("Identifiants CIS manquants, dupliqués ou inattendus")
            if actual != counts_expected:
                issues.append(f"Comptages CIS attendus {counts_expected}, observés {actual}")
            if differences:
                issues.append(f"Diagnostics réseau divergents: {differences}")
            if len(findings) != sum(actual):
                issues.append("Incohérence de comptage des statuts")
            if ir.get("source", {}).get("sha256") not in (None, hashlib.sha256(raw).hexdigest()):
                issues.append("Empreinte source altérée")
            cases.append({"configuration": filename, "status": "PASS" if not issues else "FAIL",
                          "counts": dict(zip(("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"), actual)),
                          "network_assertions": checks, "issues": issues})
        return {"name": "Pipeline de bout en bout (6 cas)", "status": "PASS" if all(c["status"] == "PASS" for c in cases) else "FAIL", "cases": cases}
    except Exception as exc:
        return {"name": "Pipeline de bout en bout (6 cas)", "status": "BLOCKED", "error": f"{type(exc).__name__}: {exc}"}


def make_html(report: dict) -> str:
    rows = []
    for item in report["sections"]:
        detail = item.get("error") or f'{item.get("tests", len(item.get("cases", [])))} tests/cas'
        rows.append(f'<tr><td>{escape(item["name"])}</td><td class="{item["status"].lower()}">{item["status"]}</td><td>{escape(str(detail))}</td></tr>')
    cards = []
    for item in report["sections"]:
        for case in item.get("cases", []):
            count_text = ", ".join(f"{k}: {v}" for k, v in case["counts"].items())
            details = "; ".join(case["issues"]) or "Tous les critères attendus correspondent."
            cards.append(f'<article><h3>{escape(case["configuration"])}</h3><p><strong>{case["status"]}</strong> — {escape(count_text)}</p><p>{escape(details)}</p></article>')
    return "".join(["<!doctype html><html lang='fr'><meta charset='utf-8'><meta name='viewport' content='width=device-width'>",
            "<title>6NLG · Validation finale Phase 4</title><style>body{font:16px system-ui;background:#0e1b2e;color:#eaf4ff;max-width:1100px;margin:40px auto;padding:0 18px}"
            "h1{color:#64e2d5}table{border-collapse:collapse;width:100%;margin:20px 0}th,td{border-bottom:1px solid #3b566b;padding:14px;text-align:left}"
            ".pass{color:#62e3a3}.fail{color:#ff8d8d}.blocked{color:#f7c569}article{background:#172c40;border:1px solid #385169;border-radius:12px;padding:8px 20px;margin:12px 0}"
            "small{color:#acbed0}</style><h1>6NLG — Phase 4 : validation finale</h1>",
            f'<p>Exécution UTC : {escape(report["generated_utc"])} · Bilan : <strong>{escape(report["status"])}</strong></p>',
            "<p>Tests statiques sur configurations de laboratoire. Aucune validation du comportement réel d'un routeur n'est inférée.</p>",
            "<table><thead><tr><th>Volet</th><th>Verdict</th><th>Couverture</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>",
            "<h2>Six configurations de référence</h2>" + "".join(cards),
            "<h2>Limites et critères de livraison</h2><p>Le statut PASS global nécessite la réussite de tous les volets.",
            " Une erreur, une dépendance manquante ou un test non exécuté bloque la validation finale.</p>"
            "<small>Les journaux de tests figurent dans le JSON associé. Ne pas déposer de configurations réelles contenant des secrets dans ce rapport.</small></html>"])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cases-dir", type=Path, default=DEFAULT_CASES)
    ap.add_argument("--output-dir", type=Path, default=ROOT / "validation_phase4" / "results")
    args = ap.parse_args()
    sections = [
        suite("Contrôles CIS (39) et preuve de source", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_cis*.py"]),
        suite("Cohérence réseau OSPF/BGP/ACL/VLAN/NAT/DHCP", [sys.executable, "-m", "unittest", "tests.test_network_coherence", "tests.test_network_advanced_v75", "tests.test_cis_network_phase12", "-v"]),
        suite("Robustesse et sécurité interface Flask", [sys.executable, "-m", "unittest", "discover", "-s", "webapp/tests", "-p", "test_*.py"]),
        pipeline(args.cases_dir),
    ]
    report = {"phase": 4, "generated_utc": datetime.now(timezone.utc).isoformat(),
              "status": "PASS" if all(s["status"] == "PASS" for s in sections) else "INCOMPLETE_OR_FAILED",
              "sections": sections}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "phase4_validation.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (args.output_dir / "phase4_validation.html").write_text(make_html(report), encoding="utf-8")
    for s in sections:
        print(f'[{s["status"]}] {s["name"]}: {s.get("tests", len(s.get("cases", [])))} tests/cas')
    print("Bilan :", report["status"], "\nRapports :", args.output_dir.resolve())
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
