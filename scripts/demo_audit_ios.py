"""Démonstrateur hors ligne sur une configuration Cisco IOS de laboratoire."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from audit_engine.rule_engine import evaluate_rules
from cisco_parser import parse_cisco_ios
from normalizers.cisco_normalizer import normalize_cisco_ios


def main() -> None:
    cli = argparse.ArgumentParser()
    cli.add_argument("configuration", type=Path)
    cli.add_argument("--rules", type=Path, default=Path("benchmarks/rules/cisco_ios/demo_rules.json"))
    args = cli.parse_args()

    raw = args.configuration.read_bytes()
    content = raw.decode("utf-8-sig")
    parsed = parse_cisco_ios(content)
    ir = normalize_cisco_ios(
        parsed, source_file=args.configuration.name,
        sha256=hashlib.sha256(raw).hexdigest(),
    )
    rules = json.loads(args.rules.read_text(encoding="utf-8"))["rules"]
    result = evaluate_rules(ir, rules, allow_demo=True)
    print("===== AUDIT CISCO IOS — DEMONSTRATION =====")
    print("Routeur :", result["device"])
    print("Configuration :", result["source_file"])
    for finding in result["findings"]:
        print(f"[{finding['status']}] {finding['rule_id']} : {finding['title']}")
        print(f"  IR : {finding['ir_path']} = {finding['observed']}")
        if finding["remediation"]:
            print("  Correction candidate :", finding["remediation"])
    print("Bilan :", result["counts"])
    print("Attention : test pédagogique ; aucune conformité CIS certifiée.")


if __name__ == "__main__":
    main()
