"""Exécution locale de l'audit statique CIS IOS 15 v4.1.1 sur un fichier."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from audit_engine.cis15_engine import audit_cis_ios15
from audit_engine.show_evidence import attach_show_evidence
from cisco_parser import parse_cisco_ios
from normalizers.cisco_normalizer import normalize_cisco_ios


def main() -> None:
    cli = argparse.ArgumentParser(description="Audit statique partiel CIS IOS 15")
    cli.add_argument("configuration", type=Path)
    cli.add_argument("--profile", choices=["L1", "L2"], default="L1")
    cli.add_argument("--assume-complete", action="store_true",
                     help="Interpréter l'absence de déclaration comme non-conformité")
    cli.add_argument("--catalogue", type=Path,
                     default=Path("benchmarks/rules/cisco_ios/cis_ios15_v4.1.1_phase5_lab.json"))
    cli.add_argument("--output", type=Path, help="Rapport JSON expurgé à enregistrer")
    cli.add_argument("--show-inventory", action="store_true",
                     help="Afficher toutes les parties parsing -> IR -> audit")
    cli.add_argument("--external-interface", action="append", default=[],
                     help="Nom exact d'une interface externe vérifiée par l'utilisateur (répétable)")
    cli.add_argument("--show-evidence", type=Path,
                     help="Résumé JSON fourni par collect_ios_show.py, jamais une sortie brute")
    args = cli.parse_args()

    raw = args.configuration.read_bytes()
    parsed = parse_cisco_ios(raw.decode("utf-8-sig"))
    ir = normalize_cisco_ios(
        parsed, source_file=args.configuration.name,
        sha256=hashlib.sha256(raw).hexdigest(),
    )
    catalogue = json.loads(args.catalogue.read_text(encoding="utf-8"))
    report = audit_cis_ios15(
        ir, catalogue, profile=args.profile,
        complete_config=args.assume_complete, parsed=parsed,
        audit_context={"external_interfaces": args.external_interface},
    )
    if args.show_evidence:
        evidence = json.loads(args.show_evidence.read_text(encoding="utf-8"))
        report = attach_show_evidence(report, evidence)

    print("===== AUDIT STATIQUE CIS CISCO IOS 15 v4.1.1 =====")
    print("Routeur :", report["hostname"], "| IOS :", report["ios_version"])
    print("Profil :", report["selected_profile"],
          "| Configuration déclarée complète :", report["complete_config_assumed"])
    for finding in report["findings"]:
        print(f"[{finding['status']}] {finding['cis_control_id']} - {finding['title']}")
        if finding["status"] == "FAIL":
            print("  Correction proposée :", finding["remediation"])
            if finding["evidence"].get("assessment_basis") == "assumed_absence":
                print("  Preuve : absence déduite (configuration déclarée complète)")
        elif finding["evidence"].get("uncertainty_reasons"):
            print("  Parsing incomplet :", ", ".join(finding["evidence"]["uncertainty_reasons"]))
    print("Bilan :", report["counts"])
    inventory = report["parsing_normalization_inventory"]
    print("Inventaire :", inventory["part_count"], "parties regroupées en",
          inventory["group_count"], "domaines ;",
          inventory["audited_part_count"], "parties couvertes par",
          inventory["mapped_cis_rule_count"], "règles CIS")
    if inventory["warnings"]:
        print("Avertissements de couverture :", "; ".join(inventory["warnings"]))
    if args.show_inventory:
        print("===== PARSING -> NORMALISATION IR -> AUDIT =====")
        for part in inventory["parts"]:
            print(f"[{part['status']}] {part['group']}/{part['part']} : "
                  f"parse={part['parser_count']} IR={part['ir_count']} "
                  f"CIS={','.join(part['cis_control_ids']) or '-'}")
    print("Couverture :", report["implemented_rule_count"],
          "règles du catalogue sélectionné, pas le benchmark complet")
    print("Statut : prototype d'audit de configuration, non certifié")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("Rapport JSON :", args.output)


if __name__ == "__main__":
    main()
