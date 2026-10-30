#!/usr/bin/env python3
"""Safely validate fresh Cisco IOS fixtures against a baseline corpus.

The digest check detects exact duplicates, not shared origin or semantic
similarity. Source independence must still be justified in the report.
No raw configuration directives or credential values are written to JSON.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

try:
    from scripts.audit_parser_coverage import audit_text
except ModuleNotFoundError:
    from audit_parser_coverage import audit_text


def _files(paths: list[Path]) -> list[Path]:
    found = []
    for entry in paths:
        if not entry.exists():
            raise FileNotFoundError(str(entry))
        if entry.is_file():
            found.append(entry)
        else:
            found.extend(sorted(p for p in entry.rglob("*") if p.is_file()
                                and p.suffix.lower() in {".cfg", ".txt"}))
    return list(dict.fromkeys(found))


def check_holdout(holdout_paths: list[Path], baseline_paths: list[Path]) -> list[dict]:
    baseline_hashes = {
        hashlib.sha256(p.read_bytes()).hexdigest() for p in _files(baseline_paths)
    }
    seen: set[str] = set()
    report = []
    for path in _files(holdout_paths):
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        audit = audit_text(raw.decode("utf-8-sig"), file=path.name)
        unknowns = (audit["unparsed_global_count"] + audit["nested_opaque_count"] +
                    audit["source_only_counts"]["platform_unmodeled"])
        exact_duplicate = digest in baseline_hashes or digest in seen
        seen.add(digest)
        report.append({
            "file": str(path),
            "sha256": digest,
            "exact_duplicate_of_baseline_or_holdout": exact_duplicate,
            "format": audit["source_format"],
            "format_confidence": audit["format_confidence"],
            "ios_family_compatible": audit["ios_family_compatible"],
            "unmodeled_count": unknowns,
            "indentation_recovery_count": audit["formatting_recovery_count"],
            "status": ("duplicate" if exact_duplicate else
                       "incompatible_or_unknown_dialect" if not audit["ios_family_compatible"] else
                       "unmodeled_commands" if unknowns else
                       "parsed_with_formatting_warning" if audit["formatting_recovery_count"] else
                       "passed"),
        })
    return report


def main() -> int:
    cli = argparse.ArgumentParser(description="Contrôle d'un corpus nouveau, sans exporter de secrets")
    cli.add_argument("holdout", nargs="+", type=Path,
                     help="Nouveaux fichiers .cfg/.txt, jamais utilisés pour développer le parseur")
    cli.add_argument("--baseline-dir", type=Path, action="append", default=[],
                     help="Corpus de développement, répétable, pour comparer les empreintes SHA-256")
    cli.add_argument("--json-summary", type=Path)
    cli.add_argument("--strict", action="store_true", help="Échoue si duplicata, dialecte incompatible, ou commande inconnue")
    args = cli.parse_args()
    if args.strict and not args.baseline_dir:
        cli.error("--strict requiert au moins un --baseline-dir pour contrôler les doublons")
    try:
        report = check_holdout(args.holdout, args.baseline_dir)
    except (FileNotFoundError, UnicodeError, OSError) as exc:
        cli.error(str(exc))
    if not report:
        cli.error("Aucun fichier .cfg/.txt à valider")
    for entry in report:
        print(f"{entry['file']}: {entry['status']} | format={entry['format']} | "
              f"inconnues={entry['unmodeled_count']} | récupérations={entry['indentation_recovery_count']}")
    passed = sum(x["status"] in {"passed", "parsed_with_formatting_warning"} for x in report)
    print(f"HOLDOUT : {passed}/{len(report)} admissibles | "
          f"{sum(x['exact_duplicate_of_baseline_or_holdout'] for x in report)} doublons exacts")
    if args.json_summary:
        args.json_summary.parent.mkdir(parents=True, exist_ok=True)
        args.json_summary.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                                     encoding="utf-8")
        print(f"Résumé sans commandes brutes : {args.json_summary}")
    if args.strict and passed != len(report):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
