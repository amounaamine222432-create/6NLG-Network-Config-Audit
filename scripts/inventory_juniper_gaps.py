#!/usr/bin/env python3
"""Inventaire exact des feuilles non adaptées, sans commandes ni valeurs sensibles."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from normalizers.juniper_ir_adapter import normalize_juniper_junos  # noqa: E402


def main() -> int:
    cli = argparse.ArgumentParser(description="Taxonomie des feuilles Junos non normalisées")
    cli.add_argument("directories", nargs="+", type=Path)
    cli.add_argument("--sections", nargs="+", default=["policy-options", "protocols"])
    cli.add_argument("--json-summary", type=Path, default=Path("reports/juniper_gap_taxonomy.json"))
    args = cli.parse_args()

    files = sorted({path.resolve() for root in args.directories
                    for path in (root.rglob("*") if root.is_dir() else [root])
                    if path.is_file() and path.suffix.lower() in {".cfg", ".conf", ".txt"}
                    and path.stat().st_size})
    if not files:
        cli.error("Aucune configuration Junos non vide trouvée")

    counts: Counter[str] = Counter()
    ok = 0
    errors: Counter[str] = Counter()
    for file in files:
        local: Counter[str] = Counter()
        try:
            normalize_juniper_junos(file, unmodeled_inventory=local)
            ok += 1
            counts.update({k: v for k, v in local.items() if k.split(".", 1)[0] in args.sections})
        except (OSError, ValueError, RuntimeError) as exc:
            errors[type(exc).__name__] += 1

    print(f"Configurations traitées : {ok}/{len(files)}")
    for section in args.sections:
        subgroups = {k: v for k, v in counts.items() if k.split(".", 1)[0] == section}
        print(f"\n=== {section} : {sum(subgroups.values())} feuilles non adaptées ===")
        for label, count in sorted(subgroups.items(), key=lambda item: (-item[1], item[0]))[:30]:
            print(f"{count:>4}  {label}")

    out = {"source_count": len(files), "processed": ok, "errors_by_exception_type": dict(errors),
           "sections": list(args.sections), "unmodeled_total": sum(counts.values()),
           "classification": dict(counts),
           "privacy_note": "Les intitulés sont issus d'une liste blanche ; aucune commande brute, adresse, nom d'objet ou secret n'est exporté."}
    args.json_summary.parent.mkdir(parents=True, exist_ok=True)
    args.json_summary.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("\nRapport JSON :", args.json_summary)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
