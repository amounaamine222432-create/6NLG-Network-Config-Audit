#!/usr/bin/env python3
"""Validation du lot Junos externe : extraction via ciscoconfparse2 + IR Cisco v1.

Chaque fichier est évalué séparément. Ne prétend jamais une normalisation
complète lorsqu'il existe des feuilles opaques ou un format incompatible.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
REPO = Path.cwd()
sys.path.insert(0, str(ROOT))

from normalizers.juniper_ir_adapter import normalize_juniper_junos  # noqa: E402


def _files(inputs: list[Path]) -> list[Path]:
    result: set[Path] = set()
    for candidate in inputs:
        if candidate.is_file() and candidate.suffix.lower() in {".cfg", ".conf", ".txt"}:
            result.add(candidate.resolve())
        elif candidate.is_dir():
            result.update(p.resolve() for p in candidate.rglob("*")
                          if p.is_file() and p.suffix.lower() in {".cfg", ".conf", ".txt"})
    return sorted(result)


def _srx_markdown_set(path: Path) -> tuple[bool, int]:
    """Prend uniquement connaissance du format public de la source SRX ; ne le parse pas."""
    inside = False
    lines = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip().startswith("```"):
            inside = not inside
        elif inside and line.lstrip().startswith("set "):
            lines += 1
    return lines > 0, lines


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Validation Junos ciscoconfparse2 -> IR v1")
    ap.add_argument("inputs", nargs="+", type=Path, help="Fichiers/répertoires .cfg, .conf, .txt")
    ap.add_argument("--schema", type=Path,
                    default=REPO / "schemas" / "network_device_ir_v1.schema.json")
    ap.add_argument("--output-dir", type=Path, default=REPO / "reports" / "juniper_ir")
    ap.add_argument("--json-summary", type=Path, default=REPO / "reports" / "juniper_ir_evaluation.json")
    ap.add_argument("--srx-markdown", type=Path,
                    help="Source SRX avec commandes 'set' dans Markdown (test de refus explicite)")
    ap.add_argument("--strict-schema", action="store_true",
                    help="Code de sortie non nul si configuration invalide/format non pris en charge")
    args = ap.parse_args(argv)

    from jsonschema import Draft202012Validator

    if not args.schema.exists():
        ap.error(f"Schéma introuvable : {args.schema}")
    schema = json.loads(args.schema.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    all_files = _files(args.inputs)
    if not all_files:
        ap.error("Aucun fichier .cfg/.conf/.txt dans les chemins indiqués")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.json_summary.parent.mkdir(parents=True, exist_ok=True)
    results = []
    for path in all_files:
        record: dict = {"file": path.name, "input_sha256": None,
                        "status": "error", "errors": []}
        if path.stat().st_size == 0:
            record["status"] = "skipped_empty"
            record["message"] = "Fichier vide de la source : non évalué"
            results.append(record)
            print(f"{path.name}: skipped_empty")
            continue
        try:
            ir = normalize_juniper_junos(path)
            errs = sorted(validator.iter_errors(ir), key=lambda e: list(map(str, e.path)))
            record["errors"] = ["/".join(map(str, e.path)) + ": " + e.message[:120] for e in errs]
            record["input_sha256"] = ir["source"]["sha256"]
            record["counts"] = ir["diagnostics"]["source_only_counts"]
            record["status"] = "schema_error" if errs else ir["diagnostics"]["status"]
            record["unmodeled_by_section"] = {
                x["section"]: x["count"] for x in ir["diagnostics"]["opaque_sections"]
            }
            if not errs:
                suffix = ir["source"]["sha256"][:10]
                out = args.output_dir / f"{path.stem}_{suffix}.ir.json"
                out.write_text(json.dumps(ir, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                record["output"] = out.name
        except (OSError, ValueError, RuntimeError) as exc:
            if isinstance(exc, ValueError) and "format=" in str(exc):
                record["errors"] = [str(exc)[:180]]
                record["status"] = "unsupported_format"
            else:
                record["errors"] = [type(exc).__name__]  # jamais un secret issu du parseur
                record["status"] = "error"
        print(f"{path.name}: {record['status']}" +
              (f" | {record['counts']['normalized_leaves']}/{record['counts']['config_leaves']} feuilles reconnues"
               if "counts" in record else ""))
        results.append(record)

    if args.srx_markdown:
        found, count = _srx_markdown_set(args.srx_markdown)
        results.append({"file": args.srx_markdown.name, "status": "unsupported_format" if found else "error",
                        "format": "junos_display_set_in_markdown" if found else "unidentified",
                        "set_statements": count,
                        "message": "Extraction SRX identifiée. Ce format ne doit pas être passé au parseur hiérarchique."})
        print(f"SRX Markdown: {results[-1]['status']} | set-statements={count}")

    status_counts = dict(Counter(record["status"] for record in results))
    totals = Counter()
    for record in results:
        totals.update(record.get("counts") or {})
    summary = {"benchmark": "validation_externe_juniper_ciscoconfparse2_ir_v1",
               "schema": args.schema.name,
               "inputs_count": len(results),
               "status_counts": status_counts,
               "totals": dict(totals),
               "results": results,
               "scope": "schema JSON valide et sous-ensemble statique ; ni conformité réseau ni équivalence sémantique totale",
               "format_limitation": "Junos 'set' SRX requiert conversion/parseur existant adapté avant normalisation"}
    args.json_summary.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
                                 encoding="utf-8")
    print("Résumé (sans commandes brutes) :", args.json_summary)
    print("Bilan :", status_counts)
    bad = sum(n for s, n in status_counts.items() if s in {"error", "unsupported_format", "schema_error"})
    return 1 if args.strict_schema and bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
