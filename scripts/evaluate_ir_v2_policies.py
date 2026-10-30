#!/usr/bin/env python3
"""Banc d'essai IR v2 : politiques et extensions fonctionnelles Cisco/Junos."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from normalizers.policy_ir_v2 import normalize_juniper_junos_v2, upgrade_cisco_ir_v1_to_v2  # noqa: E402


def _paths(inputs: list[Path]) -> list[Path]:
    return sorted({p.resolve() for root in inputs
                   for p in (root.rglob("*") if root.is_dir() else [root])
                   if p.is_file() and p.stat().st_size
                   and (p.suffix.lower() in {".cfg", ".conf", ".txt"}
                        or (not root.is_dir() and p.suffix.lower() == ".md"))})


def main() -> int:
    parser = argparse.ArgumentParser(description="Validation schéma des politiques IR v2 sur Cisco / Junos")
    parser.add_argument("--junos", type=Path, nargs="+", default=[])
    parser.add_argument("--cisco", type=Path, nargs="+", default=[])
    parser.add_argument("--schema", type=Path,
                        default=Path("schemas/network_device_ir_v2.schema.json"))
    parser.add_argument("--output-dir", type=Path, default=Path("reports/ir_v2"))
    parser.add_argument("--json-summary", type=Path, default=Path("reports/validation_ir_v2_policies.json"))
    parser.add_argument("--strict-schema", action="store_true")
    args = parser.parse_args()
    if not (args.junos or args.cisco):
        parser.error("Préciser au moins un corpus --junos ou --cisco")
    for label, inputs in (("--junos", args.junos), ("--cisco", args.cisco)):
        for item in inputs:
            if not item.exists():
                parser.error(f"Répertoire ou fichier introuvable pour {label} : {item}")
        if inputs and not _paths(inputs):
            parser.error(f"Aucun fichier .cfg/.conf/.txt non vide (ou .md explicite) dans {label}")

    from jsonschema import Draft202012Validator

    schema = json.loads(args.schema.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.json_summary.parent.mkdir(parents=True, exist_ok=True)
    samples = []
    for vendor, files in (("junos", _paths(args.junos)), ("cisco_ios", _paths(args.cisco))):
        for path in files:
            result = {"file": path.name, "vendor": vendor, "status": "error"}
            # Plusieurs topologies publiques peuvent avoir un même basename et
            # même un SHA identique : conserver un fichier de résultat par
            # entrée, sans publier le chemin absolu d'origine.
            result["source_id"] = hashlib.sha256(str(path).encode("utf-8")).hexdigest()[:12]
            try:
                if vendor == "junos":
                    ir = normalize_juniper_junos_v2(path)
                else:
                    from parsers.cisco_parser import parse_cisco_ios
                    from normalizers.cisco_normalizer import normalize_cisco_ios
                    raw = path.read_bytes()
                    parsed = parse_cisco_ios(raw.decode("utf-8", errors="replace"))
                    ir = upgrade_cisco_ir_v1_to_v2(normalize_cisco_ios(
                        parsed, source_file=path.name, sha256=hashlib.sha256(raw).hexdigest()))

                errors = list(validator.iter_errors(ir))
                result["status"] = "schema_error" if errors else "schema_valid_partial"
                result["schema_error_paths"] = ["/".join(map(str, e.path)) for e in errors]
                result["sha256"] = ir["source"]["sha256"]
                result["policies"] = len(ir["policies"]["route_policies"])
                result["community_sets"] = len(ir["policies"]["community_sets"])
                result["terms"] = sum(len(p["terms"]) for p in ir["policies"]["route_policies"])
                result["policy_v2_recognized_leaves"] = ir["diagnostics"]["source_only_counts"].get("policy_v2_leaf_count_recognized")
                result["policy_v2_unmodeled_leaves"] = ir["diagnostics"]["source_only_counts"].get("policy_v2_leaf_count_unmodeled")
                if vendor == "junos":
                    result["features_recognized_by_section"] = ir["diagnostics"]["source_only_counts"].get(
                        "junos_v2_feature_recognized_by_section", {})
                    result["features_unmodeled_by_section"] = ir["diagnostics"]["source_only_counts"].get(
                        "junos_v2_feature_unmodeled_by_section", {})
                    result["parser"] = ir["source"]["parser_schema_version"]
                if not errors:
                    out = args.output_dir / (f"{vendor}_{path.stem}_{ir['source']['sha256'][:10]}"
                                             f"_{result['source_id']}.ir_v2.json")
                    out.write_text(json.dumps(ir, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                    result["output"] = out.name
            except (ValueError, RuntimeError, OSError) as exc:
                # Ne jamais exporter les chaînes d'exceptions du parseur :
                # elles peuvent contenir du contenu libre de configuration.
                result["error_type"] = type(exc).__name__
            samples.append(result)
            print(f"{vendor:9} {path.name:24} {result['status']}")

    statuses = Counter(x["status"] for x in samples)
    recognized_features: Counter[str] = Counter()
    missing_features: Counter[str] = Counter()
    for row in samples:
        recognized_features.update(row.get("features_recognized_by_section", {}))
        missing_features.update(row.get("features_unmodeled_by_section", {}))
    summary = {
        "schema": args.schema.name,
        "files": len(samples),
        "status_counts": dict(statuses),
        "total_route_policies": sum(x.get("policies", 0) for x in samples),
        "total_community_sets": sum(x.get("community_sets", 0) for x in samples),
        "total_policy_terms": sum(x.get("terms", 0) for x in samples),
        "junos_policy_leaves_recognized": sum(x.get("policy_v2_recognized_leaves") or 0 for x in samples),
        "junos_policy_leaves_unmodeled": sum(x.get("policy_v2_unmodeled_leaves") or 0 for x in samples),
        "junos_features_recognized_by_section": dict(recognized_features),
        "junos_features_unmodeled_by_section": dict(missing_features),
        "notes": ["Structure JSON valide != comportement réseau vérifié.",
                  "Les politique Cisco et Junos ont un champ vendor_semantics distinct.",
                  "Les compteurs v1 restent disponibles comme ligne de base.",
                  "Les compteurs de nouvelles fonctionnalités sont indépendants de v1, pas une union dédupliquée.",
                  "Les fichiers étudiés durant le développement ne constituent pas un holdout indépendant."],
        "results": samples,
    }
    args.json_summary.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("Résumé (sans commandes brutes) :", args.json_summary)
    print("Bilan :", dict(statuses))
    return 1 if args.strict_schema and any(k != "schema_valid_partial" for k in statuses) else 0


if __name__ == "__main__":
    raise SystemExit(main())
