"""Compare des assertions de valeurs pour le parsing et l'IR, par famille."""
import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


def value_at(obj, path):
    current = obj
    for part in path.split("."):
        current = current[int(part)] if isinstance(current, list) else current[part]
    return current


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", default=".")
    args = ap.parse_args()
    project = Path(args.project).resolve()
    sys.path[:0] = [str(project), str(project / "parsers")]
    from cisco_parser import parse_cisco_ios
    from normalizers.cisco_normalizer import normalize_cisco_ios

    folder = project / "benchmark_extra_30_6nlg"
    records = json.loads((folder / "expected.json").read_text())
    outcome = defaultdict(Counter)
    differences = []
    for case in records:
        source = (folder / "configs" / case["file"]).read_bytes()
        parsed = parse_cisco_ios(source.decode("utf-8"))
        ir = normalize_cisco_ios(parsed, source_file=case["file"], sha256=hashlib.sha256(source).hexdigest())
        for stage, data in (("parser", parsed), ("ir", ir)):
            for path, expected in case[f"{stage}_expected"].items():
                try:
                    actual = value_at(data, path)
                    valid = type(actual) is type(expected) and actual == expected
                except (IndexError, KeyError, ValueError, TypeError):
                    actual, valid = "<MISSING>", False
                outcome[(case["family"], stage)]["ok" if valid else "error"] += 1
                if not valid:
                    differences.append({"file": case["file"], "stage": stage, "path": path,
                                        "expected": expected, "actual": actual})
    for (family, stage), counts in sorted(outcome.items()):
        total = sum(counts.values())
        print(f"{family:12} {stage:7}: {counts['ok']:3}/{total:3} assertions correctes")
    (folder / "results.json").write_text(json.dumps({"cases": len(records), "differences": differences}, indent=2) + "\n")
    print(f"{len(records)} configurations ; {len(differences)} écarts. Détails : {folder / 'results.json'}")
    return 1 if differences else 0


if __name__ == "__main__":
    raise SystemExit(main())
