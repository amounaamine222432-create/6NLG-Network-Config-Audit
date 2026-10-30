"""Produit deux rapports HTML : parsing et IR, avec chaque assertion contrôlée.

Usage : python3 benchmark_extra_30_6nlg/export_summary_html.py --project .
"""
import argparse
import hashlib
import html
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


STYLE = """
body{font:15px system-ui,Arial,sans-serif;background:#f3f6fb;color:#17263b;margin:0}
main{max-width:1200px;margin:2rem auto;background:white;padding:2rem;border-radius:14px}
h1{color:#135185}h2{margin-top:2.5rem;color:#164c78}
table{border-collapse:collapse;width:100%;font-size:14px;margin:1rem 0}
th,td{border-bottom:1px solid #dbe3ee;padding:.6rem;text-align:left;vertical-align:top}
th{background:#edf3f8}tr:nth-child(even){background:#fafcff}
code{font-size:13px;overflow-wrap:anywhere}.ok{color:#147a40;font-weight:700}
.bad{color:#bd2424;font-weight:700}.pill{padding:.4rem .7rem;border-radius:8px;background:#e9f6ec}
details{padding:.4rem .1rem}summary{cursor:pointer;color:#145184;font-weight:600}
"""


def value_at(data, selector):
    current = data
    for key in selector.split("."):
        current = current[int(key)] if isinstance(current, list) else current[key]
    return current


def escape(value):
    return html.escape(json.dumps(value, ensure_ascii=False, default=str))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--project", default=".")
    args = p.parse_args()
    project = Path(args.project).resolve()
    sys.path[:0] = [str(project), str(project / "parsers")]
    from cisco_parser import parse_cisco_ios
    from normalizers.cisco_normalizer import normalize_cisco_ios

    directory = project / "benchmark_extra_30_6nlg"
    cases = json.loads((directory / "expected.json").read_text(encoding="utf-8"))
    if len(cases) != 30:
        raise SystemExit("Le fichier expected.json doit contenir 30 scénarios")
    output = directory / "html"
    output.mkdir(exist_ok=True)
    stage_rows = {"parser": defaultdict(list), "ir": defaultdict(list)}
    for item in cases:
        raw = (directory / "configs" / item["file"]).read_bytes()
        parsed = parse_cisco_ios(raw.decode("utf-8-sig"))
        ir = normalize_cisco_ios(parsed, source_file=item["file"], sha256=hashlib.sha256(raw).hexdigest())
        for stage, data in (("parser", parsed), ("ir", ir)):
            assertions = []
            for selector, expected in item[f"{stage}_expected"].items():
                try:
                    actual = value_at(data, selector)
                    correct = type(actual) is type(expected) and actual == expected
                except (KeyError, IndexError, TypeError, ValueError):
                    actual, correct = "<ABSENT>", False
                assertions.append((selector, expected, actual, correct))
            stage_rows[stage][item["family"]].append((item["file"], assertions))

    for stage, filename in (("parser", "RESUME_PARSING_30.html"), ("ir", "RESUME_NORMALISATION_IR_30.html")):
        families = stage_rows[stage]
        counts = {name: Counter({"ok": sum(a[3] for _, checks in cases for a in checks),
                                  "total": sum(len(checks) for _, checks in cases)})
                  for name, cases in families.items()}
        total = sum(c["total"] for c in counts.values())
        ok = sum(c["ok"] for c in counts.values())
        title = "Parsing Cisco IOS 15" if stage == "parser" else "Normalisation IR Cisco IOS 15"
        parts = ["<!doctype html><html lang='fr'><head><meta charset='utf-8'><title>", title,
                 "</title><style>", STYLE, "</style></head><body><main><h1>", title,
                 " — benchmark 30</h1><p class='pill'><b>", str(ok), "/", str(total),
                 " assertions correctes</b> — ", str(total-ok), " écart(s)</p>",
                 "<p>Comparaison des valeurs attendues indépendantes et des valeurs effectivement extraites. "
                 "Ne constitue pas une mesure exhaustive de précision, rappel ou F1 sur IOS 15.</p>",
                 "<table><thead><tr><th>Famille</th><th>Configurations</th><th>Assertions correctes</th><th>Écarts</th></tr></thead><tbody>"]
        for name, cases in sorted(families.items()):
            c = counts[name]
            parts.append(f"<tr><td>{html.escape(name)}</td><td>{len(cases)}</td><td>{c['ok']}/{c['total']}</td><td>{c['total']-c['ok']}</td></tr>")
        parts.append("</tbody></table>")
        for name, cases in sorted(families.items()):
            parts.append(f"<h2>{html.escape(name)}</h2>")
            for case, assertions in cases:
                num_errors = sum(not x[3] for x in assertions)
                parts.append(f"<details><summary>{html.escape(case)} — {len(assertions)-num_errors}/{len(assertions)} correctes</summary>")
                parts.append("<table><thead><tr><th>Champ JSON</th><th>Attendu</th><th>Obtenu</th><th>État</th></tr></thead><tbody>")
                for path, expected, actual, correct in assertions:
                    parts.append("<tr><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td class='{}'>{}</td></tr>".format(
                        html.escape(path), escape(expected), escape(actual), "ok" if correct else "bad", "OK" if correct else "ÉCART"))
                parts.append("</tbody></table></details>")
        parts.append("</main></body></html>")
        path = output / filename
        path.write_text("".join(parts), encoding="utf-8")
        print(f"{stage}: {ok}/{total} assertions correctes ; HTML : {path}")


if __name__ == "__main__":
    main()
