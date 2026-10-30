"""Exporte parsing, IR et audit CIS en JSON + HTML, sans serveur Flask.

Depuis la racine du projet 6NLG :
  python3 final_validation_6nlg/export_final_validation.py --project .
"""

import argparse
import hashlib
import html
import json
import sys
from pathlib import Path


def json_file(path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")


def html_file(path, title, obj, *, audit=False):
    style = """body{font:15px system-ui,sans-serif;margin:2rem auto;max-width:1150px;color:#1b2938;background:#f5f7fa}
    main{background:white;padding:2rem;border-radius:12px;box-shadow:0 2px 18px #0001}
    h1{color:#145183}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#edf3f8;padding:1rem;border-radius:8px}
    table{border-collapse:collapse;width:100%}td,th{padding:.65rem;border-bottom:1px solid #d6e0ea;text-align:left;vertical-align:top}
    .PASS{color:#147d43;font-weight:bold}.FAIL{color:#b52222;font-weight:bold}.UNKNOWN{color:#8c6100;font-weight:bold}"""
    content = ""
    if audit:
        counts = obj.get("counts", {})
        content += "<p>" + " | ".join(f"{html.escape(k)}: <b>{v}</b>" for k, v in counts.items()) + "</p>"
        content += "<table><thead><tr><th>CIS</th><th>Statut</th><th>Contrôle</th><th>Justification</th></tr></thead><tbody>"
        for item in obj.get("findings", []):
            status = item.get("status", "UNKNOWN")
            evidence = item.get("evidence", {})
            content += "<tr><td>{}</td><td class='{}'>{}</td><td>{}</td><td><pre>{}</pre></td></tr>".format(
                html.escape(str(item.get("cis_control_id", ""))),
                html.escape(status), html.escape(status), html.escape(str(item.get("title", ""))),
                html.escape(json.dumps(evidence, ensure_ascii=False, indent=2, default=str)))
        content += "</tbody></table>"
    else:
        content += "<p>Structure complète affichée ci-dessous. Comparer avec la configuration source.</p>"
        content += "<pre>" + html.escape(json.dumps(obj, ensure_ascii=False, indent=2, default=str)) + "</pre>"
    path.write_text("<!doctype html><html lang='fr'><meta charset='utf-8'><title>" + html.escape(title) +
                    "</title><style>" + style + "</style><main><h1>" + html.escape(title) + "</h1>" +
                    content + "</main></html>", encoding="utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", default=".", help="Racine du dépôt 6NLG")
    args = ap.parse_args()
    root = Path(args.project).resolve()
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(root / "parsers"))
    from cisco_parser import parse_cisco_ios
    from normalizers.cisco_normalizer import normalize_cisco_ios
    from audit_engine.cis15_engine import audit_cis_ios15

    folder = root / "final_validation_6nlg"
    output = folder / "export"
    output.mkdir(exist_ok=True)
    catalogue = json.loads((root / "benchmarks/rules/cisco_ios/cis_ios15_v4.1.1_phase5_lab.json").read_text(encoding="utf-8"))
    configs = sorted(folder.glob("*.cfg"))
    if len(configs) != 2:
        raise SystemExit(f"Il faut exactement deux .cfg dans {folder} (trouvés : {len(configs)})")
    for path in configs:
        raw = path.read_bytes()
        parsed = parse_cisco_ios(raw.decode("utf-8-sig"))
        ir = normalize_cisco_ios(parsed, source_file=path.name, sha256=hashlib.sha256(raw).hexdigest())
        report = audit_cis_ios15(ir, catalogue, profile="L2", complete_config=False,
                                parsed=parsed, audit_context={"external_interfaces": ["GigabitEthernet0/0"]})
        prefix = path.stem
        for kind, data in (("parsing", parsed), ("ir", ir), ("audit", report)):
            json_file(output / f"{prefix}.{kind}.json", data)
            html_file(output / f"{prefix}.{kind}.html", f"6NLG — {prefix} — {kind.upper()}", data, audit=kind == "audit")
        diagnostics = parsed.get("diagnostics", {}) if isinstance(parsed, dict) else {}
        print(f"{path.name}: {report['counts']} | non parsées globales={diagnostics.get('unparsed_global_count', 'voir JSON')}")
    print(f"Export terminé : {output} (6 JSON + 6 HTML)")


if __name__ == "__main__":
    main()
