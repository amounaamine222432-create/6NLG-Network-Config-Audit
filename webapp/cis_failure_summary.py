"""Downloadable, sanitized CSV table of the CIS failures in one audit."""

from __future__ import annotations

import csv
from io import StringIO
from html import escape


def failure_summary_html(report: dict) -> bytes:
    """Standalone printable, escaped HTML summary of CIS and network failures."""
    rows = []
    for finding in report.get("findings", []):
        if finding.get("status") == "FAIL":
            rows.append((finding.get("cis_control_id") or "CIS",
                         finding.get("title") or "Contrôle non conforme",
                         finding.get("risk_level") or "À évaluer",
                         finding.get("observed_summary") or "Constat non détaillé",
                         finding.get("source_location") or "Non déterminé",
                         finding.get("remediation") or "Vérifier manuellement",
                         finding.get("verification_command") or "Non précisée",
                         finding.get("remediation_example") or "Exemple non disponible : intervention manuelle requise.",
                         finding.get("source_anchors") or []))
    for finding in (report.get("network_coherence") or {}).get("findings", []):
        if finding.get("status") in {"FAIL", "REVIEW"}:
            rows.append((finding.get("rule_id") or "RÉSEAU",
                         "Cohérence réseau", finding.get("severity") or "À évaluer",
                         finding.get("description") or "Vérification nécessaire",
                         "Contexte réseau / IR",
                         finding.get("recommendation") or "Vérifier manuellement",
                         "show ip route / show ip interface / show ip access-lists",
                         "Aucune commande corrective automatique : validation réseau requise.",
                         [{"line": line} for line in finding.get("source_lines") or []]))
    def cell(value):
        return escape(str(value), quote=True)
    cards = "".join(
        f'<article class="finding"><div class="heading"><span class="number">{index:02d}</span>'
        f'<div><span class="rule">{cell(rule)}</span><h2>{cell(title)}</h2></div>'
        f'<span class="risk">{cell(risk)}</span></div>'
        f'<section><h3>Faute / constat</h3><p>{cell(fault)}</p></section>'
        f'<section><h3>Preuve / emplacement</h3><p class="source">{cell(source)}</p>'
        f'<p>{cell(", ".join("L" + str(a.get("line")) for a in anchors[:12] if isinstance(a, dict) and type(a.get("line")) is int) or "Aucun repère direct disponible")}</p></section>'
        f'<section class="fix"><h3>Correction recommandée</h3><p>{cell(remediation)}</p></section>'
        f'<section><h3>Exemple IOS à adapter (ne pas exécuter sans validation)</h3><pre>{cell(example)}</pre></section>'
        f'<section><h3>Commande de vérification</h3><pre>{cell(command)}</pre></section></article>'
        for index, (rule, title, risk, fault, source, remediation, command, example, anchors) in enumerate(rows, 1))
    if not cards:
        cards = '<div class="empty">Aucune non-conformité FAIL ou anomalie réseau à signaler.</div>'
    hostname = cell(report.get("hostname") or "Routeur analysé")
    document = f'''<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>6NLG · Synthèse des non-conformités · {hostname}</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;background:#0d1b2b;color:#e7eff7;font:15px/1.65 system-ui,Arial,sans-serif}}
.wrap{{max-width:1050px;margin:auto;padding:35px 22px 70px}}header{{border:1px solid #31546b;border-radius:18px;padding:28px;background:#12283e}}
.eyebrow{{color:#60e4d6;letter-spacing:.15em;font-size:12px;font-weight:800}}h1{{font-size:30px;margin:8px 0}}header p{{color:#b8ccda;margin:0}}
.count{{display:inline-block;background:#193f4c;color:#92fff0;padding:8px 15px;border-radius:30px;margin-top:17px;font-weight:bold}}
.finding{{background:#142a40;border:1px solid #34546b;border-radius:16px;margin-top:22px;padding:24px;break-inside:avoid}}
.heading{{display:flex;align-items:center;gap:15px;flex-wrap:wrap;border-bottom:1px solid #365168;padding-bottom:15px}}
.number{{font-size:22px;color:#6de2d6;font-weight:bold}}.heading>div{{flex:1;min-width:170px}}.rule{{font-size:12px;color:#8de8df;font-weight:bold}}h2{{font-size:19px;margin:1px 0}}
.risk{{background:#533243;color:#ffd8db;border-radius:30px;padding:5px 12px;font-size:12px;font-weight:bold}}
section{{margin-top:16px}}h3{{margin:0 0 5px;font-size:12px;text-transform:uppercase;letter-spacing:.07em;color:#84b7d2}}
p{{margin:0;overflow-wrap:anywhere;white-space:pre-wrap}}.source,pre{{background:#0a1b2c;border-radius:8px;padding:11px 14px;overflow-wrap:anywhere;white-space:pre-wrap}}
pre{{font:12px/1.6 ui-monospace,Consolas,monospace;margin:0}}.fix{{border-left:3px solid #4ed5ac;padding-left:14px}}
.empty{{padding:25px;border:1px solid #31546b;border-radius:14px;margin-top:22px}}footer{{font-size:12px;color:#9eb1bf;margin-top:25px}}
@media print{{body{{background:white;color:#14243a}}.wrap{{max-width:none;padding:12mm}}header,.finding{{background:white;color:#14243a;border:1px solid #a6b4c0}}.source,pre{{background:#f2f6f8;color:#14243a}}.risk{{background:#fce8e9;color:#781f32}}}}
</style></head><body><main class="wrap"><header><div class="eyebrow">6NLG · AUDIT DE CONFIGURATION</div>
<h1>Synthèse des non-conformités</h1><p>Équipement : {hostname} · Contrôles CIS et cohérence réseau</p>
<div class="count">{len(rows)} anomalie(s) à examiner</div></header>{cards}
<footer>Rapport de synthèse généré à partir des résultats de l'audit. Vérifier les corrections sur l'équipement avant application.</footer>
</main></body></html>'''
    return document.encode("utf-8")


def failure_summary_csv(report: dict) -> bytes:
    buffer = StringIO(newline="")
    writer = csv.writer(buffer, delimiter=";")
    writer.writerow(("Controle CIS", "Regle", "Erreur / constat", "Impact",
                     "Emplacement source", "Correction conseillee", "Verification"))
    for finding in report.get("findings", []):
        if finding.get("status") != "FAIL":
            continue
        writer.writerow((
            finding.get("cis_control_id") or "",
            finding.get("title") or "",
            finding.get("observed_summary") or "Constat non detaille",
            finding.get("risk_level") or "NON_EVALUE",
            finding.get("source_location") or "Non determine",
            finding.get("remediation") or "Verifier manuellement",
            finding.get("verification_command") or "",
        ))
    for finding in (report.get("network_coherence") or {}).get("findings", []):
        if finding.get("status") not in {"FAIL", "REVIEW"}:
            continue
        writer.writerow((
            "RESEAU", finding.get("rule_id") or "",
            finding.get("description") or "Vérification réseau nécessaire",
            finding.get("severity") or "NON_EVALUE", "Contexte IR",
            finding.get("recommendation") or "Vérifier manuellement",
            "show ip route / show ip interface / show ip access-lists",
        ))
    return ("\ufeff" + buffer.getvalue()).encode("utf-8")
