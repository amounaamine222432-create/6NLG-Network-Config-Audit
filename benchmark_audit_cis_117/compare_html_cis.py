"""Compare 6NLG existing audit exports to the local CIS lab mapping.

The catalogue is a lab subset, NOT the official CIS benchmark PDF.
No metric is claimed without independent ground-truth labels.
"""
import argparse
import collections
import html
import json
from pathlib import Path


def esc(value):
    return html.escape(str(value), quote=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--project', default='.')
    p.add_argument('--output', default=None)
    args = p.parse_args()
    root = Path(args.project).resolve()
    catalogue_path = root / 'benchmarks/rules/cisco_ios/cis_ios15_v4.1.1_phase5_lab.json'
    export = root / 'final_validation_6nlg/export'
    output = Path(args.output).resolve() if args.output else root / 'benchmark_audit_cis_117/output'
    output.mkdir(parents=True, exist_ok=True)
    catalogue = json.loads(catalogue_path.read_text(encoding='utf-8'))
    rules = catalogue['rules']
    if len(rules) != 39:
        raise SystemExit(f'Catalogue incorrect: {len(rules)} règles, 39 attendues')
    names = ['01_R-FINAL-HARDENED', '02_R-FINAL-MIXED-RISK']
    reports = {}
    for name in names:
        path = export / f'{name}.audit.json'
        reports[name] = json.loads(path.read_text(encoding='utf-8'))
    indexed = {name: {str(x['cis_control_id']): x for x in report['findings']}
               for name, report in reports.items()}
    matrix = []
    for rule in rules:
        cid = rule['control_id']
        for expected in ('PASS', 'FAIL', 'UNKNOWN'):
            matrix.append({
                'control_id': cid, 'check': rule['check'],
                'target_status': expected, 'oracle_status': 'A_VALIDER_MANUELLEMENT',
                'case_config': None, 'expected_evidence': None,
                'comment': 'Construire une configuration indépendante et justifier le statut attendu.',
            })
    (output / 'matrice_117_a_completer.json').write_text(
        json.dumps({'method': '39 contrôles × 3 statuts ciblés; aucun oracle inventé', 'cases': matrix},
                   ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    rows = []
    discrepancies = []
    for rule in rules:
        cid = rule['control_id']
        cells = []
        for name in names:
            finding = indexed[name].get(cid)
            if not finding:
                status, evidence = 'ABSENT', {}
                discrepancies.append(f'{name}: contrôle {cid} absent')
            else:
                status, evidence = finding['status'], finding.get('evidence', {})
            cells.append((name, status, evidence))
        cols = ''.join('<td><span class="pill {}">{}</span><details><summary>Preuves IR / audit</summary><pre>{}</pre></details></td>'.format(
            esc(status), esc(status), esc(json.dumps(evidence, ensure_ascii=False, indent=2)))
            for _, status, evidence in cells)
        rows.append('<tr><td><b>{}</b><br><small>p. {}</small></td><td>{}<br><small>{}</small></td>{}<td>{}</td></tr>'.format(
            esc(cid), esc(rule.get('pdf_page', '?')), esc(rule['title']), esc(rule['check']),
            cols, esc(rule.get('remediation', ''))))
    sums = {name: dict(collections.Counter(x['status'] for x in indexed[name].values())) for name in names}
    summary = ' | '.join(f'{esc(name)} : ' + ', '.join(f'{esc(k)}={v}' for k, v in sorted(sums[name].items())) for name in names)
    style = '''body{font:14px system-ui,sans-serif;background:#f2f6fb;color:#182a3c;margin:0}
    main{max-width:1500px;margin:auto;padding:35px}h1{color:#123c64}article{background:white;padding:22px;
    border-radius:14px;margin:16px 0;box-shadow:0 2px 14px #1231}table{border-collapse:collapse;width:100%}
    th,td{border-bottom:1px solid #dbe5ee;padding:12px;vertical-align:top;text-align:left}th{background:#e8f0f8}
    tr:hover{background:#f6faff}.pill{border-radius:9px;padding:3px 8px;font-weight:bold}
    .PASS{background:#d7f5e3;color:#126838}.FAIL{background:#ffe0df;color:#a12323}
    .UNKNOWN{background:#fff0bf;color:#805400}.ABSENT{background:#ddd;color:#444}
    details{margin-top:8px}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}
    .warning{border-left:5px solid #e5a327;background:#fff8e4;padding:15px}small{color:#526476}'''
    body = f'''<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>6NLG — CIS vs HTML existants</title>
    <style>{style}</style></head><body><main><h1>6NLG — Comparaison audit existant / référentiel CIS local</h1>
    <article class="warning"><b>Portée :</b> comparaison des deux exports existants avec les 39 règles du catalogue
    local CIS IOS 15 v4.1.1 phase 5 <b>de laboratoire</b>. Il ne s'agit pas d'une certification ni d'une
    confrontation indépendante au PDF officiel. PASS signifie « le moteur a conclu PASS », non « CIS a certifié PASS ».
    La colonne recommandation est issue du catalogue local, pas d'une vérification directe du PDF original.</article>
    <article><h2>Résultats observés</h2><p>{summary}</p><p>39 contrôles × 2 configurations = 78
    observations. 39 × 3 = 117 scénarios <b>cibles</b> ; le fichier <code>matrice_117_a_completer.json</code>
    indique ceux à construire et à faire annoter indépendamment.</p>
    <p>Les résultats UNKNOWN ne doivent pas être comptés comme PASS ni comme FAIL. Les métriques précision/rappel/F1
    nécessitent des étiquettes attendues indépendantes et ne sont donc pas calculées ici.</p></article>
    <article><h2>Contrôle par contrôle : exigence / résultat / preuve</h2><table><thead><tr>
    <th>Réf. CIS locale</th><th>Intitulé du contrôle</th><th>Routeur renforcé</th>
    <th>Routeur avec risques</th><th>Correction de référence</th></tr></thead><tbody>{''.join(rows)}
    </tbody></table></article>
    <article><h2>Vérification méthodologique</h2><ol><li>Confirmer le PDF CIS officiel et sa version
    avant toute affirmation de conformité.</li><li>Pour chaque règle, préparer des échantillons PASS, FAIL et
    UNKNOWN annotés sans consulter le résultat du moteur.</li><li>Rejouer parsing → normalisation IR → audit
    sur chaque fichier, et conserver les JSON et HTML.</li><li>Contrôler les preuves et les dépendances du
    contexte (<code>complete_config</code>, interfaces WAN, commandes show).</li><li>Calculer la matrice
    de confusion par statut uniquement sur les cas dont l'oracle a été validé.</li></ol></article>
    </main></body></html>'''
    (output / 'COMPARAISON_CIS_VS_HTML_EXISTANTS.html').write_text(body, encoding='utf-8')
    (output / 'observations_existantes.json').write_text(json.dumps({
        'counts': sums, 'issues': discrepancies,
        'observations': [{
            'configuration': name, 'control_id': cid,
            'status': finding['status'], 'evidence': finding.get('evidence', {})
        } for name, findings in indexed.items() for cid, finding in findings.items()]},
        ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'39 contrôles, 78 observations, 117 scénarios à labelliser : {output}')
    if discrepancies:
        print('ATTENTION:', discrepancies)


if __name__ == '__main__':
    main()
