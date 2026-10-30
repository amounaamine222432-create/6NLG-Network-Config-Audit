"""Verify three complete lab configurations through parsing, IR and CIS V68."""
import hashlib
import html
import json
import sys
from pathlib import Path


EXPECTED_RISK_FAILS = {
    '1.2.2', '1.5.9', '2.1.1.2', '2.2.2', '2.2.5',
    '2.3.1.3', '2.3.1.4', '3.1.1', '3.3.4.1',
}
EXPECTED_NA = {'1.5.4', '1.1.5'}


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()
    sys.path[:0] = [str(root), str(root / 'parsers'), str(root / 'final_validation_6nlg')]
    from parsers.cisco_parser import parse_cisco_ios
    from normalizers.cisco_normalizer import normalize_cisco_ios
    from audit_engine.cis15_engine import audit_cis_ios15
    from export_final_validation import json_file, html_file
    directory = root / 'validation_reference_cis_39'
    output = directory / 'export'
    output.mkdir(parents=True, exist_ok=True)
    catalogue = json.loads((root / 'benchmarks/rules/cisco_ios/cis_ios15_v4.1.1_phase5_lab.json').read_text())
    files = sorted(directory.glob('*.cfg'))
    if len(files) != 3:
        raise SystemExit(f'3 configurations .cfg requises, trouvées: {len(files)}')
    records, problems = [], []
    for cfg in files:
        raw = cfg.read_bytes()
        parsed = parse_cisco_ios(raw.decode('utf-8-sig'))
        ir = normalize_cisco_ios(parsed, source_file=cfg.name, sha256=hashlib.sha256(raw).hexdigest())
        audit = audit_cis_ios15(ir, catalogue, profile='L2', complete_config=True,
                                parsed=parsed, audit_context={'external_interfaces': ['GigabitEthernet0/0']})
        for name, data in [('parsing', parsed), ('ir', ir), ('audit', audit)]:
            json_file(output / f'{cfg.stem}.{name}.json', data)
            html_file(output / f'{cfg.stem}.{name}.html', f'{cfg.name} — {name.upper()}', data,
                      audit=name == 'audit')
        statuses = {str(x['cis_control_id']): x['status'] for x in audit['findings']}
        desired = {x['control_id']: 'PASS' for x in catalogue['rules']}
        desired.update({cid: 'NOT_APPLICABLE' for cid in EXPECTED_NA})
        if 'CONTROLLED-RISKS' in cfg.stem:
            desired.update({cid: 'FAIL' for cid in EXPECTED_RISK_FAILS})
        mismatches = [{'cis': cid, 'expected': wanted, 'actual': statuses.get(cid)}
                      for cid, wanted in desired.items() if statuses.get(cid) != wanted]
        diagnostics = ir.get('diagnostics') or {}
        if diagnostics.get('unparsed_global_count') != 0:
            problems.append(f'{cfg.name}: commandes globales non analysées')
        if diagnostics.get('opaque_sections'):
            problems.append(f'{cfg.name}: sections opaques')
        problems.extend(f"{cfg.name}: CIS {m['cis']}: attendu {m['expected']}, reçu {m['actual']}"
                        for m in mismatches)
        row = {'configuration': cfg.name, 'counts': audit['counts'], 'checks': len(desired),
               'matches': len(desired) - len(mismatches),
               'unparsed_global_count': diagnostics.get('unparsed_global_count'),
               'opaque_section_count': len(diagnostics.get('opaque_sections') or []),
               'mismatches': mismatches}
        records.append(row)
        print(f"{cfg.name}: {audit['counts']} | tests={row['matches']}/{row['checks']} "
              f"| non parsées={row['unparsed_global_count']}")
    summary = {'results': records, 'problems': problems, 'benchmark_scope': '39 contrôles CIS de laboratoire',
               'complete_config': True, 'external_interfaces': ['GigabitEthernet0/0'],
               'note': 'Configs de laboratoire avec identifiants/secrets fictifs, non déployables en production.'}
    json_file(output / 'RESUME_VALIDATION.json', summary)
    table = ''.join('<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}/39</td><td>{}</td></tr>'.format(
        html.escape(x['configuration']), x['counts']['PASS'], x['counts']['FAIL'],
        x['counts']['NOT_APPLICABLE'], x['matches'], x['unparsed_global_count']) for x in records)
    links = ''.join('<li>{}: <a href="{}.parsing.html">Parsing</a> · '
                    '<a href="{}.ir.html">Normalisation IR</a> · <a href="{}.audit.html">Audit CIS</a></li>'.format(
                        html.escape(x['configuration']), Path(x['configuration']).stem,
                        Path(x['configuration']).stem, Path(x['configuration']).stem) for x in records)
    page = '''<!doctype html><html lang="fr"><meta charset="utf-8"><title>6NLG CIS 39 — Trois configurations</title>
    <style>body{font:15px system-ui;background:#eff5fb;color:#153046;margin:35px auto;max-width:1250px}
    main{background:white;padding:30px;border-radius:15px}table{width:100%;border-collapse:collapse}
    td,th{padding:12px;border-bottom:1px solid #d7e3ed;text-align:left}a{color:#155d9a}
    .warn{background:#fff2cf;padding:12px;border-radius:8px}</style><main><h1>6NLG — Comparaison des 3 configurations CIS 39</h1>
    <p class="warn">Référentiel local de laboratoire, <b>sans certification CIS officielle</b>.
    Les secrets sont fictifs et ne doivent pas être déployés. L'hypothèse de complétude est activée uniquement pour ce benchmark.</p>
    <table><tr><th>Configuration</th><th>PASS</th><th>FAIL</th><th>N/A</th><th>Attentes correctes</th>
    <th>Globales non parsées</th></tr>'''+table+'</table><h2>Explorer chaque phase</h2><ul>'+links+'</ul></main></html>'
    (output / 'RESUME_VALIDATION.html').write_text(page, encoding='utf-8')
    print(f"Bilan : {sum(x['matches'] for x in records)}/117, anomalies={len(problems)} ; exports: 9 JSON + 9 HTML + résumés")
    for problem in problems:
        print('ECART:', problem)
    return bool(problems)


if __name__ == '__main__':
    raise SystemExit(main())
