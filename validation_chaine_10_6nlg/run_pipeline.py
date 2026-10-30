"""Ten Cisco IOS 15 configs: parser -> IR -> CIS audit -> JSON/HTML reports."""
import argparse
import hashlib
import html
import json
import sys
from collections import Counter
from pathlib import Path


# Only expectations established independently in the robustness fixtures are
# scored. The two large configs are exploratory, not labeled gold standards.
EXPECTED = {
    '01_multi_eigrp_valid': {'3.3.1.8': 'PASS', '3.3.1.9': 'PASS'},
    '02_multi_eigrp_one_missing_auth': {'3.3.1.8': 'FAIL', '3.3.1.9': 'FAIL'},
    '03_acl_wan_undefined': {'3.2.2': 'FAIL', '3.2.1': 'FAIL'},
    '05_acl_wan_early_permit': {'3.2.2': 'PASS', '3.2.1': 'FAIL'},
    '07_vty_two_ranges_one_telnet': {'1.2.2': 'FAIL'},
    '08_vty_acl_one_broad': {'1.2.4': 'FAIL', '1.2.5': 'FAIL'},
    '11_ntp_good_references': {'2.3.2': 'PASS'},
    '14_ospf_two_areas_one_missing': {'3.3.2.1': 'FAIL', '3.3.2.2': 'PASS'},
}
COMPLETE = {'02_multi_eigrp_one_missing_auth', '03_acl_wan_undefined',
            '05_acl_wan_early_permit', '14_ospf_two_areas_one_missing'}


def export_html(path, title, data, mode):
    style = '''body{font:14px system-ui;background:#eff4f9;color:#192b3d;margin:30px auto;max-width:1260px}
    article{background:white;padding:25px;border-radius:13px}h1{color:#194d79}table{width:100%;border-collapse:collapse}
    th,td{padding:10px;border-bottom:1px solid #d8e1ea;text-align:left;vertical-align:top}
    pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#eef3f7;padding:12px;border-radius:8px}
    .PASS{color:#1d7843;font-weight:bold}.FAIL{color:#b22929;font-weight:bold}.UNKNOWN{color:#9b6a00;font-weight:bold}'''
    if mode == 'audit':
        counts = data.get('counts', {})
        content = '<p>' + ' · '.join(f'{html.escape(k)}: {v}' for k, v in counts.items()) + '</p>'
        content += '<table><tr><th>Réf CIS</th><th>Statut</th><th>Contrôle</th><th>Preuve</th></tr>'
        for item in data.get('findings', []):
            status = html.escape(str(item['status']))
            content += '<tr><td>{}</td><td class="{}">{}</td><td>{}</td><td><pre>{}</pre></td></tr>'.format(
                html.escape(str(item['cis_control_id'])), status, status, html.escape(str(item['title'])),
                html.escape(json.dumps(item.get('evidence', {}), ensure_ascii=False, indent=2)))
        content += '</table>'
    else:
        content = '<p>Données complètes de la phase, à rapprocher du fichier CFG.</p><pre>' + html.escape(
            json.dumps(data, ensure_ascii=False, indent=2, default=str)) + '</pre>'
    path.write_text(f'<!doctype html><html lang="fr"><meta charset="utf-8"><title>{html.escape(title)}</title>'
                    f'<style>{style}</style><article><h1>{html.escape(title)}</h1>{content}</article></html>',
                    encoding='utf-8')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--project', default='.')
    args = parser.parse_args()
    root = Path(args.project).resolve()
    folder = root / 'validation_chaine_10_6nlg'
    sys.path[:0] = [str(root), str(root / 'parsers')]
    from parsers.cisco_parser import parse_cisco_ios
    from normalizers.cisco_normalizer import normalize_cisco_ios
    from audit_engine.cis15_engine import audit_cis_ios15
    catalogue = json.loads((root / 'benchmarks/rules/cisco_ios/cis_ios15_v4.1.1_phase5_lab.json').read_text())
    configs = sorted((folder / 'configs').glob('*.cfg'))
    if len(configs) != 10:
        raise SystemExit(f'Il faut 10 configurations, trouvé {len(configs)}')
    base = folder / 'export'
    for kind in ('parsing', 'ir', 'audit'):
        (base / kind).mkdir(parents=True, exist_ok=True)
    table = []
    errors = []
    for cfg in configs:
        raw = cfg.read_bytes()
        parsed = parse_cisco_ios(raw.decode('utf-8-sig'))
        ir = normalize_cisco_ios(parsed, source_file=cfg.name, sha256=hashlib.sha256(raw).hexdigest())
        complete = cfg.stem in COMPLETE
        report = audit_cis_ios15(ir, catalogue, profile='L2', complete_config=complete,
                                 parsed=parsed, audit_context={'external_interfaces': ['GigabitEthernet0/0']})
        for kind, data in [('parsing', parsed), ('ir', ir), ('audit', report)]:
            stem = base / kind / cfg.stem
            (stem.with_suffix('.json')).write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding='utf-8')
            export_html(stem.with_suffix('.html'), f'{cfg.stem} — {kind.upper()}', data, kind)
        by_id = {f['cis_control_id']: f['status'] for f in report['findings']}
        checked = EXPECTED.get(cfg.stem, {})
        discrepancies = [{'control': cid, 'expected': expected, 'actual': by_id.get(cid)}
                         for cid, expected in checked.items() if by_id.get(cid) != expected]
        errors.extend([{'config': cfg.name, **d} for d in discrepancies])
        diagnostics = parsed.get('diagnostics', {}) if isinstance(parsed, dict) else {}
        row = {'configuration': cfg.name, 'complete': complete,
               'pass': report['counts']['PASS'], 'fail': report['counts']['FAIL'],
               'unknown': report['counts']['UNKNOWN'], 'assertions': len(checked),
               'matched_assertions': len(checked) - len(discrepancies),
               'unparsed_global': diagnostics.get('unparsed_global_count', 'non disponible')}
        table.append(row)
        print(f"{cfg.name}: CIS PASS={row['pass']} FAIL={row['fail']} UNKNOWN={row['unknown']} | "
              f"attentes {row['matched_assertions']}/{row['assertions']}")
    summary = {'configurations': 10, 'assertions': sum(x['assertions'] for x in table),
               'matched': sum(x['matched_assertions'] for x in table),
               'discrepancies': errors, 'records': table,
               'note': 'Métriques ciblées pour huit cas ; deux configurations complètes exploratoires sans oracle global.'}
    (base / 'resume.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    cells = ''.join('<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}/{}</td></tr>'.format(
        html.escape(x['configuration']), x['pass'], x['fail'], x['unknown'], html.escape(str(x['unparsed_global'])),
        x['matched_assertions'], x['assertions']) for x in table)
    links = ''.join('<li><b>{}</b> : <a href="parsing/{}.html">Parsing</a> · '
                    '<a href="ir/{}.html">Normalisation IR</a> · <a href="audit/{}.html">Audit CIS</a></li>'.format(
                        html.escape(x['configuration']), Path(x['configuration']).stem,
                        Path(x['configuration']).stem, Path(x['configuration']).stem) for x in table)
    page = '''<!doctype html><html lang="fr"><meta charset="utf-8"><title>6NLG — 10 configurations</title>
    <style>body{font:15px system-ui;color:#163047;background:#eff4fa;margin:25px auto;max-width:1300px}
    main{background:white;padding:30px;border-radius:15px}table{width:100%;border-collapse:collapse}
    td,th{padding:11px;border-bottom:1px solid #dce5ed;text-align:left}a{color:#1662a0}
    .note{background:#fff5d4;padding:15px;border-radius:7px}</style><main><h1>6NLG — Validation bout-en-bout</h1>
    <p>10 fichiers Cisco IOS 15 testés par le pipeline Parsing → Normalisation IR → Audit CIS.</p>
    <p class="note">PASS/FAIL/UNKNOWN sont les sorties du moteur, et non des étiquettes de certification. Les deux
    routeurs complets sont exploratoires. Les assertions annotées portent sur huit tests ciblés.</p>
    <table><tr><th>Configuration</th><th>PASS</th><th>FAIL</th><th>UNKNOWN</th><th>Globales non parsées</th>
    <th>Assertions</th></tr>'''+cells+'</table><h2>Explorer les trois phases</h2><ul>'+links+'</ul></main></html>'
    (base / 'RESUME_CHAINE_10.html').write_text(page, encoding='utf-8')
    print(f"Export: 30 JSON + 30 HTML et résumé ; assertions={summary['matched']}/{summary['assertions']}")
    if errors:
        print('Écarts:', errors)
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
