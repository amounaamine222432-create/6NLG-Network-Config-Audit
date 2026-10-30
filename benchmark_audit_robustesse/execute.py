"""Adversarial mixed-config audit benchmark with fixed, human-written oracles.

The expected statuses are written below and never derived from audit outputs.
"""
import argparse
import csv
import hashlib
import html
import json
import sys
from collections import Counter
from pathlib import Path


def case(name, body, expected, *, complete=False, wan=None, reason=''):
    return dict(name=name, body=body, expected=expected, complete=complete,
                wan=wan if wan is not None else ['GigabitEthernet0/0'], reason=reason)


SAMPLES = [
    case('01_multi_eigrp_valid', '''key chain AUTH10
 key 1
  key-string DUMMY10
key chain AUTH20
 key 1
  key-string DUMMY20
interface GigabitEthernet0/0
 ip address 10.10.0.1 255.255.255.0
 ip authentication mode eigrp 10 md5
 ip authentication key-chain eigrp 10 AUTH10
interface GigabitEthernet0/1
 ip address 10.20.0.1 255.255.255.0
 ip authentication mode eigrp 20 md5
 ip authentication key-chain eigrp 20 AUTH20
router eigrp 10
 network 10.10.0.0 0.0.0.255
router eigrp 20
 network 10.20.0.0 0.0.0.255''',
         {'eigrp_interface_keychain': 'PASS', 'eigrp_interface_md5': 'PASS'},
         reason='Deux processus EIGRP disjoints ne doivent pas être croisés.'),
    case('02_multi_eigrp_one_missing_auth', '''key chain AUTH
 key 1
  key-string DUMMY
interface GigabitEthernet0/0
 ip address 10.10.0.1 255.255.255.0
 ip authentication mode eigrp 10 md5
 ip authentication key-chain eigrp 10 AUTH
interface GigabitEthernet0/1
 ip address 10.20.0.1 255.255.255.0
router eigrp 10
 network 10.10.0.0 0.0.0.255
router eigrp 20
 network 10.20.0.0 0.0.0.255''',
         {'eigrp_interface_keychain': 'FAIL', 'eigrp_interface_md5': 'FAIL'}, complete=True,
         reason='Une interface réellement sélectionnée par EIGRP 20 est non protégée.'),
    case('03_acl_wan_undefined', '''interface GigabitEthernet0/0
 ip address 198.51.100.2 255.255.255.252
 ip access-group DOES-NOT-EXIST in''',
         {'external_inbound_acl': 'FAIL', 'external_antispoof_acl': 'FAIL'}, complete=True,
         reason='Référence ACL non résolue : ne jamais conclure PASS.'),
    case('04_acl_wan_not_selected', '''ip access-list extended WAN
 deny ip any any
interface GigabitEthernet0/0
 ip access-group WAN in''',
         {'external_inbound_acl': 'UNKNOWN', 'external_antispoof_acl': 'UNKNOWN'},
         wan=[], reason='Sans désignation explicite de l’interface WAN, aucune preuve de périmètre.'),
    case('05_acl_wan_early_permit', '''ip access-list extended WAN
 permit ip any any
 deny ip any any
interface GigabitEthernet0/0
 ip access-group WAN in''',
         {'external_inbound_acl': 'PASS', 'external_antispoof_acl': 'FAIL'}, complete=True,
         reason='Une règle permit any any avant les deny annule l’anti-spoofing.'),
    case('06_acl_wan_after_deny', '''ip access-list extended WAN
 deny ip any any
 permit ip any any
interface GigabitEthernet0/0
 ip access-group WAN in''',
         {'external_inbound_acl': 'PASS', 'external_antispoof_acl': 'PASS'}, complete=True,
         reason='Les refus arrivent avant le permis, mais la politique bloque tout trafic ; contrôle fonctionnel séparé requis.'),
    case('07_vty_two_ranges_one_telnet', '''line vty 0 4
 transport input ssh
line vty 5 15
 transport input ssh telnet''',
         {'vty_ssh_only': 'FAIL'}, reason='Une seule plage VTY exposant telnet suffit à faire FAIL.'),
    case('08_vty_acl_one_broad', '''ip access-list standard SECURE
 permit host 10.1.1.10
 deny any
ip access-list standard OPEN
 permit any
line vty 0 4
 access-class SECURE in
line vty 5 15
 access-class OPEN in''',
         {'vty_access_class': 'FAIL', 'vty_restricting_acl': 'FAIL'},
         reason='Une plage VTY avec ACL permissive ne peut pas être masquée par une autre restrictive.'),
    case('09_vty_acl_missing_reference', '''ip access-list standard SECURE
 permit host 10.1.1.10
 deny any
line vty 0 4
 access-class SECURE in
line vty 5 15
 access-class MISSING in''',
         {'vty_access_class': 'FAIL'}, complete=True,
         reason='Référence ACL inconnue sur une des deux plages.'),
    case('10_aaa_none_on_one_range', '''aaa new-model
aaa authentication login default local
line vty 0 4
 login authentication default
line vty 5 15
 no login''',
         {'aaa_line_vty': 'FAIL'}, reason='Une plage VTY désactive la connexion malgré l’autre plage protégée.'),
    case('11_ntp_good_references', '''ntp authenticate
ntp authentication-key 1 md5 DUMMY
ntp authentication-key 2 md5 DUMMY
ntp trusted-key 1
ntp trusted-key 2
ntp server 192.0.2.10 key 1
ntp server 192.0.2.11 key 2''',
         {'ntp_server_keys': 'PASS', 'ntp_auth_keys': 'PASS', 'ntp_trusted_keys': 'PASS', 'ntp_servers': 'PASS'},
         reason='Chaque serveur référence une clé définie et trusted.'),
    case('12_ntp_one_untrusted', '''ntp authenticate
ntp authentication-key 1 md5 DUMMY
ntp authentication-key 2 md5 DUMMY
ntp trusted-key 1
ntp server 192.0.2.10 key 1
ntp server 192.0.2.11 key 2''',
         {'ntp_server_keys': 'FAIL'}, complete=True,
         reason='Une clé définie mais non déclarée trusted ne valide pas le serveur.'),
    case('13_ntp_untrusted_partial', '''ntp authenticate
ntp authentication-key 1 md5 DUMMY
ntp server 192.0.2.10 key 1''',
         {'ntp_server_keys': 'UNKNOWN'}, complete=False,
         reason='Sans hypothèse de complétude, la relation trusted est inconnue.'),
    case('14_ospf_two_areas_one_missing', '''interface GigabitEthernet0/0
 ip address 10.1.0.1 255.255.255.0
 ip ospf message-digest-key 1 md5 DUMMY
interface GigabitEthernet0/1
 ip address 10.2.0.1 255.255.255.0
 ip ospf message-digest-key 1 md5 DUMMY
router ospf 1
 network 10.1.0.0 0.0.0.255 area 0
 network 10.2.0.0 0.0.0.255 area 1
 area 0 authentication message-digest''',
         {'ospf_area_md5': 'FAIL', 'ospf_interface_md5': 'PASS'}, complete=True,
         reason='Une zone sans authentication message-digest; clés interface néanmoins définies.'),
    case('15_ospf_one_missing_interface_key', '''interface GigabitEthernet0/0
 ip address 10.1.0.1 255.255.255.0
 ip ospf message-digest-key 1 md5 DUMMY
interface GigabitEthernet0/1
 ip address 10.2.0.1 255.255.255.0
router ospf 1
 network 10.1.0.0 0.0.0.255 area 0
 network 10.2.0.0 0.0.0.255 area 0
 area 0 authentication message-digest''',
         {'ospf_area_md5': 'PASS', 'ospf_interface_md5': 'FAIL'}, complete=True,
         reason='La zone OSPF est protégée, mais une interface manque de clé MD5.'),
    case('16_bgp_one_peer_unprotected', '''router bgp 65001
 neighbor 192.0.2.2 remote-as 65002
 neighbor 192.0.2.2 password DUMMY
 neighbor 192.0.2.3 remote-as 65003''',
         {'bgp_neighbor_password': 'FAIL'}, complete=True,
         reason='Un voisin BGP sans password invalide le contrôle global.'),
    case('17_bgp_two_peers_protected', '''router bgp 65001
 neighbor 192.0.2.2 remote-as 65002
 neighbor 192.0.2.2 password DUMMY
 neighbor 192.0.2.3 remote-as 65003
 neighbor 192.0.2.3 password DUMMY''',
         {'bgp_neighbor_password': 'PASS'},
         reason='Les deux voisins BGP possèdent explicitement un password.'),
    case('18_acl_wan_missing_binding', '''ip access-list extended WAN
 deny ip any any
interface GigabitEthernet0/0
 description WAN-EDGE''',
         {'external_inbound_acl': 'FAIL'}, complete=True,
         reason='ACL définie mais non appliquée à l’interface externe.'),
    case('19_vty_acl_defined_but_unbound', '''ip access-list standard SECURE
 permit host 10.1.1.10
 deny any
line vty 0 4
 transport input ssh''',
         {'vty_restricting_acl': 'UNKNOWN', 'vty_access_class': 'UNKNOWN'},
         reason='Une ACL existante mais sans liaison aux VTY ne prouve pas le contrôle.'),
    case('20_bgp_incomplete_neighbor', '''router bgp 65001
 neighbor 192.0.2.2 remote-as 65002''',
         {'bgp_neighbor_password': 'UNKNOWN'},
         reason='Un mot de passe absent de l’extrait ne signifie pas nécessairement absent du routeur.'),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--project', default='.')
    args = parser.parse_args()
    root = Path(args.project).resolve()
    sys.path[:0] = [str(root), str(root / 'parsers')]
    from parsers.cisco_parser import parse_cisco_ios
    from normalizers.cisco_normalizer import normalize_cisco_ios
    from audit_engine.cis15_engine import audit_cis_ios15
    rules = json.loads((root / 'benchmarks/rules/cisco_ios/cis_ios15_v4.1.1_phase5_lab.json').read_text())
    out = root / 'benchmark_audit_robustesse' / 'output'
    configs = out / 'configs'
    configs.mkdir(parents=True, exist_ok=True)
    rows = []
    reports = {}
    for sample in SAMPLES:
        config = 'version 15.2\nhostname ' + sample['name'].upper().replace('-', '_') + '\n' + sample['body'] + '\nend\n'
        (configs / (sample['name'] + '.cfg')).write_text(config, encoding='utf-8')
        parsed = parse_cisco_ios(config)
        ir = normalize_cisco_ios(parsed, source_file=sample['name'] + '.cfg', sha256=hashlib.sha256(config.encode()).hexdigest())
        report = audit_cis_ios15(ir, rules, profile='L2', complete_config=sample['complete'],
                                 parsed=parsed, audit_context={'external_interfaces': sample['wan']})
        by_check = {r['check']: r['control_id'] for r in rules['rules']}
        findings = {f['cis_control_id']: f for f in report['findings']}
        reports[sample['name']] = report
        for check, expected in sample['expected'].items():
            finding = findings[by_check[check]]
            rows.append({'case': sample['name'], 'check': check, 'control_id': finding['cis_control_id'],
                         'expected': expected, 'actual': finding['status'],
                         'match': expected == finding['status'], 'reason': sample['reason'],
                         'evidence': finding.get('evidence', {})})
    (out / 'results.json').write_text(json.dumps({'evaluations': rows, 'reports': reports}, ensure_ascii=False, indent=2), encoding='utf-8')
    with (out / 'results.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['case', 'check', 'control_id', 'expected', 'actual', 'match', 'reason'])
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row[k] for k in writer.fieldnames})
    mismatch = [r for r in rows if not r['match']]
    summary = {'configurations': len(SAMPLES), 'assertions': len(rows), 'matches': len(rows)-len(mismatch),
               'mismatches': len(mismatch), 'expected_statuses': dict(Counter(x['expected'] for x in rows)),
               'actual_statuses': dict(Counter(x['actual'] for x in rows)),
               'scope': 'oracle synthétique manuel; revue experte CIS indépendante encore nécessaire'}
    (out / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    table = ''.join('<tr class="{}"><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><details><summary>Preuve</summary><pre>{}</pre></details></td></tr>'.format(
        'ok' if x['match'] else 'bad', html.escape(x['case']), html.escape(x['check']), x['expected'], x['actual'],
        html.escape(x['reason']), html.escape(json.dumps(x['evidence'], ensure_ascii=False, indent=2))) for x in rows)
    page = f'''<!doctype html><html lang="fr"><meta charset="utf-8"><title>6NLG — Robustesse audit</title>
    <style>body{{font:14px system-ui;background:#edf4fa;color:#19344b;margin:25px auto;max-width:1400px}}
    main{{padding:25px;background:white;border-radius:12px}}table{{width:100%;border-collapse:collapse}}th,td{{padding:10px;border-bottom:1px solid #cadbe7;vertical-align:top;text-align:left}}
    .ok{{background:#eefaf0}}.bad{{background:#ffe3de}}pre{{white-space:pre-wrap}}.warning{{padding:12px;background:#fff4ce}}</style>
    <main><h1>6NLG V68 — tests adversariaux et configurations mixtes</h1><p class="warning">Oracles rédigés avant exécution.
    La cohérence avec ces scénarios ne prouve pas une certification CIS officielle.</p>
    <h2>{len(SAMPLES)} configurations · {len(rows)} assertions · {len(mismatch)} écart(s)</h2>
    <p>Les écarts rouges nécessitent une revue de la configuration, du parsing, de l’IR et de la règle avant correction.</p>
    <table><tr><th>Config</th><th>Contrôle</th><th>Attendu</th><th>Observé</th><th>Justification</th><th>Évidence</th></tr>{table}</table></main></html>'''
    (out / 'RAPPORT_ROBUSTESSE.html').write_text(page, encoding='utf-8')
    print(f'{len(SAMPLES)} configurations ; {len(rows)} assertions ; {len(mismatch)} divergences')
    for row in mismatch:
        print(f"  {row['case']} / {row['check']}: attendu {row['expected']} ; obtenu {row['actual']}")
    return len(mismatch)


if __name__ == '__main__':
    raise SystemExit(bool(main()))
