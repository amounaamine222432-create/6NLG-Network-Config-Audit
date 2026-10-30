"""117 independently specified CIS IOS 15 lab cases.

Oracle labels are declared in CASES below, BEFORE running any 6NLG code.
This is a synthetic unit benchmark, not certification against the official CIS PDF.
"""
import argparse
import csv
import hashlib
import html
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


# Each explicit positive and negative is based on Cisco IOS configuration syntax.
# The third case is deliberately incomplete: the absence of evidence must be UNKNOWN.
# Do not adjust expected labels merely to agree with engine output.
CASES = {
    'aaa_new_model': ('aaa new-model', 'no aaa new-model'),
    'vty_ssh_only': ('line vty 0 4\n transport input ssh', 'line vty 0 4\n transport input telnet'),
    'console_exec_timeout': ('line con 0\n exec-timeout 5 0', 'line con 0\n exec-timeout 20 0'),
    'vty_exec_timeout': ('line vty 0 4\n exec-timeout 5 0', 'line vty 0 4\n exec-timeout 20 0'),
    'exec_banner_present': ('banner exec #AUTHORIZED#', 'hostname TEST'),
    'login_banner': ('banner login #AUTHORIZED#', 'hostname TEST'),
    'motd_banner': ('banner motd #AUTHORIZED#', 'hostname TEST'),
    'enable_secret_present': ('enable secret 9 DUMMYHASH', 'no enable secret'),
    'local_user_secrets': ('username admin secret 9 DUMMYHASH', 'username admin password 0 DUMMY'),
    'snmp_no_rw': ('snmp-server community EXAMPLE ro', 'snmp-server community EXAMPLE rw'),
    'snmp_v3_priv': ('snmp-server group ADM v3 priv', 'snmp-server group ADM v3 auth'),
    'ssh_version2': ('ip ssh version 2', 'ip ssh version 1'),
    'syslog_buffer': ('logging buffered 64000', 'logging buffered 4096'),
    'syslog_host': ('logging host 192.0.2.10', 'hostname TEST'),
    'syslog_informational': ('logging trap informational', 'logging trap debugging'),
    'syslog_source_present': ('logging source-interface Loopback0', 'hostname TEST'),
    'ntp_auth_enabled': ('ntp authenticate', 'no ntp authenticate'),
    'ntp_auth_keys': ('ntp authentication-key 1 md5 DUMMY', 'hostname TEST'),
    'ntp_trusted_keys': ('ntp trusted-key 1', 'hostname TEST'),
    'ntp_server_keys': (
        'ntp authenticate\nntp authentication-key 1 md5 DUMMY\nntp trusted-key 1\nntp server 192.0.2.10 key 1',
        'ntp server 192.0.2.10 key 99'),
    'ntp_servers': ('ntp server 192.0.2.10', 'hostname TEST'),
    'ntp_loopback_source': ('ntp source Loopback0', 'ntp source GigabitEthernet0/0'),
    'source_routing_disabled': ('no ip source-route', 'ip source-route'),
    'proxy_arp_disabled': ('interface GigabitEthernet0/0\n no ip proxy-arp',
                           'interface GigabitEthernet0/0\n ip proxy-arp'),
    'no_tunnel_interfaces': ('interface GigabitEthernet0/0\n no ip proxy-arp',
                             'interface Tunnel0\n ip address 10.0.0.1 255.255.255.252'),
    'bgp_neighbor_password': ('router bgp 65001\n neighbor 192.0.2.2 remote-as 65002\n neighbor 192.0.2.2 password DUMMY',
                              'router bgp 65001\n neighbor 192.0.2.2 remote-as 65002'),
    'aaa_login_default': ('aaa new-model\naaa authentication login default local',
                          'aaa new-model\naaa authentication login default none'),
    'aaa_enable_default': ('aaa new-model\naaa authentication enable default enable',
                           'aaa new-model\naaa authentication enable default none'),
    'aaa_line_console': ('aaa new-model\naaa authentication login default local\nline con 0\n login authentication default',
                         'aaa new-model\nline con 0\n no login'),
    'aaa_line_tty': ('aaa new-model\naaa authentication login default local\nline tty 1 2\n login authentication default',
                     'aaa new-model\nline tty 1 2\n no login'),
    'aaa_line_vty': ('aaa new-model\naaa authentication login default local\nline vty 0 4\n login authentication default',
                     'aaa new-model\nline vty 0 4\n no login'),
    'vty_restricting_acl': ('ip access-list standard VTY-MGMT\n permit host 10.1.1.10\n deny any\nline vty 0 4\n access-class VTY-MGMT in',
                              'ip access-list standard VTY-OPEN\n permit any\nline vty 0 4\n access-class VTY-OPEN in'),
    'vty_access_class': ('ip access-list standard VTY-MGMT\n permit host 10.1.1.10\n deny any\nline vty 0 4\n access-class VTY-MGMT in',
                          'ip access-list standard VTY-MGMT\n permit host 10.1.1.10\nline vty 0 4\n transport input ssh'),
    'external_antispoof_acl': ('ip access-list extended WAN\n deny ip any any\ninterface GigabitEthernet0/0\n ip access-group WAN in',
                               'ip access-list extended WAN\n permit ip any any\ninterface GigabitEthernet0/0\n ip access-group WAN in'),
    'external_inbound_acl': ('ip access-list extended WAN\n permit ip any any\ninterface GigabitEthernet0/0\n ip access-group WAN in',
                             'interface GigabitEthernet0/0\n ip access-group UNDEFINED in'),
    'eigrp_interface_keychain': (
        'key chain KEY\n key 1\n  key-string DUMMY\ninterface GigabitEthernet0/0\n ip address 10.1.0.1 255.255.255.0\n ip authentication key-chain eigrp 10 KEY\nrouter eigrp 10\n network 10.1.0.0 0.0.0.255',
        'interface GigabitEthernet0/0\n ip address 10.1.0.1 255.255.255.0\n ip authentication key-chain eigrp 10 MISSING\nrouter eigrp 10\n network 10.1.0.0 0.0.0.255'),
    'eigrp_interface_md5': (
        'interface GigabitEthernet0/0\n ip address 10.1.0.1 255.255.255.0\n ip authentication mode eigrp 10 md5\nrouter eigrp 10\n network 10.1.0.0 0.0.0.255',
        'interface GigabitEthernet0/0\n ip address 10.1.0.1 255.255.255.0\nrouter eigrp 10\n network 10.1.0.0 0.0.0.255'),
    'ospf_area_md5': ('router ospf 1\n network 10.1.0.0 0.0.0.255 area 0\n area 0 authentication message-digest',
                       'router ospf 1\n network 10.1.0.0 0.0.0.255 area 0'),
    'ospf_interface_md5': (
        'interface GigabitEthernet0/0\n ip address 10.1.0.1 255.255.255.0\n ip ospf message-digest-key 1 md5 DUMMY\nrouter ospf 1\n network 10.1.0.0 0.0.0.255 area 0',
        'interface GigabitEthernet0/0\n ip address 10.1.0.1 255.255.255.0\n ip ospf authentication null\nrouter ospf 1\n network 10.1.0.0 0.0.0.255 area 0'),
}


def run(root, out):
    sys.path[:0] = [str(root), str(root / 'parsers')]
    from parsers.cisco_parser import parse_cisco_ios
    from normalizers.cisco_normalizer import normalize_cisco_ios
    from audit_engine.cis15_engine import audit_cis_ios15
    catalogue = json.loads((root / 'benchmarks/rules/cisco_ios/cis_ios15_v4.1.1_phase5_lab.json').read_text())
    rules = catalogue['rules']
    checks = {r['check'] for r in rules}
    if len(rules) != 39 or checks != set(CASES):
        raise ValueError(f'Incohérence catalogue/scénarios: manquants={checks-set(CASES)}, extra={set(CASES)-checks}')
    out.mkdir(parents=True, exist_ok=True)
    configs = out / 'configs'
    configs.mkdir(exist_ok=True)
    results = []
    for idx, rule in enumerate(rules, 1):
        check = rule['check']
        for scenario, expected in [('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')]:
            # The empty UNKNOWN intentionally represents a partial configuration.
            fragment = CASES[check][0 if scenario == 'pass' else 1] if scenario != 'unknown' else 'hostname TEST'
            complete = (scenario == 'pass' and check == 'no_tunnel_interfaces') or (scenario == 'fail' and check not in {
                'aaa_new_model', 'vty_ssh_only', 'console_exec_timeout', 'vty_exec_timeout',
                'local_user_secrets', 'snmp_no_rw', 'snmp_v3_priv', 'ssh_version2',
                'syslog_buffer', 'syslog_informational', 'ntp_auth_enabled',
                'ntp_loopback_source', 'source_routing_disabled', 'proxy_arp_disabled',
                'no_tunnel_interfaces', 'aaa_login_default', 'aaa_enable_default',
                'aaa_line_console', 'aaa_line_tty', 'aaa_line_vty', 'vty_restricting_acl',
                'external_antispoof_acl', 'ospf_interface_md5', 'eigrp_interface_keychain',
            })
            config = 'version 15.2\nhostname TEST\n' + fragment + '\nend\n'
            key = f'{idx:02d}_{check}_{scenario}'
            (configs / f'{key}.cfg').write_text(config, encoding='utf-8')
            parsed = parse_cisco_ios(config)
            ir = normalize_cisco_ios(parsed, source_file=f'{key}.cfg', sha256=hashlib.sha256(config.encode()).hexdigest())
            report = audit_cis_ios15(ir, catalogue, profile='L2', complete_config=complete,
                                     parsed=parsed, audit_context={'external_interfaces': ['GigabitEthernet0/0']})
            finding = next(x for x in report['findings'] if x['cis_control_id'] == rule['control_id'])
            actual = finding['status']
            results.append({'case': key, 'control_id': rule['control_id'], 'check': check,
                            'expected': expected, 'actual': actual, 'match': expected == actual,
                            'complete_config': complete, 'evidence': finding.get('evidence', {}),
                            'oracle_basis': 'manually specified isolated IOS syntax; subject to expert review'})
    (out / 'results.json').write_text(json.dumps(results, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    with (out / 'results.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['case', 'control_id', 'check', 'expected', 'actual', 'match', 'complete_config'])
        writer.writeheader()
        writer.writerows({k: x[k] for k in writer.fieldnames} for x in results)
    confusion = defaultdict(Counter)
    for r in results:
        confusion[r['expected']][r['actual']] += 1
    metrics = {}
    for label in ('PASS', 'FAIL', 'UNKNOWN'):
        tp = sum(x['expected'] == label and x['actual'] == label for x in results)
        fp = sum(x['expected'] != label and x['actual'] == label for x in results)
        fn = sum(x['expected'] == label and x['actual'] != label for x in results)
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
        metrics[label] = {'TP': tp, 'FP': fp, 'FN': fn, 'precision': precision, 'recall': recall, 'f1': f1}
    result_summary = {'total': len(results), 'match': sum(r['match'] for r in results),
                      'mismatch': sum(not r['match'] for r in results),
                      'confusion': {k: dict(v) for k, v in confusion.items()}, 'metrics': metrics,
                      'qualification': 'synthetic manually prescribed labels, pending independent subject-matter review'}
    (out / 'summary.json').write_text(json.dumps(result_summary, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    rows = ''.join('<tr class="{}"><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><details><summary>Voir preuve</summary><pre>{}</pre></details></td></tr>'.format(
        'ok' if r['match'] else 'bad', html.escape(r['control_id']), html.escape(r['check']), r['expected'],
        r['actual'], html.escape(json.dumps(r['evidence'], ensure_ascii=False, indent=2))) for r in results)
    page = '''<!doctype html><html lang="fr"><meta charset="utf-8"><title>6NLG 117 tests CIS</title><style>
    body{font:14px system-ui;background:#f3f7fc;color:#172638;margin:30px auto;max-width:1320px}main{background:white;padding:30px;border-radius:15px}
    table{border-collapse:collapse;width:100%}td,th{padding:9px;border-bottom:1px solid #dce5ed;text-align:left;vertical-align:top}
    .ok{background:#e8f9ed}.bad{background:#ffe4e4}pre{white-space:pre-wrap} .warn{background:#fff3cb;padding:14px}
    </style><main><h1>6NLG — Benchmark expérimental 117 cas</h1><p class="warn">Les attentes ont été écrites avant l'exécution
    du moteur, mais les scénarios synthétiques doivent encore être revus indépendamment par un expert Cisco/CIS. Ce résultat ne certifie
    pas la conformité à la norme CIS officielle.</p><h2>Résultats</h2><p>'''+ str(result_summary['match']) + ''' correspondances / 117 ; ''' + str(result_summary['mismatch']) + ''' écarts.</p><table><tr><th>CIS</th><th>Contrôle</th><th>Attendu</th><th>Observé</th><th>Preuve</th></tr>'''+rows+'</table></main></html>'
    (out / 'RESULTATS_117.html').write_text(page, encoding='utf-8')
    print(f"{result_summary['match']}/117 conformes aux attentes, {result_summary['mismatch']} divergences")
    for r in results:
        if not r['match']:
            print(f"  {r['case']}: attendu={r['expected']} observé={r['actual']}")
    return result_summary['mismatch']


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--project', default='.')
    parser.add_argument('--output')
    args = parser.parse_args()
    root = Path(args.project).resolve()
    raise SystemExit(bool(run(root, Path(args.output).resolve() if args.output else root / 'benchmark_audit_cis_117' / 'run_output')))
