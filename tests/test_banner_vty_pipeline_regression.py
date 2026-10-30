import json
import unittest
from pathlib import Path

from parsers.cisco_parser import parse_cisco_ios
from normalizers.cisco_normalizer import normalize_cisco_ios
from audit_engine.cis15_engine import audit_cis_ios15

ROOT = Path(__file__).resolve().parents[1]
CATALOGUE = json.loads((ROOT / 'benchmarks/rules/cisco_ios/cis_ios15_v4.1.1_phase5_lab.json').read_text())


class BannerVtyPipelineRegression(unittest.TestCase):
    def test_inline_banner_does_not_hide_lines_and_audit(self):
        raw = '''version 15.2
hostname R-BANNER
aaa new-model
aaa authentication login default local
ip ssh version 2
banner motd ^CAcces reserve^C
line con 0
 exec-timeout 5 0
 login authentication default
line vty 0 4
 exec-timeout 5 0
 transport input ssh
 login authentication default
line vty 5 15
 exec-timeout 15 0
 transport input ssh
 login authentication default
end
'''
        parsed = parse_cisco_ios(raw)
        self.assertEqual([x['identifier'] for x in parsed['lines']],
                         ['con 0', 'vty 0 4', 'vty 5 15'])
        ir = normalize_cisco_ios(parsed)
        self.assertEqual(len(ir['management']['terminal_lines']), 3)
        report = audit_cis_ios15(ir, CATALOGUE, profile='L2')
        statuses = {x['rule_id']: x['status'] for x in report['findings']}
        timeout = next(x for x in report['findings'] if x['title'] and 'EXEC VTY' in x['title'])
        self.assertEqual(timeout['status'], 'FAIL')

    def test_multiline_banner_followed_by_vty(self):
        raw = 'version 15.2\nhostname R-MULTI\nbanner motd ^C\nMessage\n^C\nline vty 0 4\n transport input ssh\nend\n'
        parsed = parse_cisco_ios(raw)
        self.assertEqual(len(parsed['lines']), 1)


if __name__ == '__main__':
    unittest.main()
