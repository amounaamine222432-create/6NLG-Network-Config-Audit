import unittest

from parsers.cisco_parser import parse_cisco_ios
from normalizers.cisco_normalizer import normalize_cisco_ios


class EigrpAclOptionTests(unittest.TestCase):
    def test_eigrp_no_auto_summary(self):
        raw = 'version 15.2\nhostname R-ONE\nrouter eigrp 10\n network 10.0.0.0 0.0.255.255\n no auto-summary\nend\n'
        parsed = parse_cisco_ios(raw)
        self.assertIs(parsed['eigrp_processes'][0]['auto_summary_enabled'], False)
        self.assertEqual(parsed['eigrp_processes'][0]['other_count'], 0)
        ir = normalize_cisco_ios(parsed)
        self.assertIs(ir['routing']['eigrp'][0]['auto_summary_enabled'], False)
        self.assertEqual(ir['routing']['eigrp'][0]['unmodeled_command_count'], 0)

    def test_eigrp_positive_and_unspecified(self):
        raw = 'version 15.2\nhostname R-TWO\nrouter eigrp 10\n auto-summary\nend\n'
        self.assertIs(normalize_cisco_ios(parse_cisco_ios(raw))['routing']['eigrp'][0]['auto_summary_enabled'], True)
        raw = 'version 15.2\nhostname R-THREE\nrouter eigrp 10\n network 10.0.0.0\nend\n'
        self.assertIsNone(normalize_cisco_ios(parse_cisco_ios(raw))['routing']['eigrp'][0]['auto_summary_enabled'])

    def test_acl_logging_mode_and_other_tokens(self):
        raw = '''version 15.2
hostname R-ACL
ip access-list extended FILTER
 deny ip any any log
 permit tcp any any eq 443 log-input
 deny ip any any time-range WORK
end
'''
        parsed = parse_cisco_ios(raw)
        entries = parsed['access_lists'][0]['entries']
        self.assertEqual(entries[0]['logging_mode'], 'log')
        self.assertEqual(entries[1]['logging_mode'], 'log-input')
        self.assertIsNone(entries[2]['logging_mode'])
        self.assertEqual(entries[2]['remaining_tokens'], ['time-range', 'WORK'])
        ir_entries = normalize_cisco_ios(parsed)['policies']['acls'][0]['entries']
        self.assertEqual([x['logging_mode'] for x in ir_entries], ['log', 'log-input', None])
        self.assertEqual([x['unmodeled_token_count'] for x in ir_entries], [0, 0, 2])


if __name__ == '__main__':
    unittest.main()
