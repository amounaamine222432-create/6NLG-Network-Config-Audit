"""Cisco IOS clock timezone: extraction, normalisation et prudence sémantique."""

import unittest

from cisco_parser import parse_cisco_ios
from normalizers.cisco_normalizer import normalize_cisco_ios


class ClockTimezoneTests(unittest.TestCase):
    def test_timezone_optional_minutes(self):
        parsed = parse_cisco_ios("hostname R1\nclock timezone CET 1\n")
        self.assertEqual(parsed["unparsed_lines"], [])
        ir = normalize_cisco_ios(parsed)
        self.assertEqual(ir["services"]["clock"]["timezone"]["hours_offset"], 1)
        self.assertEqual(ir["services"]["clock"]["timezone"]["minutes_offset"], 0)
        self.assertIsNone(ir["services"]["clock"]["synchronized"])

    def test_timezone_negative_with_minutes(self):
        parsed = parse_cisco_ios("clock timezone AST -3 30\n")
        self.assertEqual(parsed["unparsed_lines"], [])
        ir = normalize_cisco_ios(parsed)
        self.assertEqual(ir["services"]["clock"]["timezone"]["hours_offset"], -3)
        self.assertEqual(ir["services"]["clock"]["timezone"]["minutes_offset"], 30)

    def test_timezone_explicit_removal(self):
        parsed = parse_cisco_ios("clock timezone CET 1 0\nno clock timezone\n")
        self.assertEqual(parsed["unparsed_lines"], [])
        self.assertIsNone(normalize_cisco_ios(parsed)["services"]["clock"]["timezone"])

    def test_invalid_is_not_silently_classified(self):
        parsed = parse_cisco_ios("clock timezone CET bogus\nclock timezone CET 1 80\n")
        self.assertEqual(len(parsed["unparsed_lines"]), 2)
        self.assertEqual(normalize_cisco_ios(parsed)["diagnostics"]["unparsed_global_count"], 2)


if __name__ == "__main__":
    unittest.main()
