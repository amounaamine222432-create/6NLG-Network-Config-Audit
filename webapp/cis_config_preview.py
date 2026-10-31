"""Bounded, read-only and secret-redacted IOS configuration preview.

Never store the original upload. Only the redacted text is embedded in the
session-scoped HTML report; unknown/unsafe directives remain masked.
"""

from __future__ import annotations

import re


_SAFE = re.compile(r"[A-Za-z0-9_.:/, -]+\Z")
_ALLOWED_PREFIXES = (
    "version ", "hostname ", "ip source-route", "no ip source-route",
    "ip http server", "no ip http server", "no ip http secure-server",
    "aaa new-model", "no aaa new-model", "aaa authentication ",
    "ip ssh version ", "ip access-list ", "access-list ",
    "permit ", "deny ", "ip prefix-list ", "route-map ",
    "match ip address ", "vrf definition ", "rd ", "vlan ",
    "ip dhcp excluded-address ", "ip dhcp pool ", "network ",
    "default-router ", "dns-server ", "ip nat inside source ",
    "interface ", "ip address ", "ip access-group ",
    "ip nat inside", "ip nat outside", "ip proxy-arp", "no ip proxy-arp",
    "no shutdown", "shutdown", "ip authentication mode eigrp ",
    "ip authentication key-chain eigrp ", "router ospf ",
    "router eigrp ", "router bgp ", "router-id ", "bgp router-id ",
    "area ", "passive-interface ", "no auto-summary", "key chain ",
    "key ", "neighbor ", "ip route ", "logging buffered ",
    "logging trap ", "logging source-interface ", "logging host ",
    "ntp authenticate", "no ntp authenticate", "ntp trusted-key ",
    "ntp source ", "ntp server ", "snmp-server group ",
    "line con ", "line vty ", "line tty ", "exec-timeout ",
    "transport input ", "login authentication ", "access-class ",
    "end", "exit", "!",
)
_MASKED_PREFIXES = (
    "username ", "enable secret", "enable password", "key-string",
    "ntp authentication-key ", "snmp-server community ", "banner ",
    "description ", "remark ",
)


def redacted_ios_preview(source_text: str, max_lines: int = 4000) -> list[dict]:
    """Return bounded numbered text with no credentials or free-form remarks."""
    result = []
    for line_no, raw in enumerate(source_text.splitlines()[:max_lines], 1):
        command = raw.strip()
        if not command:
            shown = ""
        elif command.lower().startswith(_MASKED_PREFIXES) or re.search(
            r"\b(secret|password|community|key-string|authentication-key)\b", command, re.I
        ):
            shown = "[DIRECTIVE SENSIBLE MASQUÉE]"
        elif command.lower().startswith(_ALLOWED_PREFIXES) and _SAFE.fullmatch(command):
            shown = command
        else:
            shown = "[DIRECTIVE NON AFFICHÉE]"
        result.append({"number": line_no, "text": shown})
    if len(source_text.splitlines()) > max_lines:
        result.append({"number": max_lines + 1, "text": "[SUITE NON AFFICHÉE]"})
    return result
