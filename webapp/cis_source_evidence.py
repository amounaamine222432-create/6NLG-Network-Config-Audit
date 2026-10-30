"""Read-only, allowlisted IOS source excerpts for *presentation*, never CIS decisions.

Only patterns with a deliberately bounded syntax are exported. Unknown and
credential-bearing lines are omitted or replaced with fixed redacted labels.
"""

from __future__ import annotations

import re


_PATTERNS = {
    "aaa_new_model": [r"(?:no )?aaa new-model"],
    "vty_ssh_only": [r"line vty [0-9 ]+", r"transport input (?:ssh|telnet|none|all)(?: (?:ssh|telnet|none|all))*"],
    "console_exec_timeout": [r"line con(?:sole)? [0-9 ]+", r"exec-timeout [0-9]+(?: [0-9]+)?"],
    "vty_exec_timeout": [r"line vty [0-9 ]+", r"exec-timeout [0-9]+(?: [0-9]+)?"],
    "exec_banner_present": [r"banner exec .*"],
    "login_banner": [r"banner login .*"],
    "motd_banner": [r"banner motd .*"],
    "enable_secret_present": [r"enable (?:secret|password) .*"],
    "local_user_secrets": [r"username .*"],
    "snmp_no_rw": [r"snmp-server community .*"],
    "snmp_v3_priv": [r"snmp-server group .*"],
    "ssh_version2": [r"ip ssh version [0-9]+"],
    "syslog_buffer": [r"(?:no )?logging buffered(?: [A-Za-z0-9 ]+)?"],
    "syslog_host": [r"logging (?:host )?[0-9a-fA-F.:]+"],
    "syslog_informational": [r"logging trap [A-Za-z0-9]+"],
    "syslog_source_present": [r"logging source-interface [A-Za-z0-9_.:/-]+"],
    "ntp_auth_enabled": [r"(?:no )?ntp authenticate"],
    "ntp_auth_keys": [r"ntp authentication-key .*"],
    "ntp_trusted_keys": [r"ntp trusted-key [0-9 -]+"],
    "ntp_server_keys": [r"ntp server .*"],
    "ntp_servers": [r"ntp server .*"],
    "ntp_loopback_source": [r"ntp source [A-Za-z0-9_.:/-]+"],
    "source_routing_disabled": [r"(?:no )?ip source-route"],
    "proxy_arp_disabled": [r"interface [A-Za-z0-9_.:/-]+", r"(?:no )?ip proxy-arp"],
    "no_tunnel_interfaces": [r"interface Tunnel[0-9./-]+"],
    "bgp_neighbor_password": [r"router bgp [0-9]+", r"neighbor .* password .*"],
    "aaa_login_default": [r"aaa authentication login default (?:[A-Za-z0-9_-]+ ?)+"],
    "aaa_enable_default": [r"aaa authentication enable default (?:[A-Za-z0-9_-]+ ?)+"],
    "aaa_line_console": [r"line con(?:sole)? [0-9 ]+", r"login authentication [A-Za-z0-9_-]+"],
    "aaa_line_tty": [r"line tty [0-9 ]+", r"login authentication [A-Za-z0-9_-]+"],
    "aaa_line_vty": [r"line vty [0-9 ]+", r"login authentication [A-Za-z0-9_-]+"],
    "vty_restricting_acl": [r"line vty [0-9 ]+", r"access-class [A-Za-z0-9_.-]+ (?:in|out)", r"ip access-list (?:standard|extended) [A-Za-z0-9_.-]+", r"(?:permit|deny) .*"],
    "vty_access_class": [r"line vty [0-9 ]+", r"access-class [A-Za-z0-9_.-]+ (?:in|out)"],
    "external_antispoof_acl": [r"ip access-list extended [A-Za-z0-9_.-]+", r"(?:permit|deny) .*", r"ip access-group [A-Za-z0-9_.-]+ in"],
    "external_inbound_acl": [r"interface [A-Za-z0-9_.:/-]+", r"ip access-group [A-Za-z0-9_.-]+ in"],
    "eigrp_interface_keychain": [r"router eigrp [0-9]+", r"interface [A-Za-z0-9_.:/-]+", r"ip authentication key-chain eigrp [0-9]+ [A-Za-z0-9_.-]+"],
    "eigrp_interface_md5": [r"router eigrp [0-9]+", r"interface [A-Za-z0-9_.:/-]+", r"ip authentication mode eigrp [0-9]+ md5"],
    "ospf_area_md5": [r"router ospf [0-9]+", r"area [0-9.]+ authentication message-digest"],
    "ospf_interface_md5": [r"interface [A-Za-z0-9_.:/-]+", r"ip ospf message-digest-key .*"],
}

_COMPILED = {name: [re.compile(r"\A" + pattern + r"\Z", re.I) for pattern in patterns]
             for name, patterns in _PATTERNS.items()}


def _safe_display(command: str) -> str | None:
    """Do not expose credentials or arbitrary/free-form values."""
    low = command.lower()
    if low.startswith("username "):
        if re.match(r"username \S+ .*\b(secret|password)\b", command, re.I):
            return "username [IDENTIFIANT MASQUÉ] secret/password [MASQUÉ]"
        return "username [IDENTIFIANT MASQUÉ] (directive présente)"
    if low.startswith("enable "):
        return "enable secret/password [MASQUÉ]"
    if low.startswith("snmp-server community "):
        mode = "RW" if re.search(r"\bRW\b", command, re.I) else "RO ou non déterminé"
        return f"snmp-server community [MASQUÉ] ({mode})"
    if low.startswith("snmp-server group "):
        level = next((v for v in ("priv", "auth", "noauth") if re.search(r"\b" + v + r"\b", command, re.I)), "non déterminé")
        return f"snmp-server group [MASQUÉ] (sécurité : {level})"
    if low.startswith("ntp authentication-key "):
        match = re.match(r"ntp authentication-key (\d+)", command, re.I)
        return "ntp authentication-key " + (match.group(1) if match else "[ID]") + " [MASQUÉ]"
    if low.startswith("neighbor ") and " password " in low:
        match = re.match(r"neighbor ([A-Za-z0-9_.:-]+) password ", command, re.I)
        return f"neighbor {match.group(1)} password [MASQUÉ]" if match else None
    if low.startswith("ip ospf message-digest-key "):
        match = re.match(r"ip ospf message-digest-key (\d+) md5 ", command, re.I)
        return f"ip ospf message-digest-key {match.group(1)} md5 [MASQUÉ]" if match else None
    if low.startswith("banner "):
        return " ".join(command.split()[:2]) + " [CONTENU MASQUÉ]"
    if re.match(r"^(?:permit|deny) ", command, re.I):
        # ACEs can contain optional remarks/free-form strings; publish only a
        # constrained set of fields, otherwise redact the entire ACE.
        if re.fullmatch(r"(?:permit|deny) (?:ip|tcp|udp|icmp|gre|ospf|eigrp) (?:any|host [0-9.]+|[0-9.]+ [0-9.]+) (?:any|host [0-9.]+|[0-9.]+ [0-9.]+)(?: (?:eq|gt|lt|neq) [A-Za-z0-9-]+)?(?: log(?:-input)?)?", command, re.I):
            return command
        return "ACL permit/deny [PARAMÈTRES MASQUÉS]"
    # For remaining allowlisted patterns, reject shell metacharacters and
    # unbounded free text. No raw source is ever retained in exported findings.
    if not re.fullmatch(r"[A-Za-z0-9_.:/ -]+", command):
        return None
    return command


def source_excerpts(check: str, source_text: str, limit: int = 7) -> list[dict]:
    """Return numbered, redacted source matches (context candidates, not verdict evidence)."""
    patterns = _COMPILED.get(check, [])
    matches = []
    for number, raw in enumerate(source_text.splitlines(), 1):
        command = raw.strip()
        if not command or not any(pattern.fullmatch(command) for pattern in patterns):
            continue
        display = _safe_display(command)
        if display is None:
            continue
        matches.append({"line": number, "command": display})
        if len(matches) >= limit:
            break
    return matches
