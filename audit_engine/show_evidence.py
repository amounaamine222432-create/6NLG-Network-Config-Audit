"""Résumé non sensible de commandes IOS SHOW, sans persister les sorties brutes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
import re
from typing import Mapping


ALLOWED_SHOW_COMMANDS = (
    "show version",
    "show ip ssh",
    "show line",
    "show ip ospf interface",
    "show ip eigrp interfaces detail",
    "show ip access-lists",
    "show ip interface",
)


def summarize_show_outputs(outputs: Mapping[str, str], *, hostname: str,
                           target: str, timestamp: str | None = None) -> dict:
    """Extraire des faits conservateurs. Ne jamais renvoyer une ligne de SHOW brute."""
    if not hostname.strip():
        raise ValueError("Le hostname attendu est obligatoire")
    illegal = sorted(set(outputs) - set(ALLOWED_SHOW_COMMANDS))
    if illegal:
        raise ValueError("Commande hors de la liste blanche : " + ", ".join(illegal))
    unavailable = []
    for name, body in outputs.items():
        if re.search(r"(?im)(invalid input|ambiguous command|unrecognized command)", body):
            unavailable.append(name)

    ssh = outputs.get("show ip ssh", "")
    version_text = outputs.get("show version", "")
    identity = re.search(r"(?im)^([\w.-]+)\s+uptime\s+is\b", version_text)
    observed_hostname = identity.group(1) if identity else None
    hostname_verified = bool(observed_hostname and observed_hostname.lower() == hostname.lower())
    ssh_version = None
    if "show ip ssh" not in unavailable:
        match = re.search(r"(?i)SSH\s+Enabled\s*[-:]\s*version\s*([12])(?:\.\d+)?", ssh)
        if match:
            ssh_version = int(match.group(1))
        elif re.search(r"(?im)^SSH\s+(?:Disabled|not enabled)", ssh):
            ssh_version = 0

    ospf = outputs.get("show ip ospf interface", "")
    eigrp = outputs.get("show ip eigrp interfaces detail", "")
    ip_interfaces = outputs.get("show ip interface", "")
    acls = outputs.get("show ip access-lists", "")
    lines = outputs.get("show line", "")
    return {
        "schema_version": "1.0",
        "source": "ssh_show_read_only",
        "expected_hostname": hostname,
        "observed_hostname": observed_hostname,
        "hostname_verified": hostname_verified,
        "target": target,
        "collected_at_utc": timestamp or datetime.now(timezone.utc).isoformat(),
        "commands_requested": list(outputs),
        "unsupported_commands": unavailable,
        "observations": {
            "ssh_version": ssh_version,
            "ospf_md5_status_mentions": len(re.findall(
                r"(?i)message\s+digest\s+authentication\s+enabled", ospf)),
            "ospf_no_authentication_mentions": len(re.findall(
                r"(?i)no\s+authentication", ospf)),
            "eigrp_md5_status_mentions": len(re.findall(
                r"(?i)authentication\s+mode\s+(?:is\s+)?md5", eigrp)),
            "access_list_headers_observed": len(re.findall(
                r"(?im)^(?:extended|standard)\s+ip\s+access\s+list\s+", acls)),
            "proxy_arp_enabled_mentions": len(re.findall(
                r"(?i)proxy\s+arp\s+is\s+enabled", ip_interfaces)),
            "proxy_arp_disabled_mentions": len(re.findall(
                r"(?i)proxy\s+arp\s+is\s+disabled", ip_interfaces)),
            "line_timeout_mentions": len(re.findall(r"(?i)timeout", lines)),
        },
        "note": "Observations partielles : ne prouvent ni topologie ni conformité complète.",
    }


def attach_show_evidence(report: dict, evidence: dict) -> dict:
    """Rattacher les observations, confirmer SSH si l'état statique est UNKNOWN."""
    if evidence.get("schema_version") != "1.0" or evidence.get("source") != "ssh_show_read_only":
        raise ValueError("Format de preuves SHOW non reconnu")
    if evidence.get("expected_hostname", "").lower() != str(report.get("hostname") or "").lower():
        raise ValueError("Les preuves SHOW concernent un autre hostname")
    observations = evidence.get("observations")
    if not isinstance(observations, dict):
        raise ValueError("Observations manquantes")
    allowed_observations = {"ssh_version", "ospf_md5_status_mentions",
                            "ospf_no_authentication_mentions", "eigrp_md5_status_mentions",
                            "access_list_headers_observed", "proxy_arp_enabled_mentions",
                            "proxy_arp_disabled_mentions", "line_timeout_mentions"}
    if set(observations) - allowed_observations:
        raise ValueError("Champs SHOW inattendus : suppression des données brutes")
    if any((v is not None and (type(v) is not int or v < 0 or v > 100000))
           for v in observations.values()):
        raise ValueError("Valeurs d'observations SHOW incorrectes")
    version = observations.get("ssh_version")
    if version not in {None, 0, 1, 2}:
        raise ValueError("Version SSH invalide")
    try:
        ipaddress.ip_address(str(evidence.get("target")))
    except ValueError as exc:
        raise ValueError("Adresse cible SSH invalide") from exc
    commands = evidence.get("commands_requested")
    unsupported = evidence.get("unsupported_commands")
    if (not isinstance(commands, list) or not isinstance(unsupported, list) or
            any(c not in ALLOWED_SHOW_COMMANDS for c in commands + unsupported)):
        raise ValueError("Liste de commandes SHOW non autorisée")
    observed_hostname = evidence.get("observed_hostname")
    if observed_hostname is not None and not re.fullmatch(r"[\w.-]{1,64}", str(observed_hostname)):
        raise ValueError("Hostname observé invalide")
    timestamp = evidence.get("collected_at_utc")
    try:
        parsed_time = datetime.fromisoformat(timestamp)
        if parsed_time.tzinfo is None:
            raise ValueError("Fuseau horaire absent")
    except (ValueError, TypeError) as exc:
        raise ValueError("Horodatage SHOW invalide") from exc
    freshness = datetime.now(timezone.utc) - parsed_time.astimezone(timezone.utc)
    fresh_enough = -timedelta(minutes=10) <= freshness <= timedelta(hours=24)
    # Ne jamais recopier des champs arbitraires fournis par un JSON externe.
    report["operational_evidence"] = {
        "schema_version": "1.0", "source": "ssh_show_read_only",
        "expected_hostname": report["hostname"], "observed_hostname": observed_hostname,
        "hostname_verified": evidence.get("hostname_verified") is True,
        "evidence_fresh_24h": fresh_enough,
        "target": evidence["target"], "collected_at_utc": timestamp,
        "commands_requested": commands,
        "unsupported_commands": unsupported,
        "observations": observations,
        "note": "Données fournies par l'opérateur ; état opérationnel ponctuel.",
    }
    if (fresh_enough and "show version" in commands and "show ip ssh" in commands and
            evidence.get("hostname_verified") is True and
            str(evidence.get("observed_hostname") or "").lower() ==
            str(report.get("hostname") or "").lower() and
            version in {0, 1, 2} and
            "show ip ssh" not in evidence.get("unsupported_commands", [])):
        for finding in report.get("findings", []):
            if (finding.get("cis_control_id") == "2.1.1.2" and
                    finding.get("status") == "UNKNOWN"):
                finding["status"] = "PASS" if version == 2 else "FAIL"
                finding["evidence"] = {"ssh_version": version,
                                       "assessment_basis": "operational_show",
                                       "command": "show ip ssh"}
                if version == 2:
                    finding["remediation"] = None
                report["counts"]["UNKNOWN"] -= 1
                report["counts"][finding["status"]] += 1
                break
    return report
