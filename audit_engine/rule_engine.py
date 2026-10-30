"""MVP : comparateur de règles déclaratives sur les champs expurgés de l'IR.

N'utilise ni eval ni exécution de commandes. Seuls des chemins explicitement
autorisés peuvent être lus et reportés ; aucune donnée secrète n'est exposée.
"""

from __future__ import annotations

from typing import Any


ALLOWED_IR_PATHS = {
    "management.http_enabled", "management.https_enabled",
    "management.ssh_version", "management.enable_secret_configured",
    "services.ntp.authentication_enabled",
}
MISSING = object()


def _read_path(data: dict[str, Any], path: str) -> Any:
    value: Any = data
    for component in path.split("."):
        if not isinstance(value, dict) or component not in value:
            return MISSING
        value = value[component]
    return value


def evaluate_rules(
    ir: dict[str, Any], rules: list[dict[str, Any]], *, allow_demo: bool = False,
) -> dict[str, Any]:
    if ir.get("source", {}).get("vendor") != "cisco_ios":
        raise ValueError("Le moteur de démonstration accepte uniquement un IR Cisco IOS")
    findings: list[dict[str, Any]] = []
    used_ids: set[str] = set()
    for rule in rules:
        identifier = rule.get("id")
        path = rule.get("ir_path")
        if not isinstance(identifier, str) or not identifier or identifier in used_ids:
            raise ValueError("Identifiant de règle invalide ou dupliqué")
        used_ids.add(identifier)
        if path not in ALLOWED_IR_PATHS or rule.get("operator") != "equals":
            raise ValueError(f"Règle {identifier} : chemin ou opérateur non autorisé")
        approved = rule.get("status") == "approved" and bool(rule.get("benchmark_ref"))
        if not approved and not (allow_demo and rule.get("status") == "demo"):
            status = "NOT_EVALUATED"
            observed = None
        else:
            observed = _read_path(ir, path)
            if observed is MISSING or observed is None:
                status = "UNKNOWN"
                observed = None
            else:
                # Comparaison stricte : True n'est pas 1, par exemple.
                expected = rule["expected"]
                status = "PASS" if type(observed) is type(expected) and observed == expected else "FAIL"
        findings.append({
            "rule_id": identifier,
            "title": rule.get("title"),
            "benchmark_ref": rule.get("benchmark_ref"),
            "status": status,
            "ir_path": path,
            "observed": observed,
            "expected": rule.get("expected"),
            "remediation": rule.get("remediation") if status == "FAIL" else None,
            "note": "Configuration déclarée seulement ; fonctionnement réel non vérifié",
        })
    return {
        "device": ir.get("device", {}).get("hostname"),
        "source_file": ir.get("source", {}).get("file"),
        "benchmark_conformance_certified": False,
        "findings": findings,
        "counts": {status: sum(f["status"] == status for f in findings)
                   for status in ("PASS", "FAIL", "UNKNOWN", "NOT_EVALUATED")},
    }
