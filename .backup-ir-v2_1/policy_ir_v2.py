"""Extension additive IR v2 : politiques Junos et conversion d'IR Cisco v1.

Le découpage en objets Junos reste exclusivement assuré par ciscoconfparse2.
L'interprétation couvre uniquement des directives dont le sens est établi.
Une sortie JSON conforme au schéma ne prouve pas son équivalence opérationnelle.
"""

from __future__ import annotations

from copy import deepcopy
import ipaddress
from pathlib import Path
from typing import Any

from normalizers.juniper_ir_adapter import normalize_juniper_junos


def _text(node: Any) -> str:
    return node.text.strip()


def _tokens(node: Any) -> list[str]:
    return _text(node).split()


def _children(node: Any, prefix: str | None = None) -> list[Any]:
    result = list(node.children)
    if prefix is None:
        return result
    return [x for x in result if _text(x) == prefix or _text(x).startswith(prefix + " ")]


def _ref(node: Any = None) -> dict[str, None]:
    # Voir l'adaptateur v1 : linenum est un index dans l'arbre aplati, non
    # une preuve fiable de la ligne physique du fichier d'origine.
    return {"line": None}


def _take(marked: set[int], *nodes: Any) -> None:
    for node in nodes:
        if node is not None:
            marked.add(id(node))


def _values(tokens: list[str]) -> list[str]:
    # Les crochets sont des marqueurs syntaxiques, pas des valeurs.
    return [item.strip('"') for item in tokens if item not in ("[", "]")]


def _condition(node: Any) -> dict[str, Any] | None:
    t = _tokens(node)
    if not t:
        return None
    if t[0] == "protocol" and len(t) >= 2:
        return {"kind": "route_protocol", "values": _values(t[1:]), "source": _ref(node)}
    if t[0] == "community" and len(t) >= 2:
        return {"kind": "community_reference", "values": _values(t[1:]), "source": _ref(node)}
    if t[0] == "rib" and len(t) >= 2:
        return {"kind": "rib", "values": _values(t[1:]), "source": _ref(node)}
    if t[0] == "family" and len(t) == 2:
        return {"kind": "address_family", "values": [t[1]], "source": _ref(node)}
    if t[0] == "route-filter" and len(t) == 3 and t[2] in ("exact", "orlonger", "longer"):
        try:
            prefix = str(ipaddress.ip_network(t[1], strict=False))
        except ValueError:
            return None
        return {"kind": "route_filter", "prefix": prefix, "modifier": t[2],
                "source": _ref(node)}
    return None


def _action(node: Any) -> dict[str, Any] | None:
    t = _tokens(node)
    if len(t) == 1 and t[0] in ("accept", "reject"):
        return {"kind": t[0], "source": _ref(node)}
    if len(t) == 3 and t[0] == "community" and t[1] in ("add", "delete", "set"):
        return {"kind": "community_" + t[1], "reference": t[2], "source": _ref(node)}
    if len(t) == 2 and t[0] in ("local-preference", "metric", "tag"):
        try:
            val = int(t[1])
        except ValueError:
            return None
        if val < 0:
            return None
        kind = {"local-preference": "set_local_preference", "metric": "set_metric", "tag": "set_tag"}[t[0]]
        return {"kind": kind, "value": val, "source": _ref(node)}
    return None


def _parse_term(term: Any, order: int, marked: set[int]) -> dict[str, Any]:
    t = _tokens(term)
    name = t[1] if len(t) == 2 and t[0] == "term" else None
    _take(marked, term)
    conditions: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []
    unknown_conditions = 0
    unknown_actions = 0

    for branch in _children(term):
        t = _tokens(branch)
        if not t:
            continue
        if t[0] == "from" and len(t) == 1:
            _take(marked, branch)
            sources = _children(branch)
            for condition_node in sources:
                structured = _condition(condition_node)
                if structured is None:
                    unknown_conditions += 1
                else:
                    conditions.append(structured)
                    _take(marked, condition_node)
        elif t[0] == "from":
            # Forme directe « from protocol static; ».
            class _OneLine:
                text = _text(branch)[len("from "):]
            structured = _condition(_OneLine())
            if structured:
                conditions.append(structured)
                _take(marked, branch)
            else:
                unknown_conditions += 1
        elif t[0] == "then" and len(t) == 1:
            _take(marked, branch)
            for action_node in _children(branch):
                structured = _action(action_node)
                if structured is None:
                    unknown_actions += 1
                else:
                    actions.append(structured)
                    _take(marked, action_node)
        elif t[0] == "then":
            class _OneLine:
                text = branch.text.strip()[len("then "):]
            structured = _action(_OneLine())
            if structured:
                actions.append(structured)
                _take(marked, branch)
            else:
                unknown_actions += 1
        else:
            # « to » et options particulières non interprétées.
            unknown_conditions += 1

    return {"name": name, "order": order, "conditions": conditions, "actions": actions,
            "unmodeled_condition_count": unknown_conditions,
            "unmodeled_action_count": unknown_actions,
            "source": _ref(term)}


def _junos_policy_options(path: Path) -> tuple[list[dict], list[dict], int, int]:
    from ciscoconfparse2 import CiscoConfParse

    parser = CiscoConfParse(str(path), syntax="junos", factory=False)
    roots = [node for node in parser.config_objs if node.parent is node]
    opts = next((n for n in roots if _text(n) == "policy-options"), None)
    if opts is None:
        return [], [], 0, 0
    marked: set[int] = set()
    policies: list[dict] = []
    communities: list[dict] = []
    _take(marked, opts)

    for node in _children(opts):
        t = _tokens(node)
        if not t:
            continue
        if t[0] == "policy-statement" and len(t) == 2:
            _take(marked, node)
            terms = []
            for term in _children(node, "term"):
                terms.append(_parse_term(term, len(terms), marked))
            # Les politiques sans "term" peuvent porter from/then directement.
            direct = [x for x in _children(node) if _tokens(x) and _tokens(x)[0] in ("from", "then")]
            if direct:
                class _PolicyDirect:
                    text = ""
                    children = direct
                terms.append(_parse_term(_PolicyDirect(), len(terms), marked))
            policies.append({"name": t[1], "vendor_semantics": "junos", "terms": terms,
                             "source": _ref(node)})
        elif t[0] == "community" and len(t) >= 2:
            name = t[1]
            members: list[str] = []
            if len(t) >= 4 and t[2] == "members":
                members.extend(_values(t[3:]))
                _take(marked, node)
            else:
                for child in _children(node, "members"):
                    ct = _tokens(child)
                    members.extend(_values(ct[1:]))
                    _take(marked, child)
                if members:
                    _take(marked, node)
            if members:
                communities.append({"name": name, "members": members,
                                    "vendor_semantics": "junos", "source": _ref(node)})

    leaves = [n for n in parser.config_objs
              if not n.children and not _text(n).startswith("#") and (
                  n is opts or _is_descendant(n, opts))]
    modeled = sum(id(node) in marked for node in leaves)
    return policies, communities, modeled, len(leaves) - modeled


def _is_descendant(node: Any, ancestor: Any) -> bool:
    current = node
    while current.parent is not current:
        current = current.parent
        if current is ancestor:
            return True
    return False


def normalize_juniper_junos_v2(source_file: str | Path) -> dict[str, Any]:
    """Conserve les champs v1 et ajoute les politiques documentées de Junos."""
    source = Path(source_file)
    ir = normalize_juniper_junos(source)
    policies, communities, modeled, unknown = _junos_policy_options(source)
    ir["schema_version"] = "2.0.0"
    ir["policies"]["route_policies"] = policies
    ir["policies"]["community_sets"] = communities
    counts = ir["diagnostics"]["source_only_counts"]
    counts["policy_v2_leaf_count_recognized"] = modeled
    counts["policy_v2_leaf_count_unmodeled"] = unknown
    ir["diagnostics"]["notes"].append(
        "IR v2 : couvertures v1 conservées comme référence ; les compteurs policy_v2 sont indépendants."
    )
    ir["diagnostics"]["notes"].append(
        "Junos policy : seules les conditions/actions explicitement prises en charge sont converties."
    )
    ir["diagnostics"]["status"] = "partial"
    return ir


def upgrade_cisco_ir_v1_to_v2(original: dict[str, Any]) -> dict[str, Any]:
    """Convertit uniquement l'IR Cisco déjà normalisée, jamais les commandes brutes."""
    if original.get("schema_version") != "1.0.0" or original.get("source", {}).get("vendor") != "cisco_ios":
        raise ValueError("Une IR v1 d'origine Cisco IOS est nécessaire")
    ir = deepcopy(original)
    ir["schema_version"] = "2.0.0"
    ir["policies"]["route_policies"] = []
    ir["policies"]["community_sets"] = []

    for route_map in ir["policies"]["route_maps"]:
        terms = []
        for index, entry in enumerate(route_map.get("entries") or []):
            conds = []
            actions = []
            for operation in entry.get("operations") or []:
                kind = operation.get("operation")
                if kind in ("match_prefix_list", "match_acl", "match_community_list"):
                    condition = {
                        "match_prefix_list": "cisco_match_prefix_list",
                        "match_acl": "cisco_match_acl",
                        "match_community_list": "cisco_match_community_list",
                    }[kind]
                    conds.append({"kind": condition, "values": operation.get("references") or [],
                                  "source": entry.get("source", {"line": None})})
                elif kind in ("set_local_preference", "set_metric") and isinstance(operation.get("value"), int):
                    actions.append({"kind": kind, "value": operation["value"],
                                    "source": entry.get("source", {"line": None})})
                elif kind == "prepend_as_path":
                    actions.append({"kind": "cisco_prepend_as_path",
                                    "values": [str(x) for x in operation.get("autonomous_systems") or []],
                                    "source": entry.get("source", {"line": None})})
                elif kind == "set_bgp_communities":
                    actions.append({"kind": "cisco_set_communities",
                                    "values": operation.get("communities") or [],
                                    "source": entry.get("source", {"line": None})})
            action = {"permit": "cisco_permit", "deny": "cisco_deny"}.get(entry.get("action"))
            if action:
                actions.append({"kind": action, "source": entry.get("source", {"line": None})})
            terms.append({"name": str(entry.get("sequence")) if entry.get("sequence") is not None else None,
                          "order": index, "conditions": conds, "actions": actions,
                          "unmodeled_condition_count": 0, "unmodeled_action_count": 0,
                          "unmodeled_statement_count": entry.get("unmodeled_statement_count", 0),
                          "source": entry.get("source", {"line": None})})
        name = route_map.get("name")
        if name is not None:
            ir["policies"]["route_policies"].append({"name": str(name), "vendor_semantics": "cisco_ios",
                                                    "terms": terms, "source": {"line": None}})
    ir["diagnostics"]["notes"].append(
        "IR v2 : route-map Cisco conservée dans route_maps et projetée avec une sémantique Cisco explicite ; ne pas assimiler à Junos then accept."
    )
    return ir
