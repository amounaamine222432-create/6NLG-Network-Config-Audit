"""Chargement Junos par des bibliothèques tierces, sans grammaire maison.

* Hiérarchie { } : ciscoconfparse2 (comportement existant).
* ``show | display set`` : clijson, dont l'arbre JSON est exposé sous
  l'interface parent/enfants utilisée par les adaptateurs IR.

La projection de l'arbre de clijson en objets est un *adaptateur de données*,
pas un parseur de commandes ``set``. Les champs ambigus restent non modélisés.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ConfigNode:
    text: str
    parent: Any = None
    children: list[Any] = field(default_factory=list)


@dataclass
class ParsedJunos:
    config_objs: list[Any]
    format: str
    warnings: list[str]
    parser_name: str


def is_junos_comment_node(node: Any) -> bool:
    """Ignore uniquement les commentaires explicites, jamais une directive inconnue."""
    value = node.text.strip()
    return (value.startswith(("#", "//"))
            or (value.startswith("/*") and value.endswith("*/")))


# Clijson fournit déjà la hiérarchie des tokens. Dans l'IR, les noms de
# stanzas tels que ``group EXTERNAL`` et ``unit 0`` sont des nœuds uniques.
_NAMED = {
    "unit", "family", "group", "neighbor", "area", "route", "rule-set", "interface-range",
    "rule", "policy", "from-zone", "to-zone", "security-zone", "ids-option",
    "policy-statement", "term", "pool", "address-book", "address-set",
    "application", "application-set", "rib", "community", "prefix-list",
    "as-path", "interface", "host", "user", "source-pool",
}


def _build_node(text: str, parent: ConfigNode | None, nodes: list[ConfigNode]) -> ConfigNode:
    node = ConfigNode(text=text)
    node.parent = parent if parent is not None else node
    if parent is not None:
        parent.children.append(node)
    nodes.append(node)
    return node


def _project_object(obj: dict[str, Any], parent: ConfigNode | None,
                    nodes: list[ConfigNode]) -> None:
    """Projette les clés de l'AST clijson vers l'API déjà utilisée pour l'IR."""
    for key, value in obj.items():
        if key == "_value":
            # Un noeud avec à la fois une valeur et des enfants est ambigu.
            continue
        if isinstance(value, dict) and key in _NAMED:
            for name, subtree in value.items():
                if name == "_value":
                    continue
                name_node = _build_node(f"{key} {name}", parent, nodes)
                if isinstance(subtree, dict):
                    _project_object(subtree, name_node, nodes)
                elif isinstance(subtree, str):
                    _build_node(subtree, name_node, nodes)
                elif isinstance(subtree, list):
                    for element in subtree:
                        if isinstance(element, str):
                            _build_node(str(element), name_node, nodes)
            continue
        if isinstance(value, dict):
            container = _build_node(key, parent, nodes)
            _project_object(value, container, nodes)
        elif isinstance(value, list):
            for element in value:
                if isinstance(element, (str, int, float)):
                    _build_node(f"{key} {element}", parent, nodes)
        elif value is True:
            _build_node(key, parent, nodes)
        elif isinstance(value, (str, int, float)):
            _build_node(f"{key} {value}", parent, nodes)


def load_junos_tree(source_file: str | Path) -> ParsedJunos:
    path = Path(source_file)
    raw = path.read_text(encoding="utf-8", errors="replace")
    effective = [line.strip() for line in raw.splitlines()
                 if line.strip() and not line.lstrip().startswith(("#", "//"))]
    if not effective:
        raise ValueError("Configuration Junos vide")
    set_lines = [line for line in effective if line.startswith("set ")]
    delete_lines = [line for line in effective if line.startswith(("delete ", "deactivate "))]
    if set_lines:
        if delete_lines:
            raise ValueError("display set contenant delete/deactivate : état effectif ambigu")
        # Un fichier Markdown d'exemple SRX est explicitement identifié :
        # seules les lignes de configuration sont prises en compte.
        markdown = path.suffix.lower() == ".md"
        if not markdown and len(set_lines) != len(effective):
            raise ValueError("display set mélangé à des lignes non reconnues")
        from clijson.engines.config import parse_junos_set

        parsed = parse_junos_set("\n".join(set_lines))
        if not isinstance(parsed, dict) or not parsed:
            raise ValueError("display set : la bibliothèque n'a extrait aucun objet")
        nodes: list[ConfigNode] = []
        _project_object(parsed, None, nodes)
        if not nodes:
            raise ValueError("display set : projection vide")
        messages = ["Syntaxe display set traitée par clijson (bibliothèque externe)."]
        if markdown:
            messages.append("Extrait Markdown SRX : document d'exemple, pas de sauvegarde intégrale attestée.")
        return ParsedJunos(nodes, "display_set", messages, "clijson")

    if "{" not in raw:
        raise ValueError("format=hierarchie_junos_non_confirmee (accolades absentes)")
    from ciscoconfparse2 import CiscoConfParse

    parser = CiscoConfParse(str(path), syntax="junos", factory=False)
    return ParsedJunos(list(parser.config_objs), "hierarchical", [], "ciscoconfparse2")
