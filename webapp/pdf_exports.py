"""Two separate, in-memory, secret-safe PDF reports for the Cisco audit chain.

Only already-sanitized parsed previews, the IR inventory and CIS findings are
accepted. Never pass CLI source, raw parser objects or credential values here.
"""

from __future__ import annotations

from html import escape
from io import BytesIO
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    CondPageBreak, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
    Spacer, Table, TableStyle,
)


NAVY = colors.HexColor("#11253A")
TEAL = colors.HexColor("#087A78")
RED = colors.HexColor("#B9344B")
AMBER = colors.HexColor("#956218")
SLATE = colors.HexColor("#617286")
PALE = colors.HexColor("#F2F6FA")
LINE = colors.HexColor("#DAE4EC")
WHITE = colors.white


def _font_setup() -> str:
    """Use a Unicode-capable font without requiring external downloads."""
    font_file = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
    bold_file = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")
    if font_file.exists() and bold_file.exists():
        if "CisDejaVu" not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont("CisDejaVu", str(font_file)))
            pdfmetrics.registerFont(TTFont("CisDejaVu-Bold", str(bold_file)))
            pdfmetrics.registerFontFamily("CisDejaVu", normal="CisDejaVu", bold="CisDejaVu-Bold")
        return "CisDejaVu"
    return "Helvetica"


def _styles() -> dict[str, ParagraphStyle]:
    font = _font_setup()
    bold = "CisDejaVu-Bold" if font == "CisDejaVu" else "Helvetica-Bold"
    return {
        "title": ParagraphStyle("pdf_title", fontName=bold, fontSize=25, leading=31,
                                textColor=NAVY, spaceAfter=10),
        "subtitle": ParagraphStyle("pdf_subtitle", fontName=font, fontSize=10,
                                   leading=17, textColor=SLATE, spaceAfter=15),
        "section": ParagraphStyle("pdf_section", fontName=bold, fontSize=14,
                                  leading=20, textColor=NAVY, spaceBefore=17, spaceAfter=8),
        "subsection": ParagraphStyle("pdf_subsection", fontName=bold, fontSize=10.4,
                                     leading=15, textColor=TEAL, spaceBefore=12, spaceAfter=6),
        "body": ParagraphStyle("pdf_body", fontName=font, fontSize=8.25, leading=12.7,
                               textColor=NAVY, spaceAfter=6, wordWrap="CJK"),
        "muted": ParagraphStyle("pdf_muted", fontName=font, fontSize=7.3, leading=11,
                                textColor=SLATE, wordWrap="CJK"),
        "label": ParagraphStyle("pdf_label", fontName=bold, fontSize=8, leading=12,
                                textColor=NAVY),
        "cell": ParagraphStyle("pdf_cell", fontName=font, fontSize=7.4, leading=11.4,
                               textColor=NAVY, wordWrap="CJK"),
        "micro": ParagraphStyle("pdf_micro", fontName=font, fontSize=6.8, leading=10.8,
                                textColor=SLATE, wordWrap="CJK"),
        "center": ParagraphStyle("pdf_center", fontName=bold, fontSize=8, leading=12,
                                 textColor=NAVY, alignment=TA_CENTER),
        "command": ParagraphStyle("pdf_command", fontName=font, fontSize=7.35, leading=12.7,
                                  textColor=colors.HexColor("#0E5761"), wordWrap="CJK"),
        "rulehead": ParagraphStyle("pdf_rulehead", fontName=bold, fontSize=10.2, leading=15,
                                   textColor=NAVY),
    }


def _p(value, style: ParagraphStyle) -> Paragraph:
    text = escape(str(value if value is not None else "—")).replace("\n", "<br/>")
    return Paragraph(text, style)


def _footer(canvas, document, tag: str) -> None:
    canvas.saveState()
    canvas.setStrokeColor(LINE)
    canvas.line(42, 36, A4[0] - 42, 36)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(SLATE)
    canvas.drawString(42, 25, "6NLG / SUP'COM | Analyse statique - prototype non certifie")
    canvas.drawRightString(A4[0] - 42, 25, f"{tag} | page {document.page}")
    canvas.restoreState()


def _document(stream: BytesIO, subject: str) -> SimpleDocTemplate:
    return SimpleDocTemplate(stream, pagesize=A4, leftMargin=42, rightMargin=42,
                             topMargin=43, bottomMargin=56, title=subject,
                             author="Projet Tutore SUP'COM x 6NLG", subject=subject)


def _simple_table(headers: tuple[str, ...], rows: list[tuple], widths: list[float], styles: dict) -> Table:
    data = [[_p(head, styles["label"]) for head in headers]]
    data.extend([[_p(cell, styles["cell"]) for cell in row] for row in rows])
    table = Table(data, colWidths=widths, hAlign="LEFT", repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PALE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("LINEBELOW", (0, 0), (-1, -1), .45, LINE),
    ]))
    return table


def _metadata(story: list, styles: dict, *, hostname: str, ios: str, source: str,
              timestamp: str, sha256: str = "") -> None:
    rows = [
        ("Routeur", hostname or "Inconnu"),
        ("IOS", ios or "Non determine"),
        ("Source", source or "Non determinee"),
        ("Date UTC", timestamp),
    ]
    if sha256:
        rows.append(("SHA-256", sha256))
    story.append(_simple_table(("Propriete", "Valeur"), rows, [112, 399], styles))


def _count_sections(preview: dict) -> list[tuple]:
    descriptions = (
        ("interfaces", "Interfaces"), ("static_routes", "Routes statiques"),
        ("ospf_processes", "Processus OSPF"), ("bgp_processes", "Processus BGP"),
        ("access_lists", "ACL"), ("prefix_lists", "Prefix-lists"),
        ("route_maps", "Route-maps"), ("vrfs", "VRF"), ("vlans", "VLAN"),
        ("dhcp_pools", "Pools DHCP"), ("nat_rules", "Regles NAT"),
    )
    return [(label, len(preview.get(field) or [])) for field, label in descriptions]


def generate_parsing_ir_pdf(preview: dict, inventory: dict, *,
                            hostname: str, ios_version: str,
                            source_file: str, source_sha256: str,
                            generated_at: str) -> bytes:
    """Part 1: parse inventory and normalized IR coverage, with no raw CLI."""
    styles = _styles()
    stream = BytesIO()
    story = [
        _p("RAPPORT 01 / PARSING ET NORMALISATION", styles["subsection"]),
        _p("Cartographie de la configuration", styles["title"]),
        _p("Étapes 1 et 2 : les éléments Cisco IOS reconnus, leur représentation structurée et les limites de couverture du parseur. Les secrets et commandes brutes ne figurent pas dans ce document.", styles["subtitle"]),
    ]
    _metadata(story, styles, hostname=hostname, ios=ios_version,
              source=source_file, sha256=source_sha256, timestamp=generated_at)

    story.append(_p("Étape 1 - Résultat du parsing", styles["section"]))
    story.append(_p("Inventaire des objets Cisco IOS identifiés, à partir de la vue de parsing expurgée.", styles["body"]))
    counts = _count_sections(preview)
    story.append(_simple_table(("Objet extrait", "Nombre"),
                               counts, [355, 156], styles))

    interfaces = preview.get("interfaces") or []
    if interfaces:
        story.append(_p("Interfaces et adressage observés", styles["subsection"]))
        rows = []
        for item in interfaces:
            addresses = ", ".join(f"{a.get('address', '?')} / {a.get('mask', '?')}"
                                  for a in item.get("ipv4_addresses") or [])
            bindings = ", ".join(f"{a.get('name')} ({a.get('direction')})"
                                  for a in item.get("acl_bindings") or [])
            rows.append((item.get("name", "?"), addresses or "Aucune déclarée",
                         bindings or "Aucune déclarée"))
        story.append(_simple_table(("Interface", "IPv4 / Masque", "ACL liées"), rows,
                                   [135, 189, 187], styles))

    for name, key, describer in (
        ("Processus de routage OSPF", "ospf_processes", lambda p: f"process-id={p.get('process_id')} ; reseaux={len(p.get('networks') or [])}"),
        ("Processus de routage BGP", "bgp_processes", lambda p: f"local-as={p.get('local_as')} ; voisins={len(p.get('neighbors') or [])}"),
        ("Listes de controle d'acces", "access_lists", lambda p: f"type={p.get('acl_type')} ; entrees={len(p.get('entries') or [])}"),
    ):
        objects = preview.get(key) or []
        if objects:
            story.append(_p(name, styles["subsection"]))
            rows = [(str(p.get("name") or p.get("process_id") or p.get("local_as") or "Objet"),
                     describer(p)) for p in objects]
            story.append(_simple_table(("Identifiant", "Extraction structurée"), rows,
                                       [174, 337], styles))

    story.append(_p("Étape 2 - Normalisation IR et traçabilité", styles["section"]))
    story.append(_p("Pour chaque partie, comparaison du nombre d'éléments extraits au nombre d'éléments inscrits dans la représentation intermédiaire (IR). Une ligne NOT_PRESENT n'est pas une non-conformité CIS.", styles["body"]))
    parts = inventory.get("parts") or []
    totals = (
        ("Domaines recenses", inventory.get("group_count", 0)),
        ("Parties inventoriees", inventory.get("part_count", len(parts))),
        ("Parties reliees a une regle CIS", inventory.get("audited_part_count", 0)),
        ("Regles CIS reliees", inventory.get("mapped_cis_rule_count", 0)),
    )
    story.append(_simple_table(("Indicateur", "Valeur"), list(totals), [355, 156], styles))
    table_rows = [
        (f"{item.get('group','?')} / {item.get('part','?')}",
         str(item.get("parser_count", 0)), str(item.get("ir_count", 0)), item.get("status", "?"))
        for item in parts
    ]
    story.append(Spacer(1, 9))
    story.append(_simple_table(("Partie", "Parsing", "IR", "Couverture"),
                               table_rows, [241, 62, 49, 159], styles))
    if inventory.get("warnings"):
        story.append(_p("Limites et alertes de couverture", styles["subsection"]))
        for warning in inventory["warnings"]:
            story.append(_p(f"- {warning}", styles["body"]))
    story.append(Spacer(1, 10))
    story.append(_p("Méthodologie : le parsing et l'IR établissent les faits configurés ; ils ne produisent aucun verdict CIS à eux seuls. Le rapport 02 effectue la comparaison avec les contrôles retenus.", styles["muted"]))
    _document(stream, "NetAudit - parsing et normalisation Cisco IOS").build(
        story, onFirstPage=lambda c, d: _footer(c, d, "PARSING / IR"),
        onLaterPages=lambda c, d: _footer(c, d, "PARSING / IR"))
    return stream.getvalue()


def _rule_table(finding: dict, styles: dict) -> Table:
    status = finding["status"]
    status_color = {"PASS": TEAL, "FAIL": RED, "UNKNOWN": AMBER}.get(status, SLATE)
    heading = ParagraphStyle(f"rule_{status}", parent=styles["rulehead"], textColor=status_color)
    first = [_p(f"{finding.get('cis_control_id')} / {finding.get('title')}  •  {status}  |  Impact {finding.get('risk_level', 'NOT_ASSESSED')}", heading), ""]
    def row(label, value, style="cell"):
        return [_p(label, styles["label"]), _p(value, styles[style])]
    location = finding.get("source_location") or "Repère non disponible dans l'IR"
    observed = finding.get("observed_summary") or "Non déterminé"
    if finding.get("ios_config_observed") and "Aucune commande brute" not in finding["ios_config_observed"]:
        observed += "\n" + finding["ios_config_observed"]
    source_commands = finding.get("ios_source_excerpts") or []
    excerpt_text = ("\n".join(f"L{item['line']}  {item['command']}" for item in source_commands)
                    if source_commands else "Aucune commande correspondante affichable ; absence non prouvée.")
    basis = finding.get("evidence_basis", "non_specifiee")
    remediation = finding.get("remediation") if status == "FAIL" else (
        "Compléter la preuve ; aucun changement justifié à ce stade." if status == "UNKNOWN"
        else "Aucune correction demandée pour ce verdict.")
    rows = [
        first,
        row("01  EXIGENCE CIS", finding.get("benchmark_expected", "Non documenté")),
        row("02  CONSTAT IOS / IR", f"{observed}  |  base de preuve : {basis}"),
        row("COMMANDES SOURCE", excerpt_text + "\nExtraits indicatifs expurgés ; ne constituent pas seuls un verdict.", "command"),
        row("REPÈRES SOURCE", location + " | précision : " +
            finding.get("source_evidence_quality", "NO_SOURCE_ANCHOR") +
            ". Les débuts de blocs ne sont pas des preuves de directive.", "micro"),
        row("03  ANALYSE DE L'ÉCART", finding.get("technical_analysis", "Analyse non disponible")),
        row("04  IMPACT SÉCURITÉ", finding.get("security_impact", "Impact à qualifier")),
        row("05  CORRECTION", remediation),
        row("EXEMPLE IOS", finding.get("remediation_example", "Aucune commande"), "command"),
        row("PRÉCAUTION", finding.get("remediation_caution", "Vérifier le contexte"), "micro"),
        row("06  VÉRIFICATION", finding.get("verification_command", "show running-config"), "command"),
    ]
    table = Table(rows, colWidths=[147, 364], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PALE),
        ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#F6F9FC")),
        ("BACKGROUND", (0, 3), (-1, 3), colors.HexColor("#EDF7F6")),
        ("BACKGROUND", (0, 5), (-1, 5), colors.HexColor("#F7F9FB")),
        ("BACKGROUND", (0, 7), (-1, 7), colors.HexColor("#F3F9F8")),
        ("BACKGROUND", (0, 10), (-1, 10), colors.HexColor("#EEF7F6")),
        ("SPAN", (0, 0), (1, 0)),
        ("LINEBEFORE", (0, 0), (0, -1), 3, status_color),
        ("BOX", (0, 0), (-1, -1), .7, LINE),
        ("LINEBELOW", (0, 0), (-1, -2), .4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def generate_cis_pdf(report: dict, view: dict) -> bytes:
    """Part 2: control-by-control benchmark / observation / remediation."""
    styles = _styles()
    stream = BytesIO()
    story = [
        _p("RAPPORT 02 / MOTEUR DE CONFORMITE CIS", styles["subsection"]),
        _p("Security posture / registre technique", styles["title"]),
        _p("Exigence du référentiel, faits normalisés, explication de l'écart, risque, correction et contrôle de vérification. 39 règles sélectionnées du CIS Cisco IOS 15 v4.1.1. Audit statique et non certifié.", styles["subtitle"]),
    ]
    _metadata(story, styles, hostname=report.get("hostname"), ios=report.get("ios_version"),
              source=report.get("source_file"), sha256=report.get("source_sha256"),
              timestamp=report.get("generated_at", ""))
    story.append(_p("Synthèse des verdicts", styles["section"]))
    counts = report["counts"]
    rows = [
        ("PASS", counts["PASS"], "Critère satisfait sur la configuration observée"),
        ("FAIL", counts["FAIL"], "Écart démontré ou absence déduite de la complétude déclarée"),
        ("UNKNOWN", counts["UNKNOWN"], "Information insuffisante pour une conclusion fiable"),
        ("NOT_APPLICABLE", counts["NOT_APPLICABLE"], "Hors du périmètre applicable au cas"),
        ("NOT_SELECTED", counts["NOT_SELECTED"], "Hors profil choisi"),
    ]
    story.append(_simple_table(("Statut", "Nombre", "Signification"), rows, [121, 72, 318], styles))
    ratio = view.get("pass_percent_of_assessed")
    ratio_str = f"{ratio:.1f} %" if ratio is not None else "Non calculable"
    story.append(Spacer(1, 10))
    story.append(_p(f"Contrôles conclusifs PASS/FAIL : {view['assessed']}. Part des PASS parmi ces contrôles : {ratio_str}. Cet indicateur n'est PAS un score global de certification CIS.", styles["body"]))
    story.append(_p(f"Profil : {report.get('selected_profile')} ; configuration déclarée complète : {'oui' if report.get('complete_config_assumed') else 'non'} ; interfaces WAN désignées : {', '.join(report.get('external_interfaces_designated') or []) or 'aucune'}.", styles["body"]))
    story.append(_p("Règles de décision : une absence dans une configuration partielle ne prouve aucune vulnérabilité (UNKNOWN). Les verdicts PASS ne valident ni l'état opérationnel ni l'efficacité des politiques réseau.", styles["muted"]))
    story.append(Spacer(1, 13))
    story.append(_p("Guide de lecture", styles["section"]))
    story.append(_p("01 Exigence CIS : objectif de configuration. 02 Constat : fait de l'IR et ligne source lorsqu'elle existe. 03 Analyse : justification du verdict. 04 Impact : conséquence de sécurité. 05 Correction : commande illustrative, à adapter après revue. 06 Vérification : commande show en lecture seule.", styles["body"]))
    story.append(_p("Les repères distinguent les lignes exactes de règles ACL et les débuts de blocs IOS. Ces derniers ne prouvent pas le numéro de ligne de la directive imbriquée. Quand l'IR ne fournit pas de repère fiable, le rapport ne l'invente pas.", styles["muted"]))
    story.append(_p("Les exemples IOS contiennent des placeholders ; ils ne sont pas exécutés automatiquement. Les commandes show peuvent intégrer les noms d'interfaces et d'ACL observés : leur exécution demeure manuelle et soumise à autorisation.", styles["muted"]))

    story.append(PageBreak())  # a clear separation between executive synthesis and control register
    for group in view.get("groups", []):
        story.append(CondPageBreak(130))  # keep a domain heading with its first control
        story.append(_p(f"Domaine {group['id']} - {group['name']}", styles["section"]))
        story.append(_p(f"{group['subtitle']} | {group['fail']} écart(s) sur {group['total']} contrôle(s)", styles["muted"]))
        for finding in group["findings"]:
            story.append(Spacer(1, 8))
            story.append(KeepTogether([
                _p(f"Référence CIS {finding['cis_control_id']} | Profil {finding.get('profile')} | Page {finding.get('pdf_page') or '?'}", styles["micro"]),
                Spacer(1, 3),
                _rule_table(finding, styles),
            ]))
    supplemental = (report.get("network_coherence") or {}).get("findings") or []
    if supplemental:
        story.append(PageBreak())
        story.append(_p("Cohérence réseau - diagnostic complémentaire", styles["section"]))
        story.append(_p("Ces contrôles exploratoires sont distincts du benchmark CIS et ne modifient aucun des 39 verdicts. REVIEW impose une analyse humaine.", styles["muted"]))
        for item in supplemental:
            story.append(CondPageBreak(90))
            story.append(_p(f"{item['rule_id']} | {item['status']} | Impact {item['severity']}", styles["subsection"]))
            story.append(_p(item["description"], styles["body"]))
            story.append(_p("Constat structuré : " + str(item["evidence"]), styles["micro"]))
            story.append(_p("Recommandation : " + item["recommendation"], styles["body"]))
    story.append(Spacer(1, 15))
    story.append(_p("Limitations et périmètre", styles["section"]))
    story.append(_p("Ce document examine uniquement 39 contrôles sélectionnés et implémentés pour ce laboratoire. Il ne constitue ni le benchmark CIS complet, ni une certification, ni une mesure de risque CVSS. Les preuves structurées sont disponibles dans l'export JSON et les observations opérationnelles doivent être confirmées séparément par des commandes show collectées en lecture seule.", styles["body"]))
    _document(stream, "NetAudit - audit CIS Cisco IOS 15 et remediations").build(
        story, onFirstPage=lambda c, d: _footer(c, d, "AUDIT CIS"),
        onLaterPages=lambda c, d: _footer(c, d, "AUDIT CIS"))
    return stream.getvalue()
