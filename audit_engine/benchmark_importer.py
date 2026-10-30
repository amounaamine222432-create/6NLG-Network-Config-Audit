"""Extraction de recommandations *candidates* depuis un PDF de benchmark.

Les propositions ne deviennent jamais automatiquement des règles d'audit :
leur interprétation, leur applicabilité et leurs droits d'usage sont à valider.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any


_HEADING = re.compile(
    r"^\s*(?P<id>\d+(?:\.\d+){1,5})\s+"
    r"(?P<title>(?:Ensure|Configure|Enable|Disable|Verify|Set|Restrict|Use|"
    r"Create|Require|Prevent|Protect|Limit|Implement|Do not|Establish)\b[^\n]*)$",
    re.IGNORECASE,
)
_LABELS = (
    "Profile Applicability", "Description", "Rationale", "Impact",
    "Audit", "Remediation", "Default Value", "References", "CIS Controls",
    "Additional Information", "Notes",
)
_SECTION = re.compile(
    r"(?im)^\s*(" + "|".join(re.escape(x) for x in _LABELS) + r")\s*:\s*"
)


def _sections(lines: list[str]) -> dict[str, str]:
    """Découper un extrait en sections (Audit, Remediation, etc.)."""
    body = "\n".join(lines).strip()
    matches = list(_SECTION.finditer(body))
    result: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        result[match.group(1).lower().replace(" ", "_")] = body[match.end():end].strip()
    return result


def extract_candidates_from_pages(
    pages: list[str], *, source_name: str, sha256: str,
    product: str, benchmark_version: str,
) -> dict[str, Any]:
    """Extraire des contrôles plausibles sans les déclarer conformes ou vérifiés.

    Le même titre apparaît parfois dans la table des matières : conserver
    en priorité l'occurrence qui contient les sections Audit/Remediation.
    """
    occurrences: dict[str, list[dict[str, Any]]] = {}
    current: dict[str, Any] | None = None
    for page_number, page in enumerate(pages, 1):
        for raw in page.splitlines():
            line = raw.strip()
            match = _HEADING.match(line)
            if match:
                current = {
                    "control_id": match.group("id"),
                    "title": match.group("title").strip(),
                    "source_page": page_number,
                    "body_lines": [],
                }
                occurrences.setdefault(match.group("id"), []).append(current)
            elif current is not None:
                current["body_lines"].append(raw)

    candidates = []
    skipped_headings: list[str] = []
    for control_id, alternatives in occurrences.items():
        def quality(item: dict[str, Any]) -> tuple[int, int]:
            sections = _sections(item["body_lines"])
            return (int(bool(sections.get("audit"))) +
                    int(bool(sections.get("remediation"))),
                    len("\n".join(item["body_lines"])))

        chosen = max(alternatives, key=quality)
        sections = _sections(chosen["body_lines"])
        # Les tables CIS Controls et les titres de regroupements ont eux aussi
        # des identifiants numériques. Sans section Audit ou Remediation,
        # ne pas les présenter comme des recommandations vérifiables.
        if not sections.get("audit") and not sections.get("remediation"):
            skipped_headings.append(control_id)
            continue
        candidates.append({
            "control_id": control_id,
            "title": chosen["title"],
            "source_page": chosen["source_page"],
            "audit_text": sections.get("audit", ""),
            "remediation_text": sections.get("remediation", ""),
            "profile_text": sections.get("profile_applicability", ""),
            "extraction_confidence": (
                "high" if sections.get("audit") and sections.get("remediation")
                else "partial"
            ),
            "status": "review_required",
        })

    return {
        "metadata": {
            "source_filename": source_name,
            "sha256": sha256,
            "product_declared_by_user": product,
            "benchmark_version_declared_by_user": benchmark_version,
            "page_count": len(pages),
            "warning": (
                "Extraction heuristique : contrôler le PDF et les droits d'utilisation. "
                "Aucune règle n'est activée automatiquement."
            ),
        },
        "candidate_count": len(candidates),
        "skipped_heading_count": len(skipped_headings),
        "skipped_heading_ids": sorted(skipped_headings),
        "candidates": sorted(
            candidates, key=lambda x: [int(n) for n in x["control_id"].split(".")],
        ),
    }


def extract_pdf(path: Path, *, product: str, benchmark_version: str) -> dict[str, Any]:
    if not path.is_file() or path.suffix.lower() != ".pdf":
        raise ValueError("Indiquer un fichier PDF de benchmark existant")
    try:
        import fitz  # PyMuPDF ; dependance optionnelle de ce module
    except ImportError as exc:
        raise RuntimeError("Installer PyMuPDF : pip install -r requirements-audit.txt") from exc

    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with fitz.open(path) as document:
        if document.needs_pass:
            raise ValueError("Le PDF est protégé par un mot de passe")
        pages = [page.get_text("text", sort=True) for page in document]
    if not any(page.strip() for page in pages):
        raise ValueError("PDF sans couche texte exploitable : OCR à prévoir")
    return extract_candidates_from_pages(
        pages, source_name=path.name, sha256=digest,
        product=product, benchmark_version=benchmark_version,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Extraction prudente de contrôles candidats")
    parser.add_argument("pdf", type=Path, help="PDF de benchmark téléchargé légalement")
    parser.add_argument("--product", required=True, help="Ex. Cisco IOS 16")
    parser.add_argument("--benchmark-version", required=True, help="Ex. 2.0.0")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = extract_pdf(
        args.pdf, product=args.product, benchmark_version=args.benchmark_version,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"PDF analyse : {result['metadata']['source_filename']}")
    print(f"Candidats extraits : {result['candidate_count']}")
    print(f"Sortie : {args.output}")
    print("Statut : A REVOIR (aucune règle activée)")


if __name__ == "__main__":
    main()
