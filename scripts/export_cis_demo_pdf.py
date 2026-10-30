"""Generate the two demonstration PDFs from a synthetic Cisco IOS fixture.

This CLI never contacts a router. Do not feed untrusted device secrets to
external services: only a safe parsed preview and CIS evidence reach the PDFs.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from audit_engine.cis15_engine import audit_cis_ios15
from cisco_parser import parse_cisco_ios
from normalizers.cisco_normalizer import normalize_cisco_ios
from webapp.cis_dashboard import build_cis_dashboard, enrich_cis_report
from webapp.parsed_preview import safe_parsed_preview
from webapp.pdf_exports import generate_cis_pdf, generate_parsing_ir_pdf


ROOT = Path(__file__).resolve().parent.parent
CATALOGUE = ROOT / "benchmarks/rules/cisco_ios/cis_ios15_v4.1.1_phase5_lab.json"


def main() -> None:
    cli = argparse.ArgumentParser(description="Export de deux PDF Cisco IOS / CIS sans connexion reseau")
    cli.add_argument("configuration", type=Path)
    cli.add_argument("--profile", choices=("L1", "L2"), default="L2")
    cli.add_argument("--assume-complete", action="store_true")
    cli.add_argument("--external-interface", action="append", default=[])
    cli.add_argument("--output-dir", type=Path, default=ROOT / "output" / "pdf")
    args = cli.parse_args()

    raw = args.configuration.read_bytes()
    if len(raw) > 1024 * 1024 or not raw or b"\x00" in raw:
        raise ValueError("Configuration vide, binaire ou superieure a 1 Mio")
    parsed = parse_cisco_ios(raw.decode("utf-8-sig"))
    ir = normalize_cisco_ios(parsed, source_file=args.configuration.name,
                             sha256=hashlib.sha256(raw).hexdigest())
    catalogue = json.loads(CATALOGUE.read_text(encoding="utf-8"))
    report = audit_cis_ios15(ir, catalogue, profile=args.profile,
                             complete_config=args.assume_complete, parsed=parsed,
                             audit_context={"external_interfaces": args.external_interface})
    enrich_cis_report(report, catalogue, ir)
    report["generated_at"] = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")
    view = build_cis_dashboard(report)
    preview = safe_parsed_preview(parsed, args.configuration.name)
    parsing_pdf = generate_parsing_ir_pdf(
        preview, report["parsing_normalization_inventory"],
        hostname=report["hostname"], ios_version=report["ios_version"],
        source_file=report["source_file"], source_sha256=report["source_sha256"],
        generated_at=report["generated_at"],
    )
    cis_pdf = generate_cis_pdf(report, view)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    first = args.output_dir / "6nlg_rapport_01_parsing_ir.pdf"
    second = args.output_dir / "6nlg_rapport_02_audit_cis.pdf"
    first.write_bytes(parsing_pdf)
    second.write_bytes(cis_pdf)
    print("Rapport parsing et IR :", first)
    print("Rapport audit CIS :", second)
    print("Bilan CIS :", report["counts"])


if __name__ == "__main__":
    main()
