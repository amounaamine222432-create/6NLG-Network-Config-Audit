"""Flask UI multiconstructeur pour les composants Cisco IOS et Juniper Junos.

Les fichiers Cisco sont analysés en mémoire ; les parseurs tiers Juniper
requièrent un fichier temporaire privé, supprimé dès la requête terminée.
Le cache contient uniquement les IR et constats expurgés.
"""

from __future__ import annotations

from collections import Counter, OrderedDict
from datetime import datetime, timezone
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
from threading import RLock
import time
from typing import Any

from flask import Flask, Request as FlaskRequest, Response, abort, jsonify, render_template, request, send_file, session
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename


PROJECT_ROOT = Path(__file__).resolve().parent.parent
for module_dir in (PROJECT_ROOT, PROJECT_ROOT / "parsers", PROJECT_ROOT / "scripts"):
    if str(module_dir) not in sys.path:
        sys.path.insert(0, str(module_dir))

from cisco_parser import parse_cisco_ios  # noqa: E402
from normalizers.cisco_normalizer import normalize_cisco_ios  # noqa: E402
from audit_parser_coverage import audit_text  # noqa: E402
from report_validation import analyze_device  # noqa: E402
from audit_engine.cis15_engine import audit_cis_ios15  # noqa: E402
from audit_engine.network_coherence import audit_network_coherence  # noqa: E402

from .cis_dashboard import build_cis_dashboard, enrich_cis_report
from .detailed_report import build_detailed_devices
from .juniper_adapter import analyze_juniper
from .parsed_preview import safe_parsed_preview
from .pdf_exports import generate_parsing_ir_pdf, generate_cis_pdf
from .cis_config_preview import redacted_ios_preview
from .cis_failure_summary import failure_summary_csv, failure_summary_html


ALLOWED_SUFFIXES = {"cisco_ios": {".cfg", ".txt"}, "juniper_junos": {".cfg", ".txt", ".conf", ".md"}}
MAX_FILES = 10
MAX_FILE_BYTES = 1024 * 1024  # 1 MiB per file
MAX_REQUEST_BYTES = 12 * 1024 * 1024
REPORT_TTL_SECONDS = 30 * 60
CIS_CATALOGUE_PATH = PROJECT_ROOT / "benchmarks/rules/cisco_ios/cis_ios15_v4.1.1_phase5_lab.json"


class MemoryOnlyUploadRequest(FlaskRequest):
    """Keep Werkzeug multipart file streams in memory (bounded request size)."""

    def _get_file_stream(self, total_content_length, content_type, filename=None, content_length=None):
        return BytesIO()


class ReportStore:
    """Small, in-memory, expiring cache of already-sanitized deliverables."""

    def __init__(self, limit: int = 24, ttl_seconds: int = REPORT_TTL_SECONDS):
        self.limit = limit
        self.ttl_seconds = ttl_seconds
        self.items: OrderedDict[str, tuple[float, dict[str, bytes]]] = OrderedDict()
        self.lock = RLock()

    def put(self, payload: dict[str, bytes]) -> str:
        identifier = secrets.token_urlsafe(22)
        with self.lock:
            now = time.monotonic()
            self._purge(now)
            self.items[identifier] = (now + self.ttl_seconds, payload)
            while len(self.items) > self.limit:
                self.items.popitem(last=False)
        return identifier

    def get(self, identifier: str) -> dict[str, bytes] | None:
        with self.lock:
            self._purge(time.monotonic())
            stored = self.items.get(identifier)
            return stored[1] if stored else None

    def _purge(self, now: float) -> None:
        for identifier, (expiry, _) in list(self.items.items()):
            if expiry <= now:
                del self.items[identifier]


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _safe_name(raw_name: str, used: set[str], vendor: str = "cisco_ios") -> str:
    candidate = secure_filename(Path(raw_name.replace("\\", "/")).name)
    if not candidate or Path(candidate).suffix.lower() not in ALLOWED_SUFFIXES[vendor]:
        raise ValueError("Extension refusee pour le constructeur selectionne")
    root, suffix = candidate[: -len(Path(candidate).suffix)], Path(candidate).suffix
    unique = candidate
    counter = 2
    while unique.lower() in used:
        unique = f"{root}_{counter}{suffix}"
        counter += 1
    used.add(unique.lower())
    return unique


def _analyze_one(content: str, filename: str, digest: str) -> tuple[dict, dict, dict, dict]:
    coverage = audit_text(content, file=filename)
    if not coverage.get("ios_family_compatible"):
        raise ValueError("Format Cisco IOS non confirme ou dialecte incompatible")

    parsed = parse_cisco_ios(content)
    normalized = normalize_cisco_ios(parsed, source_file=filename, sha256=digest)
    static_review = analyze_device(parsed, filename)

    platform = coverage["source_only_counts"]
    global_unknown = coverage["unparsed_global_count"]
    nested_unknown = coverage["nested_opaque_count"]
    platform_unknown = platform["platform_unmodeled"]
    scopes = normalized.get("diagnostics", {}).get("platform_scope_limited_count", 0)
    unknown_total = global_unknown + nested_unknown + platform_unknown
    status = "a_verifier" if unknown_total or scopes or coverage["format_confidence"] != "high" else "analyse"

    result = {
        "file": filename,
        "hostname": static_review["hostname"],
        "format": coverage["source_format"],
        "format_confidence": coverage["format_confidence"],
        "status": status,
        "counts": static_review["counts"],
        "findings": static_review["findings"],
        "interfaces": static_review["interfaces"],
        "finding_totals": static_review["finding_totals"],
        "coverage": {
            "global_unknown": global_unknown,
            "nested_unknown": nested_unknown,
            "platform_modeled": platform["platform_modeled"],
            "platform_unknown": platform_unknown,
            "platform_scope_limited": scopes,
            "formatting_recoveries": coverage["formatting_recovery_count"],
            "nested_categories": coverage["nested_opaque_by_scope"],
        },
    }
    return result, normalized, static_review, safe_parsed_preview(parsed, filename)


def _build_report(devices: list[dict], when: str) -> dict:
    findings = Counter(level for device in devices for level, qty in device["finding_totals"].items() for _ in range(qty))
    return {
        "report_schema_version": "1.0",
        "generated_at": when,
        "disclaimer": "Analyse statique, sans test operationnel ni certificat de conformite.",
        "totals": {
            "devices": len(devices),
            "warnings": findings["warning"],
            "successes": findings["success"],
            "informations": findings["info"],
            "unparsed_global": sum(device["counts"]["unparsed_global"] for device in devices),
        },
        "devices": devices,
    }


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.request_class = MemoryOnlyUploadRequest
    app.config.update(
        SECRET_KEY=os.environ.get("NETAUDIT_SECRET_KEY") or secrets.token_hex(32),
        MAX_CONTENT_LENGTH=MAX_REQUEST_BYTES,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=False,  # local loopback http; use HTTPS for remote access
        JSON_AS_ASCII=False,
    )
    if test_config:
        app.config.update(test_config)
    reports = ReportStore()
    cis_reports = ReportStore()

    @app.after_request
    def security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if (request.endpoint == "view_result" and request.view_args and
                request.view_args.get("kind") == "html") or request.endpoint == "cis_view_html":
            # The report has inline CSS; it may be embedded only by this same-origin UI.
            response.headers["X-Frame-Options"] = "SAMEORIGIN"
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; "
                "img-src data:; frame-ancestors 'self'; base-uri 'none'; form-action 'none'"
            )
        else:
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "img-src 'self' data:; connect-src 'self'; "
                "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
            )
        return response

    @app.get("/")
    def home():
        csrf = session.get("csrf")
        if not csrf:
            csrf = secrets.token_urlsafe(30)
            session["csrf"] = csrf
        return render_template("index.html", csrf=csrf, max_files=MAX_FILES)

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ready", "engine": "NetAudit Cisco IOS / Juniper Junos",
                        "vendors": ["cisco_ios", "juniper_junos"], "mode": "static_local"})

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_error):
        return jsonify({"ok": False, "error": "Import trop volumineux (limite : 12 Mio par requete)."}), 413

    @app.post("/api/analyze")
    def analyze():
        if not session.get("csrf") or not secrets.compare_digest(
            request.headers.get("X-CSRF-Token", ""), session["csrf"]
        ):
            return jsonify({"ok": False, "error": "Session invalide : recharge la page."}), 403

        vendor = request.form.get("vendor", "cisco_ios")
        if vendor not in ALLOWED_SUFFIXES:
            return jsonify({"ok": False, "error": "Constructeur non pris en charge."}), 400

        files = request.files.getlist("files")
        if not files or all(not file.filename for file in files):
            return jsonify({"ok": False, "error": "Selectionne au moins un fichier .cfg ou .txt."}), 400
        if len(files) > MAX_FILES:
            return jsonify({"ok": False, "error": f"Maximum {MAX_FILES} fichiers par analyse."}), 400

        results, normalized_items, parsed_items, review_devices, errors = [], [], [], [], []
        used_names: set[str] = set()
        for file in files:
            try:
                filename = _safe_name(file.filename or "", used_names, vendor)
                data = file.stream.read(MAX_FILE_BYTES + 1)
                if len(data) > MAX_FILE_BYTES:
                    raise ValueError("Fichier depassant 1 Mio")
                if not data or b"\x00" in data:
                    raise ValueError("Fichier vide ou contenu binaire")
                content = data.decode("utf-8-sig")
                digest = hashlib.sha256(data).hexdigest()
                if vendor == "juniper_junos":
                    result, normalized, review, safe_parsed = analyze_juniper(content, filename, digest)
                else:
                    result, normalized, review, safe_parsed = _analyze_one(content, filename, digest)
            except (ValueError, UnicodeError):
                errors.append({"file": secure_filename(file.filename or "")[:100],
                               "message": "Format invalide, non pris en charge ou fichier trop volumineux."})
                continue
            # Never retain the raw upload, parsed object or CLI lines in reports.
            results.append(result)
            normalized_items.append({"file": filename, "ir": normalized})
            parsed_items.append({"file": filename, "parsed": safe_parsed})
            review_devices.append(review)

        if not results:
            return jsonify({"ok": False, "error": "Aucune configuration exploitable pour le constructeur choisi.",
                            "file_errors": errors}), 422

        now = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")
        report = _build_report(review_devices, now)
        ir_package = {"schema_version": "1.0.0", "generated_at": now, "devices": normalized_items}
        parsing_package = {"schema_version": "safe_parse_view_v1", "generated_at": now, "devices": parsed_items}
        metrics = {
            "devices": len(results),
            "interfaces": sum(item["counts"]["interfaces"] for item in results),
            "warnings": report["totals"]["warnings"],
            "unknowns": sum(item["coverage"].get("combined_unmodeled", item["coverage"].get("v1_unmodeled", 0))
                            if vendor == "juniper_junos" else
                            item["coverage"]["global_unknown"] + item["coverage"]["nested_unknown"]
                            + item["coverage"]["platform_unknown"] for item in results),
            "ospf": sum(item["counts"]["ospf"] for item in results),
            "bgp": sum(item["counts"]["bgp"] for item in results),
        }
        if vendor == "juniper_junos":
            detailed_html = render_template(
                "report_juniper.html", generated_at=now, totals=report["totals"],
                metrics=metrics,
                devices=[{"summary": result, "ir": norm["ir"], "review": review}
                         for result, norm, review in zip(results, normalized_items, review_devices)],
            )
        else:
            detailed_devices = build_detailed_devices(results, normalized_items, review_devices)
            detailed_html = render_template(
                "report_detailed.html", generated_at=now,
                totals=report["totals"], metrics=metrics, devices=detailed_devices,
            )
        reports_data = {
            "html": detailed_html.encode("utf-8"),
            "summary": _json_bytes(report),
            "ir": _json_bytes(ir_package),
            "parsing": _json_bytes(parsing_package),
        }
        identifier = reports.put(reports_data)
        session["report_ids"] = (session.get("report_ids", []) + [identifier])[-8:]
        return jsonify({
            "ok": True, "run_id": identifier, "vendor": vendor, "generated_at": now,
            "metrics": metrics, "devices": results, "file_errors": errors,
            "downloads": {key: f"/api/download/{identifier}/{key}" for key in reports_data},
        })

    @app.post("/api/cis/audit")
    def cis_audit():
        """Separate Cisco-only CIS workflow; no coupling to the legacy report."""
        if not session.get("csrf") or not secrets.compare_digest(
            request.headers.get("X-CSRF-Token", ""), session["csrf"]
        ):
            return jsonify({"ok": False, "error": "Session invalide : recharge la page."}), 403

        file = request.files.get("file")
        if file is None or not file.filename:
            return jsonify({"ok": False, "error": "Choisis un fichier Cisco IOS .cfg ou .txt."}), 400
        profile = request.form.get("profile", "L1")
        if profile not in {"L1", "L2"}:
            return jsonify({"ok": False, "error": "Profil CIS invalide (L1 ou L2)."}), 400
        completeness = request.form.get("assume_complete", "false")
        if completeness not in {"true", "false"}:
            return jsonify({"ok": False, "error": "Indicateur de complétude invalide."}), 400
        external_names = [name.strip() for raw in request.form.getlist("external_interface")
                          for name in raw.split(",") if name.strip()]
        if len(external_names) > 12 or any(len(name) > 90 or any(ch in name for ch in "\r\n\x00")
                                              for name in external_names):
            return jsonify({"ok": False, "error": "Liste des interfaces externes invalide."}), 400

        try:
            filename = _safe_name(file.filename, set(), "cisco_ios")
            data = file.stream.read(MAX_FILE_BYTES + 1)
            if len(data) > MAX_FILE_BYTES or not data or b"\x00" in data:
                raise ValueError("Fichier vide, binaire ou trop volumineux")
            content = data.decode("utf-8-sig")
            coverage = audit_text(content, file=filename)
            if not coverage.get("ios_family_compatible"):
                raise ValueError("Dialecte Cisco IOS non confirme")
            parsed = parse_cisco_ios(content)
            ir = normalize_cisco_ios(parsed, source_file=filename,
                                     sha256=hashlib.sha256(data).hexdigest())
            known_interfaces = {str(item.get("name")) for item in ir.get("interfaces", [])
                                if isinstance(item, dict)}
            if any(name not in known_interfaces for name in external_names):
                return jsonify({"ok": False, "error":
                                "Interface externe absente de la configuration : vérifie son nom exact."}), 400
            catalogue = json.loads(CIS_CATALOGUE_PATH.read_text(encoding="utf-8"))
            report = audit_cis_ios15(
                ir, catalogue, profile=profile, complete_config=completeness == "true",
                parsed=parsed, audit_context={"external_interfaces": list(dict.fromkeys(external_names))},
            )
            parsing_view = safe_parsed_preview(parsed, filename)
            enrich_cis_report(report, catalogue, ir, source_text=content)
            report["network_coherence"] = audit_network_coherence(
                ir, complete_config=completeness == "true")
            report["configuration_preview"] = redacted_ios_preview(content)
        except (ValueError, UnicodeError):
            return jsonify({"ok": False, "error":
                            "Configuration Cisco IOS invalide, non compatible ou trop volumineuse."}), 422

        # Neither the raw text nor the full parsed structure is retained or exported.
        generated_at = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")
        report["generated_at"] = generated_at
        dashboard = build_cis_dashboard(report)
        html = render_template("report_cis_ios.html", report=report, view=dashboard)
        parsing_pdf = generate_parsing_ir_pdf(
            parsing_view, report["parsing_normalization_inventory"],
            hostname=report["hostname"], ios_version=report["ios_version"],
            source_file=report["source_file"], source_sha256=report["source_sha256"],
            generated_at=generated_at,
        )
        audit_pdf = generate_cis_pdf(report, dashboard)
        identifier = cis_reports.put({
            "json": _json_bytes(report), "html": html.encode("utf-8"),
            "parsing_pdf": parsing_pdf, "cis_pdf": audit_pdf,
            "failures_csv": failure_summary_csv(report),
            "failures_html": failure_summary_html(report),
        })
        session["cis_report_ids"] = (session.get("cis_report_ids", []) + [identifier])[-8:]
        parse_counts = {
            "interfaces": len(parsing_view.get("interfaces") or []),
            "ospf": len(parsing_view.get("ospf_processes") or []),
            "bgp": len(parsing_view.get("bgp_processes") or []),
            "acls": len(parsing_view.get("access_lists") or []),
            "nat": len(parsing_view.get("nat_rules") or []),
            "dhcp": len(parsing_view.get("dhcp_pools") or []),
        }
        inventory = report["parsing_normalization_inventory"]
        return jsonify({
            "ok": True, "run_id": identifier, "report": report,
            "pipeline": {
                "parsing": {"hostname": parsing_view.get("hostname"),
                            "counts": parse_counts,
                            "interfaces": [interface.get("name") for interface in parsing_view.get("interfaces") or []],
                            "unparsed_global": parsing_view.get("diagnostics", {}).get("unparsed_global_count", 0)},
                "normalization": {"part_count": inventory["part_count"],
                                  "group_count": inventory["group_count"],
                                  "audited_part_count": inventory["audited_part_count"],
                                  "mapped_cis_rule_count": inventory["mapped_cis_rule_count"],
                                  "inventory": inventory["parts"]},
            },
            "summary": {key: value for key, value in dashboard.items() if key != "status_labels"},
            "downloads": {
                "json": f"/api/cis/download/{identifier}/json",
                "html": f"/api/cis/download/{identifier}/html",
                "parsing_pdf": f"/api/cis/download/{identifier}/parsing_pdf",
                "cis_pdf": f"/api/cis/download/{identifier}/cis_pdf",
                "failures_csv": f"/api/cis/download/{identifier}/failures_csv",
                "failures_html": f"/api/cis/download/{identifier}/failures_html",
            },
            "html_preview": f"/api/cis/view/{identifier}",
        })

    @app.get("/api/cis/download/<identifier>/<kind>")
    def cis_download(identifier: str, kind: str):
        if kind not in {"json", "html", "parsing_pdf", "cis_pdf", "failures_csv", "failures_html"} or identifier not in session.get("cis_report_ids", []):
            abort(404)
        stored = cis_reports.get(identifier)
        if not stored:
            abort(404)
        mime = {"json": "application/json", "html": "text/html; charset=utf-8",
                "parsing_pdf": "application/pdf", "cis_pdf": "application/pdf",
                "failures_csv": "text/csv; charset=utf-8", "failures_html": "text/html; charset=utf-8"}[kind]
        download_name = {
            "json": f"6nlg_cis_ios15_{identifier[:8]}.json",
            "html": f"6nlg_cis_ios15_{identifier[:8]}.html",
            "parsing_pdf": f"6nlg_parsing_ir_{identifier[:8]}.pdf",
            "cis_pdf": f"6nlg_audit_cis_{identifier[:8]}.pdf",
            "failures_csv": f"6nlg_erreurs_cis_{identifier[:8]}.csv",
            "failures_html": f"6nlg_synthese_fail_{identifier[:8]}.html",
        }[kind]
        return send_file(BytesIO(stored[kind]), mimetype=mime, as_attachment=True,
                         download_name=download_name, max_age=0)

    @app.get("/api/cis/view/<identifier>")
    def cis_view_html(identifier: str):
        if identifier not in session.get("cis_report_ids", []):
            abort(404)
        stored = cis_reports.get(identifier)
        if not stored:
            abort(404)
        return Response(stored["html"], content_type="text/html; charset=utf-8")

    @app.get("/api/download/<identifier>/<kind>")
    def download(identifier: str, kind: str):
        if identifier not in session.get("report_ids", []):
            abort(404)
        files = reports.get(identifier)
        if files is None or kind not in files:
            abort(404)
        mime_type = "text/html; charset=utf-8" if kind == "html" else "application/json"
        extension = "html" if kind == "html" else "json"
        return send_file(BytesIO(files[kind]), mimetype=mime_type, as_attachment=True,
                         download_name=f"6nlg_{kind}_{identifier[:8]}.{extension}",
                         max_age=0)

    @app.get("/api/view/<identifier>/<kind>")
    def view_result(identifier: str, kind: str):
        """Read-only, session-protected previews: safe parsing, IR and HTML."""
        if kind not in {"parsing", "ir", "html"} or identifier not in session.get("report_ids", []):
            abort(404)
        files = reports.get(identifier)
        if files is None or kind not in files:
            abort(404)
        if kind == "html":
            return Response(files[kind], content_type="text/html; charset=utf-8")
        return Response(files[kind], content_type="application/json; charset=utf-8")

    return app
