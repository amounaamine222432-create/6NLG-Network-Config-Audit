/* CIS relie au tableau de bord historique. Aucun second import de configuration. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const form = $("cisForm");
  if (!form) return;

  const names = {
    PASS: "PASS", FAIL: "FAIL", UNKNOWN: "UNKNOWN",
    NOT_APPLICABLE: "N/A", NOT_SELECTED: "HORS PROFIL", NOT_EVALUATED: "NON ÉVALUÉ",
  };
  let activeReport = null;
  let activeGroups = [];
  let generatedStageUrls = [];
  let legacySource = null;
  let auditSources = [];
  let sourceVersion = 0;

  // Compatible avec l'API phase 8 : uniquement les synthèses IR manquantes
  // sont présentées en HTML à partir des données Python existantes.
  // Le rapport de parsing original reste celui de /api/analyze : pas de doublon.
  const escapeHTML = (value) => String(value === undefined || value === null ? "" : value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  function stageDocument(title, report, body) {
    return `<!doctype html><html lang="fr"><head><meta charset="utf-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title>${escapeHTML(title)}</title><style>
      *{box-sizing:border-box}body{margin:0;background:#f3f7fb;color:#18344d;font:14px/1.6 system-ui,-apple-system,Segoe UI,sans-serif}
      main{max-width:1050px;margin:auto;padding:46px 25px}header{display:flex;justify-content:space-between;gap:20px;border-bottom:1px solid #cad9e5;padding-bottom:20px}
      .brand{font-weight:900;font-size:22px;color:#0b766c}small{color:#637f91}h1{font-size:38px;letter-spacing:-.04em;margin:37px 0 13px}
      .panel{background:#fff;border:1px solid #dce6ed;border-radius:13px;padding:23px;margin:19px 0}p{color:#536c7b}
      .stats{display:grid;grid-template-columns:repeat(3,1fr);gap:11px;margin:22px 0}.stat{background:#e8f5f2;border:1px solid #bfded7;padding:15px;border-radius:10px}
      .stat strong{font-size:29px;color:#08796c;display:block}.stat span{font-size:12px;color:#395d65}
      .table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:12px}th{text-align:left;background:#e9f1f6;color:#34556c}
      td,th{padding:10px 12px;border-bottom:1px solid #dce7ee;vertical-align:top;overflow-wrap:anywhere}
      .notice{border-left:4px solid #cf9b36;background:#fff6dd;padding:15px 19px;border-radius:8px;color:#655632;margin-top:25px}
      footer{border-top:1px solid #cbd9e3;margin-top:32px;padding-top:15px;font-size:11px;color:#67808f}
      @media(max-width:650px){.stats{grid-template-columns:1fr 1fr}header{display:block}h1{font-size:29px}}
      @media print{body{background:#fff}main{max-width:none;padding:0}.panel{break-inside:auto}}
      </style></head><body><main><header><span class="brand">netAudit / 6NLG</span>
      <small>${escapeHTML(report.generated_at || "")}</small></header><h1>${escapeHTML(title)}</h1>
      <p>Routeur : <b>${escapeHTML(report.hostname || "Inconnu")}</b> · IOS ${escapeHTML(report.ios_version || "?")}
      · Fichier : ${escapeHTML(report.source_file || "non précisé")}</p>${body}
      <div class="notice">Ce document reprend les sorties déjà calculées par le moteur Python. Une absence dans un extrait ne prouve aucune non-conformité. Les verdicts sont exclusivement dans l'audit CIS.</div>
      <footer>SUP'COM × 6NLG · Rapport statique de laboratoire · Aucun secret de configuration exporté</footer></main></body></html>`;
  }
  function makeStageReports(data) {
    const parse = data.pipeline.parsing;
    const ir = data.pipeline.normalization;
    const stat = (name, value) => `<div class="stat"><strong>${escapeHTML(value ?? 0)}</strong><span>${escapeHTML(name)}</span></div>`;
    const parsingBody = `<div class="stats">${stat("Interfaces", parse.counts.interfaces)}${stat("OSPF", parse.counts.ospf)}
      ${stat("BGP", parse.counts.bgp)}${stat("ACL", parse.counts.acls)}${stat("NAT", parse.counts.nat)}
      ${stat("DHCP", parse.counts.dhcp)}</div><section class="panel"><h2>Objets effectivement extraits</h2>
      <p>Interfaces identifiées : ${escapeHTML((parse.interfaces || []).join(", ") || "aucune observée")}</p>
      <p>Lignes globales non classées : ${escapeHTML(parse.unparsed_global ?? "non disponible")}</p>
      <small>Les détails non exposés par l'API de parsing ne sont pas extrapolés.</small></section>`;
    const rows = (ir.inventory || []).map((item) => `<tr><td>${escapeHTML(item.group)}</td><td>${escapeHTML(item.part)}</td>
      <td>${escapeHTML(item.parser_count)}</td><td>${escapeHTML(item.ir_count)}</td><td>${escapeHTML(item.status)}</td>
      <td>${escapeHTML((item.cis_control_ids || []).join(", ") || "—")}</td></tr>`).join("");
    const irBody = `<div class="stats">${stat("Parties inventoriées", ir.part_count)}${stat("Domaines", ir.group_count)}
      ${stat("Parties liées à CIS", ir.audited_part_count)}${stat("Règles reliées", ir.mapped_cis_rule_count)}</div>
      <section class="panel"><h2>Correspondance parsing → IR</h2><div class="table-wrap"><table>
      <thead><tr><th>Domaine</th><th>Partie</th><th>Parsing</th><th>IR</th><th>Statut</th><th>CIS</th></tr></thead>
      <tbody>${rows}</tbody></table></div><p>NOT_PRESENT signifie « non observé », et non « non conforme ».</p></section>`;
    return {
      normalization: stageDocument("02 · Rapport de normalisation IR", data.report, irBody),
      summary: stageDocument("Synthèse · Parsing et normalisation IR", data.report, parsingBody + irBody),
    };
  }
  function assignLocalStage(linkId, url) {
    $(linkId).href = url;
  }
  function installStageLinks(data) {
    for (const url of generatedStageUrls) URL.revokeObjectURL(url);
    generatedStageUrls = [];
    const pairs = [
      ["normalization", "cisNormalizationPreview", "cisNormalizationHtml", "02_normalisation_ir.html"],
      ["summary", "cisSummaryPreview", "cisSummaryHtml", "synthese_parsing_ir.html"],
    ];
    if (data.stage_previews && data.downloads.normalization_html && data.downloads.summary_html) {
      for (const [key, previewId, downloadId] of pairs) {
        assignLocalStage(previewId, data.stage_previews[key]);
        assignLocalStage(downloadId, data.downloads[`${key}_html`]);
      }
      return;
    }
    const localHtml = makeStageReports(data);
    for (const [key, previewId, downloadId, name] of pairs) {
      const url = URL.createObjectURL(new Blob([localHtml[key]], {type: "text/html;charset=utf-8"}));
      generatedStageUrls.push(url);
      assignLocalStage(previewId, url);
      assignLocalStage(downloadId, url);
      $(downloadId).download = name;
    }
  }

  const elem = (tag, className, value) => {
    const item = document.createElement(tag);
    if (className) item.className = className;
    if (value !== undefined) item.textContent = String(value);
    return item;
  };
  function feedback(message, isError = false) {
    const node = $("cisFeedback");
    node.textContent = message;
    node.classList.toggle("is-error", isError);
  }
  function statusChip(status) {
    const chip = elem("span", "cis-badge", names[status] || status);
    chip.dataset.status = status;
    return chip;
  }
  function makeMetric(status, number) {
    const item = elem("div", "cis-metric");
    item.dataset.status = status;
    item.append(elem("span", "", names[status] || status), elem("strong", "", number));
    return item;
  }
  function stageState(id, state) {
    const node = $(id);
    node.dataset.state = state;
    node.querySelector("i").textContent = state === "complete" ? "VALIDÉ" :
      state === "running" ? "EN COURS" : state === "error" ? "INTERROMPU" : "EN ATTENTE";
  }
  function resetCis() {
    sourceVersion += 1;
    activeReport = null;
    activeGroups = [];
    $("cisResults").classList.add("is-hidden");
    stageState("cisStageParsing", "idle");
    stageState("cisStageIR", "idle");
    stageState("cisStageAudit", "idle");
    $("cisRunBtn").disabled = true;
    $("cisSourceSelect").disabled = true;
    $("cisSourceSelect").replaceChildren(elem("option", "", "En attente du parsing et de l'IR…"));
    for (const url of generatedStageUrls) URL.revokeObjectURL(url);
    generatedStageUrls = [];
  }
  function normalizedName(name) {
    return String(name || "").normalize("NFKD").replace(/[\u0300-\u036f]/g, "")
      .replace(/[^A-Za-z0-9_.-]+/g, "_").replace(/^_+|_+$/g, "");
  }
  function useLegacyAnalysis(info) {
    resetCis();
    legacySource = null;
    auditSources = [];
    if (!info || info.vendor !== "cisco_ios") {
      $("cisPrerequisite").textContent = "Le dernier parsing concerne Juniper. L'audit CIS actuel est réservé aux configurations Cisco IOS 15 ; sélectionnez Cisco dans le tableau de bord.";
      feedback("Audit CIS non applicable à ce constructeur.");
      return;
    }
    const used = new Set();
    for (const device of info.devices || []) {
      const original = (info.files || []).findIndex((file, index) =>
        !used.has(index) && (file.name === device.file || normalizedName(file.name) === device.file));
      if (original < 0) continue; // Ne jamais associer silencieusement le mauvais fichier.
      used.add(original);
      auditSources.push({ file: info.files[original], device });
    }
    if (!auditSources.length) {
      $("cisPrerequisite").textContent = "Le parsing est terminé, mais aucun fichier Cisco accepté n'a pu être associé sans ambiguïté. Vérifiez les noms des fichiers.";
      feedback("Aucune configuration Cisco liée de façon certaine.", true);
      return;
    }
    legacySource = info;
    const select = $("cisSourceSelect");
    select.replaceChildren();
    auditSources.forEach((item, index) => {
      const option = elem("option", "", `${item.device.hostname || "Routeur"} · ${item.device.file}`);
      option.value = String(index);
      select.append(option);
    });
    select.disabled = false;
    $("cisRunBtn").disabled = false;
    $("cisPrerequisite").textContent = `${auditSources.length} fichier(s) Cisco issu(s) de l'analyse globale. Choisissez l'équipement, puis lancez la comparaison CIS sur le même fichier.`;
    stageState("cisStageParsing", "complete");
    stageState("cisStageIR", "complete");
    stageState("cisStageAudit", "idle");
    feedback("Parsing JSON et IR JSON disponibles au-dessus. Étape 3 CIS prête.");
  }
  function renderPipeline(pipeline) {
    const parse = pipeline.parsing;
    const ir = pipeline.normalization;
    const stats = $("cisIntermediateStats");
    stats.replaceChildren();
    const countLabels = [
      ["interfaces", "Interfaces"], ["ospf", "OSPF"], ["bgp", "BGP"],
      ["acls", "ACL"], ["nat", "NAT"], ["dhcp", "DHCP"],
    ];
    for (const [key, label] of countLabels) {
      const item = elem("div", "cis-intermediate-stat");
      item.append(elem("strong", "", parse.counts[key] || 0), elem("span", "", label));
      stats.append(item);
    }
    const summary = elem("div", "cis-ir-summary");
    summary.append(elem("span", "", `Parsing : ${parse.unparsed_global} ligne(s) globale(s) non classée(s)`),
      elem("span", "", `IR : ${ir.part_count} parties / ${ir.group_count} domaines`),
      elem("span", "", `${ir.audited_part_count} parties reliées à des contrôles CIS`));
    stats.append(summary);
    const mapping = $("cisMapping");
    mapping.replaceChildren();
    const table = elem("table", "cis-ir-table");
    const header = elem("tr", "");
    for (const column of ["Domaine / Partie", "Parsing", "IR", "Statut"]) {
      header.append(elem("th", "", column));
    }
    const head = elem("thead", "");
    head.append(header);
    table.append(head);
    const body = elem("tbody", "");
    for (const part of ir.inventory) {
      const line = elem("tr", "");
      line.append(elem("td", "", `${part.group} / ${part.part}`),
        elem("td", "", part.parser_count), elem("td", "", part.ir_count),
        elem("td", "", part.status));
      body.append(line);
    }
    table.append(body);
    mapping.append(table);
  }
  function renderMetrics(report, summary) {
    const counts = report.counts;
    const node = $("cisMetrics");
    node.replaceChildren();
    for (const status of ["PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE", "NOT_SELECTED"]) {
      node.append(makeMetric(status, counts[status] || 0));
    }
    const bar = $("cisDistribution");
    bar.replaceChildren();
    const total = report.implemented_rule_count || 1;
    const pairs = [
      ["PASS", counts.PASS], ["FAIL", counts.FAIL], ["UNKNOWN", counts.UNKNOWN],
      ["OTHER", (counts.NOT_APPLICABLE || 0) + (counts.NOT_SELECTED || 0) + (counts.NOT_EVALUATED || 0)],
    ];
    for (const [name, value] of pairs) {
      const segment = elem("span", "cis-seg");
      segment.dataset.status = name;
      segment.style.width = `${100 * value / total}%`;
      segment.title = `${name} : ${value}`;
      bar.append(segment);
    }
    const insights = $("cisInsights");
    insights.replaceChildren();
    const decided = elem("div", "cis-insight");
    decided.append(elem("span", "", "Contrôles conclusifs PASS / FAIL"),
      elem("strong", "", `${summary.assessed} / ${report.implemented_rule_count}`),
      elem("small", "", "Les contrôles UNKNOWN et non applicables sont exclus de cette mesure."));
    const pass = elem("div", "cis-insight");
    const ratio = summary.pass_percent_of_assessed === null ? "Non calculable" : `${summary.pass_percent_of_assessed}%`;
    pass.append(elem("span", "", "Part des PASS parmi les contrôles conclusifs"),
      elem("strong", "", ratio),
      elem("small", "", "Indicateur technique local · ce n'est pas un score de certification CIS."));
    insights.append(decided, pass);
  }
  function renderRules() {
    const filter = $("cisStatusFilter").value;
    const query = $("cisSearchInput").value.trim().toLocaleLowerCase("fr");
    const root = $("cisRules");
    root.replaceChildren();
    let visible = 0;
    for (const group of activeGroups) {
      const findings = group.findings.filter((finding) => {
        if (filter !== "ALL" && finding.status !== filter) return false;
        const searchable = `${finding.cis_control_id || ""} ${finding.title || ""} ${finding.rule_id || ""}`;
        return searchable.toLocaleLowerCase("fr").includes(query);
      });
      if (!findings.length) continue;
      visible += findings.length;
      const section = elem("section", "cis-domain");
      const heading = elem("div", "cis-domain-title");
      heading.append(elem("strong", "", `${group.id.padStart(2, "0")} / ${group.name}`),
        elem("small", "", `${findings.length} contrôle(s) affiché(s)`));
      section.append(heading);
      for (const finding of findings) {
        const item = elem("details", "cis-check");
        item.dataset.status = finding.status;
        if (finding.status === "FAIL") item.open = true;
        const summary = elem("summary", "");
        const middle = elem("span", "cis-rule-title", finding.title || "Contrôle sans titre");
        middle.append(elem("span", "cis-rule-meta", `Profil ${finding.profile} · référence p. ${finding.pdf_page ?? "—"}`));
        summary.append(elem("span", "cis-ruleid", finding.cis_control_id || "—"),
          middle, statusChip(finding.status));
        const detail = elem("div", "cis-check-detail");
        const expected = elem("div", "cis-comparison cis-expected");
        expected.append(elem("h5", "", "EXIGENCE DU CONTRÔLE CIS"),
          elem("p", "", finding.benchmark_expected || "Exigence non renseignée."));
        const observed = elem("div", "cis-comparison cis-observed");
        observed.append(elem("h5", "", "OBSERVATION DANS LA CONFIGURATION / IR"),
          elem("p", "", finding.observed_summary || "Preuve non disponible."));
        observed.append(elem("small", "cis-proof-location", finding.source_location || "Emplacement non renseigné"));
        if (Array.isArray(finding.source_anchors) && finding.source_anchors.length) {
          const anchors = elem("div", "cis-source-anchors");
          finding.source_anchors.slice(0, 8).forEach((anchor) => {
            const marker = elem("a", "cis-source-anchor", `L${anchor.line} · ${anchor.element} ↗`);
            marker.href = `${$("cisPreviewLink").href.split("#")[0]}#src-L${encodeURIComponent(anchor.line)}`;
            marker.target = "_blank";
            marker.rel = "noopener";
            marker.title = anchor.scope || "Repère de source";
            anchors.append(marker);
          });
          observed.append(anchors);
        }
        if (finding.ios_config_observed && !finding.ios_config_observed.startsWith("Aucune commande brute")) {
          observed.append(elem("code", "cis-inline-command", finding.ios_config_observed));
        }
        const panel = (number, title, content, code = false) => {
          const card = elem("div", "cis-technical-card");
          const head = elem("h5", "", `${number}  /  ${title}`);
          card.append(head, elem(code ? "pre" : "p", code ? "cis-technical-code" : "", content || "Non renseigné"));
          return card;
        };
        detail.append(expected, observed,
          panel("03", "ANALYSE DE L'ÉCART", finding.technical_analysis),
          panel("04", "IMPACT DE SÉCURITÉ", finding.security_impact));
        const remedial = panel("05", "CORRECTION RECOMMANDÉE", finding.status === "FAIL"
          ? finding.remediation : "Aucune correction justifiée : compléter les preuves avant toute action.");
        if (finding.status === "FAIL") {
          remedial.append(elem("span", "cis-technical-subtitle", "EXEMPLE IOS - À ADAPTER"),
            elem("pre", "cis-technical-code", finding.remediation_example || "Aucune commande"),
            elem("small", "cis-proof-location", finding.remediation_caution || "Revue manuelle requise."));
        } else {
          remedial.append(elem("small", "cis-proof-location", "Aucun exemple de commande corrective : écart non démontré."));
        }
        detail.append(remedial, panel("06", "VÉRIFICATION EN LECTURE SEULE", finding.verification_command, true));
        const proof = elem("details", "cis-raw-evidence");
        proof.append(elem("summary", "", "Afficher la preuve IR structurée (JSON technique)"),
          elem("pre", "", JSON.stringify(finding.evidence || {}, null, 2)));
        detail.append(proof);
        item.append(summary, detail);
        section.append(item);
      }
      root.append(section);
    }
    if (visible === 0) root.append(elem("p", "cis-empty", "Aucun contrôle ne correspond aux filtres sélectionnés."));
  }
  function showResult(data, source) {
    activeReport = data.report;
    activeGroups = data.summary.groups;
    $("cisReportName").textContent = `${activeReport.hostname || "Équipement inconnu"} · IOS ${activeReport.ios_version || "?"}`;
    $("cisReportInfo").textContent = `${activeReport.generated_at} · Profil ${activeReport.selected_profile} · ${activeReport.implemented_rule_count} contrôles CIS · Absences non présumées (UNKNOWN)`;
    const evidenceName = activeReport.source_file || source.device.file;
    $("cisTraceability").textContent = `Même fichier source : ${source.file.name} · Parsing/IR : exécution ${legacySource.runId.slice(0, 8)} · Audit CIS : ${evidenceName}. Le rapport de parsing original n'est pas remplacé.`;
    $("cisSourceParsingPreview").href = legacySource.htmlPreview;
    $("cisSourceParsingJson").href = legacySource.downloads.parsing;
    $("cisSourceIrJson").href = legacySource.downloads.ir;
    installStageLinks(data);
    $("cisPreviewLink").href = data.html_preview;
    $("cisHtmlLink").href = data.downloads.html;
    $("cisJsonLink").href = data.downloads.json;
    $("cisParsingPdf").href = data.downloads.parsing_pdf;
    $("cisAuditPdf").href = data.downloads.cis_pdf;
    $("cisFailuresCsv").href = data.downloads.failures_html;
    $("cisConfigPreview").href = data.html_preview + "#configuration-importee";
    renderPipeline(data.pipeline);
    stageState("cisStageParsing", "complete");
    stageState("cisStageIR", "complete");
    stageState("cisStageAudit", "complete");
    renderMetrics(data.report, data.summary);
    $("cisStatusFilter").value = "ALL";
    $("cisSearchInput").value = "";
    renderRules();
    $("cisResults").classList.remove("is-hidden");
    $("cisResults").scrollIntoView({behavior: "smooth", block: "start"});
  }

  window.addEventListener("netaudit:source-changed", () => {
    legacySource = null;
    auditSources = [];
    resetCis();
    $("cisPrerequisite").textContent = "La sélection a changé. Relancez le parsing et la normalisation dans le tableau de bord pour rétablir les preuves.";
    feedback("Analyse préalable requise.");
  });
  window.addEventListener("netaudit:analysis-ready", (event) => useLegacyAnalysis(event.detail));
  $("cisSourceSelect").addEventListener("change", () => {
    sourceVersion += 1;
    $("cisResults").classList.add("is-hidden");
    stageState("cisStageAudit", "idle");
    $("cisRunBtn").disabled = !legacySource;
    feedback("Équipement sélectionné. Prêt pour l'audit CIS.");
  });
  $("cisStatusFilter").addEventListener("change", renderRules);
  $("cisSearchInput").addEventListener("input", renderRules);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const source = auditSources[Number($("cisSourceSelect").value)];
    if (!legacySource || !source) {
      feedback("Analyse d'abord le fichier dans la section Parsing / IR.", true);
      return;
    }
    const file = source.file;
    if (file.size > 1024 * 1024) { feedback("Le fichier dépasse 1 Mio.", true); return; }
    const currentVersion = sourceVersion;
    const button = $("cisRunBtn");
    button.disabled = true;
    stageState("cisStageAudit", "running");
    $("cisResults").classList.add("is-hidden");
    feedback(`Audit CIS en cours sur ${source.device.file} : comparaison aux 39 contrôles et production du rapport final…`);
    try {
      const payload = new FormData();
      payload.append("file", file);
      payload.append("profile", $("cisProfile").value);
      payload.append("assume_complete", $("cisCompleteConfig").checked ? "true" : "false");
      const interfaces = $("cisExternalInterface").value.trim();
      if (interfaces) payload.append("external_interface", interfaces);
      const response = await fetch("/api/cis/audit", {
        method: "POST", credentials: "same-origin", body: payload,
        headers: {"X-CSRF-Token": document.querySelector('meta[name="csrf-token"]').content},
      });
      const data = await response.json();
      if (sourceVersion !== currentVersion) return; // La sélection a changé entre-temps.
      if (!response.ok || !data.ok) throw new Error(data.error || `Erreur HTTP ${response.status}`);
      showResult(data, source);
      feedback("Audit terminé : rapport original de parsing conservé, IR et synthèse disponibles, rapport CIS final prêt.");
    } catch (error) {
      if (sourceVersion !== currentVersion) return;
      stageState("cisStageAudit", "error");
      feedback(error && error.message ? error.message : "Impossible de terminer l'audit.", true);
    } finally {
      if (sourceVersion === currentVersion) button.disabled = false;
    }
  });
})();
