/* NetAudit console — aucun framework JavaScript et aucune configuration brute stockée. */
(() => {
  "use strict";

  const el = (id) => document.getElementById(id);
  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  const chosen = [];
  const vendorSelect = el("vendorSelect");
  const maxFiles = 10;
  const maxBytes = 1024 * 1024;
  let activeTab = "overview";
  let selectedSeverity = "all";
  let lastResult = null;
  let selectedDeviceIndex = 0;
  let detailCache = {};
  let viewSequence = 0;
  let toastTimer;

  function updateVendor() {
    chosen.splice(0, chosen.length);
    updateQueue();
    const juniper = vendorSelect.value === "juniper_junos";
    el("fileInput").accept = juniper ? ".cfg,.txt,.conf,.md" : ".cfg,.txt";
    el("supportedFormats").textContent = juniper
      ? "Formats .CFG, .CONF, .TXT, .MD · 10 fichiers maximum · 1 Mio/fichier"
      : "Formats .CFG, .TXT · 10 fichiers maximum · 1 Mio/fichier";
    el("vendorHint").textContent = juniper
      ? "Parsing Junos détaillé (ciscoconfparse2 / clijson), normalisation IR v2.4 et bilan statique ; sans audit de conformité Juniper."
      : "Parsing Cisco IOS V6.7, normalisation IR v1, contrôles statiques Cisco.";
  }

  function make(tag, className, value) {
    const item = document.createElement(tag);
    if (className) item.className = className;
    if (value !== undefined && value !== null) item.textContent = String(value);
    return item;
  }

  function addText(parent, tag, className, value) {
    const child = make(tag, className, value);
    parent.append(child);
    return child;
  }

  function svgIcon(name) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.classList.add("ico");
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", `#i-${name}`);
    svg.append(use);
    return svg;
  }

  function feedback(message, success = false) {
    const area = el("uploadFeedback");
    area.replaceChildren();
    if (message) addText(area, "div", `feedback-message${success ? " success" : ""}`, message);
  }

  function toast(message) {
    const node = el("toast");
    node.textContent = message;
    node.classList.remove("is-hidden");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => node.classList.add("is-hidden"), 4700);
  }

  // Aperçu local avant analyse : aucune configuration n'est envoyée au serveur.
  // Le contenu est toujours inséré via textContent pour éviter toute injection HTML.
  function redactConfigurationLine(line) {
    const value = line.trim();
    if (/^(?:!|#|\/\/)/.test(value)) return line;
    if (/\b(?:password|passwd|secret|community|private[-_ ]?key|authentication[-_ ]?key|key[-_ ]?string|api[-_ ]?key|token|credential|encrypted-password|pre-shared-key)\b/i.test(value)
      || /^username\s+/i.test(value)
      || /^banner\s+/i.test(value)
      || /^set\s+system\s+(?:login\s+user|root-authentication)/i.test(value)) {
      return `${line.match(/^\s*/)[0]}[DIRECTIVE SENSIBLE MASQUÉE]`;
    }
    return line;
  }

  async function showFilePreview(file, preview, status) {
    try {
      const source = await file.text();
      if (!preview.isConnected) return;
      const lines = source.replace(/\r\n?/g, "\n").split("\n");
      const limit = 1500;
      preview.textContent = lines.slice(0, limit)
        .map((line, index) => `${String(index + 1).padStart(4, "0")} │ ${redactConfigurationLine(line)}`)
        .join("\n");
      status.textContent = `${lines.length} ligne(s) · aperçu local avant analyse · données sensibles masquées`;
      if (lines.length > limit) {
        preview.textContent += `\n… ${lines.length - limit} ligne(s) supplémentaires non affichées.`;
      }
    } catch (_error) {
      if (!preview.isConnected) return;
      preview.textContent = "Impossible de lire ce fichier dans le navigateur.";
      status.textContent = "Aperçu indisponible";
    }
  }

  function updateQueue() {
    // Toute nouvelle sélection invalide les preuves d'une exécution antérieure.
    window.dispatchEvent(new Event("netaudit:source-changed"));
    const queue = el("fileQueue");
    queue.replaceChildren();
    chosen.forEach((file, index) => {
      const row = make("div", "file-entry");
      const left = make("div", "file-entry-main");
      const icon = make("span", "file-entry-icon");
      icon.append(svgIcon("file"));
      left.append(icon);
      const label = make("div");
      addText(label, "strong", "file-entry-name", file.name);
      addText(label, "small", "file-entry-size", `${(file.size / 1024).toFixed(1)} Ko`);
      left.append(label);
      const remove = make("button", "file-remove");
      remove.type = "button";
      remove.setAttribute("aria-label", `Retirer ${file.name}`);
      remove.append(svgIcon("x"));
      remove.addEventListener("click", (event) => {
        event.stopPropagation();
        chosen.splice(index, 1);
        updateQueue();
      });
      row.append(left, remove);
      const details = make("details", "file-preview-details");
      details.open = true;
      addText(details, "summary", "file-preview-toggle", "Configuration importée — afficher / masquer l’aperçu");
      const status = addText(details, "div", "file-preview-status", "Lecture locale du fichier…");
      const preview = addText(details, "pre", "file-preview-code", "Chargement de la configuration…");
      details.append(status, preview);
      row.append(details);
      queue.append(row);
      showFilePreview(file, preview, status);
    });
    el("analyzeBtn").disabled = chosen.length === 0;
    if (chosen.length) feedback(`${chosen.length} fichier(s) prêt(s) pour l'analyse.`, true);
    else feedback("");
  }

  function includeFiles(files) {
    let warning = "";
    for (const file of files) {
      if (chosen.length >= maxFiles) {
        warning = `Maximum ${maxFiles} fichiers par analyse.`;
        break;
      }
      const filePattern = vendorSelect.value === "juniper_junos" ? /\.(cfg|txt|conf|md)$/i : /\.(cfg|txt)$/i;
      if (!filePattern.test(file.name)) {
        warning = `${file.name} : extension non admise pour le constructeur choisi.`;
        continue;
      }
      if (file.size === 0 || file.size > maxBytes) {
        warning = `${file.name} : fichier vide ou supérieur à 1 Mio.`;
        continue;
      }
      if (chosen.some((item) => item.name === file.name && item.size === file.size && item.lastModified === file.lastModified)) {
        warning = `${file.name} figure déjà dans la sélection.`;
        continue;
      }
      chosen.push(file);
    }
    updateQueue();
    if (warning) { feedback(warning); toast(warning); }
  }

  const dropzone = el("dropzone");
  vendorSelect.addEventListener("change", updateVendor);
  dropzone.addEventListener("click", () => el("fileInput").click());
  dropzone.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      el("fileInput").click();
    }
  });
  el("fileInput").addEventListener("change", (event) => {
    includeFiles([...event.target.files]);
    event.target.value = "";
  });
  ["dragenter", "dragover"].forEach((name) => dropzone.addEventListener(name, (event) => {
    event.preventDefault();
    dropzone.classList.add("drag-over");
  }));
  ["dragleave", "drop"].forEach((name) => dropzone.addEventListener(name, (event) => {
    event.preventDefault();
    dropzone.classList.remove("drag-over");
  }));
  dropzone.addEventListener("drop", (event) => {
    if (event.dataTransfer && event.dataTransfer.files) includeFiles([...event.dataTransfer.files]);
  });

  const number = (value) => Number.isFinite(Number(value)) ? Number(value) : 0;
  const counted = (value) => number(value).toLocaleString("fr-FR");

  function metric(label, value, modifier = "") {
    const block = make("div", `result-metric ${modifier}`);
    addText(block, "span", "", label);
    addText(block, "strong", "", counted(value));
    return block;
  }

  function deviceTag(label, count) {
    const chip = make("span", "device-chip");
    chip.append(document.createTextNode(label));
    addText(chip, "b", "", counted(count));
    return chip;
  }

  function renderDevices(parent) {
    const list = make("div", "device-list");
    lastResult.devices.forEach((device) => {
      const card = make("article", "device-card");
      const header = make("div", "device-header");
      const heading = make("div");
      addText(heading, "strong", "device-label", device.hostname || "Équipement sans nom");
      addText(heading, "div", "device-filename", device.file);
      const badge = make("span", `status-pill ${device.status === "analyse" ? "ok" : "review"}`,
        device.status === "analyse" ? "Couverture vérifiée" : "À examiner");
      header.append(heading, badge);
      card.append(header);

      const chips = make("div", "device-chips");
      [
        ["Interfaces", device.counts.interfaces],
        ["OSPF", device.counts.ospf],
        ["BGP", device.counts.bgp],
        ["ACL", device.counts.acl],
        ["Alertes", device.finding_totals.warning || 0]
      ].forEach(([label, count]) => chips.append(deviceTag(label, count)));
      card.append(chips);
      addText(card, "div", "device-filename", `Format : ${device.format} · confiance : ${device.format_confidence} (identité matérielle non attestée)`);

      const details = make("details", "device-details");
      addText(details, "summary", "", `Voir les interfaces (${device.interfaces.length})`);
      const ul = make("ul", "device-detail-list");
      device.interfaces.forEach((iface) => {
        const addresses = Array.isArray(iface.addresses) && iface.addresses.length ? iface.addresses.join(", ") : "IP non déclarée";
        addText(ul, "li", "", `${iface.name} · ${addresses} · ${iface.admin_state}`);
      });
      if (!device.interfaces.length) addText(ul, "li", "", "Aucune interface modélisée.");
      details.append(ul);
      card.append(details);
      list.append(card);
    });
    parent.append(list);
  }

  function renderFindings(parent) {
    const findings = lastResult.devices.flatMap((device) =>
      (device.findings || []).map((finding) => ({ ...finding, device: device.hostname })));
    const filters = make("div", "finding-filter");
    const possibilities = [["all", "Tous"], ["warning", "À vérifier"], ["success", "Conformes au contrôle"], ["info", "Informations"]];
    possibilities.forEach(([key, label]) => {
      const button = make("button", `filter-button${selectedSeverity === key ? " selected" : ""}`, label);
      button.type = "button";
      button.addEventListener("click", () => { selectedSeverity = key; renderTab(); });
      filters.append(button);
    });
    parent.append(filters);
    const visible = selectedSeverity === "all" ? findings : findings.filter((f) => f.level === selectedSeverity);
    if (!visible.length) {
      addText(parent, "p", "empty-state", "Aucun contrôle dans cette catégorie pour les fichiers analysés.");
      return;
    }
    visible.forEach((finding) => {
      const row = make("article", "finding-row");
      const names = { warning: "À vérifier", success: "Conforme au contrôle", info: "Information" };
      addText(row, "span", `severity-badge ${finding.level}`, names[finding.level] || "Information");
      const content = make("div", "finding-content");
      addText(content, "strong", "finding-title", finding.title);
      addText(content, "p", "finding-observation", finding.observation);
      addText(content, "p", "finding-advice", finding.advice);
      addText(content, "div", "finding-origin", `${finding.device} · ${finding.code}${finding.source_line ? ` · ligne ${finding.source_line}` : ""}`);
      row.append(content);
      parent.append(row);
    });
  }

  function renderCoverage(parent) {
    const introduction = make("p", "coverage-intro", "Le taux de lignes reconnues ne constitue pas une certification de la sémantique ni du fonctionnement réel de l'équipement.");
    parent.append(introduction);
    const juniper = lastResult.vendor === "juniper_junos";
    const headers = juniper
      ? ["Équipement", "Non modélisées (union IR)", "IR v1 seule", "Extension v2 seule", "Format"]
      : ["Équipement", "Globales", "Sous-sections", "Plateforme", "Portée limitée"];
    const head = make("div", "coverage-row coverage-head");
    headers.forEach((heading) => addText(head, "div", "", heading));
    parent.append(head);
    lastResult.devices.forEach((device) => {
      const row = make("div", "coverage-row");
      addText(row, "div", "coverage-name", device.hostname);
      const coverage = device.coverage;
      if (juniper) {
        [coverage.combined_unmodeled, coverage.v1_unmodeled, coverage.v2_unmodeled]
          .forEach((value, i) => addText(row, "div", `coverage-value ${i === 0 && number(value) ? "warning" : "good"}`, counted(value)));
        addText(row, "div", "coverage-value", device.format.replace("junos_", ""));
      } else {
        [coverage.global_unknown, coverage.nested_unknown, coverage.platform_unknown, coverage.platform_scope_limited]
          .forEach((value) => addText(row, "div", `coverage-value ${number(value) ? "warning" : "good"}`, counted(value)));
      }
      parent.append(row);
      if (coverage.formatting_recoveries) {
        addText(parent, "p", "coverage-intro", `${device.file} : ${coverage.formatting_recoveries} ligne(s) replacée(s) dans leur section — vérification recommandée.`);
      }
    });
    addText(parent, "p", "coverage-intro", juniper
      ? "Les compteurs Junos IR v1 et extensions v2 ont des périmètres distincts et ne sont jamais additionnés. La validité du schéma n'atteste pas le fonctionnement réseau."
      : "Directives de plateforme structurées : certaines commandes historiques (dont MMI) possèdent une signification documentée, mais leur applicabilité au matériel n'est pas prouvée.");
  }

  function renderSyntaxJSON(target, value) {
    const code = make("code", "json-code");
    const json = JSON.stringify(value, null, 2);
    // A very large configuration can be rendered without thousands of DOM nodes.
    if (json.length > 160000) {
      code.textContent = json;
    } else {
      const tokens = /("(?:\\.|[^"\\])*"(?=\s*:))|("(?:\\.|[^"\\])*")|\b(true|false|null)\b|(-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\b/g;
      let start = 0;
      let match;
      while ((match = tokens.exec(json)) !== null) {
        if (match.index > start) code.append(document.createTextNode(json.slice(start, match.index)));
        code.append(make("span", match[1] ? "json-key" : match[2] ? "json-string" : match[3] ? "json-bool" : "json-number", match[0]));
        start = tokens.lastIndex;
      }
      if (start < json.length) code.append(document.createTextNode(json.slice(start)));
    }
    target.append(code);
    return json;
  }

  function renderStructuredJSON(parent, data, kind) {
    const documents = Array.isArray(data.devices) ? data.devices : [];
    if (!documents.length) {
      addText(parent, "p", "empty-state", "Aucune donnée structurée disponible.");
      return;
    }
    const index = Math.min(selectedDeviceIndex, documents.length - 1);
    const entry = documents[index];
    const parsed = kind === "parsing";
    const title = parsed ? "Parsing de la configuration" : "Normalisation · représentation intermédiaire (IR)";
    const toolbar = make("div", "json-toolbar");
    const heading = make("div", "json-heading");
    addText(heading, "span", "json-kicker", parsed ? "ÉTAPE 02 · EXTRACTION" : "ÉTAPE 03 · MODÈLE COMMUN");
    addText(heading, "h3", "", title);
    toolbar.append(heading);

    const actions = make("div", "json-actions");
    if (documents.length > 1) {
      const select = make("select", "json-device-selector");
      select.setAttribute("aria-label", "Sélectionner un équipement");
      documents.forEach((document, idx) => {
        const option = make("option", "", document.file);
        option.value = String(idx);
        select.append(option);
      });
      select.value = String(index);
      select.addEventListener("change", () => {
        selectedDeviceIndex = Number(select.value);
        renderTab();
      });
      actions.append(select);
    } else {
      addText(actions, "span", "json-filename", entry.file);
    }
    const copy = make("button", "json-copy-button", "Copier le JSON");
    copy.type = "button";
    copy.addEventListener("click", () => {
      if (!navigator.clipboard?.writeText) {
        toast("Copie indisponible : utilisez le téléchargement JSON.");
        return;
      }
      navigator.clipboard.writeText(JSON.stringify(parsed ? entry.parsed : entry.ir, null, 2))
        .then(() => toast("JSON copié dans le presse-papiers."))
        .catch(() => toast("Copie impossible : utilisez le téléchargement JSON."));
    });
    actions.append(copy);
    toolbar.append(actions);
    parent.append(toolbar);
    addText(parent, "p", "json-description", parsed
      ? (lastResult.vendor === "juniper_junos"
          ? "Extraction Junos depuis l'arbre du parseur : interfaces et adresses, routes, OSPF, BGP, VRF, politiques, filtrage et NAT. Vue structurée expurgée, distincte de l'IR : aucun secret ni commande brute."
          : "Commandes IOS reconnues et champs extraits par le parseur. Vue filtrée : secrets et lignes brutes non affichés.")
      : "Données normalisées au format IR par le moteur existant, avec sémantique et limites propres au constructeur.");
    const block = make("pre", "json-pre");
    renderSyntaxJSON(block, parsed ? entry.parsed : entry.ir);
    parent.append(block);
  }

  async function loadStructuredData(kind) {
    if (!detailCache[kind]) {
      const runId = lastResult.run_id;
      const response = await fetch(`/api/view/${encodeURIComponent(runId)}/${kind}`, { credentials: "same-origin" });
      if (!response.ok) throw new Error(`Erreur HTTP ${response.status}`);
      const data = await response.json();
      if (lastResult.run_id === runId) detailCache[kind] = data;
      return data;
    }
    return detailCache[kind];
  }

  async function renderJsonTab(parent, kind, sequence) {
    addText(parent, "p", "empty-state", "Chargement du JSON structuré…");
    try {
      const data = await loadStructuredData(kind);
      if (sequence !== viewSequence) return;
      parent.replaceChildren();
      renderStructuredJSON(parent, data, kind);
    } catch (error) {
      if (sequence !== viewSequence) return;
      parent.replaceChildren();
      addText(parent, "p", "empty-state", "Aperçu momentanément indisponible. Téléchargez le JSON via les boutons du rapport.");
    }
  }

  async function renderOverview(parent, sequence) {
    addText(parent, "p", "empty-state", "Préparation de la vue complète : parsing, IR et rapport…");
    try {
      const [parsing, ir] = await Promise.all([loadStructuredData("parsing"), loadStructuredData("ir")]);
      if (sequence !== viewSequence) return;
      parent.replaceChildren();
      addText(parent, "p", "overview-intro", "Résultats du fichier importé : parsing structuré, représentation intermédiaire IR et bilan HTML du constructeur sélectionné.");
      const grid = make("div", "overview-grid");
      const left = make("section", "overview-column");
      const right = make("section", "overview-column");
      renderStructuredJSON(left, parsing, "parsing");
      renderStructuredJSON(right, ir, "ir");
      grid.append(left, right);
      parent.append(grid);
      const report = make("section", "overview-report");
      renderReportPreview(report);
      parent.append(report);
    } catch (error) {
      if (sequence !== viewSequence) return;
      parent.replaceChildren();
      addText(parent, "p", "empty-state", "Chargement incomplet : consultez les onglets séparés ou téléchargez les rapports.");
    }
  }

  function renderReportPreview(parent) {
    const heading = make("div", "report-preview-heading");
    const left = make("div");
    addText(left, "span", "json-kicker", "ÉTAPE 04 · RESTITUTION");
    addText(left, "h3", "", "Bilan technique HTML");
    heading.append(left);
    const link = make("a", "json-copy-button", "Ouvrir le rapport");
    link.href = lastResult.downloads.html;
    link.setAttribute("download", "");
    heading.append(link);
    parent.append(heading);
    addText(parent, "p", "json-description", "Aperçu du bilan : interfaces, adresses IP, protocoles, fonctionnalités, configurations structurées et observations statiques.");
    const frame = make("iframe", "report-frame");
    frame.title = "Aperçu du rapport HTML généré";
    frame.loading = "lazy";
    frame.setAttribute("sandbox", "allow-same-origin");
    frame.src = `/api/view/${encodeURIComponent(lastResult.run_id)}/html`;
    parent.append(frame);
  }

  function renderTab() {
    if (!lastResult) return;
    const sequence = ++viewSequence;
    document.querySelectorAll(".result-tab").forEach((tab) => {
      const active = tab.dataset.tab === activeTab;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", String(active));
    });
    const view = el("resultView");
    view.replaceChildren();
    if (activeTab === "overview") renderOverview(view, sequence);
    else if (activeTab === "devices") renderDevices(view);
    else if (activeTab === "findings") renderFindings(view);
    else if (activeTab === "coverage") renderCoverage(view);
    else if (activeTab === "parsing" || activeTab === "normalization") {
      renderJsonTab(view, activeTab === "parsing" ? "parsing" : "ir", sequence);
    } else if (activeTab === "report") renderReportPreview(view);
  }

  document.querySelectorAll(".result-tab").forEach((tab) => {
    tab.addEventListener("click", () => { activeTab = tab.dataset.tab; renderTab(); });
  });

  function renderResult(payload, submittedFiles) {
    lastResult = payload;
    detailCache = {};
    selectedDeviceIndex = 0;
    selectedSeverity = "all";
    activeTab = "overview";
    el("results").classList.remove("is-hidden");
    el("navResultCount").textContent = counted(payload.metrics.devices);
    el("reportTimestamp").textContent = `Rapport généré le ${payload.generated_at} · Analyse de configuration hors ligne`;
    el("downloadSummary").href = payload.downloads.summary;
    el("downloadParsing").href = payload.downloads.parsing;
    el("downloadIR").href = payload.downloads.ir;
    el("downloadHTML").href = payload.downloads.html;
    const stats = el("resultKpis");
    stats.replaceChildren(
      metric("Équipements", payload.metrics.devices, "good"),
      metric("Interfaces", payload.metrics.interfaces),
      metric("Alertes statiques", payload.metrics.warnings, "warning"),
      metric(payload.vendor === "juniper_junos" ? "Feuilles encore non modélisées (union IR)" : "Commandes opaques",
        payload.metrics.unknowns, payload.metrics.unknowns ? "warning" : "good")
    );
    renderTab();
    if (payload.file_errors?.length) {
      toast(`${payload.file_errors.length} fichier(s) ignoré(s) : format ou dialecte non pris en charge.`);
    } else {
      toast(`Analyse terminée : ${payload.metrics.devices} équipement(s) étudié(s).`);
    }
    // Passer les File d'origine à l'étape CIS sans deuxième import ni stockage.
    // Le module CIS ne retient que les équipements effectivement acceptés ici.
    window.dispatchEvent(new CustomEvent("netaudit:analysis-ready", {
      detail: {
        vendor: payload.vendor,
        runId: payload.run_id,
        devices: payload.devices.map((device) => ({ file: device.file, hostname: device.hostname })),
        files: submittedFiles,
        downloads: payload.downloads,
        htmlPreview: `/api/view/${encodeURIComponent(payload.run_id)}/html`,
      },
    }));
    el("results").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  el("analyzeBtn").addEventListener("click", async () => {
    if (!chosen.length) return;
    const button = el("analyzeBtn");
    const submittedFiles = chosen.slice();
    button.disabled = true;
    button.classList.add("loading");
    feedback("Analyse en cours : parsing, normalisation IR et génération du rapport...", true);
    const body = new FormData();
    body.append("vendor", vendorSelect.value);
    submittedFiles.forEach((file) => body.append("files", file, file.name));
    try {
      const reply = await fetch("/api/analyze", {
        method: "POST", body, credentials: "same-origin", headers: { "X-CSRF-Token": csrf }
      });
      const payload = await reply.json();
      if (!reply.ok || !payload.ok) {
        const details = payload.file_errors?.length ? ` (${payload.file_errors.length} fichier(s) refusé(s))` : "";
        throw new Error(`${payload.error || `Erreur HTTP ${reply.status}`}${details}`);
      }
      feedback(`Analyse réussie pour ${payload.metrics.devices} configuration(s).`, true);
      renderResult(payload, submittedFiles);
    } catch (error) {
      feedback(error.message || "Impossible de terminer l'analyse.");
      toast("Analyse interrompue. Vérifiez le format des fichiers.");
    } finally {
      button.disabled = chosen.length === 0;
      button.classList.remove("loading");
    }
  });
})();
