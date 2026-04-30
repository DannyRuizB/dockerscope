// Wires UI: load sample, analyze, render graph, render ports.
(function () {
  const POPOUT_STORAGE_KEY = "_dockerscope_popout_yaml";

  const SAMPLES = {
    basic: ["samples/example.yml"],                              // first one becomes main
    extends: ["samples/extends-main.yml", "samples/extends-base.yml"],
    include: ["samples/include-main.yml", "samples/include-services.yml", "samples/include-proxy.yml"],
  };

  // fileMap holds every uploaded/loaded YAML by basename so the parser can
  // resolve `extends.file` references. The "main" YAML is whatever's currently
  // in the textarea; fileMap is the bag of side files (and also includes the
  // main itself, indexed by its basename when known).
  const fileMap = new Map();
  let mainBasename = null;

  const $input = document.getElementById("compose-input");
  const $analyze = document.getElementById("analyze");
  const $loadSample = document.getElementById("load-sample");
  const $sampleMenu = document.getElementById("sample-menu");
  const $upload = document.getElementById("upload");
  const $fileInput = document.getElementById("file-input");
  const $dropOverlay = document.getElementById("drop-overlay");
  const $filesLoaded = document.getElementById("files-loaded");
  const $graph = document.getElementById("graph");
  const $ports = document.getElementById("ports");
  const $lint = document.getElementById("lint");
  const $lintSummary = document.getElementById("lint-summary");
  const $lintToggle = document.getElementById("lint-toggle");
  const $popoutGraph = document.getElementById("popout-graph");
  const $exportToggle = document.getElementById("export-toggle");
  const $exportMenu = document.getElementById("export-menu");
  const $error = document.getElementById("parse-error");

  $analyze.addEventListener("click", run);
  $loadSample.addEventListener("click", toggleSampleMenu);
  $sampleMenu.addEventListener("click", onSampleItemClick);
  document.addEventListener("click", maybeCloseSampleMenu);
  $upload.addEventListener("click", () => $fileInput.click());
  $fileInput.addEventListener("change", onFilePicked);
  $filesLoaded.addEventListener("click", onFileChipClick);
  $lintToggle.addEventListener("click", toggleLint);
  $popoutGraph.addEventListener("click", popoutGraph);
  $exportToggle.addEventListener("click", toggleExportMenu);
  $exportMenu.addEventListener("click", onExportItemClick);
  document.addEventListener("click", maybeCloseExportMenu);

  // Run popout mode (if invoked via ?popout=graph) before anything else so the
  // page renders in fullscreen-graph layout from the start.
  maybeRunPopoutMode();

  // Analyze on Ctrl/Cmd+Enter inside the textarea
  $input.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      run();
    }
  });

  setupDragAndDrop();

  function toggleLint() {
    const collapsed = $lint.classList.toggle("collapsed");
    $lintToggle.setAttribute("aria-expanded", collapsed ? "false" : "true");
    $lintToggle.textContent = collapsed ? "▸" : "▾";
  }

  function toggleExportMenu(e) {
    e.stopPropagation();
    const open = $exportMenu.hasAttribute("hidden");
    if (open) {
      $exportMenu.removeAttribute("hidden");
      $exportToggle.setAttribute("aria-expanded", "true");
    } else {
      $exportMenu.setAttribute("hidden", "");
      $exportToggle.setAttribute("aria-expanded", "false");
    }
  }

  function maybeCloseExportMenu(e) {
    if ($exportMenu.contains(e.target) || e.target === $exportToggle) return;
    $exportMenu.setAttribute("hidden", "");
    $exportToggle.setAttribute("aria-expanded", "false");
  }

  async function onExportItemClick(e) {
    const btn = e.target.closest("button[data-format]");
    if (!btn) return;
    const format = btn.dataset.format;
    $exportMenu.setAttribute("hidden", "");
    $exportToggle.setAttribute("aria-expanded", "false");
    const cy = window.DockerScope.getCy();
    if (!cy) {
      showError("Nothing to export — analyze a compose file first.");
      return;
    }
    try {
      if (format === "png") await downloadPng(cy);
      else if (format === "svg") await downloadSvg(cy);
    } catch (err) {
      showError("Export failed: " + (err && err.message ? err.message : err));
    }
  }

  async function downloadPng(cy) {
    const blob = await cy.png({
      output: "blob-promise",
      bg: "#0f172a",
      full: true,
      scale: 2,
    });
    triggerDownload(blob, "dockerscope-graph.png");
  }

  async function downloadSvg(cy) {
    if (typeof cy.svg !== "function") {
      throw new Error("SVG plugin not loaded.");
    }
    const svgString = cy.svg({ scale: 1, full: true, bg: "#0f172a" });
    const blob = new Blob([svgString], { type: "image/svg+xml;charset=utf-8" });
    triggerDownload(blob, "dockerscope-graph.svg");
  }

  function triggerDownload(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function popoutGraph() {
    const yaml = $input.value.trim();
    if (!yaml) {
      showError("Nothing to pop out — paste or load a compose file first.");
      return;
    }
    try {
      localStorage.setItem(POPOUT_STORAGE_KEY, yaml);
      // Stash fileMap too so the popout window can resolve `extends`.
      const fileMapObj = {};
      for (const [k, v] of fileMap) fileMapObj[k] = v;
      localStorage.setItem(POPOUT_STORAGE_KEY + "_files", JSON.stringify(fileMapObj));
      localStorage.setItem(POPOUT_STORAGE_KEY + "_main", mainBasename || "");
    } catch (err) {
      showError("Could not stash the YAML for the new window: " + err.message);
      return;
    }
    const features = "popup=yes,width=1200,height=800";
    const win = window.open("?popout=graph", "_blank", features);
    if (!win) {
      showError("The browser blocked the pop-out window. Allow pop-ups for this site and try again.");
    }
  }

  function maybeRunPopoutMode() {
    const params = new URLSearchParams(location.search);
    if (params.get("popout") !== "graph") return;
    document.body.classList.add("popout-graph");
    document.title = "DockerScope — graph";
    let yaml;
    try {
      yaml = localStorage.getItem(POPOUT_STORAGE_KEY);
      localStorage.removeItem(POPOUT_STORAGE_KEY);
      const filesJson = localStorage.getItem(POPOUT_STORAGE_KEY + "_files");
      localStorage.removeItem(POPOUT_STORAGE_KEY + "_files");
      if (filesJson) {
        const obj = JSON.parse(filesJson);
        for (const [k, v] of Object.entries(obj)) fileMap.set(k, v);
      }
      const main = localStorage.getItem(POPOUT_STORAGE_KEY + "_main");
      localStorage.removeItem(POPOUT_STORAGE_KEY + "_main");
      if (main) mainBasename = main;
    } catch (_) { yaml = null; }
    if (!yaml) {
      $graph.innerHTML = '<div style="padding:24px;color:#94a3b8;font-family:system-ui">No data found in storage. Open the graph from the main window using the ↗ button.</div>';
      return;
    }
    $input.value = yaml;
    run();
  }

  function onFilePicked(e) {
    const files = e.target.files;
    if (files && files.length > 0) loadFiles(Array.from(files));
    e.target.value = "";
  }

  // Reads N files, registers each one in fileMap by basename, and uses the
  // first one as the main (drops it into the textarea, runs analyze).
  function loadFiles(files) {
    if (!files || files.length === 0) return;
    let firstReadDone = false;
    let pending = files.length;
    let firstError = null;

    const onAllDone = () => {
      renderFilesLoaded();
      if (firstError) showError(firstError);
      run();
    };

    files.forEach((file, idx) => {
      if (!/\.(ya?ml)$/i.test(file.name) && !/ya?ml/.test(file.type)) {
        firstError = firstError || `"${file.name}" doesn't look like a YAML file. Loading anyway.`;
      }
      const reader = new FileReader();
      reader.onload = () => {
        const basename = file.name;
        fileMap.set(basename, reader.result);
        if (idx === 0) {
          mainBasename = basename;
          $input.value = reader.result;
          firstReadDone = true;
        }
        if (--pending === 0) onAllDone();
      };
      reader.onerror = () => {
        firstError = firstError || `Could not read "${file.name}".`;
        if (--pending === 0) onAllDone();
      };
      reader.readAsText(file);
    });
  }

  function renderFilesLoaded() {
    if (fileMap.size === 0) {
      $filesLoaded.setAttribute("hidden", "");
      $filesLoaded.innerHTML = "";
      return;
    }
    $filesLoaded.removeAttribute("hidden");
    const chips = [];
    for (const name of fileMap.keys()) {
      const isMain = name === mainBasename;
      chips.push(`
        <span class="file-chip ${isMain ? "main" : ""}" data-name="${escapeHtml(name)}" title="${isMain ? "main file" : "click to make main"}">
          ${escapeHtml(name)}${isMain ? " · main" : ""}
          <span class="x" data-action="remove" title="Remove">✕</span>
        </span>
      `);
    }
    $filesLoaded.innerHTML = chips.join("");
  }

  function onFileChipClick(e) {
    const chip = e.target.closest(".file-chip");
    if (!chip) return;
    const name = chip.dataset.name;
    if (!name) return;
    if (e.target.dataset.action === "remove") {
      fileMap.delete(name);
      if (mainBasename === name) {
        mainBasename = fileMap.size > 0 ? fileMap.keys().next().value : null;
        if (mainBasename) $input.value = fileMap.get(mainBasename) || "";
        else $input.value = "";
      }
      renderFilesLoaded();
      run();
      return;
    }
    // Click on chip body → make this file the main
    if (mainBasename === name) return;
    mainBasename = name;
    $input.value = fileMap.get(name) || "";
    renderFilesLoaded();
    run();
  }

  function pathBasename(p) {
    return String(p).split(/[\\/]/).pop();
  }

  function setupDragAndDrop() {
    let depth = 0;
    const showOverlay = () => { $dropOverlay.hidden = false; };
    const hideOverlay = () => { $dropOverlay.hidden = true; };

    window.addEventListener("dragenter", (e) => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      depth++;
      showOverlay();
    });
    window.addEventListener("dragover", (e) => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = "copy";
    });
    window.addEventListener("dragleave", (e) => {
      if (!hasFiles(e)) return;
      depth = Math.max(0, depth - 1);
      if (depth === 0) hideOverlay();
    });
    window.addEventListener("drop", (e) => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      depth = 0;
      hideOverlay();
      const files = e.dataTransfer.files && Array.from(e.dataTransfer.files);
      if (files && files.length > 0) loadFiles(files);
    });
  }

  function hasFiles(e) {
    return e.dataTransfer && Array.from(e.dataTransfer.types || []).includes("Files");
  }

  function toggleSampleMenu(e) {
    e.stopPropagation();
    const open = $sampleMenu.hasAttribute("hidden");
    if (open) {
      $sampleMenu.removeAttribute("hidden");
      $loadSample.setAttribute("aria-expanded", "true");
    } else {
      $sampleMenu.setAttribute("hidden", "");
      $loadSample.setAttribute("aria-expanded", "false");
    }
  }

  function maybeCloseSampleMenu(e) {
    if ($sampleMenu.contains(e.target) || e.target === $loadSample) return;
    $sampleMenu.setAttribute("hidden", "");
    $loadSample.setAttribute("aria-expanded", "false");
  }

  async function onSampleItemClick(e) {
    const btn = e.target.closest("button[data-sample]");
    if (!btn) return;
    $sampleMenu.setAttribute("hidden", "");
    $loadSample.setAttribute("aria-expanded", "false");
    const key = btn.dataset.sample;
    const paths = SAMPLES[key];
    if (!paths) return;
    try {
      // Reset fileMap so a sample load starts clean
      fileMap.clear();
      mainBasename = null;
      let mainText = null;
      for (let i = 0; i < paths.length; i++) {
        const path = paths[i];
        const res = await fetch(path);
        if (!res.ok) throw new Error(`Sample not reachable (HTTP ${res.status}): ${path}. Open the page via a local server.`);
        const text = await res.text();
        const basename = pathBasename(path);
        fileMap.set(basename, text);
        if (i === 0) {
          mainBasename = basename;
          mainText = text;
        }
      }
      $input.value = mainText;
      renderFilesLoaded();
      run();
    } catch (err) {
      showError(err.message);
    }
  }

  function run() {
    clearError();
    const text = $input.value.trim();
    if (!text) {
      $ports.innerHTML = '<span class="ports-empty">Paste a compose file to analyze.</span>';
      $lint.innerHTML = '<span class="lint-empty">Analyze a compose file to see lint findings.</span>';
      $lintSummary.textContent = "";
      $graph.innerHTML = "";
      return;
    }
    // Sync the textarea content into fileMap under the main basename so the
    // user can edit the main YAML inline and re-analyze without re-uploading.
    if (mainBasename) fileMap.set(mainBasename, text);
    let model;
    try {
      model = window.DockerScope.parseCompose(text, fileMap);
    } catch (err) {
      showError(err.message);
      return;
    }
    if (model.warnings.length) {
      showError("Warnings:\n" + model.warnings.join("\n"));
    }
    const lint = window.DockerScope.lint(model);
    const worstByService = window.DockerScope.worstLevelByService(lint.findings);
    window.DockerScope.renderGraph($graph, model, worstByService);
    renderLint($lint, $lintSummary, lint, model);
    renderPorts($ports, model);
  }

  function renderLint(container, summaryEl, lint, model) {
    const total = lint.summary.error + lint.summary.warn;
    if (total === 0) {
      summaryEl.textContent = "✓ All checks passed";
      summaryEl.className = "lint-summary ok";
      container.classList.add("lint-empty");
      container.innerHTML = '<span class="lint-empty">No lint findings — this compose file looks clean.</span>';
      return;
    }
    const parts = [];
    if (lint.summary.error) parts.push(`✗ ${lint.summary.error} ${pluralize(lint.summary.error, "error")}`);
    if (lint.summary.warn) parts.push(`⚠ ${lint.summary.warn} ${pluralize(lint.summary.warn, "warning")}`);
    summaryEl.textContent = parts.join(" · ");
    summaryEl.className = "lint-summary " + (lint.summary.error ? "has-error" : "has-warn");
    container.classList.remove("lint-empty");

    // Group by service in the order services appear in the compose.
    const byService = new Map();
    for (const svc of model.services) byService.set(svc.name, []);
    for (const f of lint.findings) {
      if (!byService.has(f.service)) byService.set(f.service, []);
      byService.get(f.service).push(f);
    }

    const html = [];
    for (const [name, findings] of byService) {
      if (findings.length === 0) continue;
      // Sort: errors first, then warns
      findings.sort((a, b) => (a.level === "error" ? 0 : 1) - (b.level === "error" ? 0 : 1));
      html.push(`
        <div class="lint-group">
          <h3>${escapeHtml(name)}</h3>
          <ul>
            ${findings.map(f => `
              <li class="lint-${f.level}">
                <span class="icon">${f.level === "error" ? "✗" : "⚠"}</span>
                <div class="body">
                  <div class="msg">${renderInlineCode(f.message)}</div>
                  ${f.hint ? `<div class="hint">${renderInlineCode(f.hint)}</div>` : ""}
                  <code class="rule">${escapeHtml(f.rule)}</code>
                </div>
              </li>
            `).join("")}
          </ul>
        </div>
      `);
    }
    container.innerHTML = html.join("");
  }

  function pluralize(n, word) {
    return n === 1 ? word : word + "s";
  }

  function renderPorts(container, model) {
    const withPorts = model.services.filter(s => s.ports.length > 0);
    if (withPorts.length === 0) {
      container.innerHTML = '<span class="ports-empty">No ports exposed in this compose file.</span>';
      container.classList.add("ports-empty");
      return;
    }
    container.classList.remove("ports-empty");
    const html = withPorts.map(svc => {
      const items = svc.ports.map(p => formatPort(p)).join("");
      return `
        <div class="port-group">
          <h3>${escapeHtml(svc.name)}</h3>
          <ul>${items}</ul>
        </div>
      `;
    }).join("");
    container.innerHTML = html;
  }

  function formatPort(p) {
    const host = p.host_ip ? `${p.host_ip}:` : "";
    const left = p.published != null ? `${host}${p.published}` : "(internal)";
    const right = p.target != null ? p.target : "?";
    const proto = p.protocol && p.protocol !== "tcp" ? `<span class="proto">${escapeHtml(p.protocol)}</span>` : "";
    return `<li>${escapeHtml(left)}<span class="arrow">→</span>${escapeHtml(String(right))}${proto}</li>`;
  }

  function showError(msg) {
    $error.hidden = false;
    $error.textContent = msg;
  }

  function clearError() {
    $error.hidden = true;
    $error.textContent = "";
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[c]));
  }

  function renderInlineCode(s) {
    // Escape first so user-supplied content can never close a tag, then turn
    // `markdown-style` backticks into <code> spans.
    return escapeHtml(s).replace(/`([^`]+)`/g, "<code>$1</code>");
  }
})();
