// Wires UI: load sample, analyze, render graph, render ports.
(function () {
  const POPOUT_STORAGE_KEY = "_dockerscope_popout_yaml";

  const SAMPLES = {
    basic: ["samples/example.yml"],                              // first one becomes main
    extends: ["samples/extends-main.yml", "samples/extends-base.yml"],
    include: ["samples/include-main.yml", "samples/include-services.yml", "samples/include-proxy.yml"],
    dockerfile: ["samples/dockerfile-main.yml", "samples/api.Dockerfile", "samples/worker.Dockerfile"],
  };

  const YAML_RE = /\.(ya?ml)$/i;
  const DOCKERFILE_RE = /(^|[\\/])Dockerfile($|[._-])|\.Dockerfile$/i;

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
  const $dockerfiles = document.getElementById("dockerfiles");
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

  // Reads N files, registers each one in fileMap by basename. The first file
  // that looks like a YAML compose becomes the new main (drops into textarea).
  // Dockerfiles are kept in fileMap but never become main.
  function loadFiles(files) {
    if (!files || files.length === 0) return;
    let pending = files.length;
    let firstError = null;
    const firstYamlIdx = files.findIndex(f => YAML_RE.test(f.name) || /ya?ml/.test(f.type || ""));

    const onAllDone = () => {
      renderFilesLoaded();
      if (firstError) showError(firstError);
      run();
    };

    files.forEach((file, idx) => {
      const isYaml = YAML_RE.test(file.name) || /ya?ml/.test(file.type || "");
      const isDockerfile = DOCKERFILE_RE.test(file.name);
      if (!isYaml && !isDockerfile) {
        firstError = firstError || `"${file.name}" doesn't look like a YAML or Dockerfile. Loading anyway.`;
      }
      const reader = new FileReader();
      reader.onload = () => {
        const basename = file.name;
        fileMap.set(basename, reader.result);
        if (idx === firstYamlIdx) {
          mainBasename = basename;
          $input.value = reader.result;
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
      const isDockerfile = DOCKERFILE_RE.test(name);
      const cls = ["file-chip", isMain ? "main" : "", isDockerfile ? "dockerfile" : ""].filter(Boolean).join(" ");
      const title = isDockerfile
        ? "Dockerfile (linked from a service's build directive)"
        : (isMain ? "main file" : "click to make main");
      chips.push(`
        <span class="${cls}" data-name="${escapeHtml(name)}" title="${title}">
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
        // Pick the next YAML in fileMap as the new main, if any
        mainBasename = null;
        for (const k of fileMap.keys()) {
          if (YAML_RE.test(k)) { mainBasename = k; break; }
        }
        $input.value = mainBasename ? (fileMap.get(mainBasename) || "") : "";
      }
      renderFilesLoaded();
      run();
      return;
    }
    // Click on chip body → make this file the main, but only if it's a YAML
    if (!YAML_RE.test(name)) return;
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
      for (const path of paths) {
        const res = await fetch(path);
        if (!res.ok) throw new Error(`Sample not reachable (HTTP ${res.status}): ${path}. Open the page via a local server.`);
        const text = await res.text();
        const basename = pathBasename(path);
        fileMap.set(basename, text);
        if (mainBasename === null && YAML_RE.test(basename)) {
          mainBasename = basename;
          mainText = text;
        }
      }
      $input.value = mainText || "";
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
      $dockerfiles.innerHTML = '<span class="dockerfiles-empty">Upload a Dockerfile alongside the compose to inspect it here.</span>';
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
    renderDockerfiles($dockerfiles, model);
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

  function renderDockerfiles(container, model) {
    const withDf = model.services.filter(s => s.dockerfile && s.dockerfile.finalStage);
    if (withDf.length === 0) {
      container.classList.add("dockerfiles-empty");
      container.innerHTML = '<span class="dockerfiles-empty">Upload a Dockerfile alongside the compose to inspect it here.</span>';
      return;
    }
    container.classList.remove("dockerfiles-empty");
    const html = withDf.map(svc => {
      const df = svc.dockerfile;
      const final = df.finalStage;
      const rows = [];
      rows.push(row("Base image",
        `<code>${escapeHtml(final.from)}</code>` +
        (final.name ? ` <span class="stage-tag">stage <code>${escapeHtml(final.name)}</code></span>` : "")
      ));
      if (df.multiStage) {
        const chain = df.stages.map(s =>
          `<code>${escapeHtml(s.from)}${s.name ? " AS " + escapeHtml(s.name) : ""}</code>`
        ).join(' <span class="arrow">→</span> ');
        rows.push(row("Stages", chain));
      }
      if (final.workdir) rows.push(row("WORKDIR", `<code>${escapeHtml(final.workdir)}</code>`));
      if (final.user) rows.push(row("USER", `<code>${escapeHtml(final.user)}</code>`));
      if (final.expose.length) {
        rows.push(row("EXPOSE", final.expose.map(p => `<code>${escapeHtml(p)}</code>`).join(" ")));
      }
      if (final.env.length) {
        rows.push(row("ENV", final.env.map(e =>
          `<code>${escapeHtml(e.key)}=${escapeHtml(e.value == null ? "" : String(e.value))}</code>`
        ).join(" ")));
      }
      if (final.entrypoint) rows.push(row("ENTRYPOINT", formatExecOrShell(final.entrypoint)));
      if (final.cmd) rows.push(row("CMD", formatExecOrShell(final.cmd)));
      const badge = df.multiStage ? ' <span class="badge">multi-stage</span>' : "";
      return `
        <div class="dockerfile-group">
          <h3>${escapeHtml(svc.name)}${badge}</h3>
          <dl>${rows.join("")}</dl>
        </div>
      `;
    }).join("");
    container.innerHTML = html;
  }

  function row(label, valueHtml) {
    return `<dt>${escapeHtml(label)}</dt><dd>${valueHtml}</dd>`;
  }

  function formatExecOrShell(c) {
    if (c.exec) return `<code>${escapeHtml(JSON.stringify(c.exec))}</code>`;
    if (c.shell) return `<code>${escapeHtml(c.shell)}</code>`;
    return "";
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
