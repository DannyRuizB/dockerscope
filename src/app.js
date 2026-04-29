// Wires UI: load sample, analyze, render graph, render ports.
(function () {
  const SAMPLE_PATH = "samples/example.yml";

  const $input = document.getElementById("compose-input");
  const $analyze = document.getElementById("analyze");
  const $loadSample = document.getElementById("load-sample");
  const $upload = document.getElementById("upload");
  const $fileInput = document.getElementById("file-input");
  const $dropOverlay = document.getElementById("drop-overlay");
  const $graph = document.getElementById("graph");
  const $ports = document.getElementById("ports");
  const $lint = document.getElementById("lint");
  const $lintSummary = document.getElementById("lint-summary");
  const $error = document.getElementById("parse-error");

  $analyze.addEventListener("click", run);
  $loadSample.addEventListener("click", loadSample);
  $upload.addEventListener("click", () => $fileInput.click());
  $fileInput.addEventListener("change", onFilePicked);

  // Analyze on Ctrl/Cmd+Enter inside the textarea
  $input.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      run();
    }
  });

  setupDragAndDrop();

  function onFilePicked(e) {
    const file = e.target.files && e.target.files[0];
    if (file) loadFile(file);
    e.target.value = "";
  }

  function loadFile(file) {
    if (!/\.(ya?ml)$/i.test(file.name) && !/ya?ml/.test(file.type)) {
      showError(`"${file.name}" doesn't look like a YAML file. Loading anyway.`);
    }
    const reader = new FileReader();
    reader.onload = () => {
      $input.value = reader.result;
      run();
    };
    reader.onerror = () => showError(`Could not read "${file.name}".`);
    reader.readAsText(file);
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
      const file = e.dataTransfer.files && e.dataTransfer.files[0];
      if (file) loadFile(file);
    });
  }

  function hasFiles(e) {
    return e.dataTransfer && Array.from(e.dataTransfer.types || []).includes("Files");
  }

  async function loadSample() {
    try {
      const res = await fetch(SAMPLE_PATH);
      if (!res.ok) throw new Error(`Sample not reachable (HTTP ${res.status}). Open the page via a local server.`);
      $input.value = await res.text();
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
    let model;
    try {
      model = window.DockerScope.parseCompose(text);
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
