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
    window.DockerScope.renderGraph($graph, model);
    renderPorts($ports, model);
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
})();
