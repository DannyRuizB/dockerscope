// Renders the parsed compose model into a Cytoscape graph.
// Service nodes are blue circles; network nodes are dashed gray circles.
// Edges: depends_on (solid arrow), network membership (dashed line, no arrow).

window.DockerScope = window.DockerScope || {};

// fcose may need explicit registration; svg auto-registers on load.
if (typeof cytoscape !== "undefined" && typeof cytoscapeFcose !== "undefined" && !window.__fcoseRegistered) {
  try { cytoscape.use(cytoscapeFcose); } catch (_) { /* already registered */ }
  window.__fcoseRegistered = true;
}
// grid-guide draws alignment lines while dragging a node.
if (typeof cytoscape !== "undefined" && typeof cytoscapeGridGuide !== "undefined" && !window.__gridGuideRegistered) {
  try { cytoscape.use(cytoscapeGridGuide); } catch (_) { /* already registered */ }
  window.__gridGuideRegistered = true;
}

// Computes a node width proportional to its label, with a sensible minimum.
// Replaces `"width": "label"` which is deprecated in Cytoscape 3.30+.
function widthFromLabel(min) {
  return (ele) => {
    const label = (ele.data("label") || "");
    return Math.max(min, label.length * 7 + 18);
  };
}

let cyInstance = null;

// Exposes the current Cytoscape instance for download/export. Returns null if
// no graph has been rendered yet.
window.DockerScope.getCy = function () {
  return cyInstance;
};

window.DockerScope.renderGraph = function (containerEl, model, lintByService) {
  const elements = buildElements(model, lintByService || {});


  if (cyInstance) {
    cyInstance.destroy();
    cyInstance = null;
  }

  cyInstance = cytoscape({
    container: containerEl,
    elements,
    style: graphStyle(),
    layout: {
      name: "fcose",
      animate: false,
      fit: true,
      padding: 40,
      nodeSeparation: 80,
      idealEdgeLength: 90,
      nodeRepulsion: 8000,
      tilingPaddingVertical: 14,
      tilingPaddingHorizontal: 14,
      nestingFactor: 1.2,
      randomize: true,
      quality: "default",
    },
    minZoom: 0.3,
    maxZoom: 1.5,
    wheelSensitivity: 0.2,
  });

  // Re-fit with padding and clamp zoom so single-node graphs don't blow up.
  cyInstance.ready(() => {
    cyInstance.fit(undefined, 60);
    if (cyInstance.zoom() > 1.5) cyInstance.zoom(1.5);
    cyInstance.center();
  });

  // Alignment guidelines — appear while dragging a node, no snap to grid.
  if (typeof cyInstance.gridGuide === "function") {
    cyInstance.gridGuide({
      snapToGridOnRelease: false,
      snapToGridDuringDrag: false,
      snapToAlignmentLocationOnRelease: false,
      snapToAlignmentLocationDuringDrag: false,
      distributionGuidelines: true,
      geometricGuideline: true,
      initPosAlignment: true,
      centerToEdgeAlignment: true,
      drawGrid: false,
      resize: false,
      parentPadding: false,
      guidelinesStackOrder: 4,
      guidelinesTolerance: 4,
      guidelinesStyle: {
        strokeStyle: "#3b82f6",
        geometricGuidelineRange: 600,
        range: 200,
        minDistRange: 10,
        distGuidelineOffset: 10,
        horizontalDistColor: "#94a3b8",
        verticalDistColor: "#94a3b8",
        initPosAlignmentColor: "#a16207",
        lineDash: [4, 3],
        horizontalDistLine: [0, 0],
        verticalDistLine: [0, 0],
        initPosAlignmentLine: [2, 2],
      },
    });
  }

  // Move every currently-selected node together with the one being dragged.
  // Cytoscape's default only moves the grabbed node, which makes "select all
  // then drag" feel broken — so we capture the offset and apply it to peers.
  let dragState = null;
  cyInstance.on("grab", "node", (evt) => {
    const grabbed = evt.target;
    const peers = cyInstance.nodes(":selected").filter(n => n.id() !== grabbed.id());
    if (peers.length === 0) { dragState = null; return; }
    dragState = {
      grabbedId: grabbed.id(),
      origin: { x: grabbed.position("x"), y: grabbed.position("y") },
      peers: peers.map(n => ({ node: n, start: { x: n.position("x"), y: n.position("y") } })),
    };
  });
  cyInstance.on("drag", "node", (evt) => {
    if (!dragState || evt.target.id() !== dragState.grabbedId) return;
    const cur = evt.target.position();
    const dx = cur.x - dragState.origin.x;
    const dy = cur.y - dragState.origin.y;
    for (const p of dragState.peers) {
      p.node.position({ x: p.start.x + dx, y: p.start.y + dy });
    }
  });
  cyInstance.on("free", "node", () => { dragState = null; });
};

function buildElements(model, lintByService) {
  const elements = [];

  // Each service's "primary" network is the first one declared. The service
  // becomes a child of that network (compound node containment). Extra networks
  // are drawn as dashed edges so multi-network membership isn't lost.
  const primaryNetworkOf = new Map();
  for (const svc of model.services) {
    if (svc.networks.length > 0) primaryNetworkOf.set(svc.name, svc.networks[0]);
  }
  const networksUsedAsPrimary = new Set([...primaryNetworkOf.values()]);

  // 1. Network nodes. A network referenced as primary becomes a compound (it
  //    will visually contain its services). A network only used as secondary
  //    (or declared at top-level but unused as primary) is a regular node.
  for (const net of model.networks) {
    const isCompound = networksUsedAsPrimary.has(net);
    elements.push({
      data: { id: `net:${net}`, label: net, kind: "network" },
      classes: isCompound ? "network compound" : "network standalone",
    });
  }

  // 2. Service nodes — child of their primary network when applicable.
  for (const svc of model.services) {
    const lintLevel = lintByService[svc.name];
    const classes = ["service"];
    if (lintLevel === "error") classes.push("lint-error");
    else if (lintLevel === "warn") classes.push("lint-warn");
    const data = {
      id: `svc:${svc.name}`,
      label: svc.name,
      kind: "service",
      image: svc.image || "",
    };
    const primary = primaryNetworkOf.get(svc.name);
    if (primary) data.parent = `net:${primary}`;
    elements.push({ data, classes: classes.join(" ") });
  }

  // 3. depends_on edges
  const knownServices = new Set(model.services.map((s) => s.name));
  for (const svc of model.services) {
    for (const dep of svc.depends_on) {
      // A dangling depends_on (the linter flags it as depends-on-unknown)
      // must not take the graph down with it: Cytoscape throws on edges
      // whose target node doesn't exist.
      if (!knownServices.has(dep)) continue;
      elements.push({
        data: {
          id: `dep:${svc.name}->${dep}`,
          source: `svc:${svc.name}`,
          target: `svc:${dep}`,
          kind: "depends",
        },
        classes: "depends",
      });
    }
  }

  // 4. Extra-network edges: only for the 2nd, 3rd... networks of a service.
  //    The 1st network is already represented by compound containment.
  for (const svc of model.services) {
    if (svc.networks.length <= 1) continue;
    const extras = svc.networks.slice(1);
    for (const net of extras) {
      elements.push({
        data: {
          id: `xnet:${svc.name}--${net}`,
          source: `svc:${svc.name}`,
          target: `net:${net}`,
          kind: "network",
        },
        classes: "network-edge",
      });
    }
  }

  // 5. Volume nodes — one per unique named volume actually used and one per
  //    unique bind-mount source path. Anonymous and tmpfs volumes are skipped
  //    in v0.4 (less common, would clutter the graph).
  //
  // Bind paths can contain "/", ".", ":" — all of which can break Cytoscape
  // selector parsing if they appear in node IDs. We assign opaque short IDs
  // (`vol_0`, `bind_0`, ...) and keep the human path in the label only.
  const usedNamed = new Set();
  const usedBind = new Set();
  for (const svc of model.services) {
    for (const v of svc.volumes) {
      if (v.type === "named" && v.source) usedNamed.add(v.source);
      else if (v.type === "bind" && v.source) usedBind.add(v.source);
    }
  }
  const namedIds = new Map();
  let namedIdx = 0;
  for (const name of usedNamed) {
    const id = `vol_${namedIdx++}`;
    namedIds.set(name, id);
    elements.push({
      data: { id, label: name, kind: "volume" },
      classes: "volume named",
    });
  }
  const bindIds = new Map();
  let bindIdx = 0;
  for (const path of usedBind) {
    const id = `bind_${bindIdx++}`;
    bindIds.set(path, id);
    elements.push({
      data: { id, label: path, kind: "bind" },
      classes: "volume bind",
    });
  }

  // 6. Mount edges: service → volume node, label = target path (+ "ro" flag).
  let mountIdx = 0;
  for (const svc of model.services) {
    for (const v of svc.volumes) {
      if (!v.source) continue;
      let targetId = null;
      if (v.type === "named") targetId = namedIds.get(v.source);
      else if (v.type === "bind") targetId = bindIds.get(v.source);
      if (!targetId) continue;
      const label = (v.target || "") + (v.readonly ? "  (ro)" : "");
      const classes = ["mount-edge"];
      if (v.readonly) classes.push("readonly");
      elements.push({
        data: {
          id: `mnt_${mountIdx++}`,
          source: `svc:${svc.name}`,
          target: targetId,
          kind: "mount",
          label,
        },
        classes: classes.join(" "),
      });
    }
  }

  return elements;
}

function graphStyle() {
  return [
    {
      selector: "node.service",
      style: {
        "background-color": "#1e293b",
        "border-width": 2,
        "border-color": "#2496ed",
        "label": "data(label)",
        "color": "#e2e8f0",
        "font-family": "JetBrains Mono, Courier New, monospace",
        "font-size": 11,
        "font-weight": 500,
        "text-valign": "center",
        "text-halign": "center",
        "shape": "round-rectangle",
        "width": widthFromLabel(60),
        "height": 32,
        "padding": "10px",
        "text-outline-width": 0,
      },
    },
    {
      selector: "node.service.lint-warn",
      style: {
        "border-width": 2.5,
        "border-color": "#f59e0b",
      },
    },
    {
      selector: "node.service.lint-error",
      style: {
        "border-width": 2.5,
        "border-color": "#ef4444",
      },
    },
    {
      selector: "node.network.compound",
      style: {
        "background-color": "#1e293b",
        "background-opacity": 0.35,
        "border-width": 1.5,
        "border-color": "#475569",
        "border-style": "dashed",
        "label": "data(label)",
        "color": "#94a3b8",
        "font-family": "JetBrains Mono, Courier New, monospace",
        "font-size": 11,
        "font-style": "italic",
        "text-valign": "top",
        "text-halign": "left",
        "text-margin-x": 12,
        "text-margin-y": 6,
        "shape": "round-rectangle",
        "padding": "24px",
        "compound-sizing-wrt-labels": "include",
      },
    },
    {
      selector: "node.network.standalone",
      style: {
        "background-color": "#0f172a",
        "background-opacity": 0.6,
        "border-width": 1.5,
        "border-color": "#475569",
        "border-style": "dashed",
        "label": "data(label)",
        "color": "#64748b",
        "font-family": "JetBrains Mono, Courier New, monospace",
        "font-size": 10,
        "font-style": "italic",
        "text-valign": "center",
        "text-halign": "center",
        "shape": "round-rectangle",
        "width": widthFromLabel(60),
        "height": 24,
        "padding": "8px",
      },
    },
    {
      selector: "edge.depends",
      style: {
        "width": 1.5,
        "line-color": "#3b82f6",
        "target-arrow-color": "#3b82f6",
        "target-arrow-shape": "triangle",
        "arrow-scale": 0.9,
        "curve-style": "bezier",
      },
    },
    {
      selector: "edge.network-edge",
      style: {
        "width": 1,
        "line-color": "#475569",
        "line-style": "dashed",
        "target-arrow-shape": "none",
        "curve-style": "bezier",
        "opacity": 0.55,
      },
    },
    {
      selector: "node.volume.named",
      style: {
        "background-color": "#334155",
        "border-width": 1.5,
        "border-color": "#64748b",
        "label": "data(label)",
        "color": "#cbd5e1",
        "font-family": "JetBrains Mono, Courier New, monospace",
        "font-size": 10,
        "text-valign": "center",
        "text-halign": "center",
        "shape": "barrel",
        "width": widthFromLabel(60),
        "height": 32,
        "padding": "8px",
      },
    },
    {
      selector: "node.volume.bind",
      style: {
        "background-color": "#1e293b",
        "border-width": 1.5,
        "border-color": "#a16207",
        "label": "data(label)",
        "color": "#fde68a",
        "font-family": "JetBrains Mono, Courier New, monospace",
        "font-size": 9,
        "text-valign": "center",
        "text-halign": "center",
        "shape": "round-tag",
        "width": widthFromLabel(60),
        "height": 28,
        "padding": "6px",
      },
    },
    {
      selector: "edge.mount-edge",
      style: {
        "width": 1,
        "line-color": "#64748b",
        "target-arrow-shape": "none",
        "curve-style": "bezier",
        "opacity": 0.7,
        "label": "data(label)",
        "color": "#94a3b8",
        "font-size": 9,
        "font-family": "JetBrains Mono, Courier New, monospace",
        "text-margin-y": -8,
        "text-background-color": "#0f172a",
        "text-background-opacity": 0.85,
        "text-background-padding": 2,
      },
    },
    {
      selector: "edge.mount-edge.readonly",
      style: {
        "line-style": "dashed",
      },
    },
  ];
}
