// Renders the parsed compose model into a Cytoscape graph.
// Service nodes are blue circles; network nodes are dashed gray circles.
// Edges: depends_on (solid arrow), network membership (dashed line, no arrow).

window.DockerScope = window.DockerScope || {};

// Some UMD builds auto-register, others don't. Register defensively, only once.
if (typeof cytoscape !== "undefined" && typeof cytoscapeFcose !== "undefined" && !window.__fcoseRegistered) {
  try { cytoscape.use(cytoscapeFcose); } catch (_) { /* already registered */ }
  window.__fcoseRegistered = true;
}

let cyInstance = null;

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
  for (const svc of model.services) {
    for (const dep of svc.depends_on) {
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
        "width": "label",
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
        "width": "label",
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
  ];
}
