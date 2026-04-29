// Renders the parsed compose model into a Cytoscape graph.
// Service nodes are blue circles; network nodes are dashed gray circles.
// Edges: depends_on (solid arrow), network membership (dashed line, no arrow).

window.DockerScope = window.DockerScope || {};

let cyInstance = null;

window.DockerScope.renderGraph = function (containerEl, model) {
  const elements = buildElements(model);

  if (cyInstance) {
    cyInstance.destroy();
    cyInstance = null;
  }

  cyInstance = cytoscape({
    container: containerEl,
    elements,
    style: graphStyle(),
    layout: {
      name: "dagre",
      rankDir: "LR",
      nodeSep: 40,
      rankSep: 80,
      animate: false,
      fit: true,
      padding: 40,
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

function buildElements(model) {
  const elements = [];

  for (const svc of model.services) {
    elements.push({
      data: { id: `svc:${svc.name}`, label: svc.name, kind: "service", image: svc.image || "" },
      classes: "service",
    });
  }
  for (const net of model.networks) {
    elements.push({
      data: { id: `net:${net}`, label: net, kind: "network" },
      classes: "network",
    });
  }

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
    for (const net of svc.networks) {
      elements.push({
        data: {
          id: `net-edge:${svc.name}--${net}`,
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
        "background-color": "#2496ed",
        "border-width": 2,
        "border-color": "#1d7fcc",
        "label": "data(label)",
        "color": "#e2e8f0",
        "font-family": "JetBrains Mono, Courier New, monospace",
        "font-size": 12,
        "text-valign": "center",
        "text-halign": "center",
        "text-margin-y": 0,
        "width": 56,
        "height": 56,
        "text-outline-color": "#0f172a",
        "text-outline-width": 2,
      },
    },
    {
      selector: "node.network",
      style: {
        "background-color": "#1e293b",
        "border-width": 2,
        "border-color": "#94a3b8",
        "border-style": "dashed",
        "label": "data(label)",
        "color": "#94a3b8",
        "font-family": "JetBrains Mono, Courier New, monospace",
        "font-size": 11,
        "font-style": "italic",
        "text-valign": "center",
        "text-halign": "center",
        "shape": "round-rectangle",
        "width": 70,
        "height": 32,
      },
    },
    {
      selector: "edge.depends",
      style: {
        "width": 2,
        "line-color": "#2496ed",
        "target-arrow-color": "#2496ed",
        "target-arrow-shape": "triangle",
        "curve-style": "bezier",
      },
    },
    {
      selector: "edge.network-edge",
      style: {
        "width": 1.5,
        "line-color": "#94a3b8",
        "line-style": "dashed",
        "target-arrow-shape": "none",
        "curve-style": "bezier",
        "opacity": 0.7,
      },
    },
  ];
}
