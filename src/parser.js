// Parses a docker-compose.yml string into a normalized model.
// Output:
// {
//   services: [{ name, image, depends_on: [string], networks: [string], ports: [{published, target, protocol, host_ip}] }],
//   networks: [string],
//   warnings: [string]
// }

window.DockerScope = window.DockerScope || {};

window.DockerScope.parseCompose = function (yamlText) {
  const warnings = [];
  let doc;
  try {
    doc = jsyaml.load(yamlText);
  } catch (err) {
    throw new Error("YAML parse error: " + err.message);
  }
  if (!doc || typeof doc !== "object") {
    throw new Error("Empty or invalid compose file.");
  }

  const services = [];
  const rawServices = doc.services || {};
  if (typeof rawServices !== "object") {
    throw new Error("`services` must be a mapping.");
  }

  for (const [name, raw] of Object.entries(rawServices)) {
    if (!raw || typeof raw !== "object") {
      warnings.push(`Service "${name}" is empty or not an object.`);
      continue;
    }
    services.push({
      name,
      image: raw.image || raw.build ? (raw.image || "(build)") : null,
      depends_on: parseDependsOn(raw.depends_on),
      networks: parseServiceNetworks(raw.networks),
      ports: parsePorts(raw.ports, warnings, name),
    });
  }

  const topNetworks = doc.networks && typeof doc.networks === "object"
    ? Object.keys(doc.networks)
    : [];

  // Collect all networks referenced by services that aren't declared at top level.
  const referenced = new Set();
  services.forEach(s => s.networks.forEach(n => referenced.add(n)));
  const allNetworks = Array.from(new Set([...topNetworks, ...referenced]));

  return { services, networks: allNetworks, warnings };
};

function parseDependsOn(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.map(String);
  if (typeof value === "object") return Object.keys(value);
  return [];
}

function parseServiceNetworks(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.map(String);
  if (typeof value === "object") return Object.keys(value);
  return [];
}

function parsePorts(value, warnings, serviceName) {
  if (!value) return [];
  if (!Array.isArray(value)) {
    warnings.push(`Service "${serviceName}": ports must be a list.`);
    return [];
  }
  const out = [];
  for (const entry of value) {
    const parsed = parseSinglePort(entry);
    if (parsed) out.push(parsed);
    else warnings.push(`Service "${serviceName}": could not parse port entry ${JSON.stringify(entry)}.`);
  }
  return out;
}

// Accepts:
//   "80"               → expose-only
//   "80:80"            → host:container
//   "80:80/tcp"        → with protocol
//   "127.0.0.1:80:80"  → with host IP
//   { target, published, protocol, host_ip }  → long form
function parseSinglePort(entry) {
  if (typeof entry === "number") {
    return { published: null, target: entry, protocol: "tcp", host_ip: null };
  }
  if (typeof entry === "string") {
    let s = entry.trim();
    let protocol = "tcp";
    const slash = s.lastIndexOf("/");
    if (slash !== -1) {
      protocol = s.slice(slash + 1) || "tcp";
      s = s.slice(0, slash);
    }
    const parts = s.split(":");
    if (parts.length === 1) {
      return { published: null, target: toPort(parts[0]), protocol, host_ip: null };
    }
    if (parts.length === 2) {
      return { published: toPort(parts[0]), target: toPort(parts[1]), protocol, host_ip: null };
    }
    if (parts.length === 3) {
      return { host_ip: parts[0], published: toPort(parts[1]), target: toPort(parts[2]), protocol };
    }
    return null;
  }
  if (entry && typeof entry === "object") {
    return {
      published: entry.published != null ? toPort(entry.published) : null,
      target: entry.target != null ? toPort(entry.target) : null,
      protocol: entry.protocol || "tcp",
      host_ip: entry.host_ip || null,
    };
  }
  return null;
}

function toPort(v) {
  if (v == null || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : String(v);
}
