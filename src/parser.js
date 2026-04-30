// Parses a docker-compose.yml string into a normalized model.
// Output:
// {
//   services: [{
//     name, image, depends_on, networks, ports,
//     environment: [{key, value}],   // value is null for `KEY=` and for interpolation refs like ${X}
//     restart: string|null,
//     healthcheck: object|null,
//     volumes: [{type, source, target, readonly}],  // type: "named" | "bind" | "anonymous"
//   }],
//   networks: [string],
//   namedVolumes: [string],         // volumes used by services + declared at top level
//   warnings: [string]
// }

window.DockerScope = window.DockerScope || {};

// fileMap is an optional Map<basenameOfYamlFile, yamlString> used to resolve
// `extends.file` references. If omitted or empty, extends.file references emit
// a warning and the child service keeps its own (non-merged) properties.
window.DockerScope.parseCompose = function (yamlText, fileMap) {
  const warnings = [];
  fileMap = fileMap || new Map();
  let doc;
  try {
    doc = jsyaml.load(yamlText);
  } catch (err) {
    throw new Error("YAML parse error: " + err.message);
  }
  if (!doc || typeof doc !== "object") {
    throw new Error("Empty or invalid compose file.");
  }

  // Pre-pass: resolve every service's `extends` chain into a flat object so the
  // rest of the parser doesn't need to know about extends at all.
  if (doc.services && typeof doc.services === "object") {
    const flat = {};
    for (const [name, svc] of Object.entries(doc.services)) {
      flat[name] = resolveServiceExtends(svc, name, doc.services, fileMap, warnings, 0);
    }
    doc.services = flat;
  }

  const services = [];
  const rawServices = doc.services || {};
  if (typeof rawServices !== "object") {
    throw new Error("`services` must be a mapping.");
  }

  // Resolve top-level volume names first so per-service short-form entries can
  // tell named volumes apart from bind mounts and anonymous volumes.
  const topVolumes = doc.volumes && typeof doc.volumes === "object"
    ? Object.keys(doc.volumes)
    : [];
  const topVolumeSet = new Set(topVolumes);

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
      environment: parseEnvironment(raw.environment),
      restart: typeof raw.restart === "string" ? raw.restart : null,
      healthcheck: raw.healthcheck && typeof raw.healthcheck === "object" ? raw.healthcheck : null,
      volumes: parseVolumes(raw.volumes, topVolumeSet, warnings, name),
    });
  }

  const topNetworks = doc.networks && typeof doc.networks === "object"
    ? Object.keys(doc.networks)
    : [];

  // Collect all networks referenced by services that aren't declared at top level.
  const referenced = new Set();
  services.forEach(s => s.networks.forEach(n => referenced.add(n)));
  const allNetworks = Array.from(new Set([...topNetworks, ...referenced]));

  // Named volumes: top-level + any implicit ones referenced by services.
  const usedNamed = new Set();
  for (const svc of services) {
    for (const v of svc.volumes) {
      if (v.type === "named" && v.source) usedNamed.add(v.source);
    }
  }
  const allNamedVolumes = Array.from(new Set([...topVolumes, ...usedNamed]));

  return { services, networks: allNetworks, namedVolumes: allNamedVolumes, warnings };
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

// Accepts short and long form volume entries.
//
// Short form (string):
//   "/in/container"                    → anonymous (target only)
//   "src:/in/container"                → bind or named (depending on src shape / topVolumeSet)
//   "src:/in/container:ro"             → with options (ro flag detected)
//
// Long form (object):
//   { type: "bind"|"volume"|"tmpfs", source: "...", target: "...", read_only: true }
//
// `type` in the output is normalised to: "named", "bind", "anonymous", or "tmpfs".
function parseVolumes(value, topVolumeSet, warnings, serviceName) {
  if (!value) return [];
  if (!Array.isArray(value)) {
    warnings.push(`Service "${serviceName}": volumes must be a list.`);
    return [];
  }
  const out = [];
  for (const entry of value) {
    const parsed = parseSingleVolume(entry, topVolumeSet);
    if (parsed) out.push(parsed);
    else warnings.push(`Service "${serviceName}": could not parse volume entry ${JSON.stringify(entry)}.`);
  }
  return out;
}

function parseSingleVolume(entry, topVolumeSet) {
  if (typeof entry === "string") {
    const parts = entry.split(":");
    if (parts.length === 1) {
      return { type: "anonymous", source: null, target: parts[0], readonly: false };
    }
    let source, target, opts;
    if (parts.length === 2) {
      source = parts[0];
      target = parts[1];
      opts = "";
    } else {
      // 3+ parts: take last as opts, rest as source+target. Doesn't try to
      // handle Windows drive letters (compose docs say use forward slashes).
      source = parts[0];
      target = parts[1];
      opts = parts.slice(2).join(":");
    }
    const readonly = /(^|,)ro(,|$)/.test(opts);
    const type = isHostPath(source)
      ? "bind"
      : "named"; // named (declared at top-level OR implicit — both treated the same visually)
    return { type, source, target, readonly };
  }
  if (entry && typeof entry === "object") {
    let type = "bind";
    if (entry.type === "volume") type = "named";
    else if (entry.type === "tmpfs") type = "tmpfs";
    else if (entry.type === "bind" || !entry.type) type = "bind";
    return {
      type,
      source: entry.source != null ? String(entry.source) : null,
      target: entry.target != null ? String(entry.target) : null,
      readonly: !!entry.read_only,
    };
  }
  return null;
}

function isHostPath(s) {
  if (!s) return false;
  return s.startsWith(".") || s.startsWith("/") || s.startsWith("~") || /^[a-zA-Z]:[/\\]/.test(s);
}

// Resolves `extends` for a single service, recursively. Returns the merged
// service object with `extends` removed. Loops or chains > 5 are detected and
// the chain is cut with a warning.
//
// Extends shapes supported:
//   extends: "other-service"                          (same file, short form)
//   extends: { service: "other-service" }             (same file, long form)
//   extends: { file: "base.yml", service: "..." }     (other file, looked up
//                                                       in fileMap by basename)
function resolveServiceExtends(svc, name, sameDocServices, fileMap, warnings, depth) {
  if (!svc || typeof svc !== "object" || svc.extends == null) return svc;
  if (depth > 5) {
    warnings.push(`Service "${name}": extends chain too deep (loop?). Stopping at depth ${depth}.`);
    return stripExtends(svc);
  }

  let baseSvc = null;
  if (typeof svc.extends === "string") {
    baseSvc = sameDocServices[svc.extends];
    if (!baseSvc) {
      warnings.push(`Service "${name}": extends "${svc.extends}" not found in this file.`);
      return stripExtends(svc);
    }
    baseSvc = resolveServiceExtends(baseSvc, svc.extends, sameDocServices, fileMap, warnings, depth + 1);
  } else if (typeof svc.extends === "object") {
    const targetService = svc.extends.service;
    const targetFile = svc.extends.file;
    if (!targetService) {
      warnings.push(`Service "${name}": extends.service is required.`);
      return stripExtends(svc);
    }
    if (targetFile) {
      const basename = pathBasename(targetFile);
      const fileContent = fileMap.get(basename);
      if (!fileContent) {
        warnings.push(`Service "${name}": extends file "${targetFile}" not found among uploaded files (looking for "${basename}"). Upload it together with the main compose to resolve the merge.`);
        return stripExtends(svc);
      }
      let baseDoc;
      try {
        baseDoc = jsyaml.load(fileContent);
      } catch (err) {
        warnings.push(`Service "${name}": failed to parse extends file "${targetFile}": ${err.message}`);
        return stripExtends(svc);
      }
      const baseSvcMap = (baseDoc && baseDoc.services) || {};
      baseSvc = baseSvcMap[targetService];
      if (!baseSvc) {
        warnings.push(`Service "${name}": service "${targetService}" not found in "${targetFile}".`);
        return stripExtends(svc);
      }
      baseSvc = resolveServiceExtends(baseSvc, targetService, baseSvcMap, fileMap, warnings, depth + 1);
    } else {
      baseSvc = sameDocServices[targetService];
      if (!baseSvc) {
        warnings.push(`Service "${name}": extends "${targetService}" not found in this file.`);
        return stripExtends(svc);
      }
      baseSvc = resolveServiceExtends(baseSvc, targetService, sameDocServices, fileMap, warnings, depth + 1);
    }
  } else {
    return stripExtends(svc);
  }

  return mergeService(baseSvc, stripExtends(svc));
}

function stripExtends(svc) {
  if (!svc || typeof svc !== "object") return svc;
  const { extends: _drop, ...rest } = svc;
  return rest;
}

function pathBasename(p) {
  if (!p) return p;
  return String(p).split(/[\\/]/).pop();
}

// Compose's merge convention for a service that extends another:
// - Mapping-like fields (environment, labels, healthcheck, deploy.resources):
//   shallow merge, child keys override.
// - Array-like fields (volumes, ports, depends_on, networks list-form, command
//   words): the child appends to the parent.
// - Scalars (image, restart, container_name, ...): child overrides parent.
// - If parent and child have incompatible shapes for the same key (one array,
//   the other mapping), child wins.
function mergeService(parent, child) {
  if (!parent) return child;
  if (!child) return parent;
  const merged = { ...parent };
  for (const [key, val] of Object.entries(child)) {
    const pv = parent[key];
    if (pv == null) {
      merged[key] = val;
    } else if (Array.isArray(pv) && Array.isArray(val)) {
      merged[key] = [...pv, ...val];
    } else if (
      typeof pv === "object" && !Array.isArray(pv) &&
      typeof val === "object" && !Array.isArray(val)
    ) {
      merged[key] = { ...pv, ...val };
    } else {
      merged[key] = val;
    }
  }
  return merged;
}

// Accepts:
//   { KEY: "value", FLAG: true, NUM: 42 }   → mapping
//   ["KEY=value", "KEY", "KEY=${REF}"]      → list (KEY without = means "pass-through from host", value=null)
function parseEnvironment(value) {
  if (!value) return [];
  if (Array.isArray(value)) {
    return value.map(item => {
      if (typeof item !== "string") return null;
      const eq = item.indexOf("=");
      if (eq === -1) return { key: item, value: null };
      return { key: item.slice(0, eq), value: item.slice(eq + 1) };
    }).filter(Boolean);
  }
  if (typeof value === "object") {
    return Object.entries(value).map(([key, v]) => ({
      key,
      value: v == null ? null : String(v),
    }));
  }
  return [];
}
