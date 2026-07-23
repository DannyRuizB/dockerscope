// Parses a docker-compose.yml string into a normalized model.
// Output:
// {
//   services: [{
//     name, image, depends_on, networks, ports,
//     dependsOnConditions: {dep: string|null}, // long-form `condition` per dependency; null = none given (short form)
//     environment: [{key, value}],   // value is null for `KEY=` and for interpolation refs like ${X}
//     restart: string|null,
//     healthcheck: object|null,
//     volumes: [{type, source, target, readonly}],  // type: "named" | "bind" | "anonymous"
//     privileged: boolean,
//     capAdd: [string],               // upper-cased Linux capabilities from cap_add
//     networkMode: string|null,       // e.g. "host"
//     pidMode: string|null, ipcMode: string|null,  // e.g. "host"
//     securityOpt: [string],          // raw security_opt entries, e.g. "no-new-privileges:true"
//     buildArgs: [{key, value}],      // build.args normalized like environment
//     command: string|null, entrypoint: string|null,  // space-joined if exec-form list
//   }],
//   networks: [string],
//   namedVolumes: [string],         // volumes used by services + declared at top level
//   warnings: [string]
// }

window.DockerScope = window.DockerScope || {};

// fileMap is an optional Map<basenameOfYamlFile, yamlString> used to resolve
// `extends.file` and `include:` references. If omitted or empty, those
// references emit warnings and resolution is skipped.
window.DockerScope.parseCompose = function (yamlText, fileMap) {
  const warnings = [];
  fileMap = fileMap || new Map();
  let doc;
  try {
    doc = jsyaml.load(yamlText);
  } catch (err) {
    throw new Error("YAML parse error: " + err.message, { cause: err });
  }
  if (!doc || typeof doc !== "object") {
    throw new Error("Empty or invalid compose file.");
  }

  // Pre-pre-pass: resolve `include:` first so the rest of the pipeline sees a
  // single merged compose. Each included file is parsed and layered under the
  // caller (caller wins on name collisions, matching Compose semantics).
  doc = resolveIncludes(doc, fileMap, warnings, 0);

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
    const dockerfile = resolveDockerfile(raw.build, fileMap, warnings, name);
    services.push({
      name,
      image: raw.image || raw.build ? (raw.image || "(build)") : null,
      depends_on: parseDependsOn(raw.depends_on),
      dependsOnConditions: parseDependsOnConditions(raw.depends_on),
      networks: parseServiceNetworks(raw.networks),
      ports: parsePorts(raw.ports, warnings, name),
      environment: parseEnvironment(raw.environment),
      restart: typeof raw.restart === "string" ? raw.restart : null,
      containerName: typeof raw.container_name === "string" ? raw.container_name : null,
      // deploy.replicas, falling back to the legacy service-level `scale`.
      // Only plain numbers are kept — interpolations stay null.
      replicas: parseReplicas(raw),
      // Memory limit: modern `deploy.resources.limits.memory`, falling back
      // to the legacy service-level `mem_limit`. Kept as the raw string
      // ("512M"); numeric byte values are stringified.
      memoryLimit: parseMemoryLimit(raw),
      // PID cap: modern `deploy.resources.limits.pids` (integer), falling
      // back to the legacy service-level `pids_limit`.
      pidsLimit: parsePidsLimit(raw),
      // Log rotation: the driver name (null = compose default, json-file)
      // and the max-size option, if any — what no-log-limit judges.
      logDriver: parseLogDriver(raw),
      logMaxSize: parseLogMaxSize(raw),
      healthcheck: raw.healthcheck && typeof raw.healthcheck === "object" ? raw.healthcheck : null,
      volumes: parseVolumes(raw.volumes, topVolumeSet, warnings, name),
      privileged: raw.privileged === true,
      readOnly: raw.read_only === true,
      capAdd: parseCapAdd(raw.cap_add),
      capDrop: parseCapAdd(raw.cap_drop),
      networkMode: typeof raw.network_mode === "string" ? raw.network_mode : null,
      pidMode: typeof raw.pid === "string" ? raw.pid : null,
      ipcMode: typeof raw.ipc === "string" ? raw.ipc : null,
      securityOpt: Array.isArray(raw.security_opt) ? raw.security_opt.map(String) : [],
      // command / entrypoint accept a string or an exec-form list; normalize
      // both to one space-joined string — the linter only scans, never runs.
      command: normalizeCommand(raw.command),
      entrypoint: normalizeCommand(raw.entrypoint),
      // build.args accepts the same two shapes as environment (list of
      // "KEY=value" strings, or a mapping) — reuse the same normalizer.
      buildArgs: parseEnvironment(
        raw.build && typeof raw.build === "object" ? raw.build.args : null
      ),
      dockerfile,
      stack: resolveStack(name, dockerfile, fileMap, warnings),
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

  return {
    services,
    networks: allNetworks,
    namedVolumes: allNamedVolumes,
    // The declared-only sets (no implicit additions) — the linter needs the
    // distinction to flag references Compose would reject as undefined.
    declaredNetworks: topNetworks,
    declaredVolumes: topVolumes,
    warnings,
  };
};

function parseReplicas(raw) {
  const v = raw.deploy && typeof raw.deploy === "object" && raw.deploy.replicas != null
    ? raw.deploy.replicas
    : raw.scale;
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && /^\d+$/.test(v)) return Number(v);
  return null;
}

function parseLogDriver(raw) {
  const logging = raw.logging && typeof raw.logging === "object" ? raw.logging : null;
  return logging && typeof logging.driver === "string" ? logging.driver : null;
}

function parseLogMaxSize(raw) {
  const logging = raw.logging && typeof raw.logging === "object" ? raw.logging : null;
  const options = logging && logging.options && typeof logging.options === "object"
    ? logging.options : null;
  const v = options ? options["max-size"] : null;
  if (typeof v === "string" && v.trim()) return v.trim();
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  return null;
}

function parsePidsLimit(raw) {
  const deploy = raw.deploy && typeof raw.deploy === "object" ? raw.deploy : null;
  const resources = deploy && deploy.resources && typeof deploy.resources === "object"
    ? deploy.resources : null;
  const limits = resources && resources.limits && typeof resources.limits === "object"
    ? resources.limits : null;
  const v = limits && limits.pids != null ? limits.pids : raw.pids_limit;
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && /^\d+$/.test(v.trim())) return Number(v.trim());
  return null;
}

function parseMemoryLimit(raw) {
  const deploy = raw.deploy && typeof raw.deploy === "object" ? raw.deploy : null;
  const resources = deploy && deploy.resources && typeof deploy.resources === "object"
    ? deploy.resources : null;
  const limits = resources && resources.limits && typeof resources.limits === "object"
    ? resources.limits : null;
  const v = limits && limits.memory != null ? limits.memory : raw.mem_limit;
  if (typeof v === "string" && v.trim() !== "") return v.trim();
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  return null;
}

function parseDependsOn(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.map(String);
  if (typeof value === "object") return Object.keys(value);
  return [];
}

// command / entrypoint: string form stays as-is, exec-form list joins with
// spaces, anything else (absent, mapping garbage) becomes null.
function normalizeCommand(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(String).join(" ");
  return null;
}

// The long form of depends_on carries a per-dependency `condition`; the short
// (list) form carries none. Kept beside the flat name list so consumers that
// only need edges keep using depends_on. null = no condition given (short
// form or an empty long-form entry), which Compose treats as service_started.
function parseDependsOnConditions(value) {
  const conditions = {};
  if (Array.isArray(value)) {
    for (const name of value) conditions[String(name)] = null;
  } else if (value && typeof value === "object") {
    for (const [name, spec] of Object.entries(value)) {
      conditions[name] =
        spec && typeof spec === "object" && typeof spec.condition === "string"
          ? spec.condition
          : null;
    }
  }
  return conditions;
}

// `cap_add` / `cap_drop` are YAML lists of Linux capability names. Normalise
// to upper-case strings (compose accepts them with or without the CAP_ prefix).
function parseCapAdd(value) {
  if (!Array.isArray(value)) return [];
  return value.map(v => String(v).toUpperCase());
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

function parseSingleVolume(entry, _topVolumeSet) {
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

  let baseSvc;
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

// Resolves a service's stack from a language manifest file uploaded with the
// service-prefixed name (e.g. `api.package.json`, `worker.requirements.txt`,
// `svc.go.mod`). Silent miss: if no matching manifest is in fileMap, returns
// null without warning. If a Dockerfile is also resolved, its FROM line is
// used as a fallback for the language version when the manifest doesn't
// carry one (package.json / requirements.txt don't; go.mod does).
function resolveStack(serviceName, dockerfile, fileMap, warnings) {
  if (!window.DockerScope.parseManifest) return null;
  const candidates = [
    `${serviceName}.package.json`,
    `${serviceName}.requirements.txt`,
    `${serviceName}.go.mod`,
  ];
  for (const filename of candidates) {
    const text = fileMap.get(filename);
    if (text == null) continue;
    let result;
    try {
      result = window.DockerScope.parseManifest(filename, text);
    } catch (err) {
      warnings.push(`Service "${serviceName}": failed to parse manifest "${filename}": ${err.message}`);
      continue;
    }
    if (!result) continue;
    if (!result.languageVersion && dockerfile && window.DockerScope.languageVersionFromDockerfile) {
      result.languageVersion = window.DockerScope.languageVersionFromDockerfile(dockerfile, result.language);
    }
    result.sourceFile = filename;
    return result;
  }
  return null;
}

// Resolves a service's `build:` directive against the fileMap. Supports:
//   build: ./api                         → looks up "Dockerfile"
//   build: { dockerfile: "x.Dockerfile" } → looks up "x.Dockerfile"
//   build: { context: "./api" }          → looks up "Dockerfile"
// Silent miss: if the Dockerfile basename isn't in fileMap, returns null
// without warning. The build still works in real Docker; the panel just stays
// empty for that service.
function resolveDockerfile(build, fileMap, warnings, serviceName) {
  if (!build) return null;
  let basename = "Dockerfile";
  if (typeof build === "object" && build.dockerfile) {
    basename = pathBasename(String(build.dockerfile));
  } else if (typeof build !== "string" && typeof build !== "object") {
    return null;
  }
  const text = fileMap.get(basename);
  if (!text) return null;
  if (!window.DockerScope.parseDockerfile) {
    warnings.push(`Service "${serviceName}": Dockerfile parser not loaded.`);
    return null;
  }
  try {
    return window.DockerScope.parseDockerfile(text);
  } catch (err) {
    warnings.push(`Service "${serviceName}": failed to parse Dockerfile "${basename}": ${err.message}`);
    return null;
  }
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

// Resolves `include:` (Compose v2.20+) by merging every included file into
// the caller. Each entry can be a string path or `{path, env_file?,
// project_directory?}` — only the path matters, the rest is browser-irrelevant
// and is reported as a warning. Files are looked up by basename in fileMap.
// Recursion is bounded at depth 5.
//
// Merge semantics: included files are layered first (in declaration order), and
// the caller's own content is layered on top — so the caller wins on name
// collisions (services, networks, volumes), matching Compose's rule that the
// file doing the include is the source of truth.
function resolveIncludes(doc, fileMap, warnings, depth) {
  if (!doc || typeof doc !== "object" || doc.include == null) return doc;
  const { include: includes, ...rest } = doc;
  if (depth > 5) {
    warnings.push(`include chain too deep (loop?). Stopping at depth ${depth}.`);
    return rest;
  }
  if (!Array.isArray(includes)) {
    warnings.push("`include` must be a list.");
    return rest;
  }

  let merged = {};
  for (const entry of includes) {
    let path;
    if (typeof entry === "string") {
      path = entry;
    } else if (entry && typeof entry === "object") {
      path = entry.path;
      if (entry.env_file || entry.project_directory) {
        warnings.push(`include "${path || "?"}": env_file/project_directory ignored (DockerScope runs in the browser, no filesystem access).`);
      }
    } else {
      warnings.push(`include: skipped invalid entry ${JSON.stringify(entry)}.`);
      continue;
    }
    if (!path) {
      warnings.push("include: missing path.");
      continue;
    }
    const basename = pathBasename(path);
    const fileContent = fileMap.get(basename);
    if (!fileContent) {
      warnings.push(`include file "${path}" not found among uploaded files (looking for "${basename}"). Upload it together with the main compose to resolve the merge.`);
      continue;
    }
    let includedDoc;
    try {
      includedDoc = jsyaml.load(fileContent);
    } catch (err) {
      warnings.push(`include: failed to parse "${path}": ${err.message}`);
      continue;
    }
    if (!includedDoc || typeof includedDoc !== "object") continue;
    includedDoc = resolveIncludes(includedDoc, fileMap, warnings, depth + 1);
    merged = mergeCompose(merged, includedDoc);
  }

  return mergeCompose(merged, rest);
}

// Top-level merge of two compose docs. Mapping fields (services, networks,
// volumes, configs, secrets) are shallow-merged at the key level — child keys
// override parent keys but the values themselves are not deep-merged. Scalars
// (version, name) → child wins.
function mergeCompose(parent, child) {
  if (!parent || typeof parent !== "object") return child;
  if (!child || typeof child !== "object") return parent;
  const merged = { ...parent };
  for (const [key, val] of Object.entries(child)) {
    const pv = parent[key];
    if (pv == null) {
      merged[key] = val;
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
