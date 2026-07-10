// Static linter for compose models.
// Input:  parsed model from parser.js
// Output: { findings: [{service, level, rule, message, hint?}], summary: {error, warn, ok} }
//
// Levels:
//   "error" — likely security or correctness problem (e.g. plaintext secrets)
//   "warn"  — operational best practice (e.g. floating tag, missing healthcheck)
//
// Rules are pure functions of one service (and optionally the model). Adding a
// new rule is one entry in the RULES array.

window.DockerScope = window.DockerScope || {};

const SECRET_KEY_PATTERN = /(PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)/i;

// Matches an interpolation reference like ${VAR} or $VAR (treated as "value comes
// from outside the file" — not flagged as a literal secret).
const INTERPOLATION_PATTERN = /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/;

function ruleImageLatest(svc) {
  if (!svc.image || svc.image === "(build)") return [];
  const m = svc.image.match(/^(.+?):([^:]+)$/);
  const tag = m ? m[2] : null;
  if (tag === null) {
    return [{
      level: "warn",
      rule: "image-untagged",
      message: `image \`${svc.image}\` has no tag — Docker pulls \`latest\`.`,
      hint: "Pin to a specific version (e.g. `nginx:1.27`) for reproducible builds.",
    }];
  }
  if (tag === "latest") {
    return [{
      level: "warn",
      rule: "image-latest",
      message: `image \`${svc.image}\` uses the floating \`latest\` tag.`,
      hint: "Pin to a specific version for reproducible builds.",
    }];
  }
  return [];
}

function ruleEnvSecrets(svc) {
  const findings = [];
  for (const { key, value } of svc.environment) {
    if (!SECRET_KEY_PATTERN.test(key)) continue;
    if (value == null) continue; // pass-through (`KEY` without `=`) — the value lives in the host env, not the file.
    if (INTERPOLATION_PATTERN.test(value)) continue; // ${SECRET_FROM_HOST} — value is interpolated, not literal.
    findings.push({
      level: "error",
      rule: "env-secret",
      message: `\`${key}\` is set to a literal value in \`environment\`.`,
      hint: "Move secrets to a `.env` file referenced via `${VAR}` or to Docker secrets — never commit them.",
    });
  }
  return findings;
}

// Images that almost never want to be reachable from outside the host.
// nginx, traefik, caddy, etc. are intentionally public, so they're excluded.
const SENSITIVE_IMAGE_PATTERN = /(postgres|mysql|mariadb|mongo|mongodb|redis|memcached|elastic|rabbitmq|kafka|etcd|cassandra|influxdb|clickhouse)/i;

function rulePortPublic(svc) {
  if (!svc.image || !SENSITIVE_IMAGE_PATTERN.test(svc.image)) return [];
  const findings = [];
  for (const p of svc.ports) {
    if (p.published == null) continue; // not published, only exposed inside the network
    if (p.host_ip && p.host_ip !== "0.0.0.0") continue; // restricted to a specific interface
    findings.push({
      level: "warn",
      rule: "port-public",
      message: `port \`${p.published}\` of a database/cache image is published on all interfaces (0.0.0.0).`,
      hint: "Bind to `127.0.0.1:` so only the host can reach it, or remove the published port and rely on the internal network.",
    });
  }
  return findings;
}

function ruleNoRestart(svc) {
  if (svc.restart) return [];
  return [{
    level: "warn",
    rule: "no-restart",
    message: "no `restart` policy set.",
    hint: "Add `restart: unless-stopped` (or `always`) so the container survives reboots and crashes.",
  }];
}

function ruleNoHealthcheck(svc) {
  if (svc.healthcheck) return [];
  return [{
    level: "warn",
    rule: "no-healthcheck",
    message: "no `healthcheck` configured.",
    hint: "Add a `healthcheck` so Docker can detect unresponsive services and `depends_on: condition: service_healthy` works.",
  }];
}

// Mounting the Docker socket hands the container full control of the daemon —
// which is root on the host. It's the single most dangerous line in a compose
// file, so it's flagged even though it's occasionally intentional (Traefik,
// Portainer): those should mount it read-only and be on a trusted network.
function ruleDockerSocket(svc) {
  const findings = [];
  for (const v of svc.volumes) {
    const src = String(v.source || "");
    if (!/(^|\/)docker\.sock$/.test(src)) continue;
    findings.push({
      level: "error",
      rule: "docker-socket-mount",
      message: `mounts the Docker socket (\`${src}\`)${v.readonly ? " (read-only)" : ""}.`,
      hint: "This grants full control of the host's Docker daemon (root-equivalent). Avoid it; if a tool truly needs it, mount `:ro` and use a socket proxy.",
    });
  }
  return findings;
}

// `privileged: true` disables almost all of Docker's isolation (all caps, all
// devices) — a container escape becomes trivial.
function rulePrivileged(svc) {
  if (!svc.privileged) return [];
  return [{
    level: "error",
    rule: "privileged",
    message: "runs in `privileged` mode.",
    hint: "Drop `privileged` and grant only the specific `cap_add` / `devices` the service needs.",
  }];
}

// Sharing the host's network / PID / IPC namespace removes the isolation that
// makes a container a container.
function ruleHostNamespace(svc) {
  const findings = [];
  const ns = [
    ["network_mode", svc.networkMode],
    ["pid", svc.pidMode],
    ["ipc", svc.ipcMode],
  ];
  for (const [field, value] of ns) {
    if (value !== "host") continue;
    findings.push({
      level: "warn",
      rule: "host-namespace",
      message: `uses \`${field}: host\` — shares the host's ${field === "network_mode" ? "network" : field} namespace.`,
      hint: "Prefer the default isolated namespace; publish only the ports you need instead of sharing the host stack.",
    });
  }
  return findings;
}

// Capabilities that, added back, largely defeat the point of dropping root.
const DANGEROUS_CAPS = new Set([
  "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE",
  "SYS_RAWIO", "DAC_READ_SEARCH", "ALL",
]);
function ruleDangerousCaps(svc) {
  const findings = [];
  for (const cap of svc.capAdd) {
    const name = cap.replace(/^CAP_/, "");
    if (!DANGEROUS_CAPS.has(name)) continue;
    findings.push({
      level: name === "ALL" || name === "SYS_ADMIN" ? "error" : "warn",
      rule: "dangerous-cap",
      message: `adds the dangerous capability \`${cap}\`.`,
      hint: "Grant the narrowest capability that works; `SYS_ADMIN` / `ALL` are close to `privileged`.",
    });
  }
  return findings;
}

const RULES = [
  ruleImageLatest,
  ruleEnvSecrets,
  rulePortPublic,
  ruleNoRestart,
  ruleNoHealthcheck,
  ruleDockerSocket,
  rulePrivileged,
  ruleHostNamespace,
  ruleDangerousCaps,
];

window.DockerScope.lint = function (model) {
  const findings = [];
  for (const svc of model.services) {
    for (const rule of RULES) {
      const out = rule(svc, model);
      for (const f of out) {
        findings.push({ service: svc.name, ...f });
      }
    }
  }
  const summary = {
    error: findings.filter(f => f.level === "error").length,
    warn: findings.filter(f => f.level === "warn").length,
  };
  return { findings, summary };
};

// Returns the worst level across findings for a given service ("error" > "warn" > null).
window.DockerScope.worstLevelByService = function (findings) {
  const map = {};
  for (const f of findings) {
    if (f.level === "error") map[f.service] = "error";
    else if (f.level === "warn" && map[f.service] !== "error") map[f.service] = "warn";
  }
  return map;
};
