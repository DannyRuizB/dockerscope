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

// A service with no memory cap competes with everything else on the host: one
// leak and the kernel OOM killer starts shooting host-wide — other containers
// and the Docker daemon included. `docker compose` applies
// `deploy.resources.limits` outside Swarm since v2, and the legacy `mem_limit`
// still works; either counts as capped.
function ruleNoMemoryLimit(svc) {
  if (svc.memoryLimit != null) return [];
  return [{
    level: "warn",
    rule: "no-memory-limit",
    message: "no memory limit — a leak here can OOM the whole host.",
    hint: "Set `deploy.resources.limits.memory` (e.g. `512M`) or the legacy `mem_limit`.",
  }];
}

// A container with no PID cap can fill the host's process table: a fork bomb
// (or a runaway worker pool) starves every process on the machine, including
// the ones you'd use to fix it. Either spelling counts as capped:
// `deploy.resources.limits.pids` or the legacy `pids_limit`. Completes the
// resource-caps pair with no-memory-limit — memory kills by OOM, PIDs kill
// by exhaustion.
function ruleNoPidsLimit(svc) {
  if (svc.pidsLimit != null) return [];
  return [{
    level: "warn",
    rule: "no-pids-limit",
    message: "no PID limit — a fork bomb here can exhaust the host's process table.",
    hint: "Set `deploy.resources.limits.pids` (e.g. `256`) or the legacy `pids_limit`.",
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

// Host paths that hand the container the keys to the machine when bind-mounted:
// credentials (/etc, /root, /home), kernel surfaces (/proc, /sys, /dev), the
// boot chain (/boot) and Docker's own state (/var/lib/docker — every other
// container's filesystem). "/" is all of the above at once.
const SENSITIVE_MOUNT_ROOTS = [
  "/", "/etc", "/root", "/home", "/boot", "/proc", "/sys", "/dev",
  "/usr", "/bin", "/sbin", "/lib", "/var/lib/docker",
];

function sensitiveMountRoot(source) {
  // Normalise: strip a trailing slash so "/etc/" matches "/etc".
  const src = source.length > 1 ? source.replace(/\/+$/, "") : source;
  for (const root of SENSITIVE_MOUNT_ROOTS) {
    if (src === root) return root;
    if (root !== "/" && src.startsWith(root + "/")) return root;
  }
  return null;
}

function ruleSensitiveHostMount(svc) {
  const findings = [];
  for (const v of svc.volumes) {
    if (v.type !== "bind" || !v.source) continue;
    if (/(^|\/)docker\.sock$/.test(v.source)) continue; // its own rule, worse than a path
    const root = sensitiveMountRoot(v.source);
    if (!root) continue;
    findings.push({
      level: v.readonly ? "warn" : "error",
      rule: "sensitive-host-mount",
      message: `bind-mounts the sensitive host path \`${v.source}\`${v.readonly ? " (read-only)" : " read-write"}.`,
      hint: v.readonly
        ? `Even read-only, \`${root}\` exposes host secrets/config to the container. Mount the narrowest file or directory the service actually needs.`
        : `A writable mount under \`${root}\` lets the container tamper with the host. Mount \`:ro\`, and only the narrowest path the service actually needs.`,
    });
  }
  return findings;
}

// Added capabilities survive across setuid/sudo binaries unless the kernel is
// told not to elevate: `no-new-privileges` closes that escalation path and is
// close to free for services that don't rely on setuid.
// Docker starts every container with ~14 capabilities the app almost never
// needs (CHOWN, SETUID, NET_RAW, MKNOD…). Least privilege is `cap_drop: [ALL]`
// then `cap_add` only what's required. A container that never drops ALL keeps
// the whole default set — extra kernel surface an escape can reach for.
// Complements dangerous-cap (that one flags risky things *added*; this one
// flags the baseline never being *dropped*). A partial drop is better than
// nothing but still isn't least privilege, so only dropping ALL clears it.
function ruleNoCapDrop(svc) {
  const dropsAll = svc.capDrop.some((c) => c.replace(/^CAP_/, "") === "ALL");
  if (dropsAll) return [];
  return [{
    level: "warn",
    rule: "no-cap-drop",
    message: "keeps Docker's default capabilities — no `cap_drop: [ALL]`.",
    hint: "Add `cap_drop: [\"ALL\"]` and `cap_add` only the capabilities the service actually needs.",
  }];
}

// A writable root filesystem is what turns a foothold into a base of
// operations: a compromised process can drop tooling, patch binaries and
// persist across the exploit session. `read_only: true` makes the image
// content immutable at runtime and costs one line — apps that need scratch
// space keep it via explicit `tmpfs` / volume mounts, which is exactly the
// point: writable paths become an inventory instead of a default. Completes
// the least-privilege trio: no-cap-drop (kernel surface), no-new-privileges
// (escalation), and this one (filesystem). Volumes stay writable — the rule
// judges only the rootfs.
function ruleNoReadOnly(svc) {
  if (svc.readOnly) return [];
  return [{
    level: "warn",
    rule: "no-read-only",
    message: "runs with a writable root filesystem — no `read_only: true`.",
    hint: "Add `read_only: true` and give the service explicit scratch space where needed (`tmpfs: [/tmp]`, or a named volume) — writable paths become a deliberate inventory instead of the default.",
  }];
}

const NO_NEW_PRIVS_PATTERN = /^no-new-privileges(:true|=true)?$/;
function ruleNoNewPrivileges(svc) {
  if (svc.capAdd.length === 0) return [];
  if (svc.securityOpt.some((o) => NO_NEW_PRIVS_PATTERN.test(String(o).trim()))) return [];
  return [{
    level: "warn",
    rule: "no-new-privileges",
    message: "adds capabilities via `cap_add` without `no-new-privileges`.",
    hint: "Add `security_opt: [\"no-new-privileges:true\"]` so setuid binaries inside the container can't escalate beyond the granted capabilities.",
  }];
}

// The default seccomp profile blocks ~44 dangerous syscalls and AppArmor
// confines file / capability access; `unconfined` switches those protections
// off wholesale. Almost every container-escape exploit chain assumes at least
// one of them is disabled — legitimate needs are served by a *custom* profile,
// not by none.
const UNCONFINED_PATTERN = /^(seccomp|apparmor)[:=]unconfined$/;
function ruleSecurityUnconfined(svc) {
  const findings = [];
  for (const opt of svc.securityOpt) {
    const m = String(opt).trim().match(UNCONFINED_PATTERN);
    if (!m) continue;
    findings.push({
      level: "error",
      rule: "security-unconfined",
      message: `disables the ${m[1]} profile (\`${String(opt).trim()}\`).`,
      hint: `Most container escapes assume ${m[1]} is off. If the default profile blocks a syscall the service needs, ship a custom profile that allows just that one instead of \`unconfined\`.`,
    });
  }
  return findings;
}

// Build args are baked into the image: `docker history` prints them to anyone
// who can pull it, and they persist in the layer metadata forever. A secret
// passed this way outlives the build — worse than `environment`, which at
// least stays out of the image itself.
function ruleBuildArgSecret(svc) {
  const findings = [];
  for (const { key, value } of svc.buildArgs) {
    if (!SECRET_KEY_PATTERN.test(key)) continue;
    if (value == null) continue; // pass-through — value lives in the host env
    if (INTERPOLATION_PATTERN.test(value)) continue; // ${VAR} — still hits the image history at build time, but the file itself leaks nothing
    findings.push({
      level: "error",
      rule: "build-arg-secret",
      message: `build arg \`${key}\` carries a literal secret — build args are baked into the image history.`,
      hint: "`docker history <image>` shows build args to anyone who can pull the image. Use a BuildKit secret mount (`RUN --mount=type=secret,...`) instead.",
    });
  }
  return findings;
}

// Two containers can't bind the same host port: `docker compose up` starts the
// first and the second dies with "port is already allocated". A binding with no
// host_ip (or 0.0.0.0) claims the port on every interface, so it also collides
// with any interface-specific binding of the same port/protocol. Only plain
// numeric published ports are compared — ranges and interpolations are skipped.
function bindingsCollide(a, b) {
  if (a.published !== b.published) return false;
  if ((a.protocol || "tcp") !== (b.protocol || "tcp")) return false;
  const ipA = a.host_ip || "0.0.0.0";
  const ipB = b.host_ip || "0.0.0.0";
  return ipA === "0.0.0.0" || ipB === "0.0.0.0" || ipA === ipB;
}

function bindingLabel(p) {
  return `${p.host_ip ? p.host_ip + ":" : ""}${p.published}/${p.protocol || "tcp"}`;
}

function rulePortConflict(svc, model) {
  const findings = [];
  const idx = model.services.indexOf(svc);
  for (let i = 0; i < svc.ports.length; i++) {
    const p = svc.ports[i];
    if (typeof p.published !== "number") continue;
    let clash = null;
    // Only look backwards (earlier services, or earlier entries of this one),
    // so each conflict is reported once — on its second occurrence.
    for (let s = 0; s <= idx && !clash; s++) {
      const other = model.services[s];
      const upTo = other === svc ? i : other.ports.length;
      for (let j = 0; j < upTo; j++) {
        const q = other.ports[j];
        if (typeof q.published !== "number") continue;
        if (bindingsCollide(p, q)) { clash = other.name; break; }
      }
    }
    if (clash == null) continue;
    findings.push({
      level: "error",
      rule: "port-conflict",
      message: clash === svc.name
        ? `host port \`${bindingLabel(p)}\` is published twice by this service.`
        : `host port \`${bindingLabel(p)}\` is already published by service \`${clash}\` — the second container to start will fail with "port is already allocated".`,
      hint: "Change one of the `published` ports, or bind the services to different host IPs (e.g. `127.0.0.1:5432:5432`).",
    });
  }
  return findings;
}

// Explicit container_name values must be unique on the whole Docker host:
// two services claiming the same one can't both start ("Conflict. The
// container name ... is already in use"). Docker Compose since v2.24 refuses
// the file outright. Same reported-once convention as port-conflict: only
// the later service is flagged. As a bonus, container_name also disables
// `--scale` for that service, but that's a docs concern, not a lint error.
function ruleDuplicateContainerName(svc, model) {
  if (!svc.containerName) return [];
  const idx = model.services.indexOf(svc);
  for (let s = 0; s < idx; s++) {
    const other = model.services[s];
    if (other.containerName === svc.containerName) {
      return [{
        level: "error",
        rule: "duplicate-container-name",
        message: `\`container_name: ${svc.containerName}\` is already taken by service \`${other.name}\` — the second container to start fails with "name is already in use".`,
        hint: "Container names are host-global. Drop `container_name` (Compose generates unique names) or make them distinct.",
      }];
    }
  }
  return [];
}

// container_name pins the single name the container gets, but replicas need
// N distinct names — Compose refuses the file up front ("can't set container
// name and replicas"). Same family as the other file-rejecting rules. The
// legacy service-level `scale:` behaves identically and is folded into
// svc.replicas by the parser.
function ruleContainerNameWithReplicas(svc) {
  if (!svc.containerName || !(svc.replicas > 1)) return [];
  return [{
    level: "error",
    rule: "container-name-with-replicas",
    message: `\`container_name: ${svc.containerName}\` together with \`replicas: ${svc.replicas}\` — a container name is unique, so the service cannot be replicated and Compose refuses the file.`,
    hint: "Drop `container_name` (Compose numbers the replicas itself: project-service-1, -2, …) or set replicas to 1.",
  }];
}

// A healthcheck's grace period defaults to 0s: every probe that fails while
// the service is still booting eats into `retries`, so a slow starter (JVM
// warmup, DB crash recovery) is marked unhealthy before it ever gets going —
// and a dependent waiting on `condition: service_healthy` then never starts.
function ruleHealthcheckNoStartPeriod(svc) {
  const hc = svc.healthcheck;
  if (!hc || hc.disable === true) return [];
  if (hc.start_period != null) return [];
  return [{
    level: "warn",
    rule: "healthcheck-no-start-period",
    message: "`healthcheck` has no `start_period` — probe failures during boot count against `retries` from second zero.",
    hint: "Add `start_period` sized to the service's boot time (e.g. `start_period: 30s`) so warmup failures don't mark it unhealthy.",
  }];
}

// depends_on must name services that exist in the same file: Compose refuses
// the whole file otherwise ("service ... depends on undefined service").
// Classic ways to hit it: a rename that missed the depends_on line, or a
// service moved to another compose file.
function ruleDependsOnUnknown(svc, model) {
  const known = new Set(model.services.map((s) => s.name));
  const findings = [];
  for (const dep of svc.depends_on) {
    if (known.has(dep)) continue;
    findings.push({
      level: "error",
      rule: "depends-on-unknown",
      message: `\`depends_on\` references \`${dep}\`, which is not a service in this file — Compose refuses the whole file.`,
      hint: "Fix the name (did a rename miss this line?) or remove the entry if the service moved elsewhere.",
    });
  }
  return findings;
}

// Secrets pasted into command / entrypoint are the third door after
// environment (env-secret) and build args (build-arg-secret): a
// `redis-server --requirepass hunter2` shows up in `docker inspect`,
// `docker compose config`, `ps` inside the container, and the repo diff.
// Two shapes are scanned: secret-looking flags (--password=x, --requirepass x,
// --api-token x) and inline env assignments (MYSQL_PASSWORD=x cmd). Values
// that are interpolations (${VAR} / $VAR) come from outside the file and are
// fine; values that look like file paths (/run/secrets/db, ./certs/key.pem)
// are references to a secret, not the secret itself — both are skipped.
const CMD_SECRET_FLAG = /^--?[A-Za-z0-9-]*(password|passwd|secret|token|api-?key|requirepass|access-?key)$/i;
const CMD_SECRET_FLAG_EQ = /^(--?[A-Za-z0-9-]*(?:password|passwd|secret|token|api-?key|requirepass|access-?key))=(.+)$/i;

function isSafeCmdValue(v) {
  return v.startsWith("$") || v.startsWith("/") || v.startsWith("./") || v.startsWith("-");
}

function scanCommandString(str, where, findings) {
  // Strip shell quoting per token: `sh -c "KEY=x cmd"` keeps the inner
  // string's quotes attached to the first/last tokens.
  const tokens = String(str).split(/\s+/)
    .map((t) => t.replace(/^["']+|["']+$/g, ""))
    .filter(Boolean);
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    const eq = t.match(CMD_SECRET_FLAG_EQ);
    if (eq && !isSafeCmdValue(eq[2] ?? "")) {
      findings.push(cmdSecretFinding(where, eq[1]));
      continue;
    }
    const envM = t.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.+)$/);
    if (envM && SECRET_KEY_PATTERN.test(envM[1]) && !isSafeCmdValue(envM[2])) {
      findings.push(cmdSecretFinding(where, envM[1]));
      continue;
    }
    if (CMD_SECRET_FLAG.test(t) && i + 1 < tokens.length && !isSafeCmdValue(tokens[i + 1])) {
      findings.push(cmdSecretFinding(where, t));
      i++; // the value is consumed as this flag's argument
    }
  }
}

function cmdSecretFinding(where, what) {
  return {
    level: "error",
    rule: "command-secret",
    message: `\`${where}\` passes a literal secret via \`${what}\` — visible in \`docker inspect\`, \`docker compose config\` and \`ps\` inside the container.`,
    hint: "Read it from a file (`/run/secrets/…`, Docker secrets) or interpolate from the environment (`${VAR}`) — never inline the value.",
  };
}

function ruleCommandSecret(svc) {
  const findings = [];
  if (svc.command) scanCommandString(svc.command, "command", findings);
  if (svc.entrypoint) scanCommandString(svc.entrypoint, "entrypoint", findings);
  return findings;
}

// The short form of depends_on only waits for the dependency's container to
// START. If that dependency defines a healthcheck, the natural intent is to
// wait until it PASSES — otherwise the app races the database's warmup and
// wins just often enough to hide the bug until a slow morning. Fires only
// when the target actually has a healthcheck (nothing to wait for otherwise);
// `service_healthy` is the fix and `service_completed_successfully` is a
// deliberate different contract (one-shot jobs wait for exit, not health),
// so both stay quiet.
function ruleDependsOnIgnoresHealthcheck(svc, model) {
  const byName = new Map(model.services.map((s) => [s.name, s]));
  const findings = [];
  for (const dep of svc.depends_on) {
    const target = byName.get(dep);
    if (!target || !target.healthcheck) continue;
    const cond = (svc.dependsOnConditions || {})[dep] || null;
    if (cond === "service_healthy" || cond === "service_completed_successfully") continue;
    findings.push({
      level: "warn",
      rule: "depends-on-ignores-healthcheck",
      message: `\`depends_on: ${dep}\` only waits for the container to start, but \`${dep}\` defines a healthcheck.`,
      hint: `Use the long form — \`depends_on: { ${dep}: { condition: service_healthy } }\` — to wait until the healthcheck passes.`,
    });
  }
  return findings;
}

// A service can only attach to networks declared in the top-level `networks:`
// block: Compose refuses the whole file otherwise ("service ... refers to
// undefined network"). The implicit `default` network is exempt — every file
// has it without declaring it. Interpolated names are skipped (the value
// comes from outside the file, nothing to resolve statically).
function ruleUndeclaredNetwork(svc, model) {
  const declared = new Set(model.declaredNetworks || []);
  const findings = [];
  for (const net of svc.networks) {
    if (net === "default" || declared.has(net)) continue;
    if (String(net).includes("${")) continue;
    findings.push({
      level: "error",
      rule: "undeclared-network",
      message: `attaches to network \`${net}\`, which is not declared in the top-level \`networks:\` block — Compose refuses the whole file.`,
      hint: `Declare it (\`networks: { ${net}: {} }\` — add \`external: true\` if it already exists on the host) or fix the name.`,
    });
  }
  return findings;
}

// Same contract for named volumes: a service mounting a named volume that the
// top-level `volumes:` block doesn't declare is an undefined reference and
// Compose rejects the file. Bind mounts and anonymous volumes have no name to
// resolve, so only `type: "named"` entries are checked.
function ruleUndeclaredVolume(svc, model) {
  const declared = new Set(model.declaredVolumes || []);
  const findings = [];
  for (const v of svc.volumes) {
    if (v.type !== "named" || !v.source) continue;
    if (declared.has(v.source)) continue;
    if (String(v.source).includes("${")) continue;
    findings.push({
      level: "error",
      rule: "undeclared-volume",
      message: `mounts named volume \`${v.source}\`, which is not declared in the top-level \`volumes:\` block — Compose refuses the whole file.`,
      hint: `Declare it (\`volumes: { ${v.source}: {} }\` — add \`external: true\` if it already exists) or fix the name.`,
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
  ruleNoMemoryLimit,
  ruleNoPidsLimit,
  ruleDockerSocket,
  rulePrivileged,
  ruleHostNamespace,
  ruleDangerousCaps,
  ruleSensitiveHostMount,
  ruleNoNewPrivileges,
  ruleNoCapDrop,
  ruleNoReadOnly,
  ruleSecurityUnconfined,
  ruleBuildArgSecret,
  ruleCommandSecret,
  rulePortConflict,
  ruleDuplicateContainerName,
  ruleContainerNameWithReplicas,
  ruleHealthcheckNoStartPeriod,
  ruleDependsOnUnknown,
  ruleDependsOnIgnoresHealthcheck,
  ruleUndeclaredNetwork,
  ruleUndeclaredVolume,
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
