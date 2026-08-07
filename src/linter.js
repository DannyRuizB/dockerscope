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

// List-form `environment` (and build args) can name the same key twice —
// `["LOG_LEVEL=debug", "LOG_LEVEL=info"]` — and the LAST one silently wins.
// Nothing errors, so the file reads one way and the container runs another;
// the usual bite is editing one occurrence and leaving the stale twin above
// it. Map form (`environment: {LOG_LEVEL: info}`) can't express a duplicate —
// YAML collapses it — so this only ever fires on the list form. Reported
// once per duplicated key, naming where the survivor sits.
function ruleDuplicateEnvKey(svc) {
  const findings = [];
  for (const [field, entries] of [
    ["environment", svc.environment],
    ["build args", svc.buildArgs],
  ]) {
    if (!Array.isArray(entries)) continue;
    const seen = new Map(); // key -> count
    for (const { key } of entries) seen.set(key, (seen.get(key) || 0) + 1);
    for (const [key, count] of seen) {
      if (count < 2) continue;
      findings.push({
        level: "warn",
        rule: "duplicate-env-key",
        message: `\`${key}\` appears ${count} times in \`${field}\` — only the last value takes effect.`,
        hint: `Remove the redundant \`${key}\` entries so the file matches what the container actually gets.`,
      });
    }
  }
  return findings;
}

// Images that almost never want to be reachable from outside the host.
// nginx, traefik, caddy, etc. are intentionally public, so they're excluded.
const SENSITIVE_IMAGE_PATTERN = /(postgres|mysql|mariadb|mongo|mongodb|redis|memcached|elastic|rabbitmq|kafka|etcd|cassandra|influxdb|clickhouse)/i;

// The image name is the FIRST way to recognize a data service, not the only
// one: `image: registry.corp/team/api-db:7` matches nothing, and the port it
// publishes is just as open. The container-side port is the second tell —
// it names the protocol regardless of who built the image. Only ports whose
// service should essentially never face the internet, so a published 80 or
// 8080 stays quiet.
const SENSITIVE_CONTAINER_PORTS = {
  1433:  "mssql",
  2375:  "docker api (plaintext — remote root)",
  2376:  "docker api (tls)",
  2379:  "etcd",
  3306:  "mysql/mariadb",
  5432:  "postgres",
  5984:  "couchdb",
  6379:  "redis",
  8086:  "influxdb",
  8200:  "vault",
  9042:  "cassandra",
  9092:  "kafka",
  9200:  "elasticsearch",
  11211: "memcached",
  15672: "rabbitmq management",
  27017: "mongodb",
};

function rulePortPublic(svc) {
  const imageIsSensitive = !!svc.image && SENSITIVE_IMAGE_PATTERN.test(svc.image);
  const findings = [];
  for (const p of svc.ports) {
    if (p.published == null) continue; // not published, only exposed inside the network
    if (p.host_ip && p.host_ip !== "0.0.0.0" && p.host_ip !== "::") continue; // pinned to an interface
    const service = SENSITIVE_CONTAINER_PORTS[p.target];
    if (!imageIsSensitive && !service) continue;
    // Verified against a real daemon: a mapping with no host IP binds
    // 0.0.0.0 *and* [::], and its DNAT rule lands in nat/PREROUTING with no
    // `-d` — so it matches on every interface and never passes through
    // filter/INPUT, which is where ufw writes its rules. `ufw deny 5432`
    // does not close this. Pinning the host IP adds `-d 127.0.0.1/32` to
    // that same rule, which is what actually restricts it.
    const what = service
      ? `\`${service}\` (container port ${p.target})`
      : "a database/cache image";
    findings.push({
      level: "warn",
      rule: "port-public",
      message: `port \`${p.published}\` of ${what} is published on all interfaces (0.0.0.0 and [::]) — host firewall rules in INPUT (ufw included) do not filter it.`,
      hint: "Bind to `127.0.0.1:` (e.g. `127.0.0.1:" + p.published + ":" + p.target + "`) so only the host can reach it, or remove the published port and rely on the internal network.",
    });
  }
  return findings;
}

function ruleNoRestart(svc) {
  if (svc.restart) return [];
  // A mistyped restart is its own (worse) problem — one message, not two.
  if (svc.restartInvalid) return [];
  return [{
    level: "warn",
    rule: "no-restart",
    message: "no `restart` policy set.",
    hint: "Add `restart: unless-stopped` (or `always`) so the container survives reboots and crashes.",
  }];
}

// `restart: false` looks like a reasonable spelling of "don't restart" and is
// not: compose rejects any non-string restart outright — measured:
// "services.app.restart must be a string", the file never comes up. The YAML
// trap cuts the other way here: js-yaml and compose both speak YAML 1.2, so
// the unquoted word `no` is the STRING "no" and works — it is the
// explicitly-typed boolean (or a number) that kills the file.
function ruleRestartNotAString(svc) {
  if (!svc.restartInvalid) return [];
  return [{
    level: "error",
    rule: "restart-not-a-string",
    message: "`restart` is not a string — Compose rejects the whole file (`restart must be a string`).",
    hint: "Write `restart: \"no\"` / `always` / `unless-stopped` / `on-failure`. A YAML boolean or number here fails validation before anything starts.",
  }];
}

// A healthcheck watches a service that `restart: "no"` tells Docker never to
// revive — and if nothing waits on `service_healthy`, nobody acts on the
// verdict at all. Measured on the real daemon: health status NEVER triggers
// a restart in plain Compose (a container with `restart: always` and a
// failing probe sat at "running (unhealthy)" with RestartCount 0 and a
// growing FailingStreak) — restart policies act on process EXIT only, so the
// check's real consumers are `service_healthy` gates, external monitors and
// humans reading `docker ps`. With restart "no" and no dependent gating on
// it, the file says "watch this closely" and "never bring it back" in the
// same breath. Absence of `restart` never fires (the default is "no", but
// not writing the key is not a statement — the explicit-root-user
// precedent), and one dependent waiting on service_healthy spares it.
function ruleRestartNoWithHealthcheck(svc, model) {
  if (svc.restart !== "no") return [];
  if (!svc.healthcheck || healthcheckDisabled(svc.healthcheck)) return [];
  const consumed = model.services.some((other) =>
    other !== svc &&
    (other.depends_on || []).includes(svc.name) &&
    (other.dependsOnConditions || {})[svc.name] === "service_healthy");
  if (consumed) return [];
  return [{
    level: "warn",
    rule: "restart-no-with-healthcheck",
    message: "explicit `restart: \"no\"` on a service with a healthcheck nothing consumes.",
    hint: "Docker never restarts a container for being unhealthy — with restart \"no\" and no `service_healthy` dependent, the check labels a corpse. Give the service a restart policy, point a dependent at `condition: service_healthy`, or drop the healthcheck.",
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

// `oom_kill_disable: true` is a lie on every modern host and a host-killer
// on the old ones. On cgroups v2 (every current distro) the daemon DISCARDS
// it with a warning buried in the run output ("Your kernel does not support
// OomKillDisable. OomKillDisable discarded", verified against a real
// daemon) — the protection you think you configured does not exist. On
// cgroups v1 it is honored, and Docker's own docs forbid the combination
// judged as error here: with the OOM killer off and NO memory limit, a leak
// eats host memory the kernel is no longer allowed to reclaim — the machine
// hangs, not the container. With a limit the container freezes at the cap
// instead of dying (the one legitimate, sharp-edged use) — that keeps a
// warn, because on v2 hosts even that intent is silently dropped.
function ruleOomKillDisable(svc) {
  if (!svc.oomKillDisable) return [];
  if (svc.memoryLimit == null) {
    return [{
      level: "error",
      rule: "oom-kill-disable",
      message: "disables the OOM killer with no memory limit — a leak can hang the whole host (cgroups v1), or the flag is silently discarded (cgroups v2).",
      hint: "Remove `oom_kill_disable` — or, if you truly need it on a cgroups v1 host, pair it with a hard `memory:` limit as Docker's docs require.",
    }];
  }
  return [{
    level: "warn",
    rule: "oom-kill-disable",
    message: "disables the OOM killer — on cgroups v2 hosts (every modern distro) the daemon silently discards this flag.",
    hint: "The memory limit keeps cgroups v1 hosts safe, but on v2 the setting is a no-op: the container is OOM-killed at the cap anyway. Remove it unless you still deploy to v1 hosts.",
  }];
}

// A service with no CPU cap can pin every core on the host: a busy loop (a
// runaway retry storm, a crypto-miner in a compromised image) starves the
// other containers and the daemon itself. Completes the resource-caps
// quartet — memory kills by OOM, PIDs by table exhaustion, logs by disk,
// CPU starves. `deploy.resources.limits.cpus`, the `cpus:` shorthand or
// `cpu_quota` count as capped; `cpu_shares` does not (a weight, not a cap).
function ruleNoCpuLimit(svc) {
  if (svc.cpuLimit != null) return [];
  return [{
    level: "warn",
    rule: "no-cpu-limit",
    message: "no CPU limit set.",
    hint: "Add `deploy.resources.limits.cpus: \"0.50\"` (or the `cpus:` shorthand) so a busy loop can't pin every core on the host.",
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

// Docker's default logging driver (json-file) keeps EVERYTHING a container
// ever wrote to stdout/stderr, unrotated — a chatty or misbehaving service
// fills the host disk from /var/lib/docker/containers, and the classic
// discovery path is "why is the box read-only?" at 3am. `max-size` bounds it
// in one line. Drivers other than json-file are spared: `local` rotates by
// default, journald/syslog/fluentd/gelf hand the stream to a system that has
// its own retention, and `none` keeps nothing. Completes the disk-safety
// trio: no-memory-limit (RAM), no-pids-limit (process table), this (disk).
function ruleNoLogLimit(svc) {
  if (svc.logDriver != null && svc.logDriver !== "json-file") return [];
  if (svc.logMaxSize != null) return [];
  return [{
    level: "warn",
    rule: "no-log-limit",
    message: svc.logDriver === "json-file"
      ? "json-file logging has no `max-size` — container logs grow unbounded."
      : "no log rotation — the default json-file driver keeps every log line forever.",
    hint: "Add `logging: { driver: json-file, options: { max-size: \"10m\", max-file: \"3\" } }` (or switch to the `local` driver, which rotates by default).",
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

// An explicit `user: root` is worse than saying nothing: compose's `user:`
// OVERRIDES the image's own USER directive, so an image that ships a
// deliberate privilege drop (postgres, node, nginx-unprivileged…) gets root
// handed back by one line of YAML. Absence stays quiet on purpose — without
// pulling the image we can't know its USER, and flagging every service would
// be noise; an explicit root is the one case the file itself proves. A root
// *group* alone ("1000:0", the OpenShift arbitrary-uid pattern) is not root
// and does not fire; interpolations (`user: ${APP_UID}`) never match.
function ruleExplicitRootUser(svc) {
  if (svc.user == null) return [];
  const uid = String(svc.user).split(":")[0].trim();
  if (uid !== "root" && !/^0+$/.test(uid)) return [];
  return [{
    level: "warn",
    rule: "explicit-root-user",
    message: `\`user: ${svc.user}\` runs the service as root — overriding any privilege drop the image ships.`,
    hint: "Drop the line to keep the image's own USER, or set a non-root uid:gid (e.g. `1000:1000`).",
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

// Two mounts onto one container path never deploy: the daemon refuses to
// create the container ("Duplicate mount point") — verified against a real
// daemon; volume+volume, bind+volume and tmpfs+volume all die, and a
// trailing slash does not make two paths different. The usual sources are a
// copy-pasted volumes list, the same target spelled once in short and once
// in long syntax, or a `tmpfs:` entry colliding with a volume. File-killing
// family with port-conflict and friends — except this one needs no second
// service, one service kills itself.
function ruleDuplicateMountTarget(svc) {
  const findings = [];
  const seen = new Set();
  const targets = [
    ...(svc.volumes || []).map(v => v.target),
    ...(svc.tmpfs || []),
  ];
  for (const target of targets) {
    if (!target || typeof target !== "string") continue;
    const norm = target.replace(/\/+$/, "") || "/";
    if (seen.has(norm)) {
      findings.push({
        level: "error",
        rule: "duplicate-mount-target",
        message: `mounts \`${target}\` twice — the daemon refuses to create the container ("Duplicate mount point").`,
        hint: "Keep one mount per container path: merge the duplicated volumes / tmpfs entries and delete the rest.",
      });
    } else {
      seen.add(norm);
    }
  }
  return findings;
}

// With host networking the container shares the host's network stack, so
// there is nothing to map — the engine silently DISCARDS every `ports:`
// entry ("WARNING: Published ports are discarded when using host network
// mode", verified against a real daemon; compose runs never surface it).
// The mappings in the file are a lie either way: the service listens on
// whatever ports the process binds, not the ones written here, and a reader
// (or a firewall review) trusting the list is misled. Same silent-no-op
// family as duplicate-env-key.
function rulePortsWithHostNetwork(svc) {
  if (svc.networkMode !== "host") return [];
  const n = (svc.ports || []).length;
  if (n === 0) return [];
  return [{
    level: "warn",
    rule: "ports-with-host-network",
    message: `declares ${n} port mapping${n === 1 ? "" : "s"} under \`network_mode: host\` — Docker silently discards them.`,
    hint: "With host networking the process binds host ports directly, so the `ports:` block does nothing. Remove it, or drop `network_mode: host` and keep the mappings.",
  }];
}

// An `internal: true` network has no route to the host's interfaces — and
// that includes published ports. For a service whose ONLY networks are
// internal, the daemon keeps the request in HostConfig.PortBindings but
// never creates the binding: NetworkSettings.Ports shows null and nothing
// listens (verified against a real daemon — `docker compose up` prints no
// warning at all, and `compose ps` quietly drops the arrow). The `ports:`
// block is a lie in the file, same silent-no-op family as
// ports-with-host-network and duplicate-env-key. One non-internal network
// anywhere in the list restores the mapping (also verified), so mixed
// attachments stay quiet — as do undeclared or interpolated networks,
// whose internal flag is unknowable (`undeclared-network` owns ghosts).
// Services on `network_mode` have no networks list to judge here: host's
// dead ports are ports-with-host-network's finding.
function rulePortsOnInternalNetwork(svc, model) {
  if ((svc.ports || []).length === 0) return [];
  if (svc.networkMode) return [];
  const internal = new Set(model && model.internalNetworks || []);
  if (internal.size === 0) return [];
  const attached = svc.networks.length > 0 ? svc.networks : ["default"];
  if (!attached.every((net) => internal.has(net))) return [];
  const n = svc.ports.length;
  const nets = attached.join("`, `");
  return [{
    level: "warn",
    rule: "ports-on-internal-network",
    message: `publishes ${n} port mapping${n === 1 ? "" : "s"} but every network it joins (\`${nets}\`) is \`internal: true\` — Docker silently never binds the host port${n === 1 ? "" : "s"}.`,
    hint: "Attach the service to one non-internal network too (the internal ones keep isolating the rest), or drop the dead `ports:` block.",
  }];
}

// `network_mode` and `networks` are mutually exclusive: Compose refuses the
// whole file ("service X declares mutually exclusive `network_mode` and
// `networks`: invalid compose project", verified against a real daemon —
// host, bridge and service: modes all die identically; an *empty*
// `networks: []` is accepted, so only a non-empty list fires). The usual
// story is a service moved onto host networking (or another container's
// stack) while its old networks list stayed behind. File-killing family
// with port-conflict and duplicate-mount-target.
function ruleNetworkModeWithNetworks(svc) {
  if (!svc.networkMode || svc.networks.length === 0) return [];
  return [{
    level: "error",
    rule: "network-mode-with-networks",
    message: `declares mutually exclusive \`network_mode: ${svc.networkMode}\` and a \`networks:\` list — Compose refuses the whole file.`,
    hint: "Keep one: `network_mode` replaces network attachment entirely, so drop the `networks:` list — or drop `network_mode` and let the service join its networks.",
  }];
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

// Compose duration strings: "500ms", "5s", "1m30s", "2h", or a bare number
// (seconds). Returns milliseconds, or null when it can't be read (an
// interpolation like `${HC_TIMEOUT}`, or nonsense — never guess).
function parseComposeDuration(value) {
  if (value == null) return null;
  if (typeof value === "number") return value * 1000;
  const s = String(value).trim();
  if (/^\d+(\.\d+)?$/.test(s)) return parseFloat(s) * 1000;
  const unit = { us: 0.001, ms: 1, s: 1000, m: 60000, h: 3600000 };
  const re = /(\d+(?:\.\d+)?)(us|ms|s|m|h)/g;
  let total = 0;
  let matched = 0;
  let m;
  while ((m = re.exec(s)) !== null) {
    total += parseFloat(m[1]) * unit[m[2]];
    matched += m[0].length;
  }
  // Every character must belong to a number+unit pair, or we didn't
  // understand the string (e.g. "${HC_TIMEOUT}", "fast").
  return matched === s.length ? total : null;
}

function humanMs(ms) {
  return ms % 1000 === 0 ? `${ms / 1000}s` : `${ms}ms`;
}

// `interval` is the PAUSE BETWEEN checks, not the period of the cycle —
// Docker serializes probes and starts counting the interval only once the
// previous one returns. Almost everyone reads it as "check every N
// seconds", so a `timeout` larger than the `interval` is the tell that
// someone wanted a fast loop while allowing a slow probe: the real cycle
// becomes probe_duration + interval, and the time to notice a dead service
// becomes retries × that.
//
// Measured against a real daemon (interval 2s, timeout 6s, retries 3, probe
// sleeping 5s): each probe took 5.0s and the next started exactly 2.0s
// AFTER the previous one ended — unhealthy landed 26.1s after the first
// probe began, where the file reads like ~6s. That 3-4x gap is the finding.
//
// It also delays every `depends_on: condition: service_healthy` waiting on
// this service, which is usually where the cost is actually felt.
// Compose accepts the file without a murmur (verified) — nothing warns.
// Only `>` fires: a timeout EQUAL to the interval is a defensible "the
// probe must never take this long" choice, and a smell should not argue
// with it. Unreadable durations (interpolations) are never judged.
function ruleHealthcheckTimeoutExceedsInterval(svc) {
  const hc = svc.healthcheck;
  if (!hc || hc.disable === true) return [];
  const timeout = parseComposeDuration(hc.timeout);
  const interval = parseComposeDuration(hc.interval);
  if (timeout == null || interval == null) return [];
  if (timeout <= interval) return [];
  const retries = Number.isInteger(hc.retries) && hc.retries > 0 ? hc.retries : 3;
  const worst = retries * (timeout + interval);
  return [{
    level: "warn",
    rule: "healthcheck-timeout-exceeds-interval",
    message: `\`healthcheck.timeout\` (${humanMs(timeout)}) is longer than its \`interval\` (${humanMs(interval)}) — \`interval\` is the pause BETWEEN probes, not the cycle, so a slow probe stretches the loop to ${humanMs(timeout + interval)} and noticing a dead service can take ${humanMs(worst)} (retries: ${retries}).`,
    hint: `Keep \`timeout\` well under \`interval\` (a probe that can outlast its own cycle is the real problem), or widen \`interval\` to match what the probe actually needs. Anything waiting on \`condition: service_healthy\` waits this long too.`,
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

// A dependency that only exists under a profile the dependent doesn't share
// dies on plain `docker compose up` with "depends on undefined service" — a
// message that never mentions profiles, so the head-scratching is free.
// Verified against compose v5.3.1: gated dep + ungated dependent fails by
// default AND under any profile that enables the dependent but not the dep;
// activating a covering profile makes the very same file valid — hence warn,
// not error. The only safe shape: every profile that enables the dependent
// also enables the dependency (dependent's profiles non-empty and a subset
// of the dep's). Dangling names stay with depends-on-unknown.
function ruleDependsOnProfileGated(svc, model) {
  const byName = new Map(model.services.map((s) => [s.name, s]));
  const findings = [];
  for (const dep of svc.depends_on) {
    const target = byName.get(dep);
    if (!target) continue;
    if (target.profiles.length === 0) continue;
    const covered =
      svc.profiles.length > 0 &&
      svc.profiles.every((p) => target.profiles.includes(p));
    if (covered) continue;
    const gate = target.profiles.map((p) => `\`${p}\``).join(", ");
    findings.push({
      level: "warn",
      rule: "depends-on-profile-gated",
      message: `\`depends_on\` references \`${dep}\`, which only exists under profile(s) ${gate} — a plain \`docker compose up\` refuses the file with "depends on undefined service".`,
      hint: `Align the profiles so every run that starts \`${svc.name}\` also enables \`${dep}\` (give \`${svc.name}\` the same profiles, or ungate \`${dep}\`); \`--profile ${target.profiles[0]}\` works but must be remembered on every invocation.`,
    });
  }
  return findings;
}

// A cycle in depends_on (a → b → a, or a service depending on itself) is a
// hard error: Compose refuses the whole file with "cyclic dependency". Easy
// to create by accident when wiring up a new dependency without noticing the
// return path. Reported once per cycle — on its lexicographically-smallest
// member — since the rule runs per service. Only edges to services that
// actually exist count (a dangling name is depends-on-unknown's job). File
// sizes are tiny, so the reachability probe per node is fine.
function ruleDependsOnCycle(svc, model) {
  const names = new Set(model.services.map((s) => s.name));
  const adj = new Map(
    model.services.map((s) => [s.name, (s.depends_on || []).filter((d) => names.has(d))]),
  );
  const reachable = (start) => {
    const seen = new Set();
    const stack = [...(adj.get(start) || [])];
    while (stack.length) {
      const n = stack.pop();
      if (seen.has(n)) continue;
      seen.add(n);
      for (const m of adj.get(n) || []) stack.push(m);
    }
    return seen;
  };
  // svc is in a cycle iff it can reach itself. Its cycle = the strongly
  // connected members: nodes svc reaches that also reach svc (plus svc).
  const forward = reachable(svc.name);
  if (!forward.has(svc.name)) return [];
  const members = model.services
    .map((s) => s.name)
    .filter((name) => name === svc.name || (forward.has(name) && reachable(name).has(svc.name)))
    .sort();
  if (svc.name !== members[0]) return []; // report once, on the smallest member
  return [
    {
      level: "error",
      rule: "depends-on-cycle",
      message: `\`depends_on\` forms a cycle among ${members.map((m) => `\`${m}\``).join(", ")} — Compose refuses the whole file ("cyclic dependency").`,
      hint: "Break the loop — one of these services must not wait on the others.",
    },
  ];
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

// `disable: true` and `test: ["NONE"]` / `test: NONE` all mean "this service
// reports no health" — relevant to anyone waiting on service_healthy.
function healthcheckDisabled(hc) {
  if (hc.disable === true) return true;
  const test = hc.test;
  if (typeof test === "string") return test.trim().toUpperCase() === "NONE";
  if (Array.isArray(test)) return String(test[0] || "").trim().toUpperCase() === "NONE";
  return false;
}

// The mirror image of depends-on-ignores-healthcheck: `condition:
// service_healthy` waits for a health signal the dependency will never send.
// Without a healthcheck (or with it disabled) Compose refuses to start the
// dependent at all — 'dependency "db" has no healthcheck configured' — so
// this is a startup failure written down, not a style nit. Unknown targets
// stay quiet: depends-on-unknown already owns that finding.
function ruleServiceHealthyNoHealthcheck(svc, model) {
  const byName = new Map(model.services.map((s) => [s.name, s]));
  const findings = [];
  for (const [dep, cond] of Object.entries(svc.dependsOnConditions || {})) {
    if (cond !== "service_healthy") continue;
    const target = byName.get(dep);
    if (!target) continue;
    if (target.healthcheck && !healthcheckDisabled(target.healthcheck)) continue;
    const why = target.healthcheck ? "disables its healthcheck" : "has no healthcheck";
    findings.push({
      level: "error",
      rule: "service-healthy-no-healthcheck",
      message: `\`depends_on: { ${dep}: { condition: service_healthy } }\` — but \`${dep}\` ${why}, so the condition can never be met and Compose refuses to start this service.`,
      hint: `Give \`${dep}\` a healthcheck, or relax the condition to \`service_started\`.`,
    });
  }
  return findings;
}

// healthcheck.test in list form must start with CMD, CMD-SHELL or NONE.
// `test: ["curl", "-f", …]` looks perfectly plausible — and Compose refuses
// the whole file. Joins the file-rejecting family (depends-on-unknown,
// undeclared-network/volume, container-name-with-replicas). Interpolated
// first items are skipped: the value comes from outside the file.
function ruleHealthcheckTestInvalid(svc) {
  const hc = svc.healthcheck;
  if (!hc || !Array.isArray(hc.test) || hc.test.length === 0) return [];
  const first = String(hc.test[0] ?? "").trim();
  if (first.includes("${")) return [];
  const keyword = first.toUpperCase();
  if (keyword === "CMD" || keyword === "CMD-SHELL" || keyword === "NONE") return [];
  return [
    {
      level: "error",
      rule: "healthcheck-test-invalid",
      message: `\`healthcheck.test\` list starts with \`${first}\` — the first item must be \`CMD\`, \`CMD-SHELL\` or \`NONE\`, and Compose refuses the whole file otherwise.`,
      hint: `Use \`test: ["CMD", "${first}", …]\` (exec form) or a plain string for shell form.`,
    },
  ];
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

// A service can only mount a secret declared in the top-level `secrets:`
// block — Compose refuses the whole file otherwise ("service ... refers to
// undefined secret ..."). The classic bite: the top-level block is renamed
// or dropped in a merge and the service's reference is left dangling.
// Joins the file-rejecting family (undeclared-network/volume,
// depends-on-unknown). Interpolated names are skipped (value from outside).
function ruleUndeclaredSecret(svc, model) {
  const declared = new Set(model.declaredSecrets || []);
  const findings = [];
  for (const s of svc.secrets) {
    if (declared.has(s)) continue;
    if (String(s).includes("${")) continue;
    findings.push({
      level: "error",
      rule: "undeclared-secret",
      message: `references secret \`${s}\`, which is not declared in the top-level \`secrets:\` block — Compose refuses the whole file.`,
      hint: `Declare it (\`secrets: { ${s}: { file: ./${s}.txt } }\`, or \`external: true\` if it already exists) or fix the name.`,
    });
  }
  return findings;
}

const RULES = [
  ruleImageLatest,
  ruleEnvSecrets,
  ruleDuplicateEnvKey,
  rulePortPublic,
  ruleNoRestart,
  ruleRestartNotAString,
  ruleRestartNoWithHealthcheck,
  ruleNoHealthcheck,
  ruleNoMemoryLimit,
  ruleOomKillDisable,
  ruleNoPidsLimit,
  ruleNoCpuLimit,
  ruleNoLogLimit,
  ruleDockerSocket,
  rulePrivileged,
  ruleExplicitRootUser,
  ruleHostNamespace,
  rulePortsWithHostNetwork,
  rulePortsOnInternalNetwork,
  ruleNetworkModeWithNetworks,
  ruleDangerousCaps,
  ruleSensitiveHostMount,
  ruleNoNewPrivileges,
  ruleNoCapDrop,
  ruleNoReadOnly,
  ruleSecurityUnconfined,
  ruleBuildArgSecret,
  ruleCommandSecret,
  rulePortConflict,
  ruleDuplicateMountTarget,
  ruleDuplicateContainerName,
  ruleContainerNameWithReplicas,
  ruleHealthcheckNoStartPeriod,
  ruleHealthcheckTimeoutExceedsInterval,
  ruleDependsOnUnknown,
  ruleDependsOnCycle,
  ruleDependsOnProfileGated,
  ruleDependsOnIgnoresHealthcheck,
  ruleServiceHealthyNoHealthcheck,
  ruleHealthcheckTestInvalid,
  ruleUndeclaredNetwork,
  ruleUndeclaredVolume,
  ruleUndeclaredSecret,
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
