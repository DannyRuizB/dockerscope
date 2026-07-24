# DockerScope

> Visual analyzer for `docker-compose.yml` — paste a compose file, see the architecture.

[![lint](https://github.com/DannyRuizB/dockerscope/actions/workflows/lint.yml/badge.svg)](https://github.com/DannyRuizB/dockerscope/actions/workflows/lint.yml)
[![Live demo](https://img.shields.io/badge/demo-dannyruizb.github.io%2Fdockerscope-3b82f6)](https://dannyruizb.github.io/dockerscope/)
![No backend](https://img.shields.io/badge/backend-none%20·%20runs%20in%20your%20browser-f59e0b)
![Analyzes](https://img.shields.io/badge/analyzes-compose%20·%20Dockerfile%20·%20stack-6366f1)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

### [Try the live demo →](https://dannyruizb.github.io/dockerscope/)

![DockerScope on the stack-detection sample: chips above the textarea show stack-main.yml as main alongside api.Dockerfile, api.package.json, worker.Dockerfile and worker.requirements.txt. The graph renders api, worker, db, cache, broker and the db-data named volume; lint severity is reflected in the borders (db red for plaintext POSTGRES_PASSWORD, api/worker amber for missing restart and healthcheck, cache and broker clean). Below the graph: Lint is collapsed, Dockerfiles shows the worker entry (python:3.12-slim, WORKDIR /app, ENTRYPOINT and CMD), and Stack shows api as Node 20 + Express + PostgreSQL (pg) + Redis (ioredis) + BullMQ + AMQP/RabbitMQ sourced from api.package.json, and worker as Python 3.12 + FastAPI + PostgreSQL (psycopg2-binary) + Celery + AMQP/RabbitMQ (pika) sourced from worker.requirements.txt.](screenshots/screenshot.png)

DockerScope is a **client-side, zero-backend** tool that parses a `docker-compose.yml` file and renders:

- A **cluster-style service graph** where each network is drawn as a dashed container that visually wraps the services running on it (its first declared network); extra-network membership becomes a dashed edge so nothing is lost.
- A **lint panel** (collapsible) flagging floating tags, plaintext secrets, databases exposed on `0.0.0.0`, container-privilege risks (`docker.sock` mounts, `privileged`, host namespaces, dangerous `cap_add`), missing `restart` policy and missing healthchecks. Each finding ships with a hint on how to fix it, and affected services are highlighted on the graph.
- A **port table** listing every published port grouped by service.
- **Volumes on the graph** — named volumes appear as gray cylinders, host bind mounts as amber tags. Each mount edge is labelled with the path inside the container, with a dashed line for read-only mounts. Bind mounts are highlighted in amber because they're the most common way a container leaks host state (think `~/.ssh:ro` or `/var/run/docker.sock`).
- **Paste, upload, or drag & drop** your compose file — everything runs in the browser.
- **Pop out the graph** into a real OS window with the `↗` button — drag it to a second monitor while you keep editing in the main one.
- **Download the graph** as PNG or SVG with the `⤓` button — the SVG keeps the original colors and is fully editable in Inkscape / Figma.
- **Multi-file `extends`** — drop the main compose **and** the file it extends from at the same time, and DockerScope merges them client-side so the graph reflects the resolved services. File chips above the textarea let you switch which one is the "main".
- **Multi-file `include`** — drop the main compose along with every file it pulls in via `include:`. DockerScope merges all of them into a single model: services, networks and volumes from the included files end up next to the ones declared in the main, with the main winning on name collisions.
- **Dockerfile inspection** — drop the `Dockerfile` for any service that uses `build:` and a new "Dockerfiles" panel appears, showing base image, multi-stage chain, `EXPOSE`, `ENV`, `WORKDIR`, `USER`, `CMD` and `ENTRYPOINT` for each one.
- **Layout that stays tidy** — drag a node and alignment guidelines appear as you cross another node's row or column, or hit equal spacing between peers. Select multiple nodes (`Ctrl+A`, or shift-drag a box) and they move together as a block.
- **Stack detection** — drop a manifest prefixed with the service name (`api.package.json`, `worker.requirements.txt`, `svc.go.mod`) and DockerScope identifies the language, framework, DB clients and queue/broker clients in a new "Stack" panel — with the language version pulled from the matching Dockerfile when available.

![Multi-file extends in action: two file chips above the textarea (extends-main.yml marked as main, extends-base.yml loaded). The graph shows api, db and logger services with the properties resolved from the base file — api wrapped inside the app-net network it inherits from app-base, and the logger node attached to the ./fluent-bit.conf bind mount inherited from logger-base.](screenshots/screenshot-extends.png)

![Multi-file include in action: three file chips above the textarea (include-main.yml as main, include-services.yml and include-proxy.yml loaded). The graph shows five services merged from the three files (api and db from the main, logger and metrics from the services file, proxy from the proxy file) all wrapped inside the app-net compound. db-data appears as a named volume cylinder and ./fluent-bit.conf as an amber bind tag attached to logger.](screenshots/screenshot-include.png)

![Dockerfile inspection in action: three file chips above the textarea (dockerfile-main.yml as main, plus api.Dockerfile and worker.Dockerfile rendered with amber borders to mark them as Dockerfiles). The graph shows api, db, worker and the db-data named volume; the mount edge label /var/lib/postgresql/data is drawn horizontally so it stays readable. A new "Dockerfiles" panel below Ports shows the api entry with a multi-stage badge, its base image, stage chain, WORKDIR, USER and EXPOSE.](screenshots/screenshot-dockerfiles.png)

![Stack detection in action: chips above the textarea include green-bordered manifest files (api.package.json, worker.requirements.txt) alongside the YAML and Dockerfile chips. The graph shows api, worker and the supporting db, cache and broker services. A new "Stack" panel reads, for the api service, Node 20 + Express + PostgreSQL (pg) and Redis (ioredis) DB clients + BullMQ and AMQP/RabbitMQ queue clients sourced from api.package.json. The worker entry shows Python 3.12 + FastAPI + PostgreSQL (psycopg2-binary) + Celery and AMQP/RabbitMQ (pika) sourced from worker.requirements.txt.](screenshots/screenshot-stack.png)

**v1.0.0** — stable. The roadmap declared in this README is fully shipped.

---

## Why

Reviewing a `docker-compose.yml` from a teammate, a tutorial, or a homelab project usually means scrolling through YAML and building the architecture in your head. DockerScope flips that: paste the file, see the architecture.

It is intentionally **not** a wrapper around `docker compose config` — it runs entirely in the browser, so no Docker daemon, no upload, no server.

## What this demonstrates

A project built on container-orchestration knowledge. Skills on display:

- **Container orchestration** — deep reading of `docker-compose.yml`: services, networks, named and bind volumes, published ports, `restart` policies and healthchecks.
- **Docker security awareness** — a linter flagging plaintext secrets, databases exposed on `0.0.0.0`, risky bind mounts (e.g. `docker.sock`) and floating image tags.
- **Image internals** — Dockerfile inspection (multi-stage chains, base image, `USER`, `EXPOSE`) and language / framework / stack detection from manifests.
- **Frontend engineering** — client-side parsing and graph layout, multi-file `extends` / `include` merging, deployed on GitHub Pages.

## Use it

Live demo: **https://dannyruizb.github.io/dockerscope/** — runs 100% in your browser, no upload, no server.

Run locally — any static server works:

```bash
git clone https://github.com/DannyRuizB/dockerscope.git
cd dockerscope
python3 -m http.server 8080
# open http://localhost:8080
```

> Opening `index.html` directly with `file://` works for pasted input but blocks `Load sample` (browsers disallow `fetch` from `file://`). Use a static server.

## File naming conventions

DockerScope associates a `Dockerfile` or a language manifest to a service by **filename**. A few short rules:

- **Compose**: any `.yml` / `.yaml` file. The first one becomes the "main"; switch which is main by clicking its chip.
- **Dockerfile**: matched per service via `build.dockerfile`, or per the path given in `build`. To keep multiple Dockerfiles unambiguous, prefix them with the service name: `api.Dockerfile`, `worker.Dockerfile`. A bare `Dockerfile` works when there's only one service with `build:`.
- **Language manifest**: prefix it with the service name — `api.package.json`, `worker.requirements.txt`, `svc.go.mod`. Bare manifests (no prefix) are intentionally **not** matched, to avoid ambiguity when a compose has more than one service.

## Stack detection coverage (v0.8)

DockerScope reads dependency keys from the manifest and surfaces framework, DB drivers and queue / broker clients. Adding a new entry is one line in `src/manifest.js`.

| Language | Manifest | Frameworks | DB clients | Queue / broker |
|----------|----------|------------|-----------|----------------|
| Node | `package.json` | Next.js, NestJS, Express, Fastify, Koa, Hapi | pg, postgres, mysql2, mysql, mongodb, mongoose, Prisma, Sequelize, TypeORM, Knex, redis, ioredis, better-sqlite3, sqlite3 | BullMQ, Bull, amqplib, kafkajs, NATS, Agenda, Bee Queue |
| Python | `requirements.txt` | Django, FastAPI, Flask, Starlette, aiohttp, Tornado | psycopg2 / psycopg2-binary / psycopg3, asyncpg, pymysql, mysqlclient, pymongo, motor, redis-py, SQLAlchemy, Peewee | Celery, pika, kafka-python, confluent-kafka, RQ, Dramatiq, NATS |
| Go | `go.mod` | Gin, Echo, Fiber, Gorilla Mux, chi | pgx, lib/pq, go-sql-driver/mysql, mongo-driver, go-redis, GORM, mattn/go-sqlite3 | amqp091-go, streadway/amqp, segmentio/kafka-go, confluent-kafka-go, nats.go |

Language version is read from `go.mod` directly; for Node and Python it's inferred from a `node:N` / `python:N` `FROM` line in the matching Dockerfile when present.

## Roadmap

- [x] **v0.1** — Parse compose, render service graph (`depends_on` + networks), list ports, file upload + drag & drop.
- [x] **v0.2** — Static linter: floating tags, plaintext secrets in `environment`, public DB/cache ports, missing `restart`, missing healthchecks. Findings highlight affected services on the graph.
- [x] **v0.3** — Export graph to PNG / SVG.
- [x] **v0.4** — Volumes as nodes (named cylinders + host bind tags, mount edges labelled with container path, dashed for `:ro`).
- [x] **v0.5** — `extends` resolution across multiple uploaded files (base by `extends.file` is matched by basename, services are merged with the standard compose convention: child overrides scalars, mappings shallow-merge, arrays concat).
- [x] **v0.6** — `include` resolution: pull whole composes into the main one. Each included file contributes its services, networks and volumes; the main wins on name collisions.
- [x] **v0.7** — `Dockerfile` inspection: upload a Dockerfile alongside the compose and DockerScope surfaces base image, multi-stage chain, `EXPOSE`, `ENV`, `WORKDIR`, `USER`, `CMD` and `ENTRYPOINT` for the matching service.
- [x] **v0.8** — Stack detection from `package.json` / `requirements.txt` / `go.mod` (matched to a service by basename prefix). Identifies framework, DB clients and queue/broker clients via dependency keywords.
- [x] **v0.9** — Container-privilege lint rules: `docker-socket-mount` (error — bind-mounting `docker.sock` is root on the host), `privileged` (error), `dangerous-cap` (error/warn for high-risk `cap_add` like `SYS_ADMIN`), and `host-namespace` (warn — `network_mode`/`pid`/`ipc: host`). The parser now surfaces `privileged`, `capAdd`, `networkMode`, `pidMode`, `ipcMode`. New **Insecure (linter demo)** sample trips every rule at once.
- [x] **v0.10** — Host-mount and escalation lint rules: `sensitive-host-mount` (error when a sensitive host path — `/`, `/etc`, `/root`, `/home`, `/boot`, `/proc`, `/sys`, `/dev`, `/usr`, `/bin`, `/sbin`, `/lib`, `/var/lib/docker` or any subpath — is bind-mounted read-write; warn when `:ro`; `docker.sock` keeps its dedicated rule) and `no-new-privileges` (warn when a service uses `cap_add` without `security_opt: no-new-privileges` — setuid binaries inside the container could otherwise escalate past the granted capabilities). The parser now surfaces `securityOpt`. The **Insecure (linter demo)** sample trips both, and a regression test pins that it trips every security rule at once.
- [x] **v0.11** — Profile and build-time lint rules: `security-unconfined` (error — `security_opt` with `seccomp:unconfined` / `apparmor:unconfined` switches off the syscall filter / MAC confinement that most container-escape chains assume is disabled; custom profiles stay unflagged) and `build-arg-secret` (error — a secret-looking key with a literal value in `build.args` is baked into the image history, where `docker history` shows it to anyone who can pull the image; BuildKit secret mounts are the fix). The parser now surfaces `buildArgs`, normalized like `environment` (both the mapping and the `KEY=value` list form). The **Insecure (linter demo)** sample trips both.
- [x] **v0.12** — First cross-service lint rule: `port-conflict` (error — two services, or two `ports` entries of the same service, publish the same host port/protocol; `docker compose up` starts the first and the second dies with "port is already allocated"). Bindings without a `host_ip` (or on `0.0.0.0`) claim the port on every interface, so they collide with interface-specific bindings too; different host IPs, protocols or ports stay unflagged, and each conflict is reported once — on its second occurrence. Ranges and interpolated ports are skipped conservatively. The **Insecure (linter demo)** sample now trips it (`app` claims `proxy`'s port 80).
- [x] **v0.13** — Second cross-service rule: `duplicate-container-name` (error — two services claim the same explicit `container_name`; names are host-global, so the second container dies with "name is already in use", and Docker Compose ≥ 2.24 refuses the file outright). The parser now surfaces `containerName`. Reported once, on the second claimant, same convention as `port-conflict`; services without an explicit name are never flagged (Compose generates unique names). The **Insecure (linter demo)** sample trips it (`agent` claims `proxy`'s `edge`).
- [x] **v0.14** — Third cross-service rule: `depends-on-unknown` (error — `depends_on` names a service that doesn't exist in the file; Compose refuses the whole file with "depends on undefined service", classically after a rename missed the `depends_on` line). Both forms resolved (list and `condition:` mapping). The graph renderer is hardened alongside: a dangling `depends_on` edge is now skipped instead of taking the whole topology view down (Cytoscape throws on edges with a nonexistent target). The **Insecure (linter demo)** sample trips it (`app` depends on a ghost `cache`).
- [x] **v0.15** — Undefined-reference rules, completing the "Compose refuses the file" family: `undeclared-network` (error — a service attaches to a network that the top-level `networks:` block doesn't declare; the implicit `default` network is exempt) and `undeclared-volume` (error — a service mounts a named volume missing from the top-level `volumes:` block; bind mounts and anonymous volumes have no name to resolve, so only named mounts are checked). Interpolated names (`${VAR}`) are skipped — the value comes from outside the file. The parser now surfaces `declaredNetworks` / `declaredVolumes` (the declared-only sets, without the implicit additions the graph uses). The **Insecure (linter demo)** sample trips both (`db` attaches to a ghost `backend` network and mounts an undeclared `pgdata` volume).
- [x] **v0.16** — Lint rule `depends-on-ignores-healthcheck` (warn): a `depends_on` pointing at a service that defines a `healthcheck`, without `condition: service_healthy`. The short form only waits for the dependency's container to *start* — the app races the database's warmup and wins just often enough to hide the bug. Fires only when the target actually has a healthcheck; `service_completed_successfully` stays quiet (one-shot jobs wait for exit, not health). The parser now keeps the long-form condition per dependency (`dependsOnConditions`, `null` for the short form) beside the flat `depends_on` name list. The **Insecure (linter demo)** sample's `db` gains a `pg_isready` healthcheck so `app`'s short-form dependency trips it.
- [x] **v0.17** — Lint rule `command-secret` (error), completing the secrets trio with `env-secret` and `build-arg-secret`: a literal secret passed via `command` / `entrypoint` shows up in `docker inspect`, `docker compose config` and `ps` inside the container. Three shapes detected: secret-looking flags with separate value (`--requirepass hunter2`), `flag=value` (`--api-token=sk-…`) and inline env assignments (`MYSQL_PASSWORD=x cmd`). Interpolations (`${VAR}` / `$VAR`) are values from outside the file, and paths (`/run/secrets/db`, `./certs/key.pem`) are *references* to a secret rather than the secret — both skipped, which also keeps `--tlsCertificateKeyFile /certs/key.pem` from false-positiving on "key". Findings name the offending flag but never echo the value back. The parser now surfaces `command` / `entrypoint` (string form kept, exec-form list space-joined). The **Insecure (linter demo)** sample's `app` gains a `--api-token` that trips it.
- [x] **v0.18** — Runtime-contract lint rules: `container-name-with-replicas` (error — `container_name` together with `deploy.replicas` > 1, or the legacy service-level `scale`; a container name is unique on the host, so a fixed name can't be replicated and Compose refuses the file up front — joins the "Compose refuses the file" family) and `healthcheck-no-start-period` (warn — a `healthcheck` without `start_period`: the grace period defaults to 0s, so probe failures during boot count against `retries` and a slow starter — JVM warmup, DB crash recovery — flaps to unhealthy before it ever gets going, leaving any `condition: service_healthy` dependent waiting forever; pairs with `depends-on-ignores-healthcheck`, which guards the other side of the same contract). The parser now surfaces `replicas` (from `deploy.replicas` or `scale`, plain numbers only). The **Insecure (linter demo)** sample's `proxy` gains `replicas: 2` under its fixed name and `db`'s healthcheck stays graceless — both trip.
- [x] **v0.19** — Lint rule `no-memory-limit` (warn): a service with no memory cap competes with everything else on the host — one leak and the kernel OOM killer starts shooting host-wide, other containers and the Docker daemon included. Either spelling counts as capped: the modern `deploy.resources.limits.memory` (applied by `docker compose` outside Swarm since v2) or the legacy service-level `mem_limit`; a `limits:` block that only caps `cpus` still fires, because memory is what kills hosts. The parser now surfaces `memoryLimit`, normalized to a string from either source. Joins `no-restart` / `no-healthcheck` in the operational-hygiene family; every service of the **Insecure (linter demo)** sample trips it out of the box.
- [x] **v0.20** — Lint rule `no-pids-limit` (warn), completing the resource-caps pair with `no-memory-limit`: memory kills by OOM, PIDs kill by exhaustion. A container with no PID cap can fill the host's process table — a fork bomb (or a runaway worker pool) starves every process on the machine, including the shell you'd use to fix it — and unlike memory, the kernel has no "PID killer" to bail the host out. Either spelling counts as capped: `deploy.resources.limits.pids` (integer) or the legacy service-level `pids_limit`. The parser now surfaces `pidsLimit`, normalized to a number from either source. Every service of the **Insecure (linter demo)** sample trips it out of the box.
- [x] **v0.21** — Lint rule `no-cap-drop` (warn): Docker starts every container with ~14 Linux capabilities the app almost never needs (`CHOWN`, `SETUID`, `NET_RAW`, `MKNOD`…). Least privilege is `cap_drop: [ALL]` then `cap_add` only what's required; a container that never drops `ALL` keeps the whole default set — extra kernel surface an escape can reach for. Only dropping `ALL` clears it — a partial drop is better than nothing but still isn't least privilege. Completes the capability story with `dangerous-cap` (which flags risky caps *added*) and `no-new-privileges`: this one flags the baseline never being *dropped*. The parser now surfaces `capDrop`. Every service of the **Insecure (linter demo)** sample trips it.
- [x] **v0.22** — Lint rule `no-read-only` (warn): a writable root filesystem is what turns a foothold into a base of operations — a compromised process can drop tooling, patch binaries and persist for the session. `read_only: true` makes the image content immutable at runtime and costs one line; apps that need scratch space keep it via explicit `tmpfs` / volume mounts, which is the point — writable paths become a deliberate inventory instead of the default. Completes the least-privilege trio: `no-cap-drop` (kernel surface), `no-new-privileges` (escalation), and this one (filesystem). Volumes stay writable — the rule judges only the rootfs. The parser now surfaces `readOnly`; the clean fixture needed `read_only: true` (sixth time the pattern repeats).
- [x] **v0.23** — Lint rule `no-log-limit` (warn): Docker's default logging driver (`json-file`) keeps everything a container ever wrote to stdout/stderr, unrotated — a chatty or misbehaving service fills the host disk from `/var/lib/docker/containers`, and the classic discovery path is "why is the box read-only?" at 3am. One line bounds it: `logging.options.max-size` (plus `max-file`). Drivers other than `json-file` are spared — `local` rotates by default, journald/syslog/fluentd/gelf hand the stream to a system with its own retention, `none` keeps nothing. Completes the disk-safety trio with `no-memory-limit` (RAM) and `no-pids-limit` (process table). The parser now surfaces `logDriver` / `logMaxSize`; the clean fixture needed `max-size: "10m"` (seventh time the pattern repeats).
- [x] **v0.24** — Healthcheck-contract lint rules, the mirror pair of v0.16/v0.18: `service-healthy-no-healthcheck` (error, cross-service — `condition: service_healthy` pointing at a service with no healthcheck, or one disabled via `disable: true` / `test: NONE`: that health signal will never be sent, and Compose refuses to start the dependent — 'dependency has no healthcheck configured'; unknown targets stay quiet, `depends-on-unknown` owns those) and `healthcheck-test-invalid` (error — `healthcheck.test` in list form must start with `CMD`, `CMD-SHELL` or `NONE`; `test: ["curl", "-f", …]` looks perfectly plausible and Compose refuses the whole file, joining the file-rejecting family; interpolated first items are skipped). Where v0.16 flagged "you have a healthcheck but don't wait for it", these flag "you wait for health that will never be reported" and "your probe never parses". The **Insecure (linter demo)** sample's `proxy` now waits on `app`'s nonexistent health and `agent` gains a prefix-less probe — both trip.
- [x] **v0.25** — Lint rule `duplicate-env-key` (warn): a list-form `environment` — or build `args` — that names the same key twice, e.g. `["LOG_LEVEL=debug", "LOG_LEVEL=info"]`. Nothing errors and the **last one silently wins**, so the file reads one way and the container runs another; the usual bite is editing one occurrence and leaving the stale twin above it. Only the list form can express a duplicate — map form (`environment: {LOG_LEVEL: info}`) is collapsed by YAML — so the rule never false-positives on the map syntax. Reported once per duplicated key. The **Insecure (linter demo)** sample's `app` gains a duplicated `LOG_LEVEL`. (Considered a profiles/`depends_on` rule first, but Compose's auto-enable behaviour there has shifted across versions and couldn't be pinned down without the CLI to verify — deferred rather than guess.)

> **Out of scope, on purpose**: parsing the application source code (Express routes, SQL schemas, Python modules) is a different problem — that's a code analyzer, not a Docker analyzer. DockerScope stays focused on what Docker itself describes: services, images, networks, ports, volumes, and the build recipe.

## Stack

Pure HTML + CSS + vanilla JS. No build step, no bundler, no backend.

- [`js-yaml`](https://github.com/nodeca/js-yaml) — YAML parsing.
- [`Cytoscape.js`](https://js.cytoscape.org/) + [`cytoscape-fcose`](https://github.com/iVis-at-Bilkent/cytoscape.js-fcose) — graph rendering and force-directed layout with compound-node support (so networks can wrap their services).
- [`cytoscape-svg`](https://github.com/kaluginserg/cytoscape-svg) — SVG export.

All loaded from CDN; no `npm install` required to run the app.

## Tests

The compose / Dockerfile / manifest parsers and the linter are covered by a [`node:test`](https://nodejs.org/api/test.html) suite. Each module hangs its API off `window`, so the tests load them into a Node `vm` sandbox whose global doubles as `window` (with the same `js-yaml` the page pulls from CDN), and assert against the fixtures in `samples/`: the service model, `include:` / `extends:` resolution, stack detection from build manifests, multi-stage Dockerfile parsing, and every lint rule.

```bash
npm install   # dev only: ESLint + js-yaml (running the app needs no install)
npm test      # node --test over test/*.test.js
```

CI runs ESLint **and** this suite on every push and pull request.

## Lint rules

| Rule | Level | Triggered when |
|------|-------|----------------|
| `image-latest` / `image-untagged` | warn | image tag is `latest` or absent (Docker silently pulls `latest`) |
| `env-secret` | **error** | `environment` has a key matching `*PASSWORD*`, `*SECRET*`, `*TOKEN*`, `*KEY*` with a literal value (interpolations like `${VAR}` are fine) |
| `duplicate-env-key` | warn | a list-form `environment` (or build `args`) names the same key twice — only the last value takes effect, so the file and the running container disagree |
| `port-public` | warn | a database / cache image (Postgres, MySQL, Mongo, Redis, Elastic, Kafka…) publishes a port on `0.0.0.0` instead of `127.0.0.1:` |
| `docker-socket-mount` | **error** | a service bind-mounts `docker.sock` — full control of the host daemon (root-equivalent) |
| `privileged` | **error** | service runs in `privileged` mode (all capabilities and devices) |
| `dangerous-cap` | **error** / warn | `cap_add` grants a high-risk capability (`SYS_ADMIN` / `ALL` = error; `NET_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, `SYS_RAWIO`, `DAC_READ_SEARCH` = warn) |
| `host-namespace` | warn | `network_mode: host`, `pid: host` or `ipc: host` — shares a host namespace |
| `sensitive-host-mount` | **error** / warn | a sensitive host path (`/`, `/etc`, `/root`, `/proc`, `/var/lib/docker`…) is bind-mounted — error read-write, warn `:ro` |
| `no-new-privileges` | warn | `cap_add` grants capabilities without `security_opt: no-new-privileges` — setuid binaries could escalate past them |
| `security-unconfined` | **error** | `security_opt` disables seccomp or AppArmor (`seccomp:unconfined` / `apparmor:unconfined`) — most container escapes assume exactly this |
| `build-arg-secret` | **error** | `build.args` has a key matching `*PASSWORD*`, `*SECRET*`, `*TOKEN*`, `*KEY*` with a literal value — build args are baked into the image history (`docker history` shows them) |
| `command-secret` | **error** | `command` / `entrypoint` passes a literal secret — a secret-looking flag (`--password=x`, `--requirepass x`, `--api-token x`) or an inline env assignment (`MYSQL_PASSWORD=x cmd`); visible in `docker inspect`, `docker compose config` and `ps`. Interpolations (`${VAR}`) and file paths (`/run/secrets/…`) are fine |
| `port-conflict` | **error** | two services (or two entries of one service) publish the same host port — the second container to start fails with "port is already allocated"; a `0.0.0.0` binding collides with any interface-specific one |
| `duplicate-container-name` | **error** | two services claim the same `container_name` — names are host-global, so the second container fails with "name is already in use" (Compose ≥ 2.24 refuses the file outright) |
| `container-name-with-replicas` | **error** | a service sets both `container_name` and `deploy.replicas` (or legacy `scale`) > 1 — a fixed name can't be replicated, Compose refuses the file |
| `healthcheck-no-start-period` | warn | a `healthcheck` has no `start_period` — the grace defaults to 0s, so probe failures during boot count against `retries` and a slow starter flaps to unhealthy |
| `depends-on-unknown` | **error** | `depends_on` references a service that doesn't exist in the file — Compose refuses the whole file; classic aftermath of a rename that missed the `depends_on` line |
| `depends-on-ignores-healthcheck` | warn | `depends_on` on a service that defines a `healthcheck`, without `condition: service_healthy` — the short form only waits for the container to *start*, so the app races the dependency's warmup |
| `service-healthy-no-healthcheck` | **error** | `condition: service_healthy` on a service with no (or a disabled) `healthcheck` — the condition can never be met and Compose refuses to start the dependent |
| `healthcheck-test-invalid` | **error** | `healthcheck.test` in list form doesn't start with `CMD`, `CMD-SHELL` or `NONE` — Compose refuses the whole file |
| `undeclared-network` | **error** | a service attaches to a network missing from the top-level `networks:` block — Compose refuses the whole file (the implicit `default` network is exempt) |
| `undeclared-volume` | **error** | a service mounts a named volume missing from the top-level `volumes:` block — Compose refuses the whole file (bind mounts and anonymous volumes have no name to resolve) |
| `no-restart` | warn | service has no `restart` policy |
| `no-healthcheck` | warn | service has no `healthcheck` |
| `no-memory-limit` | warn | service has no memory cap (`deploy.resources.limits.memory` or legacy `mem_limit`) — a leak can trigger the host's OOM killer |
| `no-pids-limit` | warn | service has no PID cap (`deploy.resources.limits.pids` or legacy `pids_limit`) — a fork bomb can exhaust the host's process table |
| `no-cap-drop` | warn | service keeps Docker's default capabilities — no `cap_drop: [ALL]`; least privilege is drop-all then `cap_add` only what's needed |
| `no-read-only` | warn | service runs with a writable root filesystem — no `read_only: true`; an immutable rootfs turns writable paths into a deliberate inventory (`tmpfs`, volumes) instead of the default |
| `no-log-limit` | warn | default `json-file` logging with no `max-size` — container logs grow unbounded until the host disk fills; rotating drivers (`local`, journald, …) are spared |

Try them all at once with the **Insecure (linter demo)** sample.

## About

Built by **[Danny Ruiz](https://github.com/DannyRuizB)** — systems & network administrator (ASIR, *Administración de Sistemas Informáticos en Red*). [More projects →](https://github.com/DannyRuizB?tab=repositories)

## License

MIT © Danny Ruiz Boluda
