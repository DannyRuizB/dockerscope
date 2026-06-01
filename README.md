# DockerScope

> Visual analyzer for `docker-compose.yml` — paste a compose file, see the architecture.

[![lint](https://github.com/DannyRuizB/dockerscope/actions/workflows/lint.yml/badge.svg)](https://github.com/DannyRuizB/dockerscope/actions/workflows/lint.yml)

### [Try the live demo →](https://dannyruizb.github.io/dockerscope/)

![DockerScope on the stack-detection sample: chips above the textarea show stack-main.yml as main alongside api.Dockerfile, api.package.json, worker.Dockerfile and worker.requirements.txt. The graph renders api, worker, db, cache, broker and the db-data named volume; lint severity is reflected in the borders (db red for plaintext POSTGRES_PASSWORD, api/worker amber for missing restart and healthcheck, cache and broker clean). Below the graph: Lint is collapsed, Dockerfiles shows the worker entry (python:3.12-slim, WORKDIR /app, ENTRYPOINT and CMD), and Stack shows api as Node 20 + Express + PostgreSQL (pg) + Redis (ioredis) + BullMQ + AMQP/RabbitMQ sourced from api.package.json, and worker as Python 3.12 + FastAPI + PostgreSQL (psycopg2-binary) + Celery + AMQP/RabbitMQ (pika) sourced from worker.requirements.txt.](screenshots/screenshot.png)

DockerScope is a **client-side, zero-backend** tool that parses a `docker-compose.yml` file and renders:

- A **cluster-style service graph** where each network is drawn as a dashed container that visually wraps the services running on it (its first declared network); extra-network membership becomes a dashed edge so nothing is lost.
- A **lint panel** (collapsible) flagging floating tags, plaintext secrets, databases exposed on `0.0.0.0`, missing `restart` policy and missing healthchecks. Each finding ships with a hint on how to fix it, and affected services are highlighted on the graph.
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

> **Out of scope, on purpose**: parsing the application source code (Express routes, SQL schemas, Python modules) is a different problem — that's a code analyzer, not a Docker analyzer. DockerScope stays focused on what Docker itself describes: services, images, networks, ports, volumes, and the build recipe.

## Stack

Pure HTML + CSS + vanilla JS. No build step, no bundler, no backend.

- [`js-yaml`](https://github.com/nodeca/js-yaml) — YAML parsing.
- [`Cytoscape.js`](https://js.cytoscape.org/) + [`cytoscape-fcose`](https://github.com/iVis-at-Bilkent/cytoscape.js-fcose) — graph rendering and force-directed layout with compound-node support (so networks can wrap their services).
- [`cytoscape-svg`](https://github.com/kaluginserg/cytoscape-svg) — SVG export.

All loaded from CDN; no `npm install` required.

## Lint rules (v0.2)

| Rule | Level | Triggered when |
|------|-------|----------------|
| `image-latest` / `image-untagged` | warn | image tag is `latest` or absent (Docker silently pulls `latest`) |
| `env-secret` | **error** | `environment` has a key matching `*PASSWORD*`, `*SECRET*`, `*TOKEN*`, `*KEY*` with a literal value (interpolations like `${VAR}` are fine) |
| `port-public` | warn | a database / cache image (Postgres, MySQL, Mongo, Redis, Elastic, Kafka…) publishes a port on `0.0.0.0` instead of `127.0.0.1:` |
| `no-restart` | warn | service has no `restart` policy |
| `no-healthcheck` | warn | service has no `healthcheck` |

## About

Built by **[Danny Ruiz](https://github.com/DannyRuizB)** — systems & network administrator (ASIR, *Administración de Sistemas Informáticos en Red*). [More projects →](https://github.com/DannyRuizB?tab=repositories)

## License

MIT © Danny Ruiz Boluda
