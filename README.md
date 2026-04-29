# DockerScope

> Visual analyzer for `docker-compose.yml` — paste a compose file, see the architecture.

### [Try the live demo →](https://dannyruizb.github.io/dockerscope/)

![DockerScope rendering the sample compose: frontend and backend networks drawn as dashed compound containers wrapping their services. Lint severity in the borders (db red, api/cache/worker amber, web clean). Three volume nodes are also visible — db-data as a gray cylinder under db, ./nginx-conf as an amber tag attached to web with a dashed edge labelled "/etc/nginx/conf.d (ro)", and /var/run/docker.sock as an amber tag attached to worker.](screenshots/screenshot.png)

DockerScope is a **client-side, zero-backend** tool that parses a `docker-compose.yml` file and renders:

- A **cluster-style service graph** where each network is drawn as a dashed container that visually wraps the services running on it (its first declared network); extra-network membership becomes a dashed edge so nothing is lost.
- A **lint panel** (collapsible) flagging floating tags, plaintext secrets, databases exposed on `0.0.0.0`, missing `restart` policy and missing healthchecks. Each finding ships with a hint on how to fix it, and affected services are highlighted on the graph.
- A **port table** listing every published port grouped by service.
- **Volumes on the graph** — named volumes appear as gray cylinders, host bind mounts as amber tags. Each mount edge is labelled with the path inside the container, with a dashed line for read-only mounts. Bind mounts are highlighted in amber because they're the most common way a container leaks host state (think `~/.ssh:ro` or `/var/run/docker.sock`).
- **Paste, upload, or drag & drop** your compose file — everything runs in the browser.
- **Pop out the graph** into a real OS window with the `↗` button — drag it to a second monitor while you keep editing in the main one.
- **Download the graph** as PNG or SVG with the `⤓` button — the SVG keeps the original colors and is fully editable in Inkscape / Figma.

🚧 Work in progress — v0.4.0.

---

## Why

Reviewing a `docker-compose.yml` from a teammate, a tutorial, or a homelab project usually means scrolling through YAML and building the architecture in your head. DockerScope flips that: paste the file, see the architecture.

It is intentionally **not** a wrapper around `docker compose config` — it runs entirely in the browser, so no Docker daemon, no upload, no server.

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

## Roadmap

- [x] **v0.1** — Parse compose, render service graph (`depends_on` + networks), list ports, file upload + drag & drop.
- [x] **v0.2** — Static linter: floating tags, plaintext secrets in `environment`, public DB/cache ports, missing `restart`, missing healthchecks. Findings highlight affected services on the graph.
- [x] **v0.3** — Export graph to PNG / SVG.
- [x] **v0.4** — Volumes as nodes (named cylinders + host bind tags, mount edges labelled with container path, dashed for `:ro`).
- [ ] **v0.5** — `extends` / `include` resolution (multi-file upload).
- [ ] **v0.6** — `Dockerfile` analyzer: drop a `Dockerfile` next to the compose to surface base image, multi-stage builds, and `EXPOSE` / `ENV` / `CMD` per service.
- [ ] **v0.7** — Stack detection from `package.json` / `requirements.txt` / `go.mod` to label each service with its framework, DB driver, and queue client.

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

## License

MIT © Danny Ruiz Boluda
