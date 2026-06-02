// Parses language manifests (package.json, requirements.txt, go.mod) into a
// stack model with framework / DB clients / queue clients classified by name.
// Output of parseManifest:
// {
//   language: "Node" | "Python" | "Go",
//   languageVersion: string | null,   // sometimes available (go.mod), else null
//   framework: string | null,
//   dbClients: [string],              // human-readable labels
//   queueClients: [string],
//   depCount: number,
// }

window.DockerScope = window.DockerScope || {};

window.DockerScope.parseManifest = function (filename, text) {
  if (!filename || text == null) return null;
  const lower = String(filename).toLowerCase();
  if (lower.endsWith("package.json")) return parsePackageJson(text);
  if (lower.endsWith("requirements.txt")) return parseRequirementsTxt(text);
  if (lower.endsWith("go.mod")) return parseGoMod(text);
  return null;
};

const NODE_FRAMEWORKS = [
  ["next", "Next.js"],
  ["@nestjs/core", "NestJS"],
  ["express", "Express"],
  ["fastify", "Fastify"],
  ["koa", "Koa"],
  ["@hapi/hapi", "Hapi"],
  ["hapi", "Hapi"],
];
const NODE_DB = [
  ["pg", "PostgreSQL (pg)"],
  ["postgres", "PostgreSQL (postgres)"],
  ["mysql2", "MySQL (mysql2)"],
  ["mysql", "MySQL (mysql)"],
  ["mongodb", "MongoDB (mongodb)"],
  ["mongoose", "MongoDB (mongoose)"],
  ["@prisma/client", "Prisma"],
  ["prisma", "Prisma"],
  ["sequelize", "Sequelize"],
  ["typeorm", "TypeORM"],
  ["knex", "Knex"],
  ["redis", "Redis (redis)"],
  ["ioredis", "Redis (ioredis)"],
  ["better-sqlite3", "SQLite (better-sqlite3)"],
  ["sqlite3", "SQLite"],
];
const NODE_QUEUE = [
  ["bullmq", "BullMQ"],
  ["bull", "Bull"],
  ["amqplib", "AMQP / RabbitMQ"],
  ["kafkajs", "Kafka"],
  ["nats", "NATS"],
  ["agenda", "Agenda"],
  ["bee-queue", "Bee Queue"],
];

function parsePackageJson(text) {
  let data;
  try { data = JSON.parse(text); } catch (_) { return null; }
  if (!data || typeof data !== "object") return null;
  const deps = { ...(data.dependencies || {}), ...(data.devDependencies || {}) };
  const has = (n) => Object.prototype.hasOwnProperty.call(deps, n);
  return {
    language: "Node",
    languageVersion: null,
    framework: pickFirst(NODE_FRAMEWORKS, has),
    dbClients: pickAll(NODE_DB, has),
    queueClients: pickAll(NODE_QUEUE, has),
    depCount: Object.keys(deps).length,
  };
}

const PY_FRAMEWORKS = [
  ["django", "Django"],
  ["fastapi", "FastAPI"],
  ["flask", "Flask"],
  ["starlette", "Starlette"],
  ["aiohttp", "aiohttp"],
  ["tornado", "Tornado"],
];
const PY_DB = [
  ["psycopg2", "PostgreSQL (psycopg2)"],
  ["psycopg2-binary", "PostgreSQL (psycopg2-binary)"],
  ["psycopg", "PostgreSQL (psycopg3)"],
  ["asyncpg", "PostgreSQL (asyncpg)"],
  ["pymysql", "MySQL (pymysql)"],
  ["mysqlclient", "MySQL (mysqlclient)"],
  ["pymongo", "MongoDB (pymongo)"],
  ["motor", "MongoDB (motor)"],
  ["redis", "Redis (redis-py)"],
  ["sqlalchemy", "SQLAlchemy"],
  ["peewee", "Peewee"],
];
const PY_QUEUE = [
  ["celery", "Celery"],
  ["pika", "AMQP / RabbitMQ (pika)"],
  ["kafka-python", "Kafka"],
  ["confluent-kafka", "Kafka (confluent)"],
  ["rq", "RQ"],
  ["dramatiq", "Dramatiq"],
  ["nats-py", "NATS"],
];

function parseRequirementsTxt(text) {
  const names = new Set();
  for (const raw of String(text).split(/\r?\n/)) {
    const stripped = raw.replace(/#.*$/, "").trim();
    if (!stripped) continue;
    if (stripped.startsWith("-")) continue; // -r, -e, --extra-index-url
    const m = stripped.match(/^([A-Za-z0-9_.-]+)/);
    if (m) names.add(m[1].toLowerCase());
  }
  if (names.size === 0) return null;
  const has = (n) => names.has(n.toLowerCase());
  return {
    language: "Python",
    languageVersion: null,
    framework: pickFirst(PY_FRAMEWORKS, has),
    dbClients: pickAll(PY_DB, has),
    queueClients: pickAll(PY_QUEUE, has),
    depCount: names.size,
  };
}

const GO_FRAMEWORKS = [
  ["gin-gonic/gin", "Gin"],
  ["labstack/echo", "Echo"],
  ["gofiber/fiber", "Fiber"],
  ["gorilla/mux", "Gorilla Mux"],
  ["go-chi/chi", "chi"],
];
const GO_DB = [
  ["jackc/pgx", "PostgreSQL (pgx)"],
  ["lib/pq", "PostgreSQL (lib/pq)"],
  ["go-sql-driver/mysql", "MySQL"],
  ["mongo-driver", "MongoDB"],
  ["redis/go-redis", "Redis"],
  ["go-redis/redis", "Redis"],
  ["gorm.io/gorm", "GORM"],
  ["mattn/go-sqlite3", "SQLite"],
];
const GO_QUEUE = [
  ["rabbitmq/amqp091-go", "AMQP / RabbitMQ"],
  ["streadway/amqp", "AMQP / RabbitMQ (streadway)"],
  ["segmentio/kafka-go", "Kafka"],
  ["confluentinc/confluent-kafka-go", "Kafka (confluent)"],
  ["nats-io/nats.go", "NATS"],
];

function parseGoMod(text) {
  const requires = [];
  let inBlock = false;
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.replace(/\/\/.*$/, "").trim();
    if (!line) continue;
    if (/^require\s*\(/.test(line)) { inBlock = true; continue; }
    if (line === ")" && inBlock) { inBlock = false; continue; }
    let candidate = line;
    if (line.startsWith("require ")) candidate = line.slice("require ".length).trim();
    else if (!inBlock) continue;
    const m = candidate.match(/^(\S+)\s+v\S+/);
    if (m) requires.push(m[1].toLowerCase());
  }

  const goVersion = (text.match(/^go\s+(\S+)/m) || [])[1] || null;

  if (requires.length === 0 && !goVersion) return null;

  const has = (substr) => requires.some(r => r.includes(substr.toLowerCase()));
  return {
    language: "Go",
    languageVersion: goVersion,
    framework: pickFirst(GO_FRAMEWORKS, has),
    dbClients: pickAll(GO_DB, has),
    queueClients: pickAll(GO_QUEUE, has),
    depCount: requires.length,
  };
}

function pickFirst(table, hasFn) {
  for (const [needle, label] of table) if (hasFn(needle)) return label;
  return null;
}

function pickAll(table, hasFn) {
  const seen = new Set();
  const out = [];
  for (const [needle, label] of table) {
    if (hasFn(needle) && !seen.has(label)) { seen.add(label); out.push(label); }
  }
  return out;
}

// Tries to read a language version from a Dockerfile FROM line of the form
// `node:20-alpine`, `python:3.12-slim`, `golang:1.21`. Returns the bare
// version string or null.
window.DockerScope.languageVersionFromDockerfile = function (dockerfile, language) {
  if (!dockerfile || !dockerfile.finalStage) return null;
  const from = dockerfile.finalStage.from || "";
  const m = from.match(/^([a-z]+):([0-9]+(\.[0-9]+)*)/i);
  if (!m) return null;
  const langMap = { node: "Node", python: "Python", golang: "Go", go: "Go" };
  const detected = langMap[m[1].toLowerCase()];
  if (!detected || detected !== language) return null;
  return m[2];
};
