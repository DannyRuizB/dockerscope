'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { loadDockerScope, sample } = require('./helper');

const DS = loadDockerScope();

test('lint flags the smells present in example.yml', () => {
  const { findings } = DS.lint(DS.parseCompose(sample('example.yml')));
  const rules = new Set(findings.map((f) => f.rule));
  for (const r of ['no-healthcheck', 'env-secret', 'port-public', 'no-restart', 'image-latest']) {
    assert.ok(rules.has(r), `expected rule '${r}'`);
  }
  const f0 = findings[0];
  for (const k of ['service', 'level', 'rule', 'message']) {
    assert.ok(k in f0, `finding should carry '${k}'`);
  }
});

test('image-untagged and image-latest fire on bare / :latest images', () => {
  const yaml = ['services:', '  a:', '    image: redis', '  b:', '    image: nginx:latest'].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  const byService = {};
  for (const f of findings) (byService[f.service] ||= new Set()).add(f.rule);
  assert.ok(byService.a.has('image-untagged'), 'a → image-untagged');
  assert.ok(byService.b.has('image-latest'), 'b → image-latest');
});

test('env-secret is an error and worstLevelByService surfaces it', () => {
  const { findings } = DS.lint(DS.parseCompose(sample('example.yml')));
  assert.ok(findings.some((f) => f.rule === 'env-secret' && f.level === 'error'));

  const worst = DS.worstLevelByService(findings);
  assert.equal(worst.db, 'error');
});

test('port-public fires when a database image publishes to 0.0.0.0', () => {
  const yaml = [
    'services:',
    '  db:',
    '    image: postgres:16',
    '    restart: unless-stopped',
    '    healthcheck:',
    '      test: ["CMD", "true"]',
    '    ports: ["5432:5432"]',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  assert.ok(findings.some((f) => f.service === 'db' && f.rule === 'port-public'));
});

test('port-public does NOT fire when the port is bound to 127.0.0.1', () => {
  const yaml = [
    'services:',
    '  db:',
    '    image: postgres:16',
    '    restart: unless-stopped',
    '    healthcheck:',
    '      test: ["CMD", "true"]',
    '    ports: ["127.0.0.1:5432:5432"]',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  assert.ok(!findings.some((f) => f.rule === 'port-public'));
});

test('a fully-specified service produces no findings', () => {
  const yaml = [
    'services:',
    '  ok:',
    '    image: nginx:1.27',
    '    restart: unless-stopped',
    '    cap_drop: ["ALL"]',
    '    read_only: true',
    '    logging:',
    '      driver: json-file',
    '      options:',
    '        max-size: "10m"',
    '    healthcheck:',
    '      test: ["CMD", "true"]',
    '      start_period: 10s',
    '    deploy:',
    '      resources:',
    '        limits:',
    '          memory: 512M',
    '          pids: 256',
    "          cpus: '0.50'",
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  assert.equal(findings.filter((f) => f.service === 'ok').length, 0);
});

test('docker-socket-mount is an error and notes read-only', () => {
  const yaml = [
    'services:',
    '  proxy:',
    '    image: traefik:3.1',
    '    restart: unless-stopped',
    '    healthcheck:',
    '      test: ["CMD", "true"]',
    '    volumes:',
    '      - /var/run/docker.sock:/var/run/docker.sock:ro',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  const f = findings.find((x) => x.rule === 'docker-socket-mount');
  assert.ok(f && f.level === 'error', 'docker socket flagged as error');
  assert.match(f.message, /read-only/);
});

test('privileged mode is flagged as an error', () => {
  const yaml = ['services:', '  x:', '    image: alpine:3.20', '    privileged: true'].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  assert.ok(findings.some((f) => f.rule === 'privileged' && f.level === 'error'));
});

test('host namespaces (network_mode / pid / ipc: host) are flagged', () => {
  const yaml = [
    'services:',
    '  x:',
    '    image: alpine:3.20',
    '    network_mode: host',
    '    pid: host',
  ].join('\n');
  const rules = new Set(DS.lint(DS.parseCompose(yaml)).findings.map((f) => f.rule));
  assert.ok(rules.has('host-namespace'));
});

test('dangerous capabilities are flagged (SYS_ADMIN as error, NET_ADMIN as warn)', () => {
  const yaml = [
    'services:',
    '  x:',
    '    image: alpine:3.20',
    '    cap_add: ["SYS_ADMIN", "NET_ADMIN", "CHOWN"]',
  ].join('\n');
  const caps = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'dangerous-cap');
  // SYS_ADMIN + NET_ADMIN flagged; the benign CHOWN is not.
  assert.equal(caps.length, 2);
  assert.ok(caps.some((f) => f.message.includes('SYS_ADMIN') && f.level === 'error'));
  assert.ok(caps.some((f) => f.message.includes('NET_ADMIN') && f.level === 'warn'));
});

test('sensitive-host-mount: rw is error, ro is warn, benign paths pass', () => {
  const yaml = [
    'services:',
    '  x:',
    '    image: alpine:3.20',
    '    volumes:',
    '      - /etc:/host-etc',
    '      - /proc:/host-proc:ro',
    '      - /opt/app/data:/data',
    '      - namedvol:/var/lib/app',
    'volumes:',
    '  namedvol:',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'sensitive-host-mount');
  assert.equal(found.length, 2);
  assert.ok(found.some((f) => f.message.includes('/etc') && f.level === 'error'));
  assert.ok(found.some((f) => f.message.includes('/proc') && f.level === 'warn'));
});

test('sensitive-host-mount catches subpaths and bare / but not docker.sock', () => {
  const yaml = [
    'services:',
    '  x:',
    '    image: alpine:3.20',
    '    volumes:',
    '      - /:/host',
    '      - /var/lib/docker/volumes:/dv',
    '      - /var/run/docker.sock:/var/run/docker.sock',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'sensitive-host-mount');
  assert.equal(found.length, 2); // "/" + /var/lib/docker subpath; the socket has its own rule
  assert.ok(found.every((f) => f.level === 'error'));
});

test('no-new-privileges warns on cap_add without the security_opt', () => {
  const yaml = [
    'services:',
    '  x:',
    '    image: alpine:3.20',
    '    cap_add: ["NET_BIND_SERVICE"]',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  assert.ok(findings.some((f) => f.rule === 'no-new-privileges' && f.level === 'warn'));
});

test('no-new-privileges stays quiet when the option is set (or nothing is added)', () => {
  const yaml = [
    'services:',
    '  a:',
    '    image: alpine:3.20',
    '    cap_add: ["NET_BIND_SERVICE"]',
    '    security_opt:',
    '      - no-new-privileges:true',
    '  b:',
    '    image: alpine:3.20',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  assert.ok(!findings.some((f) => f.rule === 'no-new-privileges'));
});

test('security-unconfined flags seccomp/apparmor unconfined but not custom profiles', () => {
  const yaml = [
    'services:',
    '  x:',
    '    image: alpine:3.20',
    '    security_opt:',
    '      - seccomp:unconfined',
    '      - apparmor=unconfined',
    '  y:',
    '    image: alpine:3.20',
    '    security_opt:',
    '      - seccomp:./custom-profile.json',
    '      - no-new-privileges:true',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'security-unconfined');
  // Both the `:` and `=` spellings are caught; the custom profile is not.
  assert.equal(found.length, 2);
  assert.ok(found.every((f) => f.service === 'x' && f.level === 'error'));
});

test('build-arg-secret flags a literal secret but not interpolations or benign args', () => {
  const yaml = [
    'services:',
    '  app:',
    '    build:',
    '      context: .',
    '      args:',
    '        API_TOKEN: sk-live-123456',
    '        DB_PASSWORD: ${DB_PASSWORD}',
    '        NODE_VERSION: "24"',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'build-arg-secret');
  // Only the literal API_TOKEN; the interpolation and the benign arg pass.
  assert.equal(found.length, 1);
  assert.ok(found[0].message.includes('API_TOKEN') && found[0].level === 'error');
});

test('build-arg-secret handles the list form of build.args', () => {
  const yaml = [
    'services:',
    '  app:',
    '    build:',
    '      context: .',
    '      args:',
    '        - SECRET_KEY=hunter2',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  assert.ok(findings.some((f) => f.rule === 'build-arg-secret'));
});

test('port-conflict fires once, on the second service claiming the host port', () => {
  const yaml = [
    'services:',
    '  web:',
    '    image: nginx:1.27',
    '    ports: ["8080:80"]',
    '  admin:',
    '    image: nginx:1.27',
    '    ports: ["8080:81"]',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  const conflicts = findings.filter((f) => f.rule === 'port-conflict');
  assert.equal(conflicts.length, 1, 'one finding, not one per side');
  assert.equal(conflicts[0].service, 'admin');
  assert.equal(conflicts[0].level, 'error');
  assert.match(conflicts[0].message, /web/);
});

test('port-conflict understands 0.0.0.0 as colliding with a specific host IP', () => {
  const yaml = [
    'services:',
    '  a:',
    '    image: nginx:1.27',
    '    ports: ["127.0.0.1:5432:5432"]',
    '  b:',
    '    image: nginx:1.27',
    '    ports: ["5432:5432"]',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  assert.ok(findings.some((f) => f.rule === 'port-conflict' && f.service === 'b'));
});

test('port-conflict stays quiet on different ports, protocols, or host IPs', () => {
  const yaml = [
    'services:',
    '  a:',
    '    image: nginx:1.27',
    '    ports:',
    '      - "127.0.0.1:6000:6000"',
    '      - "53:53/tcp"',
    '  b:',
    '    image: nginx:1.27',
    '    ports:',
    '      - "127.0.0.2:6000:6000"',
    '      - "53:53/udp"',
    '      - "8080:80"',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  assert.ok(!findings.some((f) => f.rule === 'port-conflict'));
});

test('port-conflict flags a port published twice by the same service', () => {
  const yaml = [
    'services:',
    '  a:',
    '    image: nginx:1.27',
    '    ports:',
    '      - "8080:80"',
    '      - "8080:81"',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  const conflicts = findings.filter((f) => f.rule === 'port-conflict');
  assert.equal(conflicts.length, 1);
  assert.match(conflicts[0].message, /twice/);
});

test('duplicate-container-name fires once, on the second claimant', () => {
  const yaml = [
    'services:',
    '  a:',
    '    image: nginx:1.27',
    '    container_name: web',
    '  b:',
    '    image: nginx:1.27',
    '    container_name: web',
    '  c:',
    '    image: nginx:1.27',
    '    container_name: other',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  const dups = findings.filter((f) => f.rule === 'duplicate-container-name');
  assert.equal(dups.length, 1, 'one finding, not one per side');
  assert.equal(dups[0].service, 'b');
  assert.equal(dups[0].level, 'error');
  assert.match(dups[0].message, /a/);
});

test('duplicate-container-name stays quiet without explicit names', () => {
  const yaml = [
    'services:',
    '  a:',
    '    image: nginx:1.27',
    '  b:',
    '    image: nginx:1.27',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  assert.ok(!findings.some((f) => f.rule === 'duplicate-container-name'));
});

test('command-secret catches literal secrets in command and entrypoint (all three shapes)', () => {
  const yaml = [
    'services:',
    '  cache:',
    '    image: redis:7',
    '    command: redis-server --requirepass hunter2',        // flag + space
    '  db-tool:',
    '    image: mysql:8',
    '    command: sh -c "MYSQL_PASSWORD=hunter2 mysqladmin ping"',  // inline env assignment
    '  api:',
    '    image: myorg/api:1',
    '    entrypoint: ["./serve", "--api-token=sk-live-123"]',  // exec form, flag=value
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  const hits = findings.filter((f) => f.rule === 'command-secret');
  assert.equal(hits.length, 3);
  for (const h of hits) assert.equal(h.level, 'error');
  assert.ok(hits.some((h) => h.message.includes('--requirepass')));
  assert.ok(hits.some((h) => h.message.includes('MYSQL_PASSWORD')));
  assert.ok(hits.some((h) => h.message.includes('--api-token')));
  // The secret VALUE itself is never echoed back in the finding.
  for (const h of hits) {
    assert.ok(!h.message.includes('hunter2') && !h.message.includes('sk-live-123'));
  }
});

test('command-secret spares interpolations, file paths and flag-like next tokens', () => {
  const yaml = [
    'services:',
    '  a:',
    '    image: redis:7',
    '    command: redis-server --requirepass ${REDIS_PASS}',   // interpolation
    '  b:',
    '    image: mongo:7',
    '    command: mongod --tlsCertificateKeyFile /certs/key.pem',  // path = reference, not secret
    '  c:',
    '    image: myorg/api:1',
    '    command: ./serve --token --verbose',                  // next token is another flag
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  assert.ok(!findings.some((f) => f.rule === 'command-secret'));
});

test('depends-on-unknown fires on a ghost service, quiet on real ones (both forms)', () => {
  const listForm = [
    'services:',
    '  api:',
    '    image: node:22',
    '    depends_on:',
    '      - db',
    '      - cache',
    '  db:',
    '    image: postgres:16',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(listForm));
  const unknown = findings.filter((f) => f.rule === 'depends-on-unknown');
  assert.equal(unknown.length, 1, 'only the ghost is flagged');
  assert.equal(unknown[0].level, 'error');
  assert.match(unknown[0].message, /cache/);

  // Mapping form (condition: service_healthy) resolves names the same way.
  const mapForm = [
    'services:',
    '  api:',
    '    image: node:22',
    '    depends_on:',
    '      db:',
    '        condition: service_healthy',
    '  db:',
    '    image: postgres:16',
  ].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(mapForm)).findings.some((f) => f.rule === 'depends-on-unknown'));
});

test('depends-on-ignores-healthcheck fires on the short form when the target has a healthcheck', () => {
  const yaml = [
    'services:',
    '  api:',
    '    image: node:22',
    '    depends_on:',
    '      - db',
    '  db:',
    '    image: postgres:16',
    '    healthcheck:',
    '      test: ["CMD-SHELL", "pg_isready"]',
  ].join('\n');
  const hits = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'depends-on-ignores-healthcheck');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].service, 'api');
  assert.equal(hits[0].level, 'warn');
  assert.match(hits[0].message, /db/);
  assert.match(hits[0].hint, /service_healthy/);
});

test('depends-on-ignores-healthcheck also fires on a long-form entry with no condition', () => {
  const yaml = [
    'services:',
    '  api:',
    '    image: node:22',
    '    depends_on:',
    '      db: {}',
    '  db:',
    '    image: postgres:16',
    '    healthcheck:',
    '      test: ["CMD-SHELL", "pg_isready"]',
  ].join('\n');
  assert.ok(DS.lint(DS.parseCompose(yaml)).findings.some((f) => f.rule === 'depends-on-ignores-healthcheck'));
});

test('depends-on-ignores-healthcheck stays quiet for service_healthy, completed jobs, and healthcheck-less targets', () => {
  const healthy = [
    'services:',
    '  api:',
    '    image: node:22',
    '    depends_on:',
    '      db:',
    '        condition: service_healthy',
    '  migrate:',
    '    image: migrate/migrate:v4.17.0',
    '    depends_on:',
    '      db:',
    '        condition: service_completed_successfully',
    '  worker:',
    '    image: node:22',
    '    depends_on:',
    '      - plain',
    '  db:',
    '    image: postgres:16',
    '    healthcheck:',
    '      test: ["CMD-SHELL", "pg_isready"]',
    '  plain:',
    '    image: redis:7',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(healthy));
  assert.ok(!findings.some((f) => f.rule === 'depends-on-ignores-healthcheck'));
});

test('the insecure sample trips every security rule at once', () => {
  const rules = new Set(DS.lint(DS.parseCompose(sample('insecure.yml'))).findings.map((f) => f.rule));
  for (const r of [
    'image-latest', 'docker-socket-mount', 'privileged', 'host-namespace',
    'dangerous-cap', 'sensitive-host-mount', 'no-new-privileges',
    'env-secret', 'port-public', 'security-unconfined', 'build-arg-secret', 'command-secret',
    'port-conflict', 'duplicate-container-name', 'depends-on-unknown',
    'depends-on-ignores-healthcheck', 'undeclared-network', 'undeclared-volume',
    'container-name-with-replicas', 'healthcheck-no-start-period',
    'service-healthy-no-healthcheck', 'healthcheck-test-invalid',
    'duplicate-env-key', 'undeclared-secret', 'ports-with-host-network',
  ]) {
    assert.ok(rules.has(r), `expected rule '${r}'`);
  }
});

test('undeclared-network flags a missing top-level network, spares default and declared ones', () => {
  const flagged = [
    'services:',
    '  web:',
    '    image: nginx:1.27',
    '    networks:',
    '      - frontend',
    '      - default',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(flagged)).findings.filter((f) => f.rule === 'undeclared-network');
  assert.equal(found.length, 1);
  assert.equal(found[0].level, 'error');
  assert.match(found[0].message, /frontend/);

  const declared = flagged + '\nnetworks:\n  frontend:\n';
  assert.ok(!DS.lint(DS.parseCompose(declared)).findings.some((f) => f.rule === 'undeclared-network'));
});

test('undeclared-volume flags a missing named volume, ignores binds and anonymous volumes', () => {
  const flagged = [
    'services:',
    '  db:',
    '    image: postgres:16',
    '    volumes:',
    '      - pgdata:/var/lib/postgresql/data',
    '      - ./conf:/etc/postgresql:ro',
    '      - /var/cache/scratch',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(flagged)).findings.filter((f) => f.rule === 'undeclared-volume');
  assert.equal(found.length, 1);
  assert.equal(found[0].level, 'error');
  assert.match(found[0].message, /pgdata/);

  const declared = flagged + '\nvolumes:\n  pgdata:\n';
  assert.ok(!DS.lint(DS.parseCompose(declared)).findings.some((f) => f.rule === 'undeclared-volume'));
});

test('undeclared refs with interpolated names are skipped (value comes from outside)', () => {
  const rs = [
    'services:',
    '  web:',
    '    image: nginx:1.27',
    '    networks:',
    '      - ${NET_NAME}',
  ].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(rs)).findings.some((f) => f.rule === 'undeclared-network'));
});

test('container-name-with-replicas fires on a fixed name with replicas > 1', () => {
  const compose = [
    'services:',
    '  web:',
    '    image: nginx:1.27',
    '    container_name: front',
    '    deploy:',
    '      replicas: 3',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(compose)).findings.filter((f) => f.rule === 'container-name-with-replicas');
  assert.equal(found.length, 1);
  assert.equal(found[0].level, 'error');
  assert.match(found[0].message, /front/);
  assert.match(found[0].message, /replicas: 3/);
});

test('container-name-with-replicas understands the legacy scale key', () => {
  const compose = [
    'services:',
    '  web:',
    '    image: nginx:1.27',
    '    container_name: front',
    '    scale: 2',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(compose)).findings.filter((f) => f.rule === 'container-name-with-replicas');
  assert.equal(found.length, 1);
});

test('container-name-with-replicas stays quiet on 1 replica or without a fixed name', () => {
  const compose = [
    'services:',
    '  one:',
    '    image: nginx:1.27',
    '    container_name: front',
    '    deploy:',
    '      replicas: 1',
    '  many:',
    '    image: nginx:1.27',
    '    deploy:',
    '      replicas: 4',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(compose));
  assert.ok(!findings.some((f) => f.rule === 'container-name-with-replicas'));
});

test('healthcheck-no-start-period fires without start_period, quiet with it or when disabled', () => {
  const compose = [
    'services:',
    '  flappy:',
    '    image: postgres:16',
    '    healthcheck:',
    '      test: ["CMD-SHELL", "pg_isready"]',
    '      retries: 3',
    '  patient:',
    '    image: postgres:16',
    '    healthcheck:',
    '      test: ["CMD-SHELL", "pg_isready"]',
    '      start_period: 30s',
    '  optout:',
    '    image: postgres:16',
    '    healthcheck:',
    '      disable: true',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(compose)).findings.filter((f) => f.rule === 'healthcheck-no-start-period');
  assert.equal(found.length, 1);
  assert.equal(found[0].service, 'flappy');
  assert.equal(found[0].level, 'warn');
});

test('healthcheck-no-start-period leaves services with no healthcheck to no-healthcheck', () => {
  const compose = [
    'services:',
    '  bare:',
    '    image: nginx:1.27',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(compose));
  assert.ok(!findings.some((f) => f.rule === 'healthcheck-no-start-period'));
  assert.ok(findings.some((f) => f.rule === 'no-healthcheck'));
});

test('no-memory-limit fires on an uncapped service', () => {
  const compose = [
    'services:',
    '  greedy:',
    '    image: nginx:1.27',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(compose));
  const hits = findings.filter((f) => f.rule === 'no-memory-limit');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].service, 'greedy');
  assert.equal(hits[0].level, 'warn');
});

test('no-memory-limit accepts both the deploy form and the legacy mem_limit', () => {
  const compose = [
    'services:',
    '  modern:',
    '    image: nginx:1.27',
    '    deploy:',
    '      resources:',
    '        limits:',
    '          memory: 512M',
    '  legacy:',
    '    image: redis:7.4',
    '    mem_limit: 256m',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(compose));
  assert.ok(!findings.some((f) => f.rule === 'no-memory-limit'));
});

test('no-memory-limit still fires when limits only cap cpus', () => {
  // A cpus-only limit is a real limits block, but memory is what OOMs hosts.
  const compose = [
    'services:',
    '  cpuonly:',
    '    image: nginx:1.27',
    '    deploy:',
    '      resources:',
    '        limits:',
    '          cpus: "0.5"',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(compose));
  assert.ok(findings.some((f) => f.rule === 'no-memory-limit' && f.service === 'cpuonly'));
});

test('parser normalizes memoryLimit from either spelling, null when absent', () => {
  const compose = [
    'services:',
    '  a:',
    '    image: nginx:1.27',
    '    deploy: { resources: { limits: { memory: 512M } } }',
    '  b:',
    '    image: redis:7.4',
    '    mem_limit: 268435456',
    '  c:',
    '    image: postgres:17',
  ].join('\n');
  const model = DS.parseCompose(compose);
  const by = Object.fromEntries(model.services.map((s) => [s.name, s.memoryLimit]));
  assert.equal(by.a, '512M');
  assert.equal(by.b, '268435456');
  assert.equal(by.c, null);
});

test('no-pids-limit fires on an uncapped service', () => {
  const compose = [
    'services:',
    '  forky:',
    '    image: nginx:1.27',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(compose));
  const hits = findings.filter((f) => f.rule === 'no-pids-limit');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].service, 'forky');
  assert.equal(hits[0].level, 'warn');
});

test('no-pids-limit accepts both the deploy form and the legacy pids_limit', () => {
  const compose = [
    'services:',
    '  modern:',
    '    image: nginx:1.27',
    '    deploy:',
    '      resources:',
    '        limits:',
    '          pids: 256',
    '  legacy:',
    '    image: redis:7.4',
    '    pids_limit: 128',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(compose));
  assert.ok(!findings.some((f) => f.rule === 'no-pids-limit'));
});

test('parser normalizes pidsLimit from either spelling, null when absent', () => {
  const compose = [
    'services:',
    '  a:',
    '    image: nginx:1.27',
    '    deploy: { resources: { limits: { pids: 256 } } }',
    '  b:',
    '    image: redis:7.4',
    '    pids_limit: "128"',
    '  c:',
    '    image: postgres:17',
  ].join('\n');
  const model = DS.parseCompose(compose);
  const by = Object.fromEntries(model.services.map((s) => [s.name, s.pidsLimit]));
  assert.equal(by.a, 256);
  assert.equal(by.b, 128);
  assert.equal(by.c, null);
});

test('no-cap-drop fires when a service keeps the default capability set', () => {
  const compose = [
    'services:',
    '  bare:',
    '    image: nginx:1.27',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(compose));
  const hits = findings.filter((f) => f.rule === 'no-cap-drop');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].service, 'bare');
  assert.equal(hits[0].level, 'warn');
});

test('no-cap-drop is cleared by cap_drop ALL (with or without CAP_ prefix)', () => {
  const compose = [
    'services:',
    '  a:',
    '    image: nginx:1.27',
    '    cap_drop: ["ALL"]',
    '  b:',
    '    image: redis:7.4',
    '    cap_drop: ["CAP_ALL"]',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(compose));
  assert.ok(!findings.some((f) => f.rule === 'no-cap-drop'));
});

test('no-cap-drop still fires on a partial drop (not least privilege)', () => {
  // Dropping a couple of caps is better than nothing but not cap_drop: [ALL].
  const compose = [
    'services:',
    '  partial:',
    '    image: nginx:1.27',
    '    cap_drop: ["NET_RAW", "MKNOD"]',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(compose));
  assert.ok(findings.some((f) => f.rule === 'no-cap-drop' && f.service === 'partial'));
});

test('no-cap-drop composes with dangerous-cap (drop ALL then add back one)', () => {
  // Least privilege done wrong: adds SYS_ADMIN but never drops the baseline.
  const compose = [
    'services:',
    '  x:',
    '    image: nginx:1.27',
    '    cap_add: ["SYS_ADMIN"]',
  ].join('\n');
  const rules = DS.lint(DS.parseCompose(compose)).findings.map((f) => f.rule);
  assert.ok(rules.includes('no-cap-drop'));
  assert.ok(rules.includes('dangerous-cap'));
});

test('parser surfaces capDrop, upper-cased, empty when absent', () => {
  const compose = [
    'services:',
    '  a:',
    '    image: nginx:1.27',
    '    cap_drop: ["all", "net_raw"]',
    '  b:',
    '    image: redis:7.4',
  ].join('\n');
  const model = DS.parseCompose(compose);
  const by = Object.fromEntries(model.services.map((s) => [s.name, s.capDrop]));
  // JSON compare: parser output comes from the vm sandbox (cross-realm),
  // so deepEqual on the arrays fails on reference identity.
  assert.equal(JSON.stringify(by.a), JSON.stringify(['ALL', 'NET_RAW']));
  assert.equal(JSON.stringify(by.b), '[]');
});

test('no-read-only fires when a service keeps a writable root filesystem', () => {
  const compose = [
    'services:',
    '  x:',
    '    image: nginx:1.27',
  ].join('\n');
  const hits = DS.lint(DS.parseCompose(compose)).findings.filter((f) => f.rule === 'no-read-only');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].level, 'warn');
  assert.equal(hits[0].service, 'x');
});

test('no-read-only is cleared by read_only: true; an explicit false still fires', () => {
  const compose = [
    'services:',
    '  locked:',
    '    image: nginx:1.27',
    '    read_only: true',
    '  writable:',
    '    image: nginx:1.27',
    '    read_only: false',
  ].join('\n');
  const hits = DS.lint(DS.parseCompose(compose)).findings.filter((f) => f.rule === 'no-read-only');
  assert.equal(JSON.stringify(hits.map((f) => f.service)), JSON.stringify(['writable']));
});

test('no-read-only judges only the rootfs — volumes and tmpfs stay legitimate', () => {
  // The recommended shape: immutable image, scratch space via explicit mounts.
  const compose = [
    'services:',
    '  x:',
    '    image: nginx:1.27',
    '    read_only: true',
    '    tmpfs: [/tmp]',
    '    volumes:',
    '      - data:/var/lib/app',
    'volumes:',
    '  data:',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(compose));
  assert.ok(!findings.some((f) => f.rule === 'no-read-only'));
});

test('parser surfaces readOnly as a strict boolean', () => {
  const compose = [
    'services:',
    '  a:',
    '    image: nginx:1.27',
    '    read_only: true',
    '  b:',
    '    image: redis:7.4',
  ].join('\n');
  const model = DS.parseCompose(compose);
  const by = Object.fromEntries(model.services.map((s) => [s.name, s.readOnly]));
  assert.equal(by.a, true);
  assert.equal(by.b, false);
});

test('no-log-limit fires on the default driver and on json-file without max-size', () => {
  const compose = [
    'services:',
    '  default:',
    '    image: nginx:1.27',
    '  explicit:',
    '    image: nginx:1.27',
    '    logging:',
    '      driver: json-file',
  ].join('\n');
  const hits = DS.lint(DS.parseCompose(compose)).findings.filter((f) => f.rule === 'no-log-limit');
  assert.equal(hits.length, 2);
  assert.ok(hits.every((f) => f.level === 'warn'));
});

test('no-log-limit is cleared by max-size, and non-json-file drivers are spared', () => {
  const compose = [
    'services:',
    '  bounded:',
    '    image: nginx:1.27',
    '    logging:',
    '      driver: json-file',
    '      options:',
    '        max-size: "10m"',
    '  local:',
    '    image: nginx:1.27',
    '    logging:',
    '      driver: local',
    '  journald:',
    '    image: nginx:1.27',
    '    logging:',
    '      driver: journald',
    '  silent:',
    '    image: nginx:1.27',
    '    logging:',
    '      driver: none',
  ].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(compose)).findings.some((f) => f.rule === 'no-log-limit'));
});

test('parser surfaces logDriver and logMaxSize', () => {
  const compose = [
    'services:',
    '  a:',
    '    image: nginx:1.27',
    '    logging:',
    '      driver: json-file',
    '      options:',
    '        max-size: "5m"',
    '  b:',
    '    image: redis:7.4',
  ].join('\n');
  const by = Object.fromEntries(DS.parseCompose(compose).services.map((s) => [s.name, s]));
  assert.equal(by.a.logDriver, 'json-file');
  assert.equal(by.a.logMaxSize, '5m');
  assert.equal(by.b.logDriver, null);
  assert.equal(by.b.logMaxSize, null);
});

// --- service-healthy-no-healthcheck + healthcheck-test-invalid (v0.24) ------

test('service_healthy against a target with no healthcheck is an error', () => {
  const yml = [
    'services:',
    '  app:',
    '    image: app:1.0',
    '    depends_on:',
    '      db:',
    '        condition: service_healthy',
    '  db:',
    '    image: postgres:16',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yml)).findings.filter((f) => f.rule === 'service-healthy-no-healthcheck');
  assert.equal(found.length, 1);
  assert.equal(found[0].level, 'error');
  assert.match(found[0].message, /has no healthcheck/);
});

test('service_healthy against a DISABLED healthcheck also fires', () => {
  for (const hc of ['      disable: true', '      test: ["NONE"]', '      test: NONE']) {
    const yml = [
      'services:',
      '  app:',
      '    image: app:1.0',
      '    depends_on:',
      '      db:',
      '        condition: service_healthy',
      '  db:',
      '    image: postgres:16',
      '    healthcheck:',
      hc,
    ].join('\n');
    const found = DS.lint(DS.parseCompose(yml)).findings.filter((f) => f.rule === 'service-healthy-no-healthcheck');
    assert.equal(found.length, 1, `expected a finding with healthcheck ${hc.trim()}`);
    assert.match(found[0].message, /disables its healthcheck/);
  }
});

test('service_healthy with a real healthcheck, other conditions and unknown targets stay quiet', () => {
  const yml = [
    'services:',
    '  app:',
    '    image: app:1.0',
    '    depends_on:',
    '      db:',
    '        condition: service_healthy',
    '      worker:',
    '        condition: service_started',
    '      ghost:',
    '        condition: service_healthy',
    '  db:',
    '    image: postgres:16',
    '    healthcheck:',
    '      test: ["CMD-SHELL", "pg_isready"]',
    '      start_period: 10s',
    '  worker:',
    '    image: worker:1.0',
  ].join('\n');
  const findings = DS.lint(DS.parseCompose(yml)).findings;
  // ghost is depends-on-unknown's job, not this rule's.
  assert.ok(!findings.some((f) => f.rule === 'service-healthy-no-healthcheck'));
  assert.ok(findings.some((f) => f.rule === 'depends-on-unknown'));
});

test('healthcheck-test-invalid fires on a list without CMD / CMD-SHELL / NONE', () => {
  const yml = [
    'services:',
    '  web:',
    '    image: nginx:1.27',
    '    healthcheck:',
    '      test: ["curl", "-f", "http://localhost/health"]',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yml)).findings.filter((f) => f.rule === 'healthcheck-test-invalid');
  assert.equal(found.length, 1);
  assert.equal(found[0].level, 'error');
  assert.match(found[0].message, /curl/);
});

test('healthcheck-test-invalid spares valid prefixes, string form and interpolations', () => {
  const cases = [
    '      test: ["CMD", "curl", "-f", "http://localhost"]',
    '      test: ["CMD-SHELL", "curl -f http://localhost"]',
    '      test: ["cmd-shell", "curl -f http://localhost"]',
    '      test: ["NONE"]',
    '      test: curl -f http://localhost',
    '      test: ["${HC_PREFIX}", "curl"]',
  ];
  for (const line of cases) {
    const yml = ['services:', '  web:', '    image: nginx:1.27', '    healthcheck:', line].join('\n');
    const found = DS.lint(DS.parseCompose(yml)).findings.filter((f) => f.rule === 'healthcheck-test-invalid');
    assert.equal(found.length, 0, `expected no finding for ${line.trim()}`);
  }
});

// --- duplicate-env-key (v0.25) ---------------------------------------------

test('duplicate-env-key fires on a repeated list-form environment key', () => {
  const yml = [
    'services:',
    '  app:',
    '    image: app:1.0',
    '    environment:',
    '      - LOG_LEVEL=debug',
    '      - LOG_LEVEL=info',
    '      - PORT=8080',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yml)).findings.filter((f) => f.rule === 'duplicate-env-key');
  assert.equal(found.length, 1);
  assert.equal(found[0].level, 'warn');
  assert.match(found[0].message, /LOG_LEVEL/);
  assert.match(found[0].message, /2 times/);
});

test('duplicate-env-key also covers build args', () => {
  const yml = [
    'services:',
    '  app:',
    '    build:',
    '      context: .',
    '      args:',
    '        - NODE_ENV=production',
    '        - NODE_ENV=development',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yml)).findings.filter((f) => f.rule === 'duplicate-env-key');
  assert.equal(found.length, 1);
  assert.match(found[0].message, /build args/);
});

test('duplicate-env-key stays quiet on map form and on unique keys', () => {
  // Map form: YAML collapses duplicates, so there is nothing to flag.
  const mapForm = [
    'services:',
    '  app:',
    '    image: app:1.0',
    '    environment:',
    '      LOG_LEVEL: info',
    '      PORT: "8080"',
  ].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(mapForm)).findings.some((f) => f.rule === 'duplicate-env-key'));

  const unique = [
    'services:',
    '  app:',
    '    image: app:1.0',
    '    environment:',
    '      - LOG_LEVEL=info',
    '      - PORT=8080',
  ].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(unique)).findings.some((f) => f.rule === 'duplicate-env-key'));
});

// --- undeclared-secret (v0.26) ---------------------------------------------

test('undeclared-secret flags a service secret missing from the top-level block', () => {
  const yml = [
    'services:',
    '  db:',
    '    image: postgres:16',
    '    secrets:',
    '      - db_password',
    '      - api_key',
    'secrets:',
    '  db_password:',
    '    file: ./db_password.txt',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yml)).findings.filter((f) => f.rule === 'undeclared-secret');
  // db_password is declared; api_key is not.
  assert.equal(found.length, 1);
  assert.equal(found[0].level, 'error');
  assert.match(found[0].message, /api_key/);
});

test('undeclared-secret handles long-form secret entries (source:)', () => {
  const yml = [
    'services:',
    '  app:',
    '    image: app:1.0',
    '    secrets:',
    '      - source: tls_key',
    '        target: /run/secrets/tls',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yml)).findings.filter((f) => f.rule === 'undeclared-secret');
  assert.equal(found.length, 1);
  assert.match(found[0].message, /tls_key/);
});

test('undeclared-secret stays quiet when every secret is declared, and on interpolation', () => {
  const declared = [
    'services:',
    '  app:',
    '    image: app:1.0',
    '    secrets:',
    '      - db_password',
    '      - ${DYNAMIC_SECRET}',
    'secrets:',
    '  db_password:',
    '    external: true',
  ].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(declared)).findings.some((f) => f.rule === 'undeclared-secret'));

  // No secrets at all → nothing to flag.
  const none = ['services:', '  app:', '    image: app:1.0'].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(none)).findings.some((f) => f.rule === 'undeclared-secret'));
});

// --- depends-on-cycle (v0.27) ----------------------------------------------

test('depends-on-cycle flags a two-service loop, once', () => {
  const yml = [
    'services:',
    '  a:',
    '    image: a:1',
    '    depends_on: [b]',
    '  b:',
    '    image: b:1',
    '    depends_on: [a]',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yml)).findings.filter((f) => f.rule === 'depends-on-cycle');
  assert.equal(found.length, 1, 'reported exactly once');
  assert.equal(found[0].service, 'a', 'on the smallest member');
  assert.equal(found[0].level, 'error');
  assert.match(found[0].message, /`a`, `b`/);
});

test('depends-on-cycle catches a self-dependency and a 3-node loop', () => {
  const selfLoop = ['services:', '  a:', '    image: a:1', '    depends_on: [a]'].join('\n');
  assert.ok(DS.lint(DS.parseCompose(selfLoop)).findings.some((f) => f.rule === 'depends-on-cycle'));

  const three = [
    'services:',
    '  a:', '    image: a:1', '    depends_on: [b]',
    '  b:', '    image: b:1', '    depends_on: [c]',
    '  c:', '    image: c:1', '    depends_on: [a]',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(three)).findings.filter((f) => f.rule === 'depends-on-cycle');
  assert.equal(found.length, 1);
  assert.match(found[0].message, /`a`, `b`, `c`/);
});

test('depends-on-cycle stays quiet on a plain chain (no loop)', () => {
  const yml = [
    'services:',
    '  a:', '    image: a:1', '    depends_on: [b]',
    '  b:', '    image: b:1', '    depends_on: [c]',
    '  c:', '    image: c:1',
  ].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(yml)).findings.some((f) => f.rule === 'depends-on-cycle'));
});

test('depends-on-cycle ignores edges to nonexistent services (that is depends-on-unknown)', () => {
  const yml = [
    'services:',
    '  a:', '    image: a:1', '    depends_on: [ghost]',
  ].join('\n');
  const findings = DS.lint(DS.parseCompose(yml)).findings;
  assert.ok(!findings.some((f) => f.rule === 'depends-on-cycle'));
  assert.ok(findings.some((f) => f.rule === 'depends-on-unknown'));
});

test('depends-on-cycle reports each independent cycle separately', () => {
  const yml = [
    'services:',
    '  a:', '    image: a:1', '    depends_on: [b]',
    '  b:', '    image: b:1', '    depends_on: [a]',
    '  x:', '    image: x:1', '    depends_on: [y]',
    '  y:', '    image: y:1', '    depends_on: [x]',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yml)).findings.filter((f) => f.rule === 'depends-on-cycle');
  assert.equal(found.length, 2);
  // JSON.stringify, not deepEqual: the findings come from the vm sandbox, so
  // their arrays fail deepStrictEqual's cross-realm prototype check.
  assert.equal(JSON.stringify(found.map((f) => f.service).sort()), JSON.stringify(['a', 'x']));
});

// --- no-cpu-limit (v0.28) ---------------------------------------------------

test('no-cpu-limit fires on an uncapped service', () => {
  const compose = [
    'services:',
    '  spinner:',
    '    image: nginx:1.27',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(compose));
  const hits = findings.filter((f) => f.rule === 'no-cpu-limit');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].service, 'spinner');
  assert.equal(hits[0].level, 'warn');
});

test('no-cpu-limit accepts the deploy form, the cpus shorthand and cpu_quota', () => {
  const compose = [
    'services:',
    '  modern:',
    '    image: nginx:1.27',
    '    deploy:',
    '      resources:',
    '        limits:',
    "          cpus: '0.50'",
    '  shorthand:',
    '    image: redis:7.4',
    '    cpus: 1.5',
    '  lowlevel:',
    '    image: postgres:17',
    '    cpu_quota: 50000',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(compose));
  assert.ok(!findings.some((f) => f.rule === 'no-cpu-limit'));
});

test('no-cpu-limit does not count cpu_shares as a cap (a weight, not a limit)', () => {
  const compose = [
    'services:',
    '  weighted:',
    '    image: nginx:1.27',
    '    cpu_shares: 512',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(compose));
  assert.ok(findings.some((f) => f.rule === 'no-cpu-limit'));
});

// --- ports-with-host-network (v0.29) -----------------------------------------

test('ports-with-host-network fires when host networking meets a ports block', () => {
  const compose = [
    'services:',
    '  agent:',
    '    image: prom/node-exporter:v1.8.2',
    '    network_mode: host',
    '    ports:',
    '      - "9100:9100"',
    '      - "9101:9101"',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(compose));
  const hits = findings.filter((f) => f.rule === 'ports-with-host-network');
  assert.equal(hits.length, 1, 'one finding per service, not per mapping');
  assert.equal(hits[0].service, 'agent');
  assert.equal(hits[0].level, 'warn');
  assert.match(hits[0].message, /2 port mappings/);
});

test('ports-with-host-network stays quiet without ports, or without host networking', () => {
  const hostNoPorts = [
    'services:',
    '  agent:',
    '    image: prom/node-exporter:v1.8.2',
    '    network_mode: host',
  ].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(hostNoPorts)).findings.some((f) => f.rule === 'ports-with-host-network'));

  const portsNoHost = [
    'services:',
    '  web:',
    '    image: nginx:1.27',
    '    ports:',
    '      - "80:80"',
  ].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(portsNoHost)).findings.some((f) => f.rule === 'ports-with-host-network'));
});

test('ports-with-host-network ignores other network_mode values (bridge, service:, container:)', () => {
  const compose = [
    'services:',
    '  sidecar:',
    '    image: nginx:1.27',
    '    network_mode: service:web',
    '    ports:',
    '      - "8080:8080"',
    '  web:',
    '    image: nginx:1.27',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(compose));
  assert.ok(!findings.some((f) => f.rule === 'ports-with-host-network'));
});
